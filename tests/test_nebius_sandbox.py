"""Nebius Sandboxes backend, exercised against an in-process fake of the REST API.

These tests prove Arbalest sends the documented requests (offline, disposable,
bearer + Project headers) and fails closed on every error path. They do NOT
prove the live service behaves as documented; use `arbalest sandbox-check`
against a real project for that.
"""

from __future__ import annotations

import base64
import hashlib
import json

import httpx
import pytest

from engine.services.docker_manager import (
    SandboxBackend,
    SandboxLimits,
    SandboxRunSpec,
    SandboxRuntime,
    SandboxStatus,
    SandboxValidationError,
)
from engine.services.nebius_sandbox import NebiusSandboxError, NebiusSandboxManager

OP_ID = "12345678-9abc-baba-deda-0123456789ab"


def _b64(text: str) -> dict:
    return {"value": base64.b64encode(text.encode()).decode(), "encoding": "base64", "truncated": False}


class FakeSandboxes:
    """Minimal stand-in for the Sandboxes REST API."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.uploads: dict[str, bytes] = {}
        self.spawned: list[dict] = []
        self.cancelled: list[str] = []
        self.polls_until_done = 1
        self._polls = 0
        self.final_status = "SUCCESS"
        self.exit_code = 0
        self.timed_out = False
        self.stdout = "ok\n"
        self.stderr = ""
        self.error: str | None = None
        self.echo_networking: dict | None = {"enabled": False}
        self.spawn_status = 201
        self.flaky_503 = 0
        self.permissions = {"spawn": True, "spawn_disposable": True}
        self.limits: dict = {"instance_max_timeout": 3600}
        self.never_finish = False

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path.removeprefix("/sandboxes/v1")
        if self.flaky_503 and request.method == "POST" and path == "/files":
            self.flaky_503 -= 1
            return httpx.Response(503, json={"error": "busy"})
        if request.method == "GET" and path == "/whoami":
            return httpx.Response(200, json={"permissions": self.permissions, "limits": self.limits})
        if request.method == "POST" and path == "/files":
            digest = hashlib.sha256(request.content).hexdigest()
            self.uploads[digest] = request.content
            return httpx.Response(201, json={"uuid": f"00000000-0000-0000-0000-{digest[:12]}", "sha256": digest,
                                            "size": len(request.content)})
        if request.method == "POST" and path == "/instances":
            if self.spawn_status != 201:
                return httpx.Response(self.spawn_status, json={"error": "denied"})
            body = json.loads(request.content)
            self.spawned.append(body)
            reply = {"uuid": OP_ID, **body}
            if self.echo_networking is None:
                reply.pop("networking", None)
            else:
                reply["networking"] = self.echo_networking
            return httpx.Response(201, json=reply, headers={"Location": f"/v1/operations/{OP_ID}"})
        if request.method == "GET" and path == f"/operations/{OP_ID}":
            self._polls += 1
            if self.never_finish or self._polls < self.polls_until_done:
                return httpx.Response(200, json={"uuid": OP_ID, "status": "EXECUTING"})
            return httpx.Response(200, json={
                "uuid": OP_ID,
                "status": self.final_status,
                "error": self.error,
                "result": {
                    "state": {"exit_code": self.exit_code, "timed_out": self.timed_out},
                    "stdout": _b64(self.stdout),
                    "stderr": _b64(self.stderr),
                },
            })
        if request.method == "DELETE" and path == f"/operations/{OP_ID}":
            self.cancelled.append(OP_ID)
            return httpx.Response(202)
        return httpx.Response(404, json={"error": f"no route {request.method} {path}"})


def _manager(fake: FakeSandboxes, **kwargs) -> NebiusSandboxManager:
    return NebiusSandboxManager(
        api_key="test-key-123456",
        project_id="aiproject-test",
        transport=fake.transport(),
        poll_interval=0.01,
        timeout_grace=0.2,
        **kwargs,
    )


def _spec(**overrides) -> SandboxRunSpec:
    params = {
        "runtime": SandboxRuntime.PYTHON,
        "command": ("sh", "attack.sh"),
        "files": {"app.py": "x = 1\n", "attack.sh": "echo hi\n"},
    }
    params.update(overrides)
    return SandboxRunSpec(**params)


def test_manager_satisfies_the_backend_protocol():
    manager = NebiusSandboxManager(api_key="k-123456", project_id="p")
    assert isinstance(manager, SandboxBackend)


def test_requires_credentials(monkeypatch):
    monkeypatch.delenv("NEBIUS_API_KEY", raising=False)
    monkeypatch.delenv("NEBIUS_PROJECT_ID", raising=False)
    with pytest.raises(ValueError, match="NEBIUS_API_KEY"):
        NebiusSandboxManager()
    with pytest.raises(ValueError, match="NEBIUS_PROJECT_ID"):
        NebiusSandboxManager(api_key="k-123456")


def test_operation_uses_metadata_execution_result_when_top_level_result_is_an_image():
    """Nebius returns the saved-image result separately from process output."""
    manager = NebiusSandboxManager(api_key="k-123456", project_id="p")
    outcome = manager._interpret(  # noqa: SLF001 - validates the API response adapter directly.
        {
            "status": "SUCCESS",
            "result": {"image": None, "tag": None},
            "metadata": {
                "result": {
                    "state": {"exit_code": 0, "timed_out": False},
                    "stdout": _b64("ARBALEST_SANDBOX_OK\n"),
                    "stderr": _b64(""),
                }
            },
        },
        SandboxLimits(),
    )
    assert outcome.status is SandboxStatus.COMPLETED
    assert outcome.exit_code == 0
    assert outcome.stdout == "ARBALEST_SANDBOX_OK\n"


@pytest.mark.asyncio
async def test_spawn_request_is_offline_disposable_and_authenticated():
    fake = FakeSandboxes()
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()

    assert result.status is SandboxStatus.COMPLETED and result.succeeded
    assert result.stdout == "ok\n" and result.container_id == OP_ID

    body = fake.spawned[0]
    assert body["networking"] == {"enabled": False}
    assert body["disposable"] is True
    assert body["image"] == "tag:python:3.12-slim"
    assert body["shell"] is True
    assert body["cwd"] == "/run/arbalest-build/workspace"
    assert body["timeout"] == 120
    assert body["command"].endswith("&& sh attack.sh")
    assert set(body["files"]) == {
        "/run/arbalest-build/workspace/app.py",
        "/run/arbalest-build/workspace/attack.sh",
    }
    assert body["env"]["CARGO_TARGET_DIR"].startswith("/run/arbalest-build/")

    for request in fake.requests:
        assert request.headers["Authorization"] == "Bearer test-key-123456"
        assert request.headers["Project"] == "aiproject-test"


@pytest.mark.asyncio
async def test_command_is_quoted_so_a_hostile_filename_cannot_inject():
    fake = FakeSandboxes()
    manager = _manager(fake)
    try:
        await manager.run(_spec(command=("sh", "a b;rm.sh"), files={"a b;rm.sh": "echo hi\n"}))
    finally:
        await manager.aclose()
    assert "&& sh 'a b;rm.sh'" in fake.spawned[0]["command"]


@pytest.mark.asyncio
async def test_identical_files_are_uploaded_once():
    fake = FakeSandboxes()
    manager = _manager(fake)
    try:
        await manager.run(_spec(files={"a.py": "same\n", "b.py": "same\n", "attack.sh": "echo\n"}))
    finally:
        await manager.aclose()
    uploads = [r for r in fake.requests if r.method == "POST" and r.url.path.endswith("/files")]
    assert len(uploads) == 2
    assert len(fake.spawned[0]["files"]) == 3


@pytest.mark.asyncio
async def test_nonzero_exit_is_completed_but_not_succeeded():
    fake = FakeSandboxes()
    fake.exit_code = 1
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.COMPLETED
    assert result.exit_code == 1 and result.succeeded is False


@pytest.mark.asyncio
async def test_service_timeout_maps_to_timed_out_124():
    fake = FakeSandboxes()
    fake.timed_out = True
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.TIMED_OUT and result.exit_code == 124 and not result.succeeded


@pytest.mark.asyncio
async def test_failed_operation_is_an_engine_error_with_the_reason():
    fake = FakeSandboxes()
    fake.final_status = "FAILED"
    fake.error = "image pull failed"
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.ENGINE_ERROR and not result.succeeded
    assert "image pull failed" in (result.error or "")


@pytest.mark.asyncio
async def test_output_is_sanitized_and_bounded():
    fake = FakeSandboxes()
    fake.stdout = "\x1b[31mred\x1b[0m " + "A" * 10_000
    manager = _manager(fake)
    try:
        result = await manager.run(_spec(limits=SandboxLimits(max_output_bytes=4096)))
    finally:
        await manager.aclose()
    assert "\x1b" not in result.stdout
    assert result.stdout_truncated is True
    assert len(result.stdout) < 4_200


@pytest.mark.asyncio
async def test_never_finishing_operation_is_cancelled_and_reported():
    fake = FakeSandboxes()
    fake.never_finish = True
    manager = _manager(fake)
    try:
        result = await manager.run(_spec(limits=SandboxLimits(timeout_seconds=1)))
    finally:
        await manager.aclose()
    assert fake.cancelled == [OP_ID], "untrusted code must not be left running"
    assert result.status is SandboxStatus.ENGINE_ERROR and not result.succeeded
    assert "did not finish" in (result.error or "")


@pytest.mark.asyncio
async def test_networking_reported_enabled_is_refused_and_cancelled():
    fake = FakeSandboxes()
    fake.echo_networking = {"enabled": True}
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.ENGINE_ERROR and not result.succeeded
    assert "networking ENABLED" in (result.error or "")
    assert fake.cancelled == [OP_ID]


@pytest.mark.asyncio
async def test_missing_networking_echo_is_tolerated_but_still_requested_offline():
    fake = FakeSandboxes()
    fake.echo_networking = None
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.succeeded
    assert fake.spawned[0]["networking"] == {"enabled": False}


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [401, 403])
async def test_auth_failure_explains_beta_access_without_leaking_the_key(status):
    fake = FakeSandboxes()
    fake.spawn_status = status
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.ENGINE_ERROR
    assert "beta" in (result.error or "").lower() and "aiproject-test" in (result.error or "")
    assert "test-key-123456" not in (result.error or "")


@pytest.mark.asyncio
async def test_transient_503_is_retried():
    fake = FakeSandboxes()
    fake.flaky_503 = 2
    manager = _manager(fake)
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.succeeded


@pytest.mark.asyncio
async def test_unreachable_api_fails_closed():
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    manager = NebiusSandboxManager(
        api_key="k-123456", project_id="p", transport=httpx.MockTransport(boom), poll_interval=0.01
    )
    try:
        result = await manager.run(_spec())
    finally:
        await manager.aclose()
    assert result.status is SandboxStatus.ENGINE_ERROR and not result.succeeded


@pytest.mark.asyncio
async def test_unsafe_request_is_rejected_before_any_http_call():
    fake = FakeSandboxes()
    manager = _manager(fake)
    try:
        with pytest.raises(SandboxValidationError):
            await manager.run(_spec(command=("sh", "-c", "curl evil")))
    finally:
        await manager.aclose()
    assert fake.requests == []


@pytest.mark.asyncio
async def test_healthcheck_passes_and_learns_the_timeout_ceiling():
    fake = FakeSandboxes()
    fake.limits = {"instance_max_timeout": 30}
    manager = _manager(fake)
    try:
        await manager.healthcheck()
        await manager.run(_spec())
    finally:
        await manager.aclose()
    assert fake.spawned[0]["timeout"] == 30, "must not request more than the project allows"


@pytest.mark.asyncio
async def test_healthcheck_requires_spawn_permission():
    fake = FakeSandboxes()
    fake.permissions = {"list": True, "spawn": False, "spawn_disposable": False}
    manager = _manager(fake)
    try:
        with pytest.raises(NebiusSandboxError, match="cannot spawn"):
            await manager.healthcheck()
    finally:
        await manager.aclose()


@pytest.mark.asyncio
async def test_image_overrides_accept_tags_and_uuids(monkeypatch):
    monkeypatch.setenv("ARBALEST_NEBIUS_PYTHON_IMAGE", "tag:python:3.11-slim")
    monkeypatch.setenv("ARBALEST_NEBIUS_GO_IMAGE", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    fake = FakeSandboxes()
    manager = _manager(fake)
    try:
        await manager.run(_spec())
        await manager.run(_spec(runtime=SandboxRuntime.GO, command=("sh", "attack.sh")))
    finally:
        await manager.aclose()
    assert fake.spawned[0]["image"] == "tag:python:3.11-slim"
    assert fake.spawned[1]["image"] == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_invalid_image_reference_is_rejected(monkeypatch):
    monkeypatch.setenv("ARBALEST_NEBIUS_PYTHON_IMAGE", "bad image; rm -rf /")
    with pytest.raises(ValueError, match="Invalid sandbox image"):
        NebiusSandboxManager(api_key="k-123456", project_id="p")


@pytest.mark.asyncio
async def test_red_team_deployment_gate_works_with_this_backend():
    """The fail-closed verdict contract holds when the harness ran on Nebius."""
    from engine.agents.red_team_swarm import HARNESS_COMPLETED_MARKER, RedTeamResult, _deterministic_attack
    from engine.agents.architect_agent import ThreatFinding

    finding = ThreatFinding(finding_id="F", cwe="CWE-798", severity="high", summary="s", evidence=["e"],
                            affected_nodes=[])
    attack = _deterministic_attack([finding])
    fake = FakeSandboxes()
    fake.stdout = f"deterministic probe: signature not present\n{HARNESS_COMPLETED_MARKER}\n"
    manager = _manager(fake)
    try:
        sandbox = await manager.run(_spec(files={attack.filename: attack.content}, command=("sh", attack.filename)))
    finally:
        await manager.aclose()

    from engine.agents.red_team_swarm import AttackAnalysis

    clean = AttackAnalysis(exploit_successful=False, inconclusive=False, reasoning="r", evidence=[], confidence=0.4)
    result = RedTeamResult(attack=attack, sandbox=sandbox, analysis=clean)
    assert result.verification_held is True
    assert result.deployment_allowed is False
