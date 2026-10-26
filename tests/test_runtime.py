"""Shared CLI/MCP runtime: provider arming, path safety, MCP target confinement."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from engine.services import local_cli_provider, runtime
from engine.services.ai_provider import AIProviderName, NEBIUS_TOKEN_FACTORY_BASE_URL


def test_nebius_endpoint_is_token_factory():
    # The hackathon requires Nebius Token Factory; the old studio host is gone.
    assert NEBIUS_TOKEN_FACTORY_BASE_URL == "https://api.tokenfactory.nebius.com/v1/"


def test_build_provider_requires_a_key():
    with pytest.raises(RuntimeError, match="No API key armed"):
        runtime.build_provider("nebius", None)


@pytest.mark.parametrize("placeholder", ["your-nebius-api-key", "<paste-key>", "changeme", "REPLACE_ME"])
def test_build_provider_rejects_env_example_placeholder(monkeypatch, placeholder):
    monkeypatch.setenv("NEBIUS_API_KEY", placeholder)
    with pytest.raises(RuntimeError, match="placeholder"):
        runtime.build_provider("nebius", None)


@pytest.mark.asyncio
async def test_build_provider_arms_nebius_with_default_model(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    provider, name, model = runtime.build_provider(None, None)
    try:
        assert name == "nebius"
        assert model == runtime.DEFAULT_MODELS["nebius"]
    finally:
        await provider.aclose()


def test_nebius_default_is_the_ultra_tier():
    """Keep the operator-selected Ultra default without relaxing validation."""
    assert "ultra" in runtime.DEFAULT_MODELS["nebius"].lower()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_name", "command"),
    [
        (AIProviderName.CODEX_CLI.value, "codex"),
        (AIProviderName.CLAUDE_CLI.value, "claude"),
    ],
)
async def test_build_local_cli_provider_needs_no_key_and_uses_cli_default(monkeypatch, provider_name, command):
    resolved = f"C:/isolated-bin/{command}.exe"
    monkeypatch.setattr(local_cli_provider.shutil, "which", lambda name: resolved if name == command else None)

    provider, name, model = runtime.build_provider(provider_name, None)
    try:
        assert name == provider_name
        assert model == "cli-default"
        assert provider.settings.selected_model is None
        assert provider.settings.api_key.get_secret_value() == ""
        models = await provider.list_models()
        assert [(item.id, item.display_name) for item in models] == [
            ("cli-default", f"{'Codex' if command == 'codex' else 'Claude'} authenticated CLI-selected default")
        ]
    finally:
        await provider.aclose()

    selected_provider, _name, discovery_label = runtime.build_provider(provider_name, "explicit-model", discover=True)
    try:
        assert discovery_label is None
        assert selected_provider.settings.selected_model == "explicit-model"
        assert [item.id for item in await selected_provider.list_models()] == ["explicit-model"]
    finally:
        await selected_provider.aclose()


@pytest.mark.parametrize("provider_name", [AIProviderName.CODEX_CLI.value, AIProviderName.CLAUDE_CLI.value])
def test_build_local_cli_provider_requires_installed_executable(monkeypatch, provider_name):
    monkeypatch.setattr(local_cli_provider.shutil, "which", lambda _name: None)
    with pytest.raises(RuntimeError, match="executable.*not found on PATH"):
        runtime.build_provider(provider_name, None)


def test_ai_timeout_is_configurable_and_bounded(monkeypatch):
    from engine.services.ai_provider import _request_timeout

    monkeypatch.delenv("ARBALEST_AI_TIMEOUT", raising=False)
    assert _request_timeout() == 180.0
    monkeypatch.setenv("ARBALEST_AI_TIMEOUT", "5")
    assert _request_timeout() == 10.0
    monkeypatch.setenv("ARBALEST_AI_TIMEOUT", "99999")
    assert _request_timeout() == 900.0
    monkeypatch.setenv("ARBALEST_AI_TIMEOUT", "soon")
    assert _request_timeout() == 180.0


@pytest.mark.asyncio
async def test_build_provider_model_precedence(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    monkeypatch.setenv("ARBALEST_MODEL", "from-env")
    provider, _name, model = runtime.build_provider("nebius", None)
    await provider.aclose()
    assert model == "from-env"
    provider, _name, model = runtime.build_provider("nebius", "from-flag")
    await provider.aclose()
    assert model == "from-flag"


@pytest.mark.asyncio
async def test_discover_mode_selects_no_model(monkeypatch):
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    provider, _name, model = runtime.build_provider("nebius", None, discover=True)
    await provider.aclose()
    assert model is None


def test_env_file_tolerates_utf8_bom_and_never_overrides(tmp_path: Path, monkeypatch):
    (tmp_path / ".env").write_bytes("\ufeffARBALEST_TEST_A=from-file\nARBALEST_TEST_B='quoted'\n".encode("utf-8"))
    monkeypatch.delenv("ARBALEST_TEST_A", raising=False)
    monkeypatch.delenv("ARBALEST_SKIP_DOTENV", raising=False)  # the suite sets it globally
    monkeypatch.setenv("ARBALEST_TEST_B", "already-set")
    runtime.load_env_file([tmp_path])
    try:
        assert os.environ["ARBALEST_TEST_A"] == "from-file"  # BOM must not corrupt the first key
        assert os.environ["ARBALEST_TEST_B"] == "already-set"
    finally:
        os.environ.pop("ARBALEST_TEST_A", None)


@pytest.mark.parametrize("value", ["CWE-89", "SENT-PY-004", "finding_1.2"])
def test_safe_finding_id_accepts_real_ids(value):
    assert runtime.safe_finding_id(value) == value


@pytest.mark.parametrize("value", ["../../x", "a/b", "a\\b", "", "  ", "-lead", "x" * 65, "a b", "a;b"])
def test_safe_finding_id_rejects_traversal_and_junk(value):
    with pytest.raises(ValueError):
        runtime.safe_finding_id(value)


def test_resolve_inside_blocks_traversal(tmp_path: Path):
    assert runtime.resolve_inside(tmp_path, "src/a.py") == (tmp_path / "src" / "a.py").resolve()
    with pytest.raises(ValueError):
        runtime.resolve_inside(tmp_path, "../outside.py")


def test_resolve_bundle_paths_is_all_or_nothing(tmp_path: Path):
    with pytest.raises(ValueError):
        runtime.resolve_bundle_paths(tmp_path, ["ok.py", "../escape.py"])
    assert not (tmp_path.parent / "escape.py").exists()


@pytest.mark.skipif(os.name == "nt", reason="symlink creation needs elevated rights on Windows")
def test_resolve_inside_blocks_symlink_escape(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError):
        runtime.resolve_inside(root, "link/payload.py")


def test_mcp_target_is_denied_without_allowlist_or_explicit_unsafe_opt_in(tmp_path: Path, monkeypatch):
    monkeypatch.delenv(runtime.ALLOWED_ROOTS_ENV, raising=False)
    monkeypatch.delenv(runtime.UNSAFE_ALLOW_ANY_ROOT_ENV, raising=False)
    with pytest.raises(PermissionError, match="filesystem access is disabled"):
        runtime.resolve_target(str(tmp_path))
    monkeypatch.setenv(runtime.UNSAFE_ALLOW_ANY_ROOT_ENV, "1")
    assert runtime.resolve_target(str(tmp_path)) == tmp_path.resolve()


def test_mcp_target_confined_to_allowed_roots(tmp_path: Path, monkeypatch):
    allowed = tmp_path / "workspace"
    allowed.mkdir()
    other = tmp_path / "elsewhere"
    other.mkdir()
    monkeypatch.setenv(runtime.ALLOWED_ROOTS_ENV, str(allowed))
    assert runtime.resolve_target(str(allowed / "repo")) == (allowed / "repo").resolve()
    with pytest.raises(PermissionError):
        runtime.resolve_target(str(other))
    with pytest.raises(PermissionError):
        runtime.resolve_target(str(allowed / ".." / "elsewhere"))


def _clear_sandbox_env(monkeypatch):
    for var in ("ARBALEST_SANDBOX_BACKEND", "NEBIUS_PROJECT_ID", "NEBIUS_API_KEY"):
        monkeypatch.delenv(var, raising=False)


def test_sandbox_backend_auto_falls_back_to_docker_without_a_project(monkeypatch):
    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    assert runtime.sandbox_backend() == "docker"


def test_sandbox_backend_auto_prefers_nebius_when_configured(monkeypatch):
    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    monkeypatch.setenv("NEBIUS_PROJECT_ID", "aiproject-test")
    assert runtime.sandbox_backend() == "nebius"
    assert "aiproject-test" in runtime.sandbox_label()


def test_sandbox_backend_explicit_choice_wins(monkeypatch):
    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    monkeypatch.setenv("NEBIUS_PROJECT_ID", "aiproject-test")
    monkeypatch.setenv("ARBALEST_SANDBOX_BACKEND", "docker")
    assert runtime.sandbox_backend() == "docker"


def test_sandbox_backend_rejects_unknown_value(monkeypatch):
    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("ARBALEST_SANDBOX_BACKEND", "firecracker")
    with pytest.raises(RuntimeError, match="must be one of"):
        runtime.sandbox_backend()


def test_build_sandbox_manager_returns_the_nebius_backend(monkeypatch):
    from engine.services.nebius_sandbox import NebiusSandboxManager

    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    monkeypatch.setenv("NEBIUS_PROJECT_ID", "aiproject-test")
    manager = runtime.build_sandbox_manager()
    assert isinstance(manager, NebiusSandboxManager)
    assert manager.project_id == "aiproject-test"


def test_explicit_nebius_without_a_project_is_a_clear_error(monkeypatch):
    _clear_sandbox_env(monkeypatch)
    monkeypatch.setenv("ARBALEST_SANDBOX_BACKEND", "nebius")
    monkeypatch.setenv("NEBIUS_API_KEY", "real-looking-key-123456")
    with pytest.raises(RuntimeError, match="NEBIUS_PROJECT_ID"):
        runtime.build_sandbox_manager()


def test_skip_dotenv_switch_prevents_loading_a_real_env_file(tmp_path: Path, monkeypatch):
    """The test suite relies on this so a developer's real key is never read."""
    (tmp_path / ".env").write_text("ARBALEST_TEST_SKIP=leaked\n", encoding="utf-8")
    monkeypatch.delenv("ARBALEST_TEST_SKIP", raising=False)
    monkeypatch.setenv("ARBALEST_SKIP_DOTENV", "1")
    runtime.load_env_file([tmp_path])
    assert "ARBALEST_TEST_SKIP" not in os.environ


# ── Provider catalog: API presets, gateways, local, and operator endpoints ────

@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("provider_name", "key_var", "expected_host"),
    [
        ("google", "GEMINI_API_KEY", "generativelanguage.googleapis.com"),
        ("mistral", "MISTRAL_API_KEY", "api.mistral.ai"),
        ("deepseek", "DEEPSEEK_API_KEY", "api.deepseek.com"),
        ("xai", "XAI_API_KEY", "api.x.ai"),
        ("groq", "GROQ_API_KEY", "api.groq.com"),
        ("openrouter", "OPENROUTER_API_KEY", "openrouter.ai"),
    ],
)
async def test_catalog_presets_use_their_own_key_and_endpoint(monkeypatch, provider_name, key_var, expected_host):
    monkeypatch.setenv(key_var, "real-looking-key-123456")
    provider, name, model = runtime.build_provider(provider_name, "some-model")
    try:
        assert name == provider_name and model == "some-model"
        assert expected_host in str(provider._client.base_url)  # type: ignore[attr-defined]
    finally:
        await provider.aclose()


def test_presets_never_borrow_another_vendors_key(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "real-looking-key-123456")
    with pytest.raises(RuntimeError, match="No API key armed.*DEEPSEEK_API_KEY"):
        runtime.build_provider("deepseek", "deepseek-chat")


@pytest.mark.asyncio
async def test_local_ollama_needs_no_key(monkeypatch):
    provider, _name, _model = runtime.build_provider("ollama", "llama3.3")
    try:
        assert "127.0.0.1:11434" in str(provider._client.base_url)  # type: ignore[attr-defined]
    finally:
        await provider.aclose()


def test_nebius_remains_the_default_provider():
    assert runtime.DEFAULT_PROVIDER == "nebius"
    assert "nebius" in runtime.PROVIDER_KEY_ENV


def test_custom_anthropic_requires_base_url(monkeypatch):
    monkeypatch.setenv("AI_ANTHROPIC_API_KEY", "real-looking-key-123456")
    with pytest.raises(RuntimeError, match="AI_ANTHROPIC_BASE_URL"):
        runtime.build_provider("custom-anthropic", "m")


@pytest.mark.asyncio
async def test_operator_defined_provider_reads_generated_key_variable(monkeypatch, tmp_path: Path):
    config = tmp_path / "providers.json"
    config.write_text(
        '{"providers": {"corp-gateway": {"api_url": "https://llm.corp.example/v1",'
        ' "protocol": "openai_chat", "default_model": "corp-large"}}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("ARBALEST_PROVIDERS_FILE", str(config))
    monkeypatch.setenv("CORP_GATEWAY_API_KEY", "real-looking-key-123456")
    provider, name, model = runtime.build_provider("corp-gateway", None)
    try:
        assert name == "corp-gateway" and model == "corp-large"
        assert "llm.corp.example" in str(provider._client.base_url)  # type: ignore[attr-defined]
    finally:
        await provider.aclose()


def test_operator_provider_file_rejects_inline_credentials(monkeypatch, tmp_path: Path):
    config = tmp_path / "providers.json"
    config.write_text(
        '{"providers": {"leaky": {"api_url": "https://x.example/v1", "api_key": "sk-should-not-be-here"}}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("ARBALEST_PROVIDERS_FILE", str(config))
    with pytest.raises(RuntimeError, match="must not contain credentials"):
        runtime.build_provider("leaky", "m")


def test_operator_provider_cannot_shadow_builtin(monkeypatch, tmp_path: Path):
    config = tmp_path / "providers.json"
    config.write_text('{"providers": {"nebius": {"api_url": "https://evil.example/v1"}}}', encoding="utf-8")
    monkeypatch.setenv("ARBALEST_PROVIDERS_FILE", str(config))
    with pytest.raises(RuntimeError, match="collides with a built-in"):
        runtime.build_provider("nebius", None)


def test_provider_status_rows_never_leak_key_values(monkeypatch):
    monkeypatch.setenv("MISTRAL_API_KEY", "real-looking-secret-value-987")
    rows = runtime.provider_status_rows()
    assert any(row["id"] == "mistral" and row["status"] == "ready (key set)" for row in rows)
    assert "real-looking-secret-value-987" not in repr(rows)
