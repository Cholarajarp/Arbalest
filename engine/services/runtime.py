"""Shared runtime wiring for the CLI and the MCP server.

Both entry points need the same provider configuration, sandbox images,
``.env`` loading and input hygiene. Keeping that in one module means a fix
(for example an endpoint change or a path-safety rule) cannot be applied to
one front end and forgotten in the other.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from engine.services.ai_provider import AIProvider, AIProviderSettings, create_ai_provider
from engine.services.docker_manager import DockerSandboxManager, SandboxBackend, SandboxRuntime
from engine.services.nebius_sandbox import NebiusSandboxManager
from engine.services.provider_catalog import (
    ProviderCatalogError,
    ProviderProtocol,
    builtin_specs,
    get_provider_spec,
    provider_specs,
)

DEFAULT_PROVIDER = "nebius"

logger = logging.getLogger("arbalest.runtime")

# Optional per-role model routing on top of the globally selected provider
# model: a strong model can review code while a fast one summarizes intel.
# Overrides are id-validated and ignored when the transport cannot honor them.
ROLE_MODEL_ENV = "ARBALEST_MODEL_{role}"
_ROLE_MODEL_PATTERN = re.compile(r"^[\w./:@-]{1,160}$")


def model_for(role: str) -> str | None:
    """Environment override for one agent role's model, or None."""
    value = os.environ.get(ROLE_MODEL_ENV.format(role=role.upper()), "").strip()
    if not value:
        return None
    if not _ROLE_MODEL_PATTERN.fullmatch(value):
        logger.warning("Ignoring invalid %s value", ROLE_MODEL_ENV.format(role=role.upper()))
        return None
    return value


def _catalog_key_env() -> dict[str, list[str]]:
    try:
        specs = provider_specs()
    except ProviderCatalogError:
        # A malformed operator file must not hide the built-ins; build_provider
        # reports the file error when a provider is actually selected.
        specs = builtin_specs()
    return {provider_id: list(spec.key_env) for provider_id, spec in sorted(specs.items())}


# Provider id -> candidate key variables. Derived from the catalog so CLI
# choices and MCP enums include every built-in and operator-defined provider.
PROVIDER_KEY_ENV: dict[str, list[str]] = _catalog_key_env()

# Ultra is the operator-selected default for planning and code generation.
# Every model's output still requires schema and semantic validation.
# Model ids change: `arbalest models` lists what your key can use.
# Override with `-m <id>` or ARBALEST_MODEL.
DEFAULT_MODELS: dict[str, str] = {"nebius": "nvidia/Nemotron-3-Ultra-550b-a55b"}

# Images for the LOCAL DOCKER backend only (the Nebius backend has its own list
# in nebius_sandbox.py). Pinned by tag here and allowed to float only because
# ARBALEST_ENVIRONMENT=staging is set for local runs; production deployments
# must pin digests via the ARBALEST_SANDBOX_* vars.
SANDBOX_IMAGES: dict[SandboxRuntime, str] = {
    SandboxRuntime.PYTHON: "python:3.12-slim",
    SandboxRuntime.TYPESCRIPT: "node:20-alpine",
    SandboxRuntime.RUST: "rust:1.77-slim",
    SandboxRuntime.GO: "golang:1.22-alpine",
}

ALLOWED_ROOTS_ENV = "ARBALEST_MCP_ALLOWED_ROOTS"
UNSAFE_ALLOW_ANY_ROOT_ENV = "ARBALEST_MCP_UNSAFE_ALLOW_ANY_ROOT"

_PLACEHOLDER_KEY = re.compile(r"(?i)^(?:your[-_ ]|<|changeme|replace|xxx|todo)")
_FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def load_env_file(search_dirs: Iterable[Path]) -> None:
    """Load the first readable ``.env`` found. Variables already set win.

    Set ``ARBALEST_SKIP_DOTENV=1`` to skip loading entirely. The test suite does
    this so a developer's real ``.env`` can never arm the AI core or spend credits.
    """
    if os.environ.get("ARBALEST_SKIP_DOTENV", "").strip() not in ("", "0"):
        return
    for directory in search_dirs:
        candidate = Path(directory) / ".env"
        if not candidate.is_file():
            continue
        try:
            # utf-8-sig: Windows editors often write a BOM, which would
            # otherwise corrupt the first variable name.
            for raw in candidate.read_text(encoding="utf-8-sig").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key, value = key.strip(), value.strip().strip("'\"")
                if key and key not in os.environ:
                    os.environ[key] = value
        except OSError:
            continue
        break


def resolve_api_key(provider: str) -> tuple[str | None, list[str]]:
    """Return a provider-specific key without cross-vendor fallback."""
    try:
        candidates = list(get_provider_spec(provider).key_env)
    except ProviderCatalogError:
        candidates = []
    for variable in candidates:
        value = os.environ.get(variable, "").strip()
        if value:
            return value, candidates
    return None, candidates


def build_provider(
    provider_name: str | None,
    model_name: str | None,
    *,
    discover: bool = False,
) -> tuple[AIProvider, str, str | None]:
    """Build the real AI core, or raise ``RuntimeError`` with an actionable message.

    ``discover=True`` skips model selection so ``arbalest models`` can list what
    the key can use before any model has been chosen.
    """
    provider = (provider_name or os.environ.get("ARBALEST_PROVIDER") or DEFAULT_PROVIDER).strip().lower()
    try:
        spec = get_provider_spec(provider)
    except ProviderCatalogError as exc:
        raise RuntimeError(str(exc)) from exc
    base_url = (os.environ.get(spec.base_url_env, "").strip() or None) if spec.base_url_env else None
    if base_url is None and spec.user_defined:
        base_url = spec.base_url
    api_key, candidates = resolve_api_key(provider)
    is_local_session = spec.protocol is ProviderProtocol.LOCAL_CLI
    if spec.base_url_required and not base_url:
        if spec.protocol is ProviderProtocol.ANTHROPIC:
            example = "https://gateway.example.com/v1/"
        else:
            example = "http://127.0.0.1:11434/v1"
        raise RuntimeError(
            f"{spec.display_name} provider requires {spec.base_url_env} (for example {example})."
        )
    if spec.key_optional and not api_key:
        # Keyless local/self-hosted endpoint; the SDK still needs a placeholder.
        api_key = "local-no-key"
    if not is_local_session and not api_key:
        raise RuntimeError(
            f"No API key armed for provider '{provider}'. Set one of: {', '.join(candidates)} (see .env.example)."
        )
    if api_key and _PLACEHOLDER_KEY.match(api_key):
        raise RuntimeError(
            f"The API key for provider '{provider}' is still the .env.example placeholder. "
            "Put your real key in .env."
        )
    selected_model: str | None = None
    model_label: str | None = None
    if discover and is_local_session:
        selected_model = model_name or os.environ.get("ARBALEST_MODEL") or None
    elif not discover:
        selected_model = (
            model_name or os.environ.get("ARBALEST_MODEL") or DEFAULT_MODELS.get(provider) or spec.default_model
        )
        if not selected_model and not is_local_session:
            raise RuntimeError(
                f"No model selected for provider '{provider}'. Pass --model or set ARBALEST_MODEL."
            )
        model_label = selected_model or "cli-default"
    try:
        settings = AIProviderSettings(
            provider=provider,
            api_key=api_key or "",
            base_url=base_url,
            selected_model=selected_model,
        )
        return create_ai_provider(settings), provider, model_label
    except (ValidationError, ValueError) as exc:
        raise RuntimeError(f"Invalid AI provider configuration: {exc}") from exc


def provider_status_rows() -> list[dict[str, str]]:
    """Offline readiness of every catalog provider. Never prints or returns secrets."""
    import shutil

    try:
        specs = provider_specs()
        catalog_error = ""
    except ProviderCatalogError as exc:
        specs = builtin_specs()
        catalog_error = str(exc)
    rows: list[dict[str, str]] = []
    for provider_id, spec in sorted(specs.items()):
        if spec.protocol is ProviderProtocol.LOCAL_CLI:
            command = "codex" if provider_id == "codex-cli" else "claude"
            ready = "ready (CLI found)" if shutil.which(command) else f"missing `{command}` on PATH"
            credential = "existing CLI sign-in"
        else:
            key, candidates = resolve_api_key(provider_id)
            has_url = bool(
                (spec.base_url_env and os.environ.get(spec.base_url_env, "").strip()) or spec.base_url
            )
            if spec.base_url_required and not (spec.base_url_env and os.environ.get(spec.base_url_env, "").strip()):
                ready = f"needs {spec.base_url_env}"
            elif key and not _PLACEHOLDER_KEY.match(key):
                ready = "ready (key set)"
            elif spec.key_optional and has_url:
                ready = "keyless local endpoint (start the server)"
            else:
                ready = "no key"
            credential = " | ".join(candidates) or "-"
        rows.append({
            "id": provider_id,
            "name": spec.display_name + (" [default]" if provider_id == DEFAULT_PROVIDER else ""),
            "protocol": spec.protocol.value,
            "category": spec.category,
            "credential": credential,
            "status": ready,
        })
    if catalog_error:
        rows.append({"id": "!", "name": "provider file error", "protocol": "-", "category": "-",
                     "credential": "-", "status": catalog_error[:200]})
    return rows


SANDBOX_BACKEND_ENV = "ARBALEST_SANDBOX_BACKEND"
_BACKENDS = ("auto", "nebius", "docker")


def sandbox_backend() -> str:
    """Which verification sandbox to use: ``nebius`` or ``docker``.

    ``ARBALEST_SANDBOX_BACKEND`` may be ``nebius``, ``docker`` or ``auto``
    (default). ``auto`` picks Nebius Token Factory Sandboxes whenever
    ``NEBIUS_PROJECT_ID`` and a Nebius key are set, otherwise local Docker.
    """
    choice = os.environ.get(SANDBOX_BACKEND_ENV, "auto").strip().lower() or "auto"
    if choice not in _BACKENDS:
        raise RuntimeError(f"{SANDBOX_BACKEND_ENV} must be one of: {', '.join(_BACKENDS)} (got {choice!r})")
    if choice != "auto":
        return choice
    has_project = bool(os.environ.get("NEBIUS_PROJECT_ID", "").strip())
    has_key = bool(os.environ.get("NEBIUS_API_KEY", "").strip())
    return "nebius" if has_project and has_key else "docker"


def sandbox_label() -> str:
    """One-line description of the selected backend for the UI. Makes no network call."""
    backend = sandbox_backend()
    if backend == "nebius":
        project = os.environ.get("NEBIUS_PROJECT_ID", "").strip() or "no project id"
        return f"NEBIUS SANDBOXES (project {project}) - run `arbalest sandbox-check` to verify"
    return "LOCAL DOCKER"


def build_sandbox_manager() -> SandboxBackend:
    """Build the verification sandbox: Nebius Token Factory Sandboxes or local Docker."""
    backend = sandbox_backend()
    if backend == "nebius":
        try:
            return NebiusSandboxManager()
        except ValueError as exc:
            raise RuntimeError(f"Nebius Sandboxes backend is not configured: {exc}") from exc
    implicit_staging = not os.environ.get("ARBALEST_ENVIRONMENT", "").strip()
    if implicit_staging:
        # Keep out-of-the-box Docker usable (floating tags), but say so: the
        # digest-pinning interlock only arms when the operator explicitly
        # selects a production environment.
        logger.warning(
            "ARBALEST_ENVIRONMENT unset — running in implicit staging mode with mutable image tags. "
            "Set ARBALEST_ENVIRONMENT=production and digest-pinned ARBALEST_*_IMAGE values "
            "to enforce the supply-chain interlock for unverified model code."
        )
    os.environ.setdefault("ARBALEST_ENVIRONMENT", "staging")
    return DockerSandboxManager(images=dict(SANDBOX_IMAGES))


def safe_finding_id(value: str) -> str:
    """Validate a finding identifier that becomes part of a patch file name.

    Without this, ``--finding ../../x`` (or an MCP client passing the same)
    would write ``arbalest-fix-../../x.patch`` outside the target directory.
    """
    cleaned = (value or "").strip()
    if not _FINDING_ID.fullmatch(cleaned):
        raise ValueError(
            "Finding id must be 1-64 characters of letters, digits, '.', '_' or '-' (for example CWE-89)."
        )
    return cleaned


def resolve_inside(root: Path, relative: str) -> Path:
    """Resolve ``relative`` under ``root``, rejecting traversal and symlink escapes."""
    base = Path(root).resolve()
    candidate = (base / relative).resolve()
    if candidate != base and base not in candidate.parents:
        raise ValueError(f"path escapes the target directory: {relative!r}")
    return candidate


def resolve_bundle_paths(root: Path, relative_paths: Iterable[str]) -> dict[str, Path]:
    """Validate every generated path before any file is written (all or nothing)."""
    return {rel: resolve_inside(root, rel) for rel in relative_paths}


def resolve_target(raw: str) -> Path:
    """Resolve an MCP target under an explicit operator-controlled allow-list.

    MCP callers may be models, so host filesystem access is denied by default.
    A local operator can deliberately restore legacy unrestricted behavior with
    ``ARBALEST_MCP_UNSAFE_ALLOW_ANY_ROOT=1``; production deployments must never
    set that escape hatch.
    """
    path = Path(raw).expanduser().resolve()
    configured = [item for item in os.environ.get(ALLOWED_ROOTS_ENV, "").split(os.pathsep) if item.strip()]
    if not configured:
        unsafe = os.environ.get(UNSAFE_ALLOW_ANY_ROOT_ENV, "").strip().lower()
        if unsafe not in {"1", "true", "yes"}:
            raise PermissionError(
                f"MCP filesystem access is disabled until {ALLOWED_ROOTS_ENV} is configured; "
                f"set {UNSAFE_ALLOW_ANY_ROOT_ENV}=1 only for an isolated local process"
            )
        return path
    roots = [Path(item).expanduser().resolve() for item in configured]
    if not any(path == root or root in path.parents for root in roots):
        raise PermissionError(f"target is outside {ALLOWED_ROOTS_ENV}: {path}")
    return path
