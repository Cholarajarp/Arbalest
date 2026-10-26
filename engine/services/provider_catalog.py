"""Declarative catalog of every inference provider Arbalest can drive.

Each provider is described once: wire protocol, default endpoint, the
environment variables that may hold its key, and whether a key is optional.
Runtime, CLI, and MCP all derive their provider lists from this catalog, so a
provider added here is immediately selectable everywhere.

Operators can add named endpoints without code changes through a JSON file
(``ARBALEST_PROVIDERS_FILE``, ``./arbalest.providers.json``, or
``~/.arbalest/providers.json``). Keys never live in that file: a provider with
id ``my-gateway`` reads ``MY_GATEWAY_API_KEY``.

This module deliberately imports nothing from the provider adapters so it can
be used by error redaction and argument parsing without import cycles.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path


class ProviderProtocol(StrEnum):
    """Wire protocol an adapter speaks."""

    OPENAI_CHAT = "openai_chat"            # /v1/chat/completions (portable)
    OPENAI_RESPONSES = "openai_responses"  # native OpenAI Responses API
    ANTHROPIC = "anthropic"                # /v1/messages
    LOCAL_CLI = "local_cli"                # authenticated official CLI session


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    id: str
    display_name: str
    protocol: ProviderProtocol
    key_env: tuple[str, ...] = ()
    base_url: str | None = None
    base_url_env: str | None = None
    key_optional: bool = False
    base_url_required: bool = False
    default_model: str | None = None
    category: str = "api"   # api | gateway | local | subscription | custom
    user_defined: bool = False

    @property
    def needs_key(self) -> bool:
        return self.protocol is not ProviderProtocol.LOCAL_CLI and not self.key_optional


NEBIUS_TOKEN_FACTORY_BASE_URL = "https://api.tokenfactory.nebius.com/v1/"
NEBIUS_DEFAULT_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"

_BUILTINS: tuple[ProviderSpec, ...] = (
    # Default hackathon path: Nebius Token Factory + NVIDIA Nemotron.
    ProviderSpec("nebius", "Nebius Token Factory", ProviderProtocol.OPENAI_CHAT,
                 ("NEBIUS_API_KEY", "AI_API_KEY"), NEBIUS_TOKEN_FACTORY_BASE_URL, "AI_BASE_URL",
                 default_model=NEBIUS_DEFAULT_MODEL),
    # First-party APIs.
    ProviderSpec("openai", "OpenAI (Responses API)", ProviderProtocol.OPENAI_RESPONSES,
                 ("OPENAI_API_KEY",), None, "OPENAI_BASE_URL"),
    ProviderSpec("anthropic", "Anthropic (Messages API)", ProviderProtocol.ANTHROPIC,
                 ("ANTHROPIC_API_KEY",), "https://api.anthropic.com/v1/", "ANTHROPIC_BASE_URL"),
    ProviderSpec("google", "Google AI (Gemini)", ProviderProtocol.OPENAI_CHAT,
                 ("GEMINI_API_KEY", "GOOGLE_AI_API_KEY"),
                 "https://generativelanguage.googleapis.com/v1beta/openai/", "GEMINI_BASE_URL"),
    ProviderSpec("mistral", "Mistral", ProviderProtocol.OPENAI_CHAT,
                 ("MISTRAL_API_KEY",), "https://api.mistral.ai/v1/", "MISTRAL_BASE_URL"),
    ProviderSpec("deepseek", "DeepSeek", ProviderProtocol.OPENAI_CHAT,
                 ("DEEPSEEK_API_KEY",), "https://api.deepseek.com/v1/", "DEEPSEEK_BASE_URL"),
    ProviderSpec("xai", "xAI (Grok)", ProviderProtocol.OPENAI_CHAT,
                 ("XAI_API_KEY",), "https://api.x.ai/v1/", "XAI_BASE_URL"),
    ProviderSpec("groq", "Groq", ProviderProtocol.OPENAI_CHAT,
                 ("GROQ_API_KEY",), "https://api.groq.com/openai/v1/", "GROQ_BASE_URL"),
    ProviderSpec("together", "Together AI", ProviderProtocol.OPENAI_CHAT,
                 ("TOGETHER_API_KEY",), "https://api.together.xyz/v1/", "TOGETHER_BASE_URL"),
    ProviderSpec("fireworks", "Fireworks AI", ProviderProtocol.OPENAI_CHAT,
                 ("FIREWORKS_API_KEY",), "https://api.fireworks.ai/inference/v1/", "FIREWORKS_BASE_URL"),
    ProviderSpec("cerebras", "Cerebras", ProviderProtocol.OPENAI_CHAT,
                 ("CEREBRAS_API_KEY",), "https://api.cerebras.ai/v1/", "CEREBRAS_BASE_URL"),
    # Gateways.
    ProviderSpec("openrouter", "OpenRouter", ProviderProtocol.OPENAI_CHAT,
                 ("OPENROUTER_API_KEY",), "https://openrouter.ai/api/v1/", "OPENROUTER_BASE_URL",
                 category="gateway"),
    ProviderSpec("vercel", "Vercel AI Gateway", ProviderProtocol.OPENAI_CHAT,
                 ("VERCEL_AI_GATEWAY_API_KEY",), "https://ai-gateway.vercel.sh/v1/", "VERCEL_AI_GATEWAY_BASE_URL",
                 category="gateway"),
    # Local / self-hosted.
    ProviderSpec("ollama", "Ollama (local)", ProviderProtocol.OPENAI_CHAT,
                 ("OLLAMA_API_KEY",), "http://127.0.0.1:11434/v1/", "OLLAMA_BASE_URL",
                 key_optional=True, category="local"),
    ProviderSpec("lmstudio", "LM Studio (local)", ProviderProtocol.OPENAI_CHAT,
                 ("LMSTUDIO_API_KEY",), "http://127.0.0.1:1234/v1/", "LMSTUDIO_BASE_URL",
                 key_optional=True, category="local"),
    # Generic compatible endpoints (vLLM, TGI, LiteLLM, enterprise gateways).
    ProviderSpec("custom", "Custom OpenAI-compatible", ProviderProtocol.OPENAI_CHAT,
                 ("AI_API_KEY",), None, "AI_BASE_URL", key_optional=True, base_url_required=True,
                 category="custom"),
    ProviderSpec("custom-responses", "Custom OpenAI Responses-compatible", ProviderProtocol.OPENAI_RESPONSES,
                 ("AI_API_KEY",), None, "AI_BASE_URL", key_optional=True, base_url_required=True,
                 category="custom"),
    ProviderSpec("custom-anthropic", "Custom Anthropic-compatible", ProviderProtocol.ANTHROPIC,
                 ("AI_ANTHROPIC_API_KEY",), None, "AI_ANTHROPIC_BASE_URL", base_url_required=True,
                 category="custom"),
    # Existing subscriptions through official authenticated CLIs.
    ProviderSpec("codex-cli", "Codex CLI (ChatGPT sign-in)", ProviderProtocol.LOCAL_CLI, category="subscription"),
    ProviderSpec("claude-cli", "Claude Code CLI (Claude sign-in)", ProviderProtocol.LOCAL_CLI, category="subscription"),
)

PROVIDERS_FILE_ENV = "ARBALEST_PROVIDERS_FILE"
_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_USER_PROTOCOLS = {
    ProviderProtocol.OPENAI_CHAT.value,
    ProviderProtocol.OPENAI_RESPONSES.value,
    ProviderProtocol.ANTHROPIC.value,
}


class ProviderCatalogError(ValueError):
    """The provider catalog or a user provider definition is invalid."""


def key_env_for(provider_id: str) -> str:
    """Zed-style generated key variable: ``my-gateway`` -> ``MY_GATEWAY_API_KEY``."""
    return re.sub(r"[^A-Z0-9]", "_", provider_id.upper()) + "_API_KEY"


def _candidate_files() -> list[Path]:
    explicit = os.environ.get(PROVIDERS_FILE_ENV, "").strip()
    if explicit:
        return [Path(explicit).expanduser()]
    return [Path.cwd() / "arbalest.providers.json", Path.home() / ".arbalest" / "providers.json"]


def _load_user_specs() -> list[ProviderSpec]:
    """Load operator-defined endpoints. The file holds endpoints, never keys."""
    for path in _candidate_files():
        if not path.is_file():
            continue
        try:
            if path.stat().st_size > 256 * 1024:
                raise ProviderCatalogError(f"{path} exceeds 256 KiB")
            document = json.loads(path.read_text(encoding="utf-8-sig"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ProviderCatalogError(f"could not read provider file {path}: {exc}") from exc
        providers = document.get("providers") if isinstance(document, dict) else None
        if not isinstance(providers, dict):
            raise ProviderCatalogError(f"{path} must contain a top-level 'providers' object")
        specs: list[ProviderSpec] = []
        for provider_id, entry in list(providers.items())[:64]:
            specs.append(_parse_user_spec(str(provider_id), entry, path))
        return specs
    return []


def _parse_user_spec(provider_id: str, entry: object, path: Path) -> ProviderSpec:
    if not _ID.fullmatch(provider_id):
        raise ProviderCatalogError(f"{path}: provider id {provider_id!r} must be lowercase letters, digits, '-' or '_'")
    if not isinstance(entry, dict):
        raise ProviderCatalogError(f"{path}: provider {provider_id!r} must be an object")
    forbidden = {"api_key", "key", "token", "secret", "authorization"} & {str(k).lower() for k in entry}
    if forbidden:
        raise ProviderCatalogError(
            f"{path}: provider {provider_id!r} must not contain credentials; set {key_env_for(provider_id)} instead"
        )
    protocol = str(entry.get("protocol", ProviderProtocol.OPENAI_CHAT.value))
    if protocol not in _USER_PROTOCOLS:
        raise ProviderCatalogError(f"{path}: provider {provider_id!r} protocol must be one of {sorted(_USER_PROTOCOLS)}")
    api_url = entry.get("api_url")
    if not isinstance(api_url, str) or not re.fullmatch(r"https?://[^\s]+", api_url.strip()):
        raise ProviderCatalogError(f"{path}: provider {provider_id!r} needs an absolute http(s) 'api_url'")
    model = entry.get("default_model")
    if model is not None and (not isinstance(model, str) or not 0 < len(model) <= 256):
        raise ProviderCatalogError(f"{path}: provider {provider_id!r} default_model must be a string")
    return ProviderSpec(
        id=provider_id,
        display_name=str(entry.get("display_name") or provider_id)[:128],
        protocol=ProviderProtocol(protocol),
        key_env=(key_env_for(provider_id),),
        base_url=api_url.strip().rstrip("/") + "/",
        key_optional=bool(entry.get("key_optional", False)),
        default_model=model,
        category="custom",
        user_defined=True,
    )


def provider_specs() -> dict[str, ProviderSpec]:
    """Built-ins plus operator endpoints. Built-in ids cannot be overridden."""
    specs = {spec.id: spec for spec in _BUILTINS}
    for spec in _load_user_specs():
        if spec.id in specs:
            raise ProviderCatalogError(f"user provider {spec.id!r} collides with a built-in provider id")
        specs[spec.id] = spec
    return specs


def builtin_specs() -> dict[str, ProviderSpec]:
    return {spec.id: spec for spec in _BUILTINS}


def builtin_provider_ids() -> list[str]:
    return sorted(spec.id for spec in _BUILTINS)


def provider_ids() -> list[str]:
    try:
        return sorted(provider_specs())
    except ProviderCatalogError:
        return builtin_provider_ids()


def get_provider_spec(provider_id: str) -> ProviderSpec:
    specs = provider_specs()
    spec = specs.get(provider_id)
    if spec is None:
        raise ProviderCatalogError(f"Unsupported AI provider '{provider_id}'. Choose one of: {', '.join(sorted(specs))}.")
    return spec


def all_key_env_names() -> set[str]:
    """Every variable that may hold a provider secret, for error redaction."""
    names = {name for spec in _BUILTINS for name in spec.key_env}
    try:
        names.update(name for spec in _load_user_specs() for name in spec.key_env)
    except ProviderCatalogError:
        pass
    return names


__all__ = [
    "NEBIUS_DEFAULT_MODEL",
    "NEBIUS_TOKEN_FACTORY_BASE_URL",
    "PROVIDERS_FILE_ENV",
    "ProviderCatalogError",
    "ProviderProtocol",
    "ProviderSpec",
    "all_key_env_names",
    "builtin_provider_ids",
    "builtin_specs",
    "get_provider_spec",
    "key_env_for",
    "provider_ids",
    "provider_specs",
]
