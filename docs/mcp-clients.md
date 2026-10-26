# MCP clients and BYOK providers

Arbalest separates two independent choices:

1. **MCP client:** Kiro, Claude Code, Codex CLI/IDE, ChatGPT desktop, Cursor, VS Code, Windsurf, Cline, Roo Code, or another stdio MCP host.
2. **Who does the reasoning:**
   - **Host-agent mode (no key):** the client's own model and subscription. Use `prepare_remediation_context`, `submit_remediation_candidate`, and `verify_remediation_candidate`. Arbalest grounds, validates, seals, and verifies.
   - **Subscription CLI:** `ARBALEST_PROVIDER=claude-cli` or `codex-cli` runs the official signed-in CLI for every agent.
   - **API key:** `nebius` (default) or any catalog provider: `openai`, `anthropic`, `google`, `mistral`, `deepseek`, `xai`, `groq`, `together`, `fireworks`, `cerebras`, `openrouter`, `vercel`, `ollama`, `lmstudio`, `custom`, `custom-responses`, `custom-anthropic`, or a named endpoint in `arbalest.providers.json`.

A client login never flows to Arbalest implicitly. Choose host-agent tools or a `*-cli` provider deliberately. Run `arbalest providers` to see what is ready.

## Host-agent workflow

1. `scan_repository` (or your own review) identifies a finding such as `CWE-89`.
2. `prepare_remediation_context {target_path, finding}` returns the grounded finding, a bounded architecture graph, secret-redacted sources with hashes, the `MutationPlan` and `GeneratedCodeBundle` JSON schemas, and a `context_digest`.
3. The host model writes a plan and bundle, then calls `submit_remediation_candidate` with the digest. Stale context, invented files or graph nodes, unsafe paths, oversized bundles, and unsafe Rust/Go are rejected. The result is an immutable artifact and a reviewable patch; nothing is applied.
4. `verify_remediation_candidate {target_path, finding, artifact, attack?}` runs the exact bytes in the sandbox. A host-supplied harness passes the same policy gateway as model harnesses. The verdict is computed server-side.
5. Deploy only through the reviewed CLI flow.

## Install the MCP command

```powershell
uv sync --frozen
uv run arbalest-mcp
```

A wheel installation also provides `arbalest-mcp`:

```powershell
pip install .\dist\arbalest-1.0.0-py3-none-any.whl
arbalest-mcp
```

The command uses stdio JSON-RPC. Protocol data goes to stdout; diagnostics go to stderr.

## Kiro

Copy `configs/mcp/kiro.json.example` to either:

- workspace: `.kiro/settings/mcp.json`
- user: `~/.kiro/settings/mcp.json`

Kiro uses a top-level `mcpServers` object; a command-based entry is stdio and
needs no transport field. Save the file to reconnect automatically, then check
the MCP Servers view or `Kiro - MCP Logs`. Environment-variable references
require approval in Kiro's MCP approved-environment setting. See
[Kiro MCP configuration](https://kiro.dev/docs/mcp/configuration/).

## Cursor

Copy `configs/mcp/cursor.json.example` into the project's `.cursor/mcp.json`
or your user MCP configuration. Keep secrets out of the project file and start
Cursor from an environment containing the selected provider key. See
[Cursor MCP documentation](https://docs.cursor.com/en/cli/mcp).

## VS Code and GitHub Copilot

For native VS Code MCP configuration, copy `configs/mcp/vscode.mcp.json.example`
to `.vscode/mcp.json`. The template uses a password input so the provider key
is not stored in source control. VS Code also supports the portable top-level
`mcpServers` format in workspace `.mcp.json`; use `generic.json.example` for
that form. See the [VS Code MCP configuration reference](https://code.visualstudio.com/docs/copilot/reference/mcp-configuration).

## Claude Code

Copy `configs/mcp/claude-code.json.example` to `.mcp.json` in a trusted project and adjust the authorized roots. Start Claude Code from a shell that has the selected provider key, or place the key in Claude Code's private user configuration rather than the repository.

Example environment for Nebius Token Factory with NVIDIA Nemotron:

```powershell
$env:ARBALEST_PROVIDER = "nebius"
$env:ARBALEST_MODEL = "nvidia/Nemotron-3-Ultra-550b-a55b"
$env:NEBIUS_API_KEY = "<secret>"
$env:NEBIUS_PROJECT_ID = "<project>"
$env:ARBALEST_MCP_ALLOWED_ROOTS = "C:\workspaces"
claude
```

Claude Code supports local stdio MCP processes and project/user/local configuration scopes. See [Claude Code MCP documentation](https://code.claude.com/docs/en/mcp).

## Codex CLI, IDE, and ChatGPT desktop

Copy the relevant table from `configs/mcp/codex.toml.example` into user-level `~/.codex/config.toml` or a trusted project's `.codex/config.toml`. The example forwards named environment variables instead of storing keys in the file.

Codex, its IDE integration, and ChatGPT desktop share MCP configuration for the same Codex host. The official configuration supports stdio `command`, `args`, `env`, `env_vars`, `cwd`, startup/tool timeouts, required servers, tool allowlists, and approval modes. See [OpenAI MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).

## Windsurf, Cline, Roo Code, and other MCP hosts

Start with `configs/mcp/generic.json.example`. Clients using the common
`mcpServers` stdio shape need only the `arbalest-mcp` command, optional args,
and a private environment. If a client uses a different wrapper schema, map
those same command/args/env values into its local-server form. Never copy API
keys into a tracked example.

## BYOK configurations

### Nebius Token Factory (default)

```dotenv
ARBALEST_PROVIDER=nebius
NEBIUS_API_KEY=<secret>
NEBIUS_PROJECT_ID=<project>
ARBALEST_MODEL=nvidia/Nemotron-3-Ultra-550b-a55b
```

Nebius behavior and defaults remain unchanged. Run `arbalest models --provider nebius` and `arbalest sandbox-check` before a demonstration.

### Native OpenAI

```dotenv
ARBALEST_PROVIDER=openai
OPENAI_API_KEY=<secret>
ARBALEST_MODEL=<available-model-id>
```

Native OpenAI uses the Responses API with strict JSON-schema output and bounded tool calls. `OPENAI_BASE_URL` is optional for an approved compatible gateway.

### Native Anthropic

```dotenv
ARBALEST_PROVIDER=anthropic
ANTHROPIC_API_KEY=<secret>
ARBALEST_MODEL=<available-claude-model-id>
```

Anthropic uses the Messages API. Structured output is returned through a forced schema tool; agent tool calls use Anthropic `tool_use` and `tool_result` blocks. Tool turns and total calls are locally bounded.

### Custom OpenAI-compatible endpoint

```dotenv
ARBALEST_PROVIDER=custom
AI_BASE_URL=http://127.0.0.1:11434/v1/
ARBALEST_MODEL=<served-model-id>
# AI_API_KEY=<optional-endpoint-key>
```

`custom` uses portable Chat Completions; `custom-responses` uses the Responses API; `custom-anthropic` (`AI_ANTHROPIC_BASE_URL`, `AI_ANTHROPIC_API_KEY`) uses Anthropic Messages. The base URL is mandatory so a keyless configuration never falls through to a public vendor endpoint.

### Vendor presets, gateways, and local models

```dotenv
ARBALEST_PROVIDER=google        # or mistral, deepseek, xai, groq, together, fireworks, cerebras, openrouter, vercel
GEMINI_API_KEY=<secret>         # each preset reads only its own key
ARBALEST_MODEL=<model-id>
```

`ollama` and `lmstudio` default to their localhost endpoints and need no key. Override with `OLLAMA_BASE_URL` or `LMSTUDIO_BASE_URL`.

### Named endpoints

Copy `configs/providers.json.example` to `arbalest.providers.json` (or set `ARBALEST_PROVIDERS_FILE`). Each entry declares `api_url`, `protocol` (`openai_chat`, `openai_responses`, or `anthropic`), and an optional `default_model`. Keys come from `<ID>_API_KEY`, so `corp-gateway` reads `CORP_GATEWAY_API_KEY`. Files containing credential-like fields, or reusing a built-in id, are rejected.

### Existing subscriptions

```dotenv
ARBALEST_PROVIDER=claude-cli    # `claude` signed in with a Claude plan
# ARBALEST_PROVIDER=codex-cli   # `codex` signed in with ChatGPT
# ARBALEST_MODEL=<optional; omit to use the CLI's own default>
```

Arbalest runs the CLI non-interactively from an empty temporary directory with native tools and MCP servers disabled and no persisted session. It never reads `~/.claude` or `~/.codex`. Usage counts against your plan's limits.

## Security requirements

- Never place provider keys in tracked MCP configuration.
- Always configure `ARBALEST_MCP_ALLOWED_ROOTS`.
- Treat Kiro/Cursor/VS Code/Claude/Codex project MCP files as configuration, not secret stores.
- Give MCP clients approval prompts for tools that read repositories or create artifacts.
- Keep `verify_fix` non-deploying in MCP; use the reviewed CLI flow for deployment.
- A client login and an Arbalest provider credential are separate trust domains. Host-agent tools return repository source to the client, so `ARBALEST_MCP_ALLOWED_ROOTS` is the confidentiality boundary.
- Run one MCP server process per trust boundary or organization.

Content from linked provider documentation was summarized and rephrased for licensing compliance.
