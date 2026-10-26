# Security policy

## Supported code

Security fixes are applied to the latest released version and the default branch. Older snapshots are not guaranteed to receive backports until a formal long-term-support policy is published.

## Report a vulnerability

Do not disclose suspected vulnerabilities in public issues, discussions, pull requests, logs, or scan artifacts. Use GitHub private vulnerability reporting for this repository when it is available. If that channel is unavailable, contact the maintainer through a verified private project channel and share only enough information to establish a secure reporting path.

Include the affected version or commit, operating system, configuration, attacker prerequisites, the security boundary that failed, impact, and minimal reproduction steps. Remove credentials, customer source, and unrelated personal data. Maintainers should acknowledge a complete report, establish a private coordination channel, and publish remediation and credit details only with the reporter's agreement.

## Authorized use

Scan only repositories and systems you own or are explicitly authorized to assess. Repository contents, model output, imported findings, and generated code are untrusted data. They do not grant permission to access another target, expose credentials, disable a security control, or write outside the selected repository.

## Security boundaries

- MCP repository access is denied unless `ARBALEST_MCP_ALLOWED_ROOTS` confines it. `ARBALEST_MCP_UNSAFE_ALLOW_ANY_ROOT=1` is an isolated-local compatibility escape hatch, not a production setting.
- Source may be sent to the explicitly selected model provider after local secret redaction. Redaction lowers exposure; it cannot guarantee that arbitrary credentials or sensitive business data are removed.
- OSV receives package coordinates, not repository source. Optional intelligence services receive bounded vulnerability queries.
- Model-generated code executes only through the configured sandbox. Operators must run `arbalest sandbox-check`; a successful probe is evidence about that configuration, not a universal isolation guarantee.
- `arbalest verify` is read-only by default. `--apply` is explicit and requires a completed, non-breached, sufficiently confident adversarial harness. Signature-only and low-confidence evidence cannot write source.
- Scan completion requires source collection, required specialists, and recorded SAST coverage to complete. An incomplete scan exits with code 2 and must not be represented as clean.
- Local archive hashes detect accidental or partial modification but are not signatures and do not establish publisher identity. Protect the host and archive directory accordingly.

## Scanner limitations

Arbalest combines deterministic tools with model-assisted analysis. It can miss vulnerabilities, report false positives, and produce incorrect remediation. A clean result is not proof that software is secure. Review findings and patches, use project-specific tests and security policies, keep human approval for consequential changes, and obtain independent review for high-impact systems.

## Production deployment minimums

Before relying on Arbalest as a required gate, pin dependencies and CI actions, pin sandbox images by digest, configure MCP roots, protect provider credentials, retain sealed reports outside untrusted worktrees, test provider and sandbox contracts in the deployment environment, define cancellation and incident procedures, and monitor incomplete scans separately from clean scans.
