"""Self-contained, escaped executive HTML reporting."""

from __future__ import annotations

from datetime import UTC, datetime
from html import escape
from typing import Any


def _value(value: object) -> str:
    return escape(str(value), quote=True)


def findings_to_html(
    findings: list[Any],
    *,
    execution_successful: bool = True,
    notifications: list[str] | None = None,
) -> str:
    """Generate an offline report without executable remote content."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(getattr(finding, "severity", "unknown")).lower()
        if severity in counts:
            counts[severity] += 1
    grade = "INCOMPLETE" if not execution_successful else (
        "F" if counts["critical"] else "D" if counts["high"] else "C" if counts["medium"] else "B" if counts["low"] else "A"
    )
    status_class = "ok" if execution_successful else "bad"
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")

    rows: list[str] = []
    for finding in findings:
        finding_id = _value(getattr(finding, "finding_id", "Unknown"))
        severity = _value(str(getattr(finding, "severity", "unknown")).upper())
        cwe = _value(getattr(finding, "cwe", "N/A"))
        summary = _value(getattr(finding, "summary", ""))
        locations = ", ".join(_value(item) for item in getattr(finding, "affected_nodes", [])[:5]) or "—"
        evidence = "<br>".join(_value(item) for item in getattr(finding, "evidence", [])[:5]) or "—"
        rows.append(
            f'<tr><td><code>{finding_id}</code></td><td><span class="sev {severity.lower()}">{severity}</span></td>'
            f'<td>{cwe}</td><td>{summary}</td><td>{locations}</td><td>{evidence}</td></tr>'
        )
    notices = "".join(f"<li>{_value(message)}</li>" for message in (notifications or []))
    notice_block = f'<section class="notice"><h2>Execution notifications</h2><ul>{notices}</ul></section>' if notices else ""

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<title>Arbalest Security Report</title><style>
:root{{--bg:#08111f;--panel:#111c2e;--line:#29364c;--text:#edf3ff;--muted:#9aacbe;--ok:#36d399;--bad:#fb7185}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}}
main{{max-width:1400px;margin:auto;padding:32px}}header{{display:flex;justify-content:space-between;gap:24px;border-bottom:1px solid var(--line);padding-bottom:20px}}
h1{{margin:0;font-size:32px}}.muted{{color:var(--muted)}}.grade{{font-size:34px;font-weight:800}}.ok{{color:var(--ok)}}.bad{{color:var(--bad)}}
.cards{{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:12px;margin:24px 0}}.card,.notice{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:16px}}
.card strong{{display:block;font-size:28px}}table{{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line)}}th,td{{padding:11px;text-align:left;vertical-align:top;border-bottom:1px solid var(--line)}}th{{color:var(--muted)}}
.sev{{font-weight:700}}.critical{{color:#fb7185}}.high{{color:#fb923c}}.medium{{color:#facc15}}.low{{color:#60a5fa}}.info{{color:#a5b4fc}}code{{color:#c4b5fd}}footer{{color:var(--muted);margin-top:18px}}
@media(max-width:900px){{.cards{{grid-template-columns:repeat(2,1fr)}}header{{display:block}}table{{display:block;overflow:auto}}}}
</style></head><body><main>
<header><div><h1>Arbalest Security Report</h1><div class="muted">Generated {timestamp}</div></div>
<div><div class="muted">SCAN STATUS</div><div class="grade {status_class}">{grade}</div></div></header>
{notice_block}
<section class="cards"><div class="card"><span class="muted">TOTAL</span><strong>{len(findings)}</strong></div>
<div class="card"><span class="muted">CRITICAL</span><strong>{counts['critical']}</strong></div><div class="card"><span class="muted">HIGH</span><strong>{counts['high']}</strong></div>
<div class="card"><span class="muted">MEDIUM</span><strong>{counts['medium']}</strong></div><div class="card"><span class="muted">LOW</span><strong>{counts['low']}</strong></div><div class="card"><span class="muted">INFO</span><strong>{counts['info']}</strong></div></section>
<table><thead><tr><th>ID</th><th>Severity</th><th>Classification</th><th>Summary</th><th>Locations</th><th>Evidence</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
<footer>Security classifications and mappings are informational and require engineering review.</footer>
</main></body></html>"""
