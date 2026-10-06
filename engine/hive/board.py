"""FleetBoard — split-screen matrix of concurrent war-games across codebases.

TTY: the matrix redraws in place (cursor-up), giving a live fleet dashboard
while independent sandboxes fight simultaneously. Non-TTY: one dense status
line per state change — the machine-readable war record.
"""

from __future__ import annotations

import threading

from engine.ui.terminal import BLOOD_RED, DIM, EMERALD, GOLD, GRAY, NEON_ORANGE, QUANTUM_MAGENTA, Console, palette

_STATUS_STYLE = {
    "QUEUED": (GRAY, False),
    "WARGAMING": (QUANTUM_MAGENTA, True),
    "HEALED": (EMERALD, True),
    "BREACHED": (BLOOD_RED, True),
    "HELD": (NEON_ORANGE, True),
    "AUDITED": (GOLD, True),
}


class FleetBoard:
    def __init__(self, console: Console, rows: list[str]) -> None:
        self._console = console
        self._rows: dict[str, dict[str, str]] = {repo: {} for repo in rows}
        self._order = list(rows)
        self._live = console.live and not console.silent
        self._drawn = False
        self._lock = threading.Lock()

    def update(self, repo: str, **fields: str) -> None:
        with self._lock:
            self._rows.setdefault(repo, {}).update(fields)
            changed = self._rows[repo]
            if self._live:
                self._render()
            else:
                self._console.line(f"  ⬡ [{repo}] " + "  ".join(f"{k}={v}" for k, v in changed.items() if v), GRAY)

    # -- rendering -----------------------------------------------------------
    def _render(self) -> None:
        headers = ["REPO", "CWE", "SINK", "ITER", "STATUS", "SANDBOX"]
        body = []
        for repo in self._order:
            r = self._rows.get(repo, {})
            body.append([repo, r.get("cwe", "—"), r.get("sink", "—")[:26], r.get("iter", "—"),
                         r.get("status", "QUEUED"), r.get("sandbox", "—")[:16]])
        widths = [max(visible_len(h), *(visible_len(row[i]) for row in body)) if body else len(h)
                  for i, h in enumerate(headers)]
        lines = [_hline(widths, "┌", "┬", "┐")]
        lines.append("│ " + " │ ".join(palette(h.upper(), GOLD, bold=True).ljust(widths[i] + _delta(h.upper(), widths[i]))
                                       for i, h in enumerate(headers)) + " │")
        lines.append(_hline(widths, "├", "┼", "┤"))
        for row in body:
            cells = []
            for i, cell in enumerate(row):
                style = _STATUS_STYLE.get(cell) if i == 4 else None
                if style:
                    color, bold = style
                    painted = palette(cell, color, bold=bold)
                    cells.append(painted + " " * (widths[i] - visible_len(cell)))
                else:
                    cells.append(cell.ljust(widths[i]))
            lines.append("│ " + " │ ".join(cells) + " │")
        lines.append(_hline(widths, "└", "┴", "┘"))

        c = self._console
        if self._drawn:
            c._out(f"\x1b[{len(lines)}F")
        self._drawn = True
        for line in lines:
            c._out(line + "\x1b[2K\n")

    def close(self) -> None:
        if self._live and self._drawn:
            total = len(self._order) + 3
            self._console._out(f"\x1b[{total}F")
            for _ in range(total):
                self._console._out("\x1b[2K\n")
            self._console._out(f"\x1b[{total}A")
        self._drawn = False


def _hline(widths: list[int], left: str, mid: str, right: str) -> str:
    return palette(left + mid.join("─" * (w + 2) for w in widths) + right, DIM)


def visible_len(text: str) -> int:
    import re as _re
    return len(_re.sub(r"\x1b\[[0-9;]*m", "", text))


def _delta(text: str, width: int) -> int:
    return width - visible_len(text)
