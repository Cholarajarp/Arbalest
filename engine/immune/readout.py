"""Split-pane wargame readout — the war-room display.

TTY: a double-buffered two-column pane. Left column (cyan): ARCHITECT-01
drafting and repair events. Right column (blood red): REDTEAM-SWARM attack
harness generation and sandbox transcripts. Redrawn in place via ANSI cursor
movement; coalesced so high-frequency sandbox output doesn't thrash the frame.

Non-TTY: the same events surface as dense, marker-prefixed sequential lines —
the machine-readable war record.
"""

from __future__ import annotations

import asyncio
import shutil
from collections import deque

from engine.ui.terminal import BLOOD_RED, CYAN, DIM, GRAY, WHITE, Console, palette, visible_width


def _narrow(text: str, width: int) -> str:
    out, used = [], 0
    for ch in text:
        w = 2 if visible_width(ch) > 1 else 1
        if used + w > width:
            out.append("…")
            break
        out.append(ch)
        used += w
    return "".join(out)


class WargameReadout:
    """Architect (left, cyan) vs Red Team (right, blood red), split pane."""

    def __init__(self, console: Console, *, height: int = 13, title: str = "") -> None:
        self._console = console
        self._title = title
        self._height = max(height, 7)
        term = shutil.get_terminal_size((100, 40))
        self._width = min(term.columns, 110)
        self._left: deque[str] = deque(maxlen=self._height - 2)
        self._right: deque[str] = deque(maxlen=self._height - 2)
        self._pane_live = console.live and not console.silent
        self._flush_task: asyncio.Task | None = None
        self._dirty = False
        self._drawn = False

    # -- lifecycle -----------------------------------------------------------
    def open(self, title: str) -> None:
        self._title = title
        if self._pane_live:
            self._draw_frame()
        else:
            self._console.line(f"  [WARGAME] ⚔️ {title}", GRAY, bold=True)
        self._flush_task = asyncio.create_task(self._flush_loop())

    async def close(self) -> None:
        if self._flush_task is not None:
            self._flush_task.cancel()
            try:
                await self._flush_task
            except asyncio.CancelledError:
                pass
            self._flush_task = None
        # Leave the final frame on screen as the round's record; the mission
        # log continues below it.
        if self._pane_live and (self._dirty or not self._drawn):
            self._dirty = False
            self._draw_frame()
        self._console.line("  [WARGAME] pane closed", DIM)

    # -- feeds ---------------------------------------------------------------
    def left(self, line: str) -> None:
        self._left.append(line)
        if not self._pane_live:
            self._console.line(f"  ▣ ARCH ▸ {line}", CYAN)
        else:
            self._dirty = True

    def right(self, line: str) -> None:
        self._right.append(line)
        if not self._pane_live:
            self._console.line(f"  ▣ REDTEAM ▸ {line}", BLOOD_RED)
        else:
            self._dirty = True

    # -- TTY frame rendering ---------------------------------------------------
    async def _flush_loop(self) -> None:
        try:
            while True:
                if self._dirty:
                    self._dirty = False
                    self._draw_frame()
                await asyncio.sleep(0.15)
        except asyncio.CancelledError:
            if self._dirty:
                self._draw_frame()
            raise

    def _draw_frame(self) -> None:
        c = self._console
        if not self._pane_live:
            return
        half = (self._width - 3) // 2
        if self._drawn:
            c._out(f"\x1b[{self._height}F")
        self._drawn = True

        head = palette("╔═[WARGAME] ⚔️ ", DIM) + palette(_narrow(self._title, half * 2 - 18), WHITE, bold=True)
        c._out(head + "\x1b[2K\n")
        header = (
            palette("║ ", DIM) + palette("▣ ARCHITECT-01".ljust(half), CYAN, bold=True)
            + palette("║ ", DIM) + palette("▣ REDTEAM-SWARM".ljust(self._width - half - 4), BLOOD_RED, bold=True)
            + palette("║", DIM)
        )
        c._out(header + "\x1b[2K\n")
        c._out(palette("║" + "─" * half + "┬" + "─" * (self._width - half - 3) + "║", DIM) + "\x1b[2K\n")
        for row in range(self._height - 4):
            left = _narrow(self._left[row] if row < len(self._left) else "", half - 1)
            right = _narrow(self._right[row] if row < len(self._right) else "", self._width - half - 5)
            c._out(
                palette("║ ", DIM) + palette(left.ljust(half - 1), CYAN)
                + palette(" │ ", DIM) + palette(right.ljust(self._width - half - 5), BLOOD_RED)
                + palette(" ║", DIM) + "\x1b[2K\n"
            )
        footer = palette(
            f"╚{'═' * half}╧{'═' * (self._width - half - 3)}╝", DIM
        )
        c._out(footer + "\x1b[2K\n")
