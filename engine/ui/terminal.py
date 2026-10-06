"""Arbalest terminal design system.

Tier-1 presentation layer: pure-black canvas, neon-orange threat accents,
electric-blue processing, emerald confirmations. Real-time spinners, progress
bars, structured tables and bracketed phase headers. Zero third-party deps.

Degradation contract (enterprise-safe):
  * TTY  + color-capable  -> full ANSI experience.
  * NO_COLOR / TERM=dumb / non-TTY -> dense plain-text mode, no escapes.
  * silent=True -> emits nothing (machine-readable modes, MCP).
"""

from __future__ import annotations

import ctypes
import os
import re
import sys
import threading
import time
from collections.abc import Iterable, Sequence

# ---------------------------------------------------------------------------
# Palette — the only place color is defined.
# ---------------------------------------------------------------------------
NEON_ORANGE = "255,92,26"      # exploits / threats / verdicts of failure
ELECTRIC_BLUE = "53,167,255"   # processing / recon / machinery
EMERALD = "43,232,164"         # secure / verified / patched
AMBER = "255,170,51"           # medium severity (orange family)
CRIMSON = "255,71,71"          # exploit succeeded / breach
BLOOD_RED = "220,30,50"        # Red Team active — live adversarial engagement
CYAN = "0,229,255"             # Architect drafting — code generation in flight
ELECTRIC_PURPLE = "170,80,255" # blast-radius tracing / watcher mode active
DEEP_PURPLE = ELECTRIC_PURPLE
QUANTUM_MAGENTA = "255,0,200"  # cross-repo neural links — federated topology
GOLD = "255,204,0"             # antibody distribution broadcast to the fleet
ELECTRIC_GOLD = "255,214,10"   # Meta-Architect active — self-evolution drafting
MATRIX_GREEN = "0,255,102"     # self-evolution committed — recursive success
STARK_WHITE = "240,244,255"    # recursive sandbox boot
PLATINUM = "201,208,216"       # meta-mode body text
OBSIDIAN = "10,10,16"          # meta-mode background
WHITE = "242,242,242"
GRAY = "138,138,138"
DIM = "86,86,86"


class _C:
    """Internal color painter. Passthrough when disabled."""

    enabled: bool = False

    @staticmethod
    def _rgb(hex_or_rgb: str) -> str:
        return hex_or_rgb if "," in hex_or_rgb else "255,255,255"

    def __call__(self, text: object, color: str | None = None, *, bold: bool = False,
                 dim: bool = False, reverse: bool = False) -> str:
        s = str(text)
        if not self.enabled:
            return s
        codes: list[str] = []
        if bold:
            codes.append("1")
        if dim:
            codes.append("2")
        if reverse:
            codes.append("7")
        if color:
            codes.append("38;2;" + self._rgb(color))
        if not codes:
            return s
        return f"\x1b[{';'.join(codes)}m{s}\x1b[0m"


palette = _C()  # singleton; CLI calls palette.enabled = True after VT check


def _enable_windows_vt() -> bool:
    """Enable ANSI virtual terminal processing on Windows consoles."""
    if os.name != "nt":
        return True
    try:
        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        for handle_id in (-11, -12):  # STD_OUTPUT_HANDLE, STD_ERROR_HANDLE
            handle = kernel32.GetStdHandle(handle_id)
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
                return False
            if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
                return False
        return True
    except Exception:
        return False


def detect_color_support(stream=None) -> bool:
    """Decide whether ANSI color is safe on this stream."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") == "dumb":
        return False
    stream = stream or sys.stdout
    if not (hasattr(stream, "isatty") and stream.isatty()):
        return False
    if os.name == "nt":
        return _enable_windows_vt()
    return True


_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
_WIDE_RE = re.compile(
    "[\u1100-\u115f\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\ufe30-\ufe6f"
    "\uff00-\uff60\uffe0-\uffe6\U0001f300-\U0001faff\U0001f000-\U0001f02f]"
)


def visible_width(text: str) -> int:
    """ANSI-aware, wide-char-aware display width."""
    plain = _ANSI_RE.sub("", text)
    return len(plain) + len(_WIDE_RE.findall(plain))


def truncate_visible(text: str, width: int) -> str:
    """Truncate to *width* visible cells, preserving ANSI styling."""
    if visible_width(text) <= width:
        return text
    out, used = [], 0
    i = 0
    while i < len(text):
        m = _ANSI_RE.match(text, i)
        if m:
            out.append(m.group(0))
            i = m.end()
            continue
        ch = text[i]
        w = 2 if _WIDE_RE.match(ch) else 1
        if used + w > width - 1:
            out.append("…")
            break
        out.append(ch)
        used += w
        i += 1
    return "".join(out) + "\x1b[0m" if out else ""


# ---------------------------------------------------------------------------
# Severity system — vulnerabilities are the main subject.
# ---------------------------------------------------------------------------
SEV_STYLE: dict[str, dict] = {
    "critical": {"color": NEON_ORANGE, "bold": True, "reverse": True},
    "high": {"color": NEON_ORANGE, "bold": True},
    "medium": {"color": AMBER, "bold": False},
    "low": {"color": GRAY, "bold": False},
    "info": {"color": ELECTRIC_BLUE, "bold": False},
}
SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def severity_tag(sev: str) -> str:
    """Fixed-width, color-coded severity chip, e.g. 'CRITICAL'."""
    key = str(sev).lower()
    style = SEV_STYLE.get(key, SEV_STYLE["info"])
    label = key.upper().ljust(8)
    return palette(label, style["color"], bold=style.get("bold", False),
                   reverse=style.get("reverse", False))


def sev_rank(sev: str) -> int:
    key = str(sev).lower()
    return SEV_ORDER.index(key) if key in SEV_ORDER else len(SEV_ORDER)


LOGO = [
    "██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗ ",
    "██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗",
    "╚██╗ ██╔╝███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║",
    " ╚████╔╝ ██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║",
    "  ╚═══╝  ╚═╝  ╚═╝╚═╝ ╚████╝╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝",
]

SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


class Spinner:
    """Real-time braille spinner with elapsed timer. Thread-driven, silent-safe."""

    def __init__(self, console: "Console", text: str) -> None:
        self._c = console
        self._text = text
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._t0 = 0.0
        self._failed = False

    def update(self, text: str) -> None:
        self._text = text

    def fail(self) -> None:
        self._failed = True

    def __enter__(self) -> "Spinner":
        self._t0 = time.perf_counter()
        if self._c.live:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        elif not self._c.silent:
            self._c.line(f"  ▸ {self._text} …", DIM)
        return self

    def _spin(self) -> None:
        i = 0
        while not self._stop.wait(0.08):
            elapsed = time.perf_counter() - self._t0
            frame = palette(SPINNER_FRAMES[i % len(SPINNER_FRAMES)], ELECTRIC_BLUE, bold=True)
            line = f"  {frame} {self._text} … {elapsed:5.1f}s"
            self._c._rewrite(line)
            i += 1

    def __exit__(self, exc_type, exc, tb) -> None:
        elapsed = time.perf_counter() - self._t0
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        ok = exc is None and not self._failed
        mark = palette("✓", EMERALD, bold=True) if ok else palette("✗", NEON_ORANGE, bold=True)
        note = f"{self._text} — {elapsed:.1f}s"
        if self._c.live:
            self._c._rewrite(f"  {mark} {note}", newline=True)
        elif not self._c.silent:
            self._c.line(f"  {mark} {note}")


class _ProgressHandle:
    """Handle returned by Console.progress()."""

    def __init__(self, console: "Console", total: int, label: str, width: int) -> None:
        self._c = console
        self._total = max(total, 1)
        self._label = label
        self._width = width
        self._done = 0
        self._t0 = time.perf_counter()

    def tick(self, done: int | None = None, note: str = "") -> None:
        self._done = self._total if done is None else min(done, self._total)
        pct = self._done / self._total
        filled = int(round(pct * self._width))
        bar = palette("█" * filled, ELECTRIC_BLUE) + palette("░" * (self._width - filled), DIM)
        rate = self._done / max(time.perf_counter() - self._t0, 1e-6)
        eta = (self._total - self._done) / rate if rate > 0 else 0.0
        eta_txt = palette(f" eta {eta:4.0f}s", GRAY) if self._done < self._total else ""
        suffix = f" ┃ {note}" if note else ""
        line = f"  {bar} {pct:4.0%}  {self._done}/{self._total} {self._label}{eta_txt}{suffix}"
        if self._c.live:
            self._c._rewrite(line)
            if self._done >= self._total:
                self._c.print()
        elif not self._c.silent and (self._done == self._total or self._done % max(self._total // 4, 1) == 0):
            self._c.line(line.rstrip())


class Console:
    """High-contrast mission console.

    live: spinner/progress carriage-control allowed (TTY).
    silent: emit nothing (machine modes).
    """

    def __init__(self, *, stream=None, silent: bool = False, meta: bool = False) -> None:
        self._stream = stream or sys.stdout
        self.silent = silent
        self.meta = meta                # Meta-Mode: inverted scheme for self-evolution
        self.live = False
        self._last_rewrite_len = 0
        if not silent:
            try:
                self.live = bool(self._stream.isatty())
            except Exception:
                self.live = False
        if not silent and detect_color_support(self._stream):
            palette.enabled = True

    # -- low-level --------------------------------------------------------
    def _out(self, text: str) -> None:
        if self.silent:
            return
        try:
            self._stream.write(text)
            self._stream.flush()
        except Exception:
            pass

    def print(self, text: str = "") -> None:
        self._out(text + "\n")

    def line(self, text: str = "", color: str | None = None, *, bold: bool = False,
             dim: bool = False, indent: int = 0) -> None:
        pad = " " * indent
        self._out(pad + palette(text, color, bold=bold, dim=dim) + "\n")

    def _rewrite(self, text: str, *, newline: bool = False) -> None:
        """Carriage-return in-place rewrite used by spinners/progress."""
        if self.silent:
            return
        pad = max(self._last_rewrite_len - visible_width(text), 0)
        self._out("\r" + text + (" " * pad) + ("\n" if newline else ""))
        self._last_rewrite_len = 0 if newline else visible_width(text)

    # -- hero -------------------------------------------------------------
    def hero(self, version: str, provider: str, model: str, sandbox: str,
             target: str) -> None:
        for row in LOGO:
            self.print(palette(row, NEON_ORANGE, bold=True))
        self.print(palette(
            f"  DEVSECOPS STRIKE PLATFORM v{version} — SILENT ▸ PRECISE ▸ AUTONOMOUS",
            WHITE, bold=True,
        ))
        self.rule()
        self.kv("OPERATOR", "TIER-1 INCIDENT RESPONSE", ELECTRIC_BLUE)
        self.kv("TARGET", str(target))
        self.kv("AI CORE", f"{provider} / {model}", ELECTRIC_BLUE)
        self.kv("NEBIUS TOKEN FACTORY SANDBOX", sandbox,
                EMERALD if "ARMED" in sandbox else AMBER)
        self.rule()

    def rule(self) -> None:
        self.line("─" * 76, PLATINUM if self.meta else DIM, dim=not self.meta)

    def meta_band(self, text: str) -> None:
        """Full-width obsidian band — the inverted 'Meta-Mode' signature."""
        if self.silent:
            return
        pad = max(76 - visible_width(text), 2)
        if palette.enabled:
            body = f"\x1b[48;2;{OBSIDIAN}m" + palette(text + " " * pad, ELECTRIC_GOLD, bold=True) + "\x1b[0m"
        else:
            body = text
        self._out(body + "\n")

    def phase(self, index: int, total: int, title: str, icon: str = "") -> None:
        """Bracketed curriculum header: ── [1/4] 🔍 RECON PHASE ──────────"""
        accent = ELECTRIC_GOLD if self.meta else NEON_ORANGE
        body_color = STARK_WHITE if self.meta else WHITE
        head = palette(f"[{index}/{total}]", accent, bold=True)
        label = palette(f"{icon} {title}".strip().upper(), body_color, bold=True)
        used = 2 + len(f"{index}/{total}") + 1 + visible_width(f"{icon} {title}".upper()) + 1
        pad = "─" * max(76 - used, 3)
        self.print(f" {head} {label} " + palette(pad, DIM))

    # -- structured output -------------------------------------------------
    def kv(self, key: str, value: str, color: str | None = None) -> None:
        self.print(f"  {palette(key.ljust(28), GRAY)} {palette(str(value), color or WHITE)}")

    def bullet(self, text: str, color: str | None = None, *, indent: int = 5) -> None:
        self._out(" " * indent + palette("▸ ", ELECTRIC_BLUE) + palette(text, color or WHITE) + "\n")

    def note(self, text: str) -> None:
        self.line(f"  ⚠ {text}", AMBER)

    def error(self, text: str) -> None:
        self.line(f"  ✗ {text}", NEON_ORANGE, bold=True)

    def success(self, text: str) -> None:
        self.line(f"  ✓ {text}", EMERALD)

    def table(self, headers: Sequence[str], rows: Iterable[Sequence[str]],
              *, aligns: Sequence[str] | None = None, max_col: int = 42) -> None:
        """Box-drawing data table. Vulnerability-centric, zero padding waste."""
        aligns = list(aligns or ["<"] * len(headers))
        body = [list(r) for r in rows]
        widths = [visible_width(h) for h in headers]
        for row in body:
            for i, cell in enumerate(row):
                widths[i] = min(max(widths[i], visible_width(str(cell))), max_col)

        def _fmt(cell: object, width: int, align: str) -> str:
            s = truncate_visible(str(cell), width)
            gap = width - visible_width(s)
            if align == ">":
                return " " * gap + s
            if align == "^":
                left = gap // 2
                return " " * left + s + " " * (gap - left)
            return s + " " * gap

        def _hline(left: str, mid: str, right: str) -> str:
            segs = [palette("─" * (w + 2), DIM) for w in widths]
            return left + mid.join(segs) + right

        if not body:
            self.line("  ─ no records ─", DIM)
            return
        head_cells = [_fmt(palette(h.upper(), NEON_ORANGE, bold=True), widths[i], aligns[i])
                      for i, h in enumerate(headers)]
        self._out(_hline("┌", "┬", "┐") + "\n")
        self._out("│ " + " │ ".join(head_cells) + " │\n")
        self._out(_hline("├", "┼", "┤") + "\n")
        for row in body:
            cells = [_fmt(str(c), widths[i], aligns[i]) for i, c in enumerate(row)]
            self._out("│ " + " │ ".join(cells) + " │\n")
        self._out(_hline("└", "┴", "┘") + "\n")

    # -- machinery ----------------------------------------------------------
    def status_line(self, text: str, *, end: bool = False) -> None:
        """In-place HUD line (TTY only). end=True releases the line."""
        if self.live and not self.silent:
            self._rewrite(text, newline=end)

    def end_status(self) -> None:
        if self.live and not self.silent:
            self._rewrite("", newline=True)

    def spinner(self, text: str) -> Spinner:
        return Spinner(self, text)

    def progress(self, total: int, label: str = "", width: int = 30) -> _ProgressHandle:
        return _ProgressHandle(self, total, label, width)

    def section(self, title: str) -> None:
        """Agent-profile / story section divider."""
        self.print()
        self.line(f"  ══ {title} " + "═" * max(70 - len(title), 3), ELECTRIC_BLUE, bold=True)

    # -- debrief -------------------------------------------------------------
    def verdict(self, counts: dict[str, int], total: int, exit_code: int,
                report_path: str | None, elapsed: float) -> None:
        self.rule()
        safe = total == 0
        verdict_txt = "SECURED — NO ACTIONABLE THREATS" if safe else "VULNERABLE — REMEDIATION REQUIRED"
        vcolor = EMERALD if safe else NEON_ORANGE
        self.line("  FINAL DEBRIEF — BOOK A TRIAL CLASS AT arbalest.sh/trial", GRAY)
        self.print()
        self.line(f"  VERDICT: {verdict_txt}", vcolor, bold=True)
        breakdown = "   ".join(
            f"{palette(k.upper(), SEV_STYLE[k]['color'], bold=True)}×{counts[k]}"
            for k in SEV_ORDER if counts.get(k)
        )
        if breakdown:
            self.line(f"  {breakdown}", WHITE)
        if report_path:
            self.kv("SARIF REPORT", report_path, ELECTRIC_BLUE)
        self.kv("ELAPSED", f"{elapsed:.1f}s", GRAY)
        self.line(f"  EXIT CODE: {palette(str(exit_code), vcolor, bold=True)}"
                  f" {palette('(0 = SECURED, 1 = VULNERABLE)', DIM)}")
        self.rule()
