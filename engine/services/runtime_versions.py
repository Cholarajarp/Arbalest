"""Declared runtime/version awareness: base images, version files, engines.

Runtime components (PHP, Node.js, Python, Ruby, Go) are not packages in OSV
ecosystems, so interpreter-level emergencies such as PHP2Shell are invisible to
dependency scanning. This module inventories the runtimes a project *declares*
(Dockerfile ``FROM`` images, ``.nvmrc``, ``engines``, ``platform.php``,
``go.mod``, version files) and checks them against two optional data sources:

* a small, dated emergency-advisory table transcribed from authoritative vendor
  advisories (URLs included), which works fully offline;
* live end-of-life data from api.endoflife.date (failure-tolerant: unreachable
  service is reported truthfully and never fails the mission).
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import httpx

from engine.agents.architect_agent import Severity, ThreatFinding

logger = logging.getLogger("arbalest.runtime_versions")

_EOL_API = "https://api.endoflife.date/api/v1/{product}.json"
_EOL_TIMEOUT = httpx.Timeout(8.0)
# Component -> endoflife.date product slug. Products the service does not know
# resolve to a non-list response and are skipped gracefully.
_EOL_PRODUCTS = {
    "php": "php", "nodejs": "nodejs", "python": "python", "ruby": "ruby", "go": "go",
    "nginx": "nginx", "postgresql": "postgresql", "redis": "redis", "mongodb": "mongodb",
    "gitlab": "gitlab", "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine",
    "centos": "centos", "rockylinux": "rocky-linux", "fedora": "fedora",
    "rabbitmq": "rabbitmq", "elasticsearch": "elasticsearch",
}
# Cycle granularity on endoflife.date is product-specific; lookups try the
# major.minor line first and fall back to the major, so no per-product table
# is needed here.

# Dated emergency advisories transcribed from the linked authoritative
# advisories. ``floors`` maps an affected release line to its first patched
# release; ``None`` means the line is affected but the exact floor was not
# published when the entry was recorded — the operator must verify.
# ``all_below`` marks every release older than that version affected.
EMERGENCY_ADVISORIES: tuple[dict[str, Any], ...] = (
    {
        "tag": "php2shell",
        "component": "php",
        "published": date(2026, 10, 21),
        "ids": ["CVE-2026-109618", "CVE-2026-109619"],
        "floors": {"8.5": "8.5.12", "8.4": "8.4.27", "8.3": "8.3.36", "8.2": None},
        "lines": {"8.2", "8.3", "8.4", "8.5"},
        "affected": "PHP 8.2 – 8.5 before the October 2026 emergency patches",
        "url": "https://www.cisa.gov/news-events/alerts/2026/10/21/critical-vulnerabilities-php-require-immediate-patching",
    },
    {
        "tag": "nodejs-october-2026",
        "component": "nodejs",
        "published": date(2026, 10, 21),
        "ids": ["Node.js October 2026 security releases"],
        "floors": {},  # Fixed releases span 26.x/24.x/22.x; exact floors not tabulated here.
        "lines": {"22", "24", "26"},
        "affected": "Node.js 22.x / 24.x / 26.x before the October 2026 security releases",
        "url": "https://nodejs.org/en/blog/vulnerability/october-2026-security-releases",
    },
    {
        "tag": "gitlab-october-2026",
        "component": "gitlab",
        "published": date(2026, 10, 22),
        "ids": ["CVE-2026-110264", "CVE-2026-12664"],
        "floors": {"19.5": "19.5.1", "19.4": "19.4.3", "19.3": "19.3.6"},
        "lines": {"19.3", "19.4", "19.5"},
        "all_below": "19.3",  # CVE-2026-110264 affects releases back to GitLab 7.0.
        "affected": "GitLab CE/EE before the October 22, 2026 security release "
                    "(unauthenticated RCE, CVSS 10.0; affects versions back to 7.0)",
        "url": "https://www.smarttech247.com/threat-intel-reports/2026-10-22-gitlab-ce-ee-critical-high-severity-vulnerabilities",
    },
)

def _load_operator_advisories() -> list[dict[str, Any]]:
    """Optional operator-supplied emergency entries from ARBALEST_ADVISORIES_FILE.

    Entries use the same shape as EMERGENCY_ADVISORIES (tag, component,
    published ISO date, ids, floors, optional lines/all_below, affected, url).
    The dated, sourced built-in table stays the baseline; operator entries
    merge by tag so a refreshed entry extends or replaces it without code
    changes. Malformed files are ignored with a warning, never fatal.
    """
    configured = os.environ.get("ARBALEST_ADVISORIES_FILE", "").strip()
    if not configured:
        return []
    try:
        raw = json.loads(Path(configured).expanduser().read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("Ignoring unreadable advisories file %s: %s", configured, exc)
        return []
    entries = raw.get("advisories") if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        logger.warning("Advisories file %s must hold a list (or {'advisories': [...]})", configured)
        return []
    parsed: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        try:
            parsed.append({
                "tag": str(entry["tag"])[:64],
                "component": str(entry["component"])[:32],
                "published": date.fromisoformat(str(entry["published"])[:10]),
                "ids": [str(value)[:64] for value in entry.get("ids", [])][:8],
                "floors": {
                    str(key)[:8]: (str(value)[:32] if value else None)
                    for key, value in (entry.get("floors") or {}).items()
                },
                "lines": {str(value)[:8] for value in entry.get("lines", [])},
                "all_below": str(entry["all_below"])[:32] if entry.get("all_below") else None,
                "affected": str(entry.get("affected", "operator-declared affected range"))[:400],
                "url": str(entry.get("url", "operator advisories file"))[:400],
            })
        except (KeyError, ValueError, TypeError):
            logger.warning("Skipping malformed advisory entry in %s", configured)
    return parsed


def active_advisories() -> tuple[dict[str, Any], ...]:
    """Built-in dated table merged with operator entries (operator wins by tag)."""
    merged = {entry["tag"]: entry for entry in EMERGENCY_ADVISORIES}
    for entry in _load_operator_advisories():
        merged[entry["tag"]] = entry
    return tuple(merged.values())


_DOCKER_IMAGES = {
    # language runtimes
    "php": "php", "node": "nodejs", "python": "python", "ruby": "ruby",
    "golang": "go", "go": "go",
    # declared infrastructure and base distributions
    "nginx": "nginx", "postgres": "postgresql", "redis": "redis",
    "mongodb": "mongodb", "mongo": "mongodb",
    "gitlab-ce": "gitlab", "gitlab-ee": "gitlab", "gitlab-runner": "gitlab",
    "ubuntu": "ubuntu", "debian": "debian", "alpine": "alpine", "centos": "centos",
    "rockylinux": "rockylinux", "fedora": "fedora",
    "rabbitmq": "rabbitmq", "elasticsearch": "elasticsearch",
}
_VERSION_CHARS = re.compile(r"\d+(?:\.\d+)*")
_FROM_LINE = re.compile(r"(?i)^\s*FROM\s+(?:--\w[\w-]*=\S+\s+)?(\S+)")
_GOMOD_GO = re.compile(r"(?m)^\s*go\s+(\d+(?:\.\d+){1,2})")
_GOMOD_TOOLCHAIN = re.compile(r"(?m)^\s*toolchain\s+go(\d+(?:\.\d+){1,2})")
_GEMFILE_RUBY = re.compile(r"(?mi)^\s*ruby\s+[\"'](\d+(?:\.\d+){1,2})[\"']")
_ENGINES_NODE = re.compile(r"\"node\"\s*:\s*\"([^\"]+)\"")
_COMPOSER_PHP = re.compile(r"\"php\"\s*:\s*\"([^\"]+)\"")


@dataclass(frozen=True, slots=True)
class RuntimeDeclaration:
    component: str
    version: str
    declared_in: str
    line: int
    evidence: str


def _component_of_image(image: str) -> str | None:
    name = image.rsplit("/", 1)[-1].lower()
    name = name.split(":", 1)[0]
    return _DOCKER_IMAGES.get(name)


def _base_version(tag: str) -> str | None:
    match = _VERSION_CHARS.search(tag.split("-", 1)[0].replace(":", " "))
    if not match:
        match = _VERSION_CHARS.search(tag)
    return match.group(0) if match else None


def _add(target: list[RuntimeDeclaration], component: str | None, version: str | None,
         declared_in: str, line: int, evidence: str) -> None:
    if component and version:
        target.append(RuntimeDeclaration(component, version, declared_in, line, evidence))


def collect_runtime_declarations(sources: dict[str, str]) -> list[RuntimeDeclaration]:
    """Inventory runtime versions declared by the project. Never raises."""
    found: list[RuntimeDeclaration] = []
    for path, content in sources.items():
        name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        try:
            if name == "dockerfile" or name.startswith("dockerfile.") or name.endswith(".dockerfile"):
                for line_no, line in enumerate(content.splitlines(), 1):
                    match = _FROM_LINE.match(line)
                    if not match:
                        continue
                    image = match.group(1)
                    component = _component_of_image(image)
                    tag = image.split(":", 1)[1] if ":" in image else ""
                    _add(found, component, _base_version(tag), path, line_no, line.strip()[:200])
            elif name in {".nvmrc", ".node-version"}:
                _add(found, "nodejs", _base_version(content.strip()), path, 1, content.strip()[:200])
            elif name == ".python-version":
                _add(found, "python", _base_version(content.strip()), path, 1, content.strip()[:200])
            elif name == ".ruby-version":
                _add(found, "ruby", _base_version(content.strip()), path, 1, content.strip()[:200])
            elif name == ".tool-versions":
                for line_no, line in enumerate(content.splitlines(), 1):
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] in _EOL_PRODUCTS:
                        _add(found, parts[0], _base_version(parts[1]), path, line_no, line.strip()[:200])
            elif name == "go.mod":
                for pattern in (_GOMOD_TOOLCHAIN, _GOMOD_GO):
                    match = pattern.search(content)
                    if match:
                        line_no = content[: match.start()].count("\n") + 1
                        _add(found, "go", match.group(1), path, line_no, match.group(0).strip()[:200])
                        break
            elif name == "gemfile":
                match = _GEMFILE_RUBY.search(content)
                if match:
                    line_no = content[: match.start()].count("\n") + 1
                    _add(found, "ruby", match.group(1), path, line_no, match.group(0).strip()[:200])
            elif name == "package.json":
                match = _ENGINES_NODE.search(content)
                if match:
                    version = _base_version(match.group(1))
                    _add(found, "nodejs", version, path, 1, f"engines.node {match.group(1)}")
            elif name == "composer.json":
                match = _COMPOSER_PHP.search(content)
                if match:
                    version = _base_version(match.group(1))
                    if version and "." in version:
                        _add(found, "php", version, path, 1, f"php requirement {match.group(1)}")
        except (ValueError, AttributeError):
            continue
    return found


def _version_key(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split("."))
    except ValueError:
        return ()


# Components whose release lines are majors, not major.minor.
_MAJOR_LINE_COMPONENTS = {"nodejs"}


def _line(component: str, version: str) -> str:
    parts = version.split(".")
    if component in _MAJOR_LINE_COMPONENTS or len(parts) == 1:
        return parts[0]
    return f"{parts[0]}.{parts[1]}"


def _finding(component: str, tag: str, severity: Severity, summary: str,
             declarations: list[RuntimeDeclaration], ids: list[str]) -> ThreatFinding:
    return ThreatFinding(
        finding_id=f"RUNTIME-{component}-{tag}"[:128],
        cwe=ids[0] if ids and ids[0].startswith("CVE-") else "CWE-1104",
        severity=severity,
        summary=summary,
        affected_nodes=sorted({item.declared_in for item in declarations}),
        evidence=[f"{item.declared_in}:{item.line} {item.evidence}" for item in declarations[:20]],
    )


async def check_runtime_declarations(
    declarations: list[RuntimeDeclaration],
    *,
    client: httpx.AsyncClient | None = None,
    today: date | None = None,
) -> tuple[list[ThreatFinding], dict[str, Any]]:
    """Check declared runtimes against the emergency table and live EOL data."""
    findings: list[ThreatFinding] = []
    info: dict[str, Any] = {"declarations": len(declarations), "eol_checked": False, "note": ""}
    if not declarations:
        return findings, info
    today = today or datetime.now().date()
    by_key: dict[tuple[str, str], list[RuntimeDeclaration]] = {}
    for item in declarations:
        by_key.setdefault((item.component, item.version), []).append(item)

    for advisory in active_advisories():
        advisory_lines: set[str] = set(advisory.get("lines", ())) | set(advisory["floors"])
        all_below = advisory.get("all_below")
        affected: list[RuntimeDeclaration] = []
        affected_lines: set[str] = set()
        below_floor: str | None = None
        for (component, version), items in by_key.items():
            if component != advisory["component"] or not _version_key(version):
                continue
            line = _line(component, version)
            if line in advisory_lines:
                floor = advisory["floors"].get(line)
                if floor is None or _version_key(version) < _version_key(floor):
                    affected.extend(items)
                    affected_lines.add(line)
            elif all_below and _version_key(version) < _version_key(all_below):
                # Older than every patched line (e.g. "affects back to 7.0"):
                # affected; upgrade target is the newest patched release.
                affected.extend(items)
                affected_lines.add(line)
                below_floor = max(
                    (value for value in advisory["floors"].values() if value),
                    key=_version_key,
                    default=None,
                )
        if not affected:
            continue
        known_floor = any(advisory["floors"].get(line) for line in affected_lines) or below_floor is not None
        severity = Severity.CRITICAL if known_floor else Severity.MEDIUM
        ids = list(advisory["ids"])
        floors_text = ", ".join(
            f"{line}≥{advisory['floors'][line]}" if advisory["floors"].get(line)
            else f"{line}: upgrade to ≥{below_floor}" if below_floor
            else f"{line}: see vendor advisory"
            for line in sorted(affected_lines)
        )
        summary = (
            f"{advisory['affected']}: declared {advisory['component']} is in an affected range. "
            f"Patched releases: {floors_text}. "
            f"Source: {advisory['url']} (published {advisory['published'].isoformat()})"
        )
        findings.append(_finding(advisory["component"], advisory["tag"], severity, summary, affected, ids))

    products = sorted({component for component, _ in by_key if component in _EOL_PRODUCTS})
    owns_client = client is None
    if client is None:
        client = httpx.AsyncClient(timeout=_EOL_TIMEOUT, follow_redirects=True)
    try:
        for product in products:
            try:
                response = await client.get(_EOL_API.format(product=_EOL_PRODUCTS[product]))
                response.raise_for_status()
                cycles = response.json()
            except (httpx.HTTPError, ValueError):
                info["note"] = (
                    "runtime end-of-life service unreachable; declared runtimes are reported "
                    "in coverage and only the offline emergency table was checked"
                )
                continue
            if not isinstance(cycles, list):
                continue
            info["eol_checked"] = True
            cycle_map: dict[str, dict[str, Any]] = {}
            for cycle in cycles:
                if isinstance(cycle, dict) and isinstance(cycle.get("cycle"), str):
                    cycle_map[cycle["cycle"]] = cycle
            for (component, version), items in by_key.items():
                if component != product:
                    continue
                line = _line(component, version)
                # Cycle granularity is product-specific (nodejs majors,
                # nginx/redis major.minor, GitLab minor lines): try the exact
                # line first, then the bare major.
                cycle = cycle_map.get(line) or cycle_map.get(version.split(".")[0])
                if not cycle:
                    continue
                eol_raw = str(cycle.get("eol") or "")
                try:
                    eol_date = date.fromisoformat(eol_raw[:10])
                except ValueError:
                    continue
                if today > eol_date:
                    findings.append(_finding(
                        component, "eol", Severity.HIGH,
                        f"{component} {line} is end-of-life (since {eol_date.isoformat()}); "
                        "the declared version receives no security fixes",
                        items, [],
                    ))
                else:
                    # Freshness within the declared line: the service reports
                    # the newest release of this cycle; older patches lag
                    # behind security fixes without being EOL.
                    latest = str(cycle.get("latest") or "")
                    if latest and _version_key(version) < _version_key(latest):
                        findings.append(_finding(
                            component, "outdated", Severity.LOW,
                            f"{component} {version} is not the newest release of its line "
                            f"({latest} is current); security fixes may not be present",
                            items, [],
                        ))

        # CISA Known Exploited Vulnerabilities: an authoritative, dated feed of
        # actively exploited products. It carries no version ranges, so a hit
        # is reported as a verification demand, never as a version match.
        if any(component in _KEV_PRODUCTS for component, _ in by_key):
            try:
                kev, kev_date = await _fetch_kev(client)
            except (httpx.HTTPError, ValueError):
                kev, kev_date = [], ""
            if not kev:
                info["kev_checked"] = False
            else:
                info["kev_checked"] = True
                for component in sorted({name for name, _ in by_key}):
                    vendor, product_name = _KEV_PRODUCTS.get(component, ("", ""))
                    if not vendor:
                        continue
                    entries = [
                        item for item in kev
                        if isinstance(item, dict)
                        and str(item.get("vendor", "")).lower() == vendor
                        and str(item.get("product", "")).lower() == product_name
                    ]
                    if not entries:
                        continue
                    versions = sorted({version for name, version in by_key if name == component})
                    for version in versions:
                        items = by_key[(component, version)]
                        findings.append(_finding(
                            component, "kev", Severity.MEDIUM,
                            f"CISA KEV lists {len(entries)} actively exploited {vendor} {product_name} "
                            f"vulnerabilit{'y' if len(entries) == 1 else 'ies'} (feed dated {kev_date or 'unknown'}); "
                            f"declared {component} {version} — verify against the KEV entries; the feed "
                            "carries no version ranges",
                            items, [],
                        ))
    finally:
        if owns_client:
            await client.aclose()
    return findings, info


_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
# (vendor, product) names as they appear in the CISA KEV catalog.
_KEV_PRODUCTS = {
    "php": ("php", "php"),
    "gitlab": ("gitlab", "gitlab"),
    "nginx": ("nginx", "nginx"),
}


async def _fetch_kev(client: httpx.AsyncClient) -> tuple[list[Any], str]:
    response = await client.get(_KEV_URL)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        return [], ""
    vulnerabilities = payload.get("vulnerabilities")
    released = str(payload.get("dateReleased", ""))[:10]
    return (vulnerabilities if isinstance(vulnerabilities, list) else []), released
