"""Authoritative SCA and an offline, exact dependency inventory.

Lock support: uv's public PyPI registry entries; Poetry's default-index entries;
Pipenv default/develop groups; Composer release packages (including dev installs);
RubyGems GEM specs; pnpm 5.3/5.4/6.0/9.0 registry packages; Yarn classic v1 and
Berry metadata 4/5/6/8 npm resolutions; NuGet lock versions 1/2. Maven supports
only direct coordinates and bounded, local property expansion and always marks
coverage partial. No parent/BOM/profile/transitive Maven resolution is attempted.

Git, path, workspace, custom-source, protocol, and mutable-version entries are
excluded where identifiable, with partial coverage rather than guessed releases.
Conditional/dev/platform lock variants form a union, not an install plan. Registry
provenance and lock freshness cannot always be established from lockfiles alone.
Files over 512,000 characters are omitted, never prefix-parsed. Completeness is
relative to supplied manifests, not an uncollected repository or resolved graph.
"""

from __future__ import annotations

import json
import logging
import re
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, replace as dataclass_replace
from typing import Any
from xml.etree import ElementTree
from xml.parsers import expat

import httpx
import yaml

from engine.agents.architect_agent import Severity, ThreatFinding
from engine.services.ai_provider import AIProvider
from engine.services.runtime_versions import check_runtime_declarations, collect_runtime_declarations
from engine.services.source_collector import MANIFEST_NAMES

logger = logging.getLogger(__name__)

_OSV_QUERY_BATCH = "https://api.osv.dev/v1/querybatch"
_MAX_PACKAGES = 100  # Maximum queries per request, not an inventory limit.
_MAX_MANIFEST_SIZE = 512_000
_EXACT_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+_-]{0,127}$")
_SEMVER = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?(?:\+[A-Za-z0-9.-]+)?")
_PACKAGE_NAMES = {
    "PyPI": r"[A-Za-z0-9][A-Za-z0-9_.-]*",
    "npm": r"(?:@[A-Za-z0-9_.-]+/)?[A-Za-z0-9_.-]+",
    "Packagist": r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",
    "RubyGems": r"[A-Za-z0-9_.-]+",
    "NuGet": r"[A-Za-z0-9_.-]+",
    "Maven": r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+",
    "crates.io": r"[A-Za-z0-9_-]+",
}
_REQ = re.compile(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^]]+\])?\s*==\s*([^\s;]+)")
_GO = re.compile(r"^\s*([A-Za-z0-9./_-]+)\s+(v[^\s]+)")


@dataclass(frozen=True, slots=True)
class Dependency:
    ecosystem: str
    name: str
    version: str
    source: str


@dataclass(frozen=True, slots=True)
class ScaCoverage:
    manifests: int = 0
    analyzed_manifests: int = 0
    dependencies: int = 0
    unresolved_declarations: int = 0
    truncated_dependencies: int = 0
    omitted_manifests: tuple[str, ...] = ()
    runtime_declarations: int = 0
    eol_checked: bool = False

    @property
    def complete(self) -> bool:
        return (
            self.analyzed_manifests == self.manifests
            and self.unresolved_declarations == 0
            and self.truncated_dependencies == 0
        )

    @property
    def detail(self) -> str:
        if self.complete:
            return f"{self.analyzed_manifests}/{self.manifests} manifests, {self.dependencies} exact dependencies"
        return (
            f"analyzed {self.analyzed_manifests}/{self.manifests} manifests; "
            f"{self.unresolved_declarations} unresolved declaration(s), "
            f"{self.truncated_dependencies} dependency/dependencies over limit"
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "complete": self.complete,
            "manifests": self.manifests,
            "analyzed_manifests": self.analyzed_manifests,
            "dependencies": self.dependencies,
            "unresolved_declarations": self.unresolved_declarations,
            "truncated_dependencies": self.truncated_dependencies,
            "omitted_manifests": list(self.omitted_manifests),
            "runtime_declarations": self.runtime_declarations,
            "eol_checked": self.eol_checked,
        }


_SUPPORTED_MANIFESTS = frozenset({
    "requirements.txt", "package-lock.json", "package.json", "pyproject.toml", "Cargo.lock", "go.mod",
    "uv.lock", "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock",
    "pnpm-lock.yaml", "yarn.lock", "pom.xml", "packages.lock.json",
})
_LOCK_COVERAGE = {
    "package.json": ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"),
    "pyproject.toml": ("uv.lock", "poetry.lock"),
    "Pipfile": ("Pipfile.lock",),
    "composer.json": ("composer.lock",),
    "Gemfile": ("Gemfile.lock",),
    "Cargo.toml": ("Cargo.lock",),
    "go.sum": ("go.mod",),
}


def _severity(vulnerability: Mapping[str, Any]) -> Severity:
    database = vulnerability.get("database_specific")
    label = str(database.get("severity", "")).upper() if isinstance(database, Mapping) else ""
    if label in Severity.__members__:
        return Severity[label]
    for entry in vulnerability.get("severity", []) if isinstance(vulnerability.get("severity"), list) else []:
        score = str(entry.get("score", "")) if isinstance(entry, Mapping) else ""
        match = re.search(r"CVSS:[^/]+/.*?/(?:S:[^/]+/)?", score)
        numeric = re.search(r"(?:^|\s)(10(?:\.0)?|[0-9](?:\.\d)?)(?:\s|$)", score)
        if numeric:
            value = float(numeric.group(1))
            return Severity.CRITICAL if value >= 9 else Severity.HIGH if value >= 7 else Severity.MEDIUM if value >= 4 else Severity.LOW
        if match and "C:H" in score and "I:H" in score:
            return Severity.HIGH
    return Severity.MEDIUM


def _exact(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if text.startswith("v"):
        text = text[1:]
    if "*" in text or re.search(r"(?:^|[.])x(?:$|[.\-+])", text, re.I):
        return None
    return text if _EXACT_VERSION.fullmatch(text) else None



@dataclass(frozen=True, slots=True)
class _Parsed:
    dependencies: tuple[Dependency, ...] = ()
    unresolved: int = 0
    valid: bool = True


class _StrictLoader(yaml.SafeLoader):
    """Reject aliases and duplicate keys rather than silently losing lock entries."""

    def compose_node(self, parent: Any, index: Any) -> Any:
        if self.check_event(yaml.AliasEvent):
            raise ValueError("YAML aliases are not supported in lockfiles")
        return super().compose_node(parent, index)

    def construct_mapping(self, node: Any, deep: bool = False) -> dict[Any, Any]:
        result: dict[Any, Any] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if key in result:
                raise ValueError("duplicate lockfile key")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def _load_lock_yaml(content: str) -> Any:
    loader = _StrictLoader(content)
    try:
        return loader.get_single_data()
    finally:
        loader.dispose()


def _parse_maven_xml(content: str) -> ElementTree.Element:
    """Build bounded XML without allowing DTDs, entity declarations, or I/O."""
    # Input is already decoded text. Reject NULs so UTF-16/32 byte strings
    # disguised as text cannot bypass this case-insensitive declaration check.
    if len(content) > _MAX_MANIFEST_SIZE or "\u0000" in content:
        raise ValueError("oversized or NUL-containing Maven XML")
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)", content, re.I):
        raise ValueError("XML declarations are not supported")

    def reject_declaration(*args: Any) -> Any:
        raise ValueError("XML DTDs and entities are not supported")

    def expanded_name(name: str) -> str:
        return "{" + name if "}" in name else name

    builder = ElementTree.TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    # Enforce the policy at parse time too, before any DTD subset is processed.
    # Expat does not fetch external resources; the callback rejects references
    # instead of ever installing a file/network resolver.
    parser.StartDoctypeDeclHandler = reject_declaration
    parser.EntityDeclHandler = reject_declaration
    parser.ExternalEntityRefHandler = reject_declaration
    depth = 0

    def start_element(name: str, attributes: dict[str, str]) -> None:
        nonlocal depth
        depth += 1
        if depth > 128:
            raise ValueError("Maven XML nesting exceeds parser limit")
        builder.start(expanded_name(name), {expanded_name(key): value for key, value in attributes.items()})

    def end_element(name: str) -> None:
        nonlocal depth
        builder.end(expanded_name(name))
        depth -= 1

    parser.StartElementHandler = start_element
    parser.EndElementHandler = end_element
    parser.CharacterDataHandler = builder.data
    try:
        parser.Parse(content, True)
    except expat.ExpatError as exc:
        raise ValueError("malformed Maven XML") from exc
    return builder.close()


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("expected object")
    return value


def _array(value: Any) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError("expected array")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _pnpm_identity(value: str) -> tuple[str, str] | None:
    depth = 0
    for char in value:
        depth += (char == "(") - (char == ")")
        if depth < 0:
            return None
    if depth:
        return None
    identity = value.lstrip("/").split("(", 1)[0]
    match = re.fullmatch(r"(@[^/]+/[^/@]+|[^/@]+)(?:@|/)([^/]+)", identity)
    if not match:
        return None
    raw_version = match.group(2)
    version, separator, peers = raw_version.partition("_")
    if separator and "@" not in peers:
        return None
    exact = _exact(version)
    return (match.group(1), exact) if exact and _SEMVER.fullmatch(exact) else None


def _read_manifest(path: str, content: str) -> _Parsed:
    """Parse without resolution, downloads, or guessing versions from constraints.

    Malformed structures invalidate the entire file. Well-formed but unresolvable
    entries contribute to partial coverage while retaining other exact entries.
    """
    name = path.replace("\\", "/").rsplit("/", 1)[-1]
    found: list[Dependency] = []
    unresolved = 0

    def add(ecosystem: str, package: Any, raw: Any, *, allowed: bool = True) -> None:
        nonlocal unresolved
        version = _exact(raw)
        if not allowed or not isinstance(package, str) or not package or not version:
            unresolved += 1
            return
        if (not re.fullmatch(_PACKAGE_NAMES[ecosystem], package)
                or (ecosystem in {"npm", "crates.io"} and not _SEMVER.fullmatch(version))):
            unresolved += 1
            return
        if ecosystem == "Maven" and isinstance(raw, str):
            version = raw.strip()  # Maven's leading 'v' can be part of the literal artifact version.
        found.append(Dependency(ecosystem, package, version, path))

    try:
        if len(content) > _MAX_MANIFEST_SIZE:
            raise ValueError("manifest exceeds parser limit")
        data: dict[str, Any] = {}
        if name.endswith(".json") or name in {"Pipfile.lock", "composer.lock"}:
            data = _object(json.loads(content, object_pairs_hook=_unique_object))
        elif name in {"uv.lock", "poetry.lock", "Cargo.lock", "pyproject.toml"}:
            data = tomllib.loads(content)
        if name in {"uv.lock", "poetry.lock"}:
            for raw in _array(data.get("package")):
                package_data = _object(raw)
                source = _object(package_data.get("source", {}))
                if name == "uv.lock" and source in ({"virtual": "."}, {"editable": "."}):
                    continue  # The workspace root is not a third-party dependency.
                registry = source.get("registry")
                allowed = (registry in {"https://pypi.org/simple", "https://pypi.org/simple/"}
                           and set(source) == {"registry"}) if name == "uv.lock" else not source
                add("PyPI", package_data.get("name"), package_data.get("version"), allowed=allowed)
        elif name == "Pipfile.lock":
            if not any(section in data for section in ("default", "develop")):
                raise ValueError("missing Pipfile lock sections")
            metadata = _object(data.get("_meta", {}))
            indexes = {item.get("name"): item.get("url")
                       for item in (_object(raw) for raw in _array(metadata.get("sources", [])))}
            public_indexes = {key for key, url in indexes.items()
                              if url in {"https://pypi.org/simple", "https://pypi.org/simple/"}}
            unresolved += len(set(data) - {"_meta", "default", "develop"})
            for section in ("default", "develop"):
                for package, raw in _object(data.get(section, {})).items():
                    entry = _object(raw)
                    value = entry.get("version", "")
                    add("PyPI", package, value[2:] if isinstance(value, str) and value.startswith("==") else None,
                        allowed=not any(key in entry for key in ("git", "path", "file", "editable"))
                        and (not indexes or (entry.get("index") in public_indexes if "index" in entry
                                             else len(public_indexes) == len(indexes))))
        elif name == "composer.lock":
            for section in ("packages", "packages-dev"):
                if section == "packages" and section not in data:
                    raise ValueError("missing Composer packages")
                for raw in _array(data.get(section, [])):
                    entry = _object(raw)
                    release_version = entry.get("version")
                    add("Packagist", entry.get("name"), release_version,
                        allowed=isinstance(release_version, str) and not release_version.endswith("-dev"))
        elif name == "packages.lock.json":
            if type(data.get("version")) is not int or data["version"] not in (1, 2):
                raise ValueError("unsupported NuGet lock version")
            for entries in _object(data.get("dependencies")).values():
                for package, raw in _object(entries).items():
                    entry = _object(raw)
                    if entry.get("type") == "Project":
                        unresolved += 1
                        continue
                    add("NuGet", package, entry.get("resolved"),
                        allowed=entry.get("type") in {"Direct", "Transitive", "CentralTransitive"})
        elif name == "pnpm-lock.yaml":
            data = _object(_load_lock_yaml(content))
            if str(data.get("lockfileVersion")) not in {"5.3", "5.4", "6.0", "9.0"}:
                raise ValueError("unsupported pnpm lock version")
            if "packages" not in data and "importers" not in data:
                raise ValueError("missing pnpm inventory")
            packages = _object(data.get("packages", {}))
            locked_identities: set[tuple[str, str]] = set()
            for key, raw in packages.items():
                entry = _object(raw)
                if not isinstance(key, str):
                    raise ValueError("invalid pnpm package key")
                identity = _pnpm_identity(key)
                if identity is None:
                    unresolved += 1
                    continue
                locked_identities.add(identity)
                resolution = _object(entry.get("resolution", {}))
                add("npm", identity[0], identity[1],
                    allowed=not any(key in resolution for key in ("tarball", "directory", "repo")))
            importers = _object(data.get("importers", {}))
            if not importers:
                importers = {".": data}
            for importer in importers.values():
                for section in ("dependencies", "devDependencies", "optionalDependencies"):
                    for package, raw in _object(_object(importer).get(section, {})).items():
                        value = raw.get("version") if isinstance(raw, dict) else raw
                        if not isinstance(value, str):
                            unresolved += 1
                            continue
                        identity = _pnpm_identity(value) or _pnpm_identity(f"{package}@{value}")
                        if identity not in locked_identities:
                            unresolved += 1
            for key, raw in _object(data.get("snapshots", {})).items():
                _object(raw)
                if not isinstance(key, str) or _pnpm_identity(key) not in locked_identities:
                    unresolved += 1
        elif name == "yarn.lock":
            if re.search(r"^__metadata:", content, re.M):
                data = _object(_load_lock_yaml(content))
                metadata = _object(data.pop("__metadata"))
                if str(metadata.get("version")) not in {"4", "5", "6", "8"}:
                    raise ValueError("unsupported Yarn metadata version")
                for key, raw in data.items():
                    entry = _object(raw)
                    resolution = entry.get("resolution", "")
                    match = re.fullmatch(r"(@[^/]+/[^@]+|[^@]+)@npm:([^:]+)", str(resolution))
                    if match:
                        add("npm", match.group(1), entry.get("version"),
                            allowed=_exact(match.group(2)) == _exact(entry.get("version")))
                    else:
                        unresolved += 1
            else:
                if not re.search(r"^# yarn lockfile v1\s*$", content, re.M):
                    raise ValueError("unsupported Yarn classic lockfile")
                headers: list[str] = []
                selectors_seen: set[str] = set()
                fields_seen: set[str] = set()
                dependency_block = False
                version: str | None = None
                resolved: str | None = None

                def flush() -> None:
                    if not headers:
                        return
                    identities = set()
                    allowed = True
                    for selector in headers:
                        match = re.fullmatch(r"(@[^/]+/[^@]+|[^@]+)@(.+)", selector)
                        if not match:
                            raise ValueError("invalid Yarn selector")
                        identities.add(match.group(1))
                        if ":" in match.group(2) or match.group(2).startswith(("git", "http")):
                            allowed = False
                    if len(identities) != 1:
                        raise ValueError("ambiguous Yarn selectors")
                    add("npm", identities.pop(), version,
                        allowed=allowed and bool(resolved) and str(resolved).startswith((
                            "https://registry.yarnpkg.com/", "https://registry.npmjs.org/")))

                for line in content.splitlines():
                    if not line.strip() or line.startswith("#"):
                        continue
                    if not line.startswith(" "):
                        flush()
                        if not line.endswith(":"):
                            raise ValueError("invalid Yarn stanza")
                        headers = [item.strip().strip('"') for item in line[:-1].split(", ")]
                        if len(set(headers)) != len(headers) or selectors_seen.intersection(headers):
                            raise ValueError("duplicate Yarn selector")
                        selectors_seen.update(headers)
                        fields_seen.clear()
                        dependency_block = False
                        version = resolved = None
                    else:
                        if not headers:
                            raise ValueError("invalid Yarn field")
                        if line.startswith("    "):
                            if not dependency_block:
                                raise ValueError("Yarn dependency outside a dependency block")
                            if not re.fullmatch(r'    (?:"[^"\n]+"|[A-Za-z0-9_@/.-]+) "[^"\n]+"', line):
                                raise ValueError("invalid Yarn dependency field")
                            continue
                        if not re.fullmatch(r'  (?:(?:version|resolved|integrity) .+|(?:dependencies|optionalDependencies):)', line):
                            raise ValueError("unsupported Yarn field")
                        field = line.strip().split(" ", 1)[0].rstrip(":")
                        if field in fields_seen:
                            raise ValueError("duplicate Yarn field")
                        fields_seen.add(field)
                        dependency_block = field in {"dependencies", "optionalDependencies"}
                        match = re.fullmatch(r'  (version|resolved) "([^"\n]+)"', line)
                        if match:
                            if match.group(1) == "version":
                                if version is not None:
                                    raise ValueError("duplicate Yarn version")
                                version = match.group(2)
                            else:
                                resolved = match.group(2)
                        elif line.startswith(("  version", "  resolved")):
                            raise ValueError("invalid Yarn version or source")
                flush()
        elif name == "Gemfile.lock":
            section = ""
            in_specs = False
            saw_specs = False
            registry_ok = True
            for line in content.splitlines():
                if not line.strip():
                    continue
                if not line.startswith(" "):
                    section = line
                    if section not in {"GEM", "GIT", "PATH", "PLUGIN SOURCE", "PLATFORMS", "DEPENDENCIES",
                                       "RUBY VERSION", "BUNDLED WITH", "CHECKSUMS"}:
                        raise ValueError("unsupported gem lock section")
                    in_specs = False
                    registry_ok = False
                    continue
                if line.startswith("  remote:") and section == "GEM":
                    registry_ok = line.strip().split(": ", 1)[-1].rstrip("/") in {
                        "https://rubygems.org", "http://rubygems.org",
                    }
                if line == "  specs:":
                    if section not in {"GEM", "GIT", "PATH"}:
                        raise ValueError("gem specs outside a package source")
                    in_specs = saw_specs = True
                    continue
                if in_specs and line.startswith("      "):
                    if not re.fullmatch(r"      [A-Za-z0-9_.-]+(?: \([^)]+\))?", line):
                        raise ValueError("invalid gem dependency specification")
                    continue
                if in_specs and (not line.startswith("    ") or line.startswith("     ")):
                    raise ValueError("invalid gem specification indentation")
                if section in {"GEM", "GIT", "PATH"} and not in_specs:
                    if not re.fullmatch(r"  (?:remote|revision|branch|ref|glob|submodules): .+", line):
                        raise ValueError("invalid gem source metadata")
                if in_specs and line.startswith("    ") and not line.startswith("     "):
                    match = re.fullmatch(r"    ([A-Za-z0-9_.-]+) \(([^)]+)\)", line)
                    if not match:
                        raise ValueError("invalid gem specification")
                    raw_version = match.group(2)
                    # Platform-qualified gem artifacts share the gem's release version.
                    version = re.sub(r"-(?:ruby|java|(?:x86_64|x64|x86|arm64|aarch64|universal)[-A-Za-z0-9_.]*)$", "", raw_version)
                    add("RubyGems", match.group(1), version,
                        allowed=registry_ok and bool(re.fullmatch(r"[0-9]+(?:\.[A-Za-z0-9]+)*", version)))
            if not saw_specs:
                raise ValueError("missing gem specs")
        elif name == "pom.xml":
            root = _parse_maven_xml(content)
            if root.tag.rsplit("}", 1)[-1] != "project":
                raise ValueError("not a Maven project")
            namespace = root.tag[:-7] if root.tag.endswith("project") else ""

            def text(element: Any, tag: str) -> str:
                elements = element.findall(namespace + tag)
                if len(elements) > 1:
                    raise ValueError("duplicate Maven coordinate field")
                return ((elements[0].text or "") if elements else "").strip()

            properties = _unique_object([
                (child.tag.rsplit("}", 1)[-1], (child.text or "").strip())
                for child in root.findall(f"{namespace}properties/*")
            ])
            for field in ("groupId", "artifactId", "version"):
                properties[f"project.{field}"] = text(root, field)
                properties[f"pom.{field}"] = text(root, field)

            def expand(value: str) -> str:
                for _ in range(10):
                    if len(value) > 4096:
                        return ""

                    def substitute(match: re.Match[str]) -> str:
                        replacement = properties.get(match.group(1), match.group(0))
                        return replacement if len(replacement) <= 4096 else match.group(0)

                    updated = re.sub(r"\$\{([^}]+)\}", substitute, value)
                    if updated == value:
                        break
                    value = updated
                return value if len(value) <= 4096 else ""

            for maven_entry in root.findall(f"{namespace}dependencies/{namespace}dependency"):
                group = expand(text(maven_entry, "groupId"))
                artifact = expand(text(maven_entry, "artifactId"))
                add("Maven", f"{group}:{artifact}", expand(text(maven_entry, "version")),
                    allowed=bool(group and artifact) and "${" not in group + artifact
                    and not expand(text(maven_entry, "version")).endswith("-SNAPSHOT"))
            unresolved += 1  # A POM is not a resolved transitive lockfile, even with exact direct versions.
        elif name in {"package.json", "package-lock.json"}:
            if name == "package.json":
                for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
                    for package, version in _object(data.get(section, {})).items():
                        add("npm", package, version)
            elif "packages" in data:
                for key, raw in _object(data["packages"]).items():
                    if not key:
                        continue
                    entry = _object(raw)
                    package = entry.get("name") or key.rsplit("node_modules/", 1)[-1]
                    resolved_source = entry.get("resolved", "")
                    add("npm", package, entry.get("version"), allowed=not entry.get("link", False)
                        and isinstance(resolved_source, str)
                        and not resolved_source.startswith(("file:", "git", "http://", "link:")))
            elif "dependencies" in data:
                def walk(entries: Any) -> None:
                    for package, raw in _object(entries).items():
                        entry = _object(raw)
                        add("npm", package, entry.get("version"))
                        walk(entry.get("dependencies", {}))
                walk(data["dependencies"])
            else:
                raise ValueError("missing npm lock inventory")
        elif name == "Cargo.lock":
            for raw in _array(data.get("package")):
                entry = _object(raw)
                source = entry.get("source", "")
                add("crates.io", entry.get("name"), entry.get("version"),
                    allowed=source in {"registry+https://github.com/rust-lang/crates.io-index",
                                       "sparse+https://index.crates.io/"})
        elif name in {"requirements.txt", "pyproject.toml"}:
            if name == "pyproject.toml":
                project = _object(data.get("project", {}))
                lines = list(_array(project.get("dependencies", [])))
                for values in _object(project.get("optional-dependencies", {})).values():
                    lines.extend(_array(values))
                if project.get("dynamic") or data.get("tool", {}).get("poetry"):
                    unresolved += 1
            else:
                lines = [line.strip() for line in content.splitlines() if line.strip() and not line.lstrip().startswith("#")]
            for line in lines:
                if not isinstance(line, str):
                    raise ValueError("invalid requirement")
                match = _REQ.match(line)
                suffix = line[match.end():].strip() if match else ""
                if match and (not suffix or suffix.startswith((";", "#", "--hash="))):
                    add("PyPI", match.group(1), match.group(2))
                else:
                    unresolved += 1
        elif name == "go.mod":
            if not re.search(r"^\s*module\s+\S+", content, re.M):
                raise ValueError("missing Go module")
            in_require = False
            for line in content.splitlines():
                stripped = line.split("//", 1)[0].strip()
                if stripped == "require (":
                    in_require = True
                elif stripped == ")":
                    in_require = False
                elif in_require or stripped.startswith("require "):
                    match = _GO.fullmatch(stripped.removeprefix("require "))
                    if match and _SEMVER.fullmatch(match.group(2)[1:]):
                        found.append(Dependency("Go", match.group(1), match.group(2), path))
                    elif stripped:
                        unresolved += 1
                elif stripped.startswith(("replace ", "exclude ")):
                    raise ValueError("Go replacements/exclusions require module resolution")
            if in_require:
                raise ValueError("unterminated Go require block")
        else:
            return _Parsed(valid=False)
        return _Parsed(tuple(found), unresolved)
    except (ValueError, TypeError, AttributeError, KeyError, RecursionError, yaml.YAMLError, ElementTree.ParseError):
        return _Parsed(valid=False)


def _parse_dependencies(path: str, content: str) -> list[Dependency]:
    return list(_read_manifest(path, content).dependencies)


def collect_dependencies(sources: Mapping[str, str]) -> tuple[list[Dependency], ScaCoverage]:
    """Return the exact offline inventory and coverage of the supplied manifests.

    Completeness applies to supplied files only, not an uncollected repository or
    a package-manager install. Inventory retains each source for SBOM provenance.
    """
    normalized = {path.replace("\\", "/"): content for path, content in sources.items()}
    manifests = {path: content for path, content in normalized.items()
                 if path.rsplit("/", 1)[-1] in MANIFEST_NAMES | _SUPPORTED_MANIFESTS | _LOCK_COVERAGE.keys()}
    parsed = {path: _read_manifest(path, content) for path, content in manifests.items()
              if path.rsplit("/", 1)[-1] in _SUPPORTED_MANIFESTS}
    dependencies: list[Dependency] = []
    omitted: list[str] = []
    unresolved = analyzed = 0
    for path in sorted(manifests):
        name = path.rsplit("/", 1)[-1]
        covered = any(candidate in parsed and parsed[candidate].valid and parsed[candidate].unresolved == 0
                      and bool(parsed[candidate].dependencies) for candidate in _companion_paths(path, name))
        entry = parsed.get(path)
        if entry is None:
            if covered:
                analyzed += 1
            else:
                omitted.append(path)
        elif not entry.valid:
            omitted.append(path)
        else:
            analyzed += 1
            if not covered:
                dependencies.extend(entry.dependencies)
                unresolved += entry.unresolved
    unique = list(dict.fromkeys(dependencies))
    identities = {(dep.ecosystem, dep.name, dep.version) for dep in unique}
    return unique, ScaCoverage(len(manifests), analyzed, len(identities), unresolved, 0, tuple(omitted))


def _companion_paths(path: str, name: str) -> list[str]:
    prefix, separator, _ = path.replace("\\", "/").rpartition("/")
    return [f"{prefix}/{item}" if separator else item for item in _LOCK_COVERAGE.get(name, ())]


class ScaAgent:
    """Query exact inventory against OSV; never infer CVEs from model memory."""

    def __init__(self, provider: AIProvider | None = None, *, client: httpx.AsyncClient | None = None) -> None:
        self._provider = provider
        self._client = client
        self._owns_client = client is None
        self.coverage = ScaCoverage()

    async def aclose(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None

    async def analyze(self, legacy_sources: Mapping[str, str]) -> list[ThreatFinding]:
        raw_dependencies, self.coverage = collect_dependencies(legacy_sources)
        dependencies: list[Dependency] = []
        seen: set[tuple[str, str, str]] = set()
        for dependency in raw_dependencies:
            key = (dependency.ecosystem, dependency.name, dependency.version)
            if key not in seen:
                seen.add(key)
                dependencies.append(dependency)
        if not self.coverage.complete:
            logger.warning("SCA coverage is partial: %s", self.coverage.detail)

        # Declared runtimes (base images, version files, engines) are not OSV
        # packages; they are checked against the offline emergency table and
        # live EOL data, and a failure there never fails the dependency check.
        runtime_findings: list[ThreatFinding] = []
        declarations = collect_runtime_declarations(dict(legacy_sources))
        if declarations:
            client = self._client
            if client is None:
                client = httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=False)
                self._client = client
            runtime_findings, runtime_info = await check_runtime_declarations(declarations, client=client)
            self.coverage = dataclass_replace(
                self.coverage,
                runtime_declarations=runtime_info.get("declarations", len(declarations)),
                eol_checked=bool(runtime_info.get("eol_checked")),
            )
            if runtime_info.get("note"):
                logger.info("Runtime check: %s", runtime_info["note"])

        if not dependencies:
            logger.info("No exact pinned dependencies available for authoritative SCA")
            return runtime_findings

        client = self._client
        if client is None:
            client = httpx.AsyncClient(timeout=httpx.Timeout(15.0), follow_redirects=False)
            self._client = client
        results: list[dict[str, Any]] = []
        for offset in range(0, len(dependencies), _MAX_PACKAGES):
            batch = dependencies[offset:offset + _MAX_PACKAGES]
            payload = {"queries": [
                {"package": {"ecosystem": dep.ecosystem, "name": dep.name}, "version": dep.version}
                for dep in batch
            ]}
            try:
                response = await client.post(_OSV_QUERY_BATCH, json=payload)
                response.raise_for_status()
                body = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise RuntimeError("authoritative OSV dependency lookup failed") from exc
            entries = body.get("results") if isinstance(body, dict) else None
            if (not isinstance(entries, list) or len(entries) != len(batch)
                    or any(not isinstance(entry, dict) or entry.get("next_page_token")
                           or not isinstance(entry.get("vulns", []), list) for entry in entries)):
                raise RuntimeError("authoritative OSV dependency lookup returned an invalid or paginated response")
            results.extend(entries)

        findings: list[ThreatFinding] = []
        for dependency, result in zip(dependencies, results, strict=True):
            vulnerabilities = result.get("vulns", []) if isinstance(result, dict) else []
            for vulnerability in vulnerabilities[:20] if isinstance(vulnerabilities, list) else []:
                if not isinstance(vulnerability, dict):
                    continue
                vuln_id = str(vulnerability.get("id", "OSV-UNKNOWN"))[:128]
                aliases = [str(value) for value in vulnerability.get("aliases", []) if str(value).startswith("CVE-")]
                advisory = aliases[0] if aliases else vuln_id
                summary = str(vulnerability.get("summary") or vulnerability.get("details") or "Known vulnerable dependency")
                findings.append(
                    ThreatFinding(
                        finding_id=f"SCA-{dependency.ecosystem}-{dependency.name}-{vuln_id}"[:128],
                        cwe=advisory,
                        severity=_severity(vulnerability),
                        summary=f"{dependency.name} {dependency.version}: {advisory} — {summary[:500]}",
                        affected_nodes=[dependency.source],
                        evidence=[f"OSV matched exact {dependency.ecosystem} package {dependency.name}@{dependency.version}"],
                    )
                )
        return findings + runtime_findings


__all__ = ["Dependency", "ScaAgent", "ScaCoverage", "collect_dependencies"]
