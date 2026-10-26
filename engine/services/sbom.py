"""Deterministic, offline CycloneDX 1.5 inventory of supplied dependency files.

This is an inventory, not an installed-environment or dependency-graph resolver.
No network calls, fabricated transitive edges, licenses, hashes, or CVEs are added.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import quote

from engine.agents.sca_agent import Dependency, ScaCoverage, collect_dependencies

_TYPES = {
    "PyPI": "pypi", "npm": "npm", "crates.io": "cargo", "Go": "golang",
    "Packagist": "composer", "RubyGems": "gem", "Maven": "maven", "NuGet": "nuget",
}


def dependency_purl(dependency: Dependency) -> str:
    """Encode package-url namespace/name/version without treating data as syntax."""
    package_type = _TYPES[dependency.ecosystem]
    name = dependency.name
    if package_type == "pypi":
        name = re.sub(r"[-_.]+", "-", name).lower()
    elif package_type == "nuget":
        name = name.lower()
    if package_type == "maven":
        group, separator, artifact = name.partition(":")
        if not separator or not group or not artifact:
            raise ValueError("Maven package requires groupId:artifactId")
        parts = [group, artifact]
    else:
        parts = name.split("/")
    encoded = "/".join(quote(part, safe=".-_~") for part in parts)
    return f"pkg:{package_type}/{encoded}@{quote(dependency.version, safe='.-_~')}"


def dependencies_to_cyclonedx(
    dependencies: Sequence[Dependency], coverage: ScaCoverage,
) -> dict[str, Any]:
    """Export exact components and explicit supplied-manifest coverage.

    Components merge by canonical purl while retaining all source manifests.
    The absence of a dependency graph is intentional: lockfile inventories do
    not consistently encode edges, and direct declarations are not full graphs.
    """
    components: dict[str, dict[str, Any]] = {}
    sources: dict[str, set[str]] = {}
    for dependency in sorted(dependencies, key=lambda dep: (dependency_purl(dep), dep.source, dep.name)):
        purl = dependency_purl(dependency)
        if purl not in components:
            component: dict[str, Any] = {
                "type": "library", "bom-ref": purl, "name": dependency.name,
                "version": dependency.version, "purl": purl,
            }
            if dependency.ecosystem == "Maven":
                component["group"], component["name"] = dependency.name.split(":", 1)
            elif dependency.ecosystem in {"npm", "Packagist"} and "/" in dependency.name:
                component["group"], component["name"] = dependency.name.rsplit("/", 1)
            components[purl] = component
        sources.setdefault(purl, set()).add(dependency.source)
    for purl, component in components.items():
        component["properties"] = [
            {"name": "arbalest:source-manifest", "value": path} for path in sorted(sources[purl])
        ]
    return {
        "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "properties": [
                {"name": "arbalest:coverage", "value": json.dumps(coverage.as_dict(), sort_keys=True)},
                {"name": "arbalest:coverage-scope", "value": "supplied manifests only; not an installed or repository-wide inventory"},
                {"name": "arbalest:dependency-graph-complete", "value": "false"},
                {"name": "arbalest:vulnerability-lookup-performed", "value": "false"},
            ],
        },
        "components": list(components.values()),
        "compositions": [{
            "aggregate": "complete" if coverage.complete and coverage.manifests else "incomplete",
            "assemblies": list(components),
        }],
    }


def build_sbom(sources: Mapping[str, str]) -> dict[str, Any]:
    """Build a JSON-serializable CycloneDX document entirely offline."""
    dependencies, coverage = collect_dependencies(sources)
    return dependencies_to_cyclonedx(dependencies, coverage)


__all__ = ["build_sbom", "dependencies_to_cyclonedx", "dependency_purl"]
