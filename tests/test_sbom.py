"""Offline CycloneDX export: exact components, purls, provenance, and coverage."""

from __future__ import annotations

import json

import httpx
import pytest

from engine.agents.sca_agent import Dependency, ScaCoverage
from engine.services.sbom import build_sbom, dependencies_to_cyclonedx, dependency_purl


@pytest.mark.parametrize("ecosystem,name,version,purl", [
    ("PyPI", "My_Package.Name", "1.2.3", "pkg:pypi/my-package-name@1.2.3"),
    ("npm", "@scope/pkg", "1.2.3", "pkg:npm/%40scope/pkg@1.2.3"),
    ("npm", "plain", "1.0.0+build", "pkg:npm/plain@1.0.0%2Bbuild"),
    ("crates.io", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"),
    ("Go", "github.com/Owner/Repo", "v1.2.3", "pkg:golang/github.com/Owner/Repo@v1.2.3"),
    ("Packagist", "vendor/library", "1.2.3", "pkg:composer/vendor/library@1.2.3"),
    ("RubyGems", "rack", "3.0.0", "pkg:gem/rack@3.0.0"),
    ("Maven", "org.example:library", "1.2.3", "pkg:maven/org.example/library@1.2.3"),
    ("NuGet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/newtonsoft.json@13.0.3"),
])
def test_ecosystem_purls(ecosystem, name, version, purl):
    assert dependency_purl(Dependency(ecosystem, name, version, "source")) == purl


def properties(document):
    return {entry["name"]: entry["value"] for entry in document["metadata"]["properties"]}


def test_build_is_offline_deterministic_and_json_serializable(monkeypatch):
    def forbid_network(*args, **kwargs):
        raise AssertionError("SBOM must not use network")

    monkeypatch.setattr(httpx.AsyncClient, "post", forbid_network)
    monkeypatch.setattr(httpx.Client, "request", forbid_network)
    sources = {"b/requirements.txt": "requests==2.32.4", "a/requirements.txt": "requests==2.32.4"}
    document = build_sbom(sources)
    assert document == build_sbom(dict(reversed(list(sources.items()))))
    assert json.loads(json.dumps(document)) == document
    assert document["bomFormat"] == "CycloneDX"
    assert document["specVersion"] == "1.5"
    assert len(document["components"]) == 1
    component = document["components"][0]
    assert component["purl"] == component["bom-ref"] == "pkg:pypi/requests@2.32.4"
    assert component["properties"] == [
        {"name": "arbalest:source-manifest", "value": "a/requirements.txt"},
        {"name": "arbalest:source-manifest", "value": "b/requirements.txt"},
    ]
    assert json.loads(properties(document)["arbalest:coverage"])["complete"] is True
    assert properties(document)["arbalest:dependency-graph-complete"] == "false"
    assert "supplied manifests only" in properties(document)["arbalest:coverage-scope"]
    assert "dependencies" not in document  # Never invent transitive/root edges.
    assert "vulnerabilities" not in document


def test_partial_coverage_and_unsupported_manifest_are_explicit():
    document = build_sbom({"requirements.txt": "safe==1.0\nunresolved>=2", "build.gradle": "implementation 'foo:bar:1.0'"})
    coverage = json.loads(properties(document)["arbalest:coverage"])
    assert coverage["complete"] is False
    assert coverage["omitted_manifests"] == ["build.gradle"]
    assert coverage["unresolved_declarations"] == 1
    assert document["compositions"][0]["aggregate"] == "incomplete"
    assert [component["name"] for component in document["components"]] == ["safe"]


def test_multiple_versions_are_separate_components_and_no_cap():
    document = build_sbom({"requirements.txt": "foo==1.0\nfoo==2.0\n" + "\n".join(f"pkg{i}==1" for i in range(120))})
    assert len(document["components"]) == 122
    assert len({component["bom-ref"] for component in document["components"]}) == 122
    assert json.loads(properties(document)["arbalest:coverage"])["truncated_dependencies"] == 0


def test_maven_component_group_and_partial_resolution():
    document = build_sbom({"pom.xml": '''<project><dependencies><dependency>
        <groupId>org.example</groupId><artifactId>library</artifactId><version>1.2.3</version>
        </dependency></dependencies></project>'''})
    component = document["components"][0]
    assert component["group"] == "org.example"
    assert component["name"] == "library"
    assert component["purl"] == "pkg:maven/org.example/library@1.2.3"
    assert document["compositions"][0]["aggregate"] == "incomplete"


def test_canonical_purls_merge_provenance_not_distinct_versions():
    dependencies = [Dependency("PyPI", "My_Package", "1.0", "one"),
                    Dependency("PyPI", "my-package", "1.0", "two"),
                    Dependency("PyPI", "my-package", "2.0", "three")]
    document = dependencies_to_cyclonedx(dependencies, ScaCoverage(manifests=3, analyzed_manifests=3, dependencies=3))
    assert len(document["components"]) == 2
    assert len(document["components"][0]["properties"]) == 2


def test_scoped_components_split_group_and_name():
    document = build_sbom({"package-lock.json": '{"packages":{"node_modules/@scope/pkg":{"version":"1.2.3"}}}'})
    component = document["components"][0]
    assert component["group"] == "@scope"
    assert component["name"] == "pkg"


def test_empty_sources_do_not_claim_repository_is_complete():
    document = build_sbom({})
    assert document["components"] == []
    assert document["compositions"][0]["aggregate"] == "incomplete"
    assert properties(document)["arbalest:vulnerability-lookup-performed"] == "false"


def test_invalid_and_unresolved_lockfiles_are_visible():
    document = build_sbom({"uv.lock": "invalid TOML", "packages.lock.json": '{"version":1,"dependencies":{"net8.0":{"foo":{"type":"Direct"}}}}'})
    assert document["components"] == []
    coverage = json.loads(properties(document)["arbalest:coverage"])
    assert coverage["omitted_manifests"] == ["uv.lock"]
    assert coverage["unresolved_declarations"] == 1
    assert not coverage["complete"]
