"""Exact offline parsing and bounded authoritative lookups across ecosystems."""

from __future__ import annotations

import json

import httpx
import pytest

from engine.agents import sca_agent
from engine.agents.sca_agent import ScaAgent, _parse_dependencies, collect_dependencies


EXACT_MANIFESTS = [
    ("uv.lock", '''version = 1
[[package]]
name = "root"
version = "0.1.0"
source = { virtual = "." }
[[package]]
name = "requests"
version = "2.32.4"
source = { registry = "https://pypi.org/simple" }
''', "PyPI", "requests", "2.32.4"),
    ("poetry.lock", '''[[package]]
name = "requests"
version = "2.32.4"
''', "PyPI", "requests", "2.32.4"),
    ("Pipfile.lock", json.dumps({"default": {"requests": {"version": "==2.32.4"}}, "develop": {}}),
     "PyPI", "requests", "2.32.4"),
    ("composer.lock", json.dumps({"packages": [{"name": "vendor/library", "version": "v1.2.3"}], "packages-dev": []}),
     "Packagist", "vendor/library", "1.2.3"),
    ("Gemfile.lock", '''GEM
  remote: https://rubygems.org/
  specs:
    rack (3.1.2)
      base64 (>= 0)

PLATFORMS
  ruby

DEPENDENCIES
  rack

BUNDLED WITH
   2.5.0
''', "RubyGems", "rack", "3.1.2"),
    ("pnpm-lock.yaml", '''lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      '@scope/pkg':
        specifier: ^1.2.0
        version: 1.2.3(peer@2.0.0)
packages:
  '@scope/pkg@1.2.3':
    resolution: {integrity: sha512-example}
snapshots:
  '@scope/pkg@1.2.3(peer@2.0.0)': {}
''', "npm", "@scope/pkg", "1.2.3"),
    ("pnpm-lock.yaml", '''lockfileVersion: 5.4
packages:
  /foo/1.2.3_peer@2.0.0:
    resolution: {integrity: sha512-example}
''', "npm", "foo", "1.2.3"),
    ("pnpm-lock.yaml", '''lockfileVersion: '6.0'
packages:
  /@scope/pkg@1.2.3(peer@2.0.0):
    resolution: {integrity: sha512-example}
''', "npm", "@scope/pkg", "1.2.3"),
    ("yarn.lock", '''# yarn lockfile v1

"@scope/pkg@^1.0.0", "@scope/pkg@~1.2.0":
  version "1.2.3"
  resolved "https://registry.yarnpkg.com/@scope/pkg/-/pkg-1.2.3.tgz#abc"
  integrity sha512-example
  dependencies:
    child "^2.0.0"
''', "npm", "@scope/pkg", "1.2.3"),
    ("yarn.lock", '''__metadata:
  version: 8
  cacheKey: 10c0
"@scope/pkg@npm:^1.0.0":
  version: 1.2.3
  resolution: "@scope/pkg@npm:1.2.3"
  checksum: example
  languageName: node
  linkType: hard
''', "npm", "@scope/pkg", "1.2.3"),
    ("packages.lock.json", json.dumps({"version": 1, "dependencies": {
        "net8.0": {"Newtonsoft.Json": {"type": "Direct", "requested": "[13.0.3, )", "resolved": "13.0.3"}},
        "net8.0/linux-x64": {"Newtonsoft.Json": {"type": "Transitive", "resolved": "13.0.3"}},
    }}), "NuGet", "Newtonsoft.Json", "13.0.3"),
]


@pytest.mark.parametrize("filename,content,ecosystem,name,version", EXACT_MANIFESTS)
def test_exact_inventory(filename, content, ecosystem, name, version):
    dependencies, coverage = collect_dependencies({f"nested/{filename}": content})
    assert {(dep.ecosystem, dep.name, dep.version, dep.source) for dep in dependencies} == {
        (ecosystem, name, version, f"nested/{filename}"),
    }
    assert coverage.complete, coverage.as_dict()
    assert coverage.dependencies == 1


@pytest.mark.parametrize("filename,content", [
    ("uv.lock", '[[package]]\nname="local"\nversion="1.2.3"\nsource={git="https://example.test/repo"}'),
    ("uv.lock", '[[package]]\nname="local"\nversion="1.2.3"\nsource={editable="lib"}'),
    ("uv.lock", '[[package]]\nname="private"\nversion="1.2.3"\nsource={registry="https://private.test/simple"}'),
    ("poetry.lock", '[[package]]\nname="local"\nversion="1.2.3"\nsource={type="git",url="https://example.test/repo"}'),
    ("Pipfile.lock", '{"default":{"foo":{"version":"*"}}}'),
    ("Pipfile.lock", '{"default":{"foo":{"version":"==1.0", "git":"https://example.test/repo"}}}'),
    ("composer.lock", '{"packages":[{"name":"v/p", "version":"dev-main"}]}'),
    ("composer.lock", '{"packages":[{"name":"v/p", "version":"1.2.x-dev"}]}'),
    ("Gemfile.lock", 'GIT\n  remote: https://example.test/repo\n  specs:\n    foo (1.0.0)\n'),
    ("Gemfile.lock", 'PATH\n  remote: .\n  specs:\n    foo (1.0.0)\n'),
    ("Gemfile.lock", 'GEM\n  remote: https://private.test/\n  specs:\n    foo (1.0.0)\n'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\nimporters:\n  .:\n    dependencies:\n      foo: {version: "link:../foo"}\n'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages:\n  "foo@https://example.test/foo.tgz": {}\n'),
    ("yarn.lock", '__metadata: {version: 8}\n"foo@workspace:.": {version: "0.0.0-use.local", resolution: "foo@workspace:."}\n'),
    ("yarn.lock", '# yarn lockfile v1\n"foo@git+https://example.test/repo":\n  version "1.0"\n  resolved "https://example.test/repo"\n'),
    ("packages.lock.json", '{"version":1,"dependencies":{"net8.0":{"foo":{"type":"Direct", "requested":"*"}}}}'),
    ("packages.lock.json", '{"version":1,"dependencies":{"net8.0":{"foo":{"type":"Project"}}}}'),
])
def test_unresolved_entries_are_not_invented(filename, content):
    dependencies, coverage = collect_dependencies({filename: content})
    assert not dependencies
    assert not coverage.complete
    assert coverage.unresolved_declarations >= 1


@pytest.mark.parametrize("filename,content", [
    ("uv.lock", '[[package]'),
    ("uv.lock", 'package = {}'),
    ("poetry.lock", '[[package]]\nname="foo"\nversion="1"\nversion="2"'),
    ("Pipfile.lock", '{"default": []}'),
    ("Pipfile.lock", '{"default":{"foo":{"version":"==1"},"foo":{"version":"==2"}}}'),
    ("composer.lock", '{}'),
    ("composer.lock", '{"packages":[{"name":"foo/bar","version":"1.0"},42]}'),
    ("Gemfile.lock", 'GEM\n  specs:\n    invalid spec\n'),
    ("Gemfile.lock", 'GEM\n  remote: https://rubygems.org/\n  specs:\n   foo (1.0)\n'),
    ("Gemfile.lock", 'GEM\n  remote: https://rubygems.org/\n  specs:\n    foo (1.0)\n      broken (\n'),
    ("Gemfile.lock", 'DEPENDENCIES\n  foo\n'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages: [broken]'),
    ("pnpm-lock.yaml", 'lockfileVersion: 100\npackages: {}'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages:\n  foo@1: {}\n  foo@1: {}'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages: &a {foo@1: *a}'),
    ("yarn.lock", '# yarn lockfile v1\nfoo@^1:\n  version "1"\n  version "2"'),
    ("yarn.lock", '# yarn lockfile v1\nfoo@^1:\n  version nope'),
    ("yarn.lock", 'not a lockfile'),
    ("yarn.lock", '__metadata: {version: 999}'),
    ("pom.xml", '<project><dependencies>'),
    ("pom.xml", '<project><dependencies><dependency><groupId>org.example</groupId><artifactId>foo</artifactId><version>1.0</version><version>2.0</version></dependency></dependencies></project>'),
    ("pom.xml", '<project><properties><v>1.0</v><v>2.0</v></properties></project>'),
    ("pom.xml", '<!DOCTYPE project [<!ENTITY a "x">]><project/>'),
    ("packages.lock.json", '{"version":1, "dependencies": []}'),
    ("packages.lock.json", '{"version":3, "dependencies": {}}'),
    ("package-lock.json", '[]'),
])
def test_malformed_files_fail_closed(filename, content):
    dependencies, coverage = collect_dependencies({filename: content})
    assert dependencies == []
    assert not coverage.complete
    assert coverage.omitted_manifests == (filename,)
    assert coverage.analyzed_manifests == 0


def test_maven_local_properties_and_namespace_without_transitive_claim():
    pom = '''<project xmlns="http://maven.apache.org/POM/4.0.0">
      <modelVersion>4.0.0</modelVersion><version>1.2.3</version>
      <properties><lib.version>${project.version}</lib.version></properties>
      <dependencies>
        <dependency><groupId>org.example</groupId><artifactId>library</artifactId><version>${lib.version}</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>managed</artifactId></dependency>
        <dependency><groupId>org.example</groupId><artifactId>range</artifactId><version>[1,2)</version></dependency>
        <dependency><groupId>org.example</groupId><artifactId>snapshot</artifactId><version>1.0-SNAPSHOT</version></dependency>
      </dependencies>
      <dependencyManagement><dependencies><dependency><groupId>not</groupId><artifactId>installed</artifactId><version>2.0</version></dependency></dependencies></dependencyManagement>
    </project>'''
    dependencies, coverage = collect_dependencies({"pom.xml": pom})
    assert [(dep.ecosystem, dep.name, dep.version) for dep in dependencies] == [("Maven", "org.example:library", "1.2.3")]
    assert coverage.unresolved_declarations == 4
    assert not coverage.complete


def test_gem_platform_and_duplicate_versions():
    content = 'GEM\n  remote: https://rubygems.org/\n  specs:\n    nokogiri (1.18.0-x86_64-linux-gnu)\n    nokogiri (1.18.0-arm64-darwin)\n'
    dependencies, coverage = collect_dependencies({"Gemfile.lock": content})
    assert [(dep.name, dep.version) for dep in dependencies] == [("nokogiri", "1.18.0")]
    assert coverage.complete


@pytest.mark.parametrize("name,content", [
    ("requirements.txt", "foo==1.*\nfoo>=1\n-r other.txt\nfoo==1.0,!=1.0\n"),
    ("package.json", '{"dependencies":{"foo":"1.x", "bar":"^1.0", "partial":"1.0"}}'),
    ("pyproject.toml", '[project]\ndependencies=["foo>=1"]'),
])
def test_ranges_wildcards_and_includes_remain_unresolved(name, content):
    assert not _parse_dependencies(name, content)
    assert not collect_dependencies({name: content})[1].complete


def test_valid_companion_must_be_in_same_directory_and_complete():
    sources = {"app/package.json": '{"dependencies":{"foo":"^1"}}',
               "app/package-lock.json": '{"packages":{"node_modules/foo":{"version":"1.0.0"}}}'}
    dependencies, coverage = collect_dependencies(sources)
    assert coverage.complete
    assert [(dep.name, dep.version) for dep in dependencies] == [("foo", "1.0.0")]
    sources["app/package-lock.json"] = '{"packages":{"node_modules/foo":{"version":"*"}}}'
    assert not collect_dependencies(sources)[1].complete
    sources["package-lock.json"] = sources.pop("app/package-lock.json")
    assert not collect_dependencies(sources)[1].complete


def test_malformed_companion_does_not_mask_manifest():
    dependencies, coverage = collect_dependencies({"package.json": '{"dependencies":{"foo":"^1"}}',
                                                 "package-lock.json": 'not json'})
    assert not dependencies
    assert coverage.unresolved_declarations == 1
    assert coverage.omitted_manifests == ("package-lock.json",)


def test_oversized_files_are_not_silently_prefix_parsed():
    dependencies, coverage = collect_dependencies({"requirements.txt": "foo==1.0\n" + "#" * 512_000})
    assert dependencies == []
    assert not coverage.complete


def test_provenance_and_case_sensitive_package_identities():
    sources = {"one/requirements.txt": "foo==1.0", "two/requirements.txt": "foo==1.0",
               "go.mod": "module example.test/main\nrequire (\nexample.test/Foo v1.0.0\nexample.test/foo v1.0.0\n)"}
    dependencies, coverage = collect_dependencies(sources)
    assert len(dependencies) == 4
    assert coverage.dependencies == 3
    assert coverage.complete


@pytest.mark.asyncio
async def test_all_packages_queried_in_bounded_batches_without_truncation():
    batches = []

    def handler(request):
        queries = json.loads(request.content)["queries"]
        batches.append(queries)
        return httpx.Response(200, json={"results": [
            {"vulns": [{"id": "TEST-LAST", "summary": "last package"}]} if item["package"]["name"] == "pkg204" else {}
            for item in queries
        ]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        agent = ScaAgent(client=client)
        findings = await agent.analyze({"requirements.txt": "\n".join(f"pkg{i}==1.0" for i in range(205))})
    assert [len(batch) for batch in batches] == [100, 100, 5]
    assert len(findings) == 1
    assert "pkg204" in findings[0].summary
    assert agent.coverage.dependencies == 205
    assert agent.coverage.truncated_dependencies == 0
    assert agent.coverage.complete


@pytest.mark.parametrize("result", [None, [], {"vulns": "invalid"}, {"next_page_token": "more"}])
@pytest.mark.asyncio
async def test_osv_invalid_or_paginated_results_are_errors(result):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json={"results": [result]})
    )) as client:
        with pytest.raises(RuntimeError, match="invalid or paginated"):
            await ScaAgent(client=client).analyze({"requirements.txt": "foo==1.0"})


@pytest.mark.asyncio
async def test_later_batch_failure_does_not_return_partial_success():
    calls = 0

    def handler(request):
        nonlocal calls
        calls += 1
        if calls == 2:
            return httpx.Response(503)
        return httpx.Response(200, json={"results": [{} for _ in json.loads(request.content)["queries"]]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(RuntimeError, match="lookup failed"):
            await ScaAgent(client=client).analyze({"requirements.txt": "\n".join(f"pkg{i}==1" for i in range(101))})
    assert calls == 2


@pytest.mark.parametrize("filename,content", [
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages: {"foo@1.2.3": {}}\nimporters: {".": {dependencies: {foo: {version: "9.9.9"}}}}'),
    ("pnpm-lock.yaml", 'lockfileVersion: 9.0\npackages: {}\nsnapshots: {"foo@1.2.3": {}}'),
    ("pnpm-lock.yaml", 'lockfileVersion: 6.0\npackages: {"foo@1.2.3(peer@2.0.0": {}}'),
    ("Pipfile.lock", '{"default":{"foo":{"version":"==1.0", "index":"private"}}, "_meta":{"sources":[{"name":"private","url":"https://private.test/simple"}]}}'),
    ("Pipfile.lock", '{"default":{},"custom":{"foo":{"version":"==1.0"}}}'),
    ("uv.lock", '[[package]]\nname="fake"\nversion="1.0"\nsource={virtual=".",git="https://example.test/repo"}'),
])
def test_partial_and_inconsistent_locks_do_not_claim_complete(filename, content):
    assert not collect_dependencies({filename: content})[1].complete


@pytest.mark.parametrize("filename,content", [
    ("yarn.lock", '# yarn lockfile v1\nfoo@^1:\n  version "1.2.3"\n  resolved "https://registry.npmjs.org/foo.tgz"\nfoo@^1:\n  version "1.2.4"\n'),
    ("yarn.lock", '# yarn lockfile v1\nfoo@^1:\n  version "1.2.3"\n    child "^1"\n'),
    ("Gemfile.lock", 'GEM\n  remote: https://rubygems.org/\n  specs:\n    foo (1.0)\nUNKNOWN SECTION\n'),
    ("go.mod", 'module example.test/root\nrequire (\nexample.test/pkg v1.0.0\n'),
    ("go.mod", 'module example.test/root\nrequire example.test/pkg v1.0.0\nreplace example.test/pkg => ../local\n'),
])
def test_additional_malformed_or_unsupported_structures_fail_closed(filename, content):
    dependencies, coverage = collect_dependencies({filename: content})
    assert not dependencies
    assert not coverage.complete
    assert coverage.omitted_manifests == (filename,)


@pytest.mark.parametrize("filename,content,expected", [
    ("Pipfile.lock", '{"default":{"foo":{"version":"==1.0"}}, "develop":{"bar":{"version":"==2.0"}}}',
     {("foo", "1.0"), ("bar", "2.0")}),
    ("composer.lock", '{"packages":[{"name":"v/p","version":"v1.0"}], "packages-dev":[{"name":"v/dev","version":"v2.0"}]}',
     {("v/p", "1.0"), ("v/dev", "2.0")}),
    ("packages.lock.json", '{"version":2,"dependencies":{"net8.0":{"foo":{"type":"Direct","resolved":"1.0"}}, "net9.0":{"foo":{"type":"Transitive","resolved":"2.0"}}}}',
     {("foo", "1.0"), ("foo", "2.0")}),
    ("package-lock.json", '{"lockfileVersion":1,"dependencies":{"foo":{"version":"1.0.0", "dependencies":{"bar":{"version":"2.0.0"}}}}}',
     {("foo", "1.0.0"), ("bar", "2.0.0")}),
    ("pyproject.toml", '[project]\ndependencies=["foo==1.0"]\n[project.optional-dependencies]\ntest=["bar==2.0"]',
     {("foo", "1.0"), ("bar", "2.0")}),
])
def test_development_optional_nested_and_framework_inventories(filename, content, expected):
    dependencies, coverage = collect_dependencies({filename: content})
    assert {(dep.name, dep.version) for dep in dependencies} == expected
    assert coverage.complete


def test_unresolved_entries_keep_other_exact_inventory():
    dependencies, coverage = collect_dependencies({"composer.lock": '{"packages":[{"name":"v/p","version":"1.0"},{"name":"v/dev","version":"dev-main"}]}'})
    assert [(dep.name, dep.version) for dep in dependencies] == [("v/p", "1.0")]
    assert coverage.unresolved_declarations == 1
    assert not coverage.complete


def test_empty_companion_cannot_mask_unresolved_manifest():
    dependencies, coverage = collect_dependencies({"package.json": '{"dependencies":{"foo":"^1"}}',
                                                 "package-lock.json": '{"packages":{}}'})
    assert not dependencies
    assert coverage.unresolved_declarations == 1
    assert not coverage.complete


@pytest.mark.parametrize("manifest,lock", [("Pipfile", "Pipfile.lock"), ("Gemfile", "Gemfile.lock"),
                                           ("composer.json", "composer.lock"), ("pyproject.toml", "uv.lock")])
def test_expanded_lock_companions_and_windows_paths(manifest, lock):
    lock_content = next(row[1] for row in EXACT_MANIFESTS if row[0] == lock)
    content = '[project]\ndependencies=["requests>=2"]' if manifest == "pyproject.toml" else "{}"
    dependencies, coverage = collect_dependencies({f"app\\{manifest}": content, f"app\\{lock}": lock_content})
    assert coverage.complete
    assert coverage.manifests == coverage.analyzed_manifests == 2
    assert len(dependencies) == 1
    assert dependencies[0].source == f"app/{lock}"


@pytest.mark.parametrize("filename,header", [
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
    ("yarn.lock", "__metadata: {version: 8}\n"),
])
@pytest.mark.parametrize("payload", [
    'payload: !!python/object/apply:os.system ["arbalest_yaml_must_not_execute"]\n',
    'payload: !!python/name:builtins.eval ""\n',
    'payload: !!python/object:builtins.object {}\n',
    'payload: &recursive [*recursive]\n',
    'one: &one [x, x]\ntwo: &two [*one, *one]\nthree: [*two, *two]\n',
    'payload: {<<: {injected: value}}\n',
    'payload: {same: first, same: second}\n',
    'packages: {}\n---\npayload: ignored-second-document\n',
])
def test_yaml_malicious_tags_aliases_merges_and_extra_documents_fail_closed(monkeypatch, filename, header, payload):
    def forbid_execution(*args, **kwargs):
        pytest.fail("YAML construction must not execute code")

    monkeypatch.setattr("os.system", forbid_execution)
    dependencies, coverage = collect_dependencies({filename: header + payload})
    assert dependencies == []
    assert coverage.omitted_manifests == (filename,)
    assert not coverage.complete


@pytest.mark.parametrize("filename,header", [
    ("pnpm-lock.yaml", "lockfileVersion: '9.0'\n"),
    ("yarn.lock", "__metadata: {version: 8}\n"),
])
@pytest.mark.parametrize("payload", ["packages: {}\n", "packages: [unterminated\n"])
def test_yaml_loader_is_disposed_after_success_and_failure(monkeypatch, filename, header, payload):
    disposed = []
    original_dispose = sca_agent._StrictLoader.dispose

    def record_dispose(loader):
        disposed.append(loader)
        return original_dispose(loader)

    monkeypatch.setattr(sca_agent._StrictLoader, "dispose", record_dispose)
    collect_dependencies({filename: header + payload})
    assert len(disposed) == 1


_XML_ATTACKS = [
    '<!DOCTYPE project SYSTEM "https://example.invalid/evil.dtd"><project/>',
    '<!DOCTYPE project PUBLIC "evil" "file:///must-not-be-read.dtd"><project/>',
    '<!DOCTYPE project [<!ENTITY xxe SYSTEM "file:///must-not-be-read">]><project>&xxe;</project>',
    '<!DOCTYPE project [<!ENTITY xxe SYSTEM "https://example.invalid/secret">]><project>&xxe;</project>',
    '<!DOCTYPE project [<!ENTITY % remote SYSTEM "https://example.invalid/evil.dtd">%remote;]><project/>',
    '<!DOCTYPE project [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><project>&c;</project>',
    '<!dOcTyPe project [<!eNtItY x "payload">]><project>&x;</project>',
    '<!ENTITY x "payload"><project/>',
    '<project>&undeclared;</project>',
    '&#60;!DOCTYPE project><project/>',
    '&lt;!DOCTYPE project><project/>',
    '%3C!DOCTYPE project><project/>',
    '\ufeff<?xml version="1.0"?><!DOCTYPE project><project/>',
    *('<!DOCTYPE project [<!ENTITY x "payload">]><project>&x;</project>'.encode(encoding).decode("latin-1")
      for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")),
    '<project>' + '<nested>' * 129 + '</nested>' * 129 + '</project>',
]


@pytest.mark.parametrize("content", _XML_ATTACKS)
def test_malicious_maven_xml_fails_closed_without_file_or_network_access(monkeypatch, content):
    def forbid_io(*args, **kwargs):
        pytest.fail("Maven XML parsing must not perform file or network I/O")

    monkeypatch.setattr("builtins.open", forbid_io)
    monkeypatch.setattr("socket.create_connection", forbid_io)
    dependencies, coverage = collect_dependencies({"pom.xml": content})
    assert dependencies == []
    assert coverage.omitted_manifests == ("pom.xml",)
    assert not coverage.complete


@pytest.mark.parametrize("content", _XML_ATTACKS[:6])
def test_xml_parser_rejects_dtds_even_without_textual_precheck(monkeypatch, content):
    # Simulate a precheck blind spot: the parser must reject the DTD before its
    # internal/external subset can define or expand even an unused entity.
    with monkeypatch.context() as patch:
        patch.setattr(sca_agent.re, "search", lambda *args, **kwargs: None)
        with pytest.raises(ValueError) as error:
            sca_agent._parse_maven_xml(content)
    assert "XML DTDs and entities are not supported" in str(error.value)


def test_xml_input_guards_run_before_parser_creation(monkeypatch):
    def forbid_parser(*args, **kwargs):
        pytest.fail("Rejected XML must never reach Expat")

    monkeypatch.setattr(sca_agent.expat, "ParserCreate", forbid_parser)
    for content in ("<project>\x00</project>", " " * 512_001, '<!dOcTyPe project><project/>'):
        with pytest.raises(ValueError):
            sca_agent._parse_maven_xml(content)


def test_maven_xml_keeps_namespaces_comments_cdata_and_predefined_references():
    content = '''<?xml version="1.0" encoding="UTF-8"?>
    <!-- A normal Maven POM comment -->
    <project xmlns="http://maven.apache.org/POM/4.0.0"
             xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
             xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://example.invalid/pom.xsd">
      <description>Entities &amp; numeric references &#x3c; are text, not markup.</description>
      <dependencies><dependency>
        <groupId>org.example</groupId><artifactId>library</artifactId><version><![CDATA[1.2.3]]></version>
      </dependency></dependencies>
    </project>'''
    dependencies, coverage = collect_dependencies({"pom.xml": content})
    assert [(dep.name, dep.version) for dep in dependencies] == [("org.example:library", "1.2.3")]
    assert coverage.analyzed_manifests == 1
    assert coverage.unresolved_declarations == 1  # Still no transitive Maven resolution.
