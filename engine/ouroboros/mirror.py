"""The Mirror Sandbox — Arbalest executing a mutated copy of itself.

The mutated organism is installed into a Nebius Token Factory Sandbox as an
import closure: mutated files + their local dependency closure + a
``sitecustomize`` compatibility layer (the sandbox's python:3.12-slim carries
no third-party packages, so leaf SDKs are stubbed and pydantic is provided by
a real minimal shim), plus a deterministic regression battery and the
generated capability test.

Verdict doctrine mirrors the RedTeamSwarm: the ``OUROBOROS_MIRROR_SELFTEST_PASSED``
marker is evidence only when the sandbox completed cleanly — anything else is
failure. Nothing is simulated.
"""

from __future__ import annotations

MARKER_PASSED = "OUROBOROS_MIRROR_SELFTEST_PASSED"
MARKER_FAILED = "OUROBOROS_MIRROR_SELFTEST_FAILED"

# The regression battery exercises these subsystems; their import closure must
# be installed alongside the mutated files or the mirror cannot even boot.
BATTERY_SEEDS: tuple[str, ...] = (
    "engine/immune/detection.py",
    "engine/immune/topology.py",
    "engine/services/source_collector.py",
    "engine/hive/federation.py",
)

_SITECUSTOMIZE = '''"""Ouroboros mirror compatibility layer (auto-loaded in the mirror sandbox)."""
import importlib.abc
import importlib.machinery
import sys
import types
import json as _json
from unittest import mock

# Leaf third-party SDKs: any attribute AND any submodule import resolves to a
# lazy stub, because the sandbox python:3.12-slim ships no third-party packages
# and the battery never executes their internals.
_STUB_ROOTS = frozenset({
    "httpx", "openai", "docker", "chromadb", "sentence_transformers",
    "neo4j", "firebase_admin", "jwt", "cryptography", "azure", "yaml",
})


class _StubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Provides lazy stub modules (and all their submodules) for stub roots."""

    def find_spec(self, fullname, path=None, target=None):
        if fullname.split(".")[0] in _STUB_ROOTS:
            return importlib.machinery.ModuleSpec(fullname, self, is_package=True)
        return None

    def create_module(self, spec):
        module = types.ModuleType(spec.name)
        module.__path__ = []  # package marker: submodule imports route back here
        module.__getattr__ = lambda item: mock.MagicMock()  # PEP 562
        return module

    def exec_module(self, module):
        return None


sys.meta_path.insert(0, _StubFinder())


class _FieldInfo:
    def __init__(self, default=None, **kwargs):
        self.default = default


def Field(default=None, **kwargs):
    return _FieldInfo(default, **kwargs)


def ConfigDict(**kwargs):
    return dict(kwargs)


class ValidationError(Exception):
    pass


def field_validator(*args, **kwargs):
    def decorator(fn):
        return fn
    return decorator


def model_validator(*args, **kwargs):
    def decorator(fn):
        return fn
    return decorator


class SecretStr(str):
    def get_secret_value(self):
        return str(self)


class _BaseModelMeta(type):
    pass


class BaseModel(metaclass=_BaseModelMeta):
    """Minimal pydantic-compatible base: annotated fields + defaults + dump.

    Engine modules subclass BaseModel at import time, so the mirror needs real
    class semantics (unlike the leaf SDK stubs above).
    """

    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls.__fields__ = {}
        for klass in reversed(cls.__mro__):
            for name, annotation in getattr(klass, "__annotations__", {}).items():
                cls.__fields__[name] = annotation

    def __init__(self, **data):
        for name in self.__fields__:
            if name in data:
                value = data[name]
            elif hasattr(type(self), name):
                default = getattr(type(self), name)
                value = default.default if isinstance(default, _FieldInfo) else default
            else:
                value = None
            setattr(self, name, value)
        for name, value in data.items():
            if name not in self.__fields__:
                setattr(self, name, value)

    def model_dump(self, mode=None, by_alias=False):
        return {name: getattr(self, name) for name in self.__fields__}

    @classmethod
    def model_validate_json(cls, raw):
        return cls(**_json.loads(raw))

    def model_copy(self, *, update=None):
        payload = self.model_dump()
        payload.update(update or {})
        return type(self)(**payload)

    @classmethod
    def model_json_schema(cls):
        properties = {name: {"type": "string"} for name in cls.__fields__}
        return {"type": "object",
                "properties": properties,
                "required": list(cls.__fields__)}


_pydantic = types.ModuleType("pydantic")
_pydantic.BaseModel = BaseModel
_pydantic.Field = Field
_pydantic.ConfigDict = ConfigDict
_pydantic.ValidationError = ValidationError
_pydantic.field_validator = field_validator
_pydantic.model_validator = model_validator
_pydantic.SecretStr = SecretStr
sys.modules.setdefault("pydantic", _pydantic)
'''




_MIRROR_HARNESS = '''"""Ouroboros mirror self-test — proves the mutated organism still lives.

Deterministic regression battery over real engine subsystems, then the
generated capability test. Exits nonzero unless every check passes.
"""
import os
import sys
from pathlib import Path

sys.path.insert(0, os.getcwd())
RESULTS = []


def check(name, fn):
    try:
        fn()
        RESULTS.append((name, True, ""))
        print(f"  PASS {name}")
    except Exception as exc:
        RESULTS.append((name, False, f"{type(exc).__name__}: {exc}"))
        print(f"  FAIL {name}: {type(exc).__name__}: {exc}")


def battery_detection():
    from engine.immune.detection import sweep_file

    vuln = "import pickle\\n\\ndef load(blob):\\n    return pickle.loads(blob)\\n"
    hits = sweep_file("mod.py", vuln)
    assert any(f.rule_id == "SENT-PY-004" for f in hits), f"missing SENT-PY-004: {hits}"
    assert sweep_file("mod.py", "x = 1\\n") == []


def battery_topology():
    from engine.immune.detection import DetectionFinding
    from engine.immune.topology import TopologyMapper

    routes = (
        "from handlers import run_scan\\n\\n"
        "@app.route('/scan')\\n"
        "def scan_endpoint(repo):\\n"
        "    return run_scan(repo)\\n"
    )
    handlers = "from executors import run_shell\\n\\ndef run_scan(repo):\\n    return run_shell(repo)\\n"
    executors = "import os\\n\\ndef run_shell(cmd):\\n    return os.system(cmd)\\n"
    mapper = TopologyMapper({"routes.py": routes, "handlers.py": handlers, "executors.py": executors})
    finding = DetectionFinding(
        rule_id="SENT-PY-008", name="os.system", cwe="CWE-78", severity="high",
        file="executors.py", line=4, col=12, evidence="return os.system(cmd)",
    )
    radius = mapper.trace(finding)
    assert radius.proven, radius.summary()
    assert "scan_endpoint" in radius.chains[0][0]["name"]


def battery_collector():
    from engine.services.source_collector import run_recon

    os.makedirs("mirror_fix", exist_ok=True)
    with open("mirror_fix/mod.py", "w", encoding="utf-8") as fh:
        fh.write("x = 1\\n")
    with open("mirror_fix/requirements.txt", "w", encoding="utf-8") as fh:
        fh.write("pyyaml==3.13\\n")
    report = run_recon(Path("mirror_fix"))
    assert report.total_files == 2, report.summary()
    assert report.manifests == ["requirements.txt"], report.manifests


def battery_federation():
    from engine.hive.federation import FleetTopology

    lib = "def sign(payload):\\n    return payload\\n"
    svc = "from authlib.core import sign\\n\\ndef issue():\\n    return sign('x')\\n"
    topology = FleetTopology({
        "authlib": {"authlib/__init__.py": "", "authlib/core.py": lib},
        "svc": {"svc/app.py": svc},
    })
    assert topology.cross_edges, "cross-repo link missing"


def run_capability():
    with open("capability_test.py", "r", encoding="utf-8") as fh:
        code = fh.read()
    scope = {"__name__": "capability_test", "__file__": "capability_test.py"}
    exec(compile(code, "capability_test.py", "exec"), scope)


check("engine.immune.detection sweep", battery_detection)
check("engine.immune.topology attack chain", battery_topology)
check("engine.services.source_collector recon", battery_collector)
check("engine.hive.federation cross-repo link", battery_federation)
check("capability synthesis", run_capability)

ok = all(passed for _name, passed, _detail in RESULTS)
print("__PASSED_MARKER__" if ok else "__FAILED_MARKER__")
sys.exit(0 if ok else 1)
'''.replace("__PASSED_MARKER__", MARKER_PASSED).replace("__FAILED_MARKER__", MARKER_FAILED)


def build_mirror_workspace(
    mutated: dict[str, str],
    closure: list[str],
    original_sources: dict[str, str],
    capability_test: str,
    fixtures: dict[str, str] | None = None,
) -> dict[str, str]:
    """Assemble the mirror install: shim + harness + mutated files + closure."""
    workspace: dict[str, str] = {
        "sitecustomize.py": _SITECUSTOMIZE,
        "mirror_harness.py": _MIRROR_HARNESS,
        "capability_test.py": capability_test,
    }
    for path, content in mutated.items():
        workspace[path] = content
    for path in closure:
        if path not in workspace and path in original_sources:
            workspace[path] = original_sources[path]
    for path, content in (fixtures or {}).items():
        workspace[path] = content
    return workspace


def conservative_verdict(sandbox_succeeded: bool, exit_code: int | None, transcript: str) -> bool:
    """Marker-only doctrine: success requires a clean run AND the pass marker."""
    return bool(sandbox_succeeded and exit_code == 0 and MARKER_PASSED in transcript)
