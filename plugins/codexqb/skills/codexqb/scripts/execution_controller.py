#!/usr/bin/env python3
"""Typed, reviewed process execution boundary for CodexQB controllers.

Repository-controlled validators must never be launched directly by Goal or
Apply consumers.  This whole-module-pinned boundary owns environment
sanitisation, descriptor-bound working directories, process containment,
timeouts, output budgets, and process-tree cleanup.
"""

from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import ModuleType

from repository_io import (
    RepositoryIO,
    _controller_normalize_path,
    _controller_validation_cwd,
    open_repository_io,
)


MAX_VALIDATION_OUTPUT_BYTES = 8 * 1024 * 1024
VALIDATION_OUTPUT_CHUNK_BYTES = 64 * 1024
MACOS_VALIDATION_SANDBOX = Path("/usr/bin/sandbox-exec")
MACOS_VALIDATION_SANDBOX_PROFILE = "(version 1)(allow default)(deny process-fork)"
LINUX_CLONE_THREAD = 0x00010000

PLANNER_VALIDATOR_BUNDLE_SCHEMA = "codexqb.planner-validator-bundle/v1"
MAX_VALIDATOR_SOURCE_BYTES = 4 * 1024 * 1024
MAX_VALIDATOR_BUNDLE_BYTES = 16 * 1024 * 1024
_VALIDATOR_ENTRY_NAME = "validate_planner_docs.py"
_VALIDATOR_BUNDLE_NAMES = (
    "artifact_io.py",
    "git_evidence.py",
    "mount_identity.py",
    "repository_evidence.py",
    "repository_io.py",
    "safety_contracts.py",
    _VALIDATOR_ENTRY_NAME,
)
GOAL_RUN_SOURCE_SHA256 = "8b90bbbcf9abc485b82ddfe1701b4271ddf2241b4b86948f57049423a23df982"
_VALIDATOR_SOURCE_SHA256 = (
    (
        "artifact_io.py",
        "608a783cf826037517a5481436c452a980629871943a84f9375763ef13b605a5",
    ),
    (
        "git_evidence.py",
        "b192a4c22bcf39646db579f49e25e5023d95a457db9160a7eb5bd67da888fe57",
    ),
    (
        "mount_identity.py",
        "920585f6dabffa77d459ee5be06469c73265f62ea493b06f32c8e636ebbfbbc1",
    ),
    (
        "repository_evidence.py",
        "8775f67acba3dd8aada6ffca660177ff9bf27d10f62add4861eb99803502ce2b",
    ),
    (
        "repository_io.py",
        "097cb306967c1be6ae922f674ba3af86085a31c0e2ff15ad8a4f549fe8d4e220",
    ),
    (
        "safety_contracts.py",
        "df43016eae8b2fe0a766be21c02984674a1a9743bde3536167b769682b4fcd58",
    ),
    (
        "validate_planner_docs.py",
        "ceb9b70d096f5da5d3355e65bba36e8a43551c8046239c50800ef2205a222c6b",
    ),
)
_HELD_RUNTIME_CONTEXT_NAME = "_codexqb_held_runtime_context_v1"
_HELD_RUNTIME_CONTEXT_ASSURANCE = "controller_observed_loader_path_unattested"
_HELD_RUNTIME_SOURCE_NAMES = frozenset(
    {
        "apply_run.py",
        "artifact_io.py",
        "controller_store.py",
        "doctor.py",
        "evidence_contracts.py",
        "execution_controller.py",
        "git_evidence.py",
        "goal_run.py",
        "mount_identity.py",
        "repository_evidence.py",
        "repository_io.py",
        "safety_contracts.py",
        "validate_planner_docs.py",
    }
)
_HELD_GOAL_RESOURCE_NAMES = frozenset(
    {
        "references/Autopsy-Planner.md",
        "references/Fourth-Planner.md",
        "references/Second-Planner.md",
        "references/Third-Planner.md",
        "references/goal-specs/step15.md",
        "references/goal-specs/step2.md",
        "references/goal-specs/step3.md",
        "references/goal-specs/step4.md",
        "references/handoffs/run-step2.md",
        "references/handoffs/run-step3.md",
        "references/handoffs/run-step4.md",
    }
)
GOAL_RESOURCE_SOURCE_SHA256 = (
    (
        "references/Autopsy-Planner.md",
        "d931702c68298ce3d7799a5ad849f66199033a33cd68ae36317e81f4ac5f570a",
    ),
    (
        "references/Fourth-Planner.md",
        "938637aed660df1bd1cc79b878b86a9d835ff7afda21eefda3c6210e8e15cc8c",
    ),
    (
        "references/Second-Planner.md",
        "41da50f6d751f8c85e146438a61381fecfc84513800b327a54c3fc911c3ed080",
    ),
    (
        "references/Third-Planner.md",
        "2f0534bc30c3363caf31dd84421ef7f6ae868c3abd9a6fa15b1c9ff104d95666",
    ),
    (
        "references/goal-specs/step15.md",
        "00cc341eda3dfaaab0704fcc56e4726f6d010e81678ff2e97a6eaa94e7302e09",
    ),
    (
        "references/goal-specs/step2.md",
        "5c54ec11f97f2953d353b5b9613d086ee6219c83fec2a0377f80507a41ef28e6",
    ),
    (
        "references/goal-specs/step3.md",
        "c1c6af73af03f91f9dfbed27efe57eff974759e608121a6ea90a24594b5bbaad",
    ),
    (
        "references/goal-specs/step4.md",
        "864e013c8aa3e1119c738c9d82c925ccf061e74ba54e2fd1c3f2bff2ea8da756",
    ),
    (
        "references/handoffs/run-step2.md",
        "6e424211a3b1a48fd90dbfce3b37bada6f15e425ee2d760e3699ecc0f8065f1e",
    ),
    (
        "references/handoffs/run-step3.md",
        "cc162e88f4ee4e15ecd86638d197fb7662749a992c8fc7cae95cf2d72ca2c124",
    ),
    (
        "references/handoffs/run-step4.md",
        "ac211f6a4ea44966975fc4c6fe7679277f36a35b0c8a74c9dd50f3a64f71c16e",
    ),
)
_GOAL_HELD_PATHS = frozenset(
    {"scripts/goal_run.py", *(path for path, _digest in GOAL_RESOURCE_SOURCE_SHA256)}
)
_MAX_HELD_GOAL_SOURCE_BYTES = 4 * 1024 * 1024
_MAX_HELD_GOAL_RESOURCE_BUNDLE_BYTES = 16 * 1024 * 1024

if {path for path, _digest in GOAL_RESOURCE_SOURCE_SHA256} != _HELD_GOAL_RESOURCE_NAMES:
    raise RuntimeError("goal_resource_source_pin_registry_invalid")

# This bootstrap is passed as a literal to an isolated child interpreter.  It
# loads every local CodexQB dependency from the descriptor-captured envelope;
# no target or plugin-runtime pathname is placed on sys.path.
_HELD_VALIDATOR_BOOTSTRAP = r'''
import base64
import importlib.abc
import importlib.util
import json
import os
import stat
import sys
from types import ModuleType

fd = int(sys.argv[1])
with os.fdopen(fd, "rb", closefd=True) as stream:
    envelope = json.load(stream)
if envelope.get("schema") != "codexqb.planner-validator-bundle/v1":
    raise SystemExit("validator_bundle_schema_invalid")
entry_name = envelope.get("entry")
encoded_modules = envelope.get("modules")
if entry_name != "validate_planner_docs.py" or not isinstance(encoded_modules, dict):
    raise SystemExit("validator_bundle_shape_invalid")
try:
    payloads = {
        name: base64.b64decode(value, validate=True)
        for name, value in encoded_modules.items()
    }
except Exception:
    raise SystemExit("validator_bundle_encoding_invalid") from None
expected = {
    "artifact_io.py",
    "git_evidence.py",
    "mount_identity.py",
    "repository_evidence.py",
    "repository_io.py",
    "safety_contracts.py",
    "validate_planner_docs.py",
}
if set(payloads) != expected:
    raise SystemExit("validator_bundle_inventory_invalid")

try:
    dev_null_state = os.lstat("/dev/null")
except OSError:
    raise SystemExit("validator_held_origin_unavailable") from None
if not stat.S_ISCHR(dev_null_state.st_mode):
    raise SystemExit("validator_held_origin_invalid")
held_origin_root = "/dev/null/__codexqb_held__"

context_name = "_codexqb_held_runtime_context_v1"
if context_name in sys.modules:
    raise SystemExit("validator_held_context_preseeded")
context = ModuleType(context_name)
context.__file__ = "<controller-held-validator-bundle>"
context.__package__ = ""
context.schema_version = 1
context.assurance = "controller_observed_loader_path_unattested"
context.host_attested = False
context.verified = False
context.finalization_authority = False
context.runtime_sources = tuple(
    (name, payloads[name]) for name in sorted(payloads)
)
context.goal_resources = ()
sys.modules[context_name] = context

class HeldFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, sources):
        self.sources = sources

    def find_spec(self, fullname, path=None, target=None):
        filename = fullname + ".py"
        if filename == entry_name or filename not in self.sources:
            return None
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=held_origin_root + "/" + filename,
        )

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        filename = module.__name__ + ".py"
        source = self.sources[filename]
        origin = held_origin_root + "/" + filename
        module.__file__ = origin
        exec(compile(source, origin, "exec", dont_inherit=True), module.__dict__)

finder = HeldFinder(payloads)
sys.meta_path.insert(0, finder)
sys.argv = [entry_name, *sys.argv[2:]]
main_origin = held_origin_root + "/" + entry_name
namespace = {
    "__name__": "__main__",
    "__file__": main_origin,
    "__package__": None,
    "__cached__": None,
}
exec(compile(payloads[entry_name], main_origin, "exec", dont_inherit=True), namespace)
'''.strip()


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


@dataclass(frozen=True)
class ValidationProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limit_exceeded: bool
    termination_reason: str


@dataclass(frozen=True)
class PlannerValidatorBundle:
    """Opaque, descriptor-captured validator bytes and public source hashes."""

    schema: str
    bundle_sha256: str
    source_sha256: tuple[tuple[str, str], ...]
    _envelope: bytes

    def __repr__(self) -> str:
        return (
            "PlannerValidatorBundle("
            f"schema={self.schema!r}, bundle_sha256={self.bundle_sha256!r}, "
            f"source_sha256={self.source_sha256!r})"
        )


def _validator_bundle_payload(payloads: dict[str, bytes]) -> bytes:
    if set(payloads) != set(_VALIDATOR_BUNDLE_NAMES):
        raise ValueError("planner_validator_bundle_inventory_invalid")
    encoded = json.dumps(
        {
            "schema": PLANNER_VALIDATOR_BUNDLE_SCHEMA,
            "entry": _VALIDATOR_ENTRY_NAME,
            "modules": {
                name: base64.b64encode(payloads[name]).decode("ascii")
                for name in sorted(payloads)
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    if len(encoded) > MAX_VALIDATOR_BUNDLE_BYTES * 2:
        raise ValueError("planner_validator_bundle_too_large")
    return encoded


def _validated_source_tuple(
    value: object,
    expected_names: frozenset[str],
) -> tuple[tuple[str, bytes], ...]:
    if (
        type(value) is not tuple
        or len(value) != len(expected_names)
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not bytes
            or not item[0]
            or not item[1]
            for item in value
        )
    ):
        raise ValueError("held_runtime_context_invalid")
    sources = value
    names = tuple(name for name, _payload in sources)
    if (
        names != tuple(sorted(expected_names))
        or len(set(names)) != len(names)
    ):
        raise ValueError("held_runtime_context_invalid")
    return sources


def _source_tuple_payload(
    sources: tuple[tuple[str, bytes], ...],
    name: str,
) -> bytes | None:
    for current_name, payload in sources:
        if current_name == name:
            return payload
    return None


def _held_runtime_context_maps() -> tuple[
    tuple[tuple[str, bytes], ...],
    tuple[tuple[str, bytes], ...],
]:
    """Return exact launcher-held maps after one shared context check."""

    context = sys.modules.get(_HELD_RUNTIME_CONTEXT_NAME)
    if context is None:
        raise ValueError("held_runtime_context_required")
    if not isinstance(context, ModuleType):
        raise ValueError("held_runtime_context_invalid")
    state = ModuleType.__getattribute__(context, "__dict__")
    context_name = state.get("__name__")
    schema_version = state.get("schema_version")
    assurance = state.get("assurance")
    if (
        type(context_name) is not str
        or type(schema_version) is not int
        or type(assurance) is not str
        or context_name != _HELD_RUNTIME_CONTEXT_NAME
        or schema_version != 1
        or assurance != _HELD_RUNTIME_CONTEXT_ASSURANCE
        or state.get("host_attested") is not False
        or state.get("verified") is not False
        or state.get("finalization_authority") is not False
        or "runtime_sha256" in state
        or "goal_sha256" in state
    ):
        raise ValueError("held_runtime_context_invalid")
    runtime_sources = _validated_source_tuple(
        state.get("runtime_sources"),
        _HELD_RUNTIME_SOURCE_NAMES,
    )
    goal_resources = _validated_source_tuple(
        state.get("goal_resources"),
        _HELD_GOAL_RESOURCE_NAMES,
    )
    return runtime_sources, goal_resources


def _held_runtime_sources() -> tuple[tuple[str, bytes], ...]:
    """Return launcher-held runtime bytes without reopening a skill path."""

    runtime_sources, _goal_resources = _held_runtime_context_maps()
    for name, expected_sha256 in _VALIDATOR_SOURCE_SHA256:
        payload = _source_tuple_payload(runtime_sources, name)
        if payload is None:
            raise ValueError("held_runtime_context_invalid")
        if len(payload) > MAX_VALIDATOR_SOURCE_BYTES:
            raise ValueError("planner_validator_bundle_source_too_large")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError("held_runtime_context_invalid")
    return runtime_sources


def read_goal_held_bytes(relative_path: str) -> bytes:
    """Return one fully reviewed Goal source/resource from held bytes only."""

    if type(relative_path) is not str or relative_path not in _GOAL_HELD_PATHS:
        raise ValueError("untrusted_skill_resource_path")
    runtime_sources, goal_resources = _held_runtime_context_maps()
    goal_source = _source_tuple_payload(runtime_sources, "goal_run.py")
    if (
        goal_source is None
        or len(goal_source) > _MAX_HELD_GOAL_SOURCE_BYTES
        or hashlib.sha256(goal_source).hexdigest() != GOAL_RUN_SOURCE_SHA256
    ):
        raise ValueError("held_runtime_context_invalid")

    selected = goal_source if relative_path == "scripts/goal_run.py" else None
    total = 0
    for resource_path, expected_sha256 in GOAL_RESOURCE_SOURCE_SHA256:
        payload = _source_tuple_payload(goal_resources, resource_path)
        if payload is None or len(payload) > _MAX_HELD_GOAL_SOURCE_BYTES:
            raise ValueError("held_runtime_context_invalid")
        total += len(payload)
        if total > _MAX_HELD_GOAL_RESOURCE_BUNDLE_BYTES:
            raise ValueError("held_runtime_context_invalid")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError("held_runtime_context_invalid")
        if resource_path == relative_path:
            selected = payload
    if type(selected) is not bytes or not selected:
        raise ValueError("held_runtime_context_invalid")
    return selected


def capture_planner_validator_bundle() -> PlannerValidatorBundle:
    """Capture the validator subset from launcher-held descriptor bytes."""

    payloads: dict[str, bytes] = {}
    try:
        runtime_sources = _held_runtime_sources()
        total = 0
        for name in _VALIDATOR_BUNDLE_NAMES:
            data = _source_tuple_payload(runtime_sources, name)
            if data is None:
                raise ValueError("planner_validator_bundle_source_missing")
            if len(data) > MAX_VALIDATOR_SOURCE_BYTES:
                raise ValueError("planner_validator_bundle_source_too_large")
            total += len(data)
            if total > MAX_VALIDATOR_BUNDLE_BYTES:
                raise ValueError("planner_validator_bundle_too_large")
            payloads[name] = data
    except (OSError, TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and (
            str(exc).startswith("planner_validator_bundle_")
            or str(exc).startswith("held_runtime_context_")
        ):
            raise
        raise ValueError("planner_validator_bundle_capture_failed") from None
    envelope = _validator_bundle_payload(payloads)
    source_sha256 = tuple(
        (name, hashlib.sha256(payloads[name]).hexdigest())
        for name in sorted(payloads)
    )
    return PlannerValidatorBundle(
        schema=PLANNER_VALIDATOR_BUNDLE_SCHEMA,
        bundle_sha256=hashlib.sha256(envelope).hexdigest(),
        source_sha256=source_sha256,
        _envelope=envelope,
    )


def _validated_planner_validator_envelope(
    bundle: PlannerValidatorBundle,
) -> bytes:
    if type(bundle) is not PlannerValidatorBundle:
        raise TypeError("planner_validator_bundle_required")
    schema = bundle.schema
    bundle_sha256 = bundle.bundle_sha256
    source_sha256 = bundle.source_sha256
    envelope_bytes = bundle._envelope
    if (
        type(schema) is not str
        or type(bundle_sha256) is not str
        or type(source_sha256) is not tuple
        or type(envelope_bytes) is not bytes
        or any(
            type(item) is not tuple
            or len(item) != 2
            or type(item[0]) is not str
            or type(item[1]) is not str
            for item in source_sha256
        )
        or schema != PLANNER_VALIDATOR_BUNDLE_SCHEMA
        or source_sha256 != _VALIDATOR_SOURCE_SHA256
        or len(envelope_bytes) > MAX_VALIDATOR_BUNDLE_BYTES * 2
        or hashlib.sha256(envelope_bytes).hexdigest() != bundle_sha256
    ):
        raise ValueError("planner_validator_bundle_tampered")
    try:
        envelope = json.loads(envelope_bytes.decode("ascii"))
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema") != PLANNER_VALIDATOR_BUNDLE_SCHEMA
            or envelope.get("entry") != _VALIDATOR_ENTRY_NAME
            or not isinstance(envelope.get("modules"), dict)
        ):
            raise ValueError
        encoded_modules = envelope["modules"]
        if set(encoded_modules) != set(_VALIDATOR_BUNDLE_NAMES):
            raise ValueError
        payloads = {
            name: base64.b64decode(encoded_modules[name], validate=True)
            for name in _VALIDATOR_BUNDLE_NAMES
        }
        if any(
            type(payloads[name]) is not bytes
            or not payloads[name]
            or len(payloads[name]) > MAX_VALIDATOR_SOURCE_BYTES
            for name in _VALIDATOR_BUNDLE_NAMES
        ):
            raise ValueError
        if sum(len(payloads[name]) for name in _VALIDATOR_BUNDLE_NAMES) > MAX_VALIDATOR_BUNDLE_BYTES:
            raise ValueError
        if _validator_bundle_payload(payloads) != envelope_bytes:
            raise ValueError
        expected_sources = tuple(
            (name, hashlib.sha256(payloads[name]).hexdigest())
            for name in sorted(payloads)
        )
        if expected_sources != _VALIDATOR_SOURCE_SHA256:
            raise ValueError
    except (KeyError, TypeError, UnicodeDecodeError, ValueError):
        raise ValueError("planner_validator_bundle_tampered") from None
    return envelope_bytes


def planner_validator_bundle_evidence(
    bundle: PlannerValidatorBundle,
) -> dict[str, object]:
    """Return path-free evidence suitable for a producer-bundle receipt."""

    _validated_planner_validator_envelope(bundle)
    return {
        "schema": bundle.schema,
        "bundle_sha256": bundle.bundle_sha256,
        "source_sha256": [
            {"name": name, "sha256": digest}
            for name, digest in bundle.source_sha256
        ],
    }


def _lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def _sanitised_environment(root: Path) -> dict[str, str]:
    """Return a deterministic child environment without parent credentials."""

    path_entries: list[str] = []
    for raw_entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry)
        if not entry.is_absolute():
            continue
        try:
            common = os.path.commonpath((str(root), str(entry)))
        except ValueError:
            common = ""
        if common == str(root):
            continue
        normalized = str(entry)
        if normalized not in path_entries:
            path_entries.append(normalized)
    if not path_entries:
        path_entries = [entry for entry in os.defpath.split(os.pathsep) if entry]
    return {
        "PATH": os.pathsep.join(path_entries),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }


def _run_planner_validator(
    *,
    root: Path,
    mode: str,
    strict: bool = True,
    timeout_seconds: int = 30,
    bundle: PlannerValidatorBundle | None = None,
) -> tuple[int, str]:
    """Run one descriptor-captured validator bundle in an isolated Python.

    This helper remains a compatibility path for planner preflight validation;
    repository validation commands use :func:`run_bounded_validation_process`.
    The complete execution controller is whole-module pinned by policy.
    """

    captured = capture_planner_validator_bundle() if bundle is None else bundle
    envelope = _validated_planner_validator_envelope(captured)
    validator_args = ["--root", root.as_posix(), "--mode", mode]
    if strict:
        validator_args.append("--strict")
    try:
        if os.name != "posix":
            raise OSError(errno.ENOTSUP, "descriptor execution unavailable")
        with tempfile.TemporaryFile(mode="w+b") as held_bundle:
            held_bundle.write(envelope)
            held_bundle.flush()
            held_bundle.seek(0)
            descriptor = held_bundle.fileno()
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    "-c",
                    _HELD_VALIDATOR_BOOTSTRAP,
                    str(descriptor),
                    *validator_args,
                ],
                text=True,
                capture_output=True,
                check=False,
                timeout=timeout_seconds,
                env=_sanitised_environment(root),
                pass_fds=(descriptor,),
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"validator_unavailable={type(exc).__name__}"
    return completed.returncode, f"{completed.stdout}\n{completed.stderr}".strip()


def run_goal_planner_validator(
    *,
    root: Path,
    mode: str,
    strict: bool = True,
    bundle: PlannerValidatorBundle | None = None,
) -> tuple[int, str]:
    """Typed Goal preflight validator launch."""

    return _run_planner_validator(
        root=root,
        mode=mode,
        strict=strict,
        bundle=bundle,
    )


def run_step4_readiness_validator(
    *,
    root: Path,
    bundle: PlannerValidatorBundle | None = None,
) -> tuple[int, str]:
    """Typed strict Step 4 readiness validator launch."""

    return _run_planner_validator(
        root=root,
        mode="step4",
        strict=True,
        bundle=bundle,
    )


def _linux_validation_seccomp_spec() -> tuple[int, list[_SockFilter]]:
    if not sys.platform.startswith("linux") or not hasattr(os, "uname"):
        raise ValueError("secure_validation_process_isolation_not_supported")
    machine = os.uname().machine.lower()
    specs: dict[str, tuple[int, int, int | None, int | None, bool]] = {
        "x86_64": (0xC000003E, 56, 57, 58, True),
        "amd64": (0xC000003E, 56, 57, 58, True),
        "aarch64": (0xC00000B7, 220, None, None, False),
        "arm64": (0xC00000B7, 220, None, None, False),
    }
    spec = specs.get(machine)
    if spec is None:
        raise ValueError("secure_validation_process_isolation_not_supported")
    audit_arch, clone_nr, fork_nr, vfork_nr, reject_x32 = spec

    load_word_absolute = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_constant = 0x06
    seccomp_kill_process = 0x80000000
    seccomp_errno = 0x00050000
    seccomp_allow = 0x7FFF0000
    clone3_nr = 435
    instructions: list[_SockFilter] = [
        _SockFilter(load_word_absolute, 0, 0, 4),
        _SockFilter(jump_equal, 1, 0, audit_arch),
        _SockFilter(return_constant, 0, 0, seccomp_kill_process),
        _SockFilter(load_word_absolute, 0, 0, 0),
    ]
    if reject_x32:
        instructions.extend(
            [
                _SockFilter(jump_bits_set, 0, 1, 0x40000000),
                _SockFilter(return_constant, 0, 0, seccomp_kill_process),
            ]
        )
    instructions.extend(
        [
            _SockFilter(jump_equal, 0, 1, clone3_nr),
            _SockFilter(return_constant, 0, 0, seccomp_errno | errno.ENOSYS),
        ]
    )
    direct_process_checks = [
        syscall_nr for syscall_nr in (fork_nr, vfork_nr) if syscall_nr is not None
    ]
    direct_start = len(instructions)
    clone_check_index = direct_start + len(direct_process_checks)
    deny_index = clone_check_index + 3
    allow_index = deny_index + 1
    for offset, syscall_nr in enumerate(direct_process_checks):
        index = direct_start + offset
        instructions.append(
            _SockFilter(jump_equal, deny_index - index - 1, 0, syscall_nr)
        )
    instructions.extend(
        [
            _SockFilter(jump_equal, 0, allow_index - clone_check_index - 1, clone_nr),
            _SockFilter(load_word_absolute, 0, 0, 16),
            _SockFilter(jump_bits_set, 1, 0, LINUX_CLONE_THREAD),
            _SockFilter(return_constant, 0, 0, seccomp_errno | errno.EPERM),
            _SockFilter(return_constant, 0, 0, seccomp_allow),
        ]
    )
    return audit_arch, instructions


def _install_linux_validation_process_filter(
    expected_audit_arch: int,
    instructions: list[_SockFilter],
) -> None:
    current_arch, expected_instructions = _linux_validation_seccomp_spec()
    if current_arch != expected_audit_arch or [
        (item.code, item.jt, item.jf, item.k) for item in expected_instructions
    ] != [(item.code, item.jt, item.jf, item.k) for item in instructions]:
        raise OSError(errno.ENOTSUP, "validation seccomp binding changed")
    filter_array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filter_array)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    if prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno() or errno.EPERM, "could not enable no_new_privs")
    if prctl(22, 2, ctypes.addressof(program), 0, 0) != 0:  # PR_SET_SECCOMP/filter
        raise OSError(
            ctypes.get_errno() or errno.EPERM,
            "could not install validation seccomp filter",
        )


def _containment_command(
    argv: list[str],
) -> tuple[list[str], tuple[int, list[_SockFilter]] | None]:
    if sys.platform == "darwin":
        try:
            metadata = os.lstat(MACOS_VALIDATION_SANDBOX)
        except OSError as exc:
            raise ValueError("secure_validation_process_isolation_not_supported") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError("secure_validation_process_isolation_not_supported")
        return [
            str(MACOS_VALIDATION_SANDBOX),
            "-p",
            MACOS_VALIDATION_SANDBOX_PROFILE,
            *argv,
        ], None
    if sys.platform.startswith("linux"):
        return list(argv), _linux_validation_seccomp_spec()
    raise ValueError("secure_validation_process_isolation_not_supported")


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def _child_setup(
    cwd_fd: int,
    linux_seccomp: tuple[int, list[_SockFilter]] | None,
) -> None:
    os.fchdir(cwd_fd)
    os.close(cwd_fd)
    if linux_seccomp is not None:
        _install_linux_validation_process_filter(*linux_seccomp)


def _promote_fd(cwd_fd: int) -> int:
    if cwd_fd >= 3:
        return cwd_fd
    try:
        import fcntl

        duplicate = fcntl.fcntl(cwd_fd, fcntl.F_DUPFD_CLOEXEC, 3)
    except (ImportError, AttributeError, OSError) as exc:
        raise ValueError("secure_validation_process_isolation_not_supported") from exc
    os.close(cwd_fd)
    return int(duplicate)


def _open_validation_cwd_fd(
    *,
    root: Path,
    cwd: Path,
    repository: RepositoryIO | None,
    normalized_cwd: str | None,
) -> int:
    if os.name != "posix" or not hasattr(os, "fchdir"):
        raise ValueError("secure_validation_process_isolation_not_supported")
    lexical_root = _lexical_absolute(root)
    lexical_cwd = _lexical_absolute(cwd)
    if normalized_cwd is None:
        try:
            relative = lexical_cwd.relative_to(lexical_root)
        except ValueError as exc:
            raise ValueError("validation_cwd_invalid") from exc
        normalized = "." if not relative.parts else _controller_normalize_path(relative.as_posix())
    else:
        normalized = "." if normalized_cwd == "." else _controller_normalize_path(normalized_cwd)
        expected = lexical_root if normalized == "." else _lexical_absolute(lexical_root / normalized)
        if lexical_cwd != expected:
            raise ValueError("validation_cwd_binding_mismatch")
    try:
        if repository is None:
            with open_repository_io(lexical_root) as opened:
                return _open_validation_cwd_fd(
                    root=lexical_root,
                    cwd=lexical_cwd,
                    repository=opened,
                    normalized_cwd=normalized,
                )
        with _controller_validation_cwd(repository, normalized) as cwd_descriptor:
            return _promote_fd(os.dup(cwd_descriptor))
    except ValueError as exc:
        if "repository_nested_mount_rejected=" in str(exc):
            raise ValueError("validation_cwd_nested_mount_rejected") from None
        if str(exc) in {
            "validation_root_identity_changed",
            "validation_cwd_identity_changed",
            "validation_cwd_nested_mount_rejected",
        }:
            raise
        raise ValueError("validation_cwd_identity_changed") from None


def run_bounded_validation_process(
    argv: list[str],
    *,
    cwd: Path,
    root: Path,
    timeout_seconds: int,
    repository: RepositoryIO | None = None,
    normalized_cwd: str | None = None,
) -> ValidationProcessResult:
    """Run one validation from an anchored cwd with bounded output/processes."""

    if os.name != "posix" or threading.active_count() != 1:
        raise ValueError("secure_validation_process_isolation_not_supported")
    contained_argv, linux_seccomp = _containment_command(argv)
    cwd_fd = _open_validation_cwd_fd(
        root=root,
        cwd=cwd,
        repository=repository,
        normalized_cwd=normalized_cwd,
    )
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    try:
        try:
            try:
                process = subprocess.Popen(
                    contained_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    env=_sanitised_environment(root),
                    start_new_session=True,
                    pass_fds=(cwd_fd,),
                    preexec_fn=lambda: _child_setup(cwd_fd, linux_seccomp),
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                raise ValueError("validation_command_launch_failed") from exc
        finally:
            parent_cwd_fd = cwd_fd
            cwd_fd = -1
            os.close(parent_cwd_fd)

        if process.stdout is None or process.stderr is None:
            raise ValueError("validation_command_pipe_setup_failed")
        stdout = bytearray()
        stderr = bytearray()
        total = 0
        timed_out = False
        output_limit_exceeded = False
        deadline = time.monotonic() + timeout_seconds
        selector = selectors.DefaultSelector()
        streams = {process.stdout.fileno(): stdout, process.stderr.fileno(): stderr}
        for pipe in (process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ)

        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                _terminate(process)
                break
            for key, _ in selector.select(min(0.1, remaining)):
                fd = key.fileobj.fileno()
                try:
                    chunk = os.read(
                        fd,
                        min(
                            VALIDATION_OUTPUT_CHUNK_BYTES,
                            MAX_VALIDATION_OUTPUT_BYTES - total + 1,
                        ),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                streams[fd].extend(chunk)
                total += len(chunk)
                if total > MAX_VALIDATION_OUTPUT_BYTES:
                    output_limit_exceeded = True
                    _terminate(process)
                    break
            if output_limit_exceeded:
                break

        if not timed_out and not output_limit_exceeded:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate(process)
            else:
                _terminate(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise ValueError("validation_process_termination_failed") from exc

        exit_code = int(process.returncode if process.returncode is not None else -1)
        if output_limit_exceeded:
            termination_reason = "output_limit"
        elif timed_out:
            termination_reason = "timeout"
            exit_code = -1
        elif exit_code < 0:
            termination_reason = "signal"
        else:
            termination_reason = "exited"
        return ValidationProcessResult(
            exit_code=exit_code,
            stdout=bytes(stdout[:MAX_VALIDATION_OUTPUT_BYTES]),
            stderr=bytes(stderr[:MAX_VALIDATION_OUTPUT_BYTES]),
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
            termination_reason=termination_reason,
        )
    except BaseException:
        if process is not None:
            _terminate(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        raise
    finally:
        if cwd_fd >= 0:
            os.close(cwd_fd)
        if selector is not None:
            selector.close()
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
