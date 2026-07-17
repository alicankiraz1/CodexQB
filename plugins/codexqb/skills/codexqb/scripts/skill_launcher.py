#!/usr/bin/env python3
"""Launch one fixed CodexQB controller from a loader-bound skill root.

The Codex skill loader must invoke this file as an absolute first-process
Python script and must pass the canonical absolute ``SKILL.md`` path through
``--active-skill-md``.  Controller selection is a closed enum; no root,
target, or script path is accepted from the environment, ``PATH``, the target
repository, or controller arguments.

This binding remains controller-observed and unattested.  In particular, a
self-consistent copy of this launcher and its sibling ``SKILL.md`` cannot be
distinguished from the host-selected copy without a host-issued invocation
token.  The launcher therefore never grants ``host_attested``, ``VERIFIED``,
or finalization authority.
"""

from __future__ import annotations

import sys

if __name__ == "__main__" and not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
):
    sys.stderr.write(
        "codexqb_skill_launcher=blocked "
        "reason=requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)

import hashlib
import importlib.abc
import importlib.util
import os
import stat
from collections.abc import Mapping
from types import MappingProxyType, ModuleType
from typing import Sequence


SKILL_LAUNCHER_SCHEMA_VERSION = 1
SKILL_LAUNCHER_ASSURANCE = "controller_observed_loader_path_unattested"
SKILL_LAUNCHER_HOST_ATTESTED = False

_LAUNCHER_BASENAME = "skill_launcher.py"
_CONTROLLERS = MappingProxyType(
    {
        "repository-io": "repository_io.py",
        "planner-validator": "validate_planner_docs.py",
        "goal": "goal_run.py",
        "apply": "apply_run.py",
        "doctor": "doctor.py",
    }
)
_BLOCKED_PREFIX = "codexqb_skill_launcher=blocked reason="
_SHELL_SAFE_ASCII_COMPONENT_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
_HELD_RUNTIME_CONTEXT_NAME = "_codexqb_held_runtime_context_v1"
_AUTHORITY_SOURCE_SHA256 = "be6f7b957c52d72f8ad7e1e7bacb09e35ec39f798f26ee8dfcf964a762fc5315"
_AUTHORITY_BASENAME = "skill_root_authority.py"
_MAX_AUTHORITY_BYTES = 512 * 1024
_IMPORT_ORIG_ARGV = tuple(getattr(sys, "orig_argv", ()))
_IMPORTED_AS_MAIN = __name__ == "__main__"
_REVIEWED_RUNTIME_SHA256 = MappingProxyType(
    {
        "apply_run.py": "38b8d573b1d5209643a550cd406f6e8fd8223448d7dc9d9b78146d04fc8092ca",
        "artifact_io.py": "608a783cf826037517a5481436c452a980629871943a84f9375763ef13b605a5",
        "controller_store.py": "d0ebe9519b30bde7a4fe9dc736981f98c7dce6cf39dff180b95e10d952e8658e",
        "doctor.py": "2e710f5923ad1172d570b38e340f1ccd2839eda8515e9934cc240555a4046b70",
        "evidence_contracts.py": "fcbaee961f78437108f5d6413b333908bf4b8386241c577e5fc3d14ca1c1d1a6",
        "execution_controller.py": "d1ce9c117e391953ce2b6d8d5c6d841bb6264c0949bb509a635a411c32768b91",
        "git_evidence.py": "b192a4c22bcf39646db579f49e25e5023d95a457db9160a7eb5bd67da888fe57",
        "goal_run.py": "8b90bbbcf9abc485b82ddfe1701b4271ddf2241b4b86948f57049423a23df982",
        "mount_identity.py": "920585f6dabffa77d459ee5be06469c73265f62ea493b06f32c8e636ebbfbbc1",
        "repository_evidence.py": "8775f67acba3dd8aada6ffca660177ff9bf27d10f62add4861eb99803502ce2b",
        "repository_io.py": "097cb306967c1be6ae922f674ba3af86085a31c0e2ff15ad8a4f549fe8d4e220",
        "safety_contracts.py": "df43016eae8b2fe0a766be21c02984674a1a9743bde3536167b769682b4fcd58",
        "validate_planner_docs.py": "ceb9b70d096f5da5d3355e65bba36e8a43551c8046239c50800ef2205a222c6b",
    }
)
_REVIEWED_GOAL_RESOURCE_SHA256 = (
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
_GOAL_RESOURCE_PATHS = frozenset(
    relative_path for relative_path, _digest in _REVIEWED_GOAL_RESOURCE_SHA256
)
_MAX_GOAL_RESOURCE_BYTES = 4 * 1024 * 1024
_MAX_GOAL_RESOURCE_BUNDLE_BYTES = 16 * 1024 * 1024


class _LauncherBlocked(Exception):
    """Internal content-free launch rejection."""


def _immutable_source_tuple(bundle: object) -> tuple[tuple[str, bytes], ...]:
    """Copy one source mapping into a deeply immutable, canonical sequence."""

    if isinstance(bundle, Mapping):
        raw_items = tuple(bundle.items())
    elif isinstance(bundle, tuple):
        raw_items = bundle
    else:
        raise _LauncherBlocked
    if any(
        not isinstance(item, tuple)
        or len(item) != 2
        or not isinstance(item[0], str)
        or not isinstance(item[1], bytes)
        or not item[0]
        or not item[1]
        for item in raw_items
    ):
        raise _LauncherBlocked
    result = tuple(sorted(raw_items, key=lambda item: item[0]))
    if len({name for name, _payload in result}) != len(result):
        raise _LauncherBlocked
    return result


def _source_tuple_payload(
    sources: tuple[tuple[str, bytes], ...],
    name: str,
) -> bytes | None:
    for current_name, payload in sources:
        if current_name == name:
            return payload
    return None


class _HeldRuntimeContext(ModuleType):
    """A sealed sys.modules carrier for descriptor-held controller bytes."""

    def __init__(
        self,
        runtime_bundle: tuple[tuple[str, bytes], ...],
        goal_resource_bundle: tuple[tuple[str, bytes], ...],
    ) -> None:
        super().__init__(_HELD_RUNTIME_CONTEXT_NAME)
        runtime_sources = _immutable_source_tuple(runtime_bundle)
        goal_resources = _immutable_source_tuple(goal_resource_bundle)
        ModuleType.__setattr__(self, "__file__", "<held-codexqb-runtime-context>")
        ModuleType.__setattr__(self, "__package__", "")
        ModuleType.__setattr__(self, "schema_version", 1)
        ModuleType.__setattr__(self, "assurance", SKILL_LAUNCHER_ASSURANCE)
        ModuleType.__setattr__(self, "host_attested", False)
        ModuleType.__setattr__(self, "verified", False)
        ModuleType.__setattr__(self, "finalization_authority", False)
        ModuleType.__setattr__(self, "runtime_sources", runtime_sources)
        ModuleType.__setattr__(self, "goal_resources", goal_resources)
        ModuleType.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        if getattr(self, "_sealed", False):
            raise AttributeError("codexqb_held_runtime_context_immutable")
        raise AttributeError("codexqb_held_runtime_context_immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("codexqb_held_runtime_context_immutable")


def _required_first_process_flags() -> bool:
    return bool(
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.flags.optimize == 0
    )


def _required_first_process_argv() -> bool:
    return bool(
        _IMPORTED_AS_MAIN
        and len(_IMPORT_ORIG_ARGV) >= 5
        and tuple(getattr(sys, "orig_argv", ())) == _IMPORT_ORIG_ARGV
        and isinstance(_IMPORT_ORIG_ARGV[0], str)
        and _IMPORT_ORIG_ARGV[0]
        and _IMPORT_ORIG_ARGV[1:4] == ("-I", "-S", "-B")
        and _IMPORT_ORIG_ARGV[4] == os.fsdecode(__file__)
        and tuple(sys.argv) == (os.fsdecode(__file__), *_IMPORT_ORIG_ARGV[5:])
    )


if __name__ == "__main__" and not (
    _required_first_process_flags() and _required_first_process_argv()
):
    sys.stderr.write(
        _BLOCKED_PREFIX + "requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)


_LEXICAL_LAUNCHER = os.fsdecode(__file__)
_INITIAL_IMPORT_PATH = tuple(sys.path)
_LEXICAL_SCRIPTS_DIRECTORY = os.path.dirname(_LEXICAL_LAUNCHER)


def _shell_safe_absolute_path(
    value: object,
    *,
    expected_basename: str,
) -> bool:
    if not isinstance(value, str) or not value.startswith("/"):
        return False
    components = value.split("/")[1:]
    return bool(
        components
        and components[-1] == expected_basename
        and all(
            component not in {"", ".", ".."}
            and component.isascii()
            and all(
                character in _SHELL_SAFE_ASCII_COMPONENT_CHARACTERS
                for character in component
            )
            for component in components
        )
    )


def _lexical_launcher_path_is_valid(value: object, process_argv0: object) -> bool:
    if not _shell_safe_absolute_path(
        value,
        expected_basename=_LAUNCHER_BASENAME,
    ):
        return False
    # CPython may normalize __file__ independently from argv[0].  Requiring an
    # exact match makes a relative process invocation fail before local import.
    return isinstance(process_argv0, str) and process_argv0 == value


if not _shell_safe_absolute_path(
    _LEXICAL_LAUNCHER,
    expected_basename=_LAUNCHER_BASENAME,
):
    if __name__ == "__main__":
        sys.stderr.write(_BLOCKED_PREFIX + "launcher_path_rejected\n")
        raise SystemExit(2)
    raise _LauncherBlocked

if __name__ == "__main__" and not _lexical_launcher_path_is_valid(
    _LEXICAL_LAUNCHER,
    sys.argv[0] if sys.argv else None,
):
    sys.stderr.write(_BLOCKED_PREFIX + "launcher_path_rejected\n")
    raise SystemExit(2)


def _preimport_active_skill_path_is_valid(arguments: Sequence[str]) -> bool:
    return bool(
        len(arguments) >= 2
        and arguments[0] == "--active-skill-md"
        and _shell_safe_absolute_path(
            arguments[1],
            expected_basename="SKILL.md",
        )
    )


if __name__ == "__main__" and not _preimport_active_skill_path_is_valid(
    sys.argv[1:]
):
    sys.stderr.write(_BLOCKED_PREFIX + "active_skill_path_rejected\n")
    raise SystemExit(2)

def _bootstrap_directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise _LauncherBlocked
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _bootstrap_file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "pread"):
        raise _LauncherBlocked
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _bootstrap_identity(metadata: os.stat_result, *, directory: bool) -> tuple[int, ...]:
    common = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
    )
    if directory:
        return common
    return (*common, metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def _bootstrap_open_child(parent_fd: int, name: str, *, directory: bool) -> tuple[int, os.stat_result]:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            _bootstrap_directory_flags() if directory else _bootstrap_file_flags(),
            dir_fd=parent_fd,
        )
    except (OSError, TypeError, ValueError):
        raise _LauncherBlocked from None
    try:
        opened = os.fstat(descriptor)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        correct_kind = stat.S_ISDIR(opened.st_mode) if directory else stat.S_ISREG(opened.st_mode)
        if (
            not correct_kind
            or _bootstrap_identity(before, directory=directory)
            != _bootstrap_identity(opened, directory=directory)
            or _bootstrap_identity(opened, directory=directory)
            != _bootstrap_identity(after, directory=directory)
        ):
            raise _LauncherBlocked
        return descriptor, opened
    except BaseException:
        os.close(descriptor)
        raise


def _read_reviewed_authority_bytes() -> bytes:
    components = _LEXICAL_SCRIPTS_DIRECTORY.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise _LauncherBlocked
    opened_fds: list[int] = []
    try:
        root_fd = os.open("/", _bootstrap_directory_flags())
        opened_fds.append(root_fd)
        current_fd = root_fd
        for component in components:
            current_fd, _metadata = _bootstrap_open_child(
                current_fd,
                component,
                directory=True,
            )
            opened_fds.append(current_fd)
        authority_fd, metadata = _bootstrap_open_child(
            current_fd,
            _AUTHORITY_BASENAME,
            directory=False,
        )
        opened_fds.append(authority_fd)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
        if (
            metadata.st_uid != expected_uid
            or metadata.st_nlink != 1
            or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or metadata.st_size < 1
            or metadata.st_size > _MAX_AUTHORITY_BYTES
        ):
            raise _LauncherBlocked
        payload = bytearray()
        offset = 0
        while offset < metadata.st_size:
            chunk = os.pread(
                authority_fd,
                min(64 * 1024, metadata.st_size - offset),
                offset,
            )
            if not chunk:
                raise _LauncherBlocked
            payload.extend(chunk)
            offset += len(chunk)
        if os.pread(authority_fd, 1, metadata.st_size):
            raise _LauncherBlocked
        current = os.fstat(authority_fd)
        final = os.stat(
            _AUTHORITY_BASENAME,
            dir_fd=current_fd,
            follow_symlinks=False,
        )
        if (
            _bootstrap_identity(current, directory=False)
            != _bootstrap_identity(metadata, directory=False)
            or _bootstrap_identity(final, directory=False)
            != _bootstrap_identity(metadata, directory=False)
        ):
            raise _LauncherBlocked
        result = bytes(payload)
        if hashlib.sha256(result).hexdigest() != _AUTHORITY_SOURCE_SHA256:
            raise _LauncherBlocked
        return result
    except (OSError, TypeError, ValueError):
        raise _LauncherBlocked from None
    finally:
        for descriptor in reversed(opened_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _load_reviewed_authority() -> ModuleType:
    payload = _read_reviewed_authority_bytes()
    try:
        code = compile(
            payload,
            "<held-codexqb-skill-root-authority>",
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
    except (OverflowError, SyntaxError, ValueError):
        raise _LauncherBlocked from None
    module_name = "_codexqb_held_skill_root_authority_v1"
    module = ModuleType(module_name)
    module.__file__ = "<held-codexqb-skill-root-authority>"
    module.__package__ = ""
    missing = object()
    previous = sys.modules.get(module_name, missing)
    sys.modules[module_name] = module
    try:
        exec(code, module.__dict__)
    except BaseException:
        raise _LauncherBlocked from None
    finally:
        if previous is missing:
            sys.modules.pop(module_name, None)
        else:
            sys.modules[module_name] = previous
    if not callable(getattr(module, "open_skill_root_authority", None)):
        raise _LauncherBlocked
    return module


try:
    _skill_root_authority = _load_reviewed_authority()
except _LauncherBlocked:
    if __name__ == "__main__":
        sys.stderr.write(_BLOCKED_PREFIX + "authority_import_rejected\n")
        raise SystemExit(2) from None
    raise


def launcher_receipt() -> dict[str, object]:
    """Return the non-authoritative launcher assurance contract."""

    return {
        "schema_version": SKILL_LAUNCHER_SCHEMA_VERSION,
        "assurance": SKILL_LAUNCHER_ASSURANCE,
        "host_attested": SKILL_LAUNCHER_HOST_ATTESTED,
        "verified": False,
        "finalization_authority": False,
    }


class _HeldImportPath(list[str]):
    """Immutable standard-library path with no local-script fallback."""

    def __init__(self, values: Sequence[str], blocked: frozenset[str]) -> None:
        super().__init__(value for value in values if value and value not in blocked)
        self._blocked = blocked

    def __contains__(self, value: object) -> bool:
        if isinstance(value, str):
            # Reviewed modules use this membership check before attempting to
            # insert Path(__file__).parent.  Every string is logically present
            # so even a path whose lexical directory was atomically replaced
            # cannot be added for PathFinder fallback.
            return True
        return super().__contains__(value)

    def insert(self, index: int, value: str) -> None:
        del index, value

    def append(self, value: str) -> None:
        del value

    def extend(self, values: Sequence[str]) -> None:
        del values

    def __setitem__(self, index: object, value: object) -> None:
        del index, value
        raise RuntimeError("codexqb_held_import_path_immutable")

    def __delitem__(self, index: object) -> None:
        del index
        raise RuntimeError("codexqb_held_import_path_immutable")

    def clear(self) -> None:
        raise RuntimeError("codexqb_held_import_path_immutable")

    def pop(self, index: int = -1) -> str:
        del index
        raise RuntimeError("codexqb_held_import_path_immutable")

    def remove(self, value: str) -> None:
        del value
        raise RuntimeError("codexqb_held_import_path_immutable")

    def reverse(self) -> None:
        raise RuntimeError("codexqb_held_import_path_immutable")

    def sort(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("codexqb_held_import_path_immutable")

    def __iadd__(self, values: object) -> "_HeldImportPath":
        del values
        raise RuntimeError("codexqb_held_import_path_immutable")

    def __imul__(self, count: object) -> "_HeldImportPath":
        del count
        raise RuntimeError("codexqb_held_import_path_immutable")


class _HeldRuntimeFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Load the closed local module set solely from descriptor-held bytes."""

    def __init__(
        self,
        sources: tuple[tuple[str, bytes], ...],
        scripts_directory: str,
    ) -> None:
        held_sources = _immutable_source_tuple(sources)
        source_sha256 = tuple(
            (name, hashlib.sha256(payload).hexdigest())
            for name, payload in held_sources
        )
        object.__setattr__(self, "_sources", held_sources)
        object.__setattr__(self, "_expected_sources", held_sources)
        object.__setattr__(self, "_source_sha256", source_sha256)
        object.__setattr__(self, "_scripts_directory", scripts_directory)
        object.__setattr__(self, "_sealed", True)

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("codexqb_held_runtime_finder_immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("codexqb_held_runtime_finder_immutable")

    def _validated_payload(self, basename: str) -> bytes | None:
        try:
            sources = object.__getattribute__(self, "_sources")
            expected_sources = object.__getattribute__(self, "_expected_sources")
            source_sha256 = object.__getattribute__(self, "_source_sha256")
            if (
                sources is not expected_sources
                or type(sources) is not tuple
                or type(source_sha256) is not tuple
            ):
                raise ImportError
            expected_payload = _source_tuple_payload(expected_sources, basename)
            if expected_payload is None:
                return None
            payload = _source_tuple_payload(sources, basename)
            expected_digest = next(
                (
                    digest
                    for current_name, digest in source_sha256
                    if current_name == basename
                ),
                None,
            )
            if (
                type(payload) is not bytes
                or type(expected_digest) is not str
                or payload != expected_payload
                or hashlib.sha256(payload).hexdigest() != expected_digest
            ):
                raise ImportError
            return payload
        except (TypeError, ValueError):
            raise ImportError("codexqb_held_runtime_module_rejected") from None

    def find_spec(
        self,
        fullname: str,
        path: object = None,
        target: object = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if "." in fullname:
            return None
        try:
            payload = self._validated_payload(f"{fullname}.py")
        except ImportError:
            raise ImportError("codexqb_held_runtime_module_rejected") from None
        if payload is None:
            return None
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=os.path.join(self._scripts_directory, f"{fullname}.py"),
        )

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> None:
        del spec
        return None

    def exec_module(self, module: ModuleType) -> None:
        basename = f"{module.__name__}.py"
        payload = self._validated_payload(basename)
        if payload is None:
            raise ImportError("codexqb_held_runtime_module_rejected")
        origin = os.path.join(self._scripts_directory, basename)
        module.__file__ = origin
        module.__package__ = ""
        try:
            code = compile(
                payload,
                origin,
                "exec",
                flags=0,
                dont_inherit=True,
                optimize=0,
            )
            exec(code, module.__dict__)
        except BaseException as exc:
            del exc
            raise ImportError("codexqb_held_runtime_module_failed") from None


def _reviewed_runtime_bundle(bundle: object) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(bundle, Mapping) or frozenset(bundle) != frozenset(
        _REVIEWED_RUNTIME_SHA256
    ):
        raise _LauncherBlocked
    reviewed: dict[str, bytes] = {}
    for basename, expected_sha256 in _REVIEWED_RUNTIME_SHA256.items():
        payload = bundle.get(basename)
        if (
            not isinstance(payload, bytes)
            or not payload
            or hashlib.sha256(payload).hexdigest() != expected_sha256
        ):
            raise _LauncherBlocked
        reviewed[basename] = payload
    return _immutable_source_tuple(reviewed)


def _reviewed_goal_resource_bundle(bundle: object) -> tuple[tuple[str, bytes], ...]:
    if not isinstance(bundle, Mapping) or frozenset(bundle) != _GOAL_RESOURCE_PATHS:
        raise _LauncherBlocked
    reviewed: dict[str, bytes] = {}
    total = 0
    expected_sha256 = dict(_REVIEWED_GOAL_RESOURCE_SHA256)
    for relative_path in sorted(_GOAL_RESOURCE_PATHS):
        payload = bundle.get(relative_path)
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > _MAX_GOAL_RESOURCE_BYTES
            or hashlib.sha256(payload).hexdigest() != expected_sha256[relative_path]
        ):
            raise _LauncherBlocked
        total += len(payload)
        if total > _MAX_GOAL_RESOURCE_BUNDLE_BYTES:
            raise _LauncherBlocked
        reviewed[relative_path] = payload
    return _immutable_source_tuple(reviewed)


def _held_runtime_context(
    runtime_bundle: tuple[tuple[str, bytes], ...],
    goal_resource_bundle: tuple[tuple[str, bytes], ...],
) -> ModuleType:
    """Create one immutable, explicitly unattested in-process provider."""

    if _HELD_RUNTIME_CONTEXT_NAME in sys.modules:
        raise _LauncherBlocked
    if (
        not isinstance(runtime_bundle, tuple)
        or not isinstance(goal_resource_bundle, tuple)
        or any(
            not isinstance(name, str)
            or not isinstance(payload, bytes)
            or not payload
            for name, payload in (*runtime_bundle, *goal_resource_bundle)
        )
    ):
        raise _LauncherBlocked
    return _HeldRuntimeContext(runtime_bundle, goal_resource_bundle)


def _held_runtime_context_is_unchanged(
    context: ModuleType,
    *,
    runtime_sources: object,
    goal_resources: object,
) -> bool:
    try:
        state = ModuleType.__getattribute__(context, "__dict__")
    except (AttributeError, TypeError):
        return False
    context_name = state.get("__name__")
    schema_version = state.get("schema_version")
    assurance = state.get("assurance")
    if (
        sys.modules.get(_HELD_RUNTIME_CONTEXT_NAME) is not context
        or type(context_name) is not str
        or type(schema_version) is not int
        or type(assurance) is not str
        or context_name != _HELD_RUNTIME_CONTEXT_NAME
        or schema_version != 1
        or assurance != SKILL_LAUNCHER_ASSURANCE
        or state.get("runtime_sources") is not runtime_sources
        or state.get("goal_resources") is not goal_resources
        or "runtime_sha256" in state
        or "goal_sha256" in state
        or state.get("host_attested") is not False
        or state.get("verified") is not False
        or state.get("finalization_authority") is not False
    ):
        return False
    try:
        return bool(
            isinstance(runtime_sources, tuple)
            and isinstance(goal_resources, tuple)
            and _immutable_source_tuple(runtime_sources) == runtime_sources
            and _immutable_source_tuple(goal_resources) == goal_resources
        )
    except (KeyError, TypeError, ValueError):
        return False


def _held_runtime_finder_is_unchanged(
    finder: _HeldRuntimeFinder,
    *,
    sources: object,
    expected_sources: object,
    source_sha256: object,
    scripts_directory: object,
) -> bool:
    try:
        return bool(
            object.__getattribute__(finder, "_sources") is sources
            and object.__getattribute__(finder, "_expected_sources")
            is expected_sources
            and object.__getattribute__(finder, "_source_sha256")
            is source_sha256
            and object.__getattribute__(finder, "_scripts_directory")
            is scripts_directory
            and object.__getattribute__(finder, "_sealed") is True
            and sources is expected_sources
            and type(sources) is tuple
            and type(source_sha256) is tuple
            and _immutable_source_tuple(sources) == sources
            and source_sha256
            == tuple(
                (name, hashlib.sha256(payload).hexdigest())
                for name, payload in sources
            )
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _block(reason: str) -> int:
    sys.stderr.write(_BLOCKED_PREFIX + reason + "\n")
    return 2


def _launcher_is_exact_absolute_process_path() -> bool:
    return _lexical_launcher_path_is_valid(
        _LEXICAL_LAUNCHER,
        sys.argv[0] if sys.argv else None,
    )


def _parse_invocation(arguments: Sequence[str]) -> tuple[str, str, list[str]]:
    if (
        len(arguments) < 5
        or arguments[0] != "--active-skill-md"
        or arguments[2] != "--controller"
        or arguments[4] != "--"
        or not all(isinstance(value, str) for value in arguments)
    ):
        raise _LauncherBlocked
    active_skill_md = arguments[1]
    controller = arguments[3]
    target_basename = _CONTROLLERS.get(controller)
    if (
        target_basename is None
        or not _shell_safe_absolute_path(
            active_skill_md,
            expected_basename="SKILL.md",
        )
    ):
        raise _LauncherBlocked
    return active_skill_md, target_basename, list(arguments[5:])


def _controller_exit_code(value: object) -> int:
    if value is None:
        return 0
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255:
        return value
    raise _LauncherBlocked


def _execute_held_controller(
    *,
    source: bytes,
    runtime_bundle: Mapping[str, bytes] | tuple[tuple[str, bytes], ...],
    goal_resource_bundle: Mapping[str, bytes] | tuple[tuple[str, bytes], ...],
    controller_path: str,
    scripts_directory: str,
    controller_argv: list[str],
) -> int:
    if not isinstance(source, bytes) or not source:
        raise _LauncherBlocked
    try:
        code = compile(
            source,
            controller_path,
            "exec",
            flags=0,
            dont_inherit=True,
            optimize=0,
        )
    except (OverflowError, SyntaxError, ValueError):
        raise _LauncherBlocked from None

    runtime_sources = _immutable_source_tuple(runtime_bundle)
    goal_resources = _immutable_source_tuple(goal_resource_bundle)
    local_module_names = frozenset(
        basename.removesuffix(".py") for basename, _payload in runtime_sources
    )
    if (
        any(name in sys.modules for name in local_module_names)
        or _HELD_RUNTIME_CONTEXT_NAME in sys.modules
    ):
        raise _LauncherBlocked
    held_context = _held_runtime_context(runtime_sources, goal_resources)
    held_runtime_sources = held_context.runtime_sources
    held_goal_resources = held_context.goal_resources
    finder = _HeldRuntimeFinder(held_runtime_sources, scripts_directory)
    finder_sources = object.__getattribute__(finder, "_sources")
    finder_expected_sources = object.__getattribute__(finder, "_expected_sources")
    finder_source_sha256 = object.__getattribute__(finder, "_source_sha256")
    finder_scripts_directory = object.__getattribute__(finder, "_scripts_directory")
    previous_argv = sys.argv
    previous_path = sys.path
    previous_meta_path = sys.meta_path
    sys.argv = [controller_path, *controller_argv]
    blocked_import_paths = frozenset((scripts_directory, "/__codexqb_held__"))
    sys.path = _HeldImportPath(
        tuple(
            entry
            for entry in _INITIAL_IMPORT_PATH
            if isinstance(entry, str) and entry
        ),
        blocked_import_paths,
    )
    sys.meta_path = [finder, *previous_meta_path]
    sys.modules[_HELD_RUNTIME_CONTEXT_NAME] = held_context
    namespace = {
        "__name__": "__main__",
        "__file__": controller_path,
        "__package__": None,
        "__cached__": None,
        "__spec__": None,
        "__loader__": None,
        "__builtins__": __builtins__,
    }
    exit_code = 0
    provider_unchanged = False
    finder_unchanged = False
    try:
        exec(code, namespace, namespace)
    except SystemExit as exc:
        exit_code = _controller_exit_code(exc.code)
    except BaseException:
        raise _LauncherBlocked from None
    finally:
        provider_unchanged = _held_runtime_context_is_unchanged(
            held_context,
            runtime_sources=held_runtime_sources,
            goal_resources=held_goal_resources,
        )
        finder_unchanged = _held_runtime_finder_is_unchanged(
            finder,
            sources=finder_sources,
            expected_sources=finder_expected_sources,
            source_sha256=finder_source_sha256,
            scripts_directory=finder_scripts_directory,
        )
        sys.modules.pop(_HELD_RUNTIME_CONTEXT_NAME, None)
        for name in local_module_names:
            module = sys.modules.get(name)
            if module is not None and getattr(module, "__loader__", None) is finder:
                sys.modules.pop(name, None)
        sys.argv = previous_argv
        sys.path = previous_path
        sys.meta_path = previous_meta_path
    if not provider_unchanged or not finder_unchanged:
        raise _LauncherBlocked
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    if not _required_first_process_flags():
        return _block("requires_python_-I_-S_-B_first_process")
    if not _launcher_is_exact_absolute_process_path():
        return _block("launcher_path_rejected")

    try:
        active_skill_md, target_basename, controller_argv = _parse_invocation(
            list(sys.argv[1:] if argv is None else argv)
        )
    except _LauncherBlocked:
        return _block("invocation_rejected")

    try:
        with _skill_root_authority.open_skill_root_authority(
            loader_skill_md_path=active_skill_md,
            executing_script_path=_LEXICAL_LAUNCHER,
            expected_script_basename=_LAUNCHER_BASENAME,
        ) as binding:
            if binding.receipt() != {
                "schema_version": 1,
                "assurance": SKILL_LAUNCHER_ASSURANCE,
                "host_attested": False,
                "binding": "held_descriptor_skill_layout",
            }:
                raise _LauncherBlocked
            runtime_bundle = _reviewed_runtime_bundle(
                binding.read_runtime_bundle()
            )
            goal_resource_bundle = _reviewed_goal_resource_bundle(
                binding.read_skill_resource_bundle()
            )
            source = binding.read_script_bytes(target_basename)
            if source != _source_tuple_payload(runtime_bundle, target_basename):
                raise _LauncherBlocked
            controller_path = os.path.join(
                os.fspath(binding.scripts_directory),
                target_basename,
            )
            scripts_directory = os.fspath(binding.scripts_directory)
            binding.revalidate()
            return _execute_held_controller(
                source=source,
                runtime_bundle=runtime_bundle,
                goal_resource_bundle=goal_resource_bundle,
                controller_path=controller_path,
                scripts_directory=scripts_directory,
                controller_argv=controller_argv,
            )
    except _LauncherBlocked:
        return _block("controller_rejected")
    except BaseException:
        return _block("authority_rejected")


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "SKILL_LAUNCHER_ASSURANCE",
    "SKILL_LAUNCHER_HOST_ATTESTED",
    "SKILL_LAUNCHER_SCHEMA_VERSION",
    "launcher_receipt",
    "main",
]
