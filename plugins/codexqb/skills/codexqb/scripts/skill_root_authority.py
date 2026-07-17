#!/usr/bin/env python3
"""Descriptor-bound authority for a loader-supplied CodexQB skill path.

The Codex skill loader supplies the absolute ``SKILL.md`` path through an
explicit CLI argument.  This module never discovers that path from an
environment variable, ``PATH``, the current repository, or sibling plugins.
It proves that the supplied path and the caller's lexical script path name one
owner-controlled, no-follow layout while keeping the relevant descriptors
open for the caller.

This is controller-observed evidence, not host attestation.  In particular,
an identically laid-out sibling launcher that supplies a self-consistent
``SKILL.md`` path and script path cannot be distinguished from the active host
selection without a host-issued invocation token.  The receipt therefore uses
``controller_observed_loader_path_unattested`` and never grants VERIFIED or
finalization authority.
"""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
from types import MappingProxyType, ModuleType
from typing import Iterator, Mapping


SKILL_ROOT_AUTHORITY_SCHEMA_VERSION = 1
SKILL_ROOT_AUTHORITY_ASSURANCE = "controller_observed_loader_path_unattested"
MOUNT_IDENTITY_SOURCE_SHA256 = "920585f6dabffa77d459ee5be06469c73265f62ea493b06f32c8e636ebbfbbc1"
AUTHORIZED_LAUNCH_TARGET_BASENAMES = frozenset(
    {
        "apply_run.py",
        "doctor.py",
        "goal_run.py",
        "repository_io.py",
        "validate_planner_docs.py",
    }
)
RUNTIME_BUNDLE_BASENAMES = frozenset(
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
REVIEWED_SCRIPT_BASENAMES = frozenset(
    {
        *RUNTIME_BUNDLE_BASENAMES,
        "repository_io_policy.py",
        "repository_validation.py",
        "skill_launcher.py",
        "skill_root_authority.py",
    }
)
GOAL_REFERENCE_PATHS = frozenset(
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
_MAX_MOUNT_IDENTITY_BYTES = 256 * 1024
_MAX_LAUNCH_TARGET_BYTES = 4 * 1024 * 1024
_MAX_GOAL_REFERENCE_BYTES = 4 * 1024 * 1024
_MAX_GOAL_REFERENCE_BUNDLE_BYTES = 16 * 1024 * 1024
_MAX_REVIEWED_SCRIPT_ENTRIES = 64
_SHELL_SAFE_COMPONENT_RE = re.compile(r"[A-Za-z0-9._-]+", flags=re.ASCII)
_EXPECTED_BASENAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")


@dataclass(frozen=True)
class _HeldEntry:
    parent_fd: int
    name: str
    fd: int
    metadata: os.stat_result
    directory: bool


@dataclass(frozen=True)
class SkillRootAuthority:
    """One live, descriptor-held skill-layout binding.

    The descriptors are valid only inside the ``open_skill_root_authority``
    context.  Consumers that cross a mutation or admission boundary should
    call ``revalidate`` immediately before relying on the binding.
    """

    skill_root: Path
    scripts_directory: Path
    skill_markdown: Path
    executing_script: Path
    skill_root_fd: int
    scripts_fd: int
    skill_markdown_fd: int
    executing_script_fd: int
    mount_policy_fd: int
    _root_metadata: os.stat_result
    _entries: tuple[_HeldEntry, ...]
    _mount_module: ModuleType
    _mount_resolution: object

    def receipt(self) -> dict[str, object]:
        """Return content-free evidence for the controller-observed binding."""

        return {
            "schema_version": SKILL_ROOT_AUTHORITY_SCHEMA_VERSION,
            "assurance": SKILL_ROOT_AUTHORITY_ASSURANCE,
            "host_attested": False,
            "binding": "held_descriptor_skill_layout",
        }

    def revalidate(self) -> None:
        """Fail closed if any held identity, policy, ACL, or mount changed."""

        _revalidate_binding(self)

    def read_script_bytes(self, literal_basename: str) -> bytes:
        """Read one fixed launcher target through the held scripts descriptor."""

        return _read_authorized_script_bytes(self, literal_basename)

    def read_runtime_bundle(self) -> Mapping[str, bytes]:
        """Capture the complete reviewed local import bundle immutably."""

        return _read_runtime_bundle(self)

    def read_skill_resource_bundle(self) -> Mapping[str, bytes]:
        """Capture the exact Goal stage-reference set immutably."""

        return _read_skill_resource_bundle(self)


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("skill_root_authority_secure_open_unavailable")
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _file_flags() -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("skill_root_authority_secure_open_unavailable")
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )


def _lexical_absolute_components(value: object, label: str) -> tuple[Path, tuple[str, ...]]:
    if not isinstance(value, str):
        raise TypeError(f"skill_root_authority_{label}_must_be_cli_string")
    if not value or not value.startswith("/"):
        raise ValueError(f"skill_root_authority_{label}_must_be_absolute")
    # Repeated separators and dot components are rejected rather than silently
    # normalized.  This is a lexical contract; realpath is never authority.
    components = value.split("/")[1:]
    if not components or any(component in {"", ".", ".."} for component in components):
        raise ValueError(f"skill_root_authority_{label}_not_lexical")
    if any(_SHELL_SAFE_COMPONENT_RE.fullmatch(component) is None for component in components):
        raise ValueError(f"skill_root_authority_{label}_component_invalid")
    return Path(value), tuple(components)


def _expected_basename(value: object) -> str:
    if not isinstance(value, str) or _EXPECTED_BASENAME_RE.fullmatch(value) is None:
        raise ValueError("skill_root_authority_expected_basename_invalid")
    if value in {".", "..", "SKILL.md"}:
        raise ValueError("skill_root_authority_expected_basename_invalid")
    return value


def _stable_metadata(metadata: os.stat_result, *, directory: bool) -> tuple[int, ...]:
    common = (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )
    if directory:
        return common
    return (
        *common,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _stat_child(parent_fd: int, name: str) -> os.stat_result:
    try:
        return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except (NotImplementedError, TypeError) as exc:
        raise ValueError("skill_root_authority_secure_open_unavailable") from exc
    except OSError as exc:
        raise ValueError("skill_root_authority_secure_open_failed") from exc


def _open_child(parent_fd: int, name: str, *, directory: bool) -> _HeldEntry:
    before = _stat_child(parent_fd, name)
    if stat.S_ISLNK(before.st_mode):
        raise ValueError("skill_root_authority_symlink_rejected")
    flags = _directory_flags() if directory else _file_flags()
    try:
        child_fd = os.open(name, flags, dir_fd=parent_fd)
    except (NotImplementedError, TypeError) as exc:
        raise ValueError("skill_root_authority_secure_open_unavailable") from exc
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError("skill_root_authority_symlink_rejected") from exc
        raise ValueError("skill_root_authority_secure_open_failed") from exc
    try:
        opened = os.fstat(child_fd)
        after = _stat_child(parent_fd, name)
        correct_kind = stat.S_ISDIR(opened.st_mode) if directory else stat.S_ISREG(opened.st_mode)
        if (
            not correct_kind
            or _stable_metadata(before, directory=directory)
            != _stable_metadata(opened, directory=directory)
            or _stable_metadata(opened, directory=directory)
            != _stable_metadata(after, directory=directory)
        ):
            raise ValueError("skill_root_authority_identity_changed")
        return _HeldEntry(parent_fd, name, child_fd, opened, directory)
    except Exception:
        os.close(child_fd)
        raise


def _expected_uid() -> int:
    if hasattr(os, "geteuid"):
        return os.geteuid()
    if hasattr(os, "getuid"):
        return os.getuid()
    raise ValueError("skill_root_authority_owner_identity_unavailable")


def _owner_controlled(metadata: os.stat_result, *, directory: bool) -> bool:
    if metadata.st_uid != _expected_uid() or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return False
    if directory:
        return stat.S_ISDIR(metadata.st_mode)
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1


def _descriptor_has_acl(descriptor: int) -> bool:
    """Reject Linux/POSIX ACL xattrs and Darwin extended ACL entries."""

    try:
        names = os.listxattr(descriptor)
    except AttributeError:
        if sys.platform != "darwin":
            raise ValueError("skill_root_authority_acl_probe_unavailable") from None
        names = []
    except OSError as exc:
        unsupported = {errno.ENOTSUP}
        if hasattr(errno, "EOPNOTSUPP"):
            unsupported.add(errno.EOPNOTSUPP)
        if exc.errno not in unsupported or sys.platform != "darwin":
            raise ValueError("skill_root_authority_acl_probe_failed") from exc
        names = []
    normalized: list[str] = []
    for name in names:
        if not isinstance(name, (str, bytes)):
            raise ValueError("skill_root_authority_acl_probe_failed")
        normalized.append(os.fsdecode(name).casefold())
    if any("acl" in name or name == "com.apple.system.security" for name in normalized):
        return True
    if sys.platform != "darwin":
        return False

    libc = ctypes.CDLL(None, use_errno=True)
    getter = getattr(libc, "acl_get_fd_np", None)
    releaser = getattr(libc, "acl_free", None)
    if getter is None or releaser is None:
        raise ValueError("skill_root_authority_acl_probe_unavailable")
    getter.argtypes = [ctypes.c_int, ctypes.c_int]
    getter.restype = ctypes.c_void_p
    releaser.argtypes = [ctypes.c_void_p]
    releaser.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = getter(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        number = ctypes.get_errno()
        if number == errno.ENOENT:
            return False
        raise ValueError("skill_root_authority_acl_probe_failed")
    releaser(acl)
    return True


def _darwin_descriptor_acl_is_deny_only(descriptor: int) -> bool:
    """Accept only the standard deny-only ACLs on macOS ancestor paths."""

    if sys.platform != "darwin":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    getter = getattr(libc, "acl_get_fd_np", None)
    renderer = getattr(libc, "acl_to_text", None)
    releaser = getattr(libc, "acl_free", None)
    if getter is None or renderer is None or releaser is None:
        return False
    getter.argtypes = [ctypes.c_int, ctypes.c_int]
    getter.restype = ctypes.c_void_p
    renderer.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ssize_t)]
    renderer.restype = ctypes.c_void_p
    releaser.argtypes = [ctypes.c_void_p]
    releaser.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = getter(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        return False
    rendered = None
    try:
        length = ctypes.c_ssize_t()
        rendered = renderer(acl, ctypes.byref(length))
        if not rendered or length.value < 1 or length.value > 64 * 1024:
            return False
        try:
            text = ctypes.string_at(rendered, length.value).decode(
                "utf-8",
                errors="strict",
            )
        except (UnicodeDecodeError, ValueError):
            return False
        lines = [line for line in text.splitlines() if line]
        if not lines or lines[0] != "!#acl 1" or len(lines) < 2:
            return False
        return all(
            len(entry.split(":")) >= 3 and entry.split(":")[-2] == "deny"
            for entry in lines[1:]
        )
    finally:
        if rendered:
            releaser(rendered)
        releaser(acl)


def _require_trusted_ancestor(descriptor: int, expected: os.stat_result) -> None:
    current = os.fstat(descriptor)
    allowed_owners = {0, _expected_uid()}
    if (
        _stable_metadata(current, directory=True)
        != _stable_metadata(expected, directory=True)
        or not stat.S_ISDIR(current.st_mode)
        or current.st_uid not in allowed_owners
        or current.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("skill_root_authority_ancestor_owner_control_rejected")
    has_acl = _descriptor_has_acl(descriptor)
    if has_acl and not _darwin_descriptor_acl_is_deny_only(descriptor):
        raise ValueError("skill_root_authority_ancestor_acl_rejected")


def _require_owner_and_acl(entry: _HeldEntry) -> None:
    current = os.fstat(entry.fd)
    if (
        _stable_metadata(current, directory=entry.directory)
        != _stable_metadata(entry.metadata, directory=entry.directory)
        or not _owner_controlled(current, directory=entry.directory)
    ):
        raise ValueError("skill_root_authority_owner_control_rejected")
    if _descriptor_has_acl(entry.fd):
        raise ValueError("skill_root_authority_acl_rejected")


def _read_held_regular_bytes(entry: _HeldEntry, *, max_bytes: int) -> bytes:
    if entry.directory or max_bytes < 1 or not hasattr(os, "pread"):
        raise ValueError("skill_root_authority_descriptor_read_unavailable")
    _revalidate_entry(entry)
    metadata = os.fstat(entry.fd)
    if metadata.st_size < 0 or metadata.st_size > max_bytes:
        raise ValueError("skill_root_authority_script_size_rejected")
    payload = bytearray()
    offset = 0
    while offset < metadata.st_size:
        chunk = os.pread(entry.fd, min(64 * 1024, metadata.st_size - offset), offset)
        if not chunk:
            raise ValueError("skill_root_authority_script_read_incomplete")
        payload.extend(chunk)
        offset += len(chunk)
    if os.pread(entry.fd, 1, metadata.st_size):
        raise ValueError("skill_root_authority_identity_changed")
    _revalidate_entry(entry)
    return bytes(payload)


def _load_held_mount_module(entry: _HeldEntry) -> ModuleType:
    payload = _read_held_regular_bytes(entry, max_bytes=_MAX_MOUNT_IDENTITY_BYTES)
    if hashlib.sha256(payload).hexdigest() != MOUNT_IDENTITY_SOURCE_SHA256:
        raise ValueError("skill_root_authority_mount_policy_digest_mismatch")
    try:
        source = payload.decode("utf-8", errors="strict")
        code = compile(source, "<held-codexqb-mount-identity>", "exec", dont_inherit=True)
    except (UnicodeDecodeError, SyntaxError, ValueError) as exc:
        raise ValueError("skill_root_authority_mount_policy_invalid") from exc
    private_name = f"_codexqb_held_mount_identity_{os.getpid()}_{entry.fd}"
    module = ModuleType(private_name)
    module.__file__ = "<held-codexqb-mount-identity>"
    module.__package__ = ""
    missing = object()
    previous = sys.modules.get(private_name, missing)
    sys.modules[private_name] = module
    try:
        exec(code, module.__dict__)
    except Exception as exc:
        raise ValueError("skill_root_authority_mount_policy_invalid") from exc
    finally:
        if previous is missing:
            sys.modules.pop(private_name, None)
        else:
            sys.modules[private_name] = previous
    required_callables = (
        "require_mount_assurance",
        "require_same_mount",
        "resolve_mount_identity",
    )
    if (
        getattr(module, "READ_ONLY_EVIDENCE", None) != "read_only_evidence"
        or any(not callable(getattr(module, name, None)) for name in required_callables)
    ):
        raise ValueError("skill_root_authority_mount_policy_invalid")
    return module


def _root_mount_resolution(mount_module: ModuleType, root_fd: int) -> object:
    try:
        resolution = mount_module.resolve_mount_identity(root_fd, reconcile=True)
        mount_module.require_mount_assurance(
            resolution,
            mount_module.READ_ONLY_EVIDENCE,
        )
    except Exception as exc:
        raise ValueError("skill_root_authority_mount_identity_unavailable") from exc
    return resolution


def _require_same_skill_mount(
    mount_module: ModuleType,
    root_resolution: object,
    entries: tuple[_HeldEntry, ...],
    labels: tuple[str, ...],
) -> None:
    for entry, label in zip(entries, labels, strict=True):
        try:
            mount_module.require_same_mount(root_resolution, entry.fd, label)
        except ValueError as exc:
            if str(exc).startswith("repository_nested_mount_rejected="):
                raise ValueError("skill_root_authority_mount_mismatch") from exc
            raise ValueError("skill_root_authority_mount_identity_unavailable") from exc


def _revalidate_entry(entry: _HeldEntry) -> None:
    try:
        descriptor_metadata = os.fstat(entry.fd)
        path_metadata = _stat_child(entry.parent_fd, entry.name)
    except OSError as exc:
        raise ValueError("skill_root_authority_identity_changed") from exc
    expected = _stable_metadata(entry.metadata, directory=entry.directory)
    if (
        _stable_metadata(descriptor_metadata, directory=entry.directory) != expected
        or _stable_metadata(path_metadata, directory=entry.directory) != expected
    ):
        raise ValueError("skill_root_authority_identity_changed")


def _revalidate_binding(binding: SkillRootAuthority) -> None:
    try:
        root_current = os.fstat(binding._entries[0].parent_fd)
    except OSError as exc:
        raise ValueError("skill_root_authority_binding_closed") from exc
    if _stable_metadata(root_current, directory=True) != _stable_metadata(
        binding._root_metadata,
        directory=True,
    ):
        raise ValueError("skill_root_authority_identity_changed")
    for entry in binding._entries:
        _revalidate_entry(entry)

    skill_root_index = next(
        index
        for index, entry in enumerate(binding._entries)
        if entry.fd == binding.skill_root_fd
    )
    _require_trusted_ancestor(
        binding._entries[0].parent_fd,
        binding._root_metadata,
    )
    for entry in binding._entries[:skill_root_index]:
        _require_trusted_ancestor(entry.fd, entry.metadata)

    critical = (
        next(entry for entry in binding._entries if entry.fd == binding.skill_root_fd),
        next(entry for entry in binding._entries if entry.fd == binding.scripts_fd),
        next(entry for entry in binding._entries if entry.fd == binding.skill_markdown_fd),
        next(entry for entry in binding._entries if entry.fd == binding.executing_script_fd),
        next(entry for entry in binding._entries if entry.fd == binding.mount_policy_fd),
    )
    for entry in critical:
        _require_owner_and_acl(entry)

    current_resolution = _root_mount_resolution(
        binding._mount_module,
        binding.skill_root_fd,
    )
    if getattr(current_resolution, "identity", None) != getattr(
        binding._mount_resolution,
        "identity",
        None,
    ):
        raise ValueError("skill_root_authority_mount_mismatch")
    _require_same_skill_mount(
        binding._mount_module,
        current_resolution,
        critical[1:],
        (
            "scripts",
            "SKILL.md",
            "scripts/executing_script",
            "scripts/mount_identity.py",
        ),
    )


def _read_authorized_script_bytes(
    binding: SkillRootAuthority,
    literal_basename: str,
) -> bytes:
    if (
        not isinstance(literal_basename, str)
        or literal_basename not in AUTHORIZED_LAUNCH_TARGET_BASENAMES
    ):
        raise ValueError("skill_root_authority_launch_target_rejected")
    binding.revalidate()
    target = _open_child(binding.scripts_fd, literal_basename, directory=False)
    try:
        _require_owner_and_acl(target)
        _require_same_skill_mount(
            binding._mount_module,
            binding._mount_resolution,
            (target,),
            ("scripts/launch_target",),
        )
        payload = _read_held_regular_bytes(
            target,
            max_bytes=_MAX_LAUNCH_TARGET_BYTES,
        )
        _revalidate_entry(target)
        binding.revalidate()
        return payload
    finally:
        os.close(target.fd)


def _require_reviewed_script_inventory(binding: SkillRootAuthority) -> None:
    scripts_entry = next(
        entry for entry in binding._entries if entry.fd == binding.scripts_fd
    )
    _revalidate_entry(scripts_entry)
    try:
        names = os.listdir(binding.scripts_fd)
    except (OSError, TypeError, NotImplementedError) as exc:
        raise ValueError("skill_root_authority_runtime_inventory_unavailable") from exc
    if (
        len(names) > _MAX_REVIEWED_SCRIPT_ENTRIES
        or any(not isinstance(name, str) for name in names)
    ):
        raise ValueError("skill_root_authority_runtime_inventory_invalid")
    python_names = frozenset(name for name in names if name.endswith(".py"))
    if python_names != REVIEWED_SCRIPT_BASENAMES:
        raise ValueError("skill_root_authority_runtime_inventory_invalid")
    _revalidate_entry(scripts_entry)


def _read_runtime_bundle(binding: SkillRootAuthority) -> Mapping[str, bytes]:
    binding.revalidate()
    _require_reviewed_script_inventory(binding)
    opened: list[_HeldEntry] = []
    try:
        for basename in sorted(RUNTIME_BUNDLE_BASENAMES):
            opened.append(
                _open_child(binding.scripts_fd, basename, directory=False)
            )
        for entry in opened:
            _require_owner_and_acl(entry)
        _require_same_skill_mount(
            binding._mount_module,
            binding._mount_resolution,
            tuple(opened),
            tuple(
                f"scripts/runtime_module_{position:02d}"
                for position in range(1, len(opened) + 1)
            ),
        )
        payloads: dict[str, bytes] = {}
        for entry in opened:
            payload = _read_held_regular_bytes(
                entry,
                max_bytes=_MAX_LAUNCH_TARGET_BYTES,
            )
            if (
                entry.name == "mount_identity.py"
                and hashlib.sha256(payload).hexdigest()
                != MOUNT_IDENTITY_SOURCE_SHA256
            ):
                raise ValueError("skill_root_authority_mount_policy_digest_mismatch")
            payloads[entry.name] = payload
        for entry in opened:
            _revalidate_entry(entry)
        binding.revalidate()
        _require_reviewed_script_inventory(binding)
        if frozenset(payloads) != RUNTIME_BUNDLE_BASENAMES:
            raise ValueError("skill_root_authority_runtime_bundle_invalid")
        return MappingProxyType(dict(sorted(payloads.items())))
    finally:
        for entry in reversed(opened):
            try:
                os.close(entry.fd)
            except OSError:
                pass


def _goal_reference_components(path: str) -> tuple[str, ...]:
    if not isinstance(path, str):
        raise ValueError("skill_root_authority_goal_reference_inventory_invalid")
    components = tuple(path.split("/"))
    if (
        len(components) < 2
        or components[0] != "references"
        or any(
            not component
            or component in {".", ".."}
            or "\\" in component
            or "\x00" in component
            for component in components
        )
    ):
        raise ValueError("skill_root_authority_goal_reference_inventory_invalid")
    return components


def _read_skill_resource_bundle(
    binding: SkillRootAuthority,
) -> Mapping[str, bytes]:
    binding.revalidate()
    if len(GOAL_REFERENCE_PATHS) != 11:
        raise ValueError("skill_root_authority_goal_reference_inventory_invalid")
    opened: list[_HeldEntry] = []
    files: dict[str, _HeldEntry] = {}
    directory_fds: dict[tuple[str, ...], int] = {(): binding.skill_root_fd}
    try:
        for relative_path in sorted(GOAL_REFERENCE_PATHS):
            components = _goal_reference_components(relative_path)
            prefix: tuple[str, ...] = ()
            parent_fd = binding.skill_root_fd
            for component in components[:-1]:
                prefix = (*prefix, component)
                existing = directory_fds.get(prefix)
                if existing is None:
                    directory_entry = _open_child(
                        parent_fd,
                        component,
                        directory=True,
                    )
                    opened.append(directory_entry)
                    directory_fds[prefix] = directory_entry.fd
                    parent_fd = directory_entry.fd
                else:
                    parent_fd = existing
            file_entry = _open_child(
                parent_fd,
                components[-1],
                directory=False,
            )
            opened.append(file_entry)
            files[relative_path] = file_entry

        if frozenset(files) != GOAL_REFERENCE_PATHS:
            raise ValueError("skill_root_authority_goal_reference_inventory_invalid")
        for entry in opened:
            _require_owner_and_acl(entry)
        _require_same_skill_mount(
            binding._mount_module,
            binding._mount_resolution,
            tuple(opened),
            tuple(
                f"goal/reference_entry_{position:02d}"
                for position in range(1, len(opened) + 1)
            ),
        )

        total_bytes = 0
        payloads: dict[str, bytes] = {}
        for relative_path in sorted(files):
            entry = files[relative_path]
            size = os.fstat(entry.fd).st_size
            if size < 0 or size > _MAX_GOAL_REFERENCE_BYTES:
                raise ValueError("skill_root_authority_goal_reference_size_rejected")
            total_bytes += size
            if total_bytes > _MAX_GOAL_REFERENCE_BUNDLE_BYTES:
                raise ValueError("skill_root_authority_goal_reference_bundle_too_large")
            payloads[relative_path] = _read_held_regular_bytes(
                entry,
                max_bytes=_MAX_GOAL_REFERENCE_BYTES,
            )
        for entry in opened:
            _revalidate_entry(entry)
        binding.revalidate()
        if frozenset(payloads) != GOAL_REFERENCE_PATHS:
            raise ValueError("skill_root_authority_goal_reference_bundle_invalid")
        return MappingProxyType(dict(sorted(payloads.items())))
    finally:
        for entry in reversed(opened):
            try:
                os.close(entry.fd)
            except OSError:
                pass


@contextmanager
def open_skill_root_authority(
    *,
    loader_skill_md_path: str,
    executing_script_path: str,
    expected_script_basename: str,
) -> Iterator[SkillRootAuthority]:
    """Bind one CLI-supplied loader path to one lexical executing script.

    ``loader_skill_md_path`` must be the value of an explicit controller CLI
    argument supplied by the Codex skill loader.  Callers must pass their
    lexical absolute ``__file__`` as ``executing_script_path`` and a literal,
    controller-owned basename as ``expected_script_basename``.
    """

    skill_path, skill_parts = _lexical_absolute_components(
        loader_skill_md_path,
        "loader_skill_path",
    )
    script_path, script_parts = _lexical_absolute_components(
        executing_script_path,
        "executing_script_path",
    )
    expected_basename = _expected_basename(expected_script_basename)
    if skill_parts[-1] != "SKILL.md" or script_parts[-1] != expected_basename:
        raise ValueError("skill_root_authority_expected_basename_mismatch")
    skill_root_parts = skill_parts[:-1]
    if (
        len(script_parts) < 2
        or script_parts[-2] != "scripts"
        or script_parts[:-2] != skill_root_parts
    ):
        raise ValueError("skill_root_authority_layout_mismatch")

    skill_root = Path("/").joinpath(*skill_root_parts)
    scripts_directory = skill_root / "scripts"
    opened_fds: list[int] = []
    entries: list[_HeldEntry] = []
    try:
        try:
            filesystem_root_fd = os.open("/", _directory_flags())
        except OSError as exc:
            raise ValueError("skill_root_authority_secure_open_failed") from exc
        opened_fds.append(filesystem_root_fd)
        filesystem_root_metadata = os.fstat(filesystem_root_fd)
        current_fd = filesystem_root_fd
        for component in skill_root_parts:
            entry = _open_child(current_fd, component, directory=True)
            entries.append(entry)
            opened_fds.append(entry.fd)
            current_fd = entry.fd
        if not entries:
            raise ValueError("skill_root_authority_layout_mismatch")
        skill_root_entry = entries[-1]

        scripts_entry = _open_child(skill_root_entry.fd, "scripts", directory=True)
        entries.append(scripts_entry)
        opened_fds.append(scripts_entry.fd)
        skill_entry = _open_child(skill_root_entry.fd, "SKILL.md", directory=False)
        entries.append(skill_entry)
        opened_fds.append(skill_entry.fd)
        script_entry = _open_child(scripts_entry.fd, expected_basename, directory=False)
        entries.append(script_entry)
        opened_fds.append(script_entry.fd)
        mount_entry = _open_child(scripts_entry.fd, "mount_identity.py", directory=False)
        entries.append(mount_entry)
        opened_fds.append(mount_entry.fd)

        _require_trusted_ancestor(filesystem_root_fd, filesystem_root_metadata)
        skill_root_index = entries.index(skill_root_entry)
        for entry in entries[:skill_root_index]:
            _require_trusted_ancestor(entry.fd, entry.metadata)
        for entry in (
            skill_root_entry,
            scripts_entry,
            skill_entry,
            script_entry,
            mount_entry,
        ):
            _require_owner_and_acl(entry)
        if os.fstat(mount_entry.fd).st_dev != os.fstat(skill_root_entry.fd).st_dev:
            raise ValueError("skill_root_authority_mount_policy_device_mismatch")
        mount_module = _load_held_mount_module(mount_entry)
        mount_resolution = _root_mount_resolution(mount_module, skill_root_entry.fd)
        _require_same_skill_mount(
            mount_module,
            mount_resolution,
            (scripts_entry, skill_entry, script_entry, mount_entry),
            (
                "scripts",
                "SKILL.md",
                "scripts/executing_script",
                "scripts/mount_identity.py",
            ),
        )

        binding = SkillRootAuthority(
            skill_root=skill_root,
            scripts_directory=scripts_directory,
            skill_markdown=skill_path,
            executing_script=script_path,
            skill_root_fd=skill_root_entry.fd,
            scripts_fd=scripts_entry.fd,
            skill_markdown_fd=skill_entry.fd,
            executing_script_fd=script_entry.fd,
            mount_policy_fd=mount_entry.fd,
            _root_metadata=filesystem_root_metadata,
            _entries=tuple(entries),
            _mount_module=mount_module,
            _mount_resolution=mount_resolution,
        )
        binding.revalidate()
        yield binding
    finally:
        for descriptor in reversed(opened_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


__all__ = [
    "AUTHORIZED_LAUNCH_TARGET_BASENAMES",
    "GOAL_REFERENCE_PATHS",
    "MOUNT_IDENTITY_SOURCE_SHA256",
    "REVIEWED_SCRIPT_BASENAMES",
    "RUNTIME_BUNDLE_BASENAMES",
    "SKILL_ROOT_AUTHORITY_ASSURANCE",
    "SKILL_ROOT_AUTHORITY_SCHEMA_VERSION",
    "SkillRootAuthority",
    "open_skill_root_authority",
]
