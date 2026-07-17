#!/usr/bin/env python3
"""Owner-only controller state outside the target repository.

Goal and Apply runs are controller authority, not project artifacts.  This
module keeps that authority under the local CodexQB trust store and binds each
state subtree to one descriptor-observed repository identity.  The target
repository therefore remains evidence-only for these controllers.
"""

from __future__ import annotations

from contextlib import contextmanager
from collections.abc import Iterator, Sequence
import ctypes
import errno
import json
import os
from pathlib import Path
import pwd
import re
import stat
import sys

from mount_identity import (
    APPLY_RUN_MUTATION,
    READ_ONLY_EVIDENCE,
    MountResolution,
    RUN_REPLACE_QUARANTINE_DELETE,
    require_mount_assurance,
    require_same_mount,
    resolve_mount_identity,
)
from repository_io import (  # noqa: E402
    ControllerRootProof,
    _controller_canonical_root,
    _controller_root_proof,
    _require_local_authority_mount_resolution,
    open_repository_io,
)
from artifact_io import (  # noqa: E402
    atomic_write_bytes_at,
    atomic_write_json_at,
    atomic_write_text_at,
    directory_entry_matches,
    locked_directory,
    read_regular_bytes_at,
    read_regular_unvalidated_bytes_at,
    read_regular_json_at,
    read_regular_text_at,
    regular_target_metadata_at,
    unlink_regular_at,
)


# Reviewed controller-state primitives.  Protected consumers import these from
# this whole-module-pinned boundary, never from repository artifact modules.
controller_atomic_write_bytes = atomic_write_bytes_at
controller_atomic_write_json = atomic_write_json_at
controller_atomic_write_text = atomic_write_text_at
controller_directory_entry_matches = directory_entry_matches
controller_locked_directory = locked_directory
controller_read_bytes = read_regular_bytes_at
controller_read_unvalidated_bytes = read_regular_unvalidated_bytes_at
controller_read_json = read_regular_json_at
controller_read_text = read_regular_text_at
controller_regular_metadata = regular_target_metadata_at
controller_unlink_regular = unlink_regular_at
controller_require_mount_assurance = require_mount_assurance
controller_require_same_mount = require_same_mount


def controller_resolve_mount_identity(
    descriptor: int,
    *,
    reconcile: bool = True,
    preferred_provider: str | None = None,
) -> MountResolution:
    """Resolve one controller descriptor only on a proven local filesystem."""

    resolution = resolve_mount_identity(
        descriptor,
        reconcile=reconcile,
        preferred_provider=preferred_provider,
    )
    require_mount_assurance(resolution, READ_ONLY_EVIDENCE)
    _require_local_authority_mount_resolution(resolution)
    return resolution

# Descriptor-oriented primitives used by the pinned Apply controller.  These
# names are deliberately explicit so protected consumers never import ``os``
# or obtain a module-shaped escape hatch.  Policy allowlists each imported
# symbol and pins every caller body that uses a powerful primitive.
ControllerStatResult = os.stat_result
CONTROLLER_O_RDONLY = os.O_RDONLY
CONTROLLER_O_WRONLY = os.O_WRONLY
CONTROLLER_O_CREAT = os.O_CREAT
CONTROLLER_O_EXCL = os.O_EXCL
CONTROLLER_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
CONTROLLER_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
CONTROLLER_O_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
CONTROLLER_O_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
controller_open = os.open
controller_close = os.close
controller_read = os.read
controller_write = os.write
controller_stat = os.stat
controller_lstat = os.lstat
controller_fstat = os.fstat
controller_fsync = os.fsync
controller_fchmod = os.fchmod
controller_chmod = os.chmod
controller_mkdir = os.mkdir
controller_rmdir = os.rmdir
controller_unlink = os.unlink
controller_listdir = os.listdir
controller_dup = os.dup
controller_fsencode = os.fsencode
controller_strerror = os.strerror


def controller_environment_value(name: str) -> str | None:
    """Read one explicitly named controller configuration value."""

    return os.environ.get(name)


def controller_effective_uid() -> int:
    """Return the owner identity used by state permission checks."""

    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def controller_path_is_mount(path: Path) -> bool:
    return os.path.ismount(path)


def controller_path_real_normalized(path: Path | str) -> str:
    return os.path.normpath(os.path.realpath(path))


def controller_path_normalized(path: str) -> str:
    return os.path.normpath(path)


def controller_entry_exists(path: Path) -> bool:
    """Return whether an external controller-state entry exists, without following it."""

    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    return True


def controller_regular_entry_exists(path: Path) -> bool:
    """Return whether an external controller-state entry is a regular file."""

    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        return False
    return stat.S_ISREG(metadata.st_mode)


def controller_lexical_absolute(path: Path) -> Path:
    """Return a lexical absolute path without resolving repository links."""

    return Path(os.path.abspath(os.fspath(path)))


def controller_process_id() -> int:
    """Return the controller PID for collision-resistant local run labels."""

    return os.getpid()


def controller_home_directory() -> Path:
    """Return the controller account home used for its owner-only trust store."""

    try:
        record = pwd.getpwuid(controller_effective_uid())
    except (KeyError, OSError) as exc:
        raise ValueError("controller_home_identity_unavailable") from exc
    raw = record.pw_dir
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        raise ValueError("controller_home_identity_invalid")
    candidate = Path(raw)
    if not candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("controller_home_identity_invalid")
    return Path(os.path.normpath(raw))


CONTROLLER_STORE_VERSION = 1
CONTROLLER_STORE_DIR_NAME = "controller-state-v1"
REPOSITORY_BINDING_NAME = "repository-binding-v1.json"
MAX_BINDING_BYTES = 16 * 1024

GOAL_RUN_COMPONENTS = ("goal-runs",)
APPLY_RUN_COMPONENTS = (".codexqb", "apply-runs")
_SAFE_COMPONENTS = frozenset({GOAL_RUN_COMPONENTS, APPLY_RUN_COMPONENTS})


def _secure_directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("controller_store_secure_open_unavailable")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _expected_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def _descriptor_has_acl(descriptor: int) -> bool:
    """Reject POSIX/default ACLs and Darwin extended ACL entries."""

    try:
        names = os.listxattr(descriptor)
    except AttributeError:
        if sys.platform != "darwin":
            raise ValueError("controller_store_acl_probe_unavailable") from None
        names = []
    except OSError as exc:
        unsupported = {errno.ENOTSUP}
        if hasattr(errno, "EOPNOTSUPP"):
            unsupported.add(errno.EOPNOTSUPP)
        if exc.errno not in unsupported or sys.platform != "darwin":
            raise ValueError("controller_store_acl_probe_failed") from None
        names = []
    normalized_names: list[str] = []
    for name in names:
        if not isinstance(name, (str, bytes)):
            raise ValueError("controller_store_acl_probe_failed")
        normalized_names.append(os.fsdecode(name).casefold())
    if any(
        "acl" in name or name == "com.apple.system.security"
        for name in normalized_names
    ):
        return True
    if sys.platform != "darwin":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    getter = getattr(libc, "acl_get_fd_np", None)
    releaser = getattr(libc, "acl_free", None)
    if getter is None or releaser is None:
        raise ValueError("controller_store_acl_probe_unavailable")
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
        raise ValueError("controller_store_acl_probe_failed")
    # ACL_TYPE_EXTENDED returns no object for a descriptor without an extended
    # ACL.  Any returned ACL object is therefore a fail-closed finding; do not
    # accidentally interpret acl_get_entry's zero-success convention as
    # "empty".
    releaser(acl)
    return True


def _darwin_descriptor_acl_is_deny_only(descriptor: int) -> bool:
    """Accept the standard macOS home deny-delete ACL, never an allow ACL."""

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
            text = ctypes.string_at(rendered, length.value).decode("utf-8", errors="strict")
        except (UnicodeDecodeError, ValueError):
            return False
        lines = [line for line in text.splitlines() if line]
        if not lines or lines[0] != "!#acl 1" or len(lines) < 2:
            return False
        entries = lines[1:]
        return all(len(entry.split(":")) >= 3 and entry.split(":")[-2] == "deny" for entry in entries)
    finally:
        if rendered:
            releaser(rendered)
        releaser(acl)


def _private_directory(metadata: os.stat_result, *, exact: bool) -> bool:
    permissions = stat.S_IMODE(metadata.st_mode)
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata.st_uid == _expected_uid()
        and (permissions == 0o700 if exact else permissions & 0o022 == 0)
    )


def _private_regular(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_uid == _expected_uid()
        and metadata.st_nlink == 1
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def controller_tree_is_private(
    directory_fd: int,
    *,
    max_entries: int = 8192,
    max_depth: int = 128,
) -> bool:
    """Verify exact modes, ownership, ACL absence, links, and mount confinement."""

    if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
        raise ValueError("invalid_controller_tree_budget")
    if not isinstance(max_depth, int) or isinstance(max_depth, bool) or max_depth < 1:
        raise ValueError("invalid_controller_tree_depth")
    try:
        root_metadata = os.fstat(directory_fd)
        if not _private_directory(root_metadata, exact=True) or _descriptor_has_acl(directory_fd):
            return False
        resolution = controller_resolve_mount_identity(directory_fd, reconcile=True)
        require_mount_assurance(resolution, READ_ONLY_EVIDENCE)
        remaining = [max_entries]

        def inspect(parent_fd: int, prefix: str, depth: int) -> bool:
            if depth > max_depth:
                return False
            names: list[str] = []
            try:
                with os.scandir(parent_fd) as entries:
                    for entry in entries:
                        if remaining[0] <= 0:
                            return False
                        remaining[0] -= 1
                        names.append(entry.name)
            except OSError:
                return False
            for name in sorted(names):
                label = f"{prefix}/{name}" if prefix else name
                try:
                    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except OSError:
                    return False
                if stat.S_ISDIR(before.st_mode):
                    try:
                        child_fd = os.open(name, _secure_directory_flags(), dir_fd=parent_fd)
                    except OSError:
                        return False
                    try:
                        after = os.fstat(child_fd)
                        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                        if (
                            not _private_directory(after, exact=True)
                            or _descriptor_has_acl(child_fd)
                            or before.st_dev != after.st_dev
                            or before.st_ino != after.st_ino
                            or current.st_dev != after.st_dev
                            or current.st_ino != after.st_ino
                        ):
                            return False
                        require_same_mount(resolution, child_fd, label)
                        if not inspect(child_fd, label, depth + 1):
                            return False
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(before.st_mode):
                    flags = (
                        os.O_RDONLY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0)
                    )
                    try:
                        child_fd = os.open(name, flags, dir_fd=parent_fd)
                    except OSError:
                        return False
                    try:
                        after = os.fstat(child_fd)
                        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                        if (
                            not _private_regular(after)
                            or _descriptor_has_acl(child_fd)
                            or before.st_dev != after.st_dev
                            or before.st_ino != after.st_ino
                            or current.st_dev != after.st_dev
                            or current.st_ino != after.st_ino
                        ):
                            return False
                        require_same_mount(resolution, child_fd, label)
                    finally:
                        os.close(child_fd)
                else:
                    return False
            return True

        return inspect(directory_fd, "", 0)
    except (OSError, RecursionError, TypeError, ValueError):
        return False


def _open_child_directory(
    parent_fd: int,
    name: str,
    *,
    create: bool,
    exact: bool = True,
    mount_resolution: MountResolution | None = None,
) -> int:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError("invalid_controller_store_component")
    created = False
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        if not create:
            raise
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            # A concurrent controller may have created the same deterministic
            # component.  It is accepted only after the full descriptor,
            # ownership, mode, ACL, identity, and mount checks below.
            pass
        else:
            created = True
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if created:
        os.chmod(name, 0o700, dir_fd=parent_fd, follow_symlinks=False)
        os.fsync(parent_fd)
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not _private_directory(before, exact=exact):
        raise ValueError("controller_store_directory_not_private")
    child_fd = os.open(name, _secure_directory_flags(), dir_fd=parent_fd)
    try:
        after = os.fstat(child_fd)
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            not _private_directory(after, exact=exact)
            or _descriptor_has_acl(child_fd)
            or before.st_dev != after.st_dev
            or before.st_ino != after.st_ino
            or current.st_dev != after.st_dev
            or current.st_ino != after.st_ino
        ):
            raise ValueError("controller_store_directory_identity_changed")
        if mount_resolution is not None:
            require_same_mount(mount_resolution, child_fd, name)
    except Exception:
        os.close(child_fd)
        raise
    return child_fd


def _require_trusted_chain_directory(
    descriptor: int,
    *,
    owner_only: bool,
) -> os.stat_result:
    """Validate one held component of the fixed account-home descriptor chain."""

    metadata = os.fstat(descriptor)
    permissions = stat.S_IMODE(metadata.st_mode)
    allowed_owners = {_expected_uid()} if owner_only else {0, _expected_uid()}
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in allowed_owners
        or permissions & 0o022
    ):
        raise ValueError("controller_store_home_chain_not_private")
    if _descriptor_has_acl(descriptor) and not _darwin_descriptor_acl_is_deny_only(descriptor):
        raise ValueError("controller_store_home_chain_not_private")
    controller_resolve_mount_identity(descriptor, reconcile=True)
    return metadata


def _open_absolute_home_chain(home: Path) -> list[int]:
    """Open every fixed home component descriptor-relative without following links."""

    if not home.is_absolute() or ".." in home.parts:
        raise ValueError("controller_home_identity_invalid")
    components = home.parts[1:]
    opened: list[int] = []
    root_fd = os.open(os.path.sep, _secure_directory_flags())
    opened.append(root_fd)
    try:
        _require_trusted_chain_directory(root_fd, owner_only=False)
        current_fd = root_fd
        for index, component in enumerate(components):
            if not component or component in {".", ".."} or "/" in component or "\x00" in component:
                raise ValueError("controller_home_identity_invalid")
            try:
                before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                child_fd = os.open(component, _secure_directory_flags(), dir_fd=current_fd)
            except OSError as exc:
                raise ValueError("controller_store_home_chain_invalid") from exc
            opened.append(child_fd)
            after = os.fstat(child_fd)
            current = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if (
                before.st_dev != after.st_dev
                or before.st_ino != after.st_ino
                or current.st_dev != after.st_dev
                or current.st_ino != after.st_ino
            ):
                raise ValueError("controller_store_home_chain_changed")
            _require_trusted_chain_directory(
                child_fd,
                owner_only=index == len(components) - 1,
            )
            current_fd = child_fd
        return opened
    except Exception:
        for descriptor in reversed(opened):
            os.close(descriptor)
        raise


def _reject_repository_ancestor(
    descriptors: Sequence[int],
    repository_proof: ControllerRootProof | None,
) -> None:
    if repository_proof is None:
        return
    forbidden = (repository_proof.root_device, repository_proof.root_inode)
    if any((os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) == forbidden for descriptor in descriptors):
        raise ValueError("controller_store_must_be_outside_repository")


@contextmanager
def _open_controller_trust_root(
    *,
    create: bool,
    repository_proof: ControllerRootProof | None = None,
) -> Iterator[tuple[int, Path, list[int]]]:
    home = controller_home_directory()
    opened = _open_absolute_home_chain(home)
    try:
        _reject_repository_ancestor(opened, repository_proof)
        home_fd = opened[-1]
        home_mount = controller_resolve_mount_identity(home_fd, reconcile=True)
        codex_fd = _open_child_directory(
            home_fd,
            ".codex",
            create=create,
            exact=False,
            mount_resolution=home_mount,
        )
        opened.append(codex_fd)
        _reject_repository_ancestor(opened, repository_proof)
        trust_fd = _open_child_directory(
            codex_fd,
            "codexqb-trust",
            create=create,
            exact=True,
            mount_resolution=home_mount,
        )
        opened.append(trust_fd)
        _reject_repository_ancestor(opened, repository_proof)
        yield trust_fd, home / ".codex" / "codexqb-trust", opened
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


def open_controller_trust_root_fd(*, create: bool) -> int:
    """Return a held descriptor for the fixed owner trust root.

    This deliberately has no path or environment override.  Tests inject a
    home provider by patching ``controller_home_directory``; production callers
    are always bound to the effective account's passwd entry.
    """

    with _open_controller_trust_root(create=create) as (trust_fd, _path, _opened):
        return os.dup(trust_fd)


@contextmanager
def open_controller_store(
    *,
    create: bool,
    repository_proof: ControllerRootProof | None = None,
) -> Iterator[tuple[int, Path]]:
    """Open the controller-state root without following its final components."""

    with _open_controller_trust_root(
        create=create,
        repository_proof=repository_proof,
    ) as (trust_fd, trust_path, opened):
        trust_mount = controller_resolve_mount_identity(trust_fd, reconcile=True)
        store_fd = _open_child_directory(
            trust_fd,
            CONTROLLER_STORE_DIR_NAME,
            create=create,
            exact=True,
            mount_resolution=trust_mount,
        )
        opened.append(store_fd)
        _reject_repository_ancestor(opened, repository_proof)
        store_path = trust_path / CONTROLLER_STORE_DIR_NAME
        if _descriptor_has_acl(store_fd):
            raise ValueError("controller_store_acl_rejected")
        yield store_fd, store_path


def _repository_proof(root: Path) -> tuple[Path, ControllerRootProof]:
    with open_repository_io(root) as repository:
        return _controller_canonical_root(repository), _controller_root_proof(repository)


def canonical_repository_root(root: Path) -> Path:
    return _repository_proof(root)[0]


def repository_identity(root: Path) -> str:
    return _repository_proof(root)[1].repository_identity_sha256


def _binding_payload(root: Path) -> dict[str, object]:
    _canonical, proof = _repository_proof(root)
    return _binding_payload_from_proof(proof)


def _binding_payload_from_proof(proof: ControllerRootProof) -> dict[str, object]:
    return {
        "binding_version": CONTROLLER_STORE_VERSION,
        "repository_identity": proof.repository_identity_sha256,
        "repository_device": proof.root_device,
        "repository_inode": proof.root_inode,
        "mount_provider": proof.mount_provider,
        "mount_assurance": proof.mount_assurance,
    }


def _read_binding(state_fd: int) -> dict[str, object]:
    descriptor = os.open(
        REPOSITORY_BINDING_NAME,
        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
        dir_fd=state_fd,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not _private_regular(before)
            or _descriptor_has_acl(descriptor)
            or before.st_size > MAX_BINDING_BYTES
        ):
            raise ValueError("controller_repository_binding_invalid")
        chunks: list[bytes] = []
        remaining = MAX_BINDING_BYTES + 1
        while remaining:
            chunk = os.read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        raw = b"".join(chunks)
        stable_before = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        stable_after = (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if len(raw) > MAX_BINDING_BYTES or stable_before != stable_after:
            raise ValueError("controller_repository_binding_changed")
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("controller_repository_binding_invalid") from None
    finally:
        os.close(descriptor)
    if not isinstance(payload, dict):
        raise ValueError("controller_repository_binding_invalid")
    return payload


def _write_binding(state_fd: int, payload: dict[str, object]) -> None:
    raw = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    try:
        atomic_write_bytes_at(
            state_fd,
            REPOSITORY_BINDING_NAME,
            raw,
            mode=0o600,
            expected_state="missing",
        )
    except ValueError as exc:
        if str(exc) == "artifact_target_appeared_during_write":
            raise FileExistsError(REPOSITORY_BINDING_NAME) from None
        raise


def _verify_binding(state_fd: int, expected: dict[str, object]) -> None:
    try:
        actual = _read_binding(state_fd)
    except FileNotFoundError:
        raise ValueError("controller_repository_binding_missing") from None
    if actual != expected:
        raise ValueError("controller_repository_binding_mismatch")


def _state_inventory(state_fd: int, *, max_entries: int = 4) -> tuple[str, ...]:
    names: list[str] = []
    try:
        with os.scandir(state_fd) as entries:
            for entry in entries:
                if len(names) >= max_entries:
                    raise ValueError("controller_repository_state_inventory_invalid")
                names.append(entry.name)
    except OSError as exc:
        raise ValueError("controller_repository_state_inventory_unavailable") from exc
    return tuple(sorted(names))


def _open_or_enroll_repository_state(
    store_fd: int,
    identity: str,
    expected: dict[str, object],
    *,
    create: bool,
    mount_resolution: MountResolution,
) -> int:
    """Open a bound identity or atomically enroll one newly-created empty dir."""

    with locked_directory(store_fd):
        created = False
        try:
            os.stat(identity, dir_fd=store_fd, follow_symlinks=False)
        except FileNotFoundError:
            if not create:
                raise
            try:
                os.mkdir(identity, mode=0o700, dir_fd=store_fd)
            except FileExistsError:
                # A creator that does not share our lease raced enrollment.
                # Treat the resulting pre-existing directory as recovery-only.
                pass
            else:
                created = True
                os.fsync(store_fd)
        state_fd = _open_child_directory(
            store_fd,
            identity,
            create=False,
            exact=True,
            mount_resolution=mount_resolution,
        )
        try:
            if created:
                if _state_inventory(state_fd) != ():
                    raise ValueError("controller_repository_enrollment_not_empty")
                _write_binding(state_fd, expected)
                os.fsync(state_fd)
                os.fsync(store_fd)
                if _state_inventory(state_fd) != (REPOSITORY_BINDING_NAME,):
                    raise ValueError("controller_repository_enrollment_commit_unknown")
                _verify_binding(state_fd, expected)
            else:
                try:
                    _verify_binding(state_fd, expected)
                except ValueError as exc:
                    if str(exc) == "controller_repository_binding_missing":
                        raise ValueError(
                            "controller_repository_enrollment_recovery_required"
                        ) from None
                    raise
            return state_fd
        except Exception:
            os.close(state_fd)
            raise


@contextmanager
def open_repository_state(root: Path, *, create: bool) -> Iterator[tuple[int, Path]]:
    with open_repository_io(root) as repository:
        proof = _controller_root_proof(repository)
        expected = _binding_payload_from_proof(proof)
        identity = proof.repository_identity_sha256
        with open_controller_store(
            create=create,
            repository_proof=proof,
        ) as (store_fd, store_path):
            store_mount = controller_resolve_mount_identity(store_fd, reconcile=True)
            require_mount_assurance(store_mount, READ_ONLY_EVIDENCE)
            state_fd = _open_or_enroll_repository_state(
                store_fd,
                identity,
                expected,
                create=create,
                mount_resolution=store_mount,
            )
            try:
                if _binding_payload_from_proof(_controller_root_proof(repository)) != expected:
                    raise ValueError("controller_repository_root_identity_changed")
                yield state_fd, store_path / identity
                if _binding_payload_from_proof(_controller_root_proof(repository)) != expected:
                    raise ValueError("controller_repository_root_identity_changed")
            finally:
                os.close(state_fd)


def controller_state_root(root: Path) -> Path:
    canonical, proof = _repository_proof(root)
    store = controller_home_directory() / ".codex" / "codexqb-trust" / CONTROLLER_STORE_DIR_NAME
    result = store / proof.repository_identity_sha256
    try:
        result.relative_to(canonical)
    except ValueError:
        return result
    raise ValueError("controller_store_must_be_outside_repository")


def controller_runs_root(root: Path, components: Sequence[str]) -> Path:
    selected = tuple(components)
    if selected not in _SAFE_COMPONENTS:
        raise ValueError("invalid_controller_runs_kind")
    return controller_state_root(root).joinpath(*selected)


@contextmanager
def open_controller_runs_root(
    root: Path,
    components: Sequence[str],
    *,
    create: bool,
) -> Iterator[tuple[int, Path]]:
    selected = tuple(components)
    if selected not in _SAFE_COMPONENTS:
        raise ValueError("invalid_controller_runs_kind")
    with open_repository_state(root, create=create) as (state_fd, state_path):
        state_mount = controller_resolve_mount_identity(state_fd, reconcile=True)
        require_mount_assurance(state_mount, READ_ONLY_EVIDENCE)
        current_fd = os.dup(state_fd)
        current_path = state_path
        try:
            for component in selected:
                child_fd = _open_child_directory(
                    current_fd,
                    component,
                    create=create,
                    exact=True,
                    mount_resolution=state_mount,
                )
                os.close(current_fd)
                current_fd = child_fd
                current_path /= component
            yield current_fd, current_path
        finally:
            os.close(current_fd)


def goal_runs_root(root: Path) -> Path:
    return controller_runs_root(root, GOAL_RUN_COMPONENTS)


def apply_runs_root(root: Path) -> Path:
    return controller_runs_root(root, APPLY_RUN_COMPONENTS)


@contextmanager
def open_controller_run_directory(
    root: Path,
    components: Sequence[str],
    run_name: str,
    *,
    create: bool,
    allow_existing: bool,
    name_pattern: str,
) -> Iterator[tuple[int, Path, object]]:
    """Open one direct child run and return a descriptor-bound revalidator."""

    if re.fullmatch(name_pattern, run_name) is None:
        raise ValueError("invalid_controller_run_name")
    with open_controller_runs_root(root, components, create=create) as (runs_fd, runs_path):
        before_runs = os.fstat(runs_fd)
        try:
            existing = os.stat(run_name, dir_fd=runs_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not allow_existing:
            raise FileExistsError(run_name)
        created = False
        if existing is None:
            if not create:
                raise FileNotFoundError(run_name)
            os.mkdir(run_name, mode=0o700, dir_fd=runs_fd)
            os.fsync(runs_fd)
            created = True
        run_fd = -1
        try:
            run_fd = _open_child_directory(runs_fd, run_name, create=False, exact=True)
            run_metadata = os.fstat(run_fd)
            run_path = runs_path / run_name

            def revalidate() -> bool:
                try:
                    current_runs = os.fstat(runs_fd)
                    current_run = os.fstat(run_fd)
                    path_runs = os.stat(runs_path, follow_symlinks=False)
                    path_run = os.stat(run_name, dir_fd=runs_fd, follow_symlinks=False)
                except OSError:
                    return False
                return (
                    _private_directory(current_runs, exact=True)
                    and _private_directory(current_run, exact=True)
                    and before_runs.st_dev == current_runs.st_dev == path_runs.st_dev
                    and before_runs.st_ino == current_runs.st_ino == path_runs.st_ino
                    and run_metadata.st_dev == current_run.st_dev == path_run.st_dev
                    and run_metadata.st_ino == current_run.st_ino == path_run.st_ino
                    and run_metadata.st_dev == before_runs.st_dev
                    and controller_tree_is_private(run_fd)
                )

            if not revalidate():
                raise ValueError("controller_run_directory_identity_changed")
            yield run_fd, run_path, revalidate
        except Exception:
            if created and run_fd < 0:
                try:
                    os.rmdir(run_name, dir_fd=runs_fd)
                except OSError:
                    pass
            raise
        finally:
            if run_fd >= 0:
                os.close(run_fd)


def legacy_goal_runs_root(root: Path) -> Path:
    return canonical_repository_root(root) / "Planner-docs" / "Goal-Runs"


def legacy_apply_runs_root(root: Path) -> Path:
    return canonical_repository_root(root) / ".codexqb" / "apply-runs"


class ControllerRunArtifacts:
    """High-level owner-state artifact capability; no descriptor is exposed."""

    __slots__ = ("__directory_fd", "__revalidate")

    def __init__(self, directory_fd: int, revalidate: object) -> None:
        if not callable(revalidate):
            raise TypeError("controller_run_revalidator_required")
        self.__directory_fd = directory_fd
        self.__revalidate = revalidate

    def revalidate(self) -> bool:
        return bool(self.__revalidate())

    @contextmanager
    def locked(self) -> Iterator[None]:
        with locked_directory(self.__directory_fd):
            if not self.revalidate():
                raise ValueError("controller_run_directory_identity_changed")
            yield

    def read_json(self, name: str) -> dict[str, object]:
        if not self.revalidate():
            raise ValueError("controller_run_directory_identity_changed")
        return read_regular_json_at(self.__directory_fd, name)

    def write_text(self, name: str, text: str) -> None:
        atomic_write_text_at(
            self.__directory_fd,
            name,
            text,
            revalidate=self.revalidate,
        )

    def remove(self, name: str, *, missing_ok: bool = True) -> None:
        unlink_regular_at(
            self.__directory_fd,
            name,
            missing_ok=missing_ok,
            revalidate=self.revalidate,
        )

    def require_regular(self, name: str) -> None:
        if regular_target_metadata_at(self.__directory_fd, name) is None:
            raise FileNotFoundError(name)

    def has_regular(self, name: str) -> bool:
        return regular_target_metadata_at(self.__directory_fd, name) is not None


@contextmanager
def open_goal_run_artifacts(
    root: Path,
    run_dir: Path,
    *,
    create: bool,
    allow_existing: bool,
    name_pattern: str,
) -> Iterator[ControllerRunArtifacts]:
    with open_controller_run_directory(
        root,
        GOAL_RUN_COMPONENTS,
        run_dir.name,
        create=create,
        allow_existing=allow_existing,
        name_pattern=name_pattern,
    ) as (run_fd, opened_path, revalidate):
        if opened_path != run_dir:
            raise ValueError("controller_run_directory_identity_changed")
        yield ControllerRunArtifacts(run_fd, revalidate)
