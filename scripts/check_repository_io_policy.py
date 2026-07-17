#!/usr/bin/env python3
"""Check source or extracted CodexQB package for repository-I/O bypasses."""

from __future__ import annotations

import os
import sys

# Python startup hooks run before this file's first instruction, so an
# in-process restart cannot retroactively establish isolation.  Every selected
# launcher must supply the complete interpreter contract up front.
if __name__ == "__main__" and not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
):
    sys.stderr.write(
        "repository_io_policy=unsupported "
        "reason=requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)

import argparse
import ctypes
import errno
import hashlib
import importlib.abc
import importlib.util
from pathlib import Path
import stat


REPO_ROOT = Path(__file__).resolve().parents[1]
POLICY_DIR = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts"
sys.dont_write_bytecode = True
sys.pycache_prefix = os.path.join(
    os.devnull, f"codexqb-wrapper-{os.urandom(24).hex()}"
)

_BOOTSTRAP_RUNTIME_NAMES = frozenset(
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
        "repository_io_policy.py",
        "repository_validation.py",
        "safety_contracts.py",
        "skill_launcher.py",
        "skill_root_authority.py",
        "validate_planner_docs.py",
    }
)
# Every target runtime baseline must first match one reviewed source byte pin.
# Only the narrower executed set is exposed through the in-memory bootstrap
# loader; captured-but-unexecuted runtime bytes can never self-enrol.
_REVIEWED_SOURCE_SHA256 = {
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
    "repository_io_policy.py": "5f607b84f3ab0be1632b9eaac999d6a2febdee092f72cae6c2860d38baddfceb",
    "repository_validation.py": "2d9c9e98f195995020447e21b2edf48c19eb69859bd88188b6016b9c5c59af8e",
    "safety_contracts.py": "df43016eae8b2fe0a766be21c02984674a1a9743bde3536167b769682b4fcd58",
    "skill_launcher.py": "b2e59e6fbbb3412017a26b0886caf858deb1a4cc0bdfbeece5f44e1e6fb859b3",
    "skill_root_authority.py": "be6f7b957c52d72f8ad7e1e7bacb09e35ec39f798f26ee8dfcf964a762fc5315",
    "validate_planner_docs.py": "ceb9b70d096f5da5d3355e65bba36e8a43551c8046239c50800ef2205a222c6b",
}
_EXECUTED_SOURCE_NAMES = frozenset(
    {
        "artifact_io.py",
        "controller_store.py",
        "git_evidence.py",
        "mount_identity.py",
        "repository_evidence.py",
        "repository_io.py",
        "repository_io_policy.py",
        "safety_contracts.py",
    }
)
_MAX_BOOTSTRAP_FILE_BYTES = 8 * 1024 * 1024
_MAX_BOOTSTRAP_TOTAL_BYTES = 64 * 1024 * 1024
_SOURCE_CHAIN_COMPONENTS = ("plugins", "codexqb", "skills", "codexqb", "scripts")
if (
    set(_REVIEWED_SOURCE_SHA256) != set(_BOOTSTRAP_RUNTIME_NAMES)
    or not _EXECUTED_SOURCE_NAMES.issubset(_BOOTSTRAP_RUNTIME_NAMES)
    or any(
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for digest in _REVIEWED_SOURCE_SHA256.values()
    )
):
    raise RuntimeError("repository_io_policy_bootstrap_pin_registry_invalid")


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _descriptor_has_acl(descriptor: int) -> bool:
    """Reject POSIX/default ACLs and Darwin extended ACL entries."""

    try:
        names = os.listxattr(descriptor)
    except AttributeError:
        if sys.platform != "darwin":
            raise RuntimeError("repository_io_policy_acl_probe_unavailable") from None
        names = []
    except OSError as exc:
        unsupported = {errno.ENOTSUP}
        if hasattr(errno, "EOPNOTSUPP"):
            unsupported.add(errno.EOPNOTSUPP)
        if exc.errno not in unsupported or sys.platform != "darwin":
            raise RuntimeError("repository_io_policy_acl_probe_failed") from None
        names = []
    for name in names:
        try:
            normalized_name = os.fsdecode(name).casefold()
        except (TypeError, UnicodeError):
            return True
        if "acl" in normalized_name or normalized_name in {
            "com.apple.system.security",
            "security.nt_security_descriptor",
        }:
            return True
    if sys.platform != "darwin":
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    getter = getattr(libc, "acl_get_fd_np", None)
    releaser = getattr(libc, "acl_free", None)
    if getter is None or releaser is None:
        raise RuntimeError("repository_io_policy_acl_probe_unavailable")
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
        raise RuntimeError("repository_io_policy_acl_probe_failed")
    if releaser(acl) != 0:
        raise RuntimeError("repository_io_policy_acl_probe_failed")
    return True


_LOCAL_AUTHORITY_FILESYSTEM_TYPES = frozenset(
    {
        "apfs",
        "hfs",
        "ext2",
        "ext3",
        "ext4",
        "xfs",
        "btrfs",
        "bcachefs",
        "f2fs",
        "jfs",
        "reiserfs",
        "tmpfs",
        "ramfs",
        "ubifs",
    }
)
_MAX_PROC_MOUNT_BYTES = 8 * 1024 * 1024
_DARWIN_MNT_LOCAL = 0x00001000


def _mountinfo_field_is_idmapped(value: bytes) -> bool:
    return any(
        part == b"idmapped" or part.startswith(b"idmapped=")
        for part in value.split(b",")
    )


def _read_bounded_os_file(path: str, maximum: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    except (OSError, TypeError, ValueError):
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _linux_filesystem_type_from_mountinfo(
    fdinfo: bytes,
    mountinfo: bytes,
) -> str:
    mount_ids: list[int] = []
    for line in fdinfo.splitlines():
        if not line.startswith(b"mnt_id:"):
            continue
        try:
            mount_ids.append(int(line.split(b":", 1)[1].strip()))
        except ValueError:
            raise RuntimeError("repository_io_policy_filesystem_locality_unavailable") from None
    if len(mount_ids) != 1 or mount_ids[0] <= 0:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    matches: list[str] = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            current_mount_id = int(fields[0])
            separator = fields.index(b"-")
            raw_type = fields[separator + 1]
        except (ValueError, IndexError):
            raise RuntimeError("repository_io_policy_filesystem_locality_unavailable") from None
        if current_mount_id != mount_ids[0]:
            continue
        mount_attributes = fields[5:separator] + fields[separator + 3 :]
        if any(
            _mountinfo_field_is_idmapped(field.lower())
            for field in mount_attributes
        ):
            raise RuntimeError("repository_io_policy_filesystem_idmapped")
        try:
            matches.append(raw_type.decode("ascii").casefold())
        except UnicodeDecodeError:
            raise RuntimeError("repository_io_policy_filesystem_locality_unavailable") from None
    if len(matches) != 1:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    return matches[0]


def _linux_descriptor_filesystem_type(descriptor: int) -> str:
    return _linux_filesystem_type_from_mountinfo(
        _read_bounded_os_file(
            f"/proc/{os.getpid()}/fdinfo/{descriptor}",
            64 * 1024,
        ),
        _read_bounded_os_file(
            f"/proc/{os.getpid()}/mountinfo",
            _MAX_PROC_MOUNT_BYTES,
        ),
    )


class _DarwinFsid(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32 * 2)]


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFsid),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


def _darwin_descriptor_filesystem_type(descriptor: int) -> str:
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "fstatfs", None)
    if function is None:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    function.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatfs)]
    function.restype = ctypes.c_int
    payload = _DarwinStatfs()
    ctypes.set_errno(0)
    if function(descriptor, ctypes.byref(payload)) != 0:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    if int(payload.f_flags) & _DARWIN_MNT_LOCAL == 0:
        raise RuntimeError("repository_io_policy_filesystem_not_local")
    raw_type = bytes(payload.f_fstypename).split(b"\0", 1)[0]
    try:
        filesystem_type = raw_type.decode("ascii").casefold()
    except UnicodeDecodeError:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable") from None
    if not filesystem_type:
        raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")
    return filesystem_type


def _descriptor_filesystem_type(descriptor: int) -> str:
    if sys.platform.startswith("linux"):
        return _linux_descriptor_filesystem_type(descriptor)
    if sys.platform == "darwin":
        return _darwin_descriptor_filesystem_type(descriptor)
    raise RuntimeError("repository_io_policy_filesystem_locality_unavailable")


def _require_local_filesystem(descriptor: int) -> str:
    filesystem_type = _descriptor_filesystem_type(descriptor)
    if filesystem_type not in _LOCAL_AUTHORITY_FILESYSTEM_TYPES:
        raise RuntimeError("repository_io_policy_filesystem_not_local")
    return filesystem_type


def _read_all(fd: int, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            raise RuntimeError("repository_io_policy_bootstrap_short_read")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise RuntimeError("repository_io_policy_bootstrap_size_changed")
    return b"".join(chunks)


def _open_source_file(
    directory_fd: int,
    name: str,
    expected_filesystem_type: str,
) -> tuple[bytes, tuple[int, ...]]:
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(file_fd)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _require_local_filesystem(file_fd) != expected_filesystem_type
            or _descriptor_has_acl(file_fd)
            or opened.st_size > _MAX_BOOTSTRAP_FILE_BYTES
        ):
            raise RuntimeError("repository_io_policy_bootstrap_source_untrusted")
        data = _read_all(file_fd, opened.st_size)
    finally:
        os.close(file_fd)
    after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if _identity(before) != _identity(opened) or _identity(opened) != _identity(after):
        raise RuntimeError("repository_io_policy_bootstrap_source_changed")
    return data, _identity(opened)


def _open_source_anchor_chain(
    flags: int,
) -> tuple[dict[Path, int], dict[Path, tuple[int, ...]], str]:
    fds: dict[Path, int] = {}
    identities: dict[Path, tuple[int, ...]] = {}
    try:
        root_before = os.stat(REPO_ROOT, follow_symlinks=False)
        root_fd = os.open(REPO_ROOT, flags)
        root_opened = os.fstat(root_fd)
        root_after = os.stat(REPO_ROOT, follow_symlinks=False)
        root_filesystem_type = _require_local_filesystem(root_fd)
        if (
            _identity(root_before) != _identity(root_opened)
            or _identity(root_opened) != _identity(root_after)
            or not stat.S_ISDIR(root_opened.st_mode)
            or root_opened.st_uid != os.geteuid()
            or root_opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _descriptor_has_acl(root_fd)
        ):
            os.close(root_fd)
            raise RuntimeError("repository_io_policy_source_anchor_invalid")
        fds[REPO_ROOT] = root_fd
        identities[REPO_ROOT] = _identity(root_opened)
        root_device = root_opened.st_dev
        parent_fd = root_fd
        current_path = REPO_ROOT
        for component in _SOURCE_CHAIN_COMPONENTS:
            before = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            child_fd = os.open(component, flags, dir_fd=parent_fd)
            opened = os.fstat(child_fd)
            after = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            if (
                _identity(before) != _identity(opened)
                or _identity(opened) != _identity(after)
                or not stat.S_ISDIR(opened.st_mode)
                or opened.st_uid != os.geteuid()
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or _require_local_filesystem(child_fd) != root_filesystem_type
                or _descriptor_has_acl(child_fd)
                or opened.st_dev != root_device
            ):
                os.close(child_fd)
                raise RuntimeError("repository_io_policy_source_anchor_invalid")
            current_path = current_path / component
            fds[current_path] = child_fd
            identities[current_path] = _identity(opened)
            parent_fd = child_fd
        return fds, identities, root_filesystem_type
    except BaseException:
        for opened_fd in fds.values():
            os.close(opened_fd)
        raise


def _capture_policy_sources():
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    chain_fds, anchors, filesystem_type = _open_source_anchor_chain(flags)
    directory_fd = chain_fds.pop(POLICY_DIR)
    anchor_fds = chain_fds
    try:
        directory_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(directory_stat.st_mode)
            or directory_stat.st_uid != os.geteuid()
            or directory_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _descriptor_has_acl(directory_fd)
        ):
            raise RuntimeError("repository_io_policy_bootstrap_directory_untrusted")
        if set(os.listdir(directory_fd)) != set(_BOOTSTRAP_RUNTIME_NAMES):
            raise RuntimeError("repository_io_policy_bootstrap_inventory_invalid")
        payloads: dict[str, bytes] = {}
        records: dict[str, tuple[tuple[int, ...], str]] = {}
        total = 0
        for name in sorted(_BOOTSTRAP_RUNTIME_NAMES):
            data, identity = _open_source_file(
                directory_fd,
                name,
                filesystem_type,
            )
            total += len(data)
            if total > _MAX_BOOTSTRAP_TOTAL_BYTES:
                raise RuntimeError("repository_io_policy_bootstrap_budget_exceeded")
            digest = hashlib.sha256(data).hexdigest()
            expected = _REVIEWED_SOURCE_SHA256[name]
            if digest != expected:
                raise RuntimeError("repository_io_policy_bootstrap_hash_mismatch")
            payloads[name] = data
            records[name] = (identity, digest)
        if set(os.listdir(directory_fd)) != set(_BOOTSTRAP_RUNTIME_NAMES):
            raise RuntimeError("repository_io_policy_bootstrap_inventory_changed")

        if anchors[POLICY_DIR] != _identity(directory_stat):
            raise RuntimeError("repository_io_policy_source_anchor_changed")
        return (
            directory_fd,
            _identity(directory_stat),
            records,
            payloads,
            anchors,
            anchor_fds,
            filesystem_type,
        )
    except BaseException:
        for anchor_fd in anchor_fds.values():
            os.close(anchor_fd)
        os.close(directory_fd)
        raise


def _revalidate_source_snapshot() -> None:
    root_identity = _SOURCE_ANCHORS[REPO_ROOT]
    if (
        _identity(os.stat(REPO_ROOT, follow_symlinks=False)) != root_identity
        or _identity(os.fstat(_SOURCE_ANCHOR_FDS[REPO_ROOT])) != root_identity
        or _require_local_filesystem(_SOURCE_ANCHOR_FDS[REPO_ROOT])
        != _SOURCE_FILESYSTEM_TYPE
        or _descriptor_has_acl(_SOURCE_ANCHOR_FDS[REPO_ROOT])
    ):
        raise RuntimeError("repository_io_policy_source_anchor_changed")
    parent_fd = _SOURCE_ANCHOR_FDS[REPO_ROOT]
    current_path = REPO_ROOT
    for component in _SOURCE_CHAIN_COMPONENTS:
        current_path = current_path / component
        expected_identity = _SOURCE_ANCHORS[current_path]
        current_fd = (
            _SOURCE_DIRECTORY_FD
            if current_path == POLICY_DIR
            else _SOURCE_ANCHOR_FDS[current_path]
        )
        if (
            _identity(
                os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            )
            != expected_identity
            or _identity(os.fstat(current_fd)) != expected_identity
            or _identity(os.stat(current_path, follow_symlinks=False))
            != expected_identity
            or _require_local_filesystem(current_fd) != _SOURCE_FILESYSTEM_TYPE
            or _descriptor_has_acl(current_fd)
        ):
            raise RuntimeError("repository_io_policy_source_anchor_changed")
        parent_fd = current_fd
    if _identity(os.fstat(_SOURCE_DIRECTORY_FD)) != _SOURCE_DIRECTORY_IDENTITY:
        raise RuntimeError("repository_io_policy_source_directory_changed")
    if set(os.listdir(_SOURCE_DIRECTORY_FD)) != set(_BOOTSTRAP_RUNTIME_NAMES):
        raise RuntimeError("repository_io_policy_source_inventory_changed")
    for name, (expected_identity, expected_digest) in _SOURCE_RECORDS.items():
        data, identity = _open_source_file(
            _SOURCE_DIRECTORY_FD,
            name,
            _SOURCE_FILESYSTEM_TYPE,
        )
        if identity != expected_identity or hashlib.sha256(data).hexdigest() != expected_digest:
            raise RuntimeError("repository_io_policy_source_changed")


(
    _SOURCE_DIRECTORY_FD,
    _SOURCE_DIRECTORY_IDENTITY,
    _SOURCE_RECORDS,
    _SOURCE_PAYLOADS,
    _SOURCE_ANCHORS,
    _SOURCE_ANCHOR_FDS,
    _SOURCE_FILESYSTEM_TYPE,
) = _capture_policy_sources()


class _HeldSourceLoader(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    """Load exact local modules from descriptor-held bytes, never a pathname."""

    def __init__(self, payloads: dict[str, bytes]) -> None:
        self._payloads = {
            Path(filename).stem: (filename, payload)
            for filename, payload in payloads.items()
        }

    def find_spec(self, fullname: str, path=None, target=None):
        if fullname not in self._payloads:
            return None
        filename, _payload = self._payloads[fullname]
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=str(POLICY_DIR / filename),
        )

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        filename, payload = self._payloads[module.__name__]
        origin = str(POLICY_DIR / filename)
        module.__file__ = origin
        code = compile(payload, origin, "exec", dont_inherit=True, optimize=0)
        exec(code, module.__dict__)

_LOCAL_MODULE_NAMES = {Path(name).stem for name in _BOOTSTRAP_RUNTIME_NAMES}
for _module_name in _LOCAL_MODULE_NAMES:
    sys.modules.pop(_module_name, None)
while str(POLICY_DIR) in sys.path:
    sys.path.remove(str(POLICY_DIR))
_HELD_SOURCE_LOADER = _HeldSourceLoader(
    {
        name: _SOURCE_PAYLOADS[name]
        for name in _EXECUTED_SOURCE_NAMES
    }
)
sys.meta_path.insert(0, _HELD_SOURCE_LOADER)

import repository_io_policy as _policy_module  # noqa: E402

_POLICY_ORIGIN = Path(getattr(_policy_module, "__file__", "")).resolve(strict=True)
if _POLICY_ORIGIN != (POLICY_DIR / "repository_io_policy.py").resolve(strict=True):
    raise RuntimeError("repository_io_policy_origin_invalid")
_HELD_LOADED_MODULES: set[str] = set()
for _module_name in _LOCAL_MODULE_NAMES:
    _loaded = sys.modules.get(_module_name)
    if _loaded is None:
        continue
    if getattr(_loaded, "__loader__", None) is not _HELD_SOURCE_LOADER:
        raise RuntimeError("repository_io_policy_helper_origin_invalid")
    _HELD_LOADED_MODULES.add(_module_name)
if _HELD_LOADED_MODULES != {
    Path(name).stem for name in _EXECUTED_SOURCE_NAMES
}:
    raise RuntimeError("repository_io_policy_bootstrap_pin_registry_incomplete")
sys.meta_path.remove(_HELD_SOURCE_LOADER)
while str(POLICY_DIR) in sys.path:
    sys.path.remove(str(POLICY_DIR))

scan_runtime_parity = _policy_module.scan_runtime_parity
scan_captured_runtime_parity = _policy_module.scan_captured_runtime_parity
scan_authoritative_target = _policy_module.scan_authoritative_target
scan_tree = _policy_module.scan_tree
_CAPTURED_RUNTIME_SHA256 = {
    f"scripts/{name}": digest
    for name, (_identity_value, digest) in _SOURCE_RECORDS.items()
}

_BOOTSTRAP_CLOSED = False


def _close_bootstrap() -> None:
    global _BOOTSTRAP_CLOSED
    if _BOOTSTRAP_CLOSED:
        return
    _BOOTSTRAP_CLOSED = True
    for module_name in _HELD_LOADED_MODULES:
        loaded = sys.modules.get(module_name)
        if getattr(loaded, "__loader__", None) is _HELD_SOURCE_LOADER:
            sys.modules.pop(module_name, None)
    os.close(_SOURCE_DIRECTORY_FD)
    for anchor_fd in _SOURCE_ANCHOR_FDS.values():
        os.close(anchor_fd)
    _SOURCE_PAYLOADS.clear()
    _HELD_SOURCE_LOADER._payloads.clear()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument(
        "--layout",
        choices=sorted(_policy_module.LAYOUT_EXPECTATIONS),
        default=_policy_module.LAYOUT_AUTO,
    )
    parser.add_argument(
        "--target-data-only",
        action="store_true",
        help=(
            "Compare a pair-bound target as data without scanning or executing "
            "target-owned controller modules."
        ),
    )
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    target_root = Path(args.root)
    try:
        # The checker imported above is always the pinned private snapshot of
        # the source-owned implementation.  Never execute or import a target
        # package's self-checker or pin map.
        target_findings = scan_authoritative_target(
            target_root,
            _CAPTURED_RUNTIME_SHA256,
            target_layout=args.layout,
        )
        findings = sorted(
            set(
                target_findings
                if args.target_data_only
                else scan_tree(
                    REPO_ROOT,
                    layout=_policy_module.LAYOUT_REPOSITORY_PLUGIN,
                )
                + target_findings
            )
        )
        try:
            _revalidate_source_snapshot()
        except (OSError, RuntimeError, TypeError, ValueError):
            findings.append(
                _policy_module.PolicyFinding(
                    "scripts", 1, "trusted_policy_source_changed"
                )
            )
            findings = sorted(set(findings))
    finally:
        _close_bootstrap()
    if findings:
        print("repository_io_policy=failed")
        for finding in findings:
            print(f"finding={finding.render()}")
        return 1
    layout_bound = "false" if args.layout == _policy_module.LAYOUT_AUTO else "true"
    print(
        "repository_io_policy=passed external_attestation=false "
        f"layout_bound={layout_bound} layout={args.layout}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
