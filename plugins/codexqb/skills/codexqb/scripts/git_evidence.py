#!/usr/bin/env python3
"""No-exec Git workspace evidence for CodexQB.

This module deliberately avoids porcelain commands and every Git operation
that can invoke repository-controlled diff drivers, text converters, clean
filters, hooks, or file-system monitors.  Git is used only to read immutable
index/tree metadata and path names.  Worktree blob identities are computed
from descriptor-bound raw bytes by :mod:`repository_evidence`.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from functools import partial
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from repository_evidence import (
    RepositoryRootAnchor,
    normalize_repo_relative_path,
    open_repository_root_anchor,
    require_descriptor_on_repository_mount,
    require_same_repository_mount,
    revalidate_repository_root_anchor,
    snapshot_git_paths_from_anchor,
    snapshot_repository_inventory_from_anchor,
)


GIT_EVIDENCE_SCHEMA_VERSION = 1
GIT_COMMAND_TIMEOUT_SECONDS = 60
MAX_GIT_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
GIT_OUTPUT_CHUNK_BYTES = 64 * 1024
MAX_GIT_METADATA_TEXT_BYTES = 1024 * 1024
MAX_GIT_POINTER_BYTES = 4096
MAX_GIT_METADATA_TREE_PATHS = 100_000
MAX_GIT_EXCLUSION_PATHS = 4096
GIT_METADATA_SNAPSHOT_TIMEOUT_SECONDS = 60.0
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()

GIT_COMMAND_PREFIX = (
    "git",
    "--no-pager",
    "--no-replace-objects",
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.ignorestat=false",
    "-c",
    "core.untrackedCache=false",
)

_ALLOWED_GIT_ARGUMENTS = frozenset(
    {
        ("rev-parse", "--show-object-format"),
        ("rev-parse", "--show-toplevel"),
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        ("rev-parse", "--verify", "--quiet", "HEAD"),
        ("ls-files", "--stage", "-z"),
        ("ls-tree", "-r", "-z", "--full-tree", "HEAD"),
    }
)
_INDEX_MODES = frozenset({"100644", "100755", "120000", "160000"})
_OBJECT_FORMAT_LENGTHS = {"sha1": 40, "sha256": 64}
_HEX_RE = re.compile(r"[0-9a-f]+")
_DANGEROUS_CONFIG_NEEDLES = (
    b"[include]",
    b"[includeif",
    b"excludesfile=",
    b"attributesfile=",
    b"fsmonitor=",
    b"hookspath=",
    b"sshcommand=",
    b"textconv=",
    b"external=",
    b"clean=",
    b"smudge=",
    b"process=",
    b"helper=",
)


def _require_workspace_descriptor_authority(
    validator: Callable[[int, str], bool] | None,
    descriptor: int,
    path: str,
) -> None:
    if validator is None:
        return
    try:
        accepted = validator(descriptor, path)
    except Exception:
        raise ValueError("git_evidence_descriptor_authority_rejected") from None
    if accepted is not True:
        raise ValueError("git_evidence_descriptor_authority_rejected")


@dataclass(frozen=True)
class _GitProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _IndexEntry:
    mode: str
    oid: str
    stage: int


@dataclass(frozen=True)
class _TreeEntry:
    mode: str
    object_type: str
    oid: str


@dataclass(frozen=True)
class _PlumbingSnapshot:
    object_format: str
    branch: str
    head: str
    index_raw: bytes
    tree_raw: bytes
    untracked_raw: bytes


@dataclass(frozen=True)
class _GitMarkerAnchor:
    fd: int
    metadata: os.stat_result
    is_directory: bool


@dataclass(frozen=True)
class _HeldDirectoryChain:
    path: str
    fds: tuple[int, ...]
    links: tuple[tuple[int, str, int, os.stat_result], ...]

    @property
    def fd(self) -> int:
        return self.fds[-1]


@dataclass(frozen=True)
class _HeldMetadataEntry:
    parent_fd: int
    name: str
    fd: int
    metadata: os.stat_result
    is_directory: bool
    label: str


@dataclass(frozen=True)
class _AbsentMetadataEntry:
    parent_fd: int
    name: str
    label: str


@dataclass(frozen=True)
class _GitMetadataAuthority:
    git_dir_path: str
    common_dir_path: str
    git_dir_fd: int
    common_dir_fd: int
    objects_fd: int
    refs_fd: int
    index_fd: int | None
    runtime_git_dir: str
    refs_snapshot: tuple[tuple[str, bytes, int, bool], ...]
    entries: tuple[_HeldMetadataEntry, ...]
    absent_entries: tuple[_AbsentMetadataEntry, ...]
    chains: tuple[_HeldDirectoryChain, ...]

    @property
    def pass_fds(self) -> tuple[int, ...]:
        values = {
            self.git_dir_fd,
            self.common_dir_fd,
            self.objects_fd,
            self.refs_fd,
            *(entry.fd for entry in self.entries),
        }
        if self.index_fd is not None:
            values.add(self.index_fd)
        return tuple(sorted(values))


def git_subprocess_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    """Return a fixed child environment with no inherited executable state."""

    # ``source`` remains an injectable test seam, but no caller-controlled key
    # is inherited.  In particular, loader, interpreter, shell, HOME/XDG, and
    # Git config variables must not cross into the trusted Git subprocess.
    del source
    return {
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


def trusted_git_executable() -> str:
    """Resolve Git only from the platform's fixed system search path."""

    candidate = shutil.which("git", path=os.defpath)
    if candidate is None or not os.path.isabs(candidate):
        raise ValueError("trusted_git_executable_unavailable")
    try:
        resolved = Path(candidate).resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValueError("trusted_git_executable_unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("trusted_git_executable_unavailable")
    return resolved.as_posix()


def _normalize_git_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    if isinstance(arguments, (str, bytes, bytearray)) or not isinstance(arguments, Sequence):
        raise TypeError("git_evidence_arguments_must_be_sequence")
    normalized = tuple(arguments)
    if (
        normalized not in _ALLOWED_GIT_ARGUMENTS
        or any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in normalized)
    ):
        raise ValueError("git_evidence_command_not_allowed")
    return normalized


def git_command(arguments: Sequence[str]) -> list[str]:
    """Build one command from the fixed no-exec allowlist."""

    normalized = _normalize_git_arguments(arguments)
    return [trusted_git_executable(), *GIT_COMMAND_PREFIX[1:], *normalized]


def _enter_anchored_root(root_fd: int) -> None:
    """Enter the held worktree root without resolving its namespace path."""

    os.fchdir(root_fd)
    os.close(root_fd)


def _revalidate_git_anchor(anchor: RepositoryRootAnchor) -> None:
    try:
        revalidate_repository_root_anchor(anchor)
    except (TypeError, ValueError) as exc:
        raise ValueError("git_evidence_root_identity_changed") from exc


def _terminate_git_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            if process.poll() is None:
                process.kill()
        except OSError:
            pass


def _finalize_git_process(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector | None,
    *,
    operation: str,
) -> None:
    """Kill the whole process group, synchronously reap, and close every pipe."""

    reap_failure: BaseException | None = None
    try:
        _terminate_git_process_group(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_git_process_group(process)
            try:
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired) as exc:
                reap_failure = exc
        except OSError as exc:
            reap_failure = exc
    finally:
        if selector is not None:
            try:
                selector.close()
            except Exception:
                pass
        for pipe in (process.stdout, process.stderr):
            if pipe is None:
                continue
            try:
                pipe.close()
            except Exception:
                pass
    if reap_failure is not None:
        raise ValueError(f"git_evidence_command_unavailable={operation}") from reap_failure


def _run_git_process_from_anchor(
    anchor: RepositoryRootAnchor,
    arguments: Sequence[str],
    *,
    operation: str,
    allowed_returncodes: tuple[int, ...] = (0,),
    authority: _GitMetadataAuthority,
) -> _GitProcessResult:
    _revalidate_git_anchor(anchor)
    _revalidate_git_metadata_authority(anchor, authority)
    command = git_command(arguments)
    if os.name != "posix":
        raise ValueError("git_evidence_process_isolation_not_supported")
    if threading.active_count() != 1:
        raise ValueError("git_evidence_preexec_requires_single_thread")
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    stderr = bytearray()
    total = 0
    output_limit_exceeded = False
    timed_out = False
    environment = git_subprocess_environment()
    environment.update(
        {
            "GIT_COMMON_DIR": authority.runtime_git_dir,
            "GIT_DIR": authority.runtime_git_dir,
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_OBJECT_DIRECTORY": os.path.join(
                authority.runtime_git_dir,
                "objects",
            ),
            "GIT_WORK_TREE": os.fspath(anchor.path),
        }
    )
    if authority.index_fd is not None:
        environment["GIT_INDEX_FILE"] = os.path.join(
            authority.runtime_git_dir,
            "index",
        )
    try:
        try:
            process = subprocess.Popen(
                command,
                cwd=None,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                pass_fds=(anchor.fd,),
                preexec_fn=partial(_enter_anchored_root, anchor.fd),
                start_new_session=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise ValueError(f"git_evidence_command_unavailable={operation}") from exc
        deadline = time.monotonic() + GIT_COMMAND_TIMEOUT_SECONDS
        _revalidate_git_anchor(anchor)
        _revalidate_git_metadata_authority(anchor, authority)
        if process.stdout is None or process.stderr is None:
            raise ValueError(f"git_evidence_command_unavailable={operation}")
        selector = selectors.DefaultSelector()
        streams = {
            process.stdout.fileno(): stdout,
            process.stderr.fileno(): stderr,
        }
        for pipe in (process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(0.1, remaining)):
                fd = key.fileobj.fileno()
                try:
                    chunk = os.read(
                        fd,
                        min(
                            GIT_OUTPUT_CHUNK_BYTES,
                            MAX_GIT_COMMAND_OUTPUT_BYTES - total + 1,
                        ),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                streams[fd].extend(chunk)
                total += len(chunk)
                if total > MAX_GIT_COMMAND_OUTPUT_BYTES:
                    output_limit_exceeded = True
                    break
            if output_limit_exceeded:
                break
        if not timed_out and not output_limit_exceeded:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True

        if output_limit_exceeded:
            raise ValueError(f"git_evidence_output_limit_exceeded={operation}")
        if timed_out:
            raise ValueError(f"git_evidence_command_unavailable={operation}")
        _revalidate_git_anchor(anchor)
        returncode = int(process.returncode if process.returncode is not None else -1)
        if returncode not in allowed_returncodes:
            raise ValueError(f"git_evidence_command_failed={operation}")
        return _GitProcessResult(returncode, bytes(stdout), bytes(stderr))
    except OSError as exc:
        raise ValueError(f"git_evidence_command_unavailable={operation}") from exc
    finally:
        if process is not None:
            _finalize_git_process(process, selector, operation=operation)


def _run_git_process(
    root: str | os.PathLike[str] | RepositoryRootAnchor,
    arguments: Sequence[str],
    *,
    operation: str,
    allowed_returncodes: tuple[int, ...] = (0,),
    authority: _GitMetadataAuthority | None = None,
) -> _GitProcessResult:
    if isinstance(root, RepositoryRootAnchor):
        if authority is None:
            with _open_git_authority(root) as authority_pair:
                if authority_pair is None:
                    raise ValueError("git_evidence_repository_probe_failed")
                _marker, opened_authority = authority_pair
                return _run_git_process_from_anchor(
                    root,
                    arguments,
                    operation=operation,
                    allowed_returncodes=allowed_returncodes,
                    authority=opened_authority,
                )
        return _run_git_process_from_anchor(
            root,
            arguments,
            operation=operation,
            allowed_returncodes=allowed_returncodes,
            authority=authority,
        )
    try:
        with open_repository_root_anchor(root) as anchor:
            return _run_git_process(
                anchor,
                arguments,
                operation=operation,
                allowed_returncodes=allowed_returncodes,
                authority=authority,
            )
    except TypeError as exc:
        raise TypeError("git_evidence_root_must_be_path") from exc
    except ValueError as exc:
        if str(exc) == "repository_root_must_be_real_directory":
            raise ValueError("git_evidence_root_must_be_real_directory") from exc
        raise


def run_git_bytes(
    root: str | os.PathLike[str] | RepositoryRootAnchor,
    arguments: Sequence[str],
    *,
    operation: str = "allowed_git_query",
    allowed_returncodes: tuple[int, ...] = (0,),
    _authority: _GitMetadataAuthority | None = None,
) -> bytes:
    """Run one allowlisted Git query and return its byte-exact stdout."""

    return _run_git_process(
        root,
        arguments,
        operation=operation,
        allowed_returncodes=allowed_returncodes,
        authority=_authority,
    ).stdout


def git_optional_text(
    root: str | os.PathLike[str] | RepositoryRootAnchor,
    arguments: Sequence[str],
    *,
    _authority: _GitMetadataAuthority | None = None,
) -> str | None:
    """Read one optional single-line value through the same strict allowlist."""

    result = _run_git_process(
        root,
        arguments,
        operation="optional_text",
        allowed_returncodes=(0, 1),
        authority=_authority,
    )
    if result.returncode == 1:
        if result.stdout:
            raise ValueError("git_evidence_invalid_optional_text")
        return None
    return _decode_single_line(result.stdout, "optional_text")


def _decode_single_line(raw: bytes, label: str) -> str:
    value = raw[:-1] if raw.endswith(b"\n") else raw
    if not value or b"\x00" in value or b"\n" in value or b"\r" in value:
        raise ValueError(f"git_evidence_invalid_{label}")
    return os.fsdecode(value)


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _stable_metadata(metadata: os.stat_result) -> tuple[int, ...]:
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
    """Return true for any ACL; fail closed when the ACL state is unknown."""

    try:
        names = os.listxattr(descriptor)
    except AttributeError:
        if sys.platform != "darwin":
            raise ValueError("git_evidence_acl_probe_unavailable") from None
        names = []
    except OSError as exc:
        unsupported = {errno.ENOTSUP}
        if hasattr(errno, "EOPNOTSUPP"):
            unsupported.add(errno.EOPNOTSUPP)
        if exc.errno not in unsupported or sys.platform != "darwin":
            raise ValueError("git_evidence_acl_probe_failed") from None
        names = []
    for name in names:
        try:
            normalized = os.fsdecode(name).casefold()
        except (TypeError, UnicodeError):
            return True
        if "acl" in normalized or normalized in {
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
        raise ValueError("git_evidence_acl_probe_unavailable")
    getter.argtypes = [ctypes.c_int, ctypes.c_int]
    getter.restype = ctypes.c_void_p
    releaser.argtypes = [ctypes.c_void_p]
    releaser.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = getter(descriptor, 0x00000100)  # ACL_TYPE_EXTENDED
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return False
        raise ValueError("git_evidence_acl_probe_failed")
    if releaser(acl) != 0:
        raise ValueError("git_evidence_acl_probe_failed")
    return True


def _require_trusted_metadata_descriptor(
    anchor: RepositoryRootAnchor,
    descriptor: int,
    metadata: os.stat_result,
    *,
    is_directory: bool,
) -> None:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else anchor.metadata.st_uid
    if (
        anchor.metadata.st_uid != expected_uid
        or metadata.st_uid != expected_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (is_directory and not stat.S_ISDIR(metadata.st_mode))
        or (not is_directory and not stat.S_ISREG(metadata.st_mode))
        or (not is_directory and metadata.st_nlink != 1)
        or _descriptor_has_acl(descriptor)
    ):
        raise ValueError("git_evidence_metadata_untrusted")
    try:
        if is_directory:
            require_same_repository_mount(anchor, descriptor, "git-metadata")
        else:
            require_descriptor_on_repository_mount(
                anchor,
                descriptor,
                "git-metadata",
            )
    except (TypeError, ValueError) as exc:
        raise ValueError("git_evidence_metadata_untrusted") from exc


def _secure_directory_flags() -> int:
    return (
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_NOFOLLOW
        | getattr(os, "O_CLOEXEC", 0)
    )


def _secure_regular_flags() -> int:
    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def _canonical_absolute_path(raw_path: str) -> str:
    if (
        not isinstance(raw_path, str)
        or not raw_path
        or "\x00" in raw_path
        or "\n" in raw_path
        or "\r" in raw_path
        or not os.path.isabs(raw_path)
        or os.path.normpath(raw_path) != raw_path
    ):
        raise ValueError("git_evidence_metadata_path_invalid")
    return raw_path


@contextmanager
def _open_absolute_directory_chain(raw_path: str) -> Iterator[_HeldDirectoryChain]:
    path = _canonical_absolute_path(raw_path)
    components = tuple(component for component in path.split(os.sep) if component)
    fds: list[int] = []
    links: list[tuple[int, str, int, os.stat_result]] = []
    try:
        current_fd = os.open(os.sep, _secure_directory_flags())
        fds.append(current_fd)
        for component in components:
            before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode):
                raise ValueError("git_evidence_metadata_path_invalid")
            child_fd = os.open(component, _secure_directory_flags(), dir_fd=current_fd)
            opened = os.fstat(child_fd)
            if not _same_file_identity(before, opened):
                os.close(child_fd)
                raise ValueError("git_evidence_metadata_path_changed")
            links.append((current_fd, component, child_fd, opened))
            fds.append(child_fd)
            current_fd = child_fd
        if not components:
            links.append((current_fd, ".", current_fd, os.fstat(current_fd)))
        chain = _HeldDirectoryChain(path, tuple(fds), tuple(links))
        _revalidate_directory_chain(chain)
        yield chain
        _revalidate_directory_chain(chain)
    except OSError as exc:
        raise ValueError("git_evidence_metadata_path_invalid") from exc
    finally:
        for descriptor in reversed(fds):
            os.close(descriptor)


def _revalidate_directory_chain(chain: _HeldDirectoryChain) -> None:
    for parent_fd, name, child_fd, expected in chain.links:
        try:
            current_path = (
                os.fstat(child_fd)
                if name == "." and parent_fd == child_fd
                else os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            )
            current_fd = os.fstat(child_fd)
        except OSError as exc:
            raise ValueError("git_evidence_metadata_path_changed") from exc
        if (
            not stat.S_ISDIR(current_path.st_mode)
            or _stable_metadata(current_path) != _stable_metadata(expected)
            or _stable_metadata(current_fd) != _stable_metadata(expected)
        ):
            raise ValueError("git_evidence_metadata_path_changed")


@contextmanager
def _open_metadata_entry(
    anchor: RepositoryRootAnchor,
    parent_fd: int,
    name: str,
    *,
    is_directory: bool,
    label: str,
) -> Iterator[_HeldMetadataEntry]:
    if not name or "/" in name or name in {".", ".."}:
        raise ValueError("git_evidence_metadata_name_invalid")
    descriptor = -1
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        descriptor = os.open(
            name,
            _secure_directory_flags() if is_directory else _secure_regular_flags(),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError("git_evidence_metadata_required_entry_invalid") from exc
    try:
        if (
            not _same_file_identity(before, opened)
            or stat.S_ISDIR(opened.st_mode) != is_directory
            or stat.S_ISREG(opened.st_mode) == is_directory
        ):
            raise ValueError("git_evidence_metadata_required_entry_invalid")
        _require_trusted_metadata_descriptor(
            anchor,
            descriptor,
            opened,
            is_directory=is_directory,
        )
        entry = _HeldMetadataEntry(
            parent_fd,
            name,
            descriptor,
            opened,
            is_directory,
            label,
        )
        _revalidate_metadata_entry(entry)
        yield entry
        _revalidate_metadata_entry(entry)
    finally:
        os.close(descriptor)


def _revalidate_metadata_entry(entry: _HeldMetadataEntry) -> None:
    try:
        current_path = os.stat(
            entry.name,
            dir_fd=entry.parent_fd,
            follow_symlinks=False,
        )
        current_fd = os.fstat(entry.fd)
    except OSError as exc:
        raise ValueError("git_evidence_metadata_changed") from exc
    if (
        _stable_metadata(current_path) != _stable_metadata(entry.metadata)
        or _stable_metadata(current_fd) != _stable_metadata(entry.metadata)
    ):
        raise ValueError("git_evidence_metadata_changed")


def _require_absent_metadata_entry(
    parent_fd: int,
    name: str,
    label: str,
) -> _AbsentMetadataEntry:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return _AbsentMetadataEntry(parent_fd, name, label)
    except OSError as exc:
        raise ValueError("git_evidence_metadata_probe_failed") from exc
    raise ValueError("git_evidence_forbidden_metadata_present")


def _revalidate_absent_metadata_entry(entry: _AbsentMetadataEntry) -> None:
    try:
        os.stat(entry.name, dir_fd=entry.parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("git_evidence_metadata_probe_failed") from exc
    raise ValueError("git_evidence_forbidden_metadata_present")


def _read_metadata_bytes(
    entry: _HeldMetadataEntry,
    *,
    maximum: int = MAX_GIT_METADATA_TEXT_BYTES,
    allow_nul: bool = False,
) -> bytes:
    if entry.is_directory or entry.metadata.st_size > maximum:
        raise ValueError("git_evidence_metadata_payload_invalid")
    try:
        data = os.pread(entry.fd, entry.metadata.st_size + 1, 0)
    except OSError as exc:
        raise ValueError("git_evidence_metadata_payload_invalid") from exc
    _revalidate_metadata_entry(entry)
    if (
        len(data) != entry.metadata.st_size
        or len(data) > maximum
        or (not allow_nul and b"\x00" in data)
    ):
        raise ValueError("git_evidence_metadata_payload_invalid")
    return data


def _pointer_text(data: bytes, *, prefix: bytes = b"") -> str:
    if len(data) > MAX_GIT_POINTER_BYTES or not data.endswith(b"\n"):
        raise ValueError("git_evidence_metadata_pointer_invalid")
    value = data[:-1]
    if not value or b"\n" in value or b"\r" in value or not value.startswith(prefix):
        raise ValueError("git_evidence_metadata_pointer_invalid")
    raw_path = value[len(prefix) :]
    try:
        decoded = os.fsdecode(raw_path)
    except (TypeError, UnicodeError) as exc:
        raise ValueError("git_evidence_metadata_pointer_invalid") from exc
    if not decoded or os.fsencode(decoded) != raw_path:
        raise ValueError("git_evidence_metadata_pointer_invalid")
    return decoded


def _resolved_metadata_path(base: str, pointer: str) -> str:
    candidate = pointer if os.path.isabs(pointer) else os.path.join(base, pointer)
    return _canonical_absolute_path(os.path.normpath(candidate))


def _config_is_safe(data: bytes) -> bool:
    if len(data) > MAX_GIT_METADATA_TEXT_BYTES or b"\x00" in data:
        return False
    compact = b"".join(data.lower().split())
    return not any(needle in compact for needle in _DANGEROUS_CONFIG_NEEDLES)


def _repository_object_format_from_config(data: bytes) -> str:
    """Read only the format extension needed by the private Git snapshot.

    The source config is never copied into the runtime repository.  This tiny
    parser recognizes the active ``core.repositoryFormatVersion`` and
    ``extensions.objectFormat`` assignments, rejects conflicting duplicates,
    and ignores every unrelated setting.  The synthesized runtime config below
    therefore cannot inherit repository-controlled execution behavior.
    """

    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError("git_evidence_unsafe_repository_config") from exc
    section = ""
    values: dict[tuple[str, str], str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("["):
            if not line.endswith("]"):
                raise ValueError("git_evidence_unsafe_repository_config")
            section_text = line[1:-1].strip()
            if not section_text:
                raise ValueError("git_evidence_unsafe_repository_config")
            section = section_text.split(None, 1)[0].casefold()
            continue
        if not section:
            raise ValueError("git_evidence_unsafe_repository_config")
        if "=" in line:
            key_text, value_text = line.split("=", 1)
            key = key_text.strip().casefold()
            value = value_text.strip().casefold()
        else:
            key = line.casefold()
            value = "true"
        if not key:
            raise ValueError("git_evidence_unsafe_repository_config")
        identity = (section, key)
        if identity not in {
            ("core", "repositoryformatversion"),
            ("extensions", "objectformat"),
        }:
            continue
        previous = values.setdefault(identity, value)
        if previous != value:
            raise ValueError("git_evidence_unsafe_repository_config")

    object_format = values.get(("extensions", "objectformat"), "sha1")
    version = values.get(("core", "repositoryformatversion"), "0")
    if object_format == "sha1" and version in {"0", "1"}:
        return "sha1"
    if object_format == "sha256" and version == "1":
        return "sha256"
    raise ValueError("git_evidence_unsupported_object_format")


def _runtime_repository_config(object_format: str) -> bytes:
    if object_format == "sha1":
        version = "0"
        extension = ""
    elif object_format == "sha256":
        version = "1"
        extension = "[extensions]\n\tobjectFormat = sha256\n"
    else:  # pragma: no cover - protected by the strict parser
        raise ValueError("git_evidence_unsupported_object_format")
    return (
        "[core]\n"
        f"\trepositoryFormatVersion = {version}\n"
        "\tbare = false\n"
        f"{extension}"
    ).encode("ascii")


def _entry_if_present(
    stack: ExitStack,
    anchor: RepositoryRootAnchor,
    parent_fd: int,
    name: str,
    *,
    is_directory: bool,
    label: str,
    entries: list[_HeldMetadataEntry],
    absent_entries: list[_AbsentMetadataEntry],
) -> _HeldMetadataEntry | None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        absent = _AbsentMetadataEntry(parent_fd, name, label)
        absent_entries.append(absent)
        return None
    except OSError as exc:
        raise ValueError("git_evidence_metadata_probe_failed") from exc
    entry = stack.enter_context(
        _open_metadata_entry(
            anchor,
            parent_fd,
            name,
            is_directory=is_directory,
            label=label,
        )
    )
    entries.append(entry)
    return entry


def _snapshot_refs_tree(
    anchor: RepositoryRootAnchor,
    refs_fd: int,
) -> tuple[tuple[str, bytes, int, bool], ...]:
    records: list[tuple[str, bytes, int, bool]] = []
    path_count = 0
    byte_count = 0
    started = time.monotonic()

    def check_budget() -> None:
        if time.monotonic() - started > GIT_METADATA_SNAPSHOT_TIMEOUT_SECONDS:
            raise ValueError("git_evidence_refs_timeout")
        if path_count > MAX_GIT_METADATA_TREE_PATHS:
            raise ValueError("git_evidence_refs_limit_exceeded")

    def walk(directory_fd: int, prefix: str, depth: int) -> None:
        nonlocal path_count, byte_count
        if depth > 64:
            raise ValueError("git_evidence_refs_depth_exceeded")
        try:
            before_directory = os.fstat(directory_fd)
            with os.scandir(directory_fd) as iterator:
                names: list[str] = []
                for entry in iterator:
                    path_count += 1
                    check_budget()
                    names.append(entry.name)
            after_directory = os.fstat(directory_fd)
        except OSError as exc:
            raise ValueError("git_evidence_refs_snapshot_failed") from exc
        if _stable_metadata(before_directory) != _stable_metadata(after_directory):
            raise ValueError("git_evidence_refs_changed")
        for name in sorted(names):
            check_budget()
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError("git_evidence_refs_snapshot_failed")
            relative = f"{prefix}/{name}" if prefix else name
            try:
                before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except OSError as exc:
                raise ValueError("git_evidence_refs_changed") from exc
            if stat.S_ISDIR(before.st_mode):
                child_fd = -1
                try:
                    child_fd = os.open(
                        name,
                        _secure_directory_flags(),
                        dir_fd=directory_fd,
                    )
                    opened = os.fstat(child_fd)
                    if not _same_file_identity(before, opened):
                        raise ValueError("git_evidence_refs_changed")
                    _require_trusted_metadata_descriptor(
                        anchor,
                        child_fd,
                        opened,
                        is_directory=True,
                    )
                    records.append((relative, b"", stat.S_IMODE(opened.st_mode), True))
                    walk(child_fd, relative, depth + 1)
                    current = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if _stable_metadata(opened) != _stable_metadata(current):
                        raise ValueError("git_evidence_refs_changed")
                finally:
                    if child_fd >= 0:
                        os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_GIT_POINTER_BYTES:
                raise ValueError("git_evidence_refs_snapshot_failed")
            file_fd = -1
            try:
                file_fd = os.open(
                    name,
                    _secure_regular_flags(),
                    dir_fd=directory_fd,
                )
                opened = os.fstat(file_fd)
                if not _same_file_identity(before, opened):
                    raise ValueError("git_evidence_refs_changed")
                _require_trusted_metadata_descriptor(
                    anchor,
                    file_fd,
                    opened,
                    is_directory=False,
                )
                data = os.pread(file_fd, opened.st_size + 1, 0)
                current_fd = os.fstat(file_fd)
                current_path = os.stat(
                    name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
            finally:
                if file_fd >= 0:
                    os.close(file_fd)
            if (
                len(data) != opened.st_size
                or b"\x00" in data
                or _stable_metadata(opened) != _stable_metadata(current_fd)
                or _stable_metadata(opened) != _stable_metadata(current_path)
            ):
                raise ValueError("git_evidence_refs_changed")
            byte_count += len(data)
            if byte_count > 16 * 1024 * 1024:
                raise ValueError("git_evidence_refs_limit_exceeded")
            records.append((relative, data, stat.S_IMODE(opened.st_mode), False))
        if _stable_metadata(before_directory) != _stable_metadata(os.fstat(directory_fd)):
            raise ValueError("git_evidence_refs_changed")

    walk(refs_fd, "", 0)
    return tuple(records)


def _write_private_file(root_fd: int, relative: str, data: bytes) -> None:
    parts = relative.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("git_evidence_runtime_snapshot_invalid")
    current_fd = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            try:
                os.mkdir(part, 0o700, dir_fd=current_fd)
            except FileExistsError:
                pass
            child_fd = os.open(part, _secure_directory_flags(), dir_fd=current_fd)
            child = os.fstat(child_fd)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else child.st_uid
            if (
                not stat.S_ISDIR(child.st_mode)
                or child.st_uid != expected_uid
                or stat.S_IMODE(child.st_mode) != 0o700
                or _descriptor_has_acl(child_fd)
            ):
                os.close(child_fd)
                raise ValueError("git_evidence_runtime_snapshot_invalid")
            os.close(current_fd)
            current_fd = child_fd
        descriptor = os.open(
            parts[-1],
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=current_fd,
        )
        try:
            view = memoryview(data)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise ValueError("git_evidence_runtime_snapshot_invalid")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(current_fd)
    except OSError as exc:
        raise ValueError("git_evidence_runtime_snapshot_invalid") from exc
    finally:
        os.close(current_fd)


def _populate_runtime_git_dir(
    runtime_git_dir: str,
    *,
    anchor: RepositoryRootAnchor,
    objects_fd: int,
    head_data: bytes,
    index_data: bytes | None,
    refs_snapshot: tuple[tuple[str, bytes, int, bool], ...],
    packed_refs_data: bytes | None,
    shallow_data: bytes | None,
    object_format: str,
) -> None:
    root_fd = os.open(runtime_git_dir, _secure_directory_flags())
    try:
        metadata = os.fstat(root_fd)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        if (
            metadata.st_uid != expected_uid
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _descriptor_has_acl(root_fd)
        ):
            raise ValueError("git_evidence_runtime_snapshot_invalid")
        _write_private_file(root_fd, "HEAD", head_data)
        _write_private_file(
            root_fd,
            "config",
            _runtime_repository_config(object_format),
        )
        os.mkdir("refs", 0o700, dir_fd=root_fd)
        os.mkdir("objects", 0o700, dir_fd=root_fd)
        runtime_objects_fd = os.open(
            "objects",
            _secure_directory_flags(),
            dir_fd=root_fd,
        )
        try:
            _copy_objects_tree(anchor, objects_fd, runtime_objects_fd)
        finally:
            os.close(runtime_objects_fd)
        if index_data is not None:
            _write_private_file(root_fd, "index", index_data)
        for relative, data, _mode, is_directory in refs_snapshot:
            if not is_directory:
                _write_private_file(root_fd, f"refs/{relative}", data)
        if packed_refs_data is not None:
            _write_private_file(root_fd, "packed-refs", packed_refs_data)
        if shallow_data is not None:
            _write_private_file(root_fd, "shallow", shallow_data)
        os.fsync(root_fd)
    finally:
        os.close(root_fd)


def _copy_objects_tree(
    anchor: RepositoryRootAnchor,
    source_root_fd: int,
    target_root_fd: int,
) -> None:
    """Snapshot object bytes from held descriptors into controller-private storage."""

    started = time.monotonic()
    path_count = 0
    byte_count = 0

    def check_budget() -> None:
        if time.monotonic() - started > GIT_METADATA_SNAPSHOT_TIMEOUT_SECONDS:
            raise ValueError("git_evidence_objects_timeout")
        if path_count > MAX_GIT_METADATA_TREE_PATHS:
            raise ValueError("git_evidence_objects_path_limit")
        if byte_count > 512 * 1024 * 1024:
            raise ValueError("git_evidence_objects_byte_limit")

    def walk(source_fd: int, target_fd: int, depth: int) -> None:
        nonlocal path_count, byte_count
        if depth > 8:
            raise ValueError("git_evidence_objects_depth_exceeded")
        check_budget()
        source_directory_before = os.fstat(source_fd)
        try:
            with os.scandir(source_fd) as iterator:
                names: list[str] = []
                for entry in iterator:
                    path_count += 1
                    check_budget()
                    names.append(entry.name)
        except OSError as exc:
            raise ValueError("git_evidence_objects_snapshot_failed") from exc
        source_directory_after = os.fstat(source_fd)
        if _stable_metadata(source_directory_before) != _stable_metadata(
            source_directory_after
        ):
            raise ValueError("git_evidence_objects_changed")
        for name in sorted(names):
            check_budget()
            if not name or name in {".", ".."} or "/" in name or "\x00" in name:
                raise ValueError("git_evidence_objects_snapshot_failed")
            before = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            if stat.S_ISDIR(before.st_mode):
                source_child = -1
                target_child = -1
                try:
                    source_child = os.open(
                        name,
                        _secure_directory_flags(),
                        dir_fd=source_fd,
                    )
                    opened = os.fstat(source_child)
                    if not _same_file_identity(before, opened):
                        raise ValueError("git_evidence_objects_changed")
                    _require_trusted_metadata_descriptor(
                        anchor,
                        source_child,
                        opened,
                        is_directory=True,
                    )
                    os.mkdir(name, 0o700, dir_fd=target_fd)
                    target_child = os.open(
                        name,
                        _secure_directory_flags(),
                        dir_fd=target_fd,
                    )
                    # Object-info acceleration and alternate metadata are not
                    # authority inputs.  Keep an empty private info directory.
                    if name != "info" or depth != 0:
                        walk(source_child, target_child, depth + 1)
                    current_path = os.stat(
                        name,
                        dir_fd=source_fd,
                        follow_symlinks=False,
                    )
                    if _stable_metadata(opened) != _stable_metadata(current_path):
                        raise ValueError("git_evidence_objects_changed")
                finally:
                    if target_child >= 0:
                        os.close(target_child)
                    if source_child >= 0:
                        os.close(source_child)
                continue
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size < 0
                or before.st_size > 512 * 1024 * 1024
            ):
                raise ValueError("git_evidence_objects_snapshot_failed")
            byte_count += before.st_size
            check_budget()
            source_file = -1
            target_file = -1
            try:
                source_file = os.open(
                    name,
                    _secure_regular_flags(),
                    dir_fd=source_fd,
                )
                opened = os.fstat(source_file)
                if not _same_file_identity(before, opened):
                    raise ValueError("git_evidence_objects_changed")
                _require_trusted_metadata_descriptor(
                    anchor,
                    source_file,
                    opened,
                    is_directory=False,
                )
                target_file = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0),
                    0o400,
                    dir_fd=target_fd,
                )
                remaining = opened.st_size
                while remaining:
                    check_budget()
                    chunk = os.read(source_file, min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("git_evidence_objects_changed")
                    view = memoryview(chunk)
                    while view:
                        written = os.write(target_file, view)
                        if written <= 0:
                            raise ValueError("git_evidence_objects_snapshot_failed")
                        view = view[written:]
                    remaining -= len(chunk)
                current_fd = os.fstat(source_file)
                current_path = os.stat(
                    name,
                    dir_fd=source_fd,
                    follow_symlinks=False,
                )
                if (
                    _stable_metadata(opened) != _stable_metadata(current_fd)
                    or _stable_metadata(opened) != _stable_metadata(current_path)
                ):
                    raise ValueError("git_evidence_objects_changed")
            except OSError as exc:
                raise ValueError("git_evidence_objects_snapshot_failed") from exc
            finally:
                if target_file >= 0:
                    os.close(target_file)
                if source_file >= 0:
                    os.close(source_file)
        if _stable_metadata(source_directory_before) != _stable_metadata(
            os.fstat(source_fd)
        ):
            raise ValueError("git_evidence_objects_changed")

    walk(source_root_fd, target_root_fd, 0)


def _required_entry(
    stack: ExitStack,
    anchor: RepositoryRootAnchor,
    parent_fd: int,
    name: str,
    *,
    is_directory: bool,
    label: str,
    entries: list[_HeldMetadataEntry],
) -> _HeldMetadataEntry:
    entry = stack.enter_context(
        _open_metadata_entry(
            anchor,
            parent_fd,
            name,
            is_directory=is_directory,
            label=label,
        )
    )
    entries.append(entry)
    return entry


def _revalidate_git_metadata_authority(
    anchor: RepositoryRootAnchor,
    authority: _GitMetadataAuthority,
) -> None:
    _revalidate_git_anchor(anchor)
    for chain in authority.chains:
        _revalidate_directory_chain(chain)
    for entry in authority.entries:
        _revalidate_metadata_entry(entry)
        _require_trusted_metadata_descriptor(
            anchor,
            entry.fd,
            os.fstat(entry.fd),
            is_directory=entry.is_directory,
        )
    for entry in authority.absent_entries:
        _revalidate_absent_metadata_entry(entry)
    if _snapshot_refs_tree(anchor, authority.refs_fd) != authority.refs_snapshot:
        raise ValueError("git_evidence_refs_changed")
    _revalidate_git_anchor(anchor)


@contextmanager
def _open_git_metadata_authority(
    anchor: RepositoryRootAnchor,
    marker: _GitMarkerAnchor,
) -> Iterator[_GitMetadataAuthority]:
    """Resolve and hold every Git metadata root before invoking Git."""

    entries: list[_HeldMetadataEntry] = []
    absent_entries: list[_AbsentMetadataEntry] = []
    chains: list[_HeldDirectoryChain] = []
    with ExitStack() as stack:
        # Allocate scratch before holding namespace chains.  On Darwin the
        # system temporary directory can be an ancestor of a test/worktree;
        # creating it after the chains are captured would make our own mkdir
        # look like a hostile ancestor mutation.  Register it first so cleanup
        # also happens only after the held chains have completed revalidation.
        runtime_git_dir = stack.enter_context(
            tempfile.TemporaryDirectory(prefix="codexqb-git-evidence-")
        )
        os.chmod(runtime_git_dir, 0o700)
        marker_entry = _HeldMetadataEntry(
            anchor.fd,
            ".git",
            marker.fd,
            marker.metadata,
            marker.is_directory,
            "marker",
        )
        if marker.is_directory:
            git_dir_path = _canonical_absolute_path(
                os.path.join(os.fspath(anchor.path), ".git")
            )
            git_dir_fd = marker.fd
        else:
            pointer = _pointer_text(
                _read_metadata_bytes(marker_entry, maximum=MAX_GIT_POINTER_BYTES),
                prefix=b"gitdir: ",
            )
            git_dir_path = _resolved_metadata_path(os.fspath(anchor.path), pointer)
            git_chain = stack.enter_context(
                _open_absolute_directory_chain(git_dir_path)
            )
            chains.append(git_chain)
            _require_trusted_metadata_descriptor(
                anchor,
                git_chain.fd,
                os.fstat(git_chain.fd),
                is_directory=True,
            )
            git_dir_fd = git_chain.fd

        commondir_entry = _entry_if_present(
            stack,
            anchor,
            git_dir_fd,
            "commondir",
            is_directory=False,
            label="commondir-pointer",
            entries=entries,
            absent_entries=absent_entries,
        )
        if commondir_entry is None:
            if not marker.is_directory:
                raise ValueError("git_evidence_worktree_commondir_required")
            common_dir_path = git_dir_path
            common_dir_fd = git_dir_fd
        else:
            common_pointer = _pointer_text(_read_metadata_bytes(commondir_entry))
            common_dir_path = _resolved_metadata_path(
                git_dir_path,
                common_pointer,
            )
            if common_dir_path == git_dir_path:
                common_dir_fd = git_dir_fd
            else:
                common_chain = stack.enter_context(
                    _open_absolute_directory_chain(common_dir_path)
                )
                chains.append(common_chain)
                _require_trusted_metadata_descriptor(
                    anchor,
                    common_chain.fd,
                    os.fstat(common_chain.fd),
                    is_directory=True,
                )
                common_dir_fd = common_chain.fd

        if not marker.is_directory:
            backlink = _required_entry(
                stack,
                anchor,
                git_dir_fd,
                "gitdir",
                is_directory=False,
                label="worktree-backlink",
                entries=entries,
            )
            backlink_path = _resolved_metadata_path(
                git_dir_path,
                _pointer_text(_read_metadata_bytes(backlink)),
            )
            expected_backlink = _canonical_absolute_path(
                os.path.join(os.fspath(anchor.path), ".git")
            )
            physical_root = _canonical_absolute_path(
                os.path.realpath(os.fspath(anchor.path))
            )
            physical_backlink = _canonical_absolute_path(
                os.path.join(physical_root, ".git")
            )
            expected_git_dir_parent = os.path.join(common_dir_path, "worktrees")
            if (
                backlink_path not in {expected_backlink, physical_backlink}
                or os.path.dirname(git_dir_path) != expected_git_dir_parent
                or not os.path.basename(git_dir_path)
            ):
                raise ValueError("git_evidence_worktree_backlink_invalid")

            # Git canonicalizes platform aliases such as Darwin's
            # ``/var`` -> ``/private/var`` when it records a linked-worktree
            # backlink.  Accept only the caller's exact lexical root or that
            # root's exact physical spelling; arbitrary symlink aliases remain
            # invalid.  When Git used the physical spelling, bind its parent
            # and final marker back to the already-held repository descriptors
            # rather than trusting the spelling alone.
            if backlink_path == physical_backlink and backlink_path != expected_backlink:
                backlink_parent_chain = stack.enter_context(
                    _open_absolute_directory_chain(os.path.dirname(backlink_path))
                )
                chains.append(backlink_parent_chain)
                if not _same_file_identity(
                    os.fstat(backlink_parent_chain.fd),
                    anchor.metadata,
                ):
                    raise ValueError("git_evidence_worktree_backlink_invalid")
                physical_marker = _required_entry(
                    stack,
                    anchor,
                    backlink_parent_chain.fd,
                    os.path.basename(backlink_path),
                    is_directory=False,
                    label="physical-worktree-marker",
                    entries=entries,
                )
                if not _same_file_identity(physical_marker.metadata, marker.metadata):
                    raise ValueError("git_evidence_worktree_backlink_invalid")

        config = _required_entry(
            stack,
            anchor,
            common_dir_fd,
            "config",
            is_directory=False,
            label="config",
            entries=entries,
        )
        config_data = _read_metadata_bytes(config)
        if not _config_is_safe(config_data):
            raise ValueError("git_evidence_unsafe_repository_config")
        object_format = _repository_object_format_from_config(config_data)
        config_worktree = _entry_if_present(
            stack,
            anchor,
            git_dir_fd,
            "config.worktree",
            is_directory=False,
            label="config-worktree",
            entries=entries,
            absent_entries=absent_entries,
        )
        if config_worktree is not None and not _config_is_safe(
            _read_metadata_bytes(config_worktree)
        ):
            raise ValueError("git_evidence_unsafe_repository_config")

        head = _required_entry(
            stack,
            anchor,
            git_dir_fd,
            "HEAD",
            is_directory=False,
            label="head",
            entries=entries,
        )
        head_data = _read_metadata_bytes(head, maximum=MAX_GIT_POINTER_BYTES)
        if len(head_data) > MAX_GIT_POINTER_BYTES:
            raise ValueError("git_evidence_metadata_payload_invalid")
        index = _entry_if_present(
            stack,
            anchor,
            git_dir_fd,
            "index",
            is_directory=False,
            label="index",
            entries=entries,
            absent_entries=absent_entries,
        )
        index_data = (
            _read_metadata_bytes(index, allow_nul=True)
            if index is not None
            else None
        )
        objects = _required_entry(
            stack,
            anchor,
            common_dir_fd,
            "objects",
            is_directory=True,
            label="objects",
            entries=entries,
        )
        refs = _required_entry(
            stack,
            anchor,
            common_dir_fd,
            "refs",
            is_directory=True,
            label="refs",
            entries=entries,
        )
        refs_snapshot = _snapshot_refs_tree(anchor, refs.fd)
        objects_info = _required_entry(
            stack,
            anchor,
            objects.fd,
            "info",
            is_directory=True,
            label="objects-info",
            entries=entries,
        )
        info = _required_entry(
            stack,
            anchor,
            common_dir_fd,
            "info",
            is_directory=True,
            label="info",
            entries=entries,
        )

        for parent_fd, name, label in (
            (objects_info.fd, "alternates", "alternates"),
            (objects_info.fd, "http-alternates", "http-alternates"),
            (info.fd, "grafts", "grafts"),
            (refs.fd, "replace", "replace-refs"),
        ):
            absent_entries.append(
                _require_absent_metadata_entry(parent_fd, name, label)
            )

        _entry_if_present(
            stack,
            anchor,
            info.fd,
            "exclude",
            is_directory=False,
            label="info-exclude",
            entries=entries,
            absent_entries=absent_entries,
        )
        packed_refs = _entry_if_present(
            stack,
            anchor,
            common_dir_fd,
            "packed-refs",
            is_directory=False,
            label="packed-refs",
            entries=entries,
            absent_entries=absent_entries,
        )
        shallow = _entry_if_present(
            stack,
            anchor,
            common_dir_fd,
            "shallow",
            is_directory=False,
            label="shallow",
            entries=entries,
            absent_entries=absent_entries,
        )
        packed_refs_data = (
            _read_metadata_bytes(packed_refs)
            if packed_refs is not None
            else None
        )
        shallow_data = (
            _read_metadata_bytes(shallow)
            if shallow is not None
            else None
        )

        _populate_runtime_git_dir(
            runtime_git_dir,
            anchor=anchor,
            objects_fd=objects.fd,
            head_data=head_data,
            index_data=index_data,
            refs_snapshot=refs_snapshot,
            packed_refs_data=packed_refs_data,
            shallow_data=shallow_data,
            object_format=object_format,
        )

        authority = _GitMetadataAuthority(
            git_dir_path=git_dir_path,
            common_dir_path=common_dir_path,
            git_dir_fd=git_dir_fd,
            common_dir_fd=common_dir_fd,
            objects_fd=objects.fd,
            refs_fd=refs.fd,
            index_fd=index.fd if index is not None else None,
            runtime_git_dir=runtime_git_dir,
            refs_snapshot=refs_snapshot,
            entries=tuple(entries),
            absent_entries=tuple(absent_entries),
            chains=tuple(chains),
        )
        _revalidate_git_metadata_authority(anchor, authority)
        yield authority
        _revalidate_git_metadata_authority(anchor, authority)


@contextmanager
def _open_git_authority(
    anchor: RepositoryRootAnchor,
) -> Iterator[tuple[_GitMarkerAnchor, _GitMetadataAuthority] | None]:
    with _open_local_git_marker(anchor) as marker:
        if marker is None:
            yield None
            return
        with _open_git_metadata_authority(anchor, marker) as metadata:
            yield marker, metadata


def _revalidate_git_marker(
    anchor: RepositoryRootAnchor,
    marker: _GitMarkerAnchor,
) -> None:
    _revalidate_git_anchor(anchor)
    try:
        current_path = os.stat(".git", dir_fd=anchor.fd, follow_symlinks=False)
        current_fd = os.fstat(marker.fd)
    except OSError as exc:
        raise ValueError("git_evidence_repository_marker_changed") from exc
    if (
        _stable_metadata(marker.metadata) != _stable_metadata(current_path)
        or _stable_metadata(marker.metadata) != _stable_metadata(current_fd)
        or stat.S_ISDIR(current_path.st_mode) != marker.is_directory
        or stat.S_ISREG(current_path.st_mode) == marker.is_directory
    ):
        raise ValueError("git_evidence_repository_marker_changed")
    try:
        if marker.is_directory:
            require_same_repository_mount(anchor, marker.fd, ".git")
        else:
            require_descriptor_on_repository_mount(anchor, marker.fd, ".git")
    except (TypeError, ValueError) as exc:
        raise ValueError("git_evidence_repository_marker_changed") from exc
    _revalidate_git_anchor(anchor)


@contextmanager
def _open_local_git_marker(
    anchor: RepositoryRootAnchor,
) -> Iterator[_GitMarkerAnchor | None]:
    """Hold the exact root's local .git marker for the complete capture."""

    _revalidate_git_anchor(anchor)
    try:
        before = os.stat(".git", dir_fd=anchor.fd, follow_symlinks=False)
    except FileNotFoundError:
        _revalidate_git_anchor(anchor)
        yield None
        return
    except OSError as exc:
        raise ValueError("git_evidence_repository_probe_failed") from exc
    is_directory = stat.S_ISDIR(before.st_mode)
    is_regular = stat.S_ISREG(before.st_mode)
    if (
        not (is_directory or is_regular)
        or before.st_uid != anchor.metadata.st_uid
        or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or (is_regular and before.st_nlink != 1)
    ):
        raise ValueError("git_evidence_repository_marker_unsafe")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    if is_directory:
        flags |= os.O_DIRECTORY
    marker_fd = -1
    try:
        marker_fd = os.open(".git", flags, dir_fd=anchor.fd)
        opened = os.fstat(marker_fd)
        if (
            not _same_file_identity(before, opened)
            or stat.S_ISDIR(opened.st_mode) != is_directory
            or stat.S_ISREG(opened.st_mode) != is_regular
        ):
            raise ValueError("git_evidence_repository_marker_changed")
        marker = _GitMarkerAnchor(marker_fd, opened, is_directory)
        _require_trusted_metadata_descriptor(
            anchor,
            marker_fd,
            opened,
            is_directory=is_directory,
        )
        _revalidate_git_marker(anchor, marker)
        yield marker
        _revalidate_git_marker(anchor, marker)
    except OSError as exc:
        raise ValueError("git_evidence_repository_probe_failed") from exc
    finally:
        if marker_fd >= 0:
            os.close(marker_fd)


def _require_exact_git_toplevel(
    anchor: RepositoryRootAnchor,
    marker: _GitMarkerAnchor,
    authority: _GitMetadataAuthority,
) -> None:
    """Bind Git's discovered top-level directory to the held root inode."""

    _revalidate_git_marker(anchor, marker)
    result = _run_git_process(
        anchor,
        ("rev-parse", "--show-toplevel"),
        operation="repository_toplevel_probe",
        authority=authority,
    )
    raw_top_level = _decode_single_line(result.stdout, "repository_toplevel")
    if not os.path.isabs(raw_top_level) or os.path.normpath(raw_top_level) != raw_top_level:
        raise ValueError("git_evidence_repository_toplevel_mismatch")
    try:
        top_level = os.stat(raw_top_level, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("git_evidence_repository_toplevel_mismatch") from exc
    if (
        not stat.S_ISDIR(top_level.st_mode)
        or not _same_file_identity(anchor.metadata, top_level)
    ):
        raise ValueError("git_evidence_repository_toplevel_mismatch")
    _revalidate_git_marker(anchor, marker)


def _probe_object_format(
    anchor: RepositoryRootAnchor,
    authority: _GitMetadataAuthority,
) -> str:
    result = _run_git_process(
        anchor,
        ("rev-parse", "--show-object-format"),
        operation="object_format_probe",
        allowed_returncodes=(0, 128),
        authority=authority,
    )
    if result.returncode != 0:
        raise ValueError("git_evidence_repository_probe_failed")
    object_format = _decode_single_line(result.stdout, "object_format")
    if object_format not in _OBJECT_FORMAT_LENGTHS:
        raise ValueError("git_evidence_unsupported_object_format")
    return object_format


def _validate_oid(value: str, object_format: str, *, allow_zero: bool = False) -> str:
    expected_length = _OBJECT_FORMAT_LENGTHS[object_format]
    if len(value) != expected_length or _HEX_RE.fullmatch(value) is None:
        raise ValueError("git_evidence_invalid_object_id")
    if not allow_zero and set(value) == {"0"}:
        raise ValueError("git_evidence_invalid_object_id")
    return value


def _decode_path(raw: bytes) -> str:
    if not raw or b"\x00" in raw or any(character in raw for character in (b"\t", b"\r", b"\n")):
        raise ValueError("git_evidence_invalid_path")
    decoded = os.fsdecode(raw)
    try:
        normalized = normalize_repo_relative_path(decoded)
    except (TypeError, ValueError) as exc:
        raise ValueError("git_evidence_invalid_path") from exc
    if normalized != decoded or os.fsencode(decoded) != raw:
        raise ValueError("git_evidence_invalid_path")
    return normalized


def _nul_records(raw: bytes, label: str) -> list[bytes]:
    if not raw:
        return []
    if not raw.endswith(b"\x00"):
        raise ValueError(f"git_evidence_invalid_{label}")
    records = raw[:-1].split(b"\x00")
    if any(not record for record in records):
        raise ValueError(f"git_evidence_invalid_{label}")
    return records


def _parse_index(raw: bytes, object_format: str) -> dict[str, tuple[_IndexEntry, ...]]:
    grouped: dict[str, list[_IndexEntry]] = {}
    seen: set[tuple[str, int]] = set()
    for record in _nul_records(raw, "index"):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, oid_raw, stage_raw = metadata.split(b" ")
            mode = mode_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
            stage_text = stage_raw.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("git_evidence_invalid_index") from exc
        if mode not in _INDEX_MODES or stage_text not in {"0", "1", "2", "3"}:
            raise ValueError("git_evidence_invalid_index")
        path = _decode_path(raw_path)
        stage = int(stage_text)
        key = (path, stage)
        if key in seen:
            raise ValueError("git_evidence_invalid_index")
        seen.add(key)
        grouped.setdefault(path, []).append(
            _IndexEntry(mode, _validate_oid(oid, object_format, allow_zero=True), stage)
        )
    return {
        path: tuple(sorted(entries, key=lambda entry: entry.stage))
        for path, entries in sorted(grouped.items())
    }


def _parse_tree(raw: bytes, object_format: str) -> dict[str, _TreeEntry]:
    tree: dict[str, _TreeEntry] = {}
    for record in _nul_records(raw, "tree"):
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode_raw, type_raw, oid_raw = metadata.split(b" ")
            mode = mode_raw.decode("ascii")
            object_type = type_raw.decode("ascii")
            oid = oid_raw.decode("ascii")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("git_evidence_invalid_tree") from exc
        path = _decode_path(raw_path)
        if (
            mode not in _INDEX_MODES
            or object_type not in {"blob", "commit"}
            or (mode == "160000") != (object_type == "commit")
            or path in tree
        ):
            raise ValueError("git_evidence_invalid_tree")
        tree[path] = _TreeEntry(mode, object_type, _validate_oid(oid, object_format))
    return dict(sorted(tree.items()))


def _parse_untracked(raw: bytes) -> list[str]:
    paths = [_decode_path(record) for record in _nul_records(raw, "untracked_paths")]
    if len(paths) != len(set(paths)):
        raise ValueError("git_evidence_invalid_untracked_paths")
    return sorted(paths)


def _capture_plumbing(
    anchor: RepositoryRootAnchor,
    object_format: str,
    authority: _GitMetadataAuthority,
) -> _PlumbingSnapshot:
    branch_result = _run_git_process(
        anchor,
        ("symbolic-ref", "--quiet", "--short", "HEAD"),
        operation="branch",
        allowed_returncodes=(0, 1),
        authority=authority,
    )
    if branch_result.returncode == 0:
        branch = _decode_single_line(branch_result.stdout, "branch")
    elif branch_result.stdout:
        raise ValueError("git_evidence_invalid_branch")
    else:
        branch = "unknown"

    head_result = _run_git_process(
        anchor,
        ("rev-parse", "--verify", "--quiet", "HEAD"),
        operation="head",
        allowed_returncodes=(0, 1),
        authority=authority,
    )
    if head_result.returncode == 0:
        head = _validate_oid(_decode_single_line(head_result.stdout, "head"), object_format)
        tree_raw = run_git_bytes(
            anchor,
            ("ls-tree", "-r", "-z", "--full-tree", "HEAD"),
            operation="head_tree",
            _authority=authority,
        )
    elif head_result.stdout:
        raise ValueError("git_evidence_invalid_head")
    else:
        head = "unknown"
        tree_raw = b""

    return _PlumbingSnapshot(
        object_format=object_format,
        branch=branch,
        head=head,
        index_raw=run_git_bytes(
            anchor,
            ("ls-files", "--stage", "-z"),
            operation="index",
            _authority=authority,
        ),
        tree_raw=tree_raw,
        untracked_raw=b"",
    )


def _normal_index_entry(entries: tuple[_IndexEntry, ...] | None) -> _IndexEntry | None:
    if entries is None or len(entries) != 1 or entries[0].stage != 0:
        return None
    return entries[0]


def _staged_changes(
    index: dict[str, tuple[_IndexEntry, ...]],
    tree: dict[str, _TreeEntry],
) -> list[dict[str, Any]]:
    changes: list[dict[str, Any]] = []
    for path in sorted(set(index) | set(tree)):
        head_entry = tree.get(path)
        index_entries = index.get(path)
        normal = _normal_index_entry(index_entries)
        if index_entries is None:
            changes.append(
                {
                    "path": path,
                    "state": "delete",
                    "head_mode": head_entry.mode if head_entry else None,
                    "head_oid": head_entry.oid if head_entry else None,
                    "index_mode": None,
                    "index_oid": None,
                }
            )
        elif normal is None:
            changes.append(
                {
                    "path": path,
                    "state": "non_normal_index",
                    "head_mode": head_entry.mode if head_entry else None,
                    "head_oid": head_entry.oid if head_entry else None,
                    "index_entries": [
                        {"mode": entry.mode, "oid": entry.oid, "stage": entry.stage}
                        for entry in index_entries
                    ],
                }
            )
        elif head_entry is None:
            changes.append(
                {
                    "path": path,
                    "state": "add",
                    "head_mode": None,
                    "head_oid": None,
                    "index_mode": normal.mode,
                    "index_oid": normal.oid,
                }
            )
        elif head_entry.mode != normal.mode or head_entry.oid != normal.oid:
            changes.append(
                {
                    "path": path,
                    "state": "modify",
                    "head_mode": head_entry.mode,
                    "head_oid": head_entry.oid,
                    "index_mode": normal.mode,
                    "index_oid": normal.oid,
                }
            )
    return changes


def _unstaged_changes(
    index: dict[str, tuple[_IndexEntry, ...]],
    worktree: list[dict[str, object]],
    excluded_paths: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    worktree_by_path = {str(entry["path"]): entry for entry in worktree}
    changes: list[dict[str, Any]] = []
    for path, entries in index.items():
        if path in excluded_paths:
            continue
        normal = _normal_index_entry(entries)
        if normal is None:
            changes.append(
                {
                    "path": path,
                    "state": "non_normal_index",
                    "index_entries": [
                        {"mode": entry.mode, "oid": entry.oid, "stage": entry.stage}
                        for entry in entries
                    ],
                }
            )
            continue
        if normal.mode == "160000":
            changes.append(
                {
                    "path": path,
                    "state": "gitlink_unverified",
                    "index_mode": normal.mode,
                    "index_oid": normal.oid,
                }
            )
            continue
        current = worktree_by_path.get(path)
        if current is None:
            raise ValueError("git_evidence_worktree_snapshot_incomplete")
        if current.get("state") == "missing":
            changes.append(
                {
                    "path": path,
                    "state": "delete",
                    "index_mode": normal.mode,
                    "index_oid": normal.oid,
                    "worktree_mode": None,
                    "worktree_oid": None,
                }
            )
        elif (
            current.get("git_mode") != normal.mode
            or current.get("git_blob_oid") != normal.oid
        ):
            changes.append(
                {
                    "path": path,
                    "state": "modify",
                    "index_mode": normal.mode,
                    "index_oid": normal.oid,
                    "worktree_mode": current.get("git_mode"),
                    "worktree_oid": current.get("git_blob_oid"),
                }
            )
    return changes


def _canonical_digest(items: list[dict[str, Any]] | list[str]) -> str:
    if not items:
        return EMPTY_SHA256
    encoded = json.dumps(
        items,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8") + b"\n"
    return hashlib.sha256(encoded).hexdigest()


def canonical_git_evidence_digest(items: list[dict[str, Any]] | list[str]) -> str:
    """Digest a canonical plumbing evidence list using the public v1 rule."""

    return _canonical_digest(items)


def _normalize_exclusions(paths: Iterable[object]) -> tuple[str, ...]:
    if isinstance(paths, (str, bytes, bytearray, dict)) or not isinstance(paths, Iterable):
        raise TypeError("excluded_untracked_paths_must_be_iterable")
    started = time.monotonic()
    normalized: set[str] = set()
    for count, path in enumerate(paths, start=1):
        if count > MAX_GIT_EXCLUSION_PATHS:
            raise ValueError("git_evidence_exclusion_limit_exceeded")
        if time.monotonic() - started > GIT_METADATA_SNAPSHOT_TIMEOUT_SECONDS:
            raise ValueError("git_evidence_exclusion_timeout")
        normalized.add(normalize_repo_relative_path(path))
    return tuple(sorted(normalized))


def _path_is_excluded(path: str, exclusions: tuple[str, ...]) -> bool:
    return any(path == excluded or path.startswith(f"{excluded}/") for excluded in exclusions)


def _empty_evidence() -> dict[str, object]:
    return {
        "schema_version": GIT_EVIDENCE_SCHEMA_VERSION,
        "is_git": False,
        "branch": "unknown",
        "head": "unknown",
        "object_format": None,
        "tracked_paths": [],
        "untracked_paths": [],
        "worktree_entries": [],
        "untracked_entries": [],
        "staged_changes": [],
        "unstaged_changes": [],
        "status_sha256": EMPTY_SHA256,
        "staged_diff_sha256": EMPTY_SHA256,
        "unstaged_diff_sha256": EMPTY_SHA256,
        "untracked_paths_sha256": EMPTY_SHA256,
        "untracked_entries_sha256": EMPTY_SHA256,
    }


def capture_git_workspace_evidence(
    root: str | os.PathLike[str] | RepositoryRootAnchor,
    excluded_untracked_paths: Iterable[object] = (),
    *,
    exclude_untracked: Callable[[str], bool] | None = None,
    exclude_tracked: Callable[[str], bool] | None = None,
    descriptor_authority_validator: Callable[[int, str], bool] | None = None,
) -> dict[str, object]:
    """Capture deterministic Git/index/worktree evidence without executable Git features."""

    exclusions = _normalize_exclusions(excluded_untracked_paths)
    if exclude_untracked is not None and not callable(exclude_untracked):
        raise TypeError("exclude_untracked_must_be_callable")
    if exclude_tracked is not None and not callable(exclude_tracked):
        raise TypeError("exclude_tracked_must_be_callable")
    if descriptor_authority_validator is not None and not callable(
        descriptor_authority_validator
    ):
        raise TypeError("descriptor_authority_validator_must_be_callable")
    try:
        with (
            nullcontext(root)
            if isinstance(root, RepositoryRootAnchor)
            else open_repository_root_anchor(root)
        ) as anchor:
            _require_workspace_descriptor_authority(
                descriptor_authority_validator,
                anchor.fd,
                ".",
            )
            with _open_git_authority(anchor) as authority_pair:
                if authority_pair is None:
                    _require_workspace_descriptor_authority(
                        descriptor_authority_validator,
                        anchor.fd,
                        ".",
                    )
                    return _empty_evidence()
                marker, metadata_authority = authority_pair
                _require_exact_git_toplevel(anchor, marker, metadata_authority)
                _revalidate_git_metadata_authority(anchor, metadata_authority)
                object_format = _probe_object_format(anchor, metadata_authority)

                before = _capture_plumbing(
                    anchor,
                    object_format,
                    metadata_authority,
                )
                index = _parse_index(before.index_raw, object_format)
                tree = _parse_tree(before.tree_raw, object_format)

                def inventory_excluded(path: str) -> bool:
                    if path == ".git" or path.startswith(".git/"):
                        return True
                    if path in index:
                        return exclude_tracked is not None and exclude_tracked(path)
                    return _path_is_excluded(path, exclusions) or (
                        exclude_untracked is not None and exclude_untracked(path)
                    )

                repository_inventory = snapshot_repository_inventory_from_anchor(
                    anchor,
                    exclude=inventory_excluded,
                    descriptor_authority_validator=descriptor_authority_validator,
                )
                gitlink_roots = tuple(
                    f"{path}/"
                    for path, entries in index.items()
                    if (normal := _normal_index_entry(entries)) is not None
                    and normal.mode == "160000"
                )
                untracked_paths = [
                    candidate
                    for candidate in sorted(
                        str(entry["path"])
                        for entry in repository_inventory
                        if entry.get("kind") in {"regular", "symlink"}
                    )
                    if candidate not in index
                    and not any(candidate.startswith(prefix) for prefix in gitlink_roots)
                    if not _path_is_excluded(candidate, exclusions)
                    and (exclude_untracked is None or not exclude_untracked(candidate))
                ]
                tracked_paths = sorted(index)
                excluded_tracked_paths = frozenset(
                    path
                    for path in index
                    if exclude_tracked is not None and exclude_tracked(path)
                )
                tracked_snapshot_paths = [
                    tracked_path
                    for tracked_path, entries in index.items()
                    if (normal := _normal_index_entry(entries)) is not None
                    and normal.mode != "160000"
                    and tracked_path not in excluded_tracked_paths
                ]
                snapshot_paths = sorted(set(tracked_snapshot_paths) | set(untracked_paths))
                combined_worktree = (
                    snapshot_git_paths_from_anchor(
                        anchor,
                        snapshot_paths,
                        object_format=object_format,
                        descriptor_authority_validator=descriptor_authority_validator,
                    )
                    if snapshot_paths
                    else []
                )
                tracked_snapshot_path_set = set(tracked_snapshot_paths)
                untracked_path_set = set(untracked_paths)
                worktree = [
                    entry
                    for entry in combined_worktree
                    if str(entry.get("path")) in tracked_snapshot_path_set
                ]
                untracked_entries = [
                    entry
                    for entry in combined_worktree
                    if str(entry.get("path")) in untracked_path_set
                ]
                if (
                    {str(entry.get("path")) for entry in untracked_entries} != untracked_path_set
                    or any(entry.get("state") != "present" for entry in untracked_entries)
                ):
                    raise ValueError("git_evidence_untracked_snapshot_incomplete")
                after_object_format = _probe_object_format(
                    anchor,
                    metadata_authority,
                )
                if after_object_format != object_format:
                    raise ValueError("git_evidence_changed_during_capture")
                after = _capture_plumbing(
                    anchor,
                    object_format,
                    metadata_authority,
                )
                if before != after:
                    raise ValueError("git_evidence_changed_during_capture")
                if snapshot_repository_inventory_from_anchor(
                    anchor,
                    exclude=inventory_excluded,
                    descriptor_authority_validator=descriptor_authority_validator,
                ) != repository_inventory:
                    raise ValueError("git_evidence_changed_during_capture")
                _revalidate_git_metadata_authority(anchor, metadata_authority)
                _revalidate_git_marker(anchor, marker)
                _require_workspace_descriptor_authority(
                    descriptor_authority_validator,
                    anchor.fd,
                    ".",
                )

            staged_changes = _staged_changes(index, tree)
            unstaged_changes = _unstaged_changes(
                index,
                worktree,
                excluded_tracked_paths,
            )
            staged_digest = _canonical_digest(staged_changes)
            unstaged_digest = _canonical_digest(unstaged_changes)
            untracked_digest = _canonical_digest(untracked_paths)
            untracked_entries_digest = _canonical_digest(untracked_entries)
            status_entries: list[dict[str, Any]] = [
                {"domain": "staged", **change} for change in staged_changes
            ]
            status_entries.extend(
                {"domain": "unstaged", **change} for change in unstaged_changes
            )
            status_entries.extend(
                {"domain": "untracked", "path": untracked_path, "state": "untracked"}
                for untracked_path in untracked_paths
            )

            return {
                "schema_version": GIT_EVIDENCE_SCHEMA_VERSION,
                "is_git": True,
                "branch": before.branch,
                "head": before.head,
                "object_format": object_format,
                "tracked_paths": tracked_paths,
                "untracked_paths": untracked_paths,
                "worktree_entries": worktree,
                "untracked_entries": untracked_entries,
                "staged_changes": staged_changes,
                "unstaged_changes": unstaged_changes,
                "status_sha256": _canonical_digest(status_entries),
                "staged_diff_sha256": staged_digest,
                "unstaged_diff_sha256": unstaged_digest,
                "untracked_paths_sha256": untracked_digest,
                "untracked_entries_sha256": untracked_entries_digest,
            }
    except TypeError as exc:
        if str(exc) == "repository_root_must_be_path":
            raise TypeError("git_evidence_root_must_be_path") from exc
        raise
    except ValueError as exc:
        if str(exc) == "repository_root_must_be_real_directory":
            raise ValueError("git_evidence_root_must_be_real_directory") from exc
        raise


def git_tracked_paths(root: str | os.PathLike[str]) -> list[str]:
    evidence = capture_git_workspace_evidence(root)
    return list(evidence["tracked_paths"]) if evidence["is_git"] else []


def git_untracked_paths(
    root: str | os.PathLike[str],
    excluded_untracked_paths: Iterable[object] = (),
) -> list[str]:
    evidence = capture_git_workspace_evidence(root, excluded_untracked_paths)
    return list(evidence["untracked_paths"]) if evidence["is_git"] else []


def git_paths(root: str | os.PathLike[str]) -> list[str]:
    """Return the sorted union of tracked and non-ignored untracked paths."""

    evidence = capture_git_workspace_evidence(root)
    return sorted(set(evidence["tracked_paths"]) | set(evidence["untracked_paths"]))
