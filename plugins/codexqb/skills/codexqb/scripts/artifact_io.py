#!/usr/bin/env python3
"""Descriptor-bound, no-follow artifact I/O for CodexQB local helpers."""

from __future__ import annotations

from contextlib import contextmanager
import ctypes
import errno
import fcntl
import hashlib
import os
import platform
import secrets
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from safety_contracts import (  # noqa: E402
    assert_safe_serialized_artifact,
    parse_safe_persistent_json,
    serialize_safe_persistent_json,
)


Revalidator = Callable[[], bool]
DescriptorAuthorityValidator = Callable[[int, str], bool]
DirectoryAuthorityValidator = Callable[[int], bool]

_DARWIN_RENAME_SWAP = 0x00000002
_DARWIN_RENAME_EXCL = 0x00000004
_LINUX_RENAME_NOREPLACE = 0x00000001
_LINUX_RENAME_EXCHANGE = 0x00000002
_LINUX_RENAMEAT2_SYSCALL = {
    "aarch64": 276,
    "arm64": 276,
    "x86_64": 316,
    "amd64": 316,
}


def _stable_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _published_file_matches(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISREG(first.st_mode)
        and stat.S_ISREG(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
        and first.st_uid == second.st_uid
        and first.st_nlink == second.st_nlink == 1
        and first.st_size == second.st_size
        and stat.S_IMODE(first.st_mode) == stat.S_IMODE(second.st_mode)
    )


def _native_renameat(directory_fd: int, old: str, new: str, *, operation: str) -> None:
    if not valid_entry_name(old) or not valid_entry_name(new):
        raise ValueError("invalid_artifact_name")
    libc = ctypes.CDLL(None, use_errno=True)
    old_bytes = os.fsencode(old)
    new_bytes = os.fsencode(new)
    if sys.platform == "darwin":
        function = getattr(libc, "renameatx_np", None)
        if function is None:
            raise OSError(errno.ENOTSUP, "artifact_atomic_rename_unavailable")
        function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        function.restype = ctypes.c_int
        flags = _DARWIN_RENAME_EXCL if operation == "noreplace" else _DARWIN_RENAME_SWAP
        result = function(directory_fd, old_bytes, directory_fd, new_bytes, flags)
    elif sys.platform.startswith("linux"):
        flags = _LINUX_RENAME_NOREPLACE if operation == "noreplace" else _LINUX_RENAME_EXCHANGE
        function = getattr(libc, "renameat2", None)
        if function is not None:
            function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
            function.restype = ctypes.c_int
            result = function(directory_fd, old_bytes, directory_fd, new_bytes, flags)
        else:
            syscall_number = _LINUX_RENAMEAT2_SYSCALL.get(platform.machine().lower())
            if syscall_number is None:
                raise OSError(errno.ENOTSUP, "artifact_atomic_rename_unavailable")
            syscall = libc.syscall
            syscall.restype = ctypes.c_long
            result = syscall(
                ctypes.c_long(syscall_number),
                ctypes.c_int(directory_fd),
                ctypes.c_char_p(old_bytes),
                ctypes.c_int(directory_fd),
                ctypes.c_char_p(new_bytes),
                ctypes.c_uint(flags),
            )
    else:
        raise OSError(errno.ENOTSUP, "artifact_atomic_rename_unavailable")
    if result != 0:
        error = ctypes.get_errno()
        if error in {errno.EEXIST, errno.ENOTEMPTY}:
            raise FileExistsError(error, "artifact_atomic_target_exists") from None
        raise OSError(error, "artifact_atomic_rename_failed") from None


def _rename_noreplace(directory_fd: int, old: str, new: str) -> None:
    _native_renameat(directory_fd, old, new, operation="noreplace")


def _rename_exchange(directory_fd: int, first: str, second: str) -> None:
    _native_renameat(directory_fd, first, second, operation="exchange")


def secure_directory_open_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_artifact_io_not_supported")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def valid_entry_name(name: str) -> bool:
    return bool(name and name not in {".", ".."} and "/" not in name and "\\" not in name and "\x00" not in name)


def open_child_directory(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    if not valid_entry_name(name):
        raise ValueError("invalid_artifact_directory_name")
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("artifact_directory_must_be_real_directory")
    child_fd = os.open(name, secure_directory_open_flags(), dir_fd=parent_fd)
    try:
        after = os.fstat(child_fd)
    except Exception:
        os.close(child_fd)
        raise
    if not same_file_identity(before, after):
        os.close(child_fd)
        raise ValueError("artifact_directory_identity_changed")
    return child_fd, after


def _require_directory_authority(
    directory_fd: int,
    validator: DirectoryAuthorityValidator | None,
) -> None:
    if validator is None:
        return
    try:
        accepted = validator(directory_fd)
    except Exception:
        raise ValueError("artifact_parent_authority_rejected") from None
    if accepted is not True:
        raise ValueError("artifact_parent_authority_rejected")


def _remove_created_directory(parent_fd: int, name: str) -> None:
    try:
        os.rmdir(name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    except OSError:
        raise OSError(
            errno.EIO,
            "artifact_created_directory_cleanup_unknown",
        ) from None


def open_or_create_child_directory(
    parent_fd: int,
    name: str,
    *,
    create: bool,
    mode: int = 0o700,
    parent_authority_validator: DirectoryAuthorityValidator | None = None,
) -> tuple[int, os.stat_result, bool]:
    if parent_authority_validator is not None and not callable(
        parent_authority_validator
    ):
        raise TypeError("artifact_parent_authority_validator_invalid")
    _require_directory_authority(parent_fd, parent_authority_validator)
    created = False
    if create:
        try:
            os.mkdir(name, mode=mode, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
    try:
        _require_directory_authority(parent_fd, parent_authority_validator)
    except Exception:
        if created:
            _remove_created_directory(parent_fd, name)
        raise
    if created:
        try:
            created_metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if not stat.S_ISDIR(created_metadata.st_mode):
                raise ValueError("artifact_directory_must_be_real_directory")
            os.chmod(name, mode, dir_fd=parent_fd, follow_symlinks=False)
        except (OSError, TypeError, ValueError):
            raise OSError(errno.EIO, "artifact_created_directory_mode_unknown") from None
    child_fd, metadata = open_child_directory(parent_fd, name)
    try:
        if created:
            os.fchmod(child_fd, mode)
            metadata = os.fstat(child_fd)
            if stat.S_IMODE(metadata.st_mode) != mode:
                raise OSError(errno.EIO, "artifact_created_directory_mode_unknown")
        _require_directory_authority(parent_fd, parent_authority_validator)
    except Exception as exc:
        os.close(child_fd)
        if created:
            _remove_created_directory(parent_fd, name)
        if isinstance(exc, OSError):
            raise OSError(errno.EIO, "artifact_created_directory_mode_unknown") from None
        raise
    return child_fd, metadata, created


def directory_entry_matches(parent_fd: int, name: str, metadata: os.stat_result) -> bool:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(current.st_mode) and same_file_identity(current, metadata)


def _lstat_optional(directory_fd: int, name: str) -> os.stat_result | None:
    try:
        return os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None


def regular_target_metadata_at(directory_fd: int, name: str) -> os.stat_result | None:
    if not valid_entry_name(name):
        raise ValueError("invalid_artifact_name")
    metadata = _lstat_optional(directory_fd, name)
    if metadata is not None and not stat.S_ISREG(metadata.st_mode):
        raise ValueError("artifact_target_must_be_regular_file")
    return metadata


def _validate_descriptor_authority_at(
    directory_fd: int,
    name: str,
    validator: DescriptorAuthorityValidator | None,
    phase: str,
) -> os.stat_result | None:
    """Run caller authority policy on a stable descriptor for one path entry."""

    if validator is None:
        return regular_target_metadata_at(directory_fd, name)
    if phase not in {"initial", "displaced", "published"}:
        raise ValueError("artifact_descriptor_authority_phase_invalid")
    before = regular_target_metadata_at(directory_fd, name)
    if before is None:
        return None
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_fd,
        )
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or _stable_metadata(before) != _stable_metadata(opened):
            raise ValueError("artifact_descriptor_authority_rejected")
        try:
            accepted = validator(descriptor, phase)
        except Exception:
            raise ValueError("artifact_descriptor_authority_rejected") from None
        after_fd = os.fstat(descriptor)
    except ValueError:
        raise
    except (OSError, TypeError):
        raise ValueError("artifact_descriptor_authority_rejected") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    after_path = regular_target_metadata_at(directory_fd, name)
    if (
        accepted is not True
        or after_path is None
        or _stable_metadata(opened) != _stable_metadata(after_fd)
        or _stable_metadata(opened) != _stable_metadata(after_path)
    ):
        raise ValueError("artifact_descriptor_authority_rejected")
    return after_fd


def _revalidate(revalidate: Revalidator | None) -> None:
    if revalidate is not None and not revalidate():
        raise ValueError("artifact_directory_identity_changed")


def _write_all(file_fd: int, encoded: bytes) -> None:
    offset = 0
    while offset < len(encoded):
        written = os.write(file_fd, encoded[offset:])
        if written <= 0:
            raise OSError("short artifact write")
        offset += written


def _verified_target(
    directory_fd: int,
    name: str,
    *,
    expected_metadata: os.stat_result,
    expected_sha256: str,
    expected_mode: int | None = None,
) -> os.stat_result:
    before = regular_target_metadata_at(directory_fd, name)
    if (
        before is None
        or not _published_file_matches(before, expected_metadata)
        or before.st_nlink != 1
        or expected_mode is not None
        and stat.S_IMODE(before.st_mode) != expected_mode
    ):
        raise ValueError("artifact_published_identity_changed")
    content = read_regular_unvalidated_bytes_at(
        directory_fd,
        name,
        max_bytes=expected_metadata.st_size,
    )
    after = regular_target_metadata_at(directory_fd, name)
    if (
        after is None
        or _stable_metadata(before) != _stable_metadata(after)
        or len(content) != expected_metadata.st_size
        or hashlib.sha256(content).hexdigest() != expected_sha256
    ):
        raise ValueError("artifact_published_content_changed")
    return after


def _rollback_exchange(
    directory_fd: int,
    temporary: str,
    name: str,
    *,
    published_metadata: os.stat_result,
    displaced_metadata: os.stat_result,
) -> None:
    current_published = regular_target_metadata_at(directory_fd, name)
    current_displaced = regular_target_metadata_at(directory_fd, temporary)
    if (
        current_published is None
        or current_displaced is None
        or not _published_file_matches(current_published, published_metadata)
        or not _published_file_matches(current_displaced, displaced_metadata)
    ):
        raise OSError(errno.EBUSY, "artifact_exchange_rollback_ambiguous")
    _rename_exchange(directory_fd, temporary, name)
    restored = regular_target_metadata_at(directory_fd, name)
    recovered_new = regular_target_metadata_at(directory_fd, temporary)
    if (
        restored is None
        or recovered_new is None
        or not _published_file_matches(restored, displaced_metadata)
        or not _published_file_matches(recovered_new, published_metadata)
    ):
        raise OSError(errno.EBUSY, "artifact_exchange_rollback_ambiguous")
    os.fsync(directory_fd)


def atomic_write_bytes_at(
    directory_fd: int,
    name: str,
    encoded: bytes,
    *,
    revalidate: Revalidator | None = None,
    mode: int = 0o600,
    expected_state: str | None = None,
    expected_sha256: str | None = None,
    descriptor_authority_validator: DescriptorAuthorityValidator | None = None,
) -> os.stat_result:
    if not isinstance(encoded, bytes):
        raise TypeError("encoded artifact content must be bytes")
    if expected_state not in {None, "missing", "present"}:
        raise ValueError("artifact_expected_state_invalid")
    if expected_state == "present" and (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError("artifact_expected_digest_invalid")
    if expected_state != "present" and expected_sha256 is not None:
        raise ValueError("artifact_expected_digest_invalid")
    if descriptor_authority_validator is not None and not callable(
        descriptor_authority_validator
    ):
        raise TypeError("artifact_descriptor_authority_validator_invalid")
    _revalidate(revalidate)
    initial = regular_target_metadata_at(directory_fd, name)
    if initial is not None:
        _validate_descriptor_authority_at(
            directory_fd,
            name,
            descriptor_authority_validator,
            "initial",
        )
    initial_digest: str | None = None
    if expected_state == "missing" and initial is not None:
        raise ValueError("artifact_target_appeared_during_write")
    if expected_state == "present":
        if initial is None:
            raise ValueError("artifact_target_changed_during_write")
        initial_content = read_regular_unvalidated_bytes_at(
            directory_fd,
            name,
            max_bytes=initial.st_size,
        )
        confirmed = regular_target_metadata_at(directory_fd, name)
        if confirmed is None or _stable_metadata(initial) != _stable_metadata(confirmed):
            raise ValueError("artifact_target_changed_during_write")
        initial_digest = hashlib.sha256(initial_content).hexdigest()
        if initial_digest != expected_sha256:
            raise ValueError("artifact_target_changed_during_write")
    assert_safe_serialized_artifact(name, encoded)
    temporary = ""
    temporary_fd = -1
    preserve_temporary = False
    temporary_metadata: os.stat_result | None = None
    encoded_digest = hashlib.sha256(encoded).hexdigest()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        for _ in range(32):
            candidate = f".codexqb-artifact-{secrets.token_hex(16)}"
            try:
                temporary_fd = os.open(candidate, flags, mode, dir_fd=directory_fd)
                temporary = candidate
                break
            except FileExistsError:
                continue
        if temporary_fd < 0:
            raise FileExistsError("could not allocate exclusive artifact temporary file")
        try:
            os.fchmod(temporary_fd, mode)
            _write_all(temporary_fd, encoded)
            os.fsync(temporary_fd)
            temporary_metadata = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(temporary_metadata.st_mode)
                or temporary_metadata.st_nlink != 1
                or stat.S_IMODE(temporary_metadata.st_mode) != mode
                or temporary_metadata.st_size != len(encoded)
            ):
                raise OSError(errno.EIO, "artifact_temporary_verification_failed")
        finally:
            os.close(temporary_fd)
            temporary_fd = -1

        _validate_descriptor_authority_at(
            directory_fd,
            temporary,
            descriptor_authority_validator,
            "published",
        )

        _revalidate(revalidate)
        current = regular_target_metadata_at(directory_fd, name)
        if initial is None:
            if current is not None:
                raise ValueError("artifact_target_appeared_during_write")
        elif current is None or not same_file_identity(initial, current):
            raise ValueError("artifact_target_changed_during_write")
        # Give descriptor-bound callers one final pre-replace CAS/ancestor
        # check after the target identity check.  This closes the deterministic
        # mutation window used by concurrent-writer probes.
        _revalidate(revalidate)
        if temporary_metadata is None:
            raise OSError(errno.EIO, "artifact_temporary_verification_failed")
        temporary_path_metadata = regular_target_metadata_at(directory_fd, temporary)
        if (
            temporary_path_metadata is None
            or _stable_metadata(temporary_path_metadata) != _stable_metadata(temporary_metadata)
        ):
            raise OSError(errno.EIO, "artifact_temporary_identity_changed")

        if expected_state == "missing":
            try:
                _rename_noreplace(directory_fd, temporary, name)
            except FileExistsError:
                raise ValueError("artifact_target_appeared_during_write") from None
            temporary = ""
            os.fsync(directory_fd)
            published = _verified_target(
                directory_fd,
                name,
                expected_metadata=temporary_metadata,
                expected_sha256=encoded_digest,
                expected_mode=mode,
            )
            try:
                _validate_descriptor_authority_at(
                    directory_fd,
                    name,
                    descriptor_authority_validator,
                    "published",
                )
            except ValueError:
                raise OSError(errno.EBUSY, "artifact_published_authority_unknown") from None
            return published

        if expected_state == "present":
            _rename_exchange(directory_fd, temporary, name)
            preserve_temporary = True
            published = regular_target_metadata_at(directory_fd, name)
            displaced = regular_target_metadata_at(directory_fd, temporary)
            if published is None or displaced is None:
                raise OSError(errno.EIO, "artifact_exchange_state_unknown")
            try:
                _validate_descriptor_authority_at(
                    directory_fd,
                    name,
                    descriptor_authority_validator,
                    "published",
                )
                _validate_descriptor_authority_at(
                    directory_fd,
                    temporary,
                    descriptor_authority_validator,
                    "displaced",
                )
                _verified_target(
                    directory_fd,
                    name,
                    expected_metadata=temporary_metadata,
                    expected_sha256=encoded_digest,
                    expected_mode=mode,
                )
                _verified_target(
                    directory_fd,
                    temporary,
                    expected_metadata=initial,
                    expected_sha256=str(initial_digest),
                )
            except ValueError:
                try:
                    _rollback_exchange(
                        directory_fd,
                        temporary,
                        name,
                        published_metadata=published,
                        displaced_metadata=displaced,
                    )
                except (OSError, TypeError, ValueError):
                    raise OSError(errno.EBUSY, "artifact_exchange_rollback_ambiguous") from None
                preserve_temporary = False
                raise ValueError("artifact_target_changed_during_write") from None
            os.fsync(directory_fd)
            published = _verified_target(
                directory_fd,
                name,
                expected_metadata=temporary_metadata,
                expected_sha256=encoded_digest,
                expected_mode=mode,
            )
            try:
                _validate_descriptor_authority_at(
                    directory_fd,
                    name,
                    descriptor_authority_validator,
                    "published",
                )
                _validate_descriptor_authority_at(
                    directory_fd,
                    temporary,
                    descriptor_authority_validator,
                    "displaced",
                )
            except ValueError:
                try:
                    _rollback_exchange(
                        directory_fd,
                        temporary,
                        name,
                        published_metadata=published,
                        displaced_metadata=displaced,
                    )
                except (OSError, TypeError, ValueError):
                    raise OSError(errno.EBUSY, "artifact_exchange_rollback_ambiguous") from None
                preserve_temporary = False
                raise ValueError("artifact_target_changed_during_write") from None
            os.unlink(temporary, dir_fd=directory_fd)
            temporary = ""
            preserve_temporary = False
            os.fsync(directory_fd)
            verified = _verified_target(
                directory_fd,
                name,
                expected_metadata=published,
                expected_sha256=encoded_digest,
                expected_mode=mode,
            )
            _validate_descriptor_authority_at(
                directory_fd,
                name,
                descriptor_authority_validator,
                "published",
            )
            return verified

        os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        temporary = ""
        os.fsync(directory_fd)
        verified = _verified_target(
            directory_fd,
            name,
            expected_metadata=temporary_metadata,
            expected_sha256=encoded_digest,
            expected_mode=mode,
        )
        try:
            _validate_descriptor_authority_at(
                directory_fd,
                name,
                descriptor_authority_validator,
                "published",
            )
        except ValueError:
            raise OSError(errno.EBUSY, "artifact_published_authority_unknown") from None
        return verified
    finally:
        if temporary_fd >= 0:
            os.close(temporary_fd)
        if temporary and not preserve_temporary:
            try:
                os.unlink(temporary, dir_fd=directory_fd)
            except OSError:
                pass


def atomic_write_text_at(
    directory_fd: int,
    name: str,
    text: str,
    *,
    revalidate: Revalidator | None = None,
) -> None:
    atomic_write_bytes_at(directory_fd, name, text.encode("utf-8"), revalidate=revalidate)


def atomic_write_json_at(
    directory_fd: int,
    name: str,
    payload: object,
    *,
    revalidate: Revalidator | None = None,
) -> None:
    atomic_write_text_at(
        directory_fd,
        name,
        serialize_safe_persistent_json(payload),
        revalidate=revalidate,
    )


def read_regular_unvalidated_bytes_at(
    directory_fd: int,
    name: str,
    *,
    max_bytes: int = 16 * 1024 * 1024,
) -> bytes:
    """Read stable regular-file bytes for a caller that will validate the full stream."""

    before = regular_target_metadata_at(directory_fd, name)
    if before is None:
        raise FileNotFoundError(name)
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        opened = os.fstat(file_fd)
        if not stat.S_ISREG(opened.st_mode) or not same_file_identity(before, opened):
            raise ValueError("artifact_file_identity_changed")
        if opened.st_size > max_bytes:
            raise ValueError("artifact_file_too_large")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        encoded = b"".join(chunks)
        if len(encoded) > max_bytes:
            raise ValueError("artifact_file_too_large")
    finally:
        os.close(file_fd)
    after = regular_target_metadata_at(directory_fd, name)
    if after is None or not same_file_identity(before, after):
        raise ValueError("artifact_file_identity_changed")
    return encoded


def read_regular_bytes_at(directory_fd: int, name: str, *, max_bytes: int = 16 * 1024 * 1024) -> bytes:
    encoded = read_regular_unvalidated_bytes_at(directory_fd, name, max_bytes=max_bytes)
    return assert_safe_serialized_artifact(name, encoded)


def read_regular_text_at(directory_fd: int, name: str, *, max_bytes: int = 16 * 1024 * 1024) -> str:
    return read_regular_bytes_at(directory_fd, name, max_bytes=max_bytes).decode("utf-8")


def read_regular_json_at(directory_fd: int, name: str, *, max_bytes: int = 16 * 1024 * 1024) -> dict[str, object]:
    value = parse_safe_persistent_json(read_regular_text_at(directory_fd, name, max_bytes=max_bytes))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {name}")
    return value


def unlink_regular_at(
    directory_fd: int,
    name: str,
    *,
    missing_ok: bool = False,
    revalidate: Revalidator | None = None,
) -> None:
    _revalidate(revalidate)
    metadata = regular_target_metadata_at(directory_fd, name)
    if metadata is None:
        if missing_ok:
            return
        raise FileNotFoundError(name)
    current = regular_target_metadata_at(directory_fd, name)
    if current is None or not same_file_identity(metadata, current):
        raise ValueError("artifact_target_changed_during_unlink")
    _revalidate(revalidate)
    os.unlink(name, dir_fd=directory_fd)
    os.fsync(directory_fd)


@contextmanager
def locked_directory(directory_fd: int) -> Iterator[None]:
    fcntl.flock(directory_fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(directory_fd, fcntl.LOCK_UN)
