#!/usr/bin/env python3
"""Extract an already-valid CodexQB artifact for local validation.

The standard-library ``zipfile`` extractor does not restore the normalized
Unix file modes bound by PACKAGE-MANIFEST.json.  This helper verifies the ZIP,
extracts into a private sibling directory, restores those modes, verifies the
actual artifact root strictly, and only then publishes the extracted tree.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import tempfile
import zipfile

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
SAFETY_DIR = Path(__file__).resolve().parents[1] / "plugins/codexqb/skills/codexqb/scripts"
if str(SAFETY_DIR) not in sys.path:
    sys.path.insert(0, str(SAFETY_DIR))

from mount_identity import (  # noqa: E402
    NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION,
    MountResolution,
    require_mount_assurance,
    require_same_mount,
    resolve_mount_identity,
)
from package_policy import PLUGIN_ARTIFACT, SOURCE_ARTIFACT
from verify_package_manifest import snapshot_zip_stream, verify_directory, verify_zip


SAFE_FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9_]*(?:=[a-z0-9_-]+)?")


def _directory_identity(metadata: os.stat_result) -> tuple[int, int]:
    return int(metadata.st_dev), int(metadata.st_ino)


def _path_matches_directory(path: Path, expected: tuple[int, int]) -> bool:
    try:
        metadata = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and _directory_identity(metadata) == expected


def _safe_failure_code(exc: BaseException) -> str:
    if isinstance(exc, zipfile.BadZipFile):
        return "package_extract_zip_invalid"
    if isinstance(exc, OSError):
        error_name = errno.errorcode.get(exc.errno or 0, "unknown").lower()
        return f"package_extract_os_error_{error_name}"
    value = str(exc)
    if len(value) <= 160 and SAFE_FAILURE_CODE_RE.fullmatch(value):
        return value
    return "package_extract_failed"


def _require_directory_path_mount(
    path: Path,
    expected: tuple[int, int],
    root_resolution: MountResolution,
) -> None:
    if not _path_matches_directory(path, expected):
        raise ValueError("package_extract_parent_changed")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or _directory_identity(metadata) != expected
        ):
            raise ValueError("package_extract_parent_changed")
        try:
            require_same_mount(root_resolution, descriptor, ".")
        except (TypeError, ValueError) as exc:
            raise ValueError("package_extract_parent_mount_changed") from exc
    except OSError as exc:
        raise ValueError("package_extract_parent_changed") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _entry_matches_directory(
    parent_descriptor: int,
    name: str,
    expected: tuple[int, int],
) -> bool:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(metadata.st_mode) and _directory_identity(metadata) == expected


def _open_directory_at(
    parent_descriptor: int,
    name: str,
    *,
    root_resolution: MountResolution | None = None,
    relative_path: str | None = None,
) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(name, flags, dir_fd=parent_descriptor)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("package_extract_directory_invalid")
    if root_resolution is not None:
        try:
            require_same_mount(root_resolution, descriptor, relative_path)
        except (TypeError, ValueError) as exc:
            os.close(descriptor)
            raise ValueError("package_extract_nested_mount_rejected") from exc
    return descriptor


def _open_or_create_directory_chain(
    root_descriptor: int,
    parts: tuple[str, ...],
    root_resolution: MountResolution,
) -> int:
    current = os.dup(root_descriptor)
    try:
        opened_parts: list[str] = []
        for part in parts:
            try:
                os.mkdir(part, mode=0o755, dir_fd=current)
            except FileExistsError:
                pass
            opened_parts.append(part)
            child = _open_directory_at(
                current,
                part,
                root_resolution=root_resolution,
                relative_path="/".join(opened_parts),
            )
            # mkdir(2) applies the caller's umask even when an explicit mode
            # is supplied.  Bind every generated directory to the canonical
            # package mode through its already no-follow descriptor so strict
            # verification is deterministic under restrictive umasks.
            os.fchmod(child, 0o755)
            os.fsync(child)
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _write_member_at(
    root_descriptor: int,
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    root_resolution: MountResolution,
) -> None:
    parts = tuple(info.filename.rstrip("/").split("/"))
    if not parts or any(not part for part in parts):
        raise ValueError("package_extract_member_path_invalid")
    if info.is_dir():
        directory_descriptor = _open_or_create_directory_chain(
            root_descriptor,
            parts,
            root_resolution,
        )
        try:
            os.fchmod(directory_descriptor, 0o755)
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
        return

    parent_descriptor = _open_or_create_directory_chain(
        root_descriptor,
        parts[:-1],
        root_resolution,
    )
    file_descriptor = -1
    try:
        mode = stat.S_IMODE(info.external_attr >> 16)
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        file_descriptor = os.open(parts[-1], flags, mode, dir_fd=parent_descriptor)
        try:
            require_same_mount(root_resolution, file_descriptor, "/".join(parts))
        except (TypeError, ValueError) as exc:
            raise ValueError("package_extract_nested_mount_rejected") from exc
        total = 0
        with archive.open(info, "r") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(file_descriptor, view)
                    if written <= 0:
                        raise OSError("package_extract_short_write")
                    view = view[written:]
        if total != info.file_size:
            raise ValueError("package_extract_member_size_changed")
        os.fchmod(file_descriptor, mode)
        os.fsync(file_descriptor)
        os.close(file_descriptor)
        file_descriptor = -1
        os.fsync(parent_descriptor)
    finally:
        if file_descriptor >= 0:
            os.close(file_descriptor)
        os.close(parent_descriptor)


def _create_private_sibling(parent_descriptor: int, output_name: str) -> tuple[str, int]:
    for _ in range(32):
        name = f".{output_name}.extract-{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        descriptor = _open_directory_at(parent_descriptor, name)
        return name, descriptor
    raise ValueError("package_extract_private_directory_unavailable")


def _atomic_rename_no_replace(
    source: str,
    destination: str,
    *,
    parent_descriptor: int,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename_function = getattr(libc, "renameatx_np", None)
        flags = 0x00000004  # RENAME_EXCL
    elif sys.platform.startswith("linux"):
        rename_function = getattr(libc, "renameat2", None)
        flags = 0x00000001  # RENAME_NOREPLACE
    else:
        rename_function = None
        flags = 0
    if rename_function is None:
        raise ValueError("package_extract_atomic_publish_unavailable")
    rename_function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename_function.restype = ctypes.c_int
    ctypes.set_errno(0)
    result = rename_function(
        parent_descriptor,
        os.fsencode(source),
        parent_descriptor,
        os.fsencode(destination),
        flags,
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    unsupported = {
        errno.EINVAL,
        errno.ENOSYS,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    if error_number in unsupported:
        raise ValueError("package_extract_atomic_publish_unavailable")
    raise OSError(error_number, os.strerror(error_number), destination)


def _clear_generated_directory(
    directory_descriptor: int,
    root_resolution: MountResolution,
    prefix: tuple[str, ...] = (),
) -> None:
    for name in os.listdir(directory_descriptor):
        metadata = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            relative_parts = (*prefix, name)
            child = _open_directory_at(
                directory_descriptor,
                name,
                root_resolution=root_resolution,
                relative_path="/".join(relative_parts),
            )
            try:
                if _directory_identity(os.fstat(child)) != _directory_identity(metadata):
                    raise ValueError("package_extract_cleanup_identity_changed")
                _clear_generated_directory(child, root_resolution, relative_parts)
            finally:
                os.close(child)
            current = os.stat(name, dir_fd=directory_descriptor, follow_symlinks=False)
            if _directory_identity(current) != _directory_identity(metadata):
                raise ValueError("package_extract_cleanup_identity_changed")
            os.rmdir(name, dir_fd=directory_descriptor)
        else:
            os.unlink(name, dir_fd=directory_descriptor)
    os.fsync(directory_descriptor)


def _remove_generated_root(
    parent_descriptor: int,
    name: str,
    root_descriptor: int,
    expected: tuple[int, int],
    root_resolution: MountResolution,
) -> None:
    if not _entry_matches_directory(parent_descriptor, name, expected):
        return
    _clear_generated_directory(root_descriptor, root_resolution)
    if _entry_matches_directory(parent_descriptor, name, expected):
        os.rmdir(name, dir_fd=parent_descriptor)
        os.fsync(parent_descriptor)


def _open_published_artifact(
    parent_descriptor: int,
    output_name: str,
    output_identity: tuple[int, int],
    artifact_type: str,
    artifact_identity: tuple[int, int],
    root_resolution: MountResolution,
) -> tuple[int, int]:
    output_descriptor = _open_directory_at(
        parent_descriptor,
        output_name,
        root_resolution=root_resolution,
        relative_path=output_name,
    )
    artifact_descriptor = -1
    try:
        if _directory_identity(os.fstat(output_descriptor)) != output_identity:
            raise ValueError("package_extract_output_changed")
        artifact_descriptor = (
            os.dup(output_descriptor)
            if artifact_type == PLUGIN_ARTIFACT
            else _open_directory_at(
                output_descriptor,
                "CodexQB",
                root_resolution=root_resolution,
                relative_path=f"{output_name}/CodexQB",
            )
        )
        if _directory_identity(os.fstat(artifact_descriptor)) != artifact_identity:
            raise ValueError("package_extract_artifact_root_changed")
        return output_descriptor, artifact_descriptor
    except BaseException:
        if artifact_descriptor >= 0:
            os.close(artifact_descriptor)
        os.close(output_descriptor)
        raise


def extract_verified_package(package: Path, output: Path, artifact_type: str) -> Path:
    package = package.absolute()
    output = output.absolute()
    parent = output.parent.resolve(strict=True)
    output = parent / output.name
    if output.exists() or output.is_symlink():
        raise ValueError("package_extract_output_exists")

    if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        raise ValueError("package_extract_secure_open_unavailable")
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | os.O_NOFOLLOW
    )
    directory_flags = file_flags | os.O_DIRECTORY
    package_descriptor = -1
    parent_descriptor = -1
    output_descriptor = -1
    output_identity: tuple[int, int] | None = None
    artifact_descriptor = -1
    artifact_identity: tuple[int, int] | None = None
    root_resolution: MountResolution | None = None
    private_name: str | None = None
    published = False
    try:
        package_descriptor = os.open(package, file_flags)
        parent_descriptor = os.open(parent, directory_flags)
        parent_identity = _directory_identity(os.fstat(parent_descriptor))
        if not _path_matches_directory(parent, parent_identity):
            raise ValueError("package_extract_parent_changed")
        root_resolution = resolve_mount_identity(parent_descriptor, reconcile=True)
        require_mount_assurance(
            root_resolution,
            NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION,
        )
        require_same_mount(root_resolution, parent_descriptor, ".")
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        metadata = os.fstat(package_descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("package_extract_input_not_regular")
        with os.fdopen(package_descriptor, "rb", closefd=True) as package_file:
            package_descriptor = -1
            with tempfile.TemporaryFile(mode="w+b") as package_snapshot:
                snapshot_errors = snapshot_zip_stream(package_file, package_snapshot)
                if snapshot_errors:
                    raise ValueError(snapshot_errors[0])
                errors = verify_zip(
                    package_snapshot,
                    expected_artifact_type=artifact_type,
                )
                if errors:
                    raise ValueError(errors[0])
                package_snapshot.seek(0)
                private_name, output_descriptor = _create_private_sibling(
                    parent_descriptor,
                    output.name,
                )
                output_identity = _directory_identity(os.fstat(output_descriptor))
                if not _entry_matches_directory(
                    parent_descriptor,
                    private_name,
                    output_identity,
                ):
                    raise ValueError("package_extract_private_directory_changed")
                require_same_mount(root_resolution, output_descriptor, private_name)
                archive = zipfile.ZipFile(package_snapshot)
                try:
                    infos = archive.infolist()
                    for info in infos:
                        _write_member_at(
                            output_descriptor,
                            archive,
                            info,
                            root_resolution,
                        )
                finally:
                    archive.close()

        if (
            private_name is None
            or output_identity is None
            or not _entry_matches_directory(parent_descriptor, private_name, output_identity)
        ):
            raise ValueError("package_extract_private_directory_changed")
        os.fsync(output_descriptor)
        artifact_descriptor = (
            os.dup(output_descriptor)
            if artifact_type == PLUGIN_ARTIFACT
            else _open_directory_at(
                output_descriptor,
                "CodexQB",
                root_resolution=root_resolution,
                relative_path="CodexQB",
            )
        )
        artifact_identity = _directory_identity(os.fstat(artifact_descriptor))
        if artifact_type == SOURCE_ARTIFACT and not _entry_matches_directory(
            output_descriptor,
            "CodexQB",
            artifact_identity,
        ):
            raise ValueError("package_extract_artifact_root_changed")
        private_root = parent / private_name
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        artifact_root = (
            private_root
            if artifact_type == PLUGIN_ARTIFACT
            else private_root / "CodexQB"
        )
        errors = verify_directory(
            artifact_root,
            strict_artifact=True,
            expected_artifact_type=artifact_type,
        )
        if errors:
            raise ValueError(errors[0])
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        if not _entry_matches_directory(parent_descriptor, private_name, output_identity):
            raise ValueError("package_extract_private_directory_changed")
        require_same_mount(root_resolution, output_descriptor, private_name)
        if artifact_type == SOURCE_ARTIFACT and not _entry_matches_directory(
            output_descriptor,
            "CodexQB",
            artifact_identity,
        ):
            raise ValueError("package_extract_artifact_root_changed")

        _atomic_rename_no_replace(
            private_name,
            output.name,
            parent_descriptor=parent_descriptor,
        )
        published = True
        if not _entry_matches_directory(parent_descriptor, output.name, output_identity):
            raise ValueError("package_extract_output_changed")
        published_output_descriptor, published_artifact_descriptor = (
            _open_published_artifact(
                parent_descriptor,
                output.name,
                output_identity,
                artifact_type,
                artifact_identity,
                root_resolution,
            )
        )
        os.close(published_artifact_descriptor)
        os.close(published_output_descriptor)
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        if artifact_type == SOURCE_ARTIFACT and not _entry_matches_directory(
            output_descriptor,
            "CodexQB",
            artifact_identity,
        ):
            raise ValueError("package_extract_artifact_root_changed")
        os.fsync(parent_descriptor)
        published_root = output if artifact_type == PLUGIN_ARTIFACT else output / "CodexQB"
        errors = verify_directory(
            published_root,
            strict_artifact=True,
            expected_artifact_type=artifact_type,
        )
        if errors:
            raise ValueError(errors[0])
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        if not _entry_matches_directory(parent_descriptor, output.name, output_identity):
            raise ValueError("package_extract_output_changed")
        if artifact_type == SOURCE_ARTIFACT and not _entry_matches_directory(
            output_descriptor,
            "CodexQB",
            artifact_identity,
        ):
            raise ValueError("package_extract_artifact_root_changed")
        published_output_descriptor, published_artifact_descriptor = (
            _open_published_artifact(
                parent_descriptor,
                output.name,
                output_identity,
                artifact_type,
                artifact_identity,
                root_resolution,
            )
        )
        os.close(published_artifact_descriptor)
        os.close(published_output_descriptor)
        _require_directory_path_mount(parent, parent_identity, root_resolution)
        errors = verify_directory(
            published_root,
            strict_artifact=True,
            expected_artifact_type=artifact_type,
        )
        if errors:
            raise ValueError(errors[0])
        return published_root
    except BaseException as primary_error:
        cleanup_name = output.name if published else private_name
        if (
            cleanup_name is not None
            and output_descriptor >= 0
            and output_identity is not None
        ):
            if artifact_descriptor >= 0:
                os.close(artifact_descriptor)
                artifact_descriptor = -1
            try:
                if root_resolution is None:
                    if _entry_matches_directory(
                        parent_descriptor,
                        cleanup_name,
                        output_identity,
                    ) and not os.listdir(output_descriptor):
                        os.rmdir(cleanup_name, dir_fd=parent_descriptor)
                else:
                    _remove_generated_root(
                        parent_descriptor,
                        cleanup_name,
                        output_descriptor,
                        output_identity,
                        root_resolution,
                    )
            except (OSError, ValueError) as cleanup_error:
                primary_error.__cause__ = cleanup_error
                raise RuntimeError(
                    "package_extract_cleanup_state_unknown"
                ) from primary_error
        raise
    finally:
        if artifact_descriptor >= 0:
            os.close(artifact_descriptor)
        if output_descriptor >= 0:
            os.close(output_descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)
        if package_descriptor >= 0:
            os.close(package_descriptor)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zip", required=True, type=Path, dest="package")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument(
        "--artifact-type",
        required=True,
        choices=(PLUGIN_ARTIFACT, SOURCE_ARTIFACT),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    try:
        artifact_root = extract_verified_package(
            args.package,
            args.output,
            args.artifact_type,
        )
    except (OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        print(f"package_extract_failed={_safe_failure_code(exc)}")
        return 1
    print("package_extract_verification=passed")
    print(f"artifact_type={args.artifact_type}")
    print(
        "artifact_root=."
        if args.artifact_type == PLUGIN_ARTIFACT
        else "artifact_root=CodexQB"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
