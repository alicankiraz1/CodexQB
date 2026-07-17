#!/usr/bin/env python3
"""Test-only controller-home isolation and accidental-mutation guard helpers.

This module is intentionally outside the shipped plugin runtime.  Production
controllers do not import it and expose no environment or command-line
override for their passwd-home trust root.  The before/after commitment catches
accidental writes by the suite; it is not same-UID tamper resistance, host
authority, or attestation.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys
import tempfile
from collections.abc import Iterator, Sequence


REPO_ROOT = Path(__file__).resolve().parents[1]
HARNESS = Path(__file__).resolve().with_name("controller_cli_harness.py")
MAX_SNAPSHOT_ENTRIES = 100_000
MAX_SNAPSHOT_BYTES = 512 * 1024 * 1024


def effective_uid() -> int:
    return os.geteuid() if hasattr(os, "geteuid") else os.getuid()


def passwd_home() -> Path:
    raw = pwd.getpwuid(effective_uid()).pw_dir
    home = Path(raw)
    if not home.is_absolute():
        raise RuntimeError("test_controller_passwd_home_invalid")
    return home.resolve(strict=True)


def validate_test_home(path: Path) -> Path:
    """Accept only a private, direct child of the effective passwd home."""

    if not path.is_absolute():
        raise ValueError("test_controller_home_not_absolute")
    candidate = path.resolve(strict=True)
    home = passwd_home()
    if candidate.parent != home or not candidate.name.startswith(".codexqb-test-home-"):
        raise ValueError("test_controller_home_outside_test_namespace")
    metadata = candidate.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("test_controller_home_not_directory")
    if metadata.st_uid != effective_uid() or stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("test_controller_home_permissions_invalid")
    return candidate


def temporary_controller_home() -> tempfile.TemporaryDirectory[str]:
    directory = tempfile.TemporaryDirectory(
        prefix=".codexqb-test-home-",
        dir=passwd_home(),
    )
    os.chmod(directory.name, 0o700)
    validate_test_home(Path(directory.name))
    return directory


def controller_cli_command(
    controller: str,
    test_home: Path | None,
    arguments: Sequence[str],
) -> list[str]:
    if controller not in {
        "apply",
        "doctor",
        "goal",
        "planner-validator",
        "repository-io",
    }:
        raise ValueError("test_controller_kind_invalid")
    if controller in {"goal", "apply"}:
        if test_home is None:
            raise ValueError("test_controller_home_required")
        validated_home = validate_test_home(test_home)
    elif test_home is not None:
        raise ValueError("test_controller_home_not_applicable")
    else:
        validated_home = None
    command = [
        sys.executable,
        "-I",
        "-S",
        "-B",
        HARNESS.as_posix(),
        "--controller",
        controller,
    ]
    if validated_home is not None:
        command.extend(("--test-home", validated_home.as_posix()))
    command.extend(("--", *arguments))
    return command


def _entry_record(
    relative_components: tuple[str, ...],
    metadata: os.stat_result,
    *,
    kind: str,
    content_sha256: str | None = None,
) -> dict[str, object]:
    path_identity = "/".join(relative_components).encode("utf-8", errors="surrogateescape")
    record: dict[str, object] = {
        "path_sha256": hashlib.sha256(path_identity).hexdigest(),
        "kind": kind,
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "size": metadata.st_size,
        "mtime_ns": metadata.st_mtime_ns,
        "ctime_ns": metadata.st_ctime_ns,
    }
    if content_sha256 is not None:
        record["content_sha256"] = content_sha256
    return record


def _hash_regular_at(parent_fd: int, name: str, expected: os.stat_result) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=parent_fd)
    try:
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode):
            raise RuntimeError("real_trust_snapshot_entry_changed")
        if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
            raise RuntimeError("real_trust_snapshot_entry_changed")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_SNAPSHOT_BYTES:
                raise RuntimeError("real_trust_snapshot_byte_budget_exceeded")
            digest.update(chunk)
        final = os.fstat(descriptor)
        if (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns) != (
            observed.st_dev,
            observed.st_ino,
            observed.st_size,
            observed.st_mtime_ns,
        ):
            raise RuntimeError("real_trust_snapshot_entry_changed")
        return digest.hexdigest(), total
    finally:
        os.close(descriptor)


def _snapshot_directory(
    descriptor: int,
    relative_components: tuple[str, ...],
    records: list[dict[str, object]],
    budget: dict[str, int],
) -> None:
    names = sorted(os.listdir(descriptor))
    for name in names:
        if not isinstance(name, str) or not name or name in {".", ".."} or "/" in name:
            raise RuntimeError("real_trust_snapshot_entry_name_invalid")
        budget["entries"] += 1
        if budget["entries"] > MAX_SNAPSHOT_ENTRIES:
            raise RuntimeError("real_trust_snapshot_entry_budget_exceeded")
        relative = (*relative_components, name)
        metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            records.append(_entry_record(relative, metadata, kind="directory"))
            child = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    raise RuntimeError("real_trust_snapshot_entry_changed")
                _snapshot_directory(child, relative, records, budget)
            finally:
                os.close(child)
        elif stat.S_ISREG(metadata.st_mode):
            content_digest, byte_count = _hash_regular_at(descriptor, name, metadata)
            budget["bytes"] += byte_count
            if budget["bytes"] > MAX_SNAPSHOT_BYTES:
                raise RuntimeError("real_trust_snapshot_byte_budget_exceeded")
            records.append(
                _entry_record(
                    relative,
                    metadata,
                    kind="regular",
                    content_sha256=content_digest,
                )
            )
        elif stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(name, dir_fd=descriptor).encode("utf-8", errors="surrogateescape")
            records.append(
                _entry_record(
                    relative,
                    metadata,
                    kind="symlink",
                    content_sha256=hashlib.sha256(target).hexdigest(),
                )
            )
        else:
            records.append(_entry_record(relative, metadata, kind="other"))


def real_trust_store_snapshot() -> dict[str, object]:
    """Return a raw-value-free content and metadata commitment for the live trust tree."""

    home = passwd_home()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    home_fd = os.open(home, flags)
    opened = [home_fd]
    try:
        current = home_fd
        for component in (".codex", "codexqb-trust"):
            try:
                child = os.open(component, flags, dir_fd=current)
            except FileNotFoundError:
                payload = {"state": "missing", "entry_count": 0, "byte_count": 0, "entries": []}
                canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
                return {
                    "schema_version": 1,
                    "state": "missing",
                    "entry_count": 0,
                    "byte_count": 0,
                    "digest": hashlib.sha256(canonical).hexdigest(),
                }
            opened.append(child)
            current = child
        root_metadata = os.fstat(current)
        records = [_entry_record((), root_metadata, kind="directory")]
        budget = {"entries": 1, "bytes": 0}
        _snapshot_directory(current, (), records, budget)
        records.sort(key=lambda item: str(item["path_sha256"]))
        payload = {
            "state": "present",
            "entry_count": budget["entries"],
            "byte_count": budget["bytes"],
            "entries": records,
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {
            "schema_version": 1,
            "state": "present",
            "entry_count": budget["entries"],
            "byte_count": budget["bytes"],
            "digest": hashlib.sha256(canonical).hexdigest(),
        }
    finally:
        for descriptor in reversed(opened):
            os.close(descriptor)


@contextmanager
def assert_real_trust_store_unchanged() -> Iterator[None]:
    before = real_trust_store_snapshot()
    try:
        yield
    finally:
        after = real_trust_store_snapshot()
        if after != before:
            raise AssertionError("real_controller_trust_store_changed_during_test")


def _write_snapshot(output: Path) -> None:
    if not output.is_absolute():
        raise ValueError("trust_snapshot_output_not_absolute")
    payload = json.dumps(real_trust_store_snapshot(), sort_keys=True, separators=(",", ":")) + "\n"
    descriptor = os.open(
        output,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        os.write(descriptor, payload.encode("utf-8"))
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _verify_snapshot(baseline: Path) -> None:
    data = baseline.read_bytes()
    if len(data) > 4096:
        raise ValueError("trust_snapshot_baseline_oversize")
    expected = json.loads(data.decode("utf-8"))
    if expected != real_trust_store_snapshot():
        raise ValueError("real_controller_trust_store_changed_during_validation")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Guard the live controller trust tree during tests.")
    sub = parser.add_subparsers(dest="command", required=True)
    capture = sub.add_parser("capture")
    capture.add_argument("--output", required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--baseline", required=True)
    args = parser.parse_args(argv)
    if args.command == "capture":
        _write_snapshot(Path(args.output))
        print("real_controller_trust_guard=captured")
        return 0
    _verify_snapshot(Path(args.baseline))
    print("real_controller_trust_guard=unchanged")
    return 0


if __name__ == "__main__":
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.flags.optimize == 0
    ):
        raise SystemExit("test_controller_guard_requires_python_-I_-S_-B")
    raise SystemExit(main())
