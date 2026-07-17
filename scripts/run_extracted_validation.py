#!/usr/bin/env python3
"""Pair-bind a selected checkout, source ZIP, and extracted root for diagnostics.

This controller emits unsigned, hash-bound diagnostic evidence only.  It is
never host attestation, Goal/Apply authority, VERIFIED evidence, Step 4
readiness, or finalization authority.  The checkout is selected explicitly by
an externally asserted exact HEAD; target package code is not executed.
"""

from __future__ import annotations

import argparse
from functools import partial
import hashlib
import importlib.abc
import importlib.util
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import BinaryIO
import zipfile


if __name__ == "__main__" and not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
):
    sys.stderr.write(
        "extracted_package_admission=unsupported "
        "reason=requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)


def _early_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument("--expected-head")
    values, _unknown = parser.parse_known_args(argv)
    return values


_EARLY = _early_arguments(sys.argv[1:] if __name__ == "__main__" else [])
_EXECUTING_LAUNCHER = Path(os.path.abspath(__file__))
TRUSTED_ROOT = _EXECUTING_LAUNCHER.parents[1]
_SOURCE_SELECTION_ASSURANCE = "controller_observed_explicit_source_selection"
_OID_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})")
_MAX_BOOTSTRAP_FILE_BYTES = 4 * 1024 * 1024
_MAX_BOOTSTRAP_TOTAL_BYTES = 32 * 1024 * 1024
_TRUSTED_BUNDLE_PATHS = (
    "scripts/run_extracted_validation.py",
    "scripts/validate.sh",
    "scripts/check_repository_io_policy.py",
    "scripts/export_sanitized.py",
    "scripts/extract_verified_package.py",
    "scripts/verify_package_manifest.py",
    "scripts/package_policy.py",
    "scripts/run_test_suite.py",
    "evals/run_apply_behavior_smoke.py",
    "evals/run_downstream_goal_apply_dry_run.py",
    "evals/run_fixture_corpus_checks.py",
    "evals/run_goal_apply_metric_checks.py",
    "plugins/codexqb/skills/codexqb/scripts/apply_run.py",
    "plugins/codexqb/skills/codexqb/scripts/artifact_io.py",
    "plugins/codexqb/skills/codexqb/scripts/controller_store.py",
    "plugins/codexqb/skills/codexqb/scripts/doctor.py",
    "plugins/codexqb/skills/codexqb/scripts/evidence_contracts.py",
    "plugins/codexqb/skills/codexqb/scripts/execution_controller.py",
    "plugins/codexqb/skills/codexqb/scripts/git_evidence.py",
    "plugins/codexqb/skills/codexqb/scripts/goal_run.py",
    "plugins/codexqb/skills/codexqb/scripts/mount_identity.py",
    "plugins/codexqb/skills/codexqb/scripts/repository_evidence.py",
    "plugins/codexqb/skills/codexqb/scripts/repository_io.py",
    "plugins/codexqb/skills/codexqb/scripts/repository_io_policy.py",
    "plugins/codexqb/skills/codexqb/scripts/repository_validation.py",
    "plugins/codexqb/skills/codexqb/scripts/safety_contracts.py",
    "plugins/codexqb/skills/codexqb/scripts/skill_launcher.py",
    "plugins/codexqb/skills/codexqb/scripts/skill_root_authority.py",
    "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
)
_BOOTSTRAP_PAYLOADS: dict[str, bytes] = {}
_BOOTSTRAP_RECORDS: dict[str, dict[str, object]] = {}
_CAPTURED_TRUSTED_HEAD: str | None = None
_CAPTURED_BUNDLE_SHA256: str | None = None
_CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256: str | None = None


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def _bootstrap_digest(value: object) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _bootstrap_file_snapshot(
    root_descriptor: int,
    relative: str,
) -> tuple[dict[str, object], bytes] | None:
    components = relative.split("/")
    if not components or any(value in {"", ".", ".."} for value in components):
        return None
    descriptors: list[int] = []
    parent = root_descriptor
    try:
        root = os.fstat(root_descriptor)
        for component in components[:-1]:
            descriptor = os.open(
                component,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent,
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_dev != root.st_dev
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                os.close(descriptor)
                return None
            descriptors.append(descriptor)
            parent = descriptor
        before = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        descriptor = os.open(
            components[-1],
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            dir_fd=parent,
        )
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_dev != root.st_dev
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or opened.st_size > _MAX_BOOTSTRAP_FILE_BYTES
            or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
            != (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        ):
            return None
        payload = bytearray()
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            payload.extend(chunk)
            if len(payload) > _MAX_BOOTSTRAP_FILE_BYTES:
                return None
            digest.update(chunk)
        after = os.fstat(descriptor)
        final = os.stat(components[-1], dir_fd=parent, follow_symlinks=False)
        identity = (
            int(opened.st_dev),
            int(opened.st_ino),
            int(opened.st_mode),
            int(opened.st_size),
            int(opened.st_mtime_ns),
            int(opened.st_ctime_ns),
        )
        if (
            len(payload) != opened.st_size
            or identity
            != (
                int(after.st_dev),
                int(after.st_ino),
                int(after.st_mode),
                int(after.st_size),
                int(after.st_mtime_ns),
                int(after.st_ctime_ns),
            )
            or (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns)
        ):
            return None
        return (
            {
                "identity": identity,
                "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
                "path": relative,
                "sha256": digest.hexdigest(),
                "size": len(payload),
            },
            bytes(payload),
        )
    except OSError:
        return None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _bootstrap_capture_bundle(
    root_descriptor: int,
) -> tuple[str, dict[str, dict[str, object]], dict[str, bytes]] | None:
    records: dict[str, dict[str, object]] = {}
    payloads: dict[str, bytes] = {}
    total = 0
    for relative in _TRUSTED_BUNDLE_PATHS:
        snapshot = _bootstrap_file_snapshot(root_descriptor, relative)
        if snapshot is None:
            return None
        record, payload = snapshot
        total += len(payload)
        if total > _MAX_BOOTSTRAP_TOTAL_BYTES:
            return None
        records[relative] = record
        payloads[relative] = payload
    binding = [
        {
            "mode": records[path]["mode"],
            "path": path,
            "sha256": records[path]["sha256"],
            "size": records[path]["size"],
        }
        for path in sorted(records)
    ]
    return _bootstrap_digest(binding), records, payloads


class _HeldBundleFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
    def __init__(self, payloads: dict[str, bytes]) -> None:
        self.sources: dict[str, tuple[str, bytes]] = {}
        for relative, payload in payloads.items():
            if not relative.endswith(".py"):
                continue
            module = Path(relative).stem
            if module in self.sources:
                raise RuntimeError("trusted_bundle_module_collision")
            self.sources[module] = (relative, payload)

    def find_spec(self, fullname, path=None, target=None):
        if "." in fullname or fullname not in self.sources:
            return None
        relative, _payload = self.sources[fullname]
        return importlib.util.spec_from_loader(
            fullname,
            self,
            origin=(TRUSTED_ROOT / relative).as_posix(),
        )

    def create_module(self, spec):
        return None

    def exec_module(self, module) -> None:
        relative, payload = self.sources[module.__name__]
        origin = (TRUSTED_ROOT / relative).as_posix()
        module.__file__ = origin
        exec(
            compile(payload, origin, "exec", dont_inherit=True, optimize=0),
            module.__dict__,
        )


def _selected_workspace_evidence(
    payloads: dict[str, bytes],
    expected_head: str,
) -> str | None:
    finder = _HeldBundleFinder(payloads)
    try:
        sys.meta_path.insert(0, finder)
        git_evidence = __import__("git_evidence")
        evidence = git_evidence.capture_git_workspace_evidence(TRUSTED_ROOT)
    except (ImportError, OSError, RuntimeError, TypeError, ValueError):
        return None
    finally:
        try:
            sys.meta_path.remove(finder)
        except ValueError:
            pass
    if (
        evidence.get("is_git") is not True
        or evidence.get("head") != expected_head
        or evidence.get("staged_changes") != []
        or evidence.get("unstaged_changes") != []
        or evidence.get("untracked_paths") != []
    ):
        return None
    return _bootstrap_digest(
        {
            "approved_head": expected_head,
            "git_evidence_schema_version": evidence.get("schema_version"),
            "staged_diff_sha256": evidence.get("staged_diff_sha256"),
            "status_sha256": evidence.get("status_sha256"),
            "unstaged_diff_sha256": evidence.get("unstaged_diff_sha256"),
            "untracked_paths_sha256": evidence.get("untracked_paths_sha256"),
        }
    )


def _checkout_bootstrap_error() -> str | None:
    global _BOOTSTRAP_PAYLOADS
    global _BOOTSTRAP_RECORDS
    global _CAPTURED_BUNDLE_SHA256
    global _CAPTURED_TRUSTED_HEAD
    global _CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256

    if __name__ != "__main__" or not _EARLY.expected_head:
        return "explicit_expected_head_required"
    if _OID_RE.fullmatch(_EARLY.expected_head) is None:
        return "expected_head_invalid"
    root_fd = -1
    try:
        before = os.stat(TRUSTED_ROOT, follow_symlinks=False)
        root_fd = os.open(
            TRUSTED_ROOT,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        opened = os.fstat(root_fd)
        after = os.stat(TRUSTED_ROOT, follow_symlinks=False)
        if (
            not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
        ):
            return "selected_checkout_root_untrusted"
        captured = _bootstrap_capture_bundle(root_fd)
        if captured is None:
            return "selected_controller_bundle_unavailable"
        bundle_sha256, records, payloads = captured
        launcher = records.get("scripts/run_extracted_validation.py")
        executing = os.stat(_EXECUTING_LAUNCHER, follow_symlinks=False)
        if (
            not isinstance(launcher, dict)
            or tuple(launcher.get("identity", ())[:2])
            != (int(executing.st_dev), int(executing.st_ino))
        ):
            return "selected_launcher_identity_mismatch"
        workspace_sha256 = _selected_workspace_evidence(
            payloads,
            _EARLY.expected_head,
        )
        if workspace_sha256 is None:
            return "selected_checkout_head_or_workspace_mismatch"
        final = _bootstrap_capture_bundle(root_fd)
        if (
            final is None
            or final[0] != bundle_sha256
            or final[1] != records
            or final[2] != payloads
        ):
            return "selected_controller_bundle_changed"
        root_identity = {
            "device": int(opened.st_dev),
            "gid": int(opened.st_gid),
            "inode": int(opened.st_ino),
            "mode": int(opened.st_mode),
            "uid": int(opened.st_uid),
        }
        _BOOTSTRAP_PAYLOADS = payloads
        _BOOTSTRAP_RECORDS = records
        _CAPTURED_BUNDLE_SHA256 = bundle_sha256
        _CAPTURED_TRUSTED_HEAD = _EARLY.expected_head
        _CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256 = _bootstrap_digest(root_identity)
        return None
    except (OSError, RuntimeError, TypeError, ValueError):
        return "selected_checkout_internal_failure"
    finally:
        if root_fd >= 0:
            os.close(root_fd)


_TRUSTED_CHECKOUT_BOOTSTRAP_ERROR = _checkout_bootstrap_error()
if _TRUSTED_CHECKOUT_BOOTSTRAP_ERROR is None:
    _HELD_FINDER = _HeldBundleFinder(_BOOTSTRAP_PAYLOADS)
    sys.meta_path.insert(0, _HELD_FINDER)

    from mount_identity import (
        READ_ONLY_EVIDENCE,
        require_mount_assurance,
        require_same_mount,
        resolve_mount_identity,
    )
    from package_policy import (
        PACKAGE_MANIFEST_NAME,
        SOURCE_ARTIFACT,
        SOURCE_CONTROLLER_ONLY_PATHS,
        archive_prefix,
        manifest_member,
        source_controller_path,
    )
    from repository_io import (
        _controller_workspace_proof as controller_workspace_proof,
        _require_local_authority_mount_resolution,
        open_repository_io,
    )
    from verify_package_manifest import (
        MAX_ARTIFACT_FILE_BYTES,
        MAX_MANIFEST_BYTES,
        MAX_PACKAGE_ARCHIVE_BYTES,
        directory_inventory,
        manifest_contract_errors,
        manifest_entries,
        parse_manifest,
        regular_file_bytes,
        regular_file_evidence,
        secure_directory_flags,
        verify_zip,
    )


def _make_held_bundle(payloads: dict[str, bytes]):
    stream = tempfile.TemporaryFile(mode="w+b")
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_STORED) as archive:
        for relative in sorted(payloads):
            archive.writestr(relative, payloads[relative])
    stream.flush()
    os.fsync(stream.fileno())
    stream.seek(0)
    return stream


_HELD_CODE_STREAM = (
    _make_held_bundle(_BOOTSTRAP_PAYLOADS)
    if _TRUSTED_CHECKOUT_BOOTSTRAP_ERROR is None
    else None
)
_HELD_RUNNER = r"""
import hashlib,importlib.abc,importlib.util,os,stat,sys,tempfile,zipfile
fd=int(sys.argv[1]); selected=sys.argv[2]; forwarded=sys.argv[3:]
with os.fdopen(os.dup(fd),"rb") as stream:
    with zipfile.ZipFile(stream) as archive:
        sources={name:archive.read(name) for name in archive.namelist() if name.endswith(".py")}
with tempfile.TemporaryDirectory(prefix="codexqb-held-controller-") as snapshot:
    os.chmod(snapshot,0o700)
    directories={snapshot}
    for relative,payload in sorted(sources.items()):
        parts=relative.split("/")
        if any(part in {"",".",".."} for part in parts):raise RuntimeError("held_path_invalid")
        parent=snapshot
        for part in parts[:-1]:
            parent=os.path.join(parent,part)
            if not os.path.exists(parent):os.mkdir(parent,0o700)
            directories.add(parent)
        path=os.path.join(snapshot,*parts)
        out=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
        try:
            view=memoryview(payload)
            while view:
                written=os.write(out,view)
                if written<=0:raise RuntimeError("held_write_failed")
                view=view[written:]
            os.fsync(out);os.fchmod(out,0o400)
        finally:os.close(out)
    for directory in sorted(directories,key=lambda value:value.count(os.sep),reverse=True):
        descriptor=os.open(directory,os.O_RDONLY|getattr(os,"O_DIRECTORY",0)|getattr(os,"O_NOFOLLOW",0))
        try:os.fsync(descriptor)
        finally:os.close(descriptor)
        os.chmod(directory,0o500)
    def snapshot_hashes():
        return {relative:hashlib.sha256(open(os.path.join(snapshot,relative),"rb").read()).hexdigest() for relative in sorted(sources)}
    expected={relative:hashlib.sha256(payload).hexdigest() for relative,payload in sources.items()}
    if snapshot_hashes()!=expected:raise RuntimeError("held_snapshot_mismatch")
    modules={}
    for relative,payload in sources.items():
        name=relative.rsplit("/",1)[-1][:-3]
        if name in modules:raise RuntimeError("held_module_collision")
        modules[name]=(relative,payload)
    class Finder(importlib.abc.MetaPathFinder,importlib.abc.Loader):
        def find_spec(self,fullname,path=None,target=None):
            if "." in fullname or fullname not in modules:return None
            return importlib.util.spec_from_loader(fullname,self,origin=os.path.join(snapshot,modules[fullname][0]))
        def create_module(self,spec):return None
        def exec_module(self,module):
            relative,payload=modules[module.__name__]
            origin=os.path.join(snapshot,relative)
            module.__file__=origin
            exec(compile(payload,origin,"exec",dont_inherit=True,optimize=0),module.__dict__)
    sys.meta_path.insert(0,Finder())
    if selected=="__codexqb_static_policy__":
        if len(forwarded)!=1:raise RuntimeError("held_policy_arguments_invalid")
        checker=__import__("check_repository_io_policy")
        status=checker.main(["--root",".","--layout",forwarded[0],"--target-data-only"])
        if snapshot_hashes()!=expected:raise RuntimeError("held_snapshot_changed")
        if status!=0:raise SystemExit(status)
    else:
        if selected not in sources:raise RuntimeError("held_script_missing")
        origin=os.path.join(snapshot,selected)
        sys.argv=[origin,*forwarded]
        scope={"__name__":"__main__","__file__":origin,"__package__":None,"__spec__":None}
        exec(compile(sources[selected],origin,"exec",dont_inherit=True,optimize=0),scope)
"""


_PROFILES = ("static",)
_MAX_COMPONENT_OUTPUT_BYTES = 16 * 1024 * 1024
_MAX_COMPONENT_STATUS_SCAN_BYTES = 64 * 1024
_MAX_COMPONENT_STATUS_LINES = 256
_COMPONENT_TIMEOUT_SECONDS = 180
_SAFE_COMPONENT_STATUS_LINES = frozenset(
    {
        b"artifact_root=.",
        b"artifact_root=CodexQB",
        b"artifact_type=plugin",
        b"artifact_type=source",
        b"export_mode=filesystem",
        b"export_mode=strict-release",
        b"export_mode=worktree",
        b"output=created",
        b"package_extract_verification=passed",
        b"package_manifest_verification=passed",
        b"real_controller_trust_guard=unchanged",
        b"sanitized_export=created",
    }
)
_SAFE_COMPONENT_POLICY_STATUS_RE = re.compile(
    rb"repository_io_policy=passed external_attestation=false "
    rb"layout_bound=(?:true|false) "
    rb"layout=(?:repository-plugin|extracted-plugin)"
)
_SAFE_COMPONENT_COUNT_STATUS_RE = re.compile(rb"file_count=(?:0|[1-9][0-9]{0,8})")


class AdmissionError(ValueError):
    pass


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def _full_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        int(metadata.st_dev),
        int(metadata.st_ino),
        int(metadata.st_mode),
        int(metadata.st_nlink),
        int(metadata.st_uid),
        int(metadata.st_gid),
        int(metadata.st_size),
        int(metadata.st_mtime_ns),
        int(metadata.st_ctime_ns),
    )


def _snapshot_archive(path: Path, destination: BinaryIO) -> tuple[str, tuple[int, ...]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = -1
    try:
        before = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if (
            _full_identity(before) != _full_identity(opened)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or opened.st_size > MAX_PACKAGE_ARCHIVE_BYTES
        ):
            raise AdmissionError("archive_untrusted")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(1024 * 1024, MAX_PACKAGE_ARCHIVE_BYTES + 1 - total),
            )
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PACKAGE_ARCHIVE_BYTES:
                raise AdmissionError("archive_budget_exceeded")
            digest.update(chunk)
            destination.write(chunk)
        after = os.fstat(descriptor)
        final = os.stat(path, follow_symlinks=False)
        if (
            total != opened.st_size
            or _full_identity(opened) != _full_identity(after)
            or _full_identity(after) != _full_identity(final)
        ):
            raise AdmissionError("archive_changed")
        destination.flush()
        destination.seek(0)
        return digest.hexdigest(), _full_identity(opened)
    except AdmissionError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise AdmissionError("archive_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _archive_contract(snapshot: BinaryIO) -> dict[str, object]:
    snapshot.seek(0)
    errors = verify_zip(snapshot, expected_artifact_type=SOURCE_ARTIFACT)
    if errors:
        raise AdmissionError("archive_contract_failed")
    snapshot.seek(0)
    try:
        with zipfile.ZipFile(snapshot) as archive:
            manifest_name = manifest_member(SOURCE_ARTIFACT)
            manifest_data = archive.read(manifest_name)
            manifest, parse_errors = parse_manifest(manifest_data)
            if manifest is None or parse_errors or manifest_contract_errors(manifest):
                raise AdmissionError("archive_manifest_invalid")
            if manifest.get("artifact_type") != SOURCE_ARTIFACT:
                raise AdmissionError("archive_artifact_type_invalid")
            entries, entry_errors = manifest_entries(manifest)
            if entry_errors:
                raise AdmissionError("archive_manifest_entries_invalid")
            if any(source_controller_path(str(entry.get("path"))) for entry in entries):
                raise AdmissionError("archive_controller_entrypoint_forbidden")
            prefix = archive_prefix(SOURCE_ARTIFACT)
            records: list[dict[str, object]] = []
            for entry in entries:
                info = archive.getinfo(f"{prefix}{entry['path']}")
                records.append(
                    {
                        "path": entry["path"],
                        "mode": entry["mode"],
                        "size": int(info.file_size),
                        "sha256": entry["sha256"],
                    }
                )
            manifest_info = archive.getinfo(manifest_name)
            manifest_record = {
                "path": PACKAGE_MANIFEST_NAME,
                "mode": "0644",
                "size": len(manifest_data),
                "sha256": hashlib.sha256(manifest_data).hexdigest(),
            }
    except AdmissionError:
        raise
    except (KeyError, OSError, RuntimeError, ValueError, zipfile.BadZipFile) as exc:
        raise AdmissionError("archive_evidence_unavailable") from exc
    records.sort(key=lambda item: str(item["path"]))
    complete_records = [*records, manifest_record]
    complete_records.sort(key=lambda item: str(item["path"]))
    return {
        "manifest": manifest,
        "manifest_data": manifest_data,
        "manifest_sha256": manifest_record["sha256"],
        "records": tuple(records),
        "inventory_sha256": _canonical_digest(complete_records),
        "content_sha256": manifest.get("content_sha256"),
    }


def _open_root(path: Path) -> tuple[int, tuple[int, ...], object]:
    flags = secure_directory_flags()
    if flags is None:
        raise AdmissionError("root_secure_open_unavailable")
    descriptor = -1
    try:
        before = os.stat(path, follow_symlinks=False)
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        after = os.stat(path, follow_symlinks=False)
        identity = _full_identity(opened)
        if (
            _full_identity(before) != identity
            or identity != _full_identity(after)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise AdmissionError("root_untrusted")
        resolution = resolve_mount_identity(descriptor, reconcile=True)
        require_mount_assurance(resolution, READ_ONLY_EVIDENCE)
        require_same_mount(resolution, descriptor, ".")
        _require_local_authority_mount_resolution(resolution)
        result = descriptor, identity, resolution
        descriptor = -1
        return result
    except AdmissionError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise AdmissionError("root_unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _require_path_identity(path: Path, descriptor: int, expected: tuple[int, ...]) -> None:
    try:
        lexical = os.stat(path, follow_symlinks=False)
        opened = os.fstat(descriptor)
    except OSError as exc:
        raise AdmissionError("root_changed") from exc
    if _full_identity(lexical) != expected or _full_identity(opened) != expected:
        raise AdmissionError("root_changed")


def _verify_record(
    root_descriptor: int,
    resolution: object,
    record: dict[str, object],
    expected_identity: tuple[int, ...] | None,
) -> tuple[int, ...]:
    digest, size, mode, identity, nested_zip, secret_content = (
        regular_file_evidence(
            root_descriptor,
            str(record["path"]),
            min(MAX_ARTIFACT_FILE_BYTES, int(record["size"])),
            resolution,
        )
    )
    if (
        digest != record["sha256"]
        or size != record["size"]
        or mode != record["mode"]
        or identity is None
        or nested_zip
        or secret_content
        or (expected_identity is not None and identity != expected_identity)
    ):
        raise AdmissionError("package_record_mismatch")
    return identity


def _verify_target_pair(
    root_path: Path,
    root_descriptor: int,
    root_identity: tuple[int, ...],
    resolution: object,
    package: dict[str, object],
) -> str:
    _require_path_identity(root_path, root_descriptor, root_identity)
    manifest_result = regular_file_bytes(
        root_descriptor,
        PACKAGE_MANIFEST_NAME,
        MAX_MANIFEST_BYTES,
        resolution,
    )
    if (
        manifest_result is None
        or manifest_result[0] != package["manifest_data"]
        or manifest_result[1] != "0644"
    ):
        raise AdmissionError("extracted_manifest_not_archive_bound")
    records = tuple(package["records"])
    expected_paths = tuple(str(item["path"]) for item in records)
    inventory, total, failed, exceeded, inventory_errors = directory_inventory(
        root_descriptor,
        strict_artifact=True,
        artifact_type=SOURCE_ARTIFACT,
        root_resolution=resolution,
        expected_file_paths=expected_paths,
    )
    if failed or exceeded or inventory_errors:
        raise AdmissionError("extracted_inventory_unavailable")
    expected_set = {*expected_paths, PACKAGE_MANIFEST_NAME}
    if set(inventory) != expected_set:
        raise AdmissionError("extracted_inventory_mismatch")
    expected_total = len(package["manifest_data"]) + sum(
        int(item["size"]) for item in records
    )
    if total != expected_total:
        raise AdmissionError("extracted_size_mismatch")
    evidence: list[dict[str, object]] = []
    for record in records:
        identity = _verify_record(
            root_descriptor,
            resolution,
            record,
            inventory.get(str(record["path"])),
        )
        evidence.append(
            {
                "path_sha256": hashlib.sha256(
                    str(record["path"]).encode("utf-8")
                ).hexdigest(),
                "identity": identity,
            }
        )
    final_inventory, final_total, final_failed, final_exceeded, final_errors = (
        directory_inventory(
            root_descriptor,
            strict_artifact=True,
            artifact_type=SOURCE_ARTIFACT,
            root_resolution=resolution,
            expected_file_paths=expected_paths,
        )
    )
    if (
        final_failed
        or final_exceeded
        or final_errors
        or final_inventory != inventory
        or final_total != total
    ):
        raise AdmissionError("extracted_inventory_changed")
    _require_path_identity(root_path, root_descriptor, root_identity)
    return _canonical_digest(evidence)


def _verify_trusted_source(
    trusted_descriptor: int,
    trusted_resolution: object,
    records: tuple[dict[str, object], ...],
) -> tuple[str, str]:
    archive_paths = tuple(str(item["path"]) for item in records)
    for record in records:
        _verify_record(
            trusted_descriptor,
            trusted_resolution,
            record,
            None,
        )
    controller_records: list[dict[str, object]] = []
    for relative in sorted(SOURCE_CONTROLLER_ONLY_PATHS):
        digest, size, mode, identity, nested_zip, secret_content = (
            regular_file_evidence(
                trusted_descriptor,
                relative,
                MAX_ARTIFACT_FILE_BYTES,
                trusted_resolution,
            )
        )
        if (
            digest is None
            or size is None
            or mode is None
            or identity is None
            or nested_zip
            or secret_content
        ):
            raise AdmissionError("trusted_controller_inventory_mismatch")
        controller_records.append(
            {
                "path": relative,
                "mode": mode,
                "size": size,
                "sha256": digest,
            }
        )
    complete_records = sorted(
        [*records, *controller_records],
        key=lambda item: str(item["path"]),
    )
    final_records: list[dict[str, object]] = []
    for record in complete_records:
        digest, size, mode, identity, nested_zip, secret_content = (
            regular_file_evidence(
                trusted_descriptor,
                str(record["path"]),
                MAX_ARTIFACT_FILE_BYTES,
                trusted_resolution,
            )
        )
        if (
            digest is None
            or size is None
            or mode is None
            or identity is None
            or nested_zip
            or secret_content
        ):
            raise AdmissionError("trusted_source_inventory_changed")
        final_records.append(
            {"path": record["path"], "mode": mode, "size": size, "sha256": digest}
        )
    final_records.sort(key=lambda item: str(item["path"]))
    if final_records != complete_records:
        raise AdmissionError("trusted_source_inventory_changed")
    records_by_path = {str(item["path"]): item for item in complete_records}
    if not set(_TRUSTED_BUNDLE_PATHS).issubset(records_by_path):
        raise AdmissionError("trusted_bundle_inventory_missing")
    return (
        _canonical_digest(complete_records),
        _canonical_digest(
            [records_by_path[path] for path in sorted(_TRUSTED_BUNDLE_PATHS)]
        ),
    )


def _trusted_workspace_binding(package: dict[str, object]) -> str:
    manifest = package.get("manifest")
    if not isinstance(manifest, dict):
        raise AdmissionError("archive_manifest_invalid")
    try:
        with open_repository_io(TRUSTED_ROOT) as repository:
            proof = controller_workspace_proof(repository)
    except (OSError, TypeError, ValueError) as exc:
        raise AdmissionError("trusted_checkout_workspace_proof_failed") from exc
    head = proof.evidence.get("head")
    tracked_paths = proof.evidence.get("tracked_paths")
    expected_tracked_paths = sorted(
        {
            *(str(item["path"]) for item in package.get("records", ())),
            *SOURCE_CONTROLLER_ONLY_PATHS,
        }
    )
    if (
        proof.evidence.get("is_git") is not True
        or not isinstance(head, str)
        or tracked_paths != expected_tracked_paths
        or manifest.get("git_provenance_available") is not True
        or manifest.get("git_commit") != head
    ):
        raise AdmissionError("archive_not_bound_to_trusted_checkout_head")
    return _canonical_digest(
        {
            "evidence_sha256": proof.receipt.sha256,
            "mount_assurance": proof.mount_assurance,
            "mount_provider": proof.mount_provider,
            "repository_identity_sha256": proof.repository_identity_sha256,
        }
    )


def _component_environment(controller_temp: Path) -> dict[str, str]:
    executable_dir = Path(sys.executable).resolve(strict=True).parent.as_posix()
    home = controller_temp / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    return {
        "HOME": home.as_posix(),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": f"{executable_dir}:/usr/bin:/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _enter_component_root(root_descriptor: int) -> None:
    os.fchdir(root_descriptor)


def _stop_component(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def _forward_output(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        view = view[written:]


def _safe_component_status_lines(data: bytes) -> tuple[bytes, ...]:
    """Return only closed, content-free success statuses from child stdout."""

    if len(data) > _MAX_COMPONENT_STATUS_SCAN_BYTES:
        return ()
    raw_lines = data.split(b"\n")
    if len(raw_lines) > _MAX_COMPONENT_STATUS_LINES + 1:
        return ()
    accepted: list[bytes] = []
    seen: set[bytes] = set()
    for line in raw_lines:
        if not line or line in seen:
            continue
        if (
            line in _SAFE_COMPONENT_STATUS_LINES
            or _SAFE_COMPONENT_POLICY_STATUS_RE.fullmatch(line) is not None
            or _SAFE_COMPONENT_COUNT_STATUS_RE.fullmatch(line) is not None
        ):
            accepted.append(line)
            seen.add(line)
    return tuple(accepted)


def _emit_component_diagnostics(
    record: dict[str, object],
    stdout: bytes,
    *,
    successful: bool,
) -> None:
    lines: list[bytes] = []
    if successful:
        lines.extend(_safe_component_status_lines(stdout))
    for field in (
        "argv_sha256",
        "stdout_sha256",
        "stderr_sha256",
    ):
        value = record[field]
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise AdmissionError("trusted_component_diagnostic_invalid")
        lines.append(f"trusted_component_{field}={value}".encode("ascii"))
    _forward_output(1, b"\n".join(lines) + b"\n")


def _run_trusted_component(
    root_descriptor: int,
    argv: tuple[str, ...],
    environment: dict[str, str],
    *,
    failure_code: str,
) -> dict[str, object]:
    if (
        os.name != "posix"
        or threading.active_count() != 1
        or _HELD_CODE_STREAM is None
    ):
        raise AdmissionError("trusted_component_isolation_unavailable")
    if not argv or not all(isinstance(value, str) and value for value in argv):
        raise AdmissionError("trusted_component_command_invalid")
    try:
        process = subprocess.Popen(
            argv,
            cwd=None,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=(root_descriptor, _HELD_CODE_STREAM.fileno()),
            preexec_fn=partial(_enter_component_root, root_descriptor),
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise AdmissionError(failure_code) from exc
    selector: selectors.BaseSelector | None = None
    stdout_buffer = bytearray()
    stderr_buffer = bytearray()
    deadline = time.monotonic() + _COMPONENT_TIMEOUT_SECONDS
    failure: str | None = None
    try:
        if process.stdout is None or process.stderr is None:
            failure = failure_code
        else:
            selector = selectors.DefaultSelector()
            for stream, buffer in (
                (process.stdout, stdout_buffer),
                (process.stderr, stderr_buffer),
            ):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, buffer)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure = "trusted_component_timeout"
                    break
                for key, _events in selector.select(min(0.1, remaining)):
                    buffer = key.data
                    try:
                        chunk = os.read(key.fileobj.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                        continue
                    buffer.extend(chunk)
                    if (
                        len(stdout_buffer) + len(stderr_buffer)
                        > _MAX_COMPONENT_OUTPUT_BYTES
                    ):
                        failure = "trusted_component_output_limit_exceeded"
                        break
                if failure is not None:
                    break
        if failure is not None:
            _stop_component(process)
        try:
            returncode = process.wait(
                timeout=max(0.0, deadline - time.monotonic())
            )
        except subprocess.TimeoutExpired:
            failure = "trusted_component_timeout"
            _stop_component(process)
            returncode = process.wait()
    except (OSError, ValueError) as exc:
        _stop_component(process)
        process.wait()
        raise AdmissionError(failure_code) from exc
    finally:
        if selector is not None:
            selector.close()
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    if failure is not None:
        raise AdmissionError(failure)
    stdout = bytes(stdout_buffer)
    stderr = bytes(stderr_buffer)
    record = {
        "argv_sha256": _canonical_digest(list(argv)),
        "returncode": int(returncode),
        "stderr_sha256": hashlib.sha256(stderr).hexdigest(),
        "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
    }
    _emit_component_diagnostics(
        record,
        stdout,
        successful=returncode == 0,
    )
    if returncode != 0:
        raise AdmissionError(failure_code)
    return record


def _python_command(relative: str, *arguments: str) -> tuple[str, ...]:
    if (
        _HELD_CODE_STREAM is None
        or relative not in _BOOTSTRAP_PAYLOADS
        or not relative.endswith(".py")
    ):
        raise AdmissionError("trusted_component_path_invalid")
    return (
        Path(sys.executable).resolve(strict=True).as_posix(),
        "-I",
        "-S",
        "-B",
        "-c",
        _HELD_RUNNER,
        str(_HELD_CODE_STREAM.fileno()),
        relative,
        *arguments,
    )


def _run_policy_checker(
    root_descriptor: int,
    environment: dict[str, str],
    *,
    layout: str = "repository-plugin",
) -> dict[str, object]:
    return _run_trusted_component(
        root_descriptor,
        (
            Path(sys.executable).resolve(strict=True).as_posix(),
            "-I",
            "-S",
            "-B",
            "-c",
            _HELD_RUNNER,
            str(_HELD_CODE_STREAM.fileno()) if _HELD_CODE_STREAM else "-1",
            "__codexqb_static_policy__",
            layout,
        ),
        environment,
        failure_code="trusted_policy_rejected_target",
    )


def _run_package_components(
    root_descriptor: int,
    environment: dict[str, str],
    *,
    skip_unit_tests: bool,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory(prefix="codexqb-external-package-") as temp_name:
        temp = Path(temp_name)
        os.chmod(temp, 0o700)
        plugin_zip = temp / "codexqb-plugin-filesystem.zip"
        source_zip = temp / "CodexQB-source-filesystem.zip"
        plugin_root = temp / "plugin"
        source_parent = temp / "source"
        for artifact_type, output in (
            ("plugin", plugin_zip),
            ("source", source_zip),
        ):
            records.append(
                _run_trusted_component(
                    root_descriptor,
                    _python_command(
                        "scripts/export_sanitized.py",
                        "--root",
                        ".",
                        "--artifact-type",
                        artifact_type,
                        "--provenance-mode",
                        "filesystem",
                        "--output",
                        output.as_posix(),
                    ),
                    environment,
                    failure_code="trusted_package_export_failed",
                )
            )
            records.append(
                _run_trusted_component(
                    root_descriptor,
                    _python_command(
                        "scripts/verify_package_manifest.py",
                        "--zip",
                        output.as_posix(),
                    ),
                    environment,
                    failure_code="trusted_package_verification_failed",
                )
            )
        for archive, output, artifact_type in (
            (plugin_zip, plugin_root, "plugin"),
            (source_zip, source_parent, "source"),
        ):
            records.append(
                _run_trusted_component(
                    root_descriptor,
                    _python_command(
                        "scripts/extract_verified_package.py",
                        "--zip",
                        archive.as_posix(),
                        "--output",
                        output.as_posix(),
                        "--artifact-type",
                        artifact_type,
                    ),
                    environment,
                    failure_code="trusted_package_extraction_failed",
                )
            )
        source_root = source_parent / "CodexQB"
        for artifact_root, artifact_type in (
            (plugin_root, "plugin"),
            (source_root, "source"),
        ):
            records.append(
                _run_trusted_component(
                    root_descriptor,
                    _python_command(
                        "scripts/verify_package_manifest.py",
                        "--root",
                        artifact_root.as_posix(),
                        "--strict-artifact",
                        "--expected-artifact-type",
                        artifact_type,
                    ),
                    environment,
                    failure_code="trusted_extracted_verification_failed",
                )
            )
        opened: list[int] = []
        try:
            plugin_descriptor, _plugin_identity, _plugin_resolution = _open_root(
                plugin_root
            )
            opened.append(plugin_descriptor)
            source_descriptor, _source_identity, _source_resolution = _open_root(
                source_root
            )
            opened.append(source_descriptor)
            records.append(
                _run_policy_checker(
                    plugin_descriptor,
                    environment,
                    layout="extracted-plugin",
                )
            )
            records.append(_run_policy_checker(source_descriptor, environment))
        finally:
            for descriptor in opened:
                os.close(descriptor)
        if skip_unit_tests:
            print("unit_tests_skipped=1")
        else:
            records.append(
                _run_trusted_component(
                    root_descriptor,
                    _python_command("scripts/run_test_suite.py", "package"),
                    environment,
                    failure_code="trusted_package_tests_failed",
                )
            )
    return records


def _run_validation_components(
    root_descriptor: int,
    profile: str,
    environment: dict[str, str],
    *,
    skip_unit_tests: bool,
    skip_behavior_smoke: bool,
) -> tuple[dict[str, object], ...]:
    # PR2 deliberately stops at byte/inventory parity plus static policy.  No
    # extracted/package-controlled Python, tests, behavior smoke, or repository
    # validator executes without the PR4 host-native sandbox.
    if not skip_unit_tests:
        print("unit_tests_deferred_to_pr4=1")
    if not skip_behavior_smoke:
        print("behavior_smokes_deferred_to_pr4=1")
    return (_run_policy_checker(root_descriptor, environment),)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--zip", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--profile", choices=_PROFILES, default="static")
    parser.add_argument("--skip-unit-tests", action="store_true")
    parser.add_argument("--skip-behavior-smoke", action="store_true")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    archive_path = Path(args.zip)
    root_path = Path(args.root)
    root_descriptor = -1
    trusted_descriptor = -1
    try:
        if _TRUSTED_CHECKOUT_BOOTSTRAP_ERROR is not None:
            raise AdmissionError(_TRUSTED_CHECKOUT_BOOTSTRAP_ERROR)
        if args.expected_head != _EARLY.expected_head:
            raise AdmissionError("expected_head_arguments_changed")
        if (
            _CAPTURED_TRUSTED_HEAD != args.expected_head
            or _CAPTURED_BUNDLE_SHA256 is None
            or _CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256 is None
        ):
            raise AdmissionError("selected_checkout_binding_missing")
        if not archive_path.is_absolute() or not root_path.is_absolute():
            raise AdmissionError("admission_paths_must_be_absolute")
        with tempfile.TemporaryFile(mode="w+b") as snapshot:
            archive_sha256, archive_identity = _snapshot_archive(
                archive_path,
                snapshot,
            )
            package = _archive_contract(snapshot)
            root_descriptor, root_identity, root_resolution = _open_root(root_path)
            trusted_descriptor, trusted_identity, trusted_resolution = _open_root(
                TRUSTED_ROOT
            )
            trusted_workspace_sha256 = _trusted_workspace_binding(package)
            trusted_source_sha256, trusted_bundle_sha256 = _verify_trusted_source(
                trusted_descriptor,
                trusted_resolution,
                tuple(package["records"]),
            )
            if trusted_bundle_sha256 != _CAPTURED_BUNDLE_SHA256:
                raise AdmissionError("selected_controller_bundle_mismatch")
            _require_path_identity(
                TRUSTED_ROOT,
                trusted_descriptor,
                trusted_identity,
            )
            pre_state_sha256 = _verify_target_pair(
                root_path,
                root_descriptor,
                root_identity,
                root_resolution,
                package,
            )
            _require_path_identity(root_path, root_descriptor, root_identity)
            root_identity_sha256 = _canonical_digest(root_identity)
            archive_identity_sha256 = _canonical_digest(archive_identity)
            trusted_root_identity_sha256 = _canonical_digest(trusted_identity)
            trusted_root_path_sha256 = hashlib.sha256(
                TRUSTED_ROOT.as_posix().encode("utf-8")
            ).hexdigest()
            pair_digest = _canonical_digest(
                {
                    "archive_identity_sha256": archive_identity_sha256,
                    "archive_sha256": archive_sha256,
                    "artifact_type": SOURCE_ARTIFACT,
                    "content_sha256": package["content_sha256"],
                    "inventory_sha256": package["inventory_sha256"],
                    "manifest_sha256": package["manifest_sha256"],
                    "root_identity_sha256": root_identity_sha256,
                    "selected_checkout_expected_head": args.expected_head,
                    "selected_checkout_identity_sha256": (
                        _CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256
                    ),
                    "selected_checkout_path_sha256": trusted_root_path_sha256,
                    "selected_controller_bundle_sha256": (
                        _CAPTURED_BUNDLE_SHA256
                    ),
                    "source_selection_assurance": (
                        _SOURCE_SELECTION_ASSURANCE
                    ),
                    "trusted_bundle_sha256": trusted_bundle_sha256,
                    "trusted_root_identity_sha256": trusted_root_identity_sha256,
                    "trusted_source_sha256": trusted_source_sha256,
                    "trusted_workspace_sha256": trusted_workspace_sha256,
                }
            )
            component_error: AdmissionError | None = None
            component_records: tuple[dict[str, object], ...] = ()
            post_policy_record: dict[str, object] | None = None
            with tempfile.TemporaryDirectory(
                prefix="codexqb-external-controller-"
            ) as controller_name:
                controller_temp = Path(controller_name)
                os.chmod(controller_temp, 0o700)
                environment = _component_environment(controller_temp)
                try:
                    component_records = _run_validation_components(
                        root_descriptor,
                        args.profile,
                        environment,
                        skip_unit_tests=bool(args.skip_unit_tests),
                        skip_behavior_smoke=bool(args.skip_behavior_smoke),
                    )
                except AdmissionError as exc:
                    component_error = exc
                try:
                    post_policy_record = _run_policy_checker(
                        root_descriptor,
                        environment,
                    )
                except AdmissionError as exc:
                    if component_error is None:
                        component_error = exc
            post_state_sha256 = _verify_target_pair(
                root_path,
                root_descriptor,
                root_identity,
                root_resolution,
                package,
            )
            if pre_state_sha256 != post_state_sha256:
                raise AdmissionError("extracted_state_changed")
            _require_path_identity(
                TRUSTED_ROOT,
                trusted_descriptor,
                trusted_identity,
            )
            final_trusted_source_sha256, final_trusted_bundle_sha256 = (
                _verify_trusted_source(
                    trusted_descriptor,
                    trusted_resolution,
                    tuple(package["records"]),
                )
            )
            final_trusted_workspace_sha256 = _trusted_workspace_binding(package)
            if (
                final_trusted_source_sha256 != trusted_source_sha256
                or final_trusted_bundle_sha256 != trusted_bundle_sha256
                or final_trusted_workspace_sha256 != trusted_workspace_sha256
            ):
                raise AdmissionError("trusted_source_changed")
            if component_error is not None:
                raise component_error
            if post_policy_record is None:
                raise AdmissionError("trusted_post_policy_missing")
            validation_components_sha256 = _canonical_digest(
                [*component_records, post_policy_record]
            )
            receipt_sha256 = _canonical_digest(
                {
                    "execution_scope": "static_policy_and_pair_parity_only",
                    "finalization_allowed": False,
                    "host_attested": False,
                    "pair_digest": pair_digest,
                    "profile": args.profile,
                    "source_selection_assurance": (
                        _SOURCE_SELECTION_ASSURANCE
                    ),
                    "skip_behavior_smoke": bool(args.skip_behavior_smoke),
                    "skip_unit_tests": bool(args.skip_unit_tests),
                    "validation_components_sha256": validation_components_sha256,
                    "verified": False,
                }
            )
            print("extracted_package_admission=passed")
            print("external_pair_diagnostic_schema_version=1")
            print(
                f"source_selection_assurance={_SOURCE_SELECTION_ASSURANCE}"
            )
            print("execution_scope=static_policy_and_pair_parity_only")
            print("target_code_executed=false")
            print("host_attested=false")
            print("verified=false")
            print("finalization_allowed=false")
            print(f"selected_checkout_expected_head={args.expected_head}")
            print(
                "selected_checkout_identity_sha256="
                f"{_CAPTURED_TRUSTED_ROOT_IDENTITY_SHA256}"
            )
            print(
                f"selected_checkout_path_sha256={trusted_root_path_sha256}"
            )
            print(
                "selected_controller_bundle_sha256="
                f"{_CAPTURED_BUNDLE_SHA256}"
            )
            print(f"archive_sha256={archive_sha256}")
            print(f"archive_identity_sha256={archive_identity_sha256}")
            print(f"manifest_sha256={package['manifest_sha256']}")
            print(f"inventory_sha256={package['inventory_sha256']}")
            print(f"trusted_bundle_sha256={trusted_bundle_sha256}")
            print(f"trusted_source_sha256={trusted_source_sha256}")
            print(f"trusted_workspace_sha256={trusted_workspace_sha256}")
            print(f"root_identity_sha256={root_identity_sha256}")
            print(f"pair_digest={pair_digest}")
            print(
                f"validation_components_sha256={validation_components_sha256}"
            )
            print(f"external_pair_diagnostic_sha256={receipt_sha256}")
            return 0
    except AdmissionError as exc:
        print("extracted_package_admission=failed")
        print(f"error={exc}")
        return 2
    except (OSError, TypeError, ValueError) as exc:
        print("extracted_package_admission=failed")
        print("error=admission_internal_failure")
        return 2
    finally:
        for descriptor in (root_descriptor, trusted_descriptor):
            if descriptor >= 0:
                os.close(descriptor)


def main(argv: list[str] | None = None) -> int:
    return run(parse_args(sys.argv[1:] if argv is None else argv))


if __name__ == "__main__":
    raise SystemExit(main())
