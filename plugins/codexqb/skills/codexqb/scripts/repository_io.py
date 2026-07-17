#!/usr/bin/env python3
"""Mandatory repository evidence I/O boundary for CodexQB planners.

The model-facing CLI intentionally exposes only named discovery profiles and
stage-scoped Planner-docs publication.  Python callers may additionally use
exact-path snapshots, but all content still flows through one descriptor-bound
repository root and the same budgets, receipts, and no-follow checks.
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
        "codexqb_controller=unsupported "
        "reason=requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)

from types import ModuleType


def _launcher_admission_is_valid(expected_basename: str) -> bool:
    context = sys.modules.get("_codexqb_held_runtime_context_v1")
    if not isinstance(context, ModuleType):
        return False
    try:
        state = ModuleType.__getattribute__(context, "__dict__")
    except (AttributeError, TypeError):
        return False
    runtime_sources = state.get("runtime_sources")
    if (
        type(expected_basename) is not str
        or not expected_basename
        or type(state.get("__name__")) is not str
        or state.get("__name__") != "_codexqb_held_runtime_context_v1"
        or type(state.get("schema_version")) is not int
        or state.get("schema_version") != 1
        or type(state.get("assurance")) is not str
        or state.get("assurance")
        != "controller_observed_loader_path_unattested"
        or state.get("host_attested") is not False
        or state.get("verified") is not False
        or state.get("finalization_authority") is not False
        or "runtime_sha256" in state
        or "goal_sha256" in state
        or type(runtime_sources) is not tuple
        or not runtime_sources
    ):
        return False
    source_names: list[str] = []
    for item in runtime_sources:
        if type(item) is not tuple or len(item) != 2:
            return False
        source_name, source = item
        if (
            type(source_name) is not str
            or not source_name
            or type(source) is not bytes
            or not source
        ):
            return False
        source_names.append(source_name)
    return bool(
        tuple(source_names) == tuple(sorted(source_names))
        and len(source_names) == len(set(source_names))
        and expected_basename in source_names
    )

if __name__ == "__main__" and not _launcher_admission_is_valid(
    "repository_io.py"
):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\n"
    )
    raise SystemExit(2)


import argparse
from collections.abc import Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass, replace
import errno
import hashlib
import html
import json
import math
import os
from pathlib import Path
import re
import stat
import time
import unicodedata
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from artifact_io import (  # noqa: E402
    atomic_write_bytes_at,
    directory_entry_matches,
    locked_directory,
    open_child_directory,
    open_or_create_child_directory,
    regular_target_metadata_at,
)
from repository_evidence import (  # noqa: E402
    AnchoredFilePayload,
    RepositoryRootAnchor,
    baseline_digest,
    normalize_repo_relative_path,
    open_repository_cwd_anchor,
    open_repository_root_anchor,
    read_regular_files_from_anchor,
    revalidate_repository_root_anchor,
    require_descriptor_on_repository_mount,
    require_same_repository_mount,
    repository_evidence_from_snapshots,
    repository_snapshot_digest,
    snapshot_repository_inventory_from_anchor,
)
from safety_contracts import (  # noqa: E402
    assert_safe_persistent_text,
    has_secret_like,
    parse_safe_persistent_json,
    redact_secret_like,
    secret_findings,
    serialize_safe_persistent_json,
)
from git_evidence import (  # noqa: E402
    canonical_git_evidence_digest,
    capture_git_workspace_evidence,
)


REPOSITORY_IO_RECEIPT_SCHEMA = "codexqb.repository-io-receipt/v1"
PLANNER_EVIDENCE_POLICY_V1 = "planner-evidence/v1"

DEFAULT_MAX_FILE_BYTES = 4 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_PATHS = 4096
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MODEL_MAX_FILE_BYTES = 256 * 1024
DEFAULT_MODEL_MAX_TOTAL_BYTES = 1024 * 1024
DEFAULT_MODEL_MAX_MATCHES = 512
DEFAULT_MODEL_MAX_RECORD_CHARACTERS = 4096
CONTROLLER_STDIN_REQUEST_SCHEMA = "codexqb.controller-argv/v1"
MAX_CONTROLLER_STDIN_REQUEST_BYTES = DEFAULT_MAX_FILE_BYTES + 64 * 1024
MAX_CONTROLLER_STDIN_ARGV_ITEMS = 256
MAX_CONTROLLER_STDIN_ARGUMENT_CHARACTERS = DEFAULT_MAX_FILE_BYTES

_SHA256_RE = re.compile(r"[a-f0-9]{64}")
_POLICY_NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,47}/[a-z0-9][a-z0-9.-]{0,31}")
_ANSI_ESCAPE_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_PHASE_PLAN_RE = re.compile(
    r"Planner-docs/Faz-(?P<phase>[1-9][0-9]*)-Plans/"
    r"Faz(?P=phase)\.[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*\.md"
)

_IGNORED_COMPONENTS = frozenset(
    {
        ".git",
        ".codexqb",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__pycache__",
        "artifacts",
        "build",
        "dist",
        "logs",
        "node_modules",
        "tmp",
        "vendor",
        "venv",
    }
)

# Maintenance validation must observe package-blocked directories instead of
# inheriting the model-facing ignore set.  The checkout's root .git entry is
# the sole excluded authority domain; every other pruned directory is emitted
# as metadata so the fixed validator policy can accept or reject it explicitly.
_VALIDATION_EXCLUDED_ROOT_ENTRIES = frozenset({".git"})
_VALIDATION_PRUNED_DIRECTORY_NAMES = frozenset(
    {
        ".git",
        ".codexqb",
        ".cache",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".venv",
        "__macosx",
        "__pycache__",
        "artifacts",
        "build",
        "dist",
        "logs",
        "node_modules",
        "tmp",
        "venv",
    }
)


def _validation_prune_directory_name(name: str) -> bool:
    folded = name.casefold()
    return (
        folded in _VALIDATION_PRUNED_DIRECTORY_NAMES
        or folded.startswith(".env")
        or folded.endswith(".local")
        or ".local." in folded
    )

_PROFILE_PREFIXES: dict[str, tuple[str, ...] | None] = {
    "intake": None,
    "step1": None,
    "autopsy": None,
    "step2": ("Planner-docs", "README.md", "AGENTS.md"),
    "step3": ("Planner-docs",),
}

_SEARCH_SIGNALS: dict[str, tuple[tuple[str, re.Pattern[str]], ...]] = {
    "intake": (
        ("architecture", re.compile(r"\b(?:architecture|boundary|module|service)\b", re.I)),
        ("delivery", re.compile(r"\b(?:roadmap|phase|deploy|release|production)\b", re.I)),
        ("quality", re.compile(r"\b(?:test|validation|smoke|ci|audit)\b", re.I)),
    ),
    "step1": (
        ("roadmap", re.compile(r"\b(?:roadmap|phase|milestone|priority)\b", re.I)),
        ("architecture", re.compile(r"\b(?:architecture|boundary|integration|workflow)\b", re.I)),
        ("risk", re.compile(r"\b(?:risk|blocker|security|readiness)\b", re.I)),
    ),
    "autopsy": (
        ("incomplete", re.compile(r"\b(?:todo|fixme|tbd|placeholder|stub|not implemented)\b", re.I)),
        ("operations", re.compile(r"\b(?:runbook|readiness|observability|production)\b", re.I)),
        ("risk", re.compile(r"\b(?:security|credential|secret|policy|risk)\b", re.I)),
    ),
    "step2": (
        ("phase", re.compile(r"\b(?:faz|phase|stage|acceptance)\b", re.I)),
        ("dependency", re.compile(r"\b(?:dependency|depends|blocks|parallel)\b", re.I)),
        ("validation", re.compile(r"\b(?:validation|test|probe|evidence)\b", re.I)),
    ),
    "step3": (
        ("readiness", re.compile(r"\b(?:ready|blocked|pass_with_warnings|no_action_required)\b", re.I)),
        ("finding", re.compile(r"\b(?:finding|severity|p0|p1|p2|p3|repair)\b", re.I)),
        ("traceability", re.compile(r"\b(?:acceptance|dependency|evidence|risk)\b", re.I)),
    ),
}

_FIXED_STAGE_TARGETS: dict[str, frozenset[str]] = {
    "step1": frozenset({"Planner-docs/Main-Planing.md"}),
    "autopsy": frozenset(
        {
            "Planner-docs/Autopsy.md",
            "Planner-docs/Project-Ontology.md",
            "Planner-docs/Project-Comprehension.md",
        }
    ),
    "step2": frozenset(
        {
            "Planner-docs/Sub-Planing-Index.md",
            "Planner-docs/Planing-Ledger.md",
            "Planner-docs/Step2-Blocked.md",
        }
    ),
    "step3": frozenset({"Planner-docs/Sub-Planing-Audit.md"}),
    "step4": frozenset({"Planner-docs/Planing-Ledger.md"}),
}
_RECEIPT_OPERATIONS = frozenset(
    {
        "read",
        "read-model",
        "list-internal",
        "list",
        "search",
        "write-planner",
        "workspace-proof",
        "root-proof",
    }
)
_RECEIPT_STATES = frozenset({"missing", "present", "complete", "committed"})
_RECEIPT_REASONS = frozenset(
    {
        None,
        "missing",
        "redacted",
        "record_budget",
        "model_byte_budget",
        "match_budget",
        "record_character_budget",
    }
)


@dataclass(frozen=True)
class RepositoryIOPolicy:
    name: str = PLANNER_EVIDENCE_POLICY_V1
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_paths: int = DEFAULT_MAX_PATHS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS
    model_max_file_bytes: int = DEFAULT_MODEL_MAX_FILE_BYTES
    model_max_total_bytes: int = DEFAULT_MODEL_MAX_TOTAL_BYTES
    model_max_matches: int = DEFAULT_MODEL_MAX_MATCHES
    model_max_record_characters: int = DEFAULT_MODEL_MAX_RECORD_CHARACTERS

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or _POLICY_NAME_RE.fullmatch(self.name) is None:
            raise ValueError("repository_io_policy_name_invalid")
        integer_limits = (
            self.max_file_bytes,
            self.max_total_bytes,
            self.max_paths,
            self.model_max_file_bytes,
            self.model_max_total_bytes,
            self.model_max_matches,
            self.model_max_record_characters,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value <= 0 for value in integer_limits):
            raise ValueError("repository_io_policy_limit_invalid")
        if (
            not isinstance(self.timeout_seconds, (int, float))
            or isinstance(self.timeout_seconds, bool)
            or not math.isfinite(float(self.timeout_seconds))
            or self.timeout_seconds <= 0
        ):
            raise ValueError("repository_io_policy_timeout_invalid")
        if self.model_max_file_bytes > self.max_file_bytes:
            raise ValueError("repository_io_model_file_budget_exceeds_internal_budget")
        if self.model_max_total_bytes > self.max_total_bytes:
            raise ValueError("repository_io_model_total_budget_exceeds_internal_budget")


DEFAULT_POLICY = RepositoryIOPolicy()


@dataclass(frozen=True)
class RepositoryIOReceipt:
    operation: str
    path: str | None
    state: str
    sha256: str | None = None
    size: int | None = None
    bytes_scanned: int = 0
    bytes_rendered: int = 0
    path_count: int = 0
    match_count: int = 0
    truncated: bool = False
    reason: str | None = None
    policy: str = PLANNER_EVIDENCE_POLICY_V1

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": REPOSITORY_IO_RECEIPT_SCHEMA,
            "policy": self.policy,
            "operation": self.operation,
            "path": self.path,
            "state": self.state,
            "sha256": self.sha256,
            "size": self.size,
            "bytes_scanned": self.bytes_scanned,
            "bytes_rendered": self.bytes_rendered,
            "path_count": self.path_count,
            "match_count": self.match_count,
            "truncated": self.truncated,
            "reason": self.reason,
        }


@dataclass(frozen=True)
class EvidenceBytes:
    path: str
    data: bytes | None
    exists: bool
    receipt: RepositoryIOReceipt


@dataclass(frozen=True)
class EvidenceText:
    path: str
    text: str | None
    exists: bool
    audience: str
    receipt: RepositoryIOReceipt


@dataclass(frozen=True)
class PathListing:
    profile: str
    paths: tuple[str, ...]
    directories: tuple[str, ...]
    receipt: RepositoryIOReceipt


@dataclass(frozen=True)
class SearchResult:
    profile: str
    records: tuple[dict[str, object], ...]
    receipt: RepositoryIOReceipt


@dataclass(frozen=True)
class ControllerWorkspaceProof:
    evidence: dict[str, object]
    repository_identity_sha256: str
    mount_provider: str
    mount_assurance: str
    receipt: RepositoryIOReceipt


@dataclass(frozen=True)
class ControllerRootProof:
    repository_identity_sha256: str
    root_device: int
    root_inode: int
    mount_provider: str
    mount_assurance: str
    receipt: RepositoryIOReceipt


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_relative_path(value: object) -> str:
    return normalize_repo_relative_path(value)


def _public_path(path: str | None, *, max_characters: int = DEFAULT_MODEL_MAX_RECORD_CHARACTERS) -> str | None:
    if path is None:
        return None
    unsafe = (
        has_secret_like(path)
        or any(unicodedata.category(character) in {"Cc", "Cf", "Cs"} for character in path)
    )
    if not unsafe:
        try:
            assert_safe_persistent_text(path)
        except ValueError:
            unsafe = True
    if unsafe or len(path) > max_characters:
        return f"<redacted-path:{hashlib.sha256(path.encode('utf-8', errors='replace')).hexdigest()[:16]}>"
    return path


def _path_label(path: str) -> str:
    return str(_public_path(path))


def _public_receipt(receipt: RepositoryIOReceipt) -> dict[str, object]:
    payload = receipt.as_dict()
    payload["path"] = _public_path(receipt.path)
    return payload


def _model_projection(data: bytes) -> tuple[str, bool]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return "<redacted:non-utf8-repository-evidence>\n", True
    original_text = text
    # Scan the original semantic surface before changing any separator or
    # renderer syntax.  The shared scanner projects HTML entities, terminal
    # escapes, NFKC forms, Markdown visibility, and invisible-control removal;
    # a credential split across any of those forms must therefore collapse to
    # one constant response rather than expose individually harmless-looking
    # fragments after normalization.
    try:
        if secret_findings(text):
            text = redact_secret_like(text)
            if text == "<redacted:unsafe-diagnostic>":
                return "<redacted:unsafe-repository-evidence>\n", True
    except Exception:
        return "<redacted:unsafe-repository-evidence>\n", True
    # Decode semantic encodings before scanning, then remove terminal and
    # direction-control characters that could visually split a credential.
    text = html.unescape(text)
    text = _ANSI_ESCAPE_RE.sub("", text)
    normalized_chunks: list[str] = []
    normalized_buffer: list[str] = []
    for character in text.replace("\r\n", "\n").replace("\r", "\n"):
        category = unicodedata.category(character)
        if character in {"\n", "\t"}:
            normalized_buffer.append(character)
        elif category in {"Cc", "Cf", "Cs"}:
            normalized_buffer.append(" ")
        else:
            normalized_buffer.append(character)
        if len(normalized_buffer) >= 8192:
            normalized_chunks.append("".join(normalized_buffer))
            normalized_buffer.clear()
    if normalized_buffer:
        normalized_chunks.append("".join(normalized_buffer))
    rendered = unicodedata.normalize("NFKC", "".join(normalized_chunks))
    try:
        rendered = redact_secret_like(rendered)
    except Exception:
        return "<redacted:unsafe-repository-evidence>\n", True
    try:
        residual_findings = secret_findings(rendered)
    except Exception:
        return "<redacted:unsafe-repository-evidence>\n", True
    if residual_findings:
        return "<redacted:unsafe-repository-evidence>\n", True
    try:
        assert_safe_persistent_text(rendered)
    except ValueError:
        return "<redacted:unsafe-repository-evidence>\n", True
    return rendered, rendered != original_text


def _expected_state(value: object) -> tuple[str, str | None]:
    if value == "missing":
        return "missing", None
    if isinstance(value, str) and _SHA256_RE.fullmatch(value):
        return "present", value
    if isinstance(value, Mapping):
        state = value.get("state")
        digest = value.get("sha256")
        if state == "missing" and digest is None:
            return "missing", None
        if state == "present" and isinstance(digest, str) and _SHA256_RE.fullmatch(digest):
            return "present", digest
    raise ValueError("planner_write_expected_state_invalid")


def _stage_target_allowed(stage: str, path: str) -> bool:
    fixed = _FIXED_STAGE_TARGETS.get(stage)
    if fixed is None:
        return False
    if path in fixed:
        return True
    return stage == "step2" and _PHASE_PLAN_RE.fullmatch(path) is not None


_READ_ERROR_MAP = {
    "repository_evidence_total_bytes_exceeded": "repository_io_total_bytes_exceeded",
    "repository_evidence_file_too_large": "repository_io_file_too_large",
    "repository_evidence_deadline_exceeded": "repository_io_deadline_exceeded",
    "repository_evidence_path_count_exceeded": "repository_io_path_budget_exceeded",
    "repository_evidence_path_read_budget_exceeded": "repository_io_path_budget_exceeded",
}
_INVENTORY_ERROR_CODES = frozenset(
    {
        "repository_evidence_deadline_exceeded",
        "repository_evidence_directory_depth_exceeded",
        "repository_evidence_file_identity_changed",
        "repository_evidence_file_too_large",
        "repository_evidence_path_count_exceeded",
        "repository_evidence_root_identity_changed",
        "repository_evidence_target_must_be_owner_controlled_regular_file",
        "repository_evidence_target_must_be_owner_controlled_symlink",
        "repository_evidence_total_bytes_exceeded",
        "repository_inventory_changed_during_capture",
        "repository_inventory_walk_failed",
        "repository_path_parent_identity_changed",
        "secure_repository_mount_identity_changed",
        "secure_repository_mount_identity_unavailable",
        "secure_repository_mount_mismatch",
    }
)


def _exception_code(exc: BaseException) -> str:
    return str(exc).split("=", 1)[0].split(":", 1)[0]


def _canonical_record(record: Mapping[str, object]) -> str:
    return json.dumps(
        dict(record),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _redacted_path(path: str) -> str:
    return f"<redacted-path:{hashlib.sha256(path.encode('utf-8', errors='replace')).hexdigest()[:16]}>"


def _descriptor_has_acl(descriptor: int) -> bool:
    """Reject POSIX/default ACLs and Darwin extended ACL entries."""

    try:
        names = os.listxattr(descriptor)
    except AttributeError:
        if sys.platform != "darwin":
            raise ValueError("repository_io_acl_probe_unavailable") from None
        names = []
    except OSError as exc:
        # Linux exposes a symlink itself through an O_PATH|O_NOFOLLOW
        # descriptor.  fgetxattr(2), which backs listxattr(fd), rejects that
        # descriptor with EBADF even though the descriptor remains suitable
        # for identity and mount checks.  Linux does not apply POSIX access or
        # default ACLs to symbolic links, so this one verified descriptor kind
        # has no ACL state to inspect.  Keep every other EBADF fail-closed.
        if exc.errno == errno.EBADF and sys.platform.startswith("linux"):
            try:
                metadata = os.fstat(descriptor)
            except OSError:
                raise ValueError("repository_io_acl_probe_failed") from None
            if stat.S_ISLNK(metadata.st_mode):
                names = []
            else:
                raise ValueError("repository_io_acl_probe_failed") from None
        else:
            unsupported = {errno.ENOTSUP}
            if hasattr(errno, "EOPNOTSUPP"):
                unsupported.add(errno.EOPNOTSUPP)
            if exc.errno not in unsupported or sys.platform != "darwin":
                raise ValueError("repository_io_acl_probe_failed") from None
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
        raise ValueError("repository_io_acl_probe_unavailable")
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
        raise ValueError("repository_io_acl_probe_failed")
    if releaser(acl) != 0:
        raise ValueError("repository_io_acl_probe_failed")
    return True


def _require_owner_controlled_write_directory(descriptor: int) -> os.stat_result:
    """Require an existing planner-write parent to remain owner-controlled."""

    try:
        metadata = os.fstat(descriptor)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
        has_acl = _descriptor_has_acl(descriptor)
    except (OSError, TypeError, ValueError):
        raise ValueError("planner_write_parent_not_owner_controlled") from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not metadata.st_mode & stat.S_IWUSR
        or not metadata.st_mode & stat.S_IXUSR
        or has_acl
    ):
        raise ValueError("planner_write_parent_not_owner_controlled")
    return metadata


def _require_owner_controlled_parent_directory(descriptor: int) -> os.stat_result:
    """Require one held read parent to remain owner-controlled and ACL-free."""

    try:
        metadata = os.fstat(descriptor)
    except OSError:
        raise ValueError("repository_path_parent_identity_changed") from None
    try:
        has_acl = _descriptor_has_acl(descriptor)
    except (OSError, TypeError, ValueError):
        raise ValueError("repository_io_parent_acl_rejected") from None
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
    if has_acl:
        raise ValueError("repository_io_parent_acl_rejected")
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != expected_uid
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    ):
        raise ValueError("repository_path_parent_identity_changed")
    return metadata


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
_MAX_MOUNTINFO_BYTES = 8 * 1024 * 1024
_DARWIN_MNT_LOCAL = 0x00001000


def _mountinfo_filesystem_type(payload: bytes, mount_id: int) -> str:
    if (
        not isinstance(payload, bytes)
        or len(payload) > _MAX_MOUNTINFO_BYTES
        or not isinstance(mount_id, int)
        or isinstance(mount_id, bool)
        or mount_id <= 0
    ):
        raise ValueError("repository_io_filesystem_locality_unavailable")
    matches: list[str] = []
    for line in payload.splitlines():
        fields = line.split()
        if not fields:
            continue
        try:
            current_mount_id = int(fields[0])
            separator = fields.index(b"-")
            raw_type = fields[separator + 1]
        except (ValueError, IndexError):
            raise ValueError("repository_io_filesystem_locality_unavailable") from None
        if current_mount_id != mount_id:
            continue
        mount_attributes = fields[5:separator] + fields[separator + 3 :]
        attribute_tokens = {
            token.lower()
            for field in mount_attributes
            for token in field.split(b",")
            if token
        }
        if any(
            token == b"idmapped" or token.startswith(b"idmapped=")
            for token in attribute_tokens
        ):
            raise ValueError("repository_io_filesystem_idmapped")
        try:
            filesystem_type = raw_type.decode("ascii").casefold()
        except UnicodeDecodeError:
            raise ValueError("repository_io_filesystem_locality_unavailable") from None
        if not filesystem_type or not filesystem_type.replace("_", "").replace("-", "").replace(".", "").isalnum():
            raise ValueError("repository_io_filesystem_locality_unavailable")
        matches.append(filesystem_type)
    if len(matches) != 1:
        raise ValueError("repository_io_filesystem_locality_unavailable")
    return matches[0]


def _linux_mountinfo_filesystem_type(mount_id: int) -> str:
    descriptor = -1
    try:
        descriptor = os.open(
            f"/proc/{os.getpid()}/mountinfo",
            os.O_RDONLY
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_MOUNTINFO_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_MOUNTINFO_BYTES:
                raise ValueError("repository_io_filesystem_locality_unavailable")
    except (OSError, TypeError, ValueError):
        raise ValueError("repository_io_filesystem_locality_unavailable") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return _mountinfo_filesystem_type(b"".join(chunks), mount_id)


def _authority_filesystem_type_from_resolution(resolution: object) -> str:
    identity = getattr(resolution, "identity", None)
    if identity is None:
        raise ValueError("repository_io_filesystem_locality_unavailable")
    if sys.platform.startswith("linux"):
        if identity.namespace != "linux_mount_id" or len(identity.parts) != 1:
            raise ValueError("repository_io_filesystem_locality_unavailable")
        return _linux_mountinfo_filesystem_type(identity.parts[0])
    if sys.platform == "darwin":
        if identity.namespace != "darwin_fstatfs" or len(identity.parts) != 7:
            raise ValueError("repository_io_filesystem_locality_unavailable")
        raw_type = identity.parts[3]
        raw_flags = identity.parts[4]
        if (
            not isinstance(raw_type, bytes)
            or not isinstance(raw_flags, int)
            or isinstance(raw_flags, bool)
            or raw_flags & _DARWIN_MNT_LOCAL == 0
        ):
            raise ValueError("repository_io_filesystem_locality_unavailable")
        try:
            filesystem_type = raw_type.decode("ascii").casefold()
        except UnicodeDecodeError:
            raise ValueError("repository_io_filesystem_locality_unavailable") from None
        if not filesystem_type:
            raise ValueError("repository_io_filesystem_locality_unavailable")
        return filesystem_type
    raise ValueError("repository_io_filesystem_locality_unavailable")


def _require_local_authority_mount_resolution(resolution: object) -> str:
    filesystem_type = _authority_filesystem_type_from_resolution(resolution)
    if filesystem_type not in _LOCAL_AUTHORITY_FILESYSTEM_TYPES:
        raise ValueError("repository_io_filesystem_not_local")
    return filesystem_type


def _require_local_authority_filesystem(anchor: RepositoryRootAnchor) -> str:
    return _require_local_authority_mount_resolution(anchor.mount_resolution)


class _RepositoryIOEngine:
    """One anchored, budgeted repository evidence session."""

    def __init__(self, anchor: RepositoryRootAnchor, policy: RepositoryIOPolicy) -> None:
        self.anchor = anchor
        self._authority_filesystem_type = _require_local_authority_filesystem(anchor)
        # `anchor.path` is the lexical absolute path whose complete component
        # chain is held and identity-bound by RepositoryRootAnchor.  Resolving
        # it again would re-enter the mutable namespace and permit an ABA
        # symlink target to become the cached authority label.
        self.root = anchor.path
        self.policy = policy
        self._started = time.monotonic()
        self._bytes_read = 0
        self._model_bytes = 0
        self._model_records = 0
        self._path_reads = 0
        self._budgeted_paths: set[str] = set()
        self._bound_identities: dict[str, tuple[int, int, int, int, int, int, int] | None] = {}
        self._listing_cache: dict[str, tuple[dict[str, object], ...]] = {}
        self._complete_listing_cache: dict[
            str, tuple[dict[str, object], ...]
        ] = {}
        self._complete_root_identity_cache: dict[str, tuple[int, ...]] = {}
        self._validation_listing_cache: tuple[dict[str, object], ...] | None = None
        self._validation_root_identity_cache: tuple[int, ...] | None = None
        self._inventory_cache: dict[str, tuple[dict[str, object], ...]] = {}
        self.receipts: list[RepositoryIOReceipt] = []

    def _remaining_seconds(self) -> float:
        remaining = self.policy.timeout_seconds - (time.monotonic() - self._started)
        if remaining <= 0:
            raise ValueError("repository_io_deadline_exceeded")
        return remaining

    def _consume(
        self,
        *,
        path_keys: Iterable[str] = (),
        scanned: int = 0,
        rendered: int = 0,
        records: int = 0,
    ) -> None:
        self._remaining_seconds()
        new_paths = set(path_keys) - self._budgeted_paths
        if self._path_reads + len(new_paths) > self.policy.max_paths:
            raise ValueError("repository_io_path_budget_exceeded")
        if self._bytes_read + scanned > self.policy.max_total_bytes:
            raise ValueError("repository_io_total_bytes_exceeded")
        if self._model_bytes + rendered > self.policy.model_max_total_bytes:
            raise ValueError("repository_io_model_bytes_exceeded")
        if self._model_records + records > self.policy.model_max_matches:
            raise ValueError("repository_io_model_record_budget_exceeded")
        self._budgeted_paths.update(new_paths)
        self._path_reads += len(new_paths)
        self._bytes_read += scanned
        self._model_bytes += rendered
        self._model_records += records

    def _record(self, receipt: RepositoryIOReceipt) -> RepositoryIOReceipt:
        if (
            receipt.operation not in _RECEIPT_OPERATIONS
            or receipt.state not in _RECEIPT_STATES
            or receipt.reason not in _RECEIPT_REASONS
        ):
            raise ValueError("repository_io_receipt_invalid")
        receipt = replace(
            receipt,
            path=_public_path(
                receipt.path,
                max_characters=self.policy.model_max_record_characters,
            ),
            policy=self.policy.name,
        )
        self.receipts.append(receipt)
        return receipt

    @staticmethod
    def _descriptor_authority_validator(descriptor: int, _path: str) -> bool:
        try:
            return not _descriptor_has_acl(descriptor)
        except (OSError, TypeError, ValueError):
            return False

    def workspace_proof(
        self,
        *,
        exclude_untracked=None,
        exclude_tracked=None,
    ) -> ControllerWorkspaceProof:
        self._remaining_seconds()
        try:
            revalidate_repository_root_anchor(self.anchor)
            evidence = capture_git_workspace_evidence(
                self.anchor,
                exclude_untracked=exclude_untracked,
                exclude_tracked=exclude_tracked,
                descriptor_authority_validator=self._descriptor_authority_validator,
            )
            revalidate_repository_root_anchor(self.anchor)
        except (OSError, TypeError, ValueError):
            raise ValueError("repository_io_workspace_proof_failed") from None
        if not isinstance(evidence, dict):
            raise ValueError("repository_io_workspace_proof_invalid")
        digest = canonical_git_evidence_digest(evidence)
        identity_payload = b"\0".join(
            (
                b"codexqb-repository-root-proof-v1",
                os.fsencode(self.root),
                str(self.anchor.metadata.st_dev).encode("ascii"),
                str(self.anchor.metadata.st_ino).encode("ascii"),
            )
        )
        mount_provider = self.anchor.mount_resolution.selected_provider
        if mount_provider is None:
            raise ValueError("repository_io_workspace_proof_mount_unavailable")
        receipt = self._record(
            RepositoryIOReceipt(
                operation="workspace-proof",
                path=None,
                state="complete",
                sha256=digest,
                path_count=1,
            )
        )
        return ControllerWorkspaceProof(
            evidence=dict(evidence),
            repository_identity_sha256=hashlib.sha256(identity_payload).hexdigest(),
            mount_provider=mount_provider,
            mount_assurance=self.anchor.mount_resolution.assurance.value,
            receipt=receipt,
        )

    def root_proof(self) -> ControllerRootProof:
        self._remaining_seconds()
        root_identity = self._owner_controlled_root_identity()
        identity_payload = b"\0".join(
            (
                b"codexqb-repository-root-proof-v1",
                os.fsencode(self.root),
                str(root_identity[0]).encode("ascii"),
                str(root_identity[1]).encode("ascii"),
            )
        )
        identity = hashlib.sha256(identity_payload).hexdigest()
        provider = self.anchor.mount_resolution.selected_provider
        if provider is None:
            raise ValueError("repository_io_root_proof_mount_unavailable")
        if self._owner_controlled_root_identity() != root_identity:
            raise ValueError("repository_io_owner_controlled_root_failed")
        receipt = self._record(
            RepositoryIOReceipt(
                operation="root-proof",
                path=None,
                state="complete",
                sha256=identity,
                path_count=1,
            )
        )
        return ControllerRootProof(
            repository_identity_sha256=identity,
            root_device=root_identity[0],
            root_inode=root_identity[1],
            mount_provider=provider,
            mount_assurance=self.anchor.mount_resolution.assurance.value,
            receipt=receipt,
        )

    @contextmanager
    def _parent_descriptor(self, path: str) -> Iterator[tuple[int, str]]:
        parts = path.split("/")
        current_fd = self.anchor.fd
        owned: list[int] = []
        chain: list[tuple[int, str, int, os.stat_result, str]] = []
        root_identity = self._owner_controlled_root_identity()
        try:
            for index, component in enumerate(parts[:-1], start=1):
                child_fd = -1
                try:
                    before = os.stat(component, dir_fd=current_fd, follow_symlinks=False)
                    child_fd = os.open(
                        component,
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=current_fd,
                    )
                    opened = _require_owner_controlled_parent_directory(child_fd)
                except FileNotFoundError:
                    yield -1, parts[-1]
                    return
                except ValueError:
                    if child_fd >= 0:
                        os.close(child_fd)
                    raise
                except OSError as exc:
                    if child_fd >= 0:
                        os.close(child_fd)
                    raise ValueError("repository_path_parent_identity_changed") from None
                if (
                    not stat.S_ISDIR(before.st_mode)
                    or not stat.S_ISDIR(opened.st_mode)
                    or before.st_dev != self.anchor.metadata.st_dev
                    or opened.st_dev != self.anchor.metadata.st_dev
                    or before.st_dev != opened.st_dev
                    or before.st_ino != opened.st_ino
                    or self._stable_metadata(before) != self._stable_metadata(opened)
                ):
                    os.close(child_fd)
                    raise ValueError("repository_path_parent_identity_changed")
                try:
                    relative_parent = "/".join(parts[:index])
                    require_same_repository_mount(
                        self.anchor,
                        child_fd,
                        relative_parent,
                    )
                except ValueError as exc:
                    os.close(child_fd)
                    if str(exc) == "repository_io_parent_acl_rejected":
                        raise
                    raise ValueError("repository_path_parent_mount_escape") from None
                owned.append(child_fd)
                chain.append(
                    (current_fd, component, child_fd, opened, relative_parent)
                )
                current_fd = child_fd
            yield current_fd, parts[-1]
        finally:
            try:
                for (
                    parent_fd,
                    component,
                    child_fd,
                    opened,
                    relative_parent,
                ) in chain:
                    current_fd = _require_owner_controlled_parent_directory(
                        child_fd
                    )
                    try:
                        current_path = os.stat(
                            component,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                    except OSError:
                        raise ValueError(
                            "repository_path_parent_identity_changed"
                        ) from None
                    if (
                        self._stable_metadata(opened)
                        != self._stable_metadata(current_fd)
                        or self._stable_metadata(opened)
                        != self._stable_metadata(current_path)
                    ):
                        raise ValueError("repository_path_parent_identity_changed")
                    try:
                        require_same_repository_mount(
                            self.anchor,
                            child_fd,
                            relative_parent,
                        )
                    except ValueError:
                        raise ValueError(
                            "repository_path_parent_mount_escape"
                        ) from None
                if self._owner_controlled_root_identity() != root_identity:
                    raise ValueError("repository_path_parent_identity_changed")
            finally:
                for descriptor in reversed(owned):
                    os.close(descriptor)

    def _lstat(self, path: str) -> os.stat_result | None:
        revalidate_repository_root_anchor(self.anchor)
        try:
            return self._lstat_once(path)
        finally:
            revalidate_repository_root_anchor(self.anchor)

    def _lstat_once(self, path: str) -> os.stat_result | None:
        with self._parent_descriptor(path) as (parent_fd, name):
            if parent_fd < 0:
                return None
            try:
                metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            except OSError as exc:
                raise ValueError("repository_io_target_unavailable") from None
            if stat.S_ISREG(metadata.st_mode):
                descriptor = -1
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=parent_fd,
                    )
                    opened = os.fstat(descriptor)
                    require_descriptor_on_repository_mount(self.anchor, descriptor, path)
                    if _descriptor_has_acl(descriptor):
                        raise ValueError("repository_io_target_acl_rejected")
                    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except (OSError, TypeError, ValueError) as exc:
                    if str(exc) == "repository_io_target_acl_rejected":
                        raise
                    raise ValueError("repository_io_target_identity_changed") from None
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or self._stable_metadata(metadata) != self._stable_metadata(opened)
                    or self._stable_metadata(opened) != self._stable_metadata(after)
                ):
                    raise ValueError("repository_io_target_identity_changed")
                metadata = opened
            elif stat.S_ISDIR(metadata.st_mode):
                descriptor = -1
                try:
                    descriptor = os.open(
                        name,
                        os.O_RDONLY
                        | os.O_DIRECTORY
                        | os.O_NOFOLLOW
                        | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=parent_fd,
                    )
                    opened = os.fstat(descriptor)
                    require_same_repository_mount(self.anchor, descriptor, path)
                    if _descriptor_has_acl(descriptor):
                        raise ValueError("repository_io_target_acl_rejected")
                    after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except (OSError, TypeError, ValueError) as exc:
                    if str(exc) == "repository_io_target_acl_rejected":
                        raise
                    raise ValueError("repository_io_target_identity_changed") from None
                finally:
                    if descriptor >= 0:
                        os.close(descriptor)
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or self._stable_metadata(metadata) != self._stable_metadata(opened)
                    or self._stable_metadata(opened) != self._stable_metadata(after)
                ):
                    raise ValueError("repository_io_target_identity_changed")
                metadata = opened
        return metadata

    def _normalize_path_inputs(self, paths: Iterable[object]) -> list[str]:
        if isinstance(paths, (str, bytes, bytearray, Mapping)):
            raise TypeError("repository_io_paths_must_be_iterable")
        normalized: set[str] = set()
        for count, path in enumerate(paths, start=1):
            self._remaining_seconds()
            if count > self.policy.max_paths:
                raise ValueError("repository_io_path_budget_exceeded")
            normalized.add(_safe_relative_path(path))
            if len(normalized) > self.policy.max_paths:
                raise ValueError("repository_io_path_budget_exceeded")
        return sorted(normalized)

    def _bind_batch_identities(self, paths: Iterable[str]) -> None:
        for path in paths:
            self._consume(path_keys=(path,))
            metadata = self._lstat(path)
            identity = None if metadata is None else self._stable_metadata(metadata)
            existing = self._bound_identities.get(path, identity)
            if path in self._bound_identities and existing != identity:
                raise ValueError("repository_io_batch_identity_changed")
            self._bound_identities[path] = identity

    def _revalidate_bound_paths(self, paths: Iterable[str]) -> None:
        for path in paths:
            expected = self._bound_identities[path]
            metadata = self._lstat(path)
            current = None if metadata is None else self._stable_metadata(metadata)
            if current != expected:
                raise ValueError("repository_io_batch_identity_changed")

    def _path_kind_and_identity(
        self,
        normalized: str,
    ) -> tuple[str, tuple[int, int, int, int, int, int, int] | None]:
        self._consume(path_keys=(normalized,))
        metadata = self._lstat(normalized)
        if metadata is None:
            return "missing", None
        identity = self._stable_metadata(metadata)
        if stat.S_ISREG(metadata.st_mode):
            return "regular", identity
        if stat.S_ISDIR(metadata.st_mode):
            return "directory", identity
        if stat.S_ISLNK(metadata.st_mode):
            return "symlink", identity
        return "special", identity

    def path_kind(self, path: object) -> str:
        normalized = _safe_relative_path(path)
        kind, _identity = self._path_kind_and_identity(normalized)
        return kind

    def read_bytes(self, path: object, *, required: bool = True) -> EvidenceBytes:
        normalized = _safe_relative_path(path)
        try:
            kind, path_kind_identity = self._path_kind_and_identity(normalized)
        except ValueError as exc:
            if (
                normalized in self._bound_identities
                and _exception_code(exc)
                == "repository_io_owner_controlled_root_failed"
            ):
                raise ValueError("repository_io_batch_identity_changed") from None
            raise
        if normalized in self._bound_identities:
            if path_kind_identity != self._bound_identities[normalized]:
                raise ValueError("repository_io_batch_identity_changed")
        if kind == "missing":
            if required:
                raise ValueError(f"repository_io_required_path_missing={_path_label(normalized)}")
            if self._lstat(normalized) is not None:
                raise ValueError("repository_io_read_identity_changed")
            self._consume(path_keys=(normalized,))
            receipt = self._record(
                RepositoryIOReceipt("read", normalized, "missing", path_count=1, reason="missing")
            )
            return EvidenceBytes(normalized, None, False, receipt)
        if kind != "regular":
            raise ValueError(f"repository_io_regular_file_required={_path_label(normalized)}:{kind}")
        remaining_bytes = self.policy.max_total_bytes - self._bytes_read
        if remaining_bytes <= 0:
            raise ValueError("repository_io_total_bytes_exceeded")
        if path_kind_identity is None:
            raise ValueError("repository_io_read_identity_changed")
        expected_identity = self._bound_identities.get(normalized, path_kind_identity)
        if expected_identity is None:
            raise ValueError("repository_io_read_identity_changed")

        def descriptor_authority_validator(descriptor: int, path: str) -> bool:
            if (
                path != "."
                and path != normalized
                and not normalized.startswith(f"{path}/")
            ):
                return False
            try:
                return not _descriptor_has_acl(descriptor)
            except (OSError, TypeError, ValueError):
                return False

        self._consume(path_keys=(normalized,))
        try:
            payloads = read_regular_files_from_anchor(
                self.anchor,
                [normalized],
                max_bytes=self.policy.max_file_bytes,
                max_total_bytes=remaining_bytes,
                max_paths=1,
                timeout_seconds=self._remaining_seconds(),
                expected_identities={normalized: expected_identity},
                descriptor_authority_validator=descriptor_authority_validator,
            )
        except ValueError as exc:
            code = _exception_code(exc)
            mapped = _READ_ERROR_MAP.get(code)
            if mapped == "repository_io_file_too_large":
                raise ValueError(f"repository_io_file_too_large={_path_label(normalized)}") from None
            if mapped is not None:
                raise ValueError(mapped) from None
            raise ValueError("repository_io_read_identity_changed") from None
        payload: AnchoredFilePayload = payloads[0]
        after = self._lstat(normalized)
        if after is None or self._stable_metadata(after) != expected_identity:
            raise ValueError("repository_io_read_identity_changed")
        digest = hashlib.sha256(payload.data).hexdigest()
        self._consume(scanned=len(payload.data))
        receipt = self._record(
            RepositoryIOReceipt(
                "read",
                normalized,
                "present",
                sha256=digest,
                size=len(payload.data),
                bytes_scanned=len(payload.data),
                path_count=1,
            )
        )
        return EvidenceBytes(normalized, payload.data, True, receipt)

    def read_text(
        self,
        path: object,
        *,
        required: bool = True,
        audience: str = "internal",
    ) -> EvidenceText:
        if audience not in {"internal", "model"}:
            raise ValueError("repository_io_audience_invalid")
        if audience == "model" and self._model_records >= self.policy.model_max_matches:
            raise ValueError("repository_io_model_record_budget_exceeded")
        evidence = self.read_bytes(path, required=required)
        if not evidence.exists or evidence.data is None:
            visible_path = evidence.path if audience == "internal" else _path_label(evidence.path)
            if audience == "model":
                self._consume(records=1)
            return EvidenceText(visible_path, None, False, audience, evidence.receipt)
        if audience == "internal":
            try:
                text = evidence.data.decode("utf-8")
            except UnicodeDecodeError:
                raise ValueError(f"repository_io_non_utf8_text={_path_label(evidence.path)}") from None
            return EvidenceText(evidence.path, text, True, audience, evidence.receipt)
        if len(evidence.data) > self.policy.model_max_file_bytes:
            raise ValueError(f"repository_io_model_file_too_large={_path_label(evidence.path)}")
        text, truncated = _model_projection(evidence.data)
        rendered = len(text.encode("utf-8"))
        if rendered > self.policy.model_max_file_bytes:
            raise ValueError(f"repository_io_model_file_too_large={_path_label(evidence.path)}")
        self._consume(rendered=rendered, records=1)
        receipt = self._record(
            RepositoryIOReceipt(
                "read-model",
                evidence.path,
                "present",
                sha256=evidence.receipt.sha256,
                size=evidence.receipt.size,
                bytes_scanned=evidence.receipt.bytes_scanned,
                bytes_rendered=rendered,
                path_count=1,
                truncated=truncated,
                reason="redacted" if truncated else None,
            )
        )
        return EvidenceText(
            str(
                _public_path(
                    evidence.path,
                    max_characters=self.policy.model_max_record_characters,
                )
            ),
            text,
            True,
            audience,
            receipt,
        )

    def read_many(
        self,
        paths: Iterable[object],
        *,
        required: bool = True,
        audience: str = "internal",
    ) -> list[EvidenceText]:
        normalized = self._normalize_path_inputs(paths)
        if audience == "model" and len(normalized) > (
            self.policy.model_max_matches - self._model_records
        ):
            raise ValueError("repository_io_model_record_budget_exceeded")
        self._bind_batch_identities(normalized)
        result = [
            self.read_text(path, required=required, audience=audience)
            for path in normalized
        ]
        self._revalidate_bound_paths(normalized)
        return result

    def snapshot_paths(self, paths: Iterable[object]) -> list[dict[str, object]]:
        normalized = self._normalize_path_inputs(paths)
        self._bind_batch_identities(normalized)
        result: list[dict[str, object]] = []
        for path in normalized:
            evidence = self.read_bytes(path, required=False)
            result.append(
                {
                    "path": path,
                    "state": "present" if evidence.exists else "missing",
                    "sha256": evidence.receipt.sha256,
                    "size": evidence.receipt.size,
                }
            )
        self._revalidate_bound_paths(normalized)
        return result

    def _profile_selected(self, profile: str, path: str) -> bool:
        if any(part in _IGNORED_COMPONENTS for part in path.split("/")):
            return False
        prefixes = _PROFILE_PREFIXES[profile]
        if prefixes is None:
            return True
        return any(path == prefix or path.startswith(f"{prefix}/") for prefix in prefixes)

    def _profile_may_descend(self, profile: str, path: str) -> bool:
        if any(part in _IGNORED_COMPONENTS for part in path.split("/")):
            return False
        prefixes = _PROFILE_PREFIXES[profile]
        if prefixes is None:
            return True
        return any(
            path == prefix
            or path.startswith(f"{prefix}/")
            or prefix.startswith(f"{path}/")
            for prefix in prefixes
        )

    @staticmethod
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

    @staticmethod
    def _stable_root_metadata(metadata: os.stat_result) -> tuple[int, ...]:
        """Bind authority-sensitive root metadata, excluding access time."""

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

    def _owner_controlled_root_identity(self) -> tuple[int, ...]:
        """Return the unchanged held-root identity or fail closed."""

        self._remaining_seconds()
        try:
            before = os.fstat(self.anchor.fd)
            revalidate_repository_root_anchor(self.anchor)
        except ValueError as exc:
            code = _exception_code(exc)
            if code in {
                "repository_root_identity_changed",
                "repository_root_mount_identity_changed",
            }:
                raise ValueError(code) from None
            raise ValueError("repository_io_owner_controlled_root_failed") from None
        except (OSError, TypeError):
            raise ValueError("repository_io_owner_controlled_root_failed") from None
        try:
            if (
                _require_local_authority_filesystem(self.anchor)
                != self._authority_filesystem_type
            ):
                raise ValueError("repository_io_filesystem_locality_changed")
            after = os.fstat(self.anchor.fd)
        except (OSError, TypeError, ValueError):
            raise ValueError("repository_io_owner_controlled_root_failed") from None
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
        identities = (
            self._stable_root_metadata(self.anchor.metadata),
            self._stable_root_metadata(before),
            self._stable_root_metadata(after),
        )
        if (
            not stat.S_ISDIR(before.st_mode)
            or before.st_uid != expected_uid
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or _descriptor_has_acl(self.anchor.fd)
            or any(identity != identities[0] for identity in identities[1:])
        ):
            raise ValueError("repository_io_owner_controlled_root_failed")
        return identities[0]

    def _capture_metadata_listing(
        self,
        profile: str,
        *,
        include_ignored: bool = False,
        scope_prefix: str = "",
        excluded_root_entries: frozenset[str] = frozenset(),
        pruned_directory_names: frozenset[str] = frozenset(),
    ) -> tuple[dict[str, object], ...]:
        normalized_scope = (
            normalize_repo_relative_path(scope_prefix) if scope_prefix else ""
        )

        def scope_reachable(path: str) -> bool:
            return (
                not normalized_scope
                or path == normalized_scope
                or path.startswith(f"{normalized_scope}/")
                or normalized_scope.startswith(f"{path}/")
            )

        def capture_once() -> tuple[dict[str, object], ...]:
            count = 0
            entries: list[dict[str, object]] = []
            try:
                root_metadata = os.fstat(self.anchor.fd)
                expected_uid = (
                    os.geteuid() if hasattr(os, "geteuid") else root_metadata.st_uid
                )
                root_has_acl = _descriptor_has_acl(self.anchor.fd)
            except (OSError, TypeError, ValueError):
                raise ValueError(
                    "repository_io_complete_inventory_root_untrusted"
                    if include_ignored
                    else "repository_io_inventory_root_untrusted"
                ) from None
            if (
                not stat.S_ISDIR(root_metadata.st_mode)
                or root_metadata.st_uid != expected_uid
                or root_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or root_has_acl
            ):
                raise ValueError(
                    "repository_io_complete_inventory_root_untrusted"
                    if include_ignored
                    else "repository_io_inventory_root_untrusted"
                )

            def walk(directory_fd: int, parent: str, depth: int) -> None:
                nonlocal count
                if depth > 128:
                    raise ValueError("repository_io_directory_depth_exceeded")
                self._remaining_seconds()
                before_directory = os.fstat(directory_fd)
                try:
                    with os.scandir(directory_fd) as iterator:
                        names: list[str] = []
                        for entry in iterator:
                            count += 1
                            self._remaining_seconds()
                            if count > self.policy.max_paths:
                                raise ValueError("repository_io_path_budget_exceeded")
                            names.append(entry.name)
                        names.sort()
                except OSError as exc:
                    raise ValueError("repository_io_inventory_walk_failed") from None
                after_directory = os.fstat(directory_fd)
                if self._stable_metadata(before_directory) != self._stable_metadata(after_directory):
                    raise ValueError("repository_io_inventory_changed")
                for name in names:
                    path = f"{parent}/{name}" if parent else name
                    if not parent and name in excluded_root_entries:
                        continue
                    try:
                        if normalize_repo_relative_path(path) != path:
                            raise ValueError("repository_io_inventory_path_invalid")
                    except (TypeError, ValueError) as exc:
                        raise ValueError("repository_io_inventory_path_invalid") from None
                    if not scope_reachable(path):
                        continue
                    if not include_ignored and not self._profile_may_descend(profile, path):
                        continue
                    try:
                        before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    except OSError as exc:
                        raise ValueError("repository_io_inventory_changed") from None
                    if before.st_dev != self.anchor.metadata.st_dev:
                        raise ValueError("repository_io_inventory_mount_escape")
                    if stat.S_ISDIR(before.st_mode):
                        try:
                            child_fd = os.open(
                                name,
                                os.O_RDONLY
                                | os.O_DIRECTORY
                                | os.O_NOFOLLOW
                                | getattr(os, "O_CLOEXEC", 0),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(child_fd)
                        except OSError as exc:
                            raise ValueError("repository_io_inventory_parent_changed") from None
                        try:
                            if (
                                not stat.S_ISDIR(opened.st_mode)
                                or self._stable_metadata(before) != self._stable_metadata(opened)
                                or opened.st_uid
                                != (
                                    os.geteuid()
                                    if hasattr(os, "geteuid")
                                    else opened.st_uid
                                )
                                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                                or _descriptor_has_acl(child_fd)
                            ):
                                raise ValueError(
                                    "repository_io_complete_inventory_directory_untrusted"
                                    if include_ignored
                                    else "repository_io_inventory_parent_changed"
                                )
                            try:
                                require_same_repository_mount(self.anchor, child_fd, path)
                            except ValueError as exc:
                                raise ValueError("repository_io_inventory_mount_escape") from None
                            if include_ignored or self._profile_selected(profile, path):
                                directory_item: dict[str, object] = {
                                    "path": path,
                                    "kind": "directory",
                                    "mode": f"{stat.S_IMODE(opened.st_mode):04o}",
                                    "size": None,
                                }
                                if include_ignored:
                                    directory_item["identity"] = self._stable_metadata(opened)
                                entries.append(directory_item)
                            if not (
                                name.casefold() in pruned_directory_names
                                or (
                                    pruned_directory_names
                                    is _VALIDATION_PRUNED_DIRECTORY_NAMES
                                    and _validation_prune_directory_name(name)
                                )
                            ):
                                walk(child_fd, path, depth + 1)
                            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                            if self._stable_metadata(opened) != self._stable_metadata(after):
                                raise ValueError("repository_io_inventory_changed")
                        finally:
                            os.close(child_fd)
                        continue
                    if stat.S_ISREG(before.st_mode):
                        expected_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
                        if (
                            before.st_nlink != 1
                            or before.st_uid != expected_uid
                            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                        ):
                            raise ValueError(
                                f"repository_io_inventory_untrusted_regular={_path_label(path)}"
                            )
                        if before.st_size > self.policy.max_file_bytes:
                            raise ValueError(
                                f"repository_io_file_too_large={_path_label(path)}"
                            )
                        file_fd = -1
                        file_has_acl = False
                        try:
                            file_fd = os.open(
                                name,
                                os.O_RDONLY
                                | os.O_NOFOLLOW
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NONBLOCK", 0),
                                dir_fd=directory_fd,
                            )
                            opened = os.fstat(file_fd)
                            require_descriptor_on_repository_mount(self.anchor, file_fd, path)
                            file_has_acl = _descriptor_has_acl(file_fd)
                            after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        except (OSError, TypeError, ValueError):
                            raise ValueError(
                                f"repository_io_inventory_regular_identity_changed={_path_label(path)}"
                            ) from None
                        finally:
                            if file_fd >= 0:
                                os.close(file_fd)
                        if file_has_acl:
                            raise ValueError(
                                "repository_io_complete_inventory_file_acl_rejected"
                                if include_ignored
                                else "repository_io_inventory_file_acl_rejected"
                            )
                        if (
                            not stat.S_ISREG(opened.st_mode)
                            or self._stable_metadata(before) != self._stable_metadata(opened)
                            or self._stable_metadata(opened) != self._stable_metadata(after)
                        ):
                            raise ValueError(
                                f"repository_io_inventory_regular_identity_changed={_path_label(path)}"
                            )
                        if include_ignored or self._profile_selected(profile, path):
                            entries.append(
                                {
                                    "path": path,
                                    "kind": "regular",
                                    "mode": f"{stat.S_IMODE(before.st_mode):04o}",
                                    "size": before.st_size,
                                    "identity": self._stable_metadata(before),
                                }
                            )
                        continue
                    if include_ignored or self._profile_selected(profile, path):
                        kind = "symlink" if stat.S_ISLNK(before.st_mode) else "special"
                        raise ValueError(
                            f"repository_io_inventory_unsafe_entry={_path_label(path)}:{kind}"
                        )
                revalidate_repository_root_anchor(self.anchor)

            walk(self.anchor.fd, "", 0)
            return tuple(sorted(entries, key=lambda item: str(item["path"])))

        first = capture_once()
        second = capture_once()
        if first != second:
            raise ValueError("repository_io_inventory_changed")
        return first

    def _internal_listing(self, profile: str) -> tuple[dict[str, object], ...]:
        if profile not in _PROFILE_PREFIXES:
            raise ValueError("repository_io_profile_invalid")
        cached = self._listing_cache.get(profile)
        if cached is not None:
            if self._capture_metadata_listing(profile) != cached:
                raise ValueError("repository_io_inventory_changed")
            return cached
        entries = self._capture_metadata_listing(profile)
        self._consume(path_keys=(str(item["path"]) for item in entries))
        for item in entries:
            if item.get("kind") != "regular":
                continue
            path = str(item["path"])
            identity = item.get("identity")
            if not isinstance(identity, tuple) or len(identity) != 7:
                raise ValueError("repository_io_inventory_identity_missing")
            if path in self._bound_identities and self._bound_identities[path] != identity:
                raise ValueError("repository_io_inventory_changed")
            self._bound_identities[path] = identity
        self._listing_cache[profile] = entries
        self._record(
            RepositoryIOReceipt(
                "list-internal",
                None,
                "complete",
                sha256=_canonical_sha256(entries),
                path_count=len(entries),
            )
        )
        return entries

    def internal_paths(self, profile: str) -> tuple[str, ...]:
        return tuple(
            str(item["path"])
            for item in self._internal_listing(profile)
            if item.get("kind") == "regular"
        )

    def internal_directories(self, profile: str) -> tuple[str, ...]:
        return tuple(
            str(item["path"])
            for item in self._internal_listing(profile)
            if item.get("kind") == "directory"
        )

    def complete_inventory(
        self, scope_prefix: str = ""
    ) -> tuple[dict[str, object], ...]:
        """Controller-only, no-ignore identity listing for package authority."""

        normalized_scope = (
            normalize_repo_relative_path(scope_prefix) if scope_prefix else ""
        )
        root_identity_before = self._owner_controlled_root_identity()
        captured_entries = self._capture_metadata_listing(
            "intake", include_ignored=True, scope_prefix=normalized_scope
        )
        root_identity_after = self._owner_controlled_root_identity()
        if root_identity_before != root_identity_after:
            raise ValueError("repository_io_complete_inventory_changed")
        entries = (
            {
                "path": ".",
                "kind": "root",
                "mode": f"{stat.S_IMODE(self.anchor.metadata.st_mode):04o}",
                "size": None,
                "identity": root_identity_after,
            },
            *captured_entries,
        )
        cached = self._complete_listing_cache.get(normalized_scope)
        if cached is not None:
            if (
                entries != cached
                or self._complete_root_identity_cache.get(normalized_scope)
                != root_identity_after
            ):
                raise ValueError("repository_io_complete_inventory_changed")
            return cached
        self._consume(path_keys=(str(item["path"]) for item in entries))
        for item in entries:
            if item.get("kind") not in {"regular", "directory"}:
                continue
            path = str(item["path"])
            identity = item.get("identity")
            if not isinstance(identity, tuple) or len(identity) != 7:
                raise ValueError("repository_io_complete_inventory_identity_missing")
            if path in self._bound_identities and self._bound_identities[path] != identity:
                raise ValueError("repository_io_complete_inventory_changed")
            self._bound_identities[path] = identity
        self._complete_listing_cache[normalized_scope] = entries
        self._complete_root_identity_cache[normalized_scope] = root_identity_after
        return entries

    def validation_inventory(self) -> tuple[dict[str, object], ...]:
        """Controller-only no-ignore validation view with fixed safe pruning."""

        root_identity_before = self._owner_controlled_root_identity()
        captured_entries = self._capture_metadata_listing(
            "intake",
            include_ignored=True,
            excluded_root_entries=_VALIDATION_EXCLUDED_ROOT_ENTRIES,
            pruned_directory_names=_VALIDATION_PRUNED_DIRECTORY_NAMES,
        )
        root_identity_after = self._owner_controlled_root_identity()
        if root_identity_before != root_identity_after:
            raise ValueError("repository_io_validation_inventory_changed")
        entries = (
            {
                "path": ".",
                "kind": "root",
                "mode": f"{stat.S_IMODE(self.anchor.metadata.st_mode):04o}",
                "size": None,
                "identity": root_identity_after,
            },
            *captured_entries,
        )
        cached = self._validation_listing_cache
        if cached is not None:
            if (
                entries != cached
                or self._validation_root_identity_cache != root_identity_after
            ):
                raise ValueError("repository_io_validation_inventory_changed")
            return cached
        self._consume(path_keys=(str(item["path"]) for item in entries))
        for item in entries:
            if item.get("kind") not in {"directory", "regular"}:
                continue
            path = str(item["path"])
            identity = item.get("identity")
            if not isinstance(identity, tuple) or len(identity) != 7:
                raise ValueError(
                    "repository_io_validation_inventory_identity_missing"
                )
            if (
                path in self._bound_identities
                and self._bound_identities[path] != identity
            ):
                raise ValueError("repository_io_validation_inventory_changed")
            self._bound_identities[path] = identity
        self._validation_listing_cache = entries
        self._validation_root_identity_cache = root_identity_after
        return entries

    def revalidate_listing(self, profile: str) -> None:
        cached = self._internal_listing(profile)
        if self._capture_metadata_listing(profile) != cached:
            raise ValueError("repository_io_inventory_changed")

    def list_paths(
        self,
        profile: str,
    ) -> PathListing:
        selected = self._internal_listing(profile)
        remaining_records = self.policy.model_max_matches - self._model_records
        remaining_bytes = self.policy.model_max_total_bytes - self._model_bytes
        if remaining_bytes <= 0:
            raise ValueError("repository_io_model_bytes_exceeded")
        paths_list: list[str] = []
        directories_list: list[str] = []
        truncated = False
        reason: str | None = None
        for item in selected:
            if len(paths_list) + len(directories_list) >= remaining_records:
                truncated = True
                reason = "record_budget"
                break
            public = str(
                _public_path(
                    str(item["path"]),
                    max_characters=self.policy.model_max_record_characters,
                )
            )
            candidate_paths = [*paths_list, public] if item.get("kind") == "regular" else paths_list
            candidate_directories = (
                [*directories_list, public]
                if item.get("kind") == "directory"
                else directories_list
            )
            candidate_rendered = len(
                json.dumps(
                    {"paths": candidate_paths, "directories": candidate_directories},
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                ).encode("utf-8")
            )
            if candidate_rendered > remaining_bytes:
                truncated = True
                reason = "model_byte_budget"
                break
            paths_list = candidate_paths
            directories_list = candidate_directories
        paths = tuple(paths_list)
        directories = tuple(directories_list)
        rendered = len(
            json.dumps(
                {"paths": paths, "directories": directories},
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
        if rendered > remaining_bytes:
            raise ValueError("repository_io_model_bytes_exceeded")
        returned_count = len(paths) + len(directories)
        self._consume(rendered=rendered, records=returned_count)
        receipt = self._record(
            RepositoryIOReceipt(
                "list",
                None,
                "complete",
                sha256=_canonical_sha256(
                    {
                        "profile": profile,
                        "paths": paths,
                        "directories": directories,
                        "truncated": truncated,
                    }
                ),
                bytes_rendered=rendered,
                path_count=returned_count,
                truncated=truncated,
                reason=reason,
            )
        )
        listing = PathListing(profile, paths, directories, receipt)
        return listing

    def inventory(self, profile: str = "intake") -> list[dict[str, object]]:
        already_listed = profile in self._listing_cache
        remaining_bytes = self.policy.max_total_bytes - self._bytes_read
        if remaining_bytes <= 0:
            raise ValueError("repository_io_total_bytes_exceeded")
        try:
            inventory = snapshot_repository_inventory_from_anchor(
                self.anchor,
                exclude=lambda path: not self._profile_may_descend(profile, path),
                max_bytes=self.policy.max_file_bytes,
                # The primitive performs a full confirmation pass.  The
                # public policy is a logical repository-content budget,
                # so both physical passes receive twice the remaining
                # logical allowance while the session charges once.
                max_total_bytes=remaining_bytes * 2,
                max_paths=self.policy.max_paths,
                timeout_seconds=self._remaining_seconds(),
                descriptor_authority_validator=self._descriptor_authority_validator,
            )
        except ValueError as exc:
            code = _exception_code(exc)
            if code in _INVENTORY_ERROR_CODES:
                raise ValueError(f"repository_io_inventory_failed={code}") from None
            raise ValueError("repository_io_inventory_failed") from None
        selected = tuple(
            dict(item)
            for item in inventory
            if self._profile_selected(profile, str(item.get("path", "")))
        )
        unique_bytes = sum(
            int(item.get("size") or 0)
            for item in selected
            if item.get("kind") in {"regular", "symlink"}
        )
        self._consume(
            path_keys=() if already_listed else (str(item["path"]) for item in selected),
            scanned=unique_bytes,
        )
        return [dict(item) for item in selected]

    def search(self, profile: str) -> SearchResult:
        if profile not in _SEARCH_SIGNALS:
            raise ValueError("repository_io_profile_invalid")
        paths = self.internal_paths(profile)
        records: list[dict[str, object]] = []
        remaining_records = self.policy.model_max_matches - self._model_records
        remaining_bytes = self.policy.model_max_total_bytes - self._model_bytes
        if remaining_bytes < 2:
            raise ValueError("repository_io_model_bytes_exceeded")
        truncated = False
        reason: str | None = None
        scanned = 0
        paths_read = 0
        for path_index, path in enumerate(paths):
            if len(records) >= remaining_records:
                truncated = path_index < len(paths)
                reason = "match_budget" if truncated else None
                break
            evidence = self.read_bytes(path, required=True)
            scanned += evidence.receipt.bytes_scanned
            paths_read += 1
            text, _redacted = _model_projection(evidence.data or b"")
            signals = _SEARCH_SIGNALS[profile]
            for signal_index, (signal, pattern) in enumerate(signals):
                count = 0
                first_offset: int | None = None
                for match in pattern.finditer(text):
                    count += 1
                    if first_offset is None:
                        first_offset = match.start()
                if first_offset is None:
                    continue
                first_line = text.count("\n", 0, first_offset) + 1
                record = {
                    "path": _public_path(
                        path,
                        max_characters=self.policy.model_max_record_characters,
                    ),
                    "signal": signal,
                    "occurrence_count": count,
                    "first_line": first_line,
                }
                if len(_canonical_record(record)) > self.policy.model_max_record_characters:
                    record["path"] = _redacted_path(path)
                if len(_canonical_record(record)) > self.policy.model_max_record_characters:
                    truncated = True
                    reason = "record_character_budget"
                    break
                candidate = [*records, record]
                candidate_rendered = len(
                    json.dumps(
                        candidate,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                    ).encode("utf-8")
                )
                if candidate_rendered > remaining_bytes:
                    truncated = True
                    reason = "model_byte_budget"
                    break
                records.append(record)
                if len(records) >= remaining_records:
                    more_signals = any(
                        later.search(text) is not None
                        for _later_signal, later in signals[signal_index + 1 :]
                    )
                    more_paths = path_index + 1 < len(paths)
                    truncated = more_signals or more_paths
                    reason = "match_budget" if truncated else None
                    break
            if truncated:
                break
        self.revalidate_listing(profile)
        rendered = len(
            json.dumps(
                records,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode("utf-8")
        )
        self._consume(rendered=rendered, records=len(records))
        receipt = self._record(
            RepositoryIOReceipt(
                "search",
                None,
                "complete",
                sha256=_canonical_sha256({"profile": profile, "records": records}),
                bytes_scanned=scanned,
                bytes_rendered=rendered,
                path_count=paths_read,
                match_count=len(records),
                truncated=truncated,
                reason=reason,
            )
        )
        return SearchResult(profile, tuple(records), receipt)

    def _read_owner_controlled_write_target(
        self,
        parent_fd: int,
        name: str,
    ) -> tuple[os.stat_result, bytes] | None:
        """Read an existing CAS target through the descriptor we authorize."""

        before = regular_target_metadata_at(parent_fd, name)
        if before is None:
            return None
        descriptor = -1
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=parent_fd,
            )
            opened = os.fstat(descriptor)
            expected_uid = os.geteuid() if hasattr(os, "geteuid") else opened.st_uid
            try:
                has_acl = _descriptor_has_acl(descriptor)
            except (OSError, TypeError, ValueError):
                raise ValueError("planner_write_target_not_owner_controlled") from None
            if (
                not stat.S_ISREG(opened.st_mode)
                or self._stable_metadata(before) != self._stable_metadata(opened)
                or opened.st_nlink != 1
                or opened.st_uid != expected_uid
                or opened.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                or has_acl
            ):
                raise ValueError("planner_write_target_not_owner_controlled")
            require_descriptor_on_repository_mount(self.anchor, descriptor, name)
            if opened.st_size > self.policy.max_file_bytes:
                raise ValueError("planner_write_target_too_large")
            chunks: list[bytes] = []
            remaining = opened.st_size + 1
            while remaining > 0:
                self._remaining_seconds()
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            current = b"".join(chunks)
            after_fd = os.fstat(descriptor)
            try:
                has_acl_after = _descriptor_has_acl(descriptor)
            except (OSError, TypeError, ValueError):
                raise ValueError("planner_write_target_not_owner_controlled") from None
        except ValueError:
            raise
        except (OSError, TypeError):
            raise ValueError("planner_write_cas_mismatch") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        try:
            after_path = regular_target_metadata_at(parent_fd, name)
        except (OSError, TypeError, ValueError):
            raise ValueError("planner_write_cas_mismatch") from None
        if (
            after_path is None
            or has_acl_after
            or self._stable_metadata(opened) != self._stable_metadata(after_fd)
            or self._stable_metadata(opened) != self._stable_metadata(after_path)
            or len(current) != opened.st_size
        ):
            raise ValueError("planner_write_cas_mismatch")
        return opened, current

    def _open_write_parent(
        self,
        path: str,
        *,
        create: bool,
    ) -> tuple[
        int,
        list[tuple[int, str, int, os.stat_result]],
        os.stat_result,
    ]:
        revalidate_repository_root_anchor(self.anchor)
        trusted_root = _require_owner_controlled_write_directory(self.anchor.fd)
        if (
            trusted_root.st_dev != self.anchor.metadata.st_dev
            or trusted_root.st_ino != self.anchor.metadata.st_ino
        ):
            raise ValueError("planner_write_parent_not_owner_controlled")
        parts = path.split("/")
        current_fd = self.anchor.fd
        chain: list[tuple[int, str, int, os.stat_result]] = []
        for component in parts[:-1]:
            parent_path = "." if not chain else "/".join(parts[: len(chain)])

            def parent_authority_validator(descriptor: int) -> bool:
                try:
                    require_same_repository_mount(
                        self.anchor,
                        descriptor,
                        parent_path,
                    )
                    _require_owner_controlled_write_directory(descriptor)
                    return True
                except (OSError, TypeError, ValueError):
                    return False

            try:
                child_fd, metadata, created = open_or_create_child_directory(
                    current_fd,
                    component,
                    create=create,
                    mode=0o700,
                    parent_authority_validator=parent_authority_validator,
                )
            except ValueError as exc:
                for _parent, _name, descriptor, _metadata in reversed(chain):
                    os.close(descriptor)
                if str(exc) == "artifact_parent_authority_rejected":
                    raise ValueError("planner_write_parent_not_owner_controlled") from None
                raise
            except Exception:
                for _parent, _name, descriptor, _metadata in reversed(chain):
                    os.close(descriptor)
                raise
            try:
                require_same_repository_mount(
                    self.anchor,
                    child_fd,
                    "/".join(parts[: len(chain) + 1]),
                )
                trusted_metadata = _require_owner_controlled_write_directory(child_fd)
                if (
                    trusted_metadata.st_dev != metadata.st_dev
                    or trusted_metadata.st_ino != metadata.st_ino
                ):
                    raise ValueError("planner_write_parent_not_owner_controlled")
                metadata = trusted_metadata
                if created:
                    os.fsync(child_fd)
                    os.fsync(current_fd)
            except Exception:
                os.close(child_fd)
                for _parent, _name, descriptor, _metadata in reversed(chain):
                    os.close(descriptor)
                raise
            chain.append((current_fd, component, child_fd, metadata))
            current_fd = child_fd
        revalidate_repository_root_anchor(self.anchor)
        trusted_root = _require_owner_controlled_write_directory(self.anchor.fd)
        return current_fd, chain, trusted_root

    def write_planner_text(
        self,
        stage: str,
        path: object,
        text: str,
        expected_state: object,
    ) -> RepositoryIOReceipt:
        normalized = _safe_relative_path(path)
        if normalized == "Planner-docs/Step4-Readiness-Receipt.json":
            raise ValueError("planner_write_validator_owned_target")
        if not _stage_target_allowed(stage, normalized):
            raise ValueError("planner_write_target_not_allowed")
        if not isinstance(text, str):
            raise TypeError("planner_write_text_required")
        encoded = text.encode("utf-8")
        if len(encoded) > self.policy.max_file_bytes:
            raise ValueError("planner_write_file_too_large")
        assert_safe_persistent_text(text)
        expected_kind, expected_digest = _expected_state(expected_state)
        # Reserve the session budget before mutation.  A post-commit budget
        # failure would otherwise report failure for a file that did commit.
        self._consume(path_keys=(normalized,), scanned=len(encoded))
        parent_fd = -1
        chain: list[tuple[int, str, int, os.stat_result]] = []
        root_authority_metadata: os.stat_result | None = None
        committed = False
        try:
            try:
                parent_fd, chain, root_authority_metadata = self._open_write_parent(
                    normalized,
                    create=expected_kind == "missing",
                )
            except FileNotFoundError as exc:
                raise ValueError("planner_write_cas_mismatch") from None
            except OSError:
                raise ValueError("artifact_commit_state_unknown") from None

            def target_matches_expected() -> bool:
                try:
                    observed = self._read_owner_controlled_write_target(
                        parent_fd,
                        normalized.rsplit("/", 1)[-1],
                    )
                    if expected_kind == "missing":
                        return observed is None
                    if observed is None:
                        return False
                    _metadata, current = observed
                    return hashlib.sha256(current).hexdigest() == expected_digest
                except (OSError, TypeError, ValueError):
                    return False

            def revalidate() -> bool:
                try:
                    revalidate_repository_root_anchor(self.anchor)
                    current_root = _require_owner_controlled_write_directory(
                        self.anchor.fd
                    )
                    if (
                        root_authority_metadata is None
                        or self._stable_metadata(current_root)
                        != self._stable_metadata(root_authority_metadata)
                    ):
                        return False
                    for ancestor_fd, name, descriptor, metadata in chain:
                        require_same_repository_mount(self.anchor, descriptor, normalized)
                        current_parent = _require_owner_controlled_write_directory(
                            descriptor
                        )
                        if (
                            not directory_entry_matches(ancestor_fd, name, metadata)
                            or current_parent.st_dev != metadata.st_dev
                            or current_parent.st_ino != metadata.st_ino
                        ):
                            return False
                    return target_matches_expected()
                except (OSError, TypeError, ValueError):
                    return False

            authorized_target_identity: tuple[int, int, int, int, int, int, int] | None = None

            def descriptor_authority_validator(descriptor: int, phase: str) -> bool:
                try:
                    metadata = os.fstat(descriptor)
                    expected_uid = (
                        os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
                    )
                    require_descriptor_on_repository_mount(
                        self.anchor,
                        descriptor,
                        normalized,
                    )
                    if (
                        not stat.S_ISREG(metadata.st_mode)
                        or metadata.st_nlink != 1
                        or metadata.st_uid != expected_uid
                        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
                        or _descriptor_has_acl(descriptor)
                    ):
                        return False
                    if phase in {"initial", "displaced"}:
                        # Darwin's atomic exchange may advance inode ctime even
                        # when content and authority are unchanged.  Bind the
                        # durable target identity here while ACL state is
                        # checked directly on this live descriptor.
                        return (
                            authorized_target_identity is not None
                            and self._stable_metadata(metadata)[:-1]
                            == authorized_target_identity[:-1]
                        )
                    return phase == "published" and stat.S_IMODE(metadata.st_mode) == 0o600
                except (OSError, TypeError, ValueError):
                    return False

            with locked_directory(parent_fd):
                observed = self._read_owner_controlled_write_target(
                    parent_fd,
                    normalized.rsplit("/", 1)[-1],
                )
                if observed is None:
                    actual_kind, actual_digest = "missing", None
                else:
                    metadata, current = observed
                    authorized_target_identity = self._stable_metadata(metadata)
                    self._consume(scanned=len(current))
                    actual_kind, actual_digest = "present", hashlib.sha256(current).hexdigest()
                if actual_kind != expected_kind or actual_digest != expected_digest:
                    raise ValueError("planner_write_cas_mismatch")
                try:
                    published = atomic_write_bytes_at(
                        parent_fd,
                        normalized.rsplit("/", 1)[-1],
                        encoded,
                        revalidate=revalidate,
                        mode=0o600,
                        expected_state=expected_kind,
                        expected_sha256=expected_digest,
                        descriptor_authority_validator=descriptor_authority_validator,
                    )
                    try:
                        revalidate_repository_root_anchor(self.anchor)
                        current_root = _require_owner_controlled_write_directory(
                            self.anchor.fd
                        )
                        if (
                            root_authority_metadata is None
                            or self._stable_metadata(current_root)
                            != self._stable_metadata(root_authority_metadata)
                        ):
                            raise ValueError("artifact_published_parent_changed")
                        for ancestor_fd, name, descriptor, ancestor_metadata in chain:
                            require_same_repository_mount(self.anchor, descriptor, normalized)
                            current_parent = _require_owner_controlled_write_directory(
                                descriptor
                            )
                            if (
                                not directory_entry_matches(
                                    ancestor_fd,
                                    name,
                                    ancestor_metadata,
                                )
                                or current_parent.st_dev != ancestor_metadata.st_dev
                                or current_parent.st_ino != ancestor_metadata.st_ino
                            ):
                                raise ValueError("artifact_published_parent_changed")
                        target_name = normalized.rsplit("/", 1)[-1]
                        published_observation = self._read_owner_controlled_write_target(
                            parent_fd,
                            target_name,
                        )
                        if published_observation is None:
                            raise ValueError("artifact_published_identity_changed")
                        current_metadata, confirmed = published_observation
                        if (
                            self._stable_metadata(current_metadata)
                            != self._stable_metadata(published)
                            or current_metadata.st_nlink != 1
                            or stat.S_IMODE(current_metadata.st_mode) != 0o600
                        ):
                            raise ValueError("artifact_published_identity_changed")
                        after_metadata = regular_target_metadata_at(parent_fd, target_name)
                        if (
                            after_metadata is None
                            or self._stable_metadata(current_metadata)
                            != self._stable_metadata(after_metadata)
                            or len(confirmed) != len(encoded)
                            or hashlib.sha256(confirmed).hexdigest()
                            != hashlib.sha256(encoded).hexdigest()
                        ):
                            raise ValueError("artifact_published_content_changed")
                        revalidate_repository_root_anchor(self.anchor)
                    except (OSError, TypeError, ValueError):
                        raise ValueError("artifact_commit_state_unknown") from None
                    committed = True
                except OSError as exc:
                    raise ValueError("artifact_commit_state_unknown") from None
                except ValueError as exc:
                    if str(exc) in {
                        "artifact_directory_identity_changed",
                        "artifact_target_appeared_during_write",
                        "artifact_target_changed_during_write",
                    }:
                        raise ValueError("planner_write_cas_mismatch") from None
                    if str(exc) == "artifact_commit_state_unknown":
                        raise
                    raise ValueError("artifact_commit_state_unknown") from None
        finally:
            for _ancestor_fd, _name, descriptor, _metadata in reversed(chain):
                os.close(descriptor)
        if not committed:
            raise ValueError("planner_write_not_committed")
        return self._record(
            RepositoryIOReceipt(
                "write-planner",
                normalized,
                "committed",
                sha256=hashlib.sha256(encoded).hexdigest(),
                size=len(encoded),
                bytes_scanned=len(encoded),
                path_count=1,
            )
        )


_ACTIVE_ENGINES: dict[object, _RepositoryIOEngine] = {}


class RepositoryIO:
    """Narrow public facade; descriptor/controller capabilities stay private."""

    __slots__ = ("__token", "__active")

    def __init__(self, engine: _RepositoryIOEngine) -> None:
        if not isinstance(engine, _RepositoryIOEngine):
            raise TypeError("repository_io_engine_required")
        self.__token = object()
        _ACTIVE_ENGINES[self.__token] = engine
        self.__active = True

    def __get_engine(self) -> _RepositoryIOEngine:
        if not self.__active:
            raise ValueError("repository_io_session_closed")
        engine = _ACTIVE_ENGINES.get(self.__token)
        if engine is None:
            raise ValueError("repository_io_session_closed")
        return engine

    def __close(self) -> None:
        _ACTIVE_ENGINES.pop(self.__token, None)
        self.__active = False

    def read_text(
        self,
        path: object,
        *,
        required: bool = True,
        audience: str = "internal",
    ) -> EvidenceText:
        return self.__get_engine().read_text(path, required=required, audience=audience)

    def read_many(
        self,
        paths: Iterable[object],
        *,
        required: bool = True,
        audience: str = "internal",
    ) -> list[EvidenceText]:
        return self.__get_engine().read_many(paths, required=required, audience=audience)

    def list_paths(
        self,
        profile: str,
    ) -> PathListing:
        return self.__get_engine().list_paths(profile)

    def search(self, profile: str) -> SearchResult:
        return self.__get_engine().search(profile)

    def write_planner_text(
        self,
        stage: str,
        path: object,
        text: str,
        expected_state: object,
    ) -> RepositoryIOReceipt:
        return self.__get_engine().write_planner_text(stage, path, text, expected_state)


def _controller_engine(repository: RepositoryIO) -> _RepositoryIOEngine:
    if not isinstance(repository, RepositoryIO):
        raise TypeError("repository_io_session_required")
    return repository._RepositoryIO__get_engine()


def _controller_canonical_root(repository: RepositoryIO) -> Path:
    return _controller_engine(repository).root


def _controller_path_kind(repository: RepositoryIO, path: object) -> str:
    return _controller_engine(repository).path_kind(path)


def _controller_read_bytes(
    repository: RepositoryIO,
    path: object,
    *,
    required: bool = True,
) -> EvidenceBytes:
    return _controller_engine(repository).read_bytes(path, required=required)


def _controller_regular_paths(repository: RepositoryIO, profile: str) -> tuple[str, ...]:
    return _controller_engine(repository).internal_paths(profile)


def _controller_directories(repository: RepositoryIO, profile: str) -> tuple[str, ...]:
    return _controller_engine(repository).internal_directories(profile)


def _controller_complete_inventory(
    repository: RepositoryIO,
    scope_prefix: str = "",
) -> tuple[dict[str, object], ...]:
    return _controller_engine(repository).complete_inventory(scope_prefix)


def _controller_validation_inventory(
    repository: RepositoryIO,
) -> tuple[dict[str, object], ...]:
    return _controller_engine(repository).validation_inventory()


def _controller_require_owner_controlled_root(repository: RepositoryIO) -> None:
    """Fail unless the held root remains private, owned, and unchanged."""

    _controller_engine(repository)._owner_controlled_root_identity()


def _controller_inventory(
    repository: RepositoryIO,
    profile: str = "intake",
) -> list[dict[str, object]]:
    return _controller_engine(repository).inventory(profile)


def _controller_snapshot_paths(
    repository: RepositoryIO,
    paths: Iterable[object],
) -> list[dict[str, object]]:
    return _controller_engine(repository).snapshot_paths(paths)


def _controller_workspace_proof(
    repository: RepositoryIO,
    *,
    exclude_untracked=None,
    exclude_tracked=None,
) -> ControllerWorkspaceProof:
    return _controller_engine(repository).workspace_proof(
        exclude_untracked=exclude_untracked,
        exclude_tracked=exclude_tracked,
    )


def _controller_root_proof(repository: RepositoryIO) -> ControllerRootProof:
    return _controller_engine(repository).root_proof()


def _controller_evidence_digest(value: object) -> str:
    return canonical_git_evidence_digest(value)


def _controller_normalize_path(value: object) -> str:
    return normalize_repo_relative_path(value)


def _controller_snapshot_digest(value: object) -> str:
    return repository_snapshot_digest(value)


def _controller_baseline_digest(value: object) -> str:
    return baseline_digest(value)


def _controller_evidence_from_snapshots(
    allowed_paths: Iterable[object],
    baseline_snapshot: Sequence[dict[str, object]],
    current_snapshot: Sequence[dict[str, object]],
    *,
    apply_run_id: str,
    task_id: str,
    apply_run_registration_id: str,
    contract_digest: str,
    generation: int,
    review_package_sha256: str,
) -> dict[str, object]:
    return repository_evidence_from_snapshots(
        allowed_paths,
        baseline_snapshot,
        current_snapshot,
        apply_run_id=apply_run_id,
        task_id=task_id,
        apply_run_registration_id=apply_run_registration_id,
        contract_digest=contract_digest,
        generation=generation,
        review_package_sha256=review_package_sha256,
    )


@contextmanager
def _controller_validation_cwd(
    repository: RepositoryIO,
    normalized_cwd: str,
) -> Iterator[int]:
    engine = _controller_engine(repository)
    normalized = "." if normalized_cwd == "." else normalize_repo_relative_path(normalized_cwd)
    current_fd = os.dup(engine.anchor.fd)
    try:
        require_same_repository_mount(engine.anchor, current_fd, ".")
        if normalized != ".":
            prefix: list[str] = []
            for component in normalized.split("/"):
                prefix.append(component)
                child_fd, metadata = open_child_directory(current_fd, component)
                try:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ValueError("validation_cwd_identity_changed")
                    require_same_repository_mount(engine.anchor, child_fd, "/".join(prefix))
                except Exception:
                    os.close(child_fd)
                    raise
                os.close(current_fd)
                current_fd = child_fd
        yield current_fd
    finally:
        os.close(current_fd)


@contextmanager
def open_repository_io(
    root: str | os.PathLike[str],
    policy: RepositoryIOPolicy | str = DEFAULT_POLICY,
) -> Iterator[RepositoryIO]:
    selected = DEFAULT_POLICY if policy == PLANNER_EVIDENCE_POLICY_V1 else policy
    if not isinstance(selected, RepositoryIOPolicy):
        raise TypeError("repository_io_policy_required")
    with open_repository_root_anchor(root) as anchor:
        repository = RepositoryIO(_RepositoryIOEngine(anchor, selected))
        try:
            yield repository
        finally:
            repository._RepositoryIO__close()


@contextmanager
def _open_cli_repository_io_from_cwd() -> Iterator[RepositoryIO]:
    with open_repository_cwd_anchor() as anchor:
        repository = RepositoryIO(_RepositoryIOEngine(anchor, DEFAULT_POLICY))
        try:
            revalidate_repository_root_anchor(anchor)
            if _controller_engine(repository).root != anchor.path:
                raise ValueError("repository_cli_cwd_binding_failed")
            yield repository
        finally:
            repository._RepositoryIO__close()


def _print_json(value: object) -> None:
    print(serialize_safe_persistent_json(value), end="")


def _read_controller_stdin_request() -> tuple[list[str], bytes | None]:
    """Read one bounded argv-native request without involving a shell."""

    raw = sys.stdin.buffer.read(MAX_CONTROLLER_STDIN_REQUEST_BYTES + 1)
    if len(raw) > MAX_CONTROLLER_STDIN_REQUEST_BYTES:
        raise ValueError("repository_io_controller_request_too_large")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("repository_io_controller_request_non_utf8") from None
    request = parse_safe_persistent_json(decoded)
    if not isinstance(request, dict):
        raise ValueError("repository_io_controller_request_invalid")
    keys = frozenset(request)
    if keys not in (
        frozenset({"schema", "argv"}),
        frozenset({"schema", "argv", "body"}),
    ) or request.get("schema") != CONTROLLER_STDIN_REQUEST_SCHEMA:
        raise ValueError("repository_io_controller_request_invalid")
    raw_argv = request.get("argv")
    if (
        not isinstance(raw_argv, list)
        or not 1 <= len(raw_argv) <= MAX_CONTROLLER_STDIN_ARGV_ITEMS
        or any(
            not isinstance(item, str)
            or not item
            or len(item) > MAX_CONTROLLER_STDIN_ARGUMENT_CHARACTERS
            for item in raw_argv
        )
        or sum(len(item) for item in raw_argv)
        > MAX_CONTROLLER_STDIN_REQUEST_BYTES
        or "request-stdin" in raw_argv
    ):
        raise ValueError("repository_io_controller_request_invalid")
    argv = list(raw_argv)
    body = request.get("body") if "body" in request else None
    if body is not None:
        if (
            not isinstance(body, str)
            or len(body.encode("utf-8")) > DEFAULT_MAX_FILE_BYTES
            or len(argv) < 3
            or argv[0:2] != ["--root", "."]
            or argv[2] != "write-planner"
        ):
            raise ValueError("repository_io_controller_request_invalid")
        body_bytes: bytes | None = body.encode("utf-8")
    else:
        if len(argv) >= 3 and argv[0:2] == ["--root", "."] and argv[2] == "write-planner":
            raise ValueError("repository_io_controller_request_body_required")
        body_bytes = None
    return argv, body_bytes


class _RepositoryArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        del message
        raise ValueError("repository_io_cli_arguments_invalid")


def parse_args(argv: list[str]) -> argparse.Namespace:
    if (
        len(argv) < 2
        or argv[0:2] != ["--root", "."]
        or any(token == "--root" or token.startswith("--root=") for token in argv[2:])
    ):
        raise ValueError("repository_io_cli_root_must_be_exact_dot")
    parser = _RepositoryArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--root", required=True, choices=(".",), help="Repository root must be the actual current directory.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("inspect", "search"):
        child = subparsers.add_parser(command)
        child.add_argument("--profile", required=True, choices=sorted(_PROFILE_PREFIXES))
    read_model = subparsers.add_parser("read-model")
    read_model.add_argument("--path", required=True)
    write = subparsers.add_parser("write-planner")
    write.add_argument("--stage", required=True, choices=sorted(_FIXED_STAGE_TARGETS))
    write.add_argument("--path", required=True)
    expected = write.add_mutually_exclusive_group(required=True)
    expected.add_argument("--expected-missing", action="store_true")
    expected.add_argument("--expected-sha256")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    request_body: bytes | None = None
    if arguments == ["request-stdin"]:
        try:
            arguments, request_body = _read_controller_stdin_request()
        except (OSError, TypeError, ValueError):
            print("repository_io_failed=repository_io_operation_failed", file=sys.stderr)
            return 1
    try:
        args = parse_args(arguments)
    except (SystemExit, TypeError, ValueError):
        print("repository_io_failed=repository_io_operation_failed", file=sys.stderr)
        return 1
    try:
        with _open_cli_repository_io_from_cwd() as repository:
            if args.command == "inspect":
                listing = repository.list_paths(args.profile)
                _print_json(
                    {
                        "profile": listing.profile,
                        "paths": [_public_path(path) for path in listing.paths],
                        "directories": [_public_path(path) for path in listing.directories],
                        "receipt": _public_receipt(listing.receipt),
                    }
                )
            elif args.command == "search":
                result = repository.search(args.profile)
                _print_json(
                    {
                        "profile": result.profile,
                        "records": [
                            {**record, "path": _public_path(str(record.get("path", "")))}
                            for record in result.records
                        ],
                        "receipt": _public_receipt(result.receipt),
                    }
                )
            elif args.command == "read-model":
                evidence = repository.read_text(args.path, required=True, audience="model")
                _print_json(
                    {
                        "path": _public_path(evidence.path),
                        "text": evidence.text,
                        "receipt": _public_receipt(evidence.receipt),
                    }
                )
            elif args.command == "write-planner":
                data = (
                    request_body
                    if request_body is not None
                    else sys.stdin.buffer.read(DEFAULT_MAX_FILE_BYTES + 1)
                )
                if len(data) > DEFAULT_MAX_FILE_BYTES:
                    raise ValueError("planner_write_file_too_large")
                try:
                    body = data.decode("utf-8")
                except UnicodeDecodeError:
                    raise ValueError("planner_write_non_utf8_stdin") from None
                expected: object = "missing" if args.expected_missing else args.expected_sha256
                receipt = repository.write_planner_text(args.stage, args.path, body, expected)
                _print_json({"receipt": _public_receipt(receipt)})
            else:  # pragma: no cover - argparse closes this enum
                raise ValueError("repository_io_command_invalid")
    except (OSError, TypeError, ValueError) as exc:
        del exc
        print("repository_io_failed=repository_io_operation_failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_POLICY",
    "EvidenceBytes",
    "EvidenceText",
    "PLANNER_EVIDENCE_POLICY_V1",
    "PathListing",
    "REPOSITORY_IO_RECEIPT_SCHEMA",
    "RepositoryIO",
    "RepositoryIOPolicy",
    "RepositoryIOReceipt",
    "SearchResult",
    "open_repository_io",
]
