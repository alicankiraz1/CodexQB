#!/usr/bin/env python3
"""Create and validate CodexQB Step 4 apply-run artifacts.

This script manages artifact contracts and can execute only the exact planned,
safe validation commands through ``run-validation``. It does not implement
code, call Codex tools, commit, push, create PRs, deploy, or mutate external
systems.
"""

from __future__ import annotations

import argparse
import base64
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
from datetime import datetime, timezone
import difflib
import errno
import hashlib
import hmac
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from safety_contracts import (  # noqa: E402
    assert_safe_embedded_content_bytes,
    assert_safe_persistent_text,
    assert_safe_serialized_artifact,
    budget_limit,
    canonical_json_digest,
    default_budget_contract,
    implementation_contract_source_binding,
    implementation_contract_validation_command_ids,
    has_secret_like,
    parse_safe_persistent_json,
    path_is_inside,
    safe_log_text,
    safe_validation_command_item,
    serialize_safe_persistent_json,
    token_usage_not_observed,
    validate_budget_contract,
    validate_token_usage,
)
from artifact_io import (  # noqa: E402
    atomic_write_bytes_at as secure_atomic_write_bytes_at,
    atomic_write_json_at as secure_atomic_write_json_at,
    atomic_write_text_at as secure_atomic_write_text_at,
    directory_entry_matches as secure_directory_entry_matches,
    locked_directory,
    read_regular_bytes_at as secure_read_regular_bytes_at,
    read_regular_unvalidated_bytes_at as secure_read_regular_unvalidated_bytes_at,
    read_regular_json_at as secure_read_regular_json_at,
    read_regular_text_at as secure_read_regular_text_at,
    regular_target_metadata_at,
    unlink_regular_at as secure_unlink_regular_at,
)
from evidence_contracts import (  # noqa: E402
    CONTROLLER_OBSERVER,
    ENFORCED_LANDLOCK_REPO_WRITE_DENY,
    ENFORCED_SEATBELT_DENY_NETWORK,
    ENFORCED_SEATBELT_REPO_WRITE_DENY,
    ENFORCED_SECCOMP_INET_DENY,
    NOT_OBSERVED,
    REVIEW_COMPLETION_OBSERVATION_SCOPE,
    REVIEW_COMPLETION_RECEIPT_KIND,
    REVIEW_COMPLETION_RECEIPT_VERSION,
    VALIDATION_OBSERVATION_SCOPE,
    VALIDATION_RECEIPT_KIND,
    VALIDATION_RECEIPT_VERSION,
    canonical_json_digest as receipt_json_digest,
    sign_review_completion_receipt,
    sign_validation_receipt,
    trust_key_id as receipt_trust_key_id,
    verify_review_completion_receipt,
    verify_validation_receipt,
)
from repository_evidence import (  # noqa: E402
    DEFAULT_MAX_FILE_BYTES as DEFAULT_WORKSPACE_INVENTORY_MAX_FILE_BYTES,
    DEFAULT_MAX_PATHS as DEFAULT_WORKSPACE_INVENTORY_MAX_PATHS,
    DEFAULT_MAX_TOTAL_BYTES as DEFAULT_WORKSPACE_INVENTORY_MAX_TOTAL_BYTES,
    DEFAULT_SNAPSHOT_TIMEOUT_SECONDS as DEFAULT_WORKSPACE_INVENTORY_TIMEOUT_SECONDS,
    REPOSITORY_EVIDENCE_SCHEMA_VERSION,
    baseline_digest as repository_baseline_digest,
    capture_repository_evidence,
    normalize_repo_relative_path,
    open_repository_root_anchor,
    repository_snapshot_digest,
    require_same_repository_mount,
    snapshot_allowed_paths,
    snapshot_repository_inventory,
)
from mount_identity import (  # noqa: E402
    APPLY_RUN_MUTATION,
    READ_ONLY_EVIDENCE,
    RUN_REPLACE_QUARANTINE_DELETE,
    MountResolution,
    require_mount_assurance,
    require_same_mount,
    resolve_mount_identity,
)
from git_evidence import (  # noqa: E402
    canonical_git_evidence_digest,
    capture_git_workspace_evidence,
)


ARTIFACT_SCHEMA_VERSION = 3
HANDOFF_CONTRACT_VERSION = 2
APPLY_RUN_SCHEMA_VERSION = 3
SUPPORTED_APPLY_RUN_SCHEMA_VERSIONS = frozenset({APPLY_RUN_SCHEMA_VERSION})
PLUGIN_VERSION = "0.3.0"
VALIDATOR_PATH = Path(__file__).resolve().with_name("validate_planner_docs.py")
MAX_VALIDATION_OUTPUT_BYTES = 8 * 1024 * 1024
VALIDATION_OUTPUT_CHUNK_BYTES = 64 * 1024
MAX_WORKSPACE_INVENTORY_FILE_BYTES = DEFAULT_WORKSPACE_INVENTORY_MAX_FILE_BYTES
MAX_WORKSPACE_INVENTORY_TOTAL_BYTES = DEFAULT_WORKSPACE_INVENTORY_MAX_TOTAL_BYTES
MAX_WORKSPACE_INVENTORY_PATHS = DEFAULT_WORKSPACE_INVENTORY_MAX_PATHS
WORKSPACE_INVENTORY_TIMEOUT_SECONDS = DEFAULT_WORKSPACE_INVENTORY_TIMEOUT_SECONDS
MACOS_VALIDATION_SANDBOX = Path("/usr/bin/sandbox-exec")
MACOS_VALIDATION_SANDBOX_PROFILE = (
    "(version 1)(allow default)(deny process-fork)"
)
# JavaScript (Vitest) validation profile.  Unlike the pytest/unittest profile,
# it PERMITS bounded child spawning (node worker threads plus real child
# processes such as git/bash/python3) but ENFORCES network denial at the kernel
# level (macOS seatbelt ``(deny network*)`` / Linux seccomp INET-socket denial)
# and denies repository writes (macOS seatbelt file-write-deny; Linux Landlock
# best-effort backed by the post-hoc repository-digest compare).
VITEST_LOGICAL_RUNNER = "vitest"
VITEST_RUNNER_RELPATH = "node_modules/vitest/vitest.mjs"
NODE_INTERPRETER = "node"
# Candidate Vitest/Vite config filenames, resolved by descriptor under the
# pinned cwd; the first that exists as a regular file is descriptor-pinned and
# passed via ``--config``.
VITEST_CONFIG_CANDIDATES = (
    "vitest.config.ts",
    "vitest.config.mts",
    "vitest.config.cts",
    "vitest.config.js",
    "vitest.config.mjs",
    "vitest.config.cjs",
    "vite.config.ts",
    "vite.config.mts",
    "vite.config.cts",
    "vite.config.js",
    "vite.config.mjs",
    "vite.config.cjs",
)
# Executor-injected Vitest flags (the planner supplies none).  ``--no-cache``
# stops Vitest writing ``node_modules/.vite/vitest/results.json`` into the
# repository (which the repo-write-deny profile forbids); ``--pool=threads``
# with ``--no-file-parallelism`` pins deterministic in-process execution.
VITEST_INJECTED_RUN_FLAGS = (
    "run",
    "--root",
    ".",
    "--pool=threads",
    "--no-file-parallelism",
    "--reporter=default",
    "--no-cache",
)
LINUX_CLONE_THREAD = 0x00010000


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("length", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]

APPLY_MODES = {"direct", "subagent_serial", "external_superpowers", "no_action"}
WORKSPACE_BASELINE_EXCLUDED_PREFIXES = (
    ".codexqb/",
    ".git/",
    ".pytest_cache/",
    "__pycache__/",
)
WORKSPACE_BASELINE_EXCLUDED_PATHS = {
    "Planner-docs/Planing-Ledger.md",
}
WORKSPACE_BASELINE_KEYS = [
    "vcs",
    "branch",
    "base_commit",
    "git_status_porcelain_sha256",
    "staged_diff_sha256",
    "unstaged_diff_sha256",
    "untracked_inventory_sha256",
    "untracked_count",
    "workspace_file_inventory_sha256",
    "workspace_file_count",
]
IMPLEMENTATION_DRIFT_BASELINE_KEYS = {
    "git_status_porcelain_sha256",
    "unstaged_diff_sha256",
    "untracked_inventory_sha256",
    "untracked_count",
    "workspace_file_inventory_sha256",
    "workspace_file_count",
}
IMPLEMENTATION_DRIFT_SNAPSHOT_PATHS = {
    "git:status",
    "git:unstaged_diff",
    "git:untracked_inventory",
    "workspace:file_inventory",
}
TASK_STATES = {
    "PREFLIGHT",
    "BRIEFED",
    "IMPLEMENTING",
    "IMPLEMENTED",
    "TASK_REVIEW",
    "SECURITY_REVIEW",
    "FIXING",
    "RE_REVIEW",
    "VERIFIED",
    "BLOCKED",
    "NEEDS_CONTEXT",
}
IMPLEMENTER_STATUSES = {"DONE", "DONE_WITH_CONCERNS", "NEEDS_CONTEXT", "BLOCKED"}
IMPLEMENTER_REPORT_ALLOWED_FIELDS = frozenset(
    {
        "status",
        "task_id",
        "brief_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
        "implementer_agent_id",
        "files_changed",
        "concerns",
        "validation_receipt_ids",
        "change_set_id",
        "diff_sha256",
        "controller_decision",
        "blocker",
        "evidence",
    }
)
FIXER_REPORT_ALLOWED_FIELDS = frozenset(
    {
        "status",
        "task_id",
        "brief_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
        "fixer_agent_id",
        "fixes",
        "concerns",
        "validation_receipt_ids",
        "change_set_id",
        "diff_sha256",
        "controller_decision",
        "blocker",
        "evidence",
    }
)
IMPLEMENTER_EVIDENCE_FIELDS = frozenset(
    {
        "brief_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
        "validation_receipt_ids",
        "change_set_id",
        "diff_sha256",
    }
)
SPEC_VERDICTS = {"pass", "fail", "cannot_verify"}
QUALITY_VERDICTS = {"approved", "needs_fixes"}
SECURITY_VERDICTS = {"pass", "fail", "not_required"}
COMMIT_POLICIES = {"none", "local_per_slice", "user_managed"}
READY_STATUSES = {"READY", "READY_WITH_WARNINGS"}
DISPATCH_ROLES = {"implementer", "task_reviewer", "security_reviewer", "fixer", "final_reviewer"}
REVIEW_PHASES = {"spec", "quality", "security", "final"}
EXPECTED_REPORT_PATHS = {
    "implementer": "Implementer-Report.json",
    "task_reviewer_spec": "Review-Report-spec.json",
    "task_reviewer_quality": "Review-Report-quality.json",
    "security_reviewer": "Review-Report-security.json",
    "fixer": "Fix-Report.json",
    "final_reviewer": "Review-Report-final.json",
}
DISPATCH_AGENT_STATUSES = {"spawned", "completed", "failed"}
DISPATCH_ROLE_STATE_REQUIREMENTS = {
    "implementer": {"BRIEFED"},
    "task_reviewer": {"TASK_REVIEW", "RE_REVIEW"},
    "security_reviewer": {"SECURITY_REVIEW"},
    "fixer": {"FIXING"},
    "final_reviewer": {"TASK_REVIEW", "SECURITY_REVIEW", "RE_REVIEW"},
}
AGENT_PROFILES = {
    "controller": {"agent_type": "default", "model_profile": "balanced", "sandbox": "workspace-write"},
    "explorer": {"agent_type": "explorer", "model_profile": "fast", "sandbox": "read-only"},
    "implementer": {"agent_type": "worker", "model_profile": "balanced", "sandbox": "workspace-write"},
    "task_reviewer": {"agent_type": "default", "model_profile": "strong", "sandbox": "read-only"},
    "security_reviewer": {"agent_type": "default", "model_profile": "security_strong", "sandbox": "read-only"},
    "fixer": {"agent_type": "worker", "model_profile": "balanced", "sandbox": "workspace-write"},
    "final_reviewer": {"agent_type": "default", "model_profile": "strong", "sandbox": "read-only"},
}
APPLY_SAFETY = {
    "executes_implementation": False,
    "allows_commit_push_pr_deploy": False,
    "one_writer_per_slice": True,
    "subagents_read_only_by_default": True,
}
VERIFICATION_POLICY = {
    "verification_policy_version": 1,
    "repository_evidence_schema_version": REPOSITORY_EVIDENCE_SCHEMA_VERSION,
    "validation_receipt_version": VALIDATION_RECEIPT_VERSION,
    "review_completion_receipt_version": REVIEW_COMPLETION_RECEIPT_VERSION,
    "all_planned_validation_receipts_required": True,
    "live_repository_rehash_required": True,
    "receipt_context_binding_required": True,
    "review_order": ["spec", "quality", "security_if_required", "final"],
    "trusted_verified_mode": "host_attested_subagent",
    "direct_mode_independent_review_capability": False,
    "host_agent_attestation_required": True,
    "controller_asserted_agent_runs": "evidence_only_unattested",
    "host_sandbox_proof": NOT_OBSERVED,
    "approval_proof": NOT_OBSERVED,
    "network_enforcement_proof": NOT_OBSERVED,
}
STATE_TRANSITIONS = {
    "PREFLIGHT": {"BRIEFED"},
    "BRIEFED": {"IMPLEMENTING", "BLOCKED", "NEEDS_CONTEXT"},
    "IMPLEMENTING": {"IMPLEMENTED", "BLOCKED", "NEEDS_CONTEXT"},
    "IMPLEMENTED": {"TASK_REVIEW"},
    "TASK_REVIEW": {"SECURITY_REVIEW", "FIXING", "VERIFIED"},
    "FIXING": {"RE_REVIEW", "BLOCKED", "NEEDS_CONTEXT"},
    "RE_REVIEW": {"SECURITY_REVIEW", "VERIFIED", "FIXING"},
    "SECURITY_REVIEW": {"VERIFIED", "FIXING", "BLOCKED", "NEEDS_CONTEXT"},
    "VERIFIED": set(),
    "BLOCKED": set(),
    "NEEDS_CONTEXT": set(),
}
WRITER_LOCK_NAME = "Writer-Lock.json"
EVENT_CHAIN_VERSION = 1
EVENT_CHAIN_GENESIS_SHA256 = "0" * 64
EVENT_CHAIN_RESERVED_FIELDS = frozenset(
    {
        "event_chain_version",
        "sequence",
        "timestamp",
        "previous_event_sha256",
        "event_sha256",
    }
)
APPLY_RUNS_RELATIVE_DIR = Path(".codexqb") / "apply-runs"
APPLY_RUN_MARKER_NAME = ".codexqb-apply-run.json"
APPLY_RUN_MARKER_KIND = "codexqb_apply_run"
APPLY_RUN_MARKER_VERSION = 1
MAX_APPLY_RUN_MARKER_BYTES = 1024 * 1024
APPLY_DELETE_QUARANTINE_PREFIX = ".codexqb-delete-"
APPLY_RUN_REGISTRY_DIR_NAME = ".codexqb-run-registry"
APPLY_RUN_REGISTRATION_KIND = "codexqb_apply_run_registration"
APPLY_RUN_REGISTRATION_VERSION = 2
CODEXQB_TRUST_ROOT_ENV = "CODEXQB_TRUST_ROOT"
CODEXQB_TRUST_DIR_NAME = "codexqb-trust"
CODEXQB_TRUST_KEY_NAME = "apply-run-hmac-v1.key"
CODEXQB_TRUST_STATE_NAME = "apply-run-hmac-v1.state.json"
CODEXQB_TRUST_KEY_BYTES = 32
MAX_REPOSITORY_BASELINE_CONTENT_BYTES = 512 * 1024
APPLY_RUN_REPLACE_REQUIRED_KEYS = frozenset(
    {
        "apply_run_schema_version",
        "artifact_schema_version",
        "handoff_contract_version",
        "plugin_version",
        "apply_requested_mode",
        "apply_spec_id",
        "apply_spec_digest",
        "apply_policy_digest",
        "apply_spec_inputs",
        "apply_run_id",
        "apply_run_invocation_id",
        "apply_run_registration_id",
        "mode",
        "workspace_requested",
        "workspace_detected",
        "workspace_verified",
        "workspace_mode",
        "workspace_baseline",
        "worktree_path",
        "base_branch",
        "working_branch",
        "dirty_state",
        "user_approval",
        "commit_policy",
        "push_allowed",
        "pr_allowed",
        "max_writer_agents",
        "max_subagent_depth",
        "budget_contract",
        "token_usage",
        "agent_profiles",
        "source_snapshot",
        "source_snapshot_digest",
        "step4_readiness",
        "external_superpowers",
        "safety",
        "verification_policy",
        "repository_baselines",
        "workspace_file_manifest",
    }
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def parse_utc_timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def atomic_write_text(path: Path, text: str) -> None:
    secure_write_apply_artifact(path, text)


def atomic_write_json(path: Path, payload: object) -> None:
    atomic_write_text(path, serialize_safe_persistent_json(payload))


def append_event(run_dir: Path, event: dict[str, object]) -> dict[str, object]:
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        return append_event_at(handle, event)


def assert_safe_persistent_payload(payload: object) -> None:
    serialize_safe_persistent_json(payload, indent=None, separators=(",", ":"), trailing_newline=False)


def build_chained_event(
    sequence: int,
    previous_event_sha256: str,
    event: dict[str, object],
    *,
    timestamp: str | None = None,
) -> dict[str, object]:
    """Build one canonical event record without allowing chain-field injection."""

    if not isinstance(event, dict):
        raise ValueError("event_must_be_object")
    if EVENT_CHAIN_RESERVED_FIELDS.intersection(event):
        raise ValueError("event_reserved_field_forbidden")
    if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
        raise ValueError("event_sequence_invalid")
    if not re.fullmatch(r"[a-f0-9]{64}", previous_event_sha256):
        raise ValueError("event_previous_hash_invalid")
    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type_required")
    if "actor" in event and not isinstance(event["actor"], str):
        raise ValueError("event_actor_invalid")
    if "apply_run_id" in event and not safe_apply_run_id(event["apply_run_id"]):
        raise ValueError("event_apply_run_id_invalid")
    if "task_id" in event and not safe_task_id(event["task_id"]):
        raise ValueError("event_task_id_invalid")
    event_timestamp = timestamp if timestamp is not None else utc_now()
    if not isinstance(event_timestamp, str) or re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
        event_timestamp,
    ) is None:
        raise ValueError("event_timestamp_invalid")
    record: dict[str, object] = {
        "event_chain_version": EVENT_CHAIN_VERSION,
        "sequence": sequence,
        "timestamp": event_timestamp,
        "previous_event_sha256": previous_event_sha256,
        **event,
    }
    record["event_sha256"] = canonical_json_digest(record)
    assert_safe_persistent_payload(record)
    return record


def parse_chained_event_log(text: str) -> tuple[list[dict[str, object]], list[str]]:
    """Parse and verify a complete event log without exposing attacker-controlled values."""

    errors: list[str] = []
    if not text:
        return [], ["event_log_empty"]
    if not text.endswith("\n"):
        errors.append("invalid_event_log_partial_line")
    events: list[dict[str, object]] = []
    expected_previous = EVENT_CHAIN_GENESIS_SHA256
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            errors.append(f"invalid_event_blank_line=line-{line_no}")
            continue
        try:
            parsed = parse_safe_persistent_json(line)
        except (TypeError, ValueError, json.JSONDecodeError):
            errors.append(f"invalid_event_json=line-{line_no}")
            continue
        if not isinstance(parsed, dict):
            errors.append(f"invalid_event_object=line-{line_no}")
            continue
        events.append(parsed)
        sequence = parsed.get("sequence")
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence != line_no:
            errors.append(f"invalid_event_sequence=line-{line_no}")
        chain_version = parsed.get("event_chain_version")
        if (
            not isinstance(chain_version, int)
            or isinstance(chain_version, bool)
            or chain_version != EVENT_CHAIN_VERSION
        ):
            errors.append(f"invalid_event_chain_version=line-{line_no}")
        timestamp = parsed.get("timestamp")
        if not isinstance(timestamp, str) or re.fullmatch(
            r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
            timestamp,
        ) is None:
            errors.append(f"invalid_event_timestamp=line-{line_no}")
        event_type = parsed.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            errors.append(f"invalid_event_type=line-{line_no}")
        if "actor" in parsed and not isinstance(parsed["actor"], str):
            errors.append(f"invalid_event_actor=line-{line_no}")
        if "apply_run_id" in parsed and not safe_apply_run_id(parsed["apply_run_id"]):
            errors.append(f"invalid_event_apply_run_id=line-{line_no}")
        if "task_id" in parsed and not safe_task_id(parsed["task_id"]):
            errors.append(f"invalid_event_task_id=line-{line_no}")
        if parsed.get("previous_event_sha256") != expected_previous:
            errors.append(f"invalid_event_previous_hash=line-{line_no}")
        claimed_hash = parsed.get("event_sha256")
        if not isinstance(claimed_hash, str) or re.fullmatch(r"[a-f0-9]{64}", claimed_hash) is None:
            errors.append(f"invalid_event_hash=line-{line_no}")
            continue
        digest_input = dict(parsed)
        digest_input.pop("event_sha256", None)
        if canonical_json_digest(digest_input) != claimed_hash:
            errors.append(f"invalid_event_hash=line-{line_no}")
        expected_previous = claimed_hash
    return events, errors


def read_event_log_at(directory_fd: int) -> str:
    try:
        return secure_read_regular_unvalidated_bytes_at(directory_fd, "Events.jsonl").decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("invalid_event_log_utf8") from None


def load_events(run_dir: Path, errors: list[str]) -> list[dict[str, object]]:
    run_fd = -1
    try:
        run_fd = os.open(run_dir, secure_directory_open_flags())
        text = read_event_log_at(run_fd)
    except FileNotFoundError:
        errors.append("missing_events_jsonl")
        return []
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append("invalid_events_jsonl_file")
        return []
    finally:
        if run_fd >= 0:
            os.close(run_fd)
    events, event_errors = parse_chained_event_log(text)
    errors.extend(event_errors)
    return events


def safe_apply_run_id(value: object) -> bool:
    return isinstance(value, str) and bool(
        re.fullmatch(
            r"apply-(direct|external_superpowers|no_action|subagent_serial)-[a-f0-9]{12}-[A-Za-z0-9_.-]+",
            value,
        )
    )


def safe_task_id(value: object) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"AR-apply-[A-Za-z0-9_.-]+-T\d{3}", value))


def is_inside(parent: Path, child: Path) -> bool:
    return path_is_inside(parent, child)


def lexical_absolute(path: Path) -> Path:
    return Path(os.path.abspath(os.fspath(path)))


def repository_mount_relative_path(root: Path, path: Path) -> str:
    root = lexical_absolute(root)
    path = lexical_absolute(path)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected") from exc
    return relative.as_posix() if relative.parts else "."


def resolve_apply_mount_identity(directory_fd: int, operation: str) -> MountResolution:
    resolution = resolve_mount_identity(directory_fd, reconcile=True)
    require_mount_assurance(resolution, operation)
    return resolution


def require_apply_same_mount(
    root_resolution: MountResolution,
    child_fd: int,
    relative_path: str,
    *,
    mismatch_error: str,
) -> None:
    try:
        require_same_mount(root_resolution, child_fd, relative_path)
    except ValueError as exc:
        if str(exc).startswith("repository_nested_mount_rejected="):
            raise ValueError(mismatch_error) from exc
        raise


MOUNTINFO_ESCAPE_RE = re.compile(r"\\([0-7]{3})")


def decode_mountinfo_path(value: str) -> str:
    return MOUNTINFO_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 8)), value)


def path_is_mount_point(path: Path) -> bool:
    try:
        if os.path.ismount(path):
            return True
    except OSError:
        return True
    mountinfo = Path("/proc/self/mountinfo")
    if not mountinfo.exists():
        return sys.platform.startswith("linux")
    try:
        text = mountinfo.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return sys.platform.startswith("linux")
    candidate = os.path.normpath(os.path.realpath(path))
    for line in text.splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) < 5:
            continue
        mounted_at = os.path.normpath(decode_mountinfo_path(fields[4]))
        if mounted_at == candidate:
            return True
    return False


def path_has_indirect_component(root: Path, path: Path) -> bool:
    root = lexical_absolute(root)
    path = lexical_absolute(path)
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return True
        try:
            exists = current.exists()
        except OSError:
            return True
        if not exists:
            continue
        is_junction = getattr(current, "is_junction", None)
        if callable(is_junction) and is_junction():
            return True
        if path_is_mount_point(current):
            return True
    return False


def managed_apply_runs_root(root: Path) -> Path:
    return root / APPLY_RUNS_RELATIVE_DIR


def resolve_managed_apply_run_dir(
    root: Path,
    requested: Path | None,
    default_name: str | None = None,
    *,
    lexical_root: Path | None = None,
) -> Path:
    root = root.resolve()
    lexical_root = lexical_absolute(lexical_root or root)
    runs_root = managed_apply_runs_root(root)
    lexical_runs_root = lexical_root / APPLY_RUNS_RELATIVE_DIR
    candidate = requested if requested is not None else lexical_runs_root / str(default_name or "")
    candidate_lexical = lexical_absolute(candidate)
    inspection_root: Path | None = None
    for possible_root in (lexical_root, root):
        try:
            candidate_lexical.relative_to(possible_root)
        except ValueError:
            continue
        inspection_root = possible_root
        break
    if inspection_root is None:
        raise ValueError("output_dir must be inside the target repository")
    if path_has_indirect_component(
        inspection_root,
        inspection_root / APPLY_RUNS_RELATIVE_DIR,
    ) or path_has_indirect_component(inspection_root, candidate_lexical):
        raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    runs_root_resolved = runs_root.resolve(strict=False)
    candidate_resolved = candidate_lexical.resolve(strict=False)
    if not is_inside(root, candidate_resolved):
        raise ValueError("output_dir must be inside the target repository")
    if candidate_resolved == runs_root_resolved:
        raise ValueError("invalid_apply_run_output_dir=run_directory_required")
    if candidate_resolved.parent != runs_root_resolved:
        raise ValueError("invalid_apply_run_output_dir=must_be_direct_child_of_.codexqb/apply-runs")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", candidate_resolved.name) is None:
        raise ValueError("invalid_apply_run_output_dir=invalid_run_directory_name")
    if has_secret_like(candidate_resolved.name):
        raise ValueError("invalid_apply_run_output_dir=secret_like_run_directory_name")
    return candidate_resolved


def secure_directory_open_flags() -> int:
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_apply_run_replace_not_supported")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


def same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def metadata_is_owner_controlled(metadata: os.stat_result) -> bool:
    expected_uid = os.geteuid() if hasattr(os, "geteuid") else metadata.st_uid
    return metadata.st_uid == expected_uid and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0


def open_child_directory(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("replace_requires_existing_apply_run")
    child_fd = os.open(name, secure_directory_open_flags(), dir_fd=parent_fd)
    try:
        after = os.fstat(child_fd)
    except Exception:
        os.close(child_fd)
        raise
    if not same_file_identity(before, after):
        os.close(child_fd)
        raise ValueError("replace_apply_run_identity_changed")
    return child_fd, after


def opened_directory_matches_path(path: Path, metadata: os.stat_result, *, reject_mount: bool) -> bool:
    try:
        before = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISDIR(before.st_mode) or not same_file_identity(before, metadata):
        return False
    if reject_mount and path_is_mount_point(path):
        return False
    try:
        after = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(after.st_mode) and same_file_identity(before, after) and same_file_identity(after, metadata)


def metadata_is_private_directory(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata_is_owner_controlled(metadata)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
    )


def metadata_is_private_regular_file(metadata: os.stat_result) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata_is_owner_controlled(metadata)
        and stat.S_IMODE(metadata.st_mode) & 0o077 == 0
    )


def open_owned_child_directory(parent_fd: int, name: str, *, create: bool, private: bool) -> int:
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        child_fd, metadata = open_child_directory(parent_fd, name)
    except (OSError, ValueError) as exc:
        raise ValueError("codexqb_trust_store_unavailable") from exc
    valid = metadata_is_private_directory(metadata) if private else metadata_is_owner_controlled(metadata)
    if not valid:
        os.close(child_fd)
        raise ValueError("codexqb_trust_store_permissions_invalid")
    return child_fd


def open_codexqb_trust_root_fd(*, create: bool) -> int:
    override = os.environ.get(CODEXQB_TRUST_ROOT_ENV)
    if override:
        trust_root = Path(override)
        if not trust_root.is_absolute():
            raise ValueError("codexqb_trust_root_must_be_absolute")
        trust_fd = -1
        try:
            trust_fd = os.open(trust_root, secure_directory_open_flags())
            metadata = os.fstat(trust_fd)
        except OSError as exc:
            if trust_fd >= 0:
                os.close(trust_fd)
            raise ValueError("codexqb_trust_store_unavailable") from exc
        if not metadata_is_private_directory(metadata) or not opened_directory_matches_path(
            trust_root,
            metadata,
            reject_mount=True,
        ):
            os.close(trust_fd)
            raise ValueError("codexqb_trust_store_permissions_invalid")
        return trust_fd

    home = lexical_absolute(Path.home())
    home_fd = -1
    codex_fd = -1
    trust_fd = -1
    try:
        home_fd = os.open(home, secure_directory_open_flags())
        home_metadata = os.fstat(home_fd)
        if not metadata_is_owner_controlled(home_metadata) or not opened_directory_matches_path(
            home,
            home_metadata,
            reject_mount=False,
        ):
            raise ValueError("codexqb_trust_store_permissions_invalid")
        codex_fd = open_owned_child_directory(home_fd, ".codex", create=create, private=False)
        trust_fd = open_owned_child_directory(codex_fd, CODEXQB_TRUST_DIR_NAME, create=create, private=True)
        result = trust_fd
        trust_fd = -1
        return result
    finally:
        if trust_fd >= 0:
            os.close(trust_fd)
        if codex_fd >= 0:
            os.close(codex_fd)
        if home_fd >= 0:
            os.close(home_fd)


def load_apply_run_trust_state(trust_fd: int) -> dict[str, object] | None:
    try:
        metadata = os.stat(CODEXQB_TRUST_STATE_NAME, dir_fd=trust_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("codexqb_trust_key_recovery_required") from exc
    if not metadata_is_private_regular_file(metadata):
        raise ValueError("codexqb_trust_key_recovery_required")
    try:
        return load_regular_json_at(trust_fd, CODEXQB_TRUST_STATE_NAME)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("codexqb_trust_key_recovery_required") from exc


def read_apply_run_trust_key(trust_fd: int) -> bytes:
    key_fd = -1
    try:
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        key_fd = os.open(CODEXQB_TRUST_KEY_NAME, flags, dir_fd=trust_fd)
        metadata = os.fstat(key_fd)
        if not metadata_is_private_regular_file(metadata):
            raise ValueError("codexqb_trust_key_permissions_invalid")
        if metadata.st_size != CODEXQB_TRUST_KEY_BYTES:
            raise ValueError("codexqb_trust_key_invalid")
        chunks: list[bytes] = []
        remaining = CODEXQB_TRUST_KEY_BYTES + 1
        while remaining > 0:
            chunk = os.read(key_fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        key = b"".join(chunks)
        if len(key) != CODEXQB_TRUST_KEY_BYTES:
            raise ValueError("codexqb_trust_key_invalid")
        return key
    finally:
        if key_fd >= 0:
            os.close(key_fd)


def create_apply_run_trust_key(trust_fd: int) -> bytes:
    key = secrets.token_bytes(CODEXQB_TRUST_KEY_BYTES)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    key_fd = os.open(CODEXQB_TRUST_KEY_NAME, flags, 0o600, dir_fd=trust_fd)
    try:
        os.fchmod(key_fd, 0o600)
        offset = 0
        while offset < len(key):
            written = os.write(key_fd, key[offset:])
            if written <= 0:
                raise OSError("short CodexQB trust-key write")
            offset += written
        os.fsync(key_fd)
        os.fsync(trust_fd)
    except Exception:
        os.close(key_fd)
        key_fd = -1
        try:
            os.unlink(CODEXQB_TRUST_KEY_NAME, dir_fd=trust_fd)
        except OSError:
            pass
        raise
    finally:
        if key_fd >= 0:
            os.close(key_fd)
    return key


def load_or_create_apply_run_trust_key(*, create: bool) -> bytes:
    trust_fd = open_codexqb_trust_root_fd(create=create)
    try:
        state = load_apply_run_trust_state(trust_fd)
        try:
            key = read_apply_run_trust_key(trust_fd)
        except FileNotFoundError:
            if not create:
                raise ValueError("codexqb_trust_key_unavailable")
            if state is not None:
                raise ValueError("codexqb_trust_key_recovery_required")
            try:
                key = create_apply_run_trust_key(trust_fd)
            except FileExistsError:
                key = read_apply_run_trust_key(trust_fd)
        except OSError as exc:
            raise ValueError("codexqb_trust_key_unavailable") from exc
        expected_state = {
            "trust_state_version": 1,
            "trust_key_id": sha256_bytes(key)[:32],
        }
        if state is None and create:
            try:
                write_regular_json_exclusive_at(
                    trust_fd,
                    CODEXQB_TRUST_STATE_NAME,
                    expected_state,
                )
                os.fsync(trust_fd)
            except FileExistsError:
                state = load_apply_run_trust_state(trust_fd)
            else:
                state = expected_state
        if state is not None and state != expected_state:
            raise ValueError("codexqb_trust_key_recovery_required")
        return key
    finally:
        os.close(trust_fd)


def signed_apply_run_registration(
    root: Path,
    root_metadata: os.stat_result,
    payload: dict[str, object],
    *,
    create_key: bool,
) -> dict[str, object]:
    key = load_or_create_apply_run_trust_key(create=create_key)
    signed = {
        **payload,
        "root_binding_sha256": sha256_bytes(os.fsencode(root)),
        "root_device": root_metadata.st_dev,
        "root_inode": root_metadata.st_ino,
        "trust_key_id": sha256_bytes(key)[:32],
    }
    encoded = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed["registration_mac"] = hmac.new(key, encoded, hashlib.sha256).hexdigest()
    return signed


def trusted_apply_run_registration(
    root: Path,
    root_metadata: os.stat_result,
    registration: object,
) -> bool:
    if not isinstance(registration, dict):
        return False
    registration_mac = registration.get("registration_mac")
    if not isinstance(registration_mac, str) or re.fullmatch(r"[a-f0-9]{64}", registration_mac) is None:
        return False
    try:
        key = load_or_create_apply_run_trust_key(create=False)
    except (OSError, ValueError):
        return False
    if registration.get("trust_key_id") != sha256_bytes(key)[:32]:
        return False
    if registration.get("root_binding_sha256") != sha256_bytes(os.fsencode(root)):
        return False
    if registration.get("root_device") != root_metadata.st_dev or registration.get("root_inode") != root_metadata.st_ino:
        return False
    unsigned = {key_name: value for key_name, value in registration.items() if key_name != "registration_mac"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(key, encoded, hashlib.sha256).hexdigest()
    return hmac.compare_digest(registration_mac, expected)


def open_managed_apply_runs_root_fd(
    root: Path,
    *,
    create: bool,
    root_anchor_fd: int | None = None,
    root_mount_resolution: MountResolution | None = None,
    operation: str = APPLY_RUN_MUTATION,
) -> int:
    root_fd = os.dup(root_anchor_fd) if root_anchor_fd is not None else os.open(root, secure_directory_open_flags())
    codexqb_fd = -1
    runs_fd = -1
    try:
        mount_resolution = root_mount_resolution or resolve_apply_mount_identity(root_fd, operation)
        require_mount_assurance(mount_resolution, operation)
        require_apply_same_mount(
            mount_resolution,
            root_fd,
            ".",
            mismatch_error="invalid_apply_run_output_dir=root_identity_changed",
        )
        root_metadata = os.fstat(root_fd)
        if not opened_directory_matches_path(root, root_metadata, reject_mount=False):
            raise ValueError("invalid_apply_run_output_dir=root_identity_changed")
        if create:
            try:
                os.mkdir(".codexqb", mode=0o700, dir_fd=root_fd)
            except FileExistsError:
                pass
        try:
            codexqb_fd, codexqb_metadata = open_child_directory(root_fd, ".codexqb")
        except (OSError, ValueError) as exc:
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected") from exc
        require_apply_same_mount(
            mount_resolution,
            codexqb_fd,
            ".codexqb",
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        if (
            codexqb_metadata.st_dev != root_metadata.st_dev
            or not opened_directory_matches_path(root / ".codexqb", codexqb_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
        if create:
            try:
                os.mkdir("apply-runs", mode=0o700, dir_fd=codexqb_fd)
            except FileExistsError:
                pass
        try:
            runs_fd, runs_metadata = open_child_directory(codexqb_fd, "apply-runs")
        except (OSError, ValueError) as exc:
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected") from exc
        require_apply_same_mount(
            mount_resolution,
            runs_fd,
            APPLY_RUNS_RELATIVE_DIR.as_posix(),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        if (
            runs_metadata.st_dev != root_metadata.st_dev
            or not opened_directory_matches_path(
                managed_apply_runs_root(root),
                runs_metadata,
                reject_mount=True,
            )
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
        result = runs_fd
        runs_fd = -1
        return result
    finally:
        if runs_fd >= 0:
            os.close(runs_fd)
        if codexqb_fd >= 0:
            os.close(codexqb_fd)
        os.close(root_fd)


def load_regular_json_at(directory_fd: int, name: str) -> dict[str, object]:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_fd = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_APPLY_RUN_MARKER_BYTES:
            raise ValueError("replace_requires_existing_apply_run")
        chunks: list[bytes] = []
        remaining = MAX_APPLY_RUN_MARKER_BYTES + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_APPLY_RUN_MARKER_BYTES:
            raise ValueError("replace_requires_existing_apply_run")
        assert_safe_serialized_artifact(name, raw)
        payload = json.loads(raw.decode("utf-8"))
    finally:
        os.close(file_fd)
    if not isinstance(payload, dict):
        raise ValueError("replace_requires_existing_apply_run")
    return payload


def apply_run_registration_file_name(run_name: str) -> str:
    return f"{sha256_bytes(run_name.encode('utf-8'))}.json"


def open_apply_run_registry_fd(
    root: Path,
    parent_fd: int,
    *,
    create: bool,
    root_mount_resolution: MountResolution | None = None,
    operation: str = APPLY_RUN_MUTATION,
) -> int:
    mount_resolution = root_mount_resolution or resolve_apply_mount_identity(parent_fd, operation)
    require_mount_assurance(mount_resolution, operation)
    require_apply_same_mount(
        mount_resolution,
        parent_fd,
        APPLY_RUNS_RELATIVE_DIR.as_posix(),
        mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
    )
    if create:
        try:
            os.mkdir(APPLY_RUN_REGISTRY_DIR_NAME, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        registry_fd, registry_metadata = open_child_directory(parent_fd, APPLY_RUN_REGISTRY_DIR_NAME)
    except (OSError, ValueError) as exc:
        raise ValueError("replace_requires_registered_apply_run") from exc
    try:
        parent_metadata = os.fstat(parent_fd)
        registry_path = managed_apply_runs_root(root) / APPLY_RUN_REGISTRY_DIR_NAME
        require_apply_same_mount(
            mount_resolution,
            registry_fd,
            repository_mount_relative_path(root, registry_path),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        if (
            registry_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_owner_controlled(registry_metadata)
            or not opened_directory_matches_path(registry_path, registry_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    except Exception:
        os.close(registry_fd)
        raise
    return registry_fd


def write_regular_bytes_exclusive_at(
    directory_fd: int,
    name: str,
    encoded: bytes,
    *,
    max_bytes: int | None = None,
) -> None:
    if not name or name in {".", ".."} or "/" in name or "\x00" in name:
        raise ValueError("invalid_apply_run_artifact_name")
    if max_bytes is not None and len(encoded) > max_bytes:
        raise ValueError("apply_run_artifact_too_large")
    assert_safe_serialized_artifact(name, encoded)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    file_fd = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        offset = 0
        while offset < len(encoded):
            written = os.write(file_fd, encoded[offset:])
            if written <= 0:
                raise OSError("short apply-run registration write")
            offset += written
        os.fsync(file_fd)
    except Exception:
        os.close(file_fd)
        file_fd = -1
        try:
            os.unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        if file_fd >= 0:
            os.close(file_fd)


def write_regular_text_exclusive_at(directory_fd: int, name: str, text: str) -> None:
    write_regular_bytes_exclusive_at(directory_fd, name, text.encode("utf-8"))


def write_regular_json_exclusive_at(directory_fd: int, name: str, payload: object) -> None:
    encoded = serialize_safe_persistent_json(payload).encode("utf-8")
    write_regular_bytes_exclusive_at(
        directory_fd,
        name,
        encoded,
        max_bytes=MAX_APPLY_RUN_MARKER_BYTES,
    )


def write_regular_json_replace_at(directory_fd: int, name: str, payload: object) -> None:
    encoded = serialize_safe_persistent_json(payload).encode("utf-8")
    if len(encoded) > MAX_APPLY_RUN_MARKER_BYTES:
        raise ValueError("apply_run_artifact_too_large")
    secure_atomic_write_bytes_at(directory_fd, name, encoded)


def apply_run_manifest_claim_digest(run: object) -> str | None:
    if not isinstance(run, dict):
        return None
    requested_mode = run.get("apply_requested_mode")
    schema_version = run.get("apply_run_schema_version")
    source_snapshot = run.get("source_snapshot")
    spec_inputs = run.get("apply_spec_inputs")
    invocation_id = run.get("apply_run_invocation_id")
    registration_id = run.get("apply_run_registration_id")
    if (
        requested_mode not in APPLY_MODES
        or not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or not isinstance(source_snapshot, list)
    ):
        return None
    if not all(isinstance(item, dict) for item in source_snapshot):
        return None
    if not isinstance(spec_inputs, dict):
        return None
    ready_queue = spec_inputs.get("ready_queue")
    workspace_baseline_value = spec_inputs.get("workspace_baseline")
    if not isinstance(ready_queue, list) or not all(isinstance(item, dict) for item in ready_queue):
        return None
    if not isinstance(workspace_baseline_value, dict) or not workspace_baseline_value:
        return None
    if not isinstance(invocation_id, str) or re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", invocation_id) is None:
        return None
    if not isinstance(registration_id, str) or re.fullmatch(r"[a-f0-9]{64}", registration_id) is None:
        return None
    try:
        spec_digest = apply_spec_digest(
            str(requested_mode),
            source_snapshot,
            workspace_baseline_value,
            ready_queue,
            apply_run_schema_version=schema_version,
        )
        source_digest = snapshot_digest(source_snapshot)
        spec_inputs_digest = canonical_json_digest(spec_inputs)
    except (TypeError, ValueError):
        return None
    policy_digest = run.get("apply_policy_digest")
    if not isinstance(policy_digest, str) or re.fullmatch(r"[a-f0-9]{64}", policy_digest) is None:
        return None
    expected_run_id = f"apply-{requested_mode}-{spec_digest[:12]}-{invocation_id}"
    expected_spec_id = f"apply-spec-{requested_mode}-{spec_digest[:16]}"
    if run.get("apply_spec_digest") != spec_digest or run.get("apply_spec_id") != expected_spec_id:
        return None
    if run.get("apply_run_id") != expected_run_id or run.get("source_snapshot_digest") != source_digest:
        return None
    claim = {
        "apply_run_schema_version": run.get("apply_run_schema_version"),
        "artifact_schema_version": run.get("artifact_schema_version"),
        "handoff_contract_version": run.get("handoff_contract_version"),
        "plugin_version": run.get("plugin_version"),
        "apply_requested_mode": requested_mode,
        "apply_run_id": expected_run_id,
        "apply_run_invocation_id": invocation_id,
        "apply_run_registration_id": registration_id,
        "apply_spec_id": expected_spec_id,
        "apply_spec_digest": spec_digest,
        "apply_spec_inputs_digest": spec_inputs_digest,
        "apply_policy_digest": policy_digest,
        "source_snapshot_digest": source_digest,
    }
    return canonical_json_digest(claim)


def apply_run_manifest_replace_errors(run: object) -> list[str]:
    if not isinstance(run, dict):
        return ["apply_run_manifest_must_be_object"]
    errors: list[str] = []
    missing = sorted(APPLY_RUN_REPLACE_REQUIRED_KEYS - set(run))
    errors.extend(f"apply_run_manifest_missing={key}" for key in missing)
    if run.get("apply_run_schema_version") != APPLY_RUN_SCHEMA_VERSION:
        errors.append("invalid_apply_run_schema_version")
    if run.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
        errors.append("invalid_artifact_schema_version")
    if run.get("handoff_contract_version") != HANDOFF_CONTRACT_VERSION:
        errors.append("invalid_handoff_contract_version")
    if run.get("plugin_version") != PLUGIN_VERSION:
        errors.append("invalid_plugin_version")
    requested_mode = run.get("apply_requested_mode")
    mode = run.get("mode")
    if requested_mode not in APPLY_MODES:
        errors.append("invalid_apply_requested_mode")
    if mode not in APPLY_MODES:
        errors.append("invalid_mode")
    if mode != requested_mode and not external_superpowers_reconcile_is_valid(run):
        errors.append("invalid_reconciled_mode")
    for key in (
        "workspace_requested",
        "workspace_detected",
        "workspace_mode",
        "worktree_path",
        "base_branch",
        "working_branch",
        "dirty_state",
    ):
        if not isinstance(run.get(key), str):
            errors.append(f"invalid_apply_run_field={key}")
    if run.get("workspace_mode") not in {
        "non_git_unsafe",
        "unverified_current_worktree",
        "verified_isolated_worktree",
    }:
        errors.append("invalid_workspace_mode")
    if run.get("dirty_state") not in {"clean", "dirty", "non_git", "unknown"}:
        errors.append("invalid_dirty_state")
    for key in ("workspace_verified", "user_approval"):
        if not isinstance(run.get(key), bool):
            errors.append(f"invalid_apply_run_field={key}")
    if run.get("commit_policy") != "none":
        errors.append("commit_policy_must_default_to_none")
    if run.get("push_allowed") is not False:
        errors.append("push_must_default_false")
    if run.get("pr_allowed") is not False:
        errors.append("pr_must_default_false")
    if run.get("max_writer_agents") != 1:
        errors.append("only_one_writer_permitted")
    if run.get("max_subagent_depth") != 1:
        errors.append("recursive_subagents_rejected")
    errors.extend(validate_budget_contract(run.get("budget_contract")))
    errors.extend(validate_token_usage(run.get("token_usage")))
    validate_agent_profiles(run, errors)
    baseline = run.get("workspace_baseline")
    if not isinstance(baseline, dict):
        errors.append("workspace_baseline_missing")
    else:
        errors.extend(f"workspace_baseline_missing={key}" for key in WORKSPACE_BASELINE_KEYS if key not in baseline)
    readiness = run.get("step4_readiness")
    if not isinstance(readiness, dict) or not {
        "audit_path",
        "audit_present",
        "ready_queue_count",
        "validator_command",
        "validator_status",
        "validator_output_sha256",
        "execution_queue_state",
        "execution_gate",
        "mode",
    }.issubset(readiness):
        errors.append("step4_readiness_summary_missing")
    external = run.get("external_superpowers")
    if not isinstance(external, dict) or not {
        "required",
        "availability",
        "fallback_mode",
        "adapter_policy",
    }.issubset(external):
        errors.append("external_superpowers_policy_missing")
    elif external.get("availability") == "available" and not external_superpowers_available_is_valid(run):
        errors.append("external_superpowers_available_metadata_missing")
    elif external.get("availability") not in {"available", "not_checked", "unavailable"}:
        errors.append("external_superpowers_invalid_availability")
    if isinstance(external, dict) and external.get("fallback_mode") != "subagent_serial":
        errors.append("external_superpowers_invalid_fallback_mode")
    if run.get("safety") != APPLY_SAFETY:
        errors.append("invalid_apply_safety_contract")
    if apply_run_manifest_claim_digest(run) is None:
        errors.append("invalid_apply_run_manifest_claim")
    return errors


def apply_run_manifest_digest(run: object) -> str | None:
    if apply_run_manifest_replace_errors(run):
        return None
    return canonical_json_digest(run)


def apply_run_refresh_stable_digest(run: object) -> str | None:
    if apply_run_manifest_replace_errors(run):
        return None
    assert isinstance(run, dict)
    stable = {key: value for key, value in run.items() if key not in {"mode", "external_superpowers"}}
    return canonical_json_digest(stable)


def apply_run_marker_payload(root: Path, run_dir: Path, run: dict[str, object]) -> dict[str, object]:
    claim_digest = apply_run_manifest_claim_digest(run)
    manifest_digest = apply_run_manifest_digest(run)
    stable_digest = apply_run_refresh_stable_digest(run)
    if claim_digest is None or manifest_digest is None or stable_digest is None:
        raise ValueError("invalid_apply_run_manifest_claim")
    return {
        "marker_kind": APPLY_RUN_MARKER_KIND,
        "marker_version": APPLY_RUN_MARKER_VERSION,
        "run_dir": run_dir.relative_to(root).as_posix(),
        "apply_run_schema_version": run.get("apply_run_schema_version"),
        "artifact_schema_version": run.get("artifact_schema_version"),
        "handoff_contract_version": run.get("handoff_contract_version"),
        "plugin_version": run.get("plugin_version"),
        "apply_requested_mode": run.get("apply_requested_mode"),
        "apply_run_id": run.get("apply_run_id"),
        "apply_run_invocation_id": run.get("apply_run_invocation_id"),
        "apply_run_registration_id": run.get("apply_run_registration_id"),
        "apply_spec_id": run.get("apply_spec_id"),
        "apply_spec_digest": run.get("apply_spec_digest"),
        "manifest_claim_sha256": claim_digest,
        "manifest_sha256": manifest_digest,
        "refresh_stable_sha256": stable_digest,
    }


def recognized_apply_run_manifest(
    root: Path,
    run_dir: Path,
    marker: object,
    run: object,
    registration: object = None,
    run_metadata: os.stat_result | None = None,
    root_metadata: os.stat_result | None = None,
) -> bool:
    if not isinstance(marker, dict) or not isinstance(run, dict) or not isinstance(registration, dict):
        return False
    claim_digest = apply_run_manifest_claim_digest(run)
    manifest_digest = apply_run_manifest_digest(run)
    stable_digest = apply_run_refresh_stable_digest(run)
    if (
        claim_digest is None
        or manifest_digest is None
        or stable_digest is None
        or run_metadata is None
        or root_metadata is None
    ):
        return False
    if run.get("apply_run_schema_version") != APPLY_RUN_SCHEMA_VERSION:
        return False
    if run.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
        return False
    if run.get("handoff_contract_version") != HANDOFF_CONTRACT_VERSION:
        return False
    if run.get("plugin_version") != PLUGIN_VERSION:
        return False
    registration_id = run.get("apply_run_registration_id")
    if registration.get("registration_kind") != APPLY_RUN_REGISTRATION_KIND:
        return False
    if registration.get("registration_version") != APPLY_RUN_REGISTRATION_VERSION:
        return False
    if registration.get("run_name") != run_dir.name:
        return False
    if registration.get("run_dir") != run_dir.relative_to(root).as_posix():
        return False
    if registration.get("registration_id") != registration_id:
        return False
    if registration.get("manifest_claim_sha256") != claim_digest:
        return False
    if registration.get("manifest_sha256") != manifest_digest:
        return False
    if registration.get("refresh_stable_sha256") != stable_digest:
        return False
    if registration.get("run_device") != run_metadata.st_dev or registration.get("run_inode") != run_metadata.st_ino:
        return False
    if not trusted_apply_run_registration(root, root_metadata, registration):
        return False
    return marker == apply_run_marker_payload(root, run_dir, run)


def apply_run_registration_payload(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
    *,
    root_metadata: os.stat_result,
    run_metadata: os.stat_result,
    create_key: bool,
) -> dict[str, object]:
    claim_digest = apply_run_manifest_claim_digest(run)
    manifest_digest = apply_run_manifest_digest(run)
    stable_digest = apply_run_refresh_stable_digest(run)
    registration_id = run.get("apply_run_registration_id")
    if (
        claim_digest is None
        or manifest_digest is None
        or stable_digest is None
        or not isinstance(registration_id, str)
    ):
        raise ValueError("invalid_apply_run_manifest_claim")
    payload = {
        "registration_kind": APPLY_RUN_REGISTRATION_KIND,
        "registration_version": APPLY_RUN_REGISTRATION_VERSION,
        "registration_id": registration_id,
        "run_name": run_dir.name,
        "run_dir": run_dir.relative_to(root).as_posix(),
        "run_device": run_metadata.st_dev,
        "run_inode": run_metadata.st_ino,
        "manifest_claim_sha256": claim_digest,
        "manifest_sha256": manifest_digest,
        "refresh_stable_sha256": stable_digest,
    }
    return signed_apply_run_registration(root, root_metadata, payload, create_key=create_key)


def create_apply_run_registration(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
    *,
    root_metadata: os.stat_result,
    parent_fd: int,
    run_fd: int,
    run_metadata: os.stat_result,
    root_mount_resolution: MountResolution,
) -> None:
    registry_fd = -1
    try:
        parent_metadata = os.fstat(parent_fd)
        require_no_managed_recovery_quarantine(parent_fd)
        require_mount_assurance(root_mount_resolution, APPLY_RUN_MUTATION)
        require_apply_same_mount(
            root_mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        registry_fd = open_apply_run_registry_fd(
            root,
            parent_fd,
            create=True,
            root_mount_resolution=root_mount_resolution,
        )
        require_no_managed_recovery_quarantine(registry_fd)
        current_run_metadata = os.fstat(run_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not same_file_identity(run_metadata, current_run_metadata)
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
        payload = apply_run_registration_payload(
            root,
            run_dir,
            run,
            root_metadata=root_metadata,
            run_metadata=run_metadata,
            create_key=True,
        )
        try:
            write_regular_json_exclusive_at(
                registry_fd,
                apply_run_registration_file_name(run_dir.name),
                payload,
            )
        except FileExistsError as exc:
            raise ValueError(f"apply_run_registration_exists={run_dir.name}") from exc
        os.fsync(registry_fd)
    finally:
        if registry_fd >= 0:
            os.close(registry_fd)


def refresh_apply_run_provenance(run_dir: Path, run: dict[str, object]) -> None:
    run_dir = run_dir.resolve()
    root = infer_root(run_dir)
    if root is None:
        raise ValueError("source_binding_root_required")
    run_dir = resolve_managed_apply_run_dir(root, run_dir, lexical_root=root)
    root_fd = os.open(root, secure_directory_open_flags())
    parent_fd = -1
    run_fd = -1
    registry_fd = -1
    try:
        root_mount_resolution = resolve_apply_mount_identity(root_fd, APPLY_RUN_MUTATION)
        root_metadata = os.fstat(root_fd)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            root_anchor_fd=root_fd,
            root_mount_resolution=root_mount_resolution,
        )
        parent_metadata = os.fstat(parent_fd)
        require_no_managed_recovery_quarantine(parent_fd)
        run_fd, run_metadata = open_child_directory(parent_fd, run_dir.name)
        require_apply_same_mount(
            root_mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="apply_run_provenance_refresh_identity_changed",
        )
        require_no_managed_recovery_quarantine(run_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("apply_run_provenance_refresh_identity_changed")
        current_run = load_regular_json_at(run_fd, "Apply-Run.json")
        if current_run != run:
            raise ValueError("apply_run_provenance_refresh_manifest_changed")
        marker = load_regular_json_at(run_fd, APPLY_RUN_MARKER_NAME)
        registry_fd = open_apply_run_registry_fd(
            root,
            parent_fd,
            create=False,
            root_mount_resolution=root_mount_resolution,
        )
        require_no_managed_recovery_quarantine(registry_fd)
        registration_name = apply_run_registration_file_name(run_dir.name)
        registration_metadata = os.stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        registration = load_regular_json_at(registry_fd, registration_name)
        current_registration_metadata = os.stat(
            registration_name,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        if (
            not metadata_is_private_regular_file(registration_metadata)
            or not same_file_identity(registration_metadata, current_registration_metadata)
            or not trusted_apply_run_registration(root, root_metadata, registration)
        ):
            raise ValueError("apply_run_provenance_refresh_requires_trusted_registration")
        registration_id = run.get("apply_run_registration_id")
        claim_digest = apply_run_manifest_claim_digest(run)
        stable_digest = apply_run_refresh_stable_digest(run)
        current_marker = apply_run_marker_payload(root, run_dir, run)
        marker_matches_registered_manifest = (
            marker.get("manifest_claim_sha256") == registration.get("manifest_claim_sha256")
            and marker.get("manifest_sha256") == registration.get("manifest_sha256")
            and marker.get("refresh_stable_sha256") == registration.get("refresh_stable_sha256")
        )
        marker_is_current = marker == current_marker
        marker_identity_matches_current = all(
            marker.get(key) == value
            for key, value in current_marker.items()
            if key not in {"manifest_sha256"}
        )
        if (
            registration.get("registration_kind") != APPLY_RUN_REGISTRATION_KIND
            or registration.get("registration_version") != APPLY_RUN_REGISTRATION_VERSION
            or registration.get("registration_id") != registration_id
            or registration.get("run_name") != run_dir.name
            or registration.get("run_dir") != run_dir.relative_to(root).as_posix()
            or registration.get("run_device") != run_metadata.st_dev
            or registration.get("run_inode") != run_metadata.st_ino
            or registration.get("manifest_claim_sha256") != claim_digest
            or registration.get("refresh_stable_sha256") != stable_digest
            or not marker_identity_matches_current
            or not (marker_matches_registered_manifest or marker_is_current)
        ):
            raise ValueError("apply_run_provenance_refresh_requires_trusted_registration")
        new_marker = current_marker
        new_registration = apply_run_registration_payload(
            root,
            run_dir,
            run,
            root_metadata=root_metadata,
            run_metadata=run_metadata,
            create_key=False,
        )
        write_regular_json_replace_at(run_fd, APPLY_RUN_MARKER_NAME, new_marker)
        write_regular_json_replace_at(registry_fd, registration_name, new_registration)
        refreshed_marker = load_regular_json_at(run_fd, APPLY_RUN_MARKER_NAME)
        refreshed_registration = load_regular_json_at(registry_fd, registration_name)
        if not recognized_apply_run_manifest(
            root,
            run_dir,
            refreshed_marker,
            run,
            refreshed_registration,
            run_metadata,
            root_metadata,
        ):
            raise ValueError("apply_run_provenance_refresh_failed")
    finally:
        if registry_fd >= 0:
            os.close(registry_fd)
        if run_fd >= 0:
            os.close(run_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


def current_apply_run_provenance_is_valid(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
) -> bool:
    root_fd = -1
    parent_fd = -1
    run_fd = -1
    registry_fd = -1
    try:
        root = root.resolve()
        run_dir = resolve_managed_apply_run_dir(root, run_dir, lexical_root=root)
        root_fd = os.open(root, secure_directory_open_flags())
        root_mount_resolution = resolve_apply_mount_identity(root_fd, READ_ONLY_EVIDENCE)
        root_metadata = os.fstat(root_fd)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            root_anchor_fd=root_fd,
            root_mount_resolution=root_mount_resolution,
            operation=READ_ONLY_EVIDENCE,
        )
        parent_metadata = os.fstat(parent_fd)
        require_no_managed_recovery_quarantine(parent_fd)
        run_fd, run_metadata = open_child_directory(parent_fd, run_dir.name)
        require_apply_same_mount(
            root_mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        require_no_managed_recovery_quarantine(run_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
            or load_regular_json_at(run_fd, "Apply-Run.json") != run
        ):
            return False
        marker = load_regular_json_at(run_fd, APPLY_RUN_MARKER_NAME)
        registry_fd = open_apply_run_registry_fd(
            root,
            parent_fd,
            create=False,
            root_mount_resolution=root_mount_resolution,
            operation=READ_ONLY_EVIDENCE,
        )
        require_no_managed_recovery_quarantine(registry_fd)
        registration_name = apply_run_registration_file_name(run_dir.name)
        registration_metadata = os.stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        registration = load_regular_json_at(registry_fd, registration_name)
        current_registration_metadata = os.stat(
            registration_name,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(registration_metadata.st_mode)
            or registration_metadata.st_nlink != 1
            or not metadata_is_owner_controlled(registration_metadata)
            or not same_file_identity(registration_metadata, current_registration_metadata)
        ):
            return False
        return recognized_apply_run_manifest(
            root,
            run_dir,
            marker,
            run,
            registration,
            run_metadata,
            root_metadata,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    finally:
        if registry_fd >= 0:
            os.close(registry_fd)
        if run_fd >= 0:
            os.close(run_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        if root_fd >= 0:
            os.close(root_fd)


def open_regular_child(parent_fd: int, name: str) -> tuple[int, os.stat_result]:
    before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("replace_apply_run_tree_changed")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
    child_fd = os.open(name, flags, dir_fd=parent_fd)
    try:
        after = os.fstat(child_fd)
    except Exception:
        os.close(child_fd)
        raise
    if not stat.S_ISREG(after.st_mode) or not same_file_identity(before, after):
        os.close(child_fd)
        raise ValueError("replace_apply_run_tree_changed")
    return child_fd, after


def inventory_identity(metadata: os.stat_result, kind: str) -> dict[str, object]:
    return {
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def inventory_matches(metadata: os.stat_result, entry: dict[str, object], kind: str) -> bool:
    expected_mode = stat.S_ISDIR(metadata.st_mode) if kind == "directory" else stat.S_ISREG(metadata.st_mode)
    return (
        entry.get("kind") == kind
        and expected_mode
        and metadata.st_dev == entry.get("device")
        and metadata.st_ino == entry.get("inode")
    )


def build_deletion_inventory(
    directory_fd: int,
    expected_device: int,
    logical_path: Path,
    *,
    root: Path,
    root_mount_resolution: MountResolution,
) -> dict[str, object]:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    require_apply_same_mount(
        root_mount_resolution,
        directory_fd,
        repository_mount_relative_path(root, logical_path),
        mismatch_error="replace_apply_run_tree_contains_indirect_target",
    )
    directory_metadata = os.fstat(directory_fd)
    if directory_metadata.st_dev != expected_device or path_is_mount_point(logical_path):
        raise ValueError("replace_apply_run_tree_contains_indirect_target")
    inventory = inventory_identity(directory_metadata, "directory")
    entries: dict[str, object] = {}
    inventory["entries"] = entries
    for name in sorted(os.listdir(directory_fd)):
        if name.startswith(APPLY_DELETE_QUARANTINE_PREFIX):
            raise ValueError(f"replace_apply_run_recovery_required={name}")
        entry_path = logical_path / name
        metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            metadata.st_dev != expected_device
            or stat.S_ISLNK(metadata.st_mode)
            or path_is_mount_point(entry_path)
        ):
            raise ValueError("replace_apply_run_tree_contains_indirect_target")
        if stat.S_ISDIR(metadata.st_mode):
            try:
                child_fd, child_metadata = open_child_directory(directory_fd, name)
            except (OSError, ValueError) as exc:
                raise ValueError("replace_apply_run_tree_changed") from exc
            try:
                require_apply_same_mount(
                    root_mount_resolution,
                    child_fd,
                    repository_mount_relative_path(root, entry_path),
                    mismatch_error="replace_apply_run_tree_contains_indirect_target",
                )
                if (
                    child_metadata.st_dev != expected_device
                    or path_is_mount_point(entry_path)
                ):
                    raise ValueError("replace_apply_run_tree_contains_indirect_target")
                entries[name] = build_deletion_inventory(
                    child_fd,
                    expected_device,
                    entry_path,
                    root=root,
                    root_mount_resolution=root_mount_resolution,
                )
            finally:
                os.close(child_fd)
        elif stat.S_ISREG(metadata.st_mode):
            try:
                child_fd, child_metadata = open_regular_child(directory_fd, name)
            except (OSError, ValueError) as exc:
                raise ValueError("replace_apply_run_tree_changed") from exc
            try:
                require_apply_same_mount(
                    root_mount_resolution,
                    child_fd,
                    repository_mount_relative_path(root, entry_path),
                    mismatch_error="replace_apply_run_tree_contains_indirect_target",
                )
                if path_is_mount_point(entry_path):
                    raise ValueError("replace_apply_run_tree_contains_indirect_target")
                entries[name] = inventory_identity(child_metadata, "regular")
            finally:
                os.close(child_fd)
        else:
            raise ValueError("replace_apply_run_tree_contains_unsupported_file")
    return inventory


def create_deletion_quarantine(
    parent_fd: int,
    expected_device: int,
    *,
    root: Path,
    logical_parent: Path,
    root_mount_resolution: MountResolution,
) -> tuple[str, int]:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    require_apply_same_mount(
        root_mount_resolution,
        parent_fd,
        repository_mount_relative_path(root, logical_parent),
        mismatch_error="replace_apply_run_tree_changed",
    )
    for _ in range(32):
        name = f"{APPLY_DELETE_QUARANTINE_PREFIX}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            quarantine_fd, metadata = open_child_directory(parent_fd, name)
        except (OSError, ValueError) as exc:
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise ValueError("replace_apply_run_tree_changed") from exc
        try:
            require_apply_same_mount(
                root_mount_resolution,
                quarantine_fd,
                repository_mount_relative_path(root, logical_parent / name),
                mismatch_error="replace_apply_run_tree_changed",
            )
        except Exception:
            os.close(quarantine_fd)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        if metadata.st_dev != expected_device:
            os.close(quarantine_fd)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise ValueError("replace_apply_run_tree_changed")
        return name, quarantine_fd
    raise ValueError("replace_apply_run_quarantine_unavailable")


def atomic_no_replace_backend() -> tuple[object, int]:
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
        raise ValueError("secure_apply_run_replace_not_supported")
    rename_function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    rename_function.restype = ctypes.c_int
    return rename_function, flags


def atomic_rename_no_replace(
    source: str,
    destination: str,
    *,
    source_dir_fd: int,
    destination_dir_fd: int,
) -> None:
    rename_function, flags = atomic_no_replace_backend()
    ctypes.set_errno(0)
    result = rename_function(
        source_dir_fd,
        os.fsencode(source),
        destination_dir_fd,
        os.fsencode(destination),
        flags,
    )
    if result != 0:
        error_number = ctypes.get_errno()
        unsupported_errors = {
            errno.EINVAL,
            errno.ENOSYS,
            getattr(errno, "ENOTSUP", errno.EINVAL),
            getattr(errno, "EOPNOTSUPP", errno.EINVAL),
        }
        if error_number in unsupported_errors:
            raise ValueError("secure_apply_run_replace_not_supported")
        raise OSError(error_number, os.strerror(error_number), destination)


def probe_atomic_no_replace(
    parent_fd: int,
    expected_device: int,
    *,
    root: Path,
    logical_parent: Path,
    root_mount_resolution: MountResolution,
) -> None:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    atomic_no_replace_backend()
    quarantine_name, quarantine_fd = create_deletion_quarantine(
        parent_fd,
        expected_device,
        root=root,
        logical_parent=logical_parent,
        root_mount_resolution=root_mount_resolution,
    )
    source_fd = -1
    destination_fd = -1
    probe_error: Exception | None = None
    try:
        file_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0)
        )
        source_fd = os.open("probe-source", file_flags, 0o600, dir_fd=quarantine_fd)
        destination_fd = os.open("probe-destination", file_flags, 0o600, dir_fd=quarantine_fd)
        quarantine_path = logical_parent / quarantine_name
        require_apply_same_mount(
            root_mount_resolution,
            source_fd,
            repository_mount_relative_path(root, quarantine_path / "probe-source"),
            mismatch_error="secure_apply_run_replace_not_supported",
        )
        require_apply_same_mount(
            root_mount_resolution,
            destination_fd,
            repository_mount_relative_path(root, quarantine_path / "probe-destination"),
            mismatch_error="secure_apply_run_replace_not_supported",
        )
        os.close(source_fd)
        source_fd = -1
        os.close(destination_fd)
        destination_fd = -1
        try:
            atomic_rename_no_replace(
                "probe-source",
                "probe-destination",
                source_dir_fd=quarantine_fd,
                destination_dir_fd=quarantine_fd,
            )
        except FileExistsError:
            pass
        else:
            raise ValueError("secure_apply_run_replace_not_supported")
        source_metadata = os.stat("probe-source", dir_fd=quarantine_fd, follow_symlinks=False)
        destination_metadata = os.stat("probe-destination", dir_fd=quarantine_fd, follow_symlinks=False)
        if not stat.S_ISREG(source_metadata.st_mode) or not stat.S_ISREG(destination_metadata.st_mode):
            raise ValueError("secure_apply_run_replace_not_supported")
    except Exception as exc:
        probe_error = exc
    finally:
        if source_fd >= 0:
            os.close(source_fd)
        if destination_fd >= 0:
            os.close(destination_fd)
        cleanup_failed = False
        for probe_name in ("probe-source", "probe-destination"):
            try:
                os.unlink(probe_name, dir_fd=quarantine_fd)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        os.close(quarantine_fd)
        try:
            os.rmdir(quarantine_name, dir_fd=parent_fd)
        except OSError:
            cleanup_failed = True
        if cleanup_failed:
            raise ValueError("replace_apply_run_probe_cleanup_failed")
    if probe_error is not None:
        raise probe_error


def restore_quarantined_entry(
    parent_fd: int,
    quarantine_fd: int,
    quarantine_name: str,
    original_name: str,
    *,
    kind: str,
    root: Path,
    logical_parent: Path,
    root_mount_resolution: MountResolution,
) -> None:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    entry_fd = -1
    try:
        if kind == "directory":
            entry_fd, _ = open_child_directory(quarantine_fd, "entry")
        elif kind == "regular":
            entry_fd, _ = open_regular_child(quarantine_fd, "entry")
        else:
            raise ValueError(f"replace_apply_run_restore_failed={quarantine_name}")
        require_apply_same_mount(
            root_mount_resolution,
            entry_fd,
            repository_mount_relative_path(root, logical_parent / quarantine_name / "entry"),
            mismatch_error=f"replace_apply_run_restore_failed={quarantine_name}",
        )
    finally:
        if entry_fd >= 0:
            os.close(entry_fd)
    try:
        before = os.stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"replace_apply_run_restore_conflict={quarantine_name}") from exc
    try:
        atomic_rename_no_replace(
            "entry",
            original_name,
            source_dir_fd=quarantine_fd,
            destination_dir_fd=parent_fd,
        )
    except FileExistsError as exc:
        raise ValueError(f"replace_apply_run_restore_conflict={quarantine_name}") from exc
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError(f"replace_apply_run_restore_failed={quarantine_name}") from exc
    try:
        after = os.stat(original_name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"replace_apply_run_restore_failed={quarantine_name}") from exc
    if not same_file_identity(before, after):
        raise ValueError(f"replace_apply_run_restore_conflict={quarantine_name}")
    try:
        os.rmdir(quarantine_name, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError(f"replace_apply_run_restore_cleanup_failed={quarantine_name}") from exc


def delete_inventory_entry(
    parent_fd: int,
    name: str,
    entry: dict[str, object],
    expected_device: int,
    logical_parent: Path,
    *,
    root: Path,
    root_mount_resolution: MountResolution,
) -> None:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    kind = entry.get("kind")
    if kind not in {"directory", "regular"}:
        raise ValueError("replace_apply_run_tree_changed")
    entry_path = logical_parent / name
    require_apply_same_mount(
        root_mount_resolution,
        parent_fd,
        repository_mount_relative_path(root, logical_parent),
        mismatch_error="replace_apply_run_tree_changed",
    )
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("replace_apply_run_tree_changed") from exc
    if not inventory_matches(metadata, entry, str(kind)) or path_is_mount_point(entry_path):
        raise ValueError("replace_apply_run_tree_changed")

    quarantine_name, quarantine_fd = create_deletion_quarantine(
        parent_fd,
        expected_device,
        root=root,
        logical_parent=logical_parent,
        root_mount_resolution=root_mount_resolution,
    )
    moved = False
    removed = False
    entry_fd = -1
    try:
        atomic_rename_no_replace(
            name,
            "entry",
            source_dir_fd=parent_fd,
            destination_dir_fd=quarantine_fd,
        )
        moved = True
        quarantined_path = logical_parent / quarantine_name / "entry"
        quarantined_metadata = os.stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
        if (
            not inventory_matches(quarantined_metadata, entry, str(kind))
            or path_is_mount_point(quarantined_path)
        ):
            raise ValueError("replace_apply_run_tree_changed")
        if kind == "directory":
            entry_fd, opened_metadata = open_child_directory(quarantine_fd, "entry")
            require_apply_same_mount(
                root_mount_resolution,
                entry_fd,
                repository_mount_relative_path(root, quarantined_path),
                mismatch_error="replace_apply_run_tree_changed",
            )
            if not inventory_matches(opened_metadata, entry, "directory"):
                raise ValueError("replace_apply_run_tree_changed")
            clear_directory_fd(
                entry_fd,
                expected_device,
                quarantined_path,
                entry,
                root=root,
                root_mount_resolution=root_mount_resolution,
            )
            current_fd_metadata = os.fstat(entry_fd)
            current_path_metadata = os.stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
            if (
                not inventory_matches(current_fd_metadata, entry, "directory")
                or not inventory_matches(current_path_metadata, entry, "directory")
                or path_is_mount_point(quarantined_path)
            ):
                raise ValueError("replace_apply_run_tree_changed")
            os.rmdir("entry", dir_fd=quarantine_fd)
        else:
            entry_fd, opened_metadata = open_regular_child(quarantine_fd, "entry")
            require_apply_same_mount(
                root_mount_resolution,
                entry_fd,
                repository_mount_relative_path(root, quarantined_path),
                mismatch_error="replace_apply_run_tree_changed",
            )
            current_path_metadata = os.stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
            if (
                not inventory_matches(opened_metadata, entry, "regular")
                or not inventory_matches(current_path_metadata, entry, "regular")
                or path_is_mount_point(quarantined_path)
            ):
                raise ValueError("replace_apply_run_tree_changed")
            os.unlink("entry", dir_fd=quarantine_fd)
        removed = True
    except (OSError, ValueError) as exc:
        if entry_fd >= 0:
            os.close(entry_fd)
            entry_fd = -1
        if moved and not removed:
            restore_quarantined_entry(
                parent_fd,
                quarantine_fd,
                quarantine_name,
                name,
                kind=str(kind),
                root=root,
                logical_parent=logical_parent,
                root_mount_resolution=root_mount_resolution,
            )
        else:
            try:
                os.rmdir(quarantine_name, dir_fd=parent_fd)
            except OSError:
                pass
        if isinstance(exc, ValueError) and (
            str(exc) == "secure_apply_run_replace_not_supported"
            or str(exc).startswith("replace_apply_run_restore_")
        ):
            raise
        raise ValueError("replace_apply_run_tree_changed") from exc
    finally:
        if entry_fd >= 0:
            os.close(entry_fd)
        os.close(quarantine_fd)
    try:
        os.rmdir(quarantine_name, dir_fd=parent_fd)
    except OSError as exc:
        raise ValueError("replace_apply_run_tree_changed") from exc


def clear_directory_fd(
    directory_fd: int,
    expected_device: int,
    logical_path: Path,
    inventory: dict[str, object],
    *,
    root: Path,
    root_mount_resolution: MountResolution,
) -> None:
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    require_apply_same_mount(
        root_mount_resolution,
        directory_fd,
        repository_mount_relative_path(root, logical_path),
        mismatch_error="replace_apply_run_tree_changed",
    )
    directory_metadata = os.fstat(directory_fd)
    if (
        directory_metadata.st_dev != expected_device
        or not inventory_matches(directory_metadata, inventory, "directory")
        or path_is_mount_point(logical_path)
    ):
        raise ValueError("replace_apply_run_tree_changed")
    entries = inventory.get("entries")
    if not isinstance(entries, dict) or set(os.listdir(directory_fd)) != set(entries):
        raise ValueError("replace_apply_run_tree_changed")
    ordered_names = sorted(entries)
    for index, name in enumerate(ordered_names):
        if set(os.listdir(directory_fd)) != set(ordered_names[index:]):
            raise ValueError("replace_apply_run_tree_changed")
        entry = entries[name]
        if not isinstance(entry, dict):
            raise ValueError("replace_apply_run_tree_changed")
        delete_inventory_entry(
            directory_fd,
            name,
            entry,
            expected_device,
            logical_path,
            root=root,
            root_mount_resolution=root_mount_resolution,
        )
    if os.listdir(directory_fd):
        raise ValueError("replace_apply_run_tree_changed")


def require_no_managed_recovery_quarantine(parent_fd: int) -> None:
    recovery_names = sorted(
        name for name in os.listdir(parent_fd) if name.startswith(APPLY_DELETE_QUARANTINE_PREFIX)
    )
    if recovery_names:
        raise ValueError(f"replace_apply_run_recovery_required={recovery_names[0]}")


def require_no_stale_apply_run_registration(root: Path, parent_fd: int, run_name: str) -> None:
    try:
        os.stat(APPLY_RUN_REGISTRY_DIR_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("apply_run_registration_recovery_required") from exc
    registry_fd = open_apply_run_registry_fd(root, parent_fd, create=False)
    try:
        require_no_managed_recovery_quarantine(registry_fd)
        registration_name = apply_run_registration_file_name(run_name)
        try:
            os.stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ValueError(f"apply_run_registration_recovery_required={run_name}") from exc
        raise ValueError(f"apply_run_registration_recovery_required={run_name}")
    finally:
        os.close(registry_fd)


def replace_existing_apply_run(
    root: Path,
    run_dir: Path,
    *,
    root_anchor_fd: int | None = None,
    root_mount_resolution: MountResolution | None = None,
) -> None:
    if root_mount_resolution is None:
        if root_anchor_fd is None:
            raise ValueError("secure_repository_mount_identity_unavailable")
        root_mount_resolution = resolve_apply_mount_identity(
            root_anchor_fd,
            RUN_REPLACE_QUARANTINE_DELETE,
        )
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    parent_fd = open_managed_apply_runs_root_fd(
        root,
        create=False,
        root_anchor_fd=root_anchor_fd,
        root_mount_resolution=root_mount_resolution,
        operation=RUN_REPLACE_QUARANTINE_DELETE,
    )
    run_fd = -1
    registry_fd = -1
    try:
        parent_metadata = os.fstat(parent_fd)
        require_no_managed_recovery_quarantine(parent_fd)
        run_fd, run_metadata = open_child_directory(parent_fd, run_dir.name)
        require_apply_same_mount(
            root_mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="replace_apply_run_tree_contains_indirect_target",
        )
        require_no_managed_recovery_quarantine(run_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("replace_apply_run_tree_contains_indirect_target")
        try:
            marker = load_regular_json_at(run_fd, APPLY_RUN_MARKER_NAME)
            run = load_regular_json_at(run_fd, "Apply-Run.json")
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("replace_requires_existing_apply_run") from exc
        registry_fd = open_apply_run_registry_fd(
            root,
            parent_fd,
            create=False,
            root_mount_resolution=root_mount_resolution,
            operation=RUN_REPLACE_QUARANTINE_DELETE,
        )
        require_no_managed_recovery_quarantine(registry_fd)
        registration_name = apply_run_registration_file_name(run_dir.name)
        try:
            registration_metadata = os.stat(
                registration_name,
                dir_fd=registry_fd,
                follow_symlinks=False,
            )
            registration = load_regular_json_at(registry_fd, registration_name)
            current_registration_metadata = os.stat(
                registration_name,
                dir_fd=registry_fd,
                follow_symlinks=False,
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise ValueError("replace_requires_registered_apply_run") from exc
        if (
            not stat.S_ISREG(registration_metadata.st_mode)
            or registration_metadata.st_nlink != 1
            or not metadata_is_owner_controlled(registration_metadata)
            or not same_file_identity(registration_metadata, current_registration_metadata)
        ):
            raise ValueError("replace_requires_registered_apply_run")
        if not recognized_apply_run_manifest(
            root,
            run_dir,
            marker,
            run,
            registration,
            run_metadata,
            os.fstat(root_anchor_fd) if root_anchor_fd is not None else os.stat(root, follow_symlinks=False),
        ):
            raise ValueError("replace_requires_existing_apply_run")
        probe_atomic_no_replace(
            parent_fd,
            parent_metadata.st_dev,
            root=root,
            logical_parent=managed_apply_runs_root(root),
            root_mount_resolution=root_mount_resolution,
        )
        inventory = build_deletion_inventory(
            run_fd,
            parent_metadata.st_dev,
            run_dir,
            root=root,
            root_mount_resolution=root_mount_resolution,
        )
        os.close(run_fd)
        run_fd = -1
        delete_inventory_entry(
            registry_fd,
            registration_name,
            inventory_identity(registration_metadata, "regular"),
            parent_metadata.st_dev,
            managed_apply_runs_root(root) / APPLY_RUN_REGISTRY_DIR_NAME,
            root=root,
            root_mount_resolution=root_mount_resolution,
        )
        delete_inventory_entry(
            parent_fd,
            run_dir.name,
            inventory,
            parent_metadata.st_dev,
            run_dir.parent,
            root=root,
            root_mount_resolution=root_mount_resolution,
        )
    finally:
        if run_fd >= 0:
            os.close(run_fd)
        if registry_fd >= 0:
            os.close(registry_fd)
        os.close(parent_fd)


def create_managed_apply_run_directory(
    root: Path,
    run_dir: Path,
    *,
    root_anchor_fd: int | None = None,
    root_mount_resolution: MountResolution | None = None,
) -> tuple[int, int, os.stat_result]:
    parent_fd = open_managed_apply_runs_root_fd(
        root,
        create=True,
        root_anchor_fd=root_anchor_fd,
        root_mount_resolution=root_mount_resolution,
    )
    run_fd = -1
    created = False
    try:
        require_no_managed_recovery_quarantine(parent_fd)
        require_no_stale_apply_run_registration(root, parent_fd, run_dir.name)
        os.mkdir(run_dir.name, mode=0o700, dir_fd=parent_fd)
        created = True
        run_fd, run_metadata = open_child_directory(parent_fd, run_dir.name)
        mount_resolution = root_mount_resolution or resolve_apply_mount_identity(
            parent_fd,
            APPLY_RUN_MUTATION,
        )
        require_apply_same_mount(
            mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        parent_metadata = os.fstat(parent_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_private_directory(run_metadata)
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    except FileExistsError as exc:
        os.close(parent_fd)
        raise ValueError(f"apply_run_already_exists={run_dir.relative_to(root).as_posix()}") from exc
    except Exception:
        if run_fd >= 0:
            os.close(run_fd)
        if created:
            try:
                os.rmdir(run_dir.name, dir_fd=parent_fd)
            except OSError:
                pass
        os.close(parent_fd)
        raise
    return parent_fd, run_fd, run_metadata


def baseline_path_is_excluded(path: str) -> bool:
    normalized = path.replace("\\", "/")
    while normalized.startswith("./"):
        normalized = normalized[2:]
    parts = Path(normalized).parts
    if "__pycache__" in parts or normalized.endswith(".pyc"):
        return True
    if normalized in WORKSPACE_BASELINE_EXCLUDED_PATHS:
        return True
    return any(normalized == prefix.rstrip("/") or normalized.startswith(prefix) for prefix in WORKSPACE_BASELINE_EXCLUDED_PREFIXES)


def hash_inventory(entries: list[str]) -> str:
    return sha256_bytes(("\n".join(sorted(entries)) + "\n").encode("utf-8"))


def git_untracked_inventory(entries: object) -> tuple[str, int]:
    if not isinstance(entries, list):
        raise ValueError("git_evidence_untracked_entries_missing")
    selected: list[dict[str, object]] = []
    for item in entries:
        if (
            not isinstance(item, dict)
            or not isinstance(item.get("path"), str)
            or item.get("state") != "present"
        ):
            raise ValueError("git_evidence_untracked_entries_invalid")
        if not baseline_path_is_excluded(str(item["path"])):
            selected.append(item)
    selected.sort(key=lambda item: str(item["path"]))
    return canonical_git_evidence_digest(selected), len(selected)


def workspace_file_inventory_entries(root: Path) -> list[str]:
    try:
        snapshot = snapshot_repository_inventory(
            root,
            exclude=baseline_path_is_excluded,
            max_bytes=MAX_WORKSPACE_INVENTORY_FILE_BYTES,
            max_total_bytes=MAX_WORKSPACE_INVENTORY_TOTAL_BYTES,
            max_paths=MAX_WORKSPACE_INVENTORY_PATHS,
            timeout_seconds=WORKSPACE_INVENTORY_TIMEOUT_SECONDS,
        )
    except ValueError as exc:
        if str(exc) == "repository_inventory_walk_failed":
            raise ValueError("workspace_inventory_walk_failed=descriptor_capture") from exc
        raise
    entries: list[str] = []
    for item in snapshot:
        path = item.get("path")
        fingerprint = item.get("fingerprint_sha256")
        if (
            not isinstance(path, str)
            or not isinstance(fingerprint, str)
            or re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
        ):
            raise ValueError("workspace_inventory_entry_invalid")
        entries.append(f"{path}\t{fingerprint}")
    return sorted(entries)


def non_git_file_inventory_entries(root: Path) -> list[str]:
    return workspace_file_inventory_entries(root)


def non_git_file_inventory(root: Path) -> tuple[str, int]:
    entries = non_git_file_inventory_entries(root)
    return hash_inventory(entries), len(entries)


def git_workspace_file_inventory_entries(root: Path) -> list[str]:
    """Hash the whole worktree except explicit runtime/cache exclusions.

    Git status and diff output are not a trust boundary: index flags such as
    assume-unchanged and skip-worktree can hide tracked mutations, while ignore
    rules can hide new contract-external files. Direct walking keeps both kinds
    of content bound even when Git suppresses them.
    """

    return workspace_file_inventory_entries(root)


def workspace_file_manifest_map(entries: object) -> dict[str, str] | None:
    if not isinstance(entries, list) or any(not isinstance(item, str) for item in entries):
        return None
    result: dict[str, str] = {}
    for entry in entries:
        if entry.count("\t") != 1:
            return None
        path, fingerprint = entry.split("\t", 1)
        if (
            not normalize_reported_repo_path(path)
            or normalize_reported_repo_path(path) != path
            or fingerprint not in {"symlink", "missing"}
            and re.fullmatch(r"[a-f0-9]{64}", fingerprint) is None
            or path in result
        ):
            return None
        result[path] = entry
    return result


def workspace_baseline_capture(root: Path) -> tuple[dict[str, object], list[str]]:
    git_evidence = capture_git_workspace_evidence(
        root,
        exclude_untracked=baseline_path_is_excluded,
        exclude_tracked=baseline_path_is_excluded,
    )
    is_git = git_evidence.get("is_git") is True
    if is_git:
        untracked_paths = [
            str(path)
            for path in git_evidence.get("untracked_paths", [])
            if isinstance(path, str) and not baseline_path_is_excluded(path)
        ]
        staged_changes = [
            item
            for item in git_evidence.get("staged_changes", [])
            if isinstance(item, dict)
            and not baseline_path_is_excluded(str(item.get("path", "")))
        ]
        unstaged_changes = [
            item
            for item in git_evidence.get("unstaged_changes", [])
            if isinstance(item, dict)
            and not baseline_path_is_excluded(str(item.get("path", "")))
        ]
        status_entries = [{"domain": "staged", **item} for item in staged_changes]
        status_entries.extend({"domain": "unstaged", **item} for item in unstaged_changes)
        status_entries.extend(
            {"domain": "untracked", "path": path, "state": "untracked"}
            for path in untracked_paths
        )
        status_hash = canonical_git_evidence_digest(status_entries)
        staged_hash = canonical_git_evidence_digest(staged_changes)
        unstaged_hash = canonical_git_evidence_digest(unstaged_changes)
        untracked_hash, untracked_count = git_untracked_inventory(
            git_evidence.get("untracked_entries")
        )
        workspace_entries = git_workspace_file_inventory_entries(root)
        workspace_inventory_hash, workspace_inventory_count = hash_inventory(workspace_entries), len(workspace_entries)
    else:
        status_hash = sha256_bytes(b"")
        staged_hash = sha256_bytes(b"")
        unstaged_hash = sha256_bytes(b"")
        workspace_entries = non_git_file_inventory_entries(root)
        untracked_hash, untracked_count = hash_inventory(workspace_entries), len(workspace_entries)
        workspace_inventory_hash, workspace_inventory_count = untracked_hash, untracked_count
    baseline = {
        "vcs": "git" if is_git else "non_git",
        "branch": str(git_evidence.get("branch") or "unknown"),
        "base_commit": str(git_evidence.get("head") or "unknown"),
        "git_status_porcelain_sha256": status_hash,
        "staged_diff_sha256": staged_hash,
        "unstaged_diff_sha256": unstaged_hash,
        "untracked_inventory_sha256": untracked_hash,
        "untracked_count": untracked_count,
        "workspace_file_inventory_sha256": workspace_inventory_hash,
        "workspace_file_count": workspace_inventory_count,
    }
    return baseline, workspace_entries


def workspace_baseline(root: Path) -> dict[str, object]:
    baseline, _entries = workspace_baseline_capture(root)
    return baseline


def normalize_reported_repo_path(value: object) -> str:
    if not isinstance(value, str):
        return ""
    normalized = value.strip().replace("\\", "/")
    if (
        not normalized
        or Path(normalized).is_absolute()
        or ".." in Path(normalized).parts
        or baseline_path_is_excluded(normalized)
    ):
        return ""
    return normalized


def implementation_contract_paths(task: dict[str, object]) -> set[str]:
    contract = task.get("implementation_contract")
    if not isinstance(contract, dict):
        return set()
    paths = contract.get("implementation_paths")
    if not isinstance(paths, list):
        return set()
    allowed: set[str] = set()
    for item in paths:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        normalized_path = normalize_reported_repo_path(path)
        if normalized_path:
            allowed.add(normalized_path)
    return allowed


def read_repository_file_no_follow(
    root: Path,
    relative_path: str,
    *,
    max_bytes: int = MAX_REPOSITORY_BASELINE_CONTENT_BYTES,
) -> bytes | None:
    """Read one explicit repository file without following path components."""

    normalized = normalize_repo_relative_path(relative_path)
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("repository_read_max_bytes_invalid")
    root = root.resolve(strict=True)
    root_fd = os.open(root, secure_directory_open_flags())
    current_fd = root_fd
    owned_fds: list[int] = []
    file_fd = -1
    try:
        root_metadata = os.fstat(root_fd)
        if not opened_directory_matches_path(root, root_metadata, reject_mount=False):
            raise ValueError("repository_root_identity_changed")
        parts = normalized.split("/")
        for part in parts[:-1]:
            try:
                child_fd, child_metadata = open_child_directory(current_fd, part)
            except FileNotFoundError:
                return None
            if child_metadata.st_dev != root_metadata.st_dev:
                os.close(child_fd)
                raise ValueError("repository_path_cross_device_rejected")
            owned_fds.append(child_fd)
            current_fd = child_fd
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0)
        try:
            file_fd = os.open(parts[-1], flags, dir_fd=current_fd)
        except FileNotFoundError:
            return None
        before = os.fstat(file_fd)
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else before.st_uid
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_uid != expected_uid
            or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError("repository_file_not_owner_controlled_regular")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        content = b"".join(chunks)
        if len(content) > max_bytes:
            raise ValueError("repository_baseline_content_too_large")
        after = os.fstat(file_fd)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("repository_file_changed_during_read")
        return content
    finally:
        if file_fd >= 0:
            os.close(file_fd)
        for directory_fd in reversed(owned_fds):
            os.close(directory_fd)
        os.close(root_fd)


def capture_repository_baselines(root: Path, tasks: list[dict[str, object]]) -> list[dict[str, object]]:
    baselines: list[dict[str, object]] = []
    for task in tasks:
        task_id = str(task.get("task_id", ""))
        paths = sorted(implementation_contract_paths(task))
        snapshot = snapshot_allowed_paths(root, paths)
        contents: list[dict[str, object]] = []
        total_bytes = 0
        for entry in snapshot:
            if entry.get("state") != "present":
                continue
            path = str(entry["path"])
            content = read_repository_file_no_follow(root, path)
            if content is None or sha256_bytes(content) != entry.get("sha256") or len(content) != entry.get("size"):
                raise ValueError(f"repository_baseline_capture_changed={task_id}:{path}")
            assert_safe_embedded_content_bytes(content)
            total_bytes += len(content)
            if total_bytes > MAX_REPOSITORY_BASELINE_CONTENT_BYTES:
                raise ValueError(f"repository_baseline_content_too_large={task_id}")
            contents.append(
                {
                    "path": path,
                    "sha256": entry["sha256"],
                    "size": entry["size"],
                    "content_base64": base64.b64encode(content).decode("ascii"),
                }
            )
        baselines.append(
            {
                "task_id": task_id,
                "implementation_contract_digest": task.get("implementation_contract_digest"),
                "allowed_paths": paths,
                "snapshot": snapshot,
                "baseline_digest": repository_baseline_digest(snapshot),
                "contents": contents,
            }
        )
    return baselines


def repository_baseline_for_task(run: dict[str, object], task_id: str) -> dict[str, object] | None:
    baselines = run.get("repository_baselines")
    if not isinstance(baselines, list):
        return None
    matches = [item for item in baselines if isinstance(item, dict) and item.get("task_id") == task_id]
    return matches[0] if len(matches) == 1 else None


def implementation_contract_paths_by_state(task: dict[str, object], state: str) -> set[str]:
    contract = task.get("implementation_contract")
    if not isinstance(contract, dict):
        return set()
    paths = contract.get("implementation_paths")
    if not isinstance(paths, list):
        return set()
    allowed: set[str] = set()
    for item in paths:
        if not isinstance(item, dict) or item.get("state") != state:
            continue
        normalized_path = normalize_reported_repo_path(item.get("path"))
        if normalized_path:
            allowed.add(normalized_path)
    return allowed


def read_external_report_json(path: Path) -> object:
    parent_fd = os.open(path.parent, secure_directory_open_flags())
    try:
        return parse_safe_persistent_json(secure_read_regular_text_at(parent_fd, path.name))
    finally:
        os.close(parent_fd)


def implementation_report_files(run_dir: Path, task: dict[str, object]) -> set[str]:
    task_id = str(task.get("task_id", ""))
    if not safe_task_id(task_id):
        return set()
    report_path = run_dir / task_id / "Implementer-Report.json"
    if not report_path.is_file():
        return set()
    try:
        report = read_external_report_json(report_path)
        assert_safe_persistent_payload(report)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()
    if not isinstance(report, dict) or report.get("status") not in {"DONE", "DONE_WITH_CONCERNS"}:
        return set()
    files = report.get("files_changed")
    if not isinstance(files, list):
        return set()
    normalized: set[str] = set()
    for item in files:
        normalized_path = normalize_reported_repo_path(item)
        if normalized_path:
            normalized.add(normalized_path)
    return normalized


def fix_report_files(run_dir: Path, task: dict[str, object]) -> set[str]:
    task_id = str(task.get("task_id", ""))
    if not safe_task_id(task_id):
        return set()
    report_path = run_dir / task_id / "Fix-Report.json"
    if not report_path.is_file():
        return set()
    try:
        report = read_external_report_json(report_path)
    except (OSError, ValueError, json.JSONDecodeError):
        return set()
    if not isinstance(report, dict):
        return set()
    try:
        assert_safe_persistent_payload(report)
    except ValueError:
        return set()
    fixes = report.get("fixes")
    if not isinstance(fixes, list):
        return set()
    normalized: set[str] = set()
    for fix in fixes:
        if not isinstance(fix, dict):
            continue
        files = fix.get("files_changed")
        if not isinstance(files, list):
            continue
        for item in files:
            normalized_path = normalize_reported_repo_path(item)
            if normalized_path:
                normalized.add(normalized_path)
    return normalized


def allowed_implementation_file_drift_paths(run_dir: Path, tasks: list[object]) -> set[str]:
    allowed: set[str] = set()
    drift_states = {"IMPLEMENTED", "TASK_REVIEW", "SECURITY_REVIEW", "FIXING", "RE_REVIEW", "VERIFIED"}
    for task in tasks:
        if not isinstance(task, dict) or task.get("state") not in drift_states:
            continue
        contract_paths = implementation_contract_paths(task)
        reported_paths = implementation_report_files(run_dir, task) | fix_report_files(run_dir, task)
        allowed.update(contract_paths & reported_paths)
    return allowed


def allowed_implementation_drift_paths(run_dir: Path, tasks: list[object]) -> set[str]:
    files = allowed_implementation_file_drift_paths(run_dir, tasks)
    allowed = set(files)
    for path in files:
        allowed.update(parent.as_posix() for parent in Path(path).parents if parent.as_posix() != ".")
    return allowed


def allowed_proposed_implementation_drift_paths(run_dir: Path, tasks: list[object]) -> set[str]:
    allowed: set[str] = set()
    drift_states = {"IMPLEMENTED", "TASK_REVIEW", "SECURITY_REVIEW", "FIXING", "RE_REVIEW", "VERIFIED"}
    for task in tasks:
        if not isinstance(task, dict) or task.get("state") not in drift_states:
            continue
        proposed_paths = implementation_contract_paths_by_state(task, "proposed")
        reported_paths = implementation_report_files(run_dir, task) | fix_report_files(run_dir, task)
        selected = proposed_paths & reported_paths
        allowed.update(selected)
        for path in selected:
            allowed.update(parent.as_posix() for parent in Path(path).parents if parent.as_posix() != ".")
    return allowed


def implementation_workspace_drift(
    root: Path,
    run_dir: Path,
    tasks: list[object],
    run: dict[str, object] | None = None,
) -> dict[str, object]:
    stored_entries = run.get("workspace_file_manifest") if isinstance(run, dict) else None
    stored_map = workspace_file_manifest_map(stored_entries)
    if stored_map is None:
        return {"allowed": False, "changed_paths": set(), "allowed_paths": set()}
    git_evidence = capture_git_workspace_evidence(
        root,
        exclude_untracked=baseline_path_is_excluded,
        exclude_tracked=baseline_path_is_excluded,
    )
    is_git = git_evidence.get("is_git") is True
    current_entries = (
        git_workspace_file_inventory_entries(root)
        if is_git
        else non_git_file_inventory_entries(root)
    )
    current_map = workspace_file_manifest_map(current_entries)
    if current_map is None:
        return {"allowed": False, "changed_paths": set(), "allowed_paths": set()}
    changed_paths = {
        path
        for path in set(stored_map) | set(current_map)
        if stored_map.get(path) != current_map.get(path)
    }
    allowed_file_paths = allowed_implementation_file_drift_paths(run_dir, tasks)
    allowed_paths = allowed_implementation_drift_paths(run_dir, tasks)
    parent_paths = allowed_paths - allowed_file_paths
    allowed_parent_additions = {
        path
        for path in changed_paths & parent_paths
        if path not in stored_map and path in current_map
    }
    disallowed_parent_changes = (changed_paths & parent_paths) - allowed_parent_additions
    if not is_git:
        return {
            "allowed": bool(changed_paths) and changed_paths <= allowed_paths and not disallowed_parent_changes,
            "changed_paths": changed_paths,
            "allowed_paths": allowed_paths,
        }

    baseline = run.get("workspace_baseline") if isinstance(run, dict) else None
    stored_staged_digest = baseline.get("staged_diff_sha256") if isinstance(baseline, dict) else None
    current_staged_changes = [
        item
        for item in git_evidence.get("staged_changes", [])
        if isinstance(item, dict)
        and not baseline_path_is_excluded(str(item.get("path", "")))
    ]
    current_staged_digest = canonical_git_evidence_digest(current_staged_changes)
    staged_unchanged = is_sha256(stored_staged_digest) and stored_staged_digest == current_staged_digest
    tracked_paths = {
        str(path)
        for path in git_evidence.get("tracked_paths", [])
        if isinstance(path, str) and not baseline_path_is_excluded(path)
    }
    untracked_delta_paths = changed_paths - tracked_paths
    allowed_untracked_paths = allowed_proposed_implementation_drift_paths(run_dir, tasks)
    allowed = (
        bool(changed_paths)
        and staged_unchanged
        and changed_paths <= allowed_paths
        and not disallowed_parent_changes
        and untracked_delta_paths <= allowed_untracked_paths
    )
    return {
        "allowed": allowed,
        "changed_paths": changed_paths,
        "allowed_paths": allowed_paths,
        "allowed_untracked_paths": allowed_untracked_paths,
        "staged_unchanged": staged_unchanged,
        "untracked_paths": untracked_delta_paths,
    }


def snapshot_matches_except(stored: list[dict[str, str]], current: list[dict[str, str]], ignored_paths: set[str]) -> bool:
    def normalize(items: list[dict[str, str]]) -> list[dict[str, str]]:
        normalized: list[dict[str, str]] = []
        for item in items:
            path = item.get("path", "")
            if path in ignored_paths:
                replacement = dict(item)
                replacement["sha256"] = "<implementation-drift>"
                normalized.append(replacement)
            else:
                normalized.append(item)
        return sorted(normalized, key=lambda value: (value.get("path", ""), value.get("sha256", "")))

    return normalize(stored) == normalize(current)


def patch_changed_paths(patch_text: str) -> set[str]:
    paths: set[str] = set()
    for line in patch_text.splitlines():
        if line.startswith("diff --git "):
            parts = line.split()
            if len(parts) >= 4:
                candidate = parts[3]
                if candidate.startswith("b/"):
                    candidate = candidate[2:]
                normalized = normalize_reported_repo_path(candidate)
                if normalized:
                    paths.add(normalized)
        elif line.startswith("+++ "):
            candidate = line[4:].strip()
            if candidate == "/dev/null":
                continue
            if candidate.startswith("b/"):
                candidate = candidate[2:]
            normalized = normalize_reported_repo_path(candidate)
            if normalized:
                paths.add(normalized)
    return paths


def planned_validation_key(command: dict[str, object]) -> tuple[str, str]:
    command_id = str(command.get("id", ""))
    core = {
        key: command.get(key)
        for key in (
            "id",
            "argv",
            "cwd",
            "expected_exit_code",
            "timeout_seconds",
            "network",
            "probe_tier",
        )
    }
    return command_id, canonical_json_digest(core)


def is_sha256(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def validation_evidence_has_output_hash(item: dict[str, object]) -> bool:
    hash_fields = (
        "output_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "combined_output_sha256",
        "artifact_sha256",
    )
    present = [field for field in hash_fields if field in item]
    if not present:
        return False
    return all(is_sha256(item.get(field)) for field in present)


def git_default_branch(root: Path) -> str:
    # Remote refs are intentionally outside the no-exec Git evidence allowlist.
    # The base branch is therefore advisory and fails safe when host attestation
    # does not provide a trusted value.
    return "unknown"


def workspace_dirty_state(baseline: dict[str, object]) -> str:
    if baseline.get("vcs") != "git":
        return "non_git"
    empty_hash = sha256_bytes(b"")
    dirty = (
        baseline.get("git_status_porcelain_sha256") != empty_hash
        or baseline.get("staged_diff_sha256") != empty_hash
        or baseline.get("unstaged_diff_sha256") != empty_hash
        or int(baseline.get("untracked_count", 0) or 0) > 0
    )
    return "dirty" if dirty else "clean"


def git_worktree_requires_approval(baseline: dict[str, object]) -> bool:
    if baseline.get("vcs") != "git":
        return False
    branch = str(baseline.get("branch") or "unknown")
    return branch in {"main", "master", "unknown"} or workspace_dirty_state(baseline) == "dirty"


def collect_snapshot(
    root: Path,
    baseline: dict[str, object] | None = None,
) -> list[dict[str, str]]:
    planner = root / "Planner-docs"
    files = sorted(planner.glob("**/*.md")) if planner.is_dir() else []
    snapshot = [
        {"path": path.relative_to(root).as_posix(), "sha256": sha256_bytes(path.read_bytes())}
        for path in files
        if path.is_file() and path.name != "Planing-Ledger.md"
    ]
    baseline = baseline or workspace_baseline(root)
    branch = str(baseline["branch"])
    commit = str(baseline["base_commit"])
    snapshot.append({"path": "git:branch", "sha256": sha256_bytes(branch.encode("utf-8")), "value": branch})
    snapshot.append({"path": "git:commit", "sha256": sha256_bytes(commit.encode("utf-8")), "value": commit})
    snapshot.append({"path": "git:status", "sha256": str(baseline["git_status_porcelain_sha256"])})
    snapshot.append({"path": "git:staged_diff", "sha256": str(baseline["staged_diff_sha256"])})
    snapshot.append({"path": "git:unstaged_diff", "sha256": str(baseline["unstaged_diff_sha256"])})
    snapshot.append({"path": "git:untracked_inventory", "sha256": str(baseline["untracked_inventory_sha256"])})
    if baseline["vcs"] == "non_git":
        snapshot.append({"path": "workspace:file_inventory", "sha256": str(baseline["workspace_file_inventory_sha256"])})
    return snapshot


def snapshot_digest(snapshot: list[dict[str, str]]) -> str:
    return sha256_bytes(json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def invocation_suffix(value: str | None = None) -> str:
    raw = value or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{os.getpid()}"
    if has_secret_like(raw):
        raise ValueError("secret_like_run_id_suffix")
    suffix = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-._")
    if not suffix or has_secret_like(suffix):
        raise ValueError("invalid_run_id_suffix")
    return suffix[:64]


def normalize_spec_baseline(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return {key: value.get(key, "") for key in WORKSPACE_BASELINE_KEYS}


def apply_spec_digest(
    mode: str,
    snapshot: list[dict[str, str]],
    workspace_baseline_value: object,
    ready_queue: list[dict[str, object]],
    *,
    apply_run_schema_version: int = APPLY_RUN_SCHEMA_VERSION,
) -> str:
    payload = {
        "mode": mode,
        "source_snapshot": snapshot,
        "workspace_baseline": normalize_spec_baseline(workspace_baseline_value),
        "ready_queue": ready_queue,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "handoff_contract_version": HANDOFF_CONTRACT_VERSION,
        "apply_run_schema_version": apply_run_schema_version,
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def apply_run_id(
    mode: str,
    snapshot: list[dict[str, str]],
    workspace_baseline_value: object,
    ready_queue: list[dict[str, object]] | None = None,
    run_id_suffix: str | None = None,
) -> str:
    digest = apply_spec_digest(
        mode,
        snapshot,
        workspace_baseline_value,
        ready_queue or [],
        apply_run_schema_version=APPLY_RUN_SCHEMA_VERSION,
    )
    return f"apply-{mode}-{digest[:12]}-{invocation_suffix(run_id_suffix)}"


def infer_root(run_dir: Path) -> Path | None:
    parts = run_dir.resolve().parts
    if len(parts) >= 3 and parts[-3:-1] == (".codexqb", "apply-runs"):
        return run_dir.resolve().parents[2]
    return None


@dataclass
class ApplyMutationHandle:
    root: Path
    run_dir: Path
    root_fd: int
    parent_fd: int
    run_fd: int
    run_metadata: os.stat_result
    run: dict[str, object]
    root_mount_resolution: MountResolution
    mount_operation: str

    def revalidate(self) -> bool:
        try:
            parent_metadata = os.fstat(self.parent_fd)
            require_mount_assurance(self.root_mount_resolution, self.mount_operation)
            require_same_mount(self.root_mount_resolution, self.root_fd, ".")
            require_same_mount(
                self.root_mount_resolution,
                self.parent_fd,
                APPLY_RUNS_RELATIVE_DIR.as_posix(),
            )
            require_same_mount(
                self.root_mount_resolution,
                self.run_fd,
                repository_mount_relative_path(self.root, self.run_dir),
            )
        except (OSError, TypeError, ValueError):
            return False
        return (
            self.run_metadata.st_dev == parent_metadata.st_dev
            and secure_directory_entry_matches(self.parent_fd, self.run_dir.name, self.run_metadata)
            and opened_directory_matches_path(self.run_dir, self.run_metadata, reject_mount=True)
        )


def lexical_managed_apply_run(root_candidate: Path) -> tuple[Path, Path]:
    lexical_run_dir = lexical_absolute(root_candidate)
    parts = lexical_run_dir.parts
    if len(parts) < 3 or parts[-3:-1] != (".codexqb", "apply-runs"):
        raise ValueError("invalid_apply_run_output_dir=managed_run_required")
    lexical_root = lexical_run_dir.parents[2]
    root = lexical_root.resolve(strict=True)
    run_dir = resolve_managed_apply_run_dir(
        root,
        lexical_run_dir,
        lexical_root=lexical_root,
    )
    return root, run_dir


@contextmanager
def open_verified_apply_run_for_mutation(
    run_dir: Path,
    *,
    require_provenance: bool = True,
) -> Iterator[ApplyMutationHandle]:
    root, canonical_run_dir = lexical_managed_apply_run(run_dir)
    root_fd = os.open(root, secure_directory_open_flags())
    parent_fd = -1
    opened_run_fd = -1
    try:
        root_mount_resolution = resolve_apply_mount_identity(root_fd, APPLY_RUN_MUTATION)
        root_metadata = os.fstat(root_fd)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            root_anchor_fd=root_fd,
            root_mount_resolution=root_mount_resolution,
        )
        parent_metadata = os.fstat(parent_fd)
        require_no_managed_recovery_quarantine(parent_fd)
        opened_run_fd, run_metadata = open_child_directory(parent_fd, canonical_run_dir.name)
        require_apply_same_mount(
            root_mount_resolution,
            opened_run_fd,
            repository_mount_relative_path(root, canonical_run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        require_no_managed_recovery_quarantine(opened_run_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_private_directory(run_metadata)
            or not opened_directory_matches_path(canonical_run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
        with locked_directory(opened_run_fd):
            run = load_regular_json_at(opened_run_fd, "Apply-Run.json")
            if require_provenance and not current_apply_run_provenance_is_valid(root, canonical_run_dir, run):
                raise ValueError("apply_run_provenance_unverified")
            handle = ApplyMutationHandle(
                root=root,
                run_dir=canonical_run_dir,
                root_fd=root_fd,
                parent_fd=parent_fd,
                run_fd=opened_run_fd,
                run_metadata=run_metadata,
                run=run,
                root_mount_resolution=root_mount_resolution,
                mount_operation=APPLY_RUN_MUTATION,
            )
            if not handle.revalidate() or load_regular_json_at(opened_run_fd, "Apply-Run.json") != run:
                raise ValueError("apply_run_mutation_identity_changed")
            if not same_file_identity(root_metadata, os.fstat(root_fd)):
                raise ValueError("invalid_apply_run_output_dir=root_identity_changed")
            yield handle
    finally:
        if opened_run_fd >= 0:
            os.close(opened_run_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


@contextmanager
def open_verified_apply_run_for_read(run_dir: Path) -> Iterator[ApplyMutationHandle]:
    """Open a registered run descriptor-relative without taking its writer lock."""

    root, canonical_run_dir = lexical_managed_apply_run(run_dir)
    root_fd = os.open(root, secure_directory_open_flags())
    parent_fd = -1
    opened_run_fd = -1
    try:
        root_mount_resolution = resolve_apply_mount_identity(root_fd, READ_ONLY_EVIDENCE)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            root_anchor_fd=root_fd,
            root_mount_resolution=root_mount_resolution,
            operation=READ_ONLY_EVIDENCE,
        )
        parent_metadata = os.fstat(parent_fd)
        opened_run_fd, run_metadata = open_child_directory(parent_fd, canonical_run_dir.name)
        require_apply_same_mount(
            root_mount_resolution,
            opened_run_fd,
            repository_mount_relative_path(root, canonical_run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_private_directory(run_metadata)
            or not opened_directory_matches_path(canonical_run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
        run = load_regular_json_at(opened_run_fd, "Apply-Run.json")
        if not current_apply_run_provenance_is_valid(root, canonical_run_dir, run):
            raise ValueError("apply_run_provenance_unverified")
        handle = ApplyMutationHandle(
            root=root,
            run_dir=canonical_run_dir,
            root_fd=root_fd,
            parent_fd=parent_fd,
            run_fd=opened_run_fd,
            run_metadata=run_metadata,
            run=run,
            root_mount_resolution=root_mount_resolution,
            mount_operation=READ_ONLY_EVIDENCE,
        )
        if not handle.revalidate():
            raise ValueError("apply_run_read_identity_changed")
        yield handle
    finally:
        if opened_run_fd >= 0:
            os.close(opened_run_fd)
        if parent_fd >= 0:
            os.close(parent_fd)
        os.close(root_fd)


@contextmanager
def open_apply_task_for_mutation(
    handle: ApplyMutationHandle,
    task_id: str,
) -> Iterator[tuple[int, object]]:
    if not safe_task_id(task_id):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    if not handle.revalidate():
        raise ValueError("apply_run_mutation_identity_changed")
    task_fd, task_metadata = open_child_directory(handle.run_fd, task_id)
    try:
        require_apply_same_mount(
            handle.root_mount_resolution,
            task_fd,
            repository_mount_relative_path(handle.root, handle.run_dir / task_id),
            mismatch_error="invalid_apply_run_task_directory",
        )
        if task_metadata.st_dev != handle.run_metadata.st_dev or not metadata_is_private_directory(task_metadata):
            raise ValueError("invalid_apply_run_task_directory")

        def revalidate() -> bool:
            try:
                require_same_mount(
                    handle.root_mount_resolution,
                    task_fd,
                    repository_mount_relative_path(handle.root, handle.run_dir / task_id),
                )
            except (OSError, TypeError, ValueError):
                return False
            return handle.revalidate() and secure_directory_entry_matches(
                handle.run_fd,
                task_id,
                task_metadata,
            )

        if not revalidate():
            raise ValueError("apply_run_task_identity_changed")
        yield task_fd, revalidate
    finally:
        os.close(task_fd)


def append_event_at(handle: ApplyMutationHandle, event: dict[str, object]) -> dict[str, object]:
    existing = read_event_log_at(handle.run_fd)
    parsed_events, errors = parse_chained_event_log(existing)
    if errors:
        raise ValueError(errors[0])
    if parsed_events[0].get("event_type") != "apply_run_initialized":
        raise ValueError("first_event_must_initialize_apply_run")
    if parsed_events[0].get("apply_run_id") != handle.run.get("apply_run_id"):
        raise ValueError("initial_event_apply_run_id_mismatch")
    if "apply_run_id" in event:
        if not safe_apply_run_id(event.get("apply_run_id")):
            raise ValueError("event_apply_run_id_invalid")
        if event.get("apply_run_id") != handle.run.get("apply_run_id"):
            raise ValueError("event_apply_run_id_mismatch")
    previous_hash = str(parsed_events[-1]["event_sha256"])
    record = build_chained_event(
        len(parsed_events) + 1,
        previous_hash,
        event,
    )
    encoded_record = serialize_safe_persistent_json(
        record,
        indent=None,
        separators=(",", ":"),
    )
    updated = existing + encoded_record
    try:
        secure_atomic_write_text_at(
            handle.run_fd,
            "Events.jsonl",
            updated,
            revalidate=handle.revalidate,
        )
    except OSError:
        # A directory fsync can fail after rename committed the new bytes. Reconcile
        # under the run lock so callers never duplicate an already-appended event.
        try:
            observed = read_event_log_at(handle.run_fd)
        except (OSError, UnicodeDecodeError, ValueError):
            raise ValueError("event_log_commit_state_unknown") from None
        if observed != updated:
            raise
        try:
            os.fsync(handle.run_fd)
        except OSError:
            raise ValueError("event_log_commit_state_unknown") from None
    return record


def receipt_events_by_sequence(handle: ApplyMutationHandle) -> dict[int, dict[str, object]]:
    """Load the controller event log strictly for receipt-to-lifecycle binding."""

    text = read_event_log_at(handle.run_fd)
    parsed_events, errors = parse_chained_event_log(text)
    if errors:
        raise ValueError(errors[0])
    return {int(event["sequence"]): event for event in parsed_events}


APPLY_TOP_LEVEL_MUTABLE_ARTIFACTS = frozenset(
    {
        "Apply-Run.json",
        "Events.jsonl",
        "Final-Review.json",
        "Progress.json",
        "Result.json",
        WRITER_LOCK_NAME,
    }
)
APPLY_TASK_MUTABLE_ARTIFACT_RE = re.compile(
    r"(?:Dispatch-Packet\.json|Implementer-Report\.json|Review-Package\.patch|Task-Review\.json|Fix-Report\.json|"
    r"Review-Report-(?:spec|quality|security|final)\.json|Change-Set-[0-9]{2}\.json|"
    r"Validation-Receipt-VAL-[A-Z0-9_.-]{1,60}-[a-f0-9]{12}\.json|"
    r"Review-Receipt-(?:spec|quality|security|final)-[a-f0-9]{12}\.json|"
    r"Agent-Run-(?:implementer|fixer)-[0-9]{2}\.json|"
    r"Agent-Run-(?:task_reviewer-(?:spec|quality)|security_reviewer-security|final_reviewer-final)-[0-9]{2}\.json)"
)


def secure_write_apply_artifact(path: Path, text: str) -> None:
    lexical_path = lexical_absolute(path)
    parent = lexical_path.parent
    task_id: str | None = None
    if len(parent.parts) >= 3 and parent.parts[-3:-1] == (".codexqb", "apply-runs"):
        run_dir = parent
        if lexical_path.name not in APPLY_TOP_LEVEL_MUTABLE_ARTIFACTS:
            raise ValueError("invalid_apply_run_artifact_name")
    elif len(parent.parent.parts) >= 3 and parent.parent.parts[-3:-1] == (".codexqb", "apply-runs"):
        run_dir = parent.parent
        task_id = parent.name
        if not safe_task_id(task_id) or APPLY_TASK_MUTABLE_ARTIFACT_RE.fullmatch(lexical_path.name) is None:
            raise ValueError("invalid_apply_run_artifact_name")
    else:
        raise ValueError("invalid_apply_run_artifact_path")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        if task_id is None:
            secure_atomic_write_text_at(
                handle.run_fd,
                lexical_path.name,
                text,
                revalidate=handle.revalidate,
            )
        else:
            with open_apply_task_for_mutation(handle, task_id) as (task_fd, revalidate):
                secure_atomic_write_text_at(task_fd, lexical_path.name, text, revalidate=revalidate)


def audit_finding_ids(value: str) -> list[str]:
    cleaned = value.strip()
    if not cleaned or cleaned.lower() in {"none", "n/a", "na", "-"}:
        return []
    return [
        part.strip()
        for part in re.split(r"[,; ]+", cleaned)
        if part.strip() and part.strip().lower() not in {"none", "n/a", "na", "-"}
    ]


def extract_ready_queue(root: Path) -> list[dict[str, object]]:
    audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
    if not audit.is_file():
        return []
    text = audit.read_text(encoding="utf-8", errors="replace")
    items: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for match in re.finditer(
        r"\b(READY_WITH_WARNINGS|READY)\b\s*:?\s*`?((?:Planner-docs/)?Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md)`?",
        text,
        flags=re.IGNORECASE,
    ):
        path = match.group(2)
        if not path.startswith("Planner-docs/"):
            path = f"Planner-docs/{path}"
        key = (match.group(1).upper(), path)
        if key not in seen:
            seen.add(key)
            items.append({"readiness_status": key[0], "subplan_path": path, "finding_ids": [], "dependency_state": ""})
    for line in text.splitlines():
        if "|" not in line or "---" in line:
            continue
        cells = [cell.strip().strip("`") for cell in line.strip().strip("|").split("|")]
        if len(cells) < 2:
            continue
        path, status = cells[0], cells[1].upper()
        if status not in {"READY", "READY_WITH_WARNINGS"}:
            continue
        if not re.fullmatch(r"(?:Planner-docs/)?Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md", path):
            continue
        if not path.startswith("Planner-docs/"):
            path = f"Planner-docs/{path}"
        key = (status, path)
        if key not in seen:
            seen.add(key)
            items.append(
                {
                    "readiness_status": status,
                    "subplan_path": path,
                    "finding_ids": audit_finding_ids(cells[2]) if len(cells) >= 3 else [],
                    "dependency_state": cells[3] if len(cells) >= 4 else "",
                }
            )
    return items


def audit_text(root: Path) -> str:
    audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
    if not audit.is_file():
        return ""
    return audit.read_text(encoding="utf-8", errors="replace")


def run_step4_validator(root: Path) -> tuple[int, str]:
    command = [
        sys.executable,
        VALIDATOR_PATH.as_posix(),
        "--root",
        root.as_posix(),
        "--mode",
        "step4",
        "--strict",
    ]
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, f"validator_unavailable={type(exc).__name__}"
    return completed.returncode, f"{completed.stdout}\n{completed.stderr}".strip()


def validator_metric(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return ""


def validate_step4_queue(root: Path, mode: str) -> dict[str, str]:
    audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
    if not audit.is_file():
        raise ValueError("missing_step4_audit=Planner-docs/Sub-Planing-Audit.md")
    code, output = run_step4_validator(root)
    output_hash = sha256_bytes(output.encode("utf-8"))
    if code != 0:
        raise ValueError(f"step4_validator_failed={output_hash}")
    queue_state = validator_metric(output, "execution_queue_state") or "unknown"
    if mode == "no_action":
        if queue_state != "NO_ACTION_REQUIRED":
            raise ValueError(f"no_action_requires_no_action_required_audit={queue_state}")
        return {"validator_status": "passed", "execution_queue_state": queue_state, "validator_output_sha256": output_hash}
    if not extract_ready_queue(root):
        if "NO_ACTION_REQUIRED" in audit_text(root):
            raise ValueError("no_action_required_use_no_action_mode")
        raise ValueError("missing_step4_ready_queue")
    if queue_state == "NO_ACTION_REQUIRED":
        raise ValueError("no_action_required_use_no_action_mode")
    return {"validator_status": "passed", "execution_queue_state": queue_state, "validator_output_sha256": output_hash}


def extract_contract_signals(text: str) -> dict[str, list[str]]:
    patterns = {
        "acceptance_criteria": r"(?:acceptance|behavior|mp-ph\d+-as-\d+)",
        "allowed_paths": r"(?:allowed.*path|implementation[_ ]path|write[_ ]path)",
        "forbidden_paths": r"(?:forbidden[_ ]path|forbidden.*path|must not modify|do not modify)",
        "parent_signals": r"(?:parent[_ ]signal|parent acceptance|acceptance signal|signal id)",
        "dependencies": r"(?:depends_on|dependency|blocks|can_run_in_parallel|activation_conditions)",
        "framework_ownership": r"(?:framework ownership|ownership matrix|trl|vllm|peft)",
        "algorithmic_invariants": r"(?:invariant|rollout|policy fingerprint|trainer-step|stateful)",
        "structured_validation_commands": r"(?:validation[_ ]command|argv|expected_exit_code|probe_tier)",
        "security_requirements": r"(?:security[_ ]review|required security|risk[_ ]domain|secret|credential)",
    }
    signals = {key: [] for key in patterns}
    for line in text.splitlines():
        stripped = line.strip().strip("|").strip()
        if not stripped or len(stripped) > 240:
            continue
        lowered = stripped.lower()
        for key, pattern in patterns.items():
            if re.search(pattern, lowered):
                signals[key].append(stripped)
    return signals


def extract_subplan_contract(root: Path, subplan_path: str) -> dict[str, list[str]]:
    path = root / subplan_path
    if not path.is_file():
        return {key: [] for key in extract_contract_signals("").keys()}
    return extract_contract_signals(path.read_text(encoding="utf-8", errors="replace"))


def extract_implementation_contract(root: Path, subplan_path: str) -> dict[str, object]:
    binding = implementation_contract_source_binding(root, subplan_path)
    contract = binding.get("implementation_contract")
    return contract if isinstance(contract, dict) else {}


def contract_validation_commands(contract: dict[str, object]) -> list[dict[str, object]]:
    commands = contract.get("validation_commands")
    if not isinstance(commands, list):
        return []
    normalized: list[dict[str, object]] = []
    for item in commands:
        if not isinstance(item, dict):
            continue
        normalized.append(json.loads(json.dumps(item, sort_keys=True)))
    return normalized


def validation_command_ids(contract: dict[str, object]) -> list[str]:
    return implementation_contract_validation_command_ids(contract)


def normalized_json_object(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}
    return json.loads(json.dumps(value, sort_keys=True))


def task_id_for(run_id: str, index: int) -> str:
    return f"AR-{run_id}-T{index:03d}"


def task_contract_payload(task: dict[str, object]) -> dict[str, object]:
    return {
        "source_subplan_path": task.get("source_subplan_path"),
        "source_subplan_sha256": task.get("source_subplan_sha256"),
        "implementation_contract_digest": task.get("implementation_contract_digest"),
        "validation_command_ids": task.get("validation_command_ids", []),
        "parent_acceptance_signal_ids": task.get("parent_acceptance_signal_ids", []),
        "security_review_required": task.get("security_review_required"),
        "risk_class": task.get("risk_class", ""),
        "risk_domains": task.get("risk_domains", []),
    }


def task_contract_digest(task: dict[str, object]) -> str:
    return canonical_json_digest(task_contract_payload(task))


def apply_budget_contract(run: dict[str, object]) -> dict[str, object]:
    contract = run.get("budget_contract")
    return contract if isinstance(contract, dict) else default_budget_contract()


def default_tasks(root: Path, mode: str, run_id: str, ready_queue: list[dict[str, object]] | None = None) -> list[dict[str, object]]:
    if mode == "no_action":
        return []
    queue = ready_queue if ready_queue is not None else extract_ready_queue(root)
    tasks: list[dict[str, object]] = []
    for index, item in enumerate(queue, start=1):
        subplan_path = str(item["subplan_path"])
        binding = implementation_contract_source_binding(root, subplan_path)
        contract = extract_subplan_contract(root, subplan_path)
        implementation_contract = binding.get("implementation_contract")
        implementation_contract = implementation_contract if isinstance(implementation_contract, dict) else {}
        security_review_required = implementation_contract.get("security_review_required")
        structured_contract = normalized_json_object(implementation_contract)
        task = {
            "task_id": task_id_for(run_id, index),
            "state": "BRIEFED",
            "readiness_status": item["readiness_status"],
            "source_subplan_path": subplan_path,
            "source_subplan_sha256": binding.get("source_subplan_sha256"),
            "fresh_context_contract": contract,
            "implementation_contract": structured_contract,
            "implementation_contract_digest": binding.get("implementation_contract_digest"),
            "finding_ids": item.get("finding_ids", []),
            "dependency_state": item.get("dependency_state", ""),
            "security_review_required": security_review_required if isinstance(security_review_required, bool) else False,
            "parent_acceptance_signal_ids": binding.get("parent_acceptance_signal_ids", []),
            "risk_class": binding.get("risk_class", ""),
            "risk_domains": binding.get("risk_domains", []),
            "writer_lock": None,
            "validation_commands": contract_validation_commands(implementation_contract),
            "validation_command_ids": validation_command_ids(implementation_contract),
            "dispatch": None,
            "agent_runs": [],
            "writer_report_bindings": {},
            "implementation_generation": 0,
            "change_set": None,
            "validation_receipts": [],
            "review_receipts": {},
            "evidence_chain_status": "not_started",
            "verification_assurance": "controller_asserted",
            "redispatch_count": 0,
            "fix_cycle_count": 0,
        }
        task["task_contract_digest"] = task_contract_digest(task)
        tasks.append(task)
    return tasks


def step4_readiness_summary(
    root: Path,
    mode: str,
    ready_queue: list[dict[str, object]],
    validation: dict[str, str],
) -> dict[str, object]:
    audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
    text = audit_text(root)
    queue_state = validation.get("execution_queue_state", "")
    return {
        "audit_path": "Planner-docs/Sub-Planing-Audit.md",
        "audit_present": audit.is_file(),
        "ready_queue_count": len(ready_queue),
        "no_action_required": queue_state == "NO_ACTION_REQUIRED" or "NO_ACTION_REQUIRED" in text,
        "validator_command": [
            "python3",
            "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
            "--root",
            ".",
            "--mode",
            "step4",
            "--strict",
        ],
        "validator_status": validation.get("validator_status", "unknown"),
        "validator_output_sha256": validation.get("validator_output_sha256", ""),
        "execution_queue_state": queue_state,
        "execution_gate": "step4_validator_must_pass_before_product_changes",
        "mode": mode,
    }


def external_superpowers_policy(mode: str) -> dict[str, object]:
    return {
        "required": mode == "external_superpowers",
        "availability": "not_checked",
        "fallback_mode": "subagent_serial",
        "adapter_policy": "reconcile_before_dispatch",
    }


def workspace_mode_for(mode: str, baseline: dict[str, object]) -> str:
    non_git_action_mode = baseline.get("vcs") == "non_git" and mode != "no_action"
    return "non_git_unsafe" if non_git_action_mode else "unverified_current_worktree"


def user_approval_for(mode: str, baseline: dict[str, object]) -> bool:
    action_mode = mode != "no_action"
    non_git_action_mode = baseline.get("vcs") == "non_git" and action_mode
    unverified_git_action_mode = action_mode and git_worktree_requires_approval(baseline)
    return bool(non_git_action_mode or unverified_git_action_mode)


def apply_policy_envelope(
    root: Path,
    mode: str,
    baseline: dict[str, object],
    readiness: dict[str, object],
) -> dict[str, object]:
    return {
        "workspace_requested": "isolated_worktree",
        "workspace_detected": baseline.get("vcs"),
        "workspace_verified": False,
        "workspace_mode": workspace_mode_for(mode, baseline),
        "worktree_path": ".",
        "base_branch": git_default_branch(root) if baseline.get("vcs") == "git" else "unknown",
        "working_branch": baseline.get("branch"),
        "dirty_state": workspace_dirty_state(baseline),
        "user_approval": user_approval_for(mode, baseline),
        "commit_policy": "none",
        "push_allowed": False,
        "pr_allowed": False,
        "max_writer_agents": 1,
        "max_subagent_depth": 1,
        "budget_contract": default_budget_contract(),
        "agent_profiles": AGENT_PROFILES,
        "step4_readiness": readiness,
        "external_superpowers": external_superpowers_policy(mode),
        "safety": dict(APPLY_SAFETY),
        "verification_policy": dict(VERIFICATION_POLICY),
    }


def apply_policy_digest(root: Path, mode: str, baseline: dict[str, object], readiness: dict[str, object]) -> str:
    return canonical_json_digest(apply_policy_envelope(root, mode, baseline, readiness))


def external_superpowers_reconcile_is_valid(run: dict[str, object]) -> bool:
    external = run.get("external_superpowers")
    return (
        run.get("apply_requested_mode") == "external_superpowers"
        and run.get("mode") == "subagent_serial"
        and isinstance(external, dict)
        and external.get("required") is True
        and external.get("availability") == "unavailable"
        and external.get("fallback_mode") == "subagent_serial"
        and external.get("reconciled_to") == "subagent_serial"
        and external.get("adapter_policy") == "fallback_to_subagent_serial"
        and parse_utc_timestamp(external.get("reconciled_at")) is not None
    )


def external_superpowers_available_is_valid(run: dict[str, object]) -> bool:
    external = run.get("external_superpowers")
    return (
        run.get("apply_requested_mode") == "external_superpowers"
        and run.get("mode") == "external_superpowers"
        and isinstance(external, dict)
        and external.get("required") is True
        and external.get("availability") == "available"
        and external.get("fallback_mode") == "subagent_serial"
        and isinstance(external.get("version"), str)
        and bool(external.get("version"))
        and isinstance(external.get("source_path"), str)
        and bool(external.get("source_path"))
        and isinstance(external.get("adapter_policy"), str)
        and bool(external.get("adapter_policy"))
        and external.get("license_acknowledged") is True
    )


def task_brief_text(index: int, mode: str, task: dict[str, object]) -> str:
    return "\n".join(
        [
            f"# Task {index} Brief",
            "",
            f"- task_id: {task['task_id']}",
            f"- mode: {mode}",
            "- commit_policy: none",
            f"- source_subplan_path: {task.get('source_subplan_path')}",
            f"- source_subplan_sha256: {task.get('source_subplan_sha256')}",
            f"- implementation_contract_digest: {task.get('implementation_contract_digest')}",
            f"- task_contract_digest: {task.get('task_contract_digest')}",
            f"- parent_acceptance_signal_ids: {','.join(str(item) for item in task.get('parent_acceptance_signal_ids', [])) or 'none'}",
            f"- risk_class: {task.get('risk_class') or 'unknown'}",
            f"- risk_domains: {','.join(str(item) for item in task.get('risk_domains', [])) or 'none'}",
            f"- readiness_status: {task.get('readiness_status')}",
            f"- finding_ids: {json.dumps(task.get('finding_ids', []), sort_keys=True, separators=(',', ':'))}",
            f"- dependency_state: {task.get('dependency_state')}",
            f"- security_review_required: {json.dumps(task.get('security_review_required'))}",
            f"- validation_command_ids: {','.join(str(item) for item in task.get('validation_command_ids', [])) or 'none'}",
            f"- validation_commands: {json.dumps(task.get('validation_commands', []), sort_keys=True, separators=(',', ':'))}",
            f"- implementation_contract: {json.dumps(task.get('implementation_contract', {}), sort_keys=True, separators=(',', ':'))}",
            f"- fresh_context_contract: {json.dumps(task.get('fresh_context_contract', {}), sort_keys=True, separators=(',', ':'))}",
            "- dispatch_packet: generated by `apply_run.py dispatch` before subagent implementation",
            "- state_machine: BRIEFED -> IMPLEMENTING -> IMPLEMENTED -> TASK_REVIEW -> VERIFIED",
            "- report_paths: Dispatch-Packet.json, Implementer-Report.json, Task-Review.json, Fix-Report.json",
            "- stop_conditions: unsafe path, failing validation, missing evidence, required security review failure, snapshot mismatch",
            "",
        ]
    )


def create_apply_run(
    root: Path,
    mode: str,
    output_dir: Path | None = None,
    commit_policy: str = "none",
    *,
    replace: bool = False,
    resume: bool = False,
    run_id_suffix: str | None = None,
    allow_non_git_unsafe: bool = False,
    allow_unverified_git_worktree: bool = False,
) -> dict[str, object]:
    lexical_root = lexical_absolute(root)
    root = root.resolve()
    root_anchor_fd = os.open(root, secure_directory_open_flags())
    try:
        root_mount_resolution = resolve_apply_mount_identity(root_anchor_fd, APPLY_RUN_MUTATION)
        if replace:
            require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
        return create_apply_run_anchored(
            root,
            mode,
            output_dir,
            commit_policy,
            replace=replace,
            resume=resume,
            run_id_suffix=run_id_suffix,
            allow_non_git_unsafe=allow_non_git_unsafe,
            allow_unverified_git_worktree=allow_unverified_git_worktree,
            lexical_root=lexical_root,
            root_anchor_fd=root_anchor_fd,
            root_mount_resolution=root_mount_resolution,
        )
    finally:
        os.close(root_anchor_fd)


def create_apply_run_anchored(
    root: Path,
    mode: str,
    output_dir: Path | None,
    commit_policy: str,
    *,
    replace: bool,
    resume: bool,
    run_id_suffix: str | None,
    allow_non_git_unsafe: bool,
    allow_unverified_git_worktree: bool,
    lexical_root: Path,
    root_anchor_fd: int,
    root_mount_resolution: MountResolution,
) -> dict[str, object]:
    require_mount_assurance(root_mount_resolution, APPLY_RUN_MUTATION)
    require_apply_same_mount(
        root_mount_resolution,
        root_anchor_fd,
        ".",
        mismatch_error="invalid_apply_run_output_dir=root_identity_changed",
    )
    if replace:
        require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    if not opened_directory_matches_path(
        root,
        os.fstat(root_anchor_fd),
        reject_mount=False,
    ):
        raise ValueError("invalid_apply_run_output_dir=root_identity_changed")
    if mode not in APPLY_MODES:
        raise ValueError(f"unsupported apply mode: {mode}")
    if commit_policy not in COMMIT_POLICIES:
        raise ValueError(f"unsupported commit policy: {commit_policy}")
    if commit_policy != "none":
        raise ValueError("commit_policy defaults to none; other policies require explicit controller approval outside apply_run.py")
    if resume and output_dir is None:
        raise ValueError("resume_requires_output_dir")
    if resume:
        run_dir = resolve_managed_apply_run_dir(root, output_dir, lexical_root=lexical_root)
        run = load_json_strict(run_dir / "Apply-Run.json")
        errors = validate_apply_run(run_dir, root)
        if errors:
            raise ValueError(";".join(errors))
        return {"apply_run_id": str(run["apply_run_id"]), "run_dir": run_dir.as_posix(), "state": "resumed"}
    baseline, workspace_file_manifest = workspace_baseline_capture(root)
    snapshot = collect_snapshot(root, baseline)
    ready_queue = [] if mode == "no_action" else extract_ready_queue(root)
    budget_contract = default_budget_contract()
    if len(ready_queue) > budget_limit(budget_contract, "max_selected_tasks"):
        raise ValueError("budget_selected_tasks_exceeded")
    spec_digest = apply_spec_digest(
        mode,
        snapshot,
        baseline,
        ready_queue,
        apply_run_schema_version=APPLY_RUN_SCHEMA_VERSION,
    )
    suffix = invocation_suffix(run_id_suffix)
    run_id = apply_run_id(mode, snapshot, baseline, ready_queue, suffix)
    run_dir = resolve_managed_apply_run_dir(root, output_dir, run_id, lexical_root=lexical_root)
    step4_validation = validate_step4_queue(root, mode)
    step4_readiness = step4_readiness_summary(root, mode, ready_queue, step4_validation)
    policy = apply_policy_envelope(root, mode, baseline, step4_readiness)
    policy_digest = canonical_json_digest(policy)
    action_mode = mode != "no_action"
    non_git_action_mode = baseline["vcs"] == "non_git" and mode != "no_action"
    if non_git_action_mode and not allow_non_git_unsafe:
        raise ValueError("non_git_workspace_requires_explicit_approval")
    unverified_git_action_mode = action_mode and git_worktree_requires_approval(baseline)
    if unverified_git_action_mode and not allow_unverified_git_worktree:
        raise ValueError("git_workspace_requires_explicit_current_worktree_approval")
    if run_dir.exists() and not replace:
        raise ValueError(f"apply_run_already_exists={run_dir.relative_to(root).as_posix()}")

    tasks = default_tasks(root, mode, run_id, ready_queue)
    repository_baselines = capture_repository_baselines(root, tasks)
    registration_id = secrets.token_hex(32)
    run = {
        "apply_run_schema_version": APPLY_RUN_SCHEMA_VERSION,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "handoff_contract_version": HANDOFF_CONTRACT_VERSION,
        "plugin_version": PLUGIN_VERSION,
        "apply_requested_mode": mode,
        "apply_spec_id": f"apply-spec-{mode}-{spec_digest[:16]}",
        "apply_spec_digest": spec_digest,
        "apply_policy_digest": policy_digest,
        "apply_spec_inputs": {"ready_queue": ready_queue, "workspace_baseline": baseline},
        "apply_run_id": run_id,
        "apply_run_invocation_id": suffix,
        "apply_run_registration_id": registration_id,
        "mode": mode,
        "workspace_requested": policy["workspace_requested"],
        "workspace_detected": policy["workspace_detected"],
        "workspace_verified": policy["workspace_verified"],
        "workspace_mode": policy["workspace_mode"],
        "worktree_path": policy["worktree_path"],
        "base_branch": policy["base_branch"],
        "working_branch": policy["working_branch"],
        "dirty_state": policy["dirty_state"],
        "user_approval": policy["user_approval"],
        "workspace_baseline": baseline,
        "commit_policy": policy["commit_policy"],
        "push_allowed": policy["push_allowed"],
        "pr_allowed": policy["pr_allowed"],
        "max_writer_agents": policy["max_writer_agents"],
        "max_subagent_depth": policy["max_subagent_depth"],
        "budget_contract": policy["budget_contract"],
        "token_usage": token_usage_not_observed(),
        "agent_profiles": policy["agent_profiles"],
        "source_snapshot": snapshot,
        "source_snapshot_digest": snapshot_digest(snapshot),
        "step4_readiness": policy["step4_readiness"],
        "external_superpowers": policy["external_superpowers"],
        "safety": policy["safety"],
        "verification_policy": policy["verification_policy"],
        "repository_baselines": repository_baselines,
        "workspace_file_manifest": workspace_file_manifest,
    }
    progress = {
        "apply_run_id": run_id,
        "mode": mode,
        "tasks": tasks,
        "verified_task_ids": [],
        "active_writer_locks": [],
        "final_review_required": mode != "no_action",
        "final_review_complete": mode == "no_action",
        "resume_cursor": None,
        "events": [],
    }
    result = {
        "apply_run_id": run_id,
        "status": "no_action" if mode == "no_action" else "initialized",
        "completed_tasks": [],
        "blocked_tasks": [],
        "budget_contract": budget_contract,
        "token_usage": token_usage_not_observed(),
        "next_action": "Use the Step 4 handoff to execute tasks; update Progress.json after each state transition.",
    }
    task_briefs: dict[str, str] = {}
    for index, task in enumerate(tasks, start=1):
        task_name = str(task["task_id"])
        if not safe_task_id(task_name):
            raise ValueError(f"invalid_task_id={task_name}")
        brief = assert_safe_persistent_text(task_brief_text(index, mode, task))
        task["brief_sha256"] = sha256_bytes(brief.encode("utf-8"))
        task_briefs[task_name] = brief
    initial_event = build_chained_event(
        1,
        EVENT_CHAIN_GENESIS_SHA256,
        {
            "event_type": "apply_run_initialized",
            "apply_run_id": run_id,
            "mode": mode,
            "task_ids": [task["task_id"] for task in tasks],
            "actor": "apply_run.py",
        },
    )
    for name, payload in (
        ("Apply-Run.json", run),
        ("Final-Review.json", {"status": "not_started" if mode != "no_action" else "not_required"}),
        ("Result.json", result),
        ("Progress.json", progress),
    ):
        assert_safe_serialized_artifact(name, serialize_safe_persistent_json(payload).encode("utf-8"))
    assert_safe_serialized_artifact(
        "Events.jsonl",
        serialize_safe_persistent_json(initial_event, indent=None, separators=(",", ":")).encode("utf-8"),
    )
    load_or_create_apply_run_trust_key(create=True)
    if run_dir.exists() and replace:
        replace_existing_apply_run(
            root,
            run_dir,
            root_anchor_fd=root_anchor_fd,
            root_mount_resolution=root_mount_resolution,
        )
    parent_fd, run_fd, run_metadata = create_managed_apply_run_directory(
        root,
        run_dir,
        root_anchor_fd=root_anchor_fd,
        root_mount_resolution=root_mount_resolution,
    )
    try:
        write_regular_json_exclusive_at(run_fd, "Apply-Run.json", run)
        write_regular_json_exclusive_at(
            run_fd,
            "Final-Review.json",
            {"status": "not_started" if mode != "no_action" else "not_required"},
        )
        write_regular_json_exclusive_at(run_fd, "Result.json", result)
        for task in tasks:
            task_name = str(task["task_id"])
            os.mkdir(task_name, mode=0o700, dir_fd=run_fd)
            task_fd, task_metadata = open_child_directory(run_fd, task_name)
            try:
                require_apply_same_mount(
                    root_mount_resolution,
                    task_fd,
                    repository_mount_relative_path(root, run_dir / task_name),
                    mismatch_error="invalid_apply_run_task_directory",
                )
                if task_metadata.st_dev != run_metadata.st_dev or not metadata_is_private_directory(task_metadata):
                    raise ValueError("invalid_apply_run_task_directory")
                brief = task_briefs[task_name]
                write_regular_text_exclusive_at(task_fd, "Brief.md", brief)
                write_regular_json_exclusive_at(task_fd, "Implementer-Report.json", {"status": "PENDING"})
                write_regular_text_exclusive_at(task_fd, "Review-Package.patch", "")
                write_regular_json_exclusive_at(task_fd, "Task-Review.json", {"status": "PENDING"})
                write_regular_json_exclusive_at(task_fd, "Fix-Report.json", {"status": "PENDING"})
                for phase in sorted(REVIEW_PHASES):
                    write_regular_json_exclusive_at(task_fd, f"Review-Report-{phase}.json", {"status": "PENDING"})
                os.fsync(task_fd)
            finally:
                os.close(task_fd)
        write_regular_json_exclusive_at(run_fd, "Progress.json", progress)
        write_regular_text_exclusive_at(
            run_fd,
            "Events.jsonl",
            serialize_safe_persistent_json(
                initial_event,
                indent=None,
                separators=(",", ":"),
            ),
        )
        write_regular_json_exclusive_at(
            run_fd,
            APPLY_RUN_MARKER_NAME,
            apply_run_marker_payload(root, run_dir, run),
        )
        os.fsync(run_fd)
        create_apply_run_registration(
            root,
            run_dir,
            run,
            root_metadata=os.fstat(root_anchor_fd),
            parent_fd=parent_fd,
            run_fd=run_fd,
            run_metadata=run_metadata,
            root_mount_resolution=root_mount_resolution,
        )
        os.fsync(parent_fd)
    finally:
        os.close(run_fd)
        os.close(parent_fd)
    return {"apply_run_id": run_id, "run_dir": run_dir.as_posix(), "state": result["status"]}


def reconcile_external_superpowers(run_dir: Path) -> dict[str, object]:
    with open_verified_apply_run_for_mutation(run_dir, require_provenance=False) as handle:
        run_dir = handle.run_dir
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        external = run.get("external_superpowers")
        if run.get("mode") != "external_superpowers":
            if external_superpowers_reconcile_is_valid(run):
                manifest_errors = apply_run_manifest_replace_errors(run)
                if manifest_errors:
                    raise ValueError(";".join(manifest_errors))
                refresh_apply_run_provenance(run_dir, run)
                return {"state": "reconciled", "mode": "subagent_serial", "recovered": True}
            if not current_apply_run_provenance_is_valid(handle.root, run_dir, run):
                raise ValueError("apply_run_provenance_unverified")
            return {"state": "unchanged", "mode": run.get("mode")}
        if not isinstance(external, dict):
            raise ValueError("external_superpowers_policy_missing")
        availability = external.get("availability")
        if availability == "not_checked":
            raise ValueError("external_superpowers_readiness_not_checked")
        if availability == "available":
            missing = []
            for key in ("version", "source_path", "adapter_policy"):
                if not external.get(key):
                    missing.append(key)
            if external.get("license_acknowledged") is not True:
                missing.append("license_acknowledged")
            if missing:
                raise ValueError(f"external_superpowers_available_metadata_missing={','.join(missing)}")
            manifest_errors = apply_run_manifest_replace_errors(run)
            if manifest_errors:
                raise ValueError(";".join(manifest_errors))
            refresh_apply_run_provenance(run_dir, run)
            return {"state": "ready", "mode": "external_superpowers"}
        if availability != "unavailable":
            raise ValueError(f"external_superpowers_invalid_availability={availability}")
        if external.get("fallback_mode") != "subagent_serial":
            raise ValueError("external_superpowers_unavailable_requires_subagent_serial_fallback")
        manifest_errors = apply_run_manifest_replace_errors(run)
        if manifest_errors:
            raise ValueError(";".join(manifest_errors))

        run["mode"] = "subagent_serial"
        external["reconciled_to"] = "subagent_serial"
        external["reconciled_at"] = utc_now()
        external["adapter_policy"] = "fallback_to_subagent_serial"
        progress["mode"] = "subagent_serial"
        event = append_event_at(
            handle,
            {
                "event_type": "external_superpowers_reconciled",
                "from": "external_superpowers",
                "to": "subagent_serial",
                "actor": "apply_run.py",
                "evidence": ["external_superpowers availability unavailable; fallback_mode subagent_serial"],
            },
        )
        progress["events"] = [
            {"sequence": event["sequence"], "event_type": "external_superpowers_reconciled", "to": "subagent_serial"}
        ]
        secure_atomic_write_json_at(
            handle.run_fd,
            "Apply-Run.json",
            run,
            revalidate=handle.revalidate,
        )
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        refresh_apply_run_provenance(run_dir, run)
        return {"state": "reconciled", "mode": "subagent_serial", "event_sequence": event["sequence"]}


def load_json(path: Path, errors: list[str], label: str) -> object:
    encoded = read_artifact_bytes(path, errors, label)
    if encoded is None:
        return {}
    return decode_json_artifact(encoded, errors, label)


def decode_json_artifact(encoded: bytes, errors: list[str], label: str) -> object:
    try:
        return parse_safe_persistent_json(encoded.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        errors.append(f"invalid_json={label}")
        return {}


def read_artifact_bytes(
    path: Path,
    errors: list[str],
    label: str,
    *,
    required: bool = True,
) -> bytes | None:
    parent_fd = -1
    try:
        parent_fd = os.open(path.parent, secure_directory_open_flags())
        encoded = secure_read_regular_bytes_at(parent_fd, path.name)
        assert_safe_serialized_artifact(path.name, encoded)
        return encoded
    except FileNotFoundError:
        if required:
            errors.append(f"missing_{label}")
        return None
    except (OSError, ValueError):
        errors.append(f"invalid_artifact_file={label}")
        return None
    finally:
        if parent_fd >= 0:
            os.close(parent_fd)


def read_artifact_text(
    path: Path,
    errors: list[str],
    label: str,
    *,
    required: bool = True,
) -> str | None:
    encoded = read_artifact_bytes(path, errors, label, required=required)
    if encoded is None:
        return None
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError:
        errors.append(f"invalid_artifact_file={label}")
        return None


def load_json_strict(path: Path) -> dict[str, object]:
    parent_fd = os.open(path.parent, secure_directory_open_flags())
    try:
        return secure_read_regular_json_at(parent_fd, path.name)
    finally:
        os.close(parent_fd)


def find_task(progress: dict[str, object], task_id: str) -> dict[str, object]:
    tasks = progress.get("tasks", [])
    if not isinstance(tasks, list):
        raise ValueError("progress_tasks_must_be_list")
    for task in tasks:
        if isinstance(task, dict) and task.get("task_id") == task_id:
            return task
    raise ValueError(f"unknown_task_id={task_id}")


def lock_payload(run_dir: Path, task_id: str, owner: str) -> dict[str, object]:
    return {
        "lock_id": sha256_bytes(f"{run_dir}:{task_id}:{owner}".encode("utf-8"))[:16],
        "task_id": task_id,
        "owner": owner,
        "acquired_at": utc_now(),
        "expires_in_seconds": 3600,
    }


def lock_expiry(lock: dict[str, object]) -> datetime | None:
    acquired = parse_utc_timestamp(lock.get("acquired_at"))
    expires = lock.get("expires_in_seconds")
    if acquired is None or not isinstance(expires, (int, float)) or expires < 0:
        return None
    return datetime.fromtimestamp(acquired.timestamp() + float(expires), timezone.utc)


def lock_is_expired(lock: dict[str, object], *, now: datetime | None = None) -> bool:
    expiry = lock_expiry(lock)
    if expiry is None:
        return False
    return (now or datetime.now(timezone.utc)) >= expiry


def acquire_writer_lock(
    handle: ApplyMutationHandle,
    progress: dict[str, object],
    task: dict[str, object],
    owner: str,
) -> dict[str, object]:
    locks = progress.get("active_writer_locks", [])
    if locks:
        raise ValueError("active_writer_lock_exists")
    lock = lock_payload(handle.run_dir, str(task["task_id"]), owner)
    if not handle.revalidate():
        raise ValueError("apply_run_mutation_identity_changed")
    try:
        write_regular_json_exclusive_at(handle.run_fd, WRITER_LOCK_NAME, lock)
    except FileExistsError as exc:
        raise ValueError("active_writer_lock_exists") from exc
    os.fsync(handle.run_fd)
    progress["active_writer_locks"] = [lock]
    task["writer_lock"] = lock
    return lock


def release_writer_lock(
    handle: ApplyMutationHandle,
    progress: dict[str, object],
    task: dict[str, object],
    owner: str | None = None,
) -> dict[str, object] | None:
    lock: dict[str, object] | None = None
    metadata = regular_target_metadata_at(handle.run_fd, WRITER_LOCK_NAME)
    if metadata is not None:
        lock = secure_read_regular_json_at(handle.run_fd, WRITER_LOCK_NAME)
        if owner and lock.get("owner") != owner:
            raise ValueError("writer_lock_owner_mismatch")
        secure_unlink_regular_at(
            handle.run_fd,
            WRITER_LOCK_NAME,
            revalidate=handle.revalidate,
        )
    progress["active_writer_locks"] = []
    task["writer_lock"] = None
    return lock


def trusted_task_transition_errors(
    handle: ApplyMutationHandle,
    progress: dict[str, object],
    task: dict[str, object],
    *,
    verified_candidate: bool,
) -> list[str]:
    """Validate immutable task inputs and live repository scope at trust gates."""

    run = handle.run
    task_id = str(task.get("task_id", ""))
    errors: list[str] = []
    if run.get("verification_policy") != VERIFICATION_POLICY:
        errors.append("verification_policy_mismatch")
    tasks = progress.get("tasks")
    if not isinstance(tasks, list):
        return ["progress_tasks_must_be_list"]
    typed_tasks = [item for item in tasks if isinstance(item, dict)]
    if len(typed_tasks) != len(tasks):
        errors.append("progress_task_must_be_object")
    task_indexes = [
        index
        for index, item in enumerate(typed_tasks, start=1)
        if item is task or item.get("task_id") == task_id
    ]
    if len(task_indexes) != 1:
        errors.append(f"trusted_transition_task_identity_invalid={task_id or 'missing'}")
        return list(dict.fromkeys(errors))

    task_ids = [str(item.get("task_id", "")) for item in typed_tasks]
    if len(task_ids) != len(set(task_ids)):
        errors.append("duplicate_task_id")
    for queued_task in typed_tasks:
        validate_task_source_binding(handle.root, queued_task, errors)
        queued_task_id = str(queued_task.get("task_id", ""))
        if queued_task.get("verification_assurance") != "controller_asserted":
            errors.append(f"invalid_verification_assurance={queued_task_id}")
        receipt_map = queued_task.get("review_receipts")
        has_final_receipt = isinstance(receipt_map, dict) and isinstance(receipt_map.get("final"), dict)
        expected_evidence_status = "complete_unattested" if has_final_receipt else None
        if expected_evidence_status is not None and queued_task.get("evidence_chain_status") != expected_evidence_status:
            errors.append(f"complete_review_chain_must_remain_unattested={queued_task_id}")

    task_baseline = repository_baseline_for_task(run, task_id)
    if task_baseline is None:
        errors.append(f"repository_baseline_missing={task_id}")
    else:
        try:
            if task_baseline.get("allowed_paths") != sorted(implementation_contract_paths(task)):
                errors.append(f"repository_baseline_path_mismatch={task_id}")
            if task_baseline.get("implementation_contract_digest") != task.get("implementation_contract_digest"):
                errors.append(f"repository_baseline_contract_mismatch={task_id}")
            if task_baseline.get("baseline_digest") != repository_baseline_digest(task_baseline.get("snapshot", [])):
                errors.append(f"repository_baseline_digest_mismatch={task_id}")
            baseline_content_map(task_baseline)
        except (TypeError, ValueError) as exc:
            errors.append(f"repository_baseline_invalid={task_id}:{exc}")

    task_dir = handle.run_dir / task_id
    brief_text = read_artifact_text(
        task_dir / "Brief.md",
        errors,
        f"{task_id}_task_brief",
        required=False,
    )
    if brief_text is None:
        if f"invalid_artifact_file={task_id}_task_brief" not in errors:
            errors.append(f"missing_task_brief={task_id}")
    else:
        if task.get("brief_sha256") != sha256_bytes(brief_text.encode("utf-8")):
            errors.append(f"task_brief_hash_mismatch={task_id}")
        brief_mode = str(run.get("apply_requested_mode", run.get("mode", "")))
        if brief_text != task_brief_text(task_indexes[0], brief_mode, task):
            errors.append(f"task_brief_contract_mismatch={task_id}")

    validate_dispatch_packet(handle.run_dir, run, task, errors)
    try:
        drift = implementation_workspace_drift(handle.root, handle.run_dir, tasks, run)
        baseline = run.get("workspace_baseline")
        current_baseline: dict[str, object] | None = None
        if not isinstance(baseline, dict):
            errors.append("workspace_baseline_missing")
        else:
            current_baseline = workspace_baseline(handle.root)
            for key in WORKSPACE_BASELINE_KEYS:
                if baseline.get(key) == current_baseline.get(key):
                    continue
                if drift.get("allowed") is True and key in IMPLEMENTATION_DRIFT_BASELINE_KEYS:
                    continue
                errors.append(f"workspace_baseline_mismatch={key}")
        current_snapshot = collect_snapshot(handle.root, current_baseline)
        source_snapshot = run.get("source_snapshot")
        if not isinstance(source_snapshot, list):
            errors.append("invalid_source_snapshot")
        elif run.get("source_snapshot_digest") != snapshot_digest(current_snapshot):
            if not (
                drift.get("allowed") is True
                and snapshot_matches_except(source_snapshot, current_snapshot, IMPLEMENTATION_DRIFT_SNAPSHOT_PATHS)
            ):
                errors.append("source_snapshot_mismatch")
    except (OSError, TypeError, ValueError) as exc:
        errors.append(f"workspace_scope_validation_unavailable={exc}")

    if verified_candidate:
        candidate = json.loads(json.dumps(task))
        candidate["state"] = "VERIFIED"
        validate_task_artifacts(
            handle.run_dir,
            candidate,
            errors,
            root=handle.root,
            run=run,
            task_index=task_indexes[0],
        )
    return list(dict.fromkeys(errors))


def transition_task_state(run_dir: Path, task_id: str, to_state: str, actor: str, evidence: list[str] | None = None) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "to_state": to_state, "actor": actor, "evidence": evidence or []}
    )
    if not safe_task_id(task_id):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    if to_state not in TASK_STATES:
        raise ValueError(f"invalid_target_state={to_state}")
    if not actor.strip():
        raise ValueError("transition_actor_required")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        from_state = str(task.get("state", ""))
        if to_state not in STATE_TRANSITIONS.get(from_state, set()):
            raise ValueError(f"invalid_transition={from_state}->{to_state}")
        if run.get("mode") == "subagent_serial" and to_state == "IMPLEMENTING":
            dispatch = task.get("dispatch")
            if not isinstance(dispatch, dict):
                raise ValueError(f"subagent_dispatch_packet_missing={task_id}")
            if dispatch.get("role") != "implementer" or dispatch.get("status") not in {"spawned", "completed"}:
                raise ValueError(f"subagent_dispatch_spawn_required={task_id}")
        if run.get("mode") == "subagent_serial" and from_state == "IMPLEMENTING" and to_state == "IMPLEMENTED":
            _, writer_error = current_completed_writer_record(handle, task)
            if writer_error:
                raise ValueError(writer_error)
        if run.get("mode") == "subagent_serial" and from_state == "FIXING" and to_state == "RE_REVIEW":
            _, writer_error = current_completed_writer_record(handle, task)
            if writer_error:
                raise ValueError(writer_error)
        if to_state == "SECURITY_REVIEW" and not task_review_phase_is_current(handle, task, "quality", "pass"):
            raise ValueError(f"security_review_requires_quality_pass={task_id}")
        if to_state == "VERIFIED":
            verification_errors = trusted_task_transition_errors(
                handle,
                progress,
                task,
                verified_candidate=True,
            )
            verification_errors.extend(task_verification_errors(handle, task))
            if verification_errors:
                raise ValueError(";".join(dict.fromkeys(verification_errors)))
        if to_state == "FIXING":
            max_fix_cycles = budget_limit(apply_budget_contract(run), "max_fix_cycles")
            current_cycles = task.get("fix_cycle_count", 0)
            if not isinstance(current_cycles, int) or isinstance(current_cycles, bool) or current_cycles < 0:
                raise ValueError(f"fix_cycle_count_invalid={task_id}")
            if current_cycles >= max_fix_cycles:
                raise ValueError(f"budget_max_fix_cycles_exceeded={task_id}")
            task["fix_cycle_count"] = current_cycles + 1
            task["change_set"] = None
            task["validation_receipts"] = []
            task["review_receipts"] = {}
            task["evidence_chain_status"] = "in_progress"
            task["verification_assurance"] = "controller_asserted"

        lock_event: dict[str, object] | None = None
        if to_state == "IMPLEMENTING":
            lock_event = acquire_writer_lock(handle, progress, task, actor)
        elif from_state == "IMPLEMENTING":
            lock_event = release_writer_lock(handle, progress, task, actor)

        task["state"] = to_state
        if to_state == "VERIFIED":
            verified_ids = progress.get("verified_task_ids")
            verified_ids = verified_ids if isinstance(verified_ids, list) else []
            progress["verified_task_ids"] = sorted({*map(str, verified_ids), task_id})
        event = append_event_at(
            handle,
            {
                "event_type": "task_transition",
                "task_id": task_id,
                "from": from_state,
                "to": to_state,
                "actor": actor,
                "evidence": evidence or [],
                "writer_lock": lock_event,
            },
        )
        progress["resume_cursor"] = {"task_id": task_id, "state": to_state, "event_sequence": event["sequence"]}
        progress["events"] = [
            {"sequence": event["sequence"], "event_type": "task_transition", "task_id": task_id, "to": to_state}
        ]
        if to_state == "FIXING":
            secure_atomic_write_json_at(
                handle.run_fd,
                "Final-Review.json",
                final_review_aggregate(progress.get("tasks")),
                revalidate=handle.revalidate,
            )
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        return event


def task_dir_for(run_dir: Path, task_id: str) -> Path:
    if not safe_task_id(task_id):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    task_dir = (run_dir / task_id).resolve()
    if not is_inside(run_dir, task_dir):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    return task_dir


def safe_agent_id(value: str) -> bool:
    return bool(re.fullmatch(r"[A-Za-z0-9_.:-]{3,160}", value))


def agent_runs(task: dict[str, object]) -> list[dict[str, object]]:
    runs = task.get("agent_runs", [])
    return runs if isinstance(runs, list) else []


def agent_run_artifact_name(role: str, review_phase: str | None, attempt: int) -> str:
    phase_suffix = f"-{review_phase}" if review_phase is not None else ""
    return f"Agent-Run-{role}{phase_suffix}-{attempt:02d}.json"


def next_agent_attempt(task: dict[str, object], role: str, review_phase: str | None = None) -> int:
    attempts = [
        run.get("attempt")
        for run in agent_runs(task)
        if isinstance(run, dict)
        and run.get("role") == role
        and run.get("review_phase") == review_phase
        and isinstance(run.get("attempt"), int)
    ]
    return max(attempts, default=0) + 1


def agent_run_completed(task: dict[str, object], role: str, review_phase: str | None = None) -> bool:
    return any(
        isinstance(run, dict)
        and run.get("role") == role
        and run.get("review_phase") == review_phase
        and run.get("status") == "completed"
        for run in agent_runs(task)
    )


def upsert_agent_run(task: dict[str, object], record: dict[str, object]) -> None:
    runs = agent_runs(task)
    replaced = False
    for index, run in enumerate(runs):
        if (
            isinstance(run, dict)
            and run.get("role") == record.get("role")
            and run.get("review_phase") == record.get("review_phase")
            and run.get("attempt") == record.get("attempt")
        ):
            runs[index] = record
            replaced = True
            break
    if not replaced:
        runs.append(record)
    task["agent_runs"] = runs


def dispatch_prompt(
    run: dict[str, object],
    task: dict[str, object],
    role: str,
    brief_text: str,
    review_phase: str | None = None,
) -> str:
    profile = AGENT_PROFILES[role]
    task_id = str(task["task_id"])
    source_path = task.get("source_subplan_path")
    contract = json.dumps(task.get("fresh_context_contract", {}), indent=2, sort_keys=True)
    implementation_contract = json.dumps(task.get("implementation_contract", {}), indent=2, sort_keys=True)
    return "\n".join(
        [
            f"# CodexQB Fresh {role.replace('_', ' ').title()} Dispatch",
            "",
            "Use only this fresh task context. Do not assume parent chat history.",
            "Do not commit, push, open PRs, deploy, or mutate external systems.",
            "Stop and report a blocker on unsafe paths, missing sources, failed validation, secrets, or scope overflow.",
            "",
            f"- apply_run_id: {run.get('apply_run_id')}",
            f"- task_id: {task_id}",
            f"- role: {role}",
            f"- review_phase: {review_phase or 'not_applicable'}",
            f"- agent_type: {profile['agent_type']}",
            f"- model_profile: {profile['model_profile']}",
            f"- sandbox: {profile['sandbox']}",
            f"- source_subplan_path: {source_path}",
            f"- source_subplan_sha256: {task.get('source_subplan_sha256')}",
            f"- implementation_contract_digest: {task.get('implementation_contract_digest')}",
            f"- task_contract_digest: {task.get('task_contract_digest')}",
            f"- brief_sha256: {task.get('brief_sha256')}",
            "",
            "## Fresh Context Contract",
            "",
            "```json",
            contract,
            "```",
            "",
            "## Structured Implementation Contract",
            "",
            "```json",
            implementation_contract,
            "```",
            "",
            "## Task Brief",
            "",
            brief_text.rstrip(),
            "",
            "## Required Return",
            "",
            "- List files changed or reviewed.",
            "- Record validation commands as structured argv with exit codes.",
            (
                "- Return exactly one structured JSON review report in the final response; the read-only reviewer "
                "must not write repository or Apply artifacts. The controller must normalize that payload with "
                "normalize-review before recording completion."
                if review_phase is not None
                else (
                    "- Return exactly one structured JSON writer report in the final response; do not write Apply artifacts. "
                    "The controller must persist it with normalize-writer before recording completion or transitioning state."
                )
            ),
            "- Include any blocker as a concise, actionable finding with evidence.",
            "",
        ]
    )


def prepare_dispatch_packet(
    run_dir: Path,
    task_id: str,
    role: str,
    actor: str,
    evidence: list[str] | None = None,
    review_phase: str | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "role": role,
            "review_phase": review_phase,
            "actor": actor,
            "evidence": evidence or [],
        }
    )
    if role not in DISPATCH_ROLES:
        raise ValueError(f"invalid_dispatch_role={role}")
    if not actor.strip():
        raise ValueError("dispatch_actor_required")
    expected_phase = {
        "task_reviewer": {"spec", "quality"},
        "security_reviewer": {"security"},
        "final_reviewer": {"final"},
    }.get(role)
    if expected_phase is None and review_phase is not None:
        raise ValueError(f"dispatch_review_phase_not_applicable={role}")
    if expected_phase is not None and review_phase not in expected_phase:
        raise ValueError(f"dispatch_review_phase_required={role}")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        if run.get("mode") != "subagent_serial":
            raise ValueError(f"dispatch_requires_subagent_serial_mode={run.get('mode')}")
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        state = str(task.get("state", ""))
        if state not in DISPATCH_ROLE_STATE_REQUIREMENTS[role]:
            raise ValueError(f"dispatch_requires_state={role}:{state or 'missing'}")
        if role == "task_reviewer" and review_phase == "quality" and not task_review_phase_is_current(
            handle, task, "spec", "pass"
        ):
            raise ValueError(f"quality_review_requires_spec_pass={task_id}")
        if role == "security_reviewer" and not task_review_phase_is_current(handle, task, "quality", "pass"):
            raise ValueError(f"security_review_requires_quality_pass={task_id}")
        if role == "final_reviewer":
            if not task_review_phase_is_current(handle, task, "quality", "pass"):
                raise ValueError(f"final_review_requires_quality_pass={task_id}")
            if task.get("security_review_required") is True and not task_review_phase_is_current(
                handle, task, "security", "pass"
            ):
                raise ValueError(f"final_review_requires_security_pass={task_id}")
        existing = task.get("dispatch")
        if isinstance(existing, dict) and existing.get("status") in {"packet_ready", "spawned"}:
            raise ValueError(f"dispatch_already_active={task_id}")

        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            try:
                brief_text = secure_read_regular_text_at(task_fd, "Brief.md")
            except FileNotFoundError as exc:
                raise ValueError(f"missing_task_brief={task_id}") from exc
            brief_sha = sha256_bytes(brief_text.encode("utf-8"))
            if task.get("brief_sha256") != brief_sha:
                raise ValueError(f"brief_hash_mismatch={task_id}")

            prompt = dispatch_prompt(run, task, role, brief_text, review_phase)
            prompt_sha = sha256_bytes(prompt.encode("utf-8"))
            attempt = next_agent_attempt(task, role, review_phase)
            if attempt > budget_limit(apply_budget_contract(run), "max_agent_attempts_per_role"):
                raise ValueError(f"budget_max_agent_attempts_exceeded={task_id}:{role}")
            packet = {
                "dispatch_packet_schema_version": 1,
                "task_id": task_id,
                "role": role,
                "review_phase": review_phase,
                "attempt": attempt,
                "dispatch_status": "packet_ready",
                "spawn_tool": "multi_agent_v1.spawn_agent",
                "spawn_request": {
                    "agent_type": AGENT_PROFILES[role]["agent_type"],
                    "fork_context": False,
                    "message": prompt,
                },
                "model_profile": AGENT_PROFILES[role]["model_profile"],
                "model_override": None,
                "sandbox": AGENT_PROFILES[role]["sandbox"],
                "source_subplan_path": task.get("source_subplan_path"),
                "source_subplan_sha256": task.get("source_subplan_sha256"),
                "implementation_contract_digest": task.get("implementation_contract_digest"),
                "task_contract_digest": task.get("task_contract_digest"),
                "brief_sha256": brief_sha,
                "prompt_sha256": prompt_sha,
                "run_relative_task_dir": task_id,
                "expected_report_paths": dict(EXPECTED_REPORT_PATHS),
                "prepared_by": actor,
                "prepared_at": utc_now(),
            }
            secure_atomic_write_json_at(
                task_fd,
                "Dispatch-Packet.json",
                packet,
                revalidate=task_revalidate,
            )
            packet_sha = sha256_bytes(
                secure_read_regular_text_at(task_fd, "Dispatch-Packet.json").encode("utf-8")
            )
            if not task_revalidate():
                raise ValueError("apply_run_task_identity_changed")
            event = append_event_at(
                handle,
                {
                    "event_type": "subagent_dispatch_packet_prepared",
                    "task_id": task_id,
                    "role": role,
                    "review_phase": review_phase,
                    "actor": actor,
                    "evidence": evidence or [],
                    "spawn_tool": "multi_agent_v1.spawn_agent",
                    "agent_type": AGENT_PROFILES[role]["agent_type"],
                    "brief_sha256": brief_sha,
                    "prompt_sha256": prompt_sha,
                    "packet_sha256": packet_sha,
                    "attempt": attempt,
                },
            )
            task["dispatch"] = {
                "status": "packet_ready",
                "role": role,
                "review_phase": review_phase,
                "spawn_tool": "multi_agent_v1.spawn_agent",
                "prompt_sha256": prompt_sha,
                "packet_sha256": packet_sha,
                "attempt": attempt,
                "event_sequence": event["sequence"],
            }
            progress["resume_cursor"] = {
                "task_id": task_id,
                "state": state,
                "event_sequence": event["sequence"],
            }
            progress["events"] = [
                {
                    "sequence": event["sequence"],
                    "event_type": "subagent_dispatch_packet_prepared",
                    "task_id": task_id,
                    "role": role,
                }
            ]
            secure_atomic_write_json_at(
                handle.run_fd,
                "Progress.json",
                progress,
                revalidate=task_revalidate,
            )
            packet_path = handle.run_dir / task_id / "Dispatch-Packet.json"
            return {"event": event, "packet_path": packet_path.as_posix(), "packet_sha256": packet_sha}


def record_agent_status(
    run_dir: Path,
    task_id: str,
    role: str,
    agent_id: str,
    status: str,
    actor: str,
    evidence: list[str] | None = None,
    summary: str | None = None,
    review_phase: str | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "role": role,
            "agent_id": agent_id,
            "status": status,
            "actor": actor,
            "summary": summary,
            "evidence": evidence or [],
            "review_phase": review_phase,
        }
    )
    if role not in DISPATCH_ROLES:
        raise ValueError(f"invalid_dispatch_role={role}")
    if status not in DISPATCH_AGENT_STATUSES:
        raise ValueError(f"invalid_agent_status={status}")
    if not safe_agent_id(agent_id):
        raise ValueError(f"invalid_agent_id={agent_id or 'missing'}")
    if not actor.strip():
        raise ValueError("record_agent_actor_required")
    expected_phase = {
        "task_reviewer": {"spec", "quality"},
        "security_reviewer": {"security"},
        "final_reviewer": {"final"},
    }.get(role)
    if expected_phase is None and review_phase is not None:
        raise ValueError(f"record_agent_review_phase_not_applicable={role}")
    if expected_phase is not None and review_phase not in expected_phase:
        raise ValueError(f"record_agent_review_phase_required={role}")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        if run.get("mode") != "subagent_serial":
            raise ValueError(f"record_agent_requires_subagent_serial_mode={run.get('mode')}")
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        dispatch = task.get("dispatch")
        if not isinstance(dispatch, dict):
            raise ValueError(f"subagent_dispatch_packet_missing={task_id}")
        if dispatch.get("role") != role:
            raise ValueError(f"dispatch_role_mismatch={task_id}:{role}")
        if dispatch.get("review_phase") != review_phase:
            raise ValueError(f"dispatch_review_phase_mismatch={task_id}:{review_phase or 'missing'}")
        if status == "spawned":
            if dispatch.get("status") != "packet_ready":
                raise ValueError(f"dispatch_spawn_requires_packet_ready={task_id}")
        else:
            if dispatch.get("status") != "spawned":
                raise ValueError(f"dispatch_result_requires_spawned={task_id}")
            if dispatch.get("agent_id") != agent_id:
                raise ValueError(f"dispatch_agent_id_mismatch={task_id}")
        if status == "completed" and review_phase is not None:
            writer_agent_ids = {
                str(item.get("agent_id"))
                for item in agent_runs(task)
                if isinstance(item, dict)
                and item.get("role") in {"implementer", "fixer"}
                and item.get("status") == "completed"
                and isinstance(item.get("agent_id"), str)
            }
            if agent_id in writer_agent_ids:
                raise ValueError(f"reviewer_agent_must_differ_from_writer={task_id}:{review_phase}")

        attempt = dispatch.get("attempt")
        if not isinstance(attempt, int) or attempt < 1:
            raise ValueError(f"dispatch_attempt_invalid={task_id}")
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            now = utc_now()
            completed_report_name: str | None = None
            completed_report_sha256: str | None = None
            report_normalized_event_sequence: int | None = None
            if status == "completed" and review_phase is not None:
                completed_report_name = f"Review-Report-{review_phase}.json"
                report_bytes = secure_read_regular_bytes_at(task_fd, completed_report_name)
                try:
                    report = json.loads(report_bytes.decode("utf-8"))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    raise ValueError(
                        f"review_report_invalid={task_id}:{review_phase}"
                    ) from exc
                report_verdict = review_report_verdict(review_phase, report)
                if (
                    report_verdict not in {"pass", "fail", "cannot_verify", "needs_fixes"}
                    or report.get("task_id") != task_id
                    or report.get("reviewer_agent_id") != agent_id
                ):
                    raise ValueError(
                        f"review_report_agent_context_mismatch={task_id}:{review_phase}"
                    )
                completed_report_sha256 = sha256_bytes(report_bytes)
                normalized_events = [
                    event
                    for event in receipt_events_by_sequence(handle).values()
                    if event.get("event_type") == "review_report_normalized"
                    and event.get("task_id") == task_id
                    and event.get("review_phase") == review_phase
                    and event.get("role") == role
                    and event.get("agent_id") == agent_id
                    and event.get("attempt") == attempt
                    and event.get("report_path") == completed_report_name
                    and event.get("report_sha256") == completed_report_sha256
                ]
                if len(normalized_events) != 1:
                    raise ValueError(
                        f"review_report_controller_normalization_missing={task_id}:{review_phase}"
                    )
                report_normalized_event_sequence = int(normalized_events[0]["sequence"])
                spawn_sequence = dispatch.get("event_sequence")
                if not isinstance(spawn_sequence, int) or report_normalized_event_sequence <= spawn_sequence:
                    raise ValueError(
                        f"review_report_normalization_order_invalid={task_id}:{review_phase}"
                    )
            previous_runs = [
                item
                for item in agent_runs(task)
                if isinstance(item, dict)
                and item.get("role") == role
                and item.get("review_phase") == review_phase
                and item.get("attempt") == attempt
            ]
            record = {
                "task_id": task_id,
                "role": role,
                "review_phase": review_phase,
                "attempt": attempt,
                "agent_id": agent_id,
                "identity_assurance": "controller_asserted",
                "status": status,
                "packet_sha256": dispatch.get("packet_sha256"),
                "prompt_sha256": dispatch.get("prompt_sha256"),
                "spawn_tool": dispatch.get("spawn_tool"),
                "summary": summary or "",
            }
            if completed_report_name is not None and completed_report_sha256 is not None:
                record["report_path"] = completed_report_name
                record["report_sha256"] = completed_report_sha256
                record["report_normalized_event_sequence"] = report_normalized_event_sequence
            if status == "spawned":
                record["spawned_at"] = now
            else:
                if previous_runs and previous_runs[0].get("spawned_at"):
                    record["spawned_at"] = previous_runs[0]["spawned_at"]
                record[f"{status}_at"] = now
            upsert_agent_run(task, record)
            secure_atomic_write_json_at(
                task_fd,
                agent_run_artifact_name(role, review_phase, attempt),
                record,
                revalidate=task_revalidate,
            )

            dispatch["status"] = status
            dispatch["agent_id"] = agent_id
            dispatch["updated_at"] = now
            if summary:
                dispatch["summary"] = summary
            if status == "failed":
                dispatch["failure_recoverable"] = True
            task["dispatch"] = dispatch

            event = append_event_at(
                handle,
                {
                    "event_type": "subagent_dispatch_status_recorded",
                    "task_id": task_id,
                    "role": role,
                    "review_phase": review_phase,
                    "attempt": attempt,
                    "agent_id": agent_id,
                    "status": status,
                    "actor": actor,
                    "evidence": evidence or [],
                    "summary": summary or "",
                    "report_path": completed_report_name,
                    "report_sha256": completed_report_sha256,
                    "report_normalized_event_sequence": report_normalized_event_sequence,
                },
            )
            record["event_sequence"] = event["sequence"]
            if status == "spawned":
                record["spawn_event_sequence"] = event["sequence"]
            else:
                prior_spawn_sequence = previous_runs[0].get("spawn_event_sequence") if previous_runs else None
                record["spawn_event_sequence"] = prior_spawn_sequence
                record[f"{status}_event_sequence"] = event["sequence"]
            upsert_agent_run(task, record)
            secure_atomic_write_json_at(
                task_fd,
                agent_run_artifact_name(role, review_phase, attempt),
                record,
                revalidate=task_revalidate,
            )
            progress["resume_cursor"] = {
                "task_id": task_id,
                "state": task.get("state"),
                "event_sequence": event["sequence"],
            }
            progress["events"] = [
                {
                    "sequence": event["sequence"],
                    "event_type": "subagent_dispatch_status_recorded",
                    "task_id": task_id,
                    "role": role,
                    "review_phase": review_phase,
                    "status": status,
                }
            ]
            secure_atomic_write_json_at(
                handle.run_fd,
                "Progress.json",
                progress,
                revalidate=task_revalidate,
            )
            return event


def normalize_writer_report(
    run_dir: Path,
    task_id: str,
    role: str,
    agent_id: str,
    report_payload: object,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    """Persist a writer's structured return only through controller-owned I/O."""

    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "role": role,
            "agent_id": agent_id,
            "report": report_payload,
            "actor": actor,
            "evidence": evidence or [],
        }
    )
    if role not in {"implementer", "fixer"}:
        raise ValueError(f"invalid_writer_report_role={role}")
    if not safe_agent_id(agent_id):
        raise ValueError(f"invalid_agent_id={agent_id or 'missing'}")
    if not actor.strip():
        raise ValueError("writer_report_normalizer_actor_required")
    if not isinstance(report_payload, dict):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    agent_field = "implementer_agent_id" if role == "implementer" else "fixer_agent_id"
    report_name = "Implementer-Report.json" if role == "implementer" else "Fix-Report.json"
    payload = json.loads(
        serialize_safe_persistent_json(
            report_payload,
            indent=None,
            separators=(",", ":"),
            trailing_newline=False,
        )
    )
    allowed_fields = (
        IMPLEMENTER_REPORT_ALLOWED_FIELDS if role == "implementer" else FIXER_REPORT_ALLOWED_FIELDS
    )
    if set(payload) - allowed_fields:
        raise ValueError(f"writer_report_unknown_field={task_id}:{role}")
    status = payload.get("status")
    if (
        payload.get("task_id") != task_id
        or payload.get(agent_field) != agent_id
        or status not in IMPLEMENTER_STATUSES
    ):
        raise ValueError(f"writer_report_agent_context_mismatch={task_id}:{role}")
    for field in ("brief_sha256", "task_contract_digest", "change_set_id", "diff_sha256"):
        if field in payload and not is_sha256(payload.get(field)):
            raise ValueError(f"writer_report_invalid={task_id}:{role}")
    if (
        "implementation_contract_digest" in payload
        and payload.get("implementation_contract_digest") is not None
        and not is_sha256(payload.get("implementation_contract_digest"))
    ):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    receipt_ids = payload.get("validation_receipt_ids")
    if receipt_ids is not None and (
        not isinstance(receipt_ids, list)
        or any(not is_sha256(item) for item in receipt_ids)
        or len(receipt_ids) != len(set(receipt_ids))
    ):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    for field in ("controller_decision", "blocker"):
        if field in payload and not isinstance(payload.get(field), str):
            raise ValueError(f"writer_report_invalid={task_id}:{role}")
    evidence_items = payload.get("evidence")
    if evidence_items is not None and (
        not isinstance(evidence_items, list)
        or any(not isinstance(item, str) for item in evidence_items)
    ):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    concerns = payload.get("concerns")
    if concerns is not None and (
        not isinstance(concerns, list)
        or any(not isinstance(item, str) or not item.strip() for item in concerns)
    ):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    if status == "DONE_WITH_CONCERNS" and (
        not isinstance(payload.get("controller_decision"), str)
        or not str(payload.get("controller_decision")).strip()
    ):
        raise ValueError(f"writer_report_invalid={task_id}:{role}")
    if role == "implementer":
        files_changed = payload.get("files_changed")
        present_evidence_fields = IMPLEMENTER_EVIDENCE_FIELDS.intersection(payload)
        if (
            not isinstance(files_changed, list)
            or any(not isinstance(item, str) or not item.strip() for item in files_changed)
            or any(normalize_reported_repo_path(item) != item for item in files_changed)
            or len(files_changed) != len(set(files_changed))
            or "concerns" not in payload
            or not isinstance(concerns, list)
            or (
                present_evidence_fields
                and present_evidence_fields != IMPLEMENTER_EVIDENCE_FIELDS
            )
            or (
                present_evidence_fields == IMPLEMENTER_EVIDENCE_FIELDS
                and (
                    status != "DONE"
                    or not files_changed
                    or not isinstance(receipt_ids, list)
                    or not receipt_ids
                )
            )
        ):
            raise ValueError(f"writer_report_invalid={task_id}:{role}")
    else:
        fixes = payload.get("fixes")
        if not isinstance(fixes, list) or any(not isinstance(item, dict) for item in fixes):
            raise ValueError(f"writer_report_invalid={task_id}:{role}")

    with open_verified_apply_run_for_mutation(run_dir) as handle:
        if handle.run.get("mode") != "subagent_serial":
            raise ValueError(f"writer_report_requires_subagent_serial_mode={handle.run.get('mode')}")
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        dispatch = task.get("dispatch")
        if (
            not isinstance(dispatch, dict)
            or dispatch.get("role") != role
            or dispatch.get("review_phase") is not None
            or dispatch.get("status") not in {"spawned", "completed"}
            or dispatch.get("agent_id") != agent_id
        ):
            raise ValueError(f"writer_report_dispatch_context_mismatch={task_id}:{role}")
        attempt = dispatch.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError(f"dispatch_attempt_invalid={task_id}")
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            secure_atomic_write_json_at(
                task_fd,
                report_name,
                payload,
                revalidate=task_revalidate,
            )
            report_bytes = secure_read_regular_bytes_at(task_fd, report_name)
        report_sha = sha256_bytes(report_bytes)
        event = append_event_at(
            handle,
            {
                "event_type": "writer_report_normalized",
                "task_id": task_id,
                "role": role,
                "agent_id": agent_id,
                "attempt": attempt,
                "actor": actor,
                "evidence": evidence or [],
                "report_path": report_name,
                "report_sha256": report_sha,
                "controller_supplied_report_payload_sha256": canonical_json_digest(payload),
                "host_completion_proof": NOT_OBSERVED,
            },
        )
        bindings = task.get("writer_report_bindings")
        if not isinstance(bindings, dict):
            bindings = {}
        bindings[role] = {
            "agent_id": agent_id,
            "attempt": attempt,
            "path": report_name,
            "sha256": report_sha,
            "payload_sha256": canonical_json_digest(payload),
            "normalized_event_sequence": event["sequence"],
        }
        task["writer_report_bindings"] = bindings
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": event["sequence"],
        }
        progress["events"] = [
            {
                "sequence": event["sequence"],
                "event_type": "writer_report_normalized",
                "task_id": task_id,
                "role": role,
            }
        ]
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        return {
            "event": event,
            "report_path": (handle.run_dir / task_id / report_name).as_posix(),
            "report_sha256": report_sha,
        }


def normalize_review_report(
    run_dir: Path,
    task_id: str,
    phase: str,
    agent_id: str,
    report_payload: object,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    """Persist a read-only reviewer's structured return under controller control.

    This records controller observation only. It deliberately does not claim a
    host-issued completion or identity attestation.
    """

    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "phase": phase,
            "agent_id": agent_id,
            "report": report_payload,
            "actor": actor,
            "evidence": evidence or [],
        }
    )
    if phase not in REVIEW_PHASES:
        raise ValueError(f"invalid_review_phase={phase}")
    if not safe_agent_id(agent_id):
        raise ValueError(f"invalid_agent_id={agent_id or 'missing'}")
    if not actor.strip():
        raise ValueError("review_report_normalizer_actor_required")
    if not isinstance(report_payload, dict):
        raise ValueError(f"review_report_invalid={task_id}:{phase}")
    role = review_phase_expected_role(phase)
    allowed_verdicts = {
        "spec": {"pass", "fail", "cannot_verify"},
        "quality": {"pass", "fail", "needs_fixes", "cannot_verify"},
        "security": {"pass", "fail", "needs_fixes", "cannot_verify"},
        "final": {"pass", "fail", "needs_fixes", "cannot_verify"},
    }[phase]
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        if handle.run.get("mode") != "subagent_serial":
            raise ValueError(f"review_report_requires_subagent_serial_mode={handle.run.get('mode')}")
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        invariant_errors = trusted_task_transition_errors(
            handle,
            progress,
            task,
            verified_candidate=False,
        )
        if invariant_errors:
            raise ValueError(";".join(invariant_errors))
        dispatch = task.get("dispatch")
        if not isinstance(dispatch, dict):
            raise ValueError(f"subagent_dispatch_packet_missing={task_id}")
        if (
            dispatch.get("role") != role
            or dispatch.get("review_phase") != phase
            or dispatch.get("status") != "spawned"
            or dispatch.get("agent_id") != agent_id
        ):
            raise ValueError(f"review_report_dispatch_context_mismatch={task_id}:{phase}")
        attempt = dispatch.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
            raise ValueError(f"dispatch_attempt_invalid={task_id}")
        if any(
            event.get("event_type") == "review_report_normalized"
            and event.get("task_id") == task_id
            and event.get("review_phase") == phase
            and event.get("attempt") == attempt
            for event in receipt_events_by_sequence(handle).values()
        ):
            raise ValueError(f"review_report_already_normalized={task_id}:{phase}:{attempt}")
        payload = json.loads(json.dumps(report_payload, sort_keys=True))
        verdict = review_report_verdict(phase, payload)
        report_evidence = payload.get("evidence")
        if (
            verdict not in allowed_verdicts
            or payload.get("task_id") != task_id
            or payload.get("reviewer_agent_id") != agent_id
            or not isinstance(report_evidence, list)
            or not report_evidence
            or any(not isinstance(item, str) or not item.strip() for item in report_evidence)
        ):
            raise ValueError(f"review_report_agent_context_mismatch={task_id}:{phase}")
        report_name = f"Review-Report-{phase}.json"
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            secure_atomic_write_json_at(
                task_fd,
                report_name,
                payload,
                revalidate=task_revalidate,
            )
            report_bytes = secure_read_regular_bytes_at(task_fd, report_name)
        report_sha = sha256_bytes(report_bytes)
        event = append_event_at(
            handle,
            {
                "event_type": "review_report_normalized",
                "task_id": task_id,
                "review_phase": phase,
                "role": role,
                "agent_id": agent_id,
                "attempt": attempt,
                "actor": actor,
                "evidence": evidence or [],
                "report_path": report_name,
                "report_sha256": report_sha,
                "controller_supplied_report_payload_sha256": canonical_json_digest(payload),
                "host_completion_proof": NOT_OBSERVED,
            },
        )
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": event["sequence"],
        }
        progress["events"] = [
            {
                "sequence": event["sequence"],
                "event_type": "review_report_normalized",
                "task_id": task_id,
                "review_phase": phase,
            }
        ]
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        return {
            "event": event,
            "report_path": (handle.run_dir / task_id / report_name).as_posix(),
            "report_sha256": report_sha,
        }


CHANGE_SET_KIND = "codexqb_controller_change_set"
CHANGE_SET_VERSION = 1
CHANGE_SET_MAC_DOMAIN = b"codexqb.change-set.v1\0"


def change_set_unsigned(payload: dict[str, object]) -> dict[str, object]:
    return {key: value for key, value in payload.items() if key != "change_set_mac"}


def sign_change_set(payload: dict[str, object], master_key: bytes) -> dict[str, object]:
    unsigned = change_set_unsigned(payload)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return {
        **unsigned,
        "change_set_mac": hmac.new(master_key, CHANGE_SET_MAC_DOMAIN + encoded, hashlib.sha256).hexdigest(),
    }


def verify_change_set(payload: object, master_key: bytes) -> bool:
    if not isinstance(payload, dict):
        return False
    claimed = payload.get("change_set_mac")
    if not is_sha256(claimed):
        return False
    unsigned = change_set_unsigned(payload)
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(master_key, CHANGE_SET_MAC_DOMAIN + encoded, hashlib.sha256).hexdigest()
    return hmac.compare_digest(str(claimed), expected)


def baseline_content_map(baseline: dict[str, object]) -> dict[str, bytes]:
    snapshot = baseline.get("snapshot")
    contents = baseline.get("contents")
    if not isinstance(snapshot, list) or not isinstance(contents, list):
        raise ValueError("repository_baseline_invalid")
    expected_present = {
        str(item.get("path")): (item.get("sha256"), item.get("size"))
        for item in snapshot
        if isinstance(item, dict) and item.get("state") == "present"
    }
    decoded: dict[str, bytes] = {}
    for item in contents:
        if not isinstance(item, dict):
            raise ValueError("repository_baseline_content_invalid")
        path = str(item.get("path", ""))
        if path in decoded or path not in expected_present or not isinstance(item.get("content_base64"), str):
            raise ValueError("repository_baseline_content_invalid")
        try:
            content = base64.b64decode(item["content_base64"], validate=True)
        except (ValueError, TypeError) as exc:
            raise ValueError("repository_baseline_content_invalid") from exc
        try:
            assert_safe_embedded_content_bytes(content)
        except ValueError as exc:
            raise ValueError("repository_baseline_secret_rejected") from exc
        expected_sha, expected_size = expected_present[path]
        if sha256_bytes(content) != expected_sha or len(content) != expected_size:
            raise ValueError("repository_baseline_content_invalid")
        decoded[path] = content
    if set(decoded) != set(expected_present):
        raise ValueError("repository_baseline_content_missing")
    return decoded


def changed_files_for_receipt(manifest: object) -> list[dict[str, object]]:
    if not isinstance(manifest, list):
        raise ValueError("repository_change_manifest_invalid")
    state_map = {"add": "added", "modify": "modified", "delete": "deleted"}
    changed: list[dict[str, object]] = []
    for item in manifest:
        if not isinstance(item, dict) or item.get("state") == "unchanged":
            continue
        state = str(item.get("state", ""))
        if state not in state_map:
            raise ValueError("repository_change_manifest_invalid")
        changed.append(
            {
                "path": str(item.get("path", "")),
                "change": state_map[state],
                "before_sha256": item.get("before_sha256"),
                "after_sha256": item.get("after_sha256"),
            }
        )
    return sorted(changed, key=lambda item: str(item["path"]))


def controller_patch_for_manifest(
    root: Path,
    baseline: dict[str, object],
    manifest: object,
) -> str:
    if not isinstance(manifest, list):
        raise ValueError("repository_change_manifest_invalid")
    before_contents = baseline_content_map(baseline)
    sections: list[str] = []
    for item in manifest:
        if not isinstance(item, dict) or item.get("state") == "unchanged":
            continue
        path = normalize_repo_relative_path(item.get("path"))
        state = str(item.get("state", ""))
        before = before_contents.get(path, b"")
        after = read_repository_file_no_follow(root, path)
        if state == "add":
            if before or after is None:
                raise ValueError(f"repository_change_manifest_mismatch={path}")
            before = b""
        elif state == "modify":
            if path not in before_contents or after is None:
                raise ValueError(f"repository_change_manifest_mismatch={path}")
        elif state == "delete":
            if path not in before_contents or after is not None:
                raise ValueError(f"repository_change_manifest_mismatch={path}")
            after = b""
        else:
            raise ValueError("repository_change_manifest_invalid")
        after_bytes = after if isinstance(after, bytes) else b""
        if sha256_bytes(before) != item.get("before_sha256") and state != "add":
            raise ValueError(f"repository_baseline_hash_mismatch={path}")
        if state != "delete" and sha256_bytes(after_bytes) != item.get("after_sha256"):
            raise ValueError(f"repository_current_hash_mismatch={path}")
        sections.append(f"diff --git a/{path} b/{path}\n")
        if b"\x00" in before or b"\x00" in after_bytes:
            sections.append(f"Binary files a/{path} and b/{path} differ\n")
            continue
        try:
            before_text = before.decode("utf-8")
            after_text = after_bytes.decode("utf-8")
        except UnicodeDecodeError:
            sections.append(f"Binary files a/{path} and b/{path} differ\n")
            continue
        from_file = "/dev/null" if state == "add" else f"a/{path}"
        to_file = "/dev/null" if state == "delete" else f"b/{path}"
        diff = difflib.unified_diff(
            before_text.splitlines(keepends=True),
            after_text.splitlines(keepends=True),
            fromfile=from_file,
            tofile=to_file,
            lineterm="\n",
        )
        rendered = "".join(diff)
        if rendered and not rendered.endswith("\n"):
            rendered += "\n"
        sections.append(rendered)
    patch = "".join(sections)
    if not patch.strip():
        raise ValueError("change_set_requires_live_repository_change")
    return patch


def repository_receipt_snapshot(
    root: Path,
    run: dict[str, object],
    repository_evidence: dict[str, object],
    review_package_sha256: str,
    captured_at: str,
) -> dict[str, object]:
    current = workspace_baseline(root)
    vcs = str(current.get("vcs", "non_git"))
    head = str(current.get("base_commit", "unknown")) if vcs == "git" else "not_applicable"
    base = str(run.get("workspace_baseline", {}).get("base_commit", "")) if isinstance(
        run.get("workspace_baseline"), dict
    ) else ""
    if vcs != "git":
        base = "not_applicable"
    changed = changed_files_for_receipt(repository_evidence.get("manifest"))
    return {
        "captured_at": captured_at,
        "vcs": vcs,
        "head_commit": head,
        "base_commit": base,
        "git_status_porcelain_sha256": current["git_status_porcelain_sha256"],
        "staged_diff_sha256": current["staged_diff_sha256"],
        "unstaged_diff_sha256": current["unstaged_diff_sha256"],
        "untracked_inventory_sha256": current["untracked_inventory_sha256"],
        "review_package_sha256": review_package_sha256,
        "changed_files": changed,
        "changed_files_sha256": receipt_json_digest(changed),
    }


def capture_task_change_set(
    run_dir: Path,
    task_id: str,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "actor": actor, "evidence": evidence or []}
    )
    if not actor.strip():
        raise ValueError("change_set_actor_required")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        if task.get("state") not in {"IMPLEMENTED", "TASK_REVIEW", "SECURITY_REVIEW", "RE_REVIEW"}:
            raise ValueError(f"change_set_requires_implemented_state={task_id}:{task.get('state')}")
        baseline = repository_baseline_for_task(run, task_id)
        if baseline is None or baseline.get("implementation_contract_digest") != task.get(
            "implementation_contract_digest"
        ):
            raise ValueError(f"repository_baseline_missing={task_id}")
        paths = sorted(implementation_contract_paths(task))
        if baseline.get("allowed_paths") != paths:
            raise ValueError(f"repository_baseline_path_mismatch={task_id}")
        generation_value = task.get("implementation_generation", 0)
        if not isinstance(generation_value, int) or isinstance(generation_value, bool) or generation_value < 0:
            raise ValueError(f"implementation_generation_invalid={task_id}")
        generation = generation_value + 1
        if generation > 99:
            raise ValueError(f"implementation_generation_exhausted={task_id}")
        preliminary = capture_repository_evidence(
            handle.root,
            paths,
            baseline.get("snapshot", []),
            apply_run_id=str(run["apply_run_id"]),
            task_id=task_id,
            apply_run_registration_id=str(run["apply_run_registration_id"]),
            contract_digest=str(task["implementation_contract_digest"]),
            generation=generation,
            review_package_sha256=sha256_bytes(b""),
        )
        patch = controller_patch_for_manifest(handle.root, baseline, preliminary.get("manifest"))
        patch_sha = sha256_bytes(patch.encode("utf-8"))
        repository_evidence = capture_repository_evidence(
            handle.root,
            paths,
            baseline.get("snapshot", []),
            apply_run_id=str(run["apply_run_id"]),
            task_id=task_id,
            apply_run_registration_id=str(run["apply_run_registration_id"]),
            contract_digest=str(task["implementation_contract_digest"]),
            generation=generation,
            review_package_sha256=patch_sha,
        )
        if preliminary.get("current_snapshot_digest") != repository_evidence.get("current_snapshot_digest"):
            raise ValueError(f"repository_changed_during_change_set_capture={task_id}")
        captured_at = utc_now()
        master_key = load_or_create_apply_run_trust_key(create=False)
        payload = sign_change_set(
            {
                "change_set_kind": CHANGE_SET_KIND,
                "change_set_version": CHANGE_SET_VERSION,
                "change_set_id": secrets.token_hex(32),
                "trust_key_id": receipt_trust_key_id(master_key),
                "captured_at": captured_at,
                "apply_run_id": run["apply_run_id"],
                "apply_run_registration_id": run["apply_run_registration_id"],
                "task_id": task_id,
                "implementation_contract_digest": task["implementation_contract_digest"],
                "task_contract_digest": task["task_contract_digest"],
                "implementation_generation": generation,
                "review_package_sha256": patch_sha,
                "baseline_digest": repository_evidence["baseline_digest"],
                "current_snapshot_digest": repository_evidence["current_snapshot_digest"],
                "changed_files": changed_files_for_receipt(repository_evidence["manifest"]),
                "changed_files_digest": repository_evidence["changed_files_digest"],
                "repository_state_digest": repository_evidence["repository_state_digest"],
                "manifest": repository_evidence["manifest"],
            },
            master_key,
        )
        file_name = f"Change-Set-{generation:02d}.json"
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            secure_atomic_write_text_at(
                task_fd,
                "Review-Package.patch",
                patch,
                revalidate=task_revalidate,
            )
            write_regular_json_exclusive_at(task_fd, file_name, payload)
            os.fsync(task_fd)
        event = append_event_at(
            handle,
            {
                "event_type": "controller_change_set_captured",
                "task_id": task_id,
                "actor": actor,
                "implementation_generation": generation,
                "change_set_id": payload["change_set_id"],
                "repository_state_digest": payload["repository_state_digest"],
                "review_package_sha256": patch_sha,
                "evidence": evidence or [],
            },
        )
        task["implementation_generation"] = generation
        task["change_set"] = {
            "change_set_id": payload["change_set_id"],
            "path": file_name,
            "sha256": receipt_json_digest(payload),
            "repository_state_digest": payload["repository_state_digest"],
            "review_package_sha256": patch_sha,
            "event_sequence": event["sequence"],
        }
        task["validation_receipts"] = []
        task["review_receipts"] = {}
        task["evidence_chain_status"] = "in_progress"
        task["verification_assurance"] = "controller_asserted"
        progress["events"] = [
            {
                "sequence": event["sequence"],
                "event_type": "controller_change_set_captured",
                "task_id": task_id,
            }
        ]
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": event["sequence"],
        }
        secure_atomic_write_json_at(handle.run_fd, "Progress.json", progress, revalidate=handle.revalidate)
        return {
            "event": event,
            "change_set_path": (handle.run_dir / task_id / file_name).as_posix(),
            "change_set_id": payload["change_set_id"],
            "repository_state_digest": payload["repository_state_digest"],
        }


def load_current_change_set(
    handle: ApplyMutationHandle,
    task: dict[str, object],
) -> tuple[dict[str, object], dict[str, object]]:
    task_id = str(task.get("task_id", ""))
    reference = task.get("change_set")
    if not isinstance(reference, dict):
        raise ValueError(f"change_set_missing={task_id}")
    file_name = reference.get("path")
    generation = task.get("implementation_generation")
    if not isinstance(generation, int):
        raise ValueError(f"change_set_generation_invalid={task_id}")
    expected_file_name = f"Change-Set-{generation:02d}.json"
    if file_name != expected_file_name:
        raise ValueError(f"change_set_reference_invalid={task_id}")
    with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
        payload = secure_read_regular_json_at(task_fd, str(file_name))
        patch = secure_read_regular_text_at(task_fd, "Review-Package.patch")
    master_key = load_or_create_apply_run_trust_key(create=False)
    if not verify_change_set(payload, master_key):
        raise ValueError(f"change_set_mac_invalid={task_id}")
    if reference.get("sha256") != receipt_json_digest(payload):
        raise ValueError(f"change_set_reference_digest_mismatch={task_id}")
    if (
        payload.get("change_set_kind") != CHANGE_SET_KIND
        or payload.get("change_set_version") != CHANGE_SET_VERSION
        or payload.get("trust_key_id") != receipt_trust_key_id(master_key)
        or payload.get("apply_run_id") != handle.run.get("apply_run_id")
        or payload.get("apply_run_registration_id") != handle.run.get("apply_run_registration_id")
        or payload.get("task_id") != task_id
        or payload.get("implementation_contract_digest") != task.get("implementation_contract_digest")
        or payload.get("task_contract_digest") != task.get("task_contract_digest")
        or payload.get("implementation_generation") != generation
    ):
        raise ValueError(f"change_set_context_mismatch={task_id}")
    patch_sha = sha256_bytes(patch.encode("utf-8"))
    if payload.get("review_package_sha256") != patch_sha or reference.get("review_package_sha256") != patch_sha:
        raise ValueError(f"verified_live_diff_mismatch={task_id}")
    baseline = repository_baseline_for_task(handle.run, task_id)
    if baseline is None:
        raise ValueError(f"repository_baseline_missing={task_id}")
    current = capture_repository_evidence(
        handle.root,
        baseline.get("allowed_paths", []),
        baseline.get("snapshot", []),
        apply_run_id=str(handle.run["apply_run_id"]),
        task_id=task_id,
        apply_run_registration_id=str(handle.run["apply_run_registration_id"]),
        contract_digest=str(task["implementation_contract_digest"]),
        generation=int(generation),
        review_package_sha256=patch_sha,
    )
    current_changed_files = changed_files_for_receipt(current.get("manifest"))
    stored_changed_files = payload.get("changed_files")
    current_changed_paths = {
        str(item.get("path")) for item in current_changed_files if isinstance(item, dict)
    }
    stored_changed_paths = {
        str(item.get("path")) for item in stored_changed_files if isinstance(stored_changed_files, list) and isinstance(item, dict)
    }
    if not current_changed_files or current_changed_paths != stored_changed_paths:
        raise ValueError(f"verified_live_diff_mismatch={task_id}")
    if (
        payload.get("current_snapshot_digest") != current.get("current_snapshot_digest")
        or payload.get("changed_files_digest") != current.get("changed_files_digest")
        or payload.get("repository_state_digest") != current.get("repository_state_digest")
        or payload.get("manifest") != current.get("manifest")
    ):
        raise ValueError(f"verified_repository_state_digest_mismatch={task_id}")
    regenerated_patch = controller_patch_for_manifest(handle.root, baseline, current.get("manifest"))
    if regenerated_patch != patch:
        raise ValueError(f"verified_live_diff_mismatch={task_id}")
    return payload, current


def receipt_run_binding(handle: ApplyMutationHandle) -> dict[str, object]:
    root_metadata = os.fstat(handle.root_fd)
    run = handle.run
    return {
        "root_binding_sha256": sha256_bytes(os.fsencode(handle.root)),
        "root_device": root_metadata.st_dev,
        "root_inode": root_metadata.st_ino,
        "apply_run_registration_id": run["apply_run_registration_id"],
        "apply_run_id": run["apply_run_id"],
        "apply_spec_digest": run["apply_spec_digest"],
        "workspace_mode": run["workspace_mode"],
    }


def receipt_task_binding(task: dict[str, object]) -> dict[str, object]:
    return {
        "task_id": task["task_id"],
        "brief_sha256": task["brief_sha256"],
        "implementation_contract_digest": task["implementation_contract_digest"],
        "task_contract_digest": task["task_contract_digest"],
        "implementation_generation": task.get("implementation_generation", 0),
        "fix_cycle_count": task.get("fix_cycle_count", 0),
    }


def completed_agent_record(
    task: dict[str, object],
    role: str,
    review_phase: str | None = None,
) -> dict[str, object] | None:
    matches = [
        item
        for item in agent_runs(task)
        if isinstance(item, dict)
        and item.get("role") == role
        and item.get("review_phase") == review_phase
        and item.get("status") == "completed"
    ]
    if not matches:
        return None
    return sorted(matches, key=lambda item: int(item.get("attempt", 0)))[-1]


def current_completed_writer_record(
    handle: ApplyMutationHandle,
    task: dict[str, object],
) -> tuple[dict[str, object] | None, str | None]:
    """Return the completed writer responsible for the current evidence generation."""

    task_id = str(task.get("task_id", ""))
    fix_cycle_count = task.get("fix_cycle_count", 0)
    if not isinstance(fix_cycle_count, int) or isinstance(fix_cycle_count, bool) or fix_cycle_count < 0:
        return None, f"fix_cycle_count_invalid={task_id}"
    role = "fixer" if fix_cycle_count > 0 else "implementer"
    record = completed_agent_record(task, role)
    if record is None:
        error = "current_fixer_completion_required" if role == "fixer" else "subagent_dispatch_completion_required"
        return None, f"{error}={task_id}"
    if record.get("identity_assurance") != "controller_asserted":
        return None, f"controller_asserted_writer_identity_required={task_id}:{role}"
    bindings = task.get("writer_report_bindings")
    binding = bindings.get(role) if isinstance(bindings, dict) else None
    expected_report = "Fix-Report.json" if role == "fixer" else "Implementer-Report.json"
    if (
        not isinstance(binding, dict)
        or binding.get("agent_id") != record.get("agent_id")
        or binding.get("attempt") != record.get("attempt")
        or binding.get("path") != expected_report
        or not isinstance(binding.get("normalized_event_sequence"), int)
    ):
        return None, f"writer_report_controller_normalization_required={task_id}:{role}"
    try:
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
            report_bytes = secure_read_regular_bytes_at(task_fd, expected_report)
            report = parse_safe_persistent_json(report_bytes.decode("utf-8"))
        events = receipt_events_by_sequence(handle)
    except (OSError, UnicodeDecodeError, ValueError):
        return None, f"writer_report_controller_normalization_required={task_id}:{role}"
    normalized_sequence = binding.get("normalized_event_sequence")
    normalized_event = events.get(normalized_sequence)
    if (
        not isinstance(report, dict)
        or binding.get("sha256") != sha256_bytes(report_bytes)
        or binding.get("payload_sha256") != canonical_json_digest(report)
        or not isinstance(normalized_event, dict)
        or normalized_event.get("event_type") != "writer_report_normalized"
        or normalized_event.get("task_id") != task_id
        or normalized_event.get("role") != role
        or normalized_event.get("agent_id") != record.get("agent_id")
        or normalized_event.get("attempt") != record.get("attempt")
        or normalized_event.get("report_sha256") != binding.get("sha256")
    ):
        return None, f"writer_report_controller_normalization_required={task_id}:{role}"
    if role == "fixer":
        fixing_sequences = [
            sequence
            for sequence, event in events.items()
            if event.get("event_type") == "task_transition"
            and event.get("task_id") == task_id
            and event.get("to") == "FIXING"
        ]
        completed_sequence = record.get("completed_event_sequence")
        if (
            not fixing_sequences
            or not isinstance(completed_sequence, int)
            or isinstance(completed_sequence, bool)
            or completed_sequence <= max(fixing_sequences)
        ):
            return None, f"current_fixer_completion_required={task_id}"
    return record, None


def agent_record_sha256_at(
    task_fd: int,
    record: dict[str, object],
) -> tuple[str, str]:
    role = str(record.get("role", ""))
    phase = record.get("review_phase")
    phase_value = str(phase) if isinstance(phase, str) else None
    attempt = record.get("attempt")
    if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt < 1:
        raise ValueError("agent_run_attempt_invalid")
    name = agent_run_artifact_name(role, phase_value, attempt)
    encoded = secure_read_regular_bytes_at(task_fd, name)
    try:
        artifact = json.loads(encoded.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("agent_run_artifact_invalid") from exc
    if artifact != record:
        raise ValueError("agent_run_artifact_progress_mismatch")
    return name, sha256_bytes(encoded)


def normalized_command_cwd(root: Path, value: object) -> tuple[str, Path]:
    if value == ".":
        return ".", root
    normalized = normalize_repo_relative_path(value)
    path = lexical_absolute(root / normalized)
    try:
        metadata = os.lstat(path)
    except FileNotFoundError as exc:
        raise ValueError("validation_cwd_missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink() or not is_inside(root, path):
        raise ValueError("validation_cwd_invalid")
    return normalized, path


@dataclass(frozen=True)
class ValidationProcessResult:
    exit_code: int
    stdout: bytes
    stderr: bytes
    timed_out: bool
    output_limit_exceeded: bool
    termination_reason: str
    network_enforcement_proof: str = NOT_OBSERVED
    host_sandbox_proof: str = NOT_OBSERVED


def validation_subprocess_environment(root: Path) -> dict[str, str]:
    """Build a deterministic child environment without parent credentials.

    Validation commands execute repository-controlled code.  They therefore
    receive only executable search paths and a minimal locale/Python policy,
    never arbitrary parent variables such as provider keys, proxies, Git
    overrides, Python import hooks, or pytest options.
    """

    path_entries: list[str] = []
    for raw_entry in os.environ.get("PATH", os.defpath).split(os.pathsep):
        if not raw_entry:
            continue
        entry = Path(raw_entry)
        if not entry.is_absolute():
            continue
        try:
            common = os.path.commonpath((str(root), str(entry)))
        except ValueError:
            common = ""
        if common == str(root):
            continue
        normalized = str(entry)
        if normalized not in path_entries:
            path_entries.append(normalized)
    if not path_entries:
        path_entries = [entry for entry in os.defpath.split(os.pathsep) if entry]

    environment = {
        "PATH": os.pathsep.join(path_entries),
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
    }
    if os.name == "nt":
        for name in ("SystemRoot", "WINDIR", "COMSPEC", "PATHEXT"):
            value = os.environ.get(name)
            if value:
                environment[name] = value
    return environment


def _linux_validation_seccomp_spec() -> tuple[int, list[_SockFilter]]:
    """Return an architecture-bound filter that forbids new process trees.

    Same-process threads remain available through ``clone(CLONE_THREAD)``.
    ``clone3`` reports ENOSYS so libc can fall back to the inspectable clone
    ABI; process-forming clone, fork, and vfork report EPERM.  An unexpected
    syscall ABI is killed rather than being allowed to reinterpret numbers.
    """

    if not sys.platform.startswith("linux") or not hasattr(os, "uname"):
        raise ValueError("secure_validation_process_isolation_not_supported")
    machine = os.uname().machine.lower()
    specs: dict[str, tuple[int, int, int | None, int | None, bool]] = {
        "x86_64": (0xC000003E, 56, 57, 58, True),
        "amd64": (0xC000003E, 56, 57, 58, True),
        "aarch64": (0xC00000B7, 220, None, None, False),
        "arm64": (0xC00000B7, 220, None, None, False),
    }
    spec = specs.get(machine)
    if spec is None:
        raise ValueError("secure_validation_process_isolation_not_supported")
    audit_arch, clone_nr, fork_nr, vfork_nr, reject_x32 = spec

    # Classic BPF opcodes used by seccomp.
    load_word_absolute = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_constant = 0x06
    seccomp_kill_process = 0x80000000
    seccomp_errno = 0x00050000
    seccomp_allow = 0x7FFF0000
    clone3_nr = 435

    instructions: list[_SockFilter] = [
        _SockFilter(load_word_absolute, 0, 0, 4),
        _SockFilter(jump_equal, 1, 0, audit_arch),
        _SockFilter(return_constant, 0, 0, seccomp_kill_process),
        _SockFilter(load_word_absolute, 0, 0, 0),
    ]
    if reject_x32:
        # x32 shares AUDIT_ARCH_X86_64 but sets bit 30 on syscall numbers.
        instructions.extend(
            [
                _SockFilter(jump_bits_set, 0, 1, 0x40000000),
                _SockFilter(return_constant, 0, 0, seccomp_kill_process),
            ]
        )
    instructions.extend(
        [
            _SockFilter(jump_equal, 0, 1, clone3_nr),
            _SockFilter(return_constant, 0, 0, seccomp_errno | errno.ENOSYS),
        ]
    )

    direct_process_checks: list[int] = [
        syscall_nr for syscall_nr in (fork_nr, vfork_nr) if syscall_nr is not None
    ]
    # Each direct-process match jumps to the EPERM return immediately before
    # the final ALLOW instruction.  Offsets are relative to the next opcode.
    direct_start = len(instructions)
    clone_check_index = direct_start + len(direct_process_checks)
    deny_index = clone_check_index + 3
    allow_index = deny_index + 1
    for offset, syscall_nr in enumerate(direct_process_checks):
        index = direct_start + offset
        instructions.append(
            _SockFilter(jump_equal, deny_index - index - 1, 0, syscall_nr)
        )
    instructions.extend(
        [
            _SockFilter(jump_equal, 0, allow_index - clone_check_index - 1, clone_nr),
            _SockFilter(load_word_absolute, 0, 0, 16),
            _SockFilter(jump_bits_set, 1, 0, LINUX_CLONE_THREAD),
            _SockFilter(return_constant, 0, 0, seccomp_errno | errno.EPERM),
            _SockFilter(return_constant, 0, 0, seccomp_allow),
        ]
    )
    return audit_arch, instructions


def _js_validation_seccomp_spec() -> tuple[int, list[_SockFilter]]:
    """Return an architecture-bound filter that permits spawning but denies egress.

    The JavaScript validation profile inverts the pytest model: ``fork``,
    ``vfork``, ``clone`` and ``clone3`` are all allowed (node's runtime and real
    child processes such as git/bash/python3 must spawn).  Network egress is
    denied at the *syscall* level with ``EACCES`` (never KILL — libuv must see
    the errno and fall back to its threadpool):

    * ``socket(domain, ...)`` is denied whenever ``domain`` is ``AF_UNIX`` (1),
      ``AF_INET`` (2) or ``AF_INET6`` (10).  Denying ``AF_UNIX`` closes the
      "connect to a local resolver / proxy / docker.sock to exfiltrate" path;
      ``socketpair()`` is a *separate* syscall (allowed by the terminal ALLOW),
      so fork/thread IPC is unaffected.  ``AF_NETLINK`` (16) stays allowed
      (kernel-local; some libc resolvers enumerate interfaces).
    * ``io_uring_setup`` (425), ``io_uring_enter`` (426) and
      ``io_uring_register`` (427) are denied so a target cannot drive
      ``IORING_OP_SOCKET``/``CONNECT``/``SEND`` to reach the network with zero
      ``socket()`` calls (same numbers on x86_64 and aarch64).

    The filter is inherited across ``fork``/``exec`` (installed with
    ``NO_NEW_PRIVS``), so every descendant is equally unable to open an egress
    socket or an io_uring ring.  An unexpected ABI is killed, not reinterpreted.
    """

    if not sys.platform.startswith("linux") or not hasattr(os, "uname"):
        raise ValueError("secure_js_validation_isolation_not_supported")
    machine = os.uname().machine.lower()
    specs: dict[str, tuple[int, int, bool]] = {
        "x86_64": (0xC000003E, 41, True),
        "amd64": (0xC000003E, 41, True),
        "aarch64": (0xC00000B7, 198, False),
        "arm64": (0xC00000B7, 198, False),
    }
    spec = specs.get(machine)
    if spec is None:
        raise ValueError("secure_js_validation_isolation_not_supported")
    audit_arch, socket_nr, reject_x32 = spec

    load_word_absolute = 0x20
    jump_equal = 0x15
    jump_bits_set = 0x45
    return_constant = 0x06
    seccomp_kill_process = 0x80000000
    seccomp_errno = 0x00050000
    seccomp_allow = 0x7FFF0000
    af_unix = 1
    af_inet = 2
    af_inet6 = 10
    io_uring_setup, io_uring_enter, io_uring_register = 425, 426, 427
    # seccomp_data layout: nr@0, arch@4, args[0] low word @16.
    instructions: list[_SockFilter] = [
        _SockFilter(load_word_absolute, 0, 0, 4),
        _SockFilter(jump_equal, 1, 0, audit_arch),
        _SockFilter(return_constant, 0, 0, seccomp_kill_process),
        _SockFilter(load_word_absolute, 0, 0, 0),
    ]
    if reject_x32:
        # x32 shares AUDIT_ARCH_X86_64 but sets bit 30 on syscall numbers.
        instructions.extend(
            [
                _SockFilter(jump_bits_set, 0, 1, 0x40000000),
                _SockFilter(return_constant, 0, 0, seccomp_kill_process),
            ]
        )
    # Fixed tail layout (indices relative to `base`, the first io_uring check):
    #   +0 JEQ io_uring_setup     -> DENY
    #   +1 JEQ io_uring_enter     -> DENY
    #   +2 JEQ io_uring_register  -> DENY
    #   +3 JEQ socket_nr          -> fall through (domain check); else ALLOW_ns
    #   +4 LD  args[0]
    #   +5 JEQ AF_UNIX            -> DENY
    #   +6 JEQ AF_INET           -> DENY
    #   +7 JEQ AF_INET6          -> DENY
    #   +8 RET ALLOW              (socket, non-egress domain e.g. AF_NETLINK)
    #   +9 RET EACCES             (DENY: io_uring or egress socket)
    #  +10 RET ALLOW              (ALLOW_ns: every other syscall)
    base = len(instructions)
    deny_index = base + 9
    allow_ns_index = base + 10
    instructions.extend(
        [
            _SockFilter(jump_equal, deny_index - (base + 0) - 1, 0, io_uring_setup),
            _SockFilter(jump_equal, deny_index - (base + 1) - 1, 0, io_uring_enter),
            _SockFilter(jump_equal, deny_index - (base + 2) - 1, 0, io_uring_register),
            _SockFilter(jump_equal, 0, allow_ns_index - (base + 3) - 1, socket_nr),
            _SockFilter(load_word_absolute, 0, 0, 16),
            _SockFilter(jump_equal, deny_index - (base + 5) - 1, 0, af_unix),
            _SockFilter(jump_equal, deny_index - (base + 6) - 1, 0, af_inet),
            _SockFilter(jump_equal, deny_index - (base + 7) - 1, 0, af_inet6),
            _SockFilter(return_constant, 0, 0, seccomp_allow),  # AF_NETLINK / other
            _SockFilter(return_constant, 0, 0, seccomp_errno | errno.EACCES),  # DENY
            _SockFilter(return_constant, 0, 0, seccomp_allow),  # every non-socket syscall
        ]
    )
    return audit_arch, instructions


def _macos_js_validation_profile(root: Path) -> str:
    """Build the sandbox-exec seatbelt profile for JavaScript validation.

    Spawning is permitted (``allow default``); all network is denied; and every
    write under the realpath of the repository root is denied (tmpdir writes,
    which live outside the repo, remain allowed).  When ``.git`` is a GITFILE
    (linked worktree/submodule), the EXTERNAL gitdir lives outside the root but
    its ``hooks/``/``config`` execute against this tree — so it is denied too,
    otherwise a target could plant a hook there and escape the sandbox.  Every
    path is escaped for the seatbelt string literal.
    """

    def _escape(value: str) -> str:
        return value.replace("\\", "\\\\").replace('"', '\\"')

    resolved = os.path.realpath(root)
    denies = [f'(deny file-write* (subpath "{_escape(resolved)}"))']
    resolved_prefix = resolved.rstrip(os.sep) + os.sep
    for git_dir in _resolve_git_control_surface_dirs(lexical_absolute(root)):
        git_real = os.path.realpath(git_dir)
        # Only add EXTERNAL gitdirs; an in-tree ``.git`` dir is already covered by
        # the root subpath deny above.
        if git_real == resolved or git_real.startswith(resolved_prefix):
            continue
        denies.append(f'(deny file-write* (subpath "{_escape(git_real)}"))')
    return (
        "(version 1)"
        "(allow default)"
        "(deny network*)"
        + "".join(denies)
    )


def _linux_landlock_abi() -> int:
    """Return the Landlock ABI version (>=1) or 0 when unavailable. Best-effort.

    ``landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION)`` reports
    the ABI without creating a ruleset; -ENOSYS / any error maps to 0.
    """

    try:
        libc = ctypes.CDLL(None, use_errno=True)
        syscall = libc.syscall
        syscall.restype = ctypes.c_long
        landlock_create_ruleset_version = 1
        abi = syscall(
            ctypes.c_long(444),
            None,
            ctypes.c_size_t(0),
            ctypes.c_uint32(landlock_create_ruleset_version),
        )
        return int(abi) if abi and abi > 0 else 0
    except (OSError, AttributeError, ValueError):
        return 0


def _install_linux_validation_landlock_best_effort(root: Path) -> None:
    """Restrict filesystem writes to outside the repository, if Landlock exists.

    This is defense-in-depth only: absence or failure is non-fatal because the
    post-hoc repository-digest compare (which for validation includes the VCS
    control dirs) is the authoritative repo-write control.  Any error silently
    leaves that digest backstop in force.
    """

    try:
        abi = _linux_landlock_abi()
        if abi < 1:
            return
        libc = ctypes.CDLL(None, use_errno=True)
        # Landlock syscalls share these numbers on x86_64 and aarch64.
        nr_create, nr_add_rule, nr_restrict = 444, 445, 446

        class _RulesetAttr(ctypes.Structure):
            _fields_ = [("handled_access_fs", ctypes.c_uint64)]

        class _PathBeneathAttr(ctypes.Structure):
            _fields_ = [
                ("allowed_access", ctypes.c_uint64),
                ("parent_fd", ctypes.c_int32),
            ]

        syscall = libc.syscall
        syscall.restype = ctypes.c_long

        # *Write-shaped* access rights ONLY (never READ_FILE/READ_DIR/EXECUTE):
        # WRITE_FILE(1), REMOVE_DIR(4), REMOVE_FILE(5), MAKE_CHAR(6), MAKE_DIR(7),
        # MAKE_REG(8), MAKE_SOCK(9), MAKE_FIFO(10), MAKE_BLOCK(11), MAKE_SYM(12).
        # Handling only write rights leaves reads/executes unaffected everywhere,
        # so node can still read node_modules.  REFER(13, ABI>=2) closes the
        # cross-directory rename()/link() route into the repo; TRUNCATE(14,
        # ABI>=3) closes truncate()-based modification of repo files.  Both are
        # added only when the running kernel supports them (else the ruleset
        # create would EINVAL and drop us to the digest backstop).
        handled = 0
        for bit in (1, 4, 5, 6, 7, 8, 9, 10, 11, 12):
            handled |= 1 << bit
        if abi >= 2:
            handled |= 1 << 13  # LANDLOCK_ACCESS_FS_REFER
        if abi >= 3:
            handled |= 1 << 14  # LANDLOCK_ACCESS_FS_TRUNCATE
        attr = _RulesetAttr(handled)
        ruleset_fd = syscall(
            ctypes.c_long(nr_create),
            ctypes.byref(attr),
            ctypes.c_size_t(ctypes.sizeof(attr)),
            ctypes.c_uint32(0),
        )
        if ruleset_fd < 0:
            return
        # Landlock rejects (EINVAL) a path_beneath rule on a *file* whose
        # allowed_access includes directory-only rights (MAKE_*/REMOVE_*/REFER),
        # silently dropping the rule.  So grant directories the full handled set
        # but grant device FILES only the file-applicable rights.
        file_access = 1 << 1  # WRITE_FILE
        if abi >= 3:
            file_access |= 1 << 14  # TRUNCATE
        try:
            for writable in _js_validation_landlock_writable_paths():
                path_fd = -1
                try:
                    access = handled if os.path.isdir(writable) else file_access
                    path_fd = os.open(writable, os.O_PATH if hasattr(os, "O_PATH") else os.O_RDONLY)
                    rule = _PathBeneathAttr(access, path_fd)
                    syscall(
                        ctypes.c_long(nr_add_rule),
                        ctypes.c_int(int(ruleset_fd)),
                        ctypes.c_uint32(1),  # LANDLOCK_RULE_PATH_BENEATH
                        ctypes.byref(rule),
                        ctypes.c_uint32(0),
                    )
                except OSError:
                    continue
                finally:
                    if path_fd >= 0:
                        os.close(path_fd)
            pr_set_no_new_privs = 38
            libc.prctl(pr_set_no_new_privs, 1, 0, 0, 0)
            syscall(
                ctypes.c_long(nr_restrict),
                ctypes.c_int(int(ruleset_fd)),
                ctypes.c_uint32(0),
            )
        finally:
            os.close(int(ruleset_fd))
    except (OSError, AttributeError, ValueError):
        return


def _js_validation_landlock_writable_paths() -> list[str]:
    # Only what child processes actually need to WRITE, all OUTSIDE any repo:
    # the OS temporary directories plus a few character devices (git/bash/node
    # open /dev/null and friends for write).  Broad /proc and /dev grants are
    # deliberately dropped.  Reads/executes are never in the handled set, so
    # they remain permitted everywhere regardless of this allowlist.
    candidates = [
        os.environ.get("TMPDIR"),
        "/tmp",
        "/var/tmp",
        "/dev/null",
        "/dev/zero",
        "/dev/full",
        "/dev/tty",
        "/dev/random",
        "/dev/urandom",
    ]
    seen: set[str] = set()
    paths: list[str] = []
    for value in candidates:
        if not value or not os.path.exists(value):
            continue
        real = os.path.realpath(value)
        if real not in seen:
            seen.add(real)
            paths.append(real)
    return paths


def _open_validation_regular_file_fd(cwd_fd: int, relpath: str) -> tuple[int, os.stat_result]:
    """Open ``relpath`` beneath ``cwd_fd`` with no symlink component, as a file.

    Walks each path component with ``O_NOFOLLOW`` directory opens and opens the
    final component ``O_RDONLY|O_NOFOLLOW`` as a regular file, returning the
    held descriptor (CLOEXEC) and its stat metadata for inode-equality binding.
    """

    parts = [part for part in relpath.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        raise ValueError("validation_js_target_invalid")
    intermediate: list[int] = []
    current = cwd_fd
    try:
        for name in parts[:-1]:
            child_fd, _ = open_child_directory(current, name)
            intermediate.append(child_fd)
            current = child_fd
        leaf = parts[-1]
        before = os.stat(leaf, dir_fd=current, follow_symlinks=False)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("validation_js_target_not_regular_file")
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        file_fd = os.open(leaf, flags, dir_fd=current)
        try:
            after = os.fstat(file_fd)
        except OSError:
            os.close(file_fd)
            raise
        if not stat.S_ISREG(after.st_mode) or not same_file_identity(before, after):
            os.close(file_fd)
            raise ValueError("validation_js_target_identity_changed")
        return file_fd, after
    finally:
        for fd in intermediate:
            os.close(fd)


def _install_linux_validation_process_filter(
    expected_audit_arch: int,
    instructions: list[_SockFilter],
    *,
    spec_fn=_linux_validation_seccomp_spec,
) -> None:
    """Install the already architecture-checked seccomp filter in the child."""

    current_arch, expected_instructions = spec_fn()
    if current_arch != expected_audit_arch or [
        (item.code, item.jt, item.jf, item.k) for item in expected_instructions
    ] != [(item.code, item.jt, item.jf, item.k) for item in instructions]:
        raise OSError(errno.ENOTSUP, "validation seccomp binding changed")
    filter_array = (_SockFilter * len(instructions))(*instructions)
    program = _SockFprog(len(instructions), filter_array)
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    prctl.restype = ctypes.c_int
    pr_set_no_new_privs = 38
    pr_set_seccomp = 22
    seccomp_mode_filter = 2
    if prctl(pr_set_no_new_privs, 1, 0, 0, 0) != 0:
        error_number = ctypes.get_errno() or errno.EPERM
        raise OSError(error_number, "could not enable no_new_privs")
    if prctl(
        pr_set_seccomp,
        seccomp_mode_filter,
        ctypes.addressof(program),
        0,
        0,
    ) != 0:
        error_number = ctypes.get_errno() or errno.EPERM
        raise OSError(error_number, "could not install validation seccomp filter")


def _validation_containment_command(
    argv: list[str],
    *,
    js_profile: bool = False,
    root: Path | None = None,
) -> tuple[list[str], tuple[int, list[_SockFilter]] | None, str, str]:
    """Bind validation to a host mechanism that prevents descendant escape.

    Returns ``(contained_argv, linux_seccomp_spec_or_None,
    network_enforcement_proof, host_sandbox_proof)``.  For the JavaScript profile
    (``js_profile``) spawning is permitted while network is kernel-denied; the
    proofs record the real enforcement — ``host_sandbox_proof`` states whether
    repo writes are *preventively* denied (seatbelt on macOS; Landlock on Linux
    when the kernel supports it) or only caught by the post-hoc digest backstop.
    The non-JS profile makes no such claims.
    """

    if sys.platform == "darwin":
        try:
            metadata = os.lstat(MACOS_VALIDATION_SANDBOX)
        except OSError as exc:
            raise ValueError("secure_validation_process_isolation_not_supported") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ValueError("secure_validation_process_isolation_not_supported")
        if js_profile:
            if root is None:
                raise ValueError("secure_js_validation_isolation_not_supported")
            profile = _macos_js_validation_profile(root)
            network_proof = ENFORCED_SEATBELT_DENY_NETWORK
            host_sandbox_proof = ENFORCED_SEATBELT_REPO_WRITE_DENY
        else:
            profile = MACOS_VALIDATION_SANDBOX_PROFILE
            network_proof = NOT_OBSERVED
            host_sandbox_proof = NOT_OBSERVED
        return (
            [str(MACOS_VALIDATION_SANDBOX), "-p", profile, *argv],
            None,
            network_proof,
            host_sandbox_proof,
        )
    if sys.platform.startswith("linux"):
        if js_profile:
            # The JS profile PERMITS spawning, so seccomp alone cannot stop a
            # descendant from writing the tree.  Repo-write PREVENTION therefore
            # relies on Landlock.  Without it, an unconfined target could forge a
            # MAC'd success receipt into ``.codexqb/`` BEFORE the post-hoc digest
            # ever runs, so the digest backstop is not a sufficient substitute —
            # fail closed: do not execute and publish no receipt.
            if _linux_landlock_abi() < 1:
                raise ValueError("secure_js_validation_isolation_not_supported")
            return (
                list(argv),
                _js_validation_seccomp_spec(),
                ENFORCED_SECCOMP_INET_DENY,
                ENFORCED_LANDLOCK_REPO_WRITE_DENY,
            )
        return list(argv), _linux_validation_seccomp_spec(), NOT_OBSERVED, NOT_OBSERVED
    raise ValueError(
        "secure_js_validation_isolation_not_supported"
        if js_profile
        else "secure_validation_process_isolation_not_supported"
    )


def _terminate_validation_process(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass


def _linux_session_member_pids(session_id: int) -> list[int]:
    """PIDs whose session id equals ``session_id`` (Linux ``/proc`` sweep, else [])."""

    if not sys.platform.startswith("linux"):
        return []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return []
    pids: list[int] = []
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(f"/proc/{entry}/stat", "rb") as handle:
                data = handle.read()
        except OSError:
            continue
        # `pid (comm) state ppid pgrp session ...` — comm may contain spaces and
        # parentheses, so parse the fields AFTER the final ')'.
        rparen = data.rfind(b")")
        if rparen == -1:
            continue
        fields = data[rparen + 2 :].split()
        if len(fields) < 4:
            continue
        try:
            if int(fields[3]) == session_id:
                pids.append(int(entry))
        except ValueError:
            continue
    return pids


def _reap_validation_process_tree(
    process: subprocess.Popen[bytes], *, rounds: int = 5, pause: float = 0.05
) -> None:
    """Best-effort SIGKILL of the validation's whole process group/session.

    ``start_new_session=True`` makes the leader a session+group leader, so
    ``killpg(leader)`` reaps children that stayed in that group.  A descendant that
    calls ``setpgid()`` moves to a NEW group in the SAME session; on Linux we
    additionally sweep ``/proc`` by session id to reap those before the caller
    takes its post-run snapshot, so a straggler cannot mutate the tree AFTER the
    snapshot is captured.

    RESIDUAL: a descendant that calls ``setsid()`` starts a brand-new session and,
    once its ancestors exit, becomes an orphan reparented to init with no reliable
    back-link — unavoidable for a spawning profile, and unreachable on macOS
    (no ``/proc``).  Such an orphan still inherited the seccomp filter under
    NO_NEW_PRIVS (INET/AF_UNIX/io_uring denied — it cannot exfiltrate), and any
    repo write it manages before the after-snapshot is caught by the
    content-inclusive control-surface digest, which fails the validation closed.
    """

    if os.name != "posix":
        return
    leader = process.pid
    for _ in range(max(1, rounds)):
        killed_any = False
        try:
            os.killpg(leader, signal.SIGKILL)
            killed_any = True
        except (ProcessLookupError, OSError):
            pass
        for pid in _linux_session_member_pids(leader):
            if pid == leader:
                continue
            try:
                os.kill(pid, signal.SIGKILL)
                killed_any = True
            except (ProcessLookupError, OSError):
                pass
        if not killed_any:
            break
        time.sleep(pause)


def _validation_child_setup(
    cwd_fd: int,
    linux_seccomp: tuple[int, list[_SockFilter]] | None,
    *,
    js_profile: bool = False,
    root: Path | None = None,
) -> None:
    """Enter the anchored cwd and enable process containment before exec."""

    os.fchdir(cwd_fd)
    os.close(cwd_fd)
    if linux_seccomp is not None:
        spec_fn = _js_validation_seccomp_spec if js_profile else _linux_validation_seccomp_spec
        _install_linux_validation_process_filter(*linux_seccomp, spec_fn=spec_fn)
    if js_profile and sys.platform.startswith("linux") and root is not None:
        # Defense-in-depth repo-write denial; the authoritative control remains
        # the post-hoc repository-digest compare, so failure here is non-fatal.
        _install_linux_validation_landlock_best_effort(root)


def _promote_validation_fd(cwd_fd: int) -> int:
    """Keep the cwd anchor out of Popen's stdin/stdout/stderr remap range."""

    if cwd_fd >= 3:
        return cwd_fd
    try:
        import fcntl

        duplicate = fcntl.fcntl(cwd_fd, fcntl.F_DUPFD_CLOEXEC, 3)
    except (ImportError, AttributeError, OSError) as exc:
        raise ValueError("secure_validation_process_isolation_not_supported") from exc
    os.close(cwd_fd)
    return int(duplicate)


def _open_validation_cwd_fd(
    *,
    root: Path,
    cwd: Path,
    root_fd: int | None,
    normalized_cwd: str | None,
) -> int:
    """Open a planned cwd component-by-component below an anchored root."""

    if os.name != "posix" or not hasattr(os, "fchdir"):
        raise ValueError("secure_validation_process_isolation_not_supported")

    lexical_root = lexical_absolute(root)
    lexical_cwd = lexical_absolute(cwd)
    if normalized_cwd is None:
        try:
            relative = lexical_cwd.relative_to(lexical_root)
        except ValueError as exc:
            raise ValueError("validation_cwd_invalid") from exc
        normalized = (
            "."
            if not relative.parts
            else normalize_repo_relative_path(relative.as_posix())
        )
    else:
        normalized = (
            "."
            if normalized_cwd == "."
            else normalize_repo_relative_path(normalized_cwd)
        )
        expected = (
            lexical_root
            if normalized == "."
            else lexical_absolute(lexical_root / normalized)
        )
        if lexical_cwd != expected:
            raise ValueError("validation_cwd_binding_mismatch")

    with open_repository_root_anchor(lexical_root) as repository_anchor:
        opened_root_fd = -1
        current_fd = -1
        try:
            opened_root_fd = os.dup(
                root_fd if root_fd is not None else repository_anchor.fd
            )
            opened_root_fd = _promote_validation_fd(opened_root_fd)
            root_metadata = os.fstat(opened_root_fd)
            if (
                not same_file_identity(root_metadata, repository_anchor.metadata)
                or not opened_directory_matches_path(
                    lexical_root,
                    root_metadata,
                    reject_mount=False,
                )
            ):
                raise ValueError("validation_root_identity_changed")
            try:
                require_same_repository_mount(repository_anchor, opened_root_fd, ".")
            except ValueError as exc:
                raise ValueError("validation_root_mount_identity_changed") from exc
            current_fd = opened_root_fd
            opened_root_fd = -1
            if normalized != ".":
                relative_parts: list[str] = []
                for component in normalized.split("/"):
                    child_fd = -1
                    relative_parts.append(component)
                    relative_path = "/".join(relative_parts)
                    try:
                        child_fd, child_metadata = open_child_directory(
                            current_fd,
                            component,
                        )
                        if child_metadata.st_dev != repository_anchor.metadata.st_dev:
                            raise ValueError("validation_cwd_cross_device")
                        require_same_repository_mount(
                            repository_anchor,
                            child_fd,
                            relative_path,
                        )
                    except (OSError, ValueError) as exc:
                        if child_fd >= 0:
                            os.close(child_fd)
                        if "repository_nested_mount_rejected=" in str(exc):
                            raise ValueError(
                                "validation_cwd_nested_mount_rejected"
                            ) from exc
                        raise ValueError("validation_cwd_identity_changed") from exc
                    os.close(current_fd)
                    current_fd = child_fd

            # Re-open the final lexical path and compare it to the descriptor
            # chain.  This catches a same-inode bind mount or replacement that
            # appeared while the component walk was in progress.
            try:
                with open_repository_root_anchor(lexical_cwd) as cwd_anchor:
                    current_metadata = os.fstat(current_fd)
                    if not same_file_identity(current_metadata, cwd_anchor.metadata):
                        raise ValueError("validation_cwd_identity_changed")
                    require_same_repository_mount(
                        repository_anchor,
                        cwd_anchor.fd,
                        normalized,
                    )
                    require_same_repository_mount(
                        repository_anchor,
                        current_fd,
                        normalized,
                    )
            except ValueError as exc:
                if "repository_nested_mount_rejected=" in str(exc):
                    raise ValueError("validation_cwd_nested_mount_rejected") from exc
                if str(exc) == "validation_cwd_identity_changed":
                    raise
                raise ValueError("validation_cwd_identity_changed") from exc

            current_fd = _promote_validation_fd(current_fd)
            result = current_fd
            current_fd = -1
            return result
        finally:
            if current_fd >= 0:
                os.close(current_fd)
            if opened_root_fd >= 0:
                os.close(opened_root_fd)


def _resolve_validation_node_interpreter(root: Path) -> str:
    """Resolve an absolute ``node`` from the scrubbed PATH, never inside the repo."""

    env_path = validation_subprocess_environment(root).get("PATH", "")
    canonical_root = os.path.realpath(root)
    for entry in env_path.split(os.pathsep):
        if not entry or not os.path.isabs(entry):
            continue
        candidate = os.path.join(entry, NODE_INTERPRETER)
        if not (os.path.isfile(candidate) and os.access(candidate, os.X_OK)):
            continue
        real = os.path.realpath(candidate)
        try:
            if os.path.commonpath([canonical_root, real]) == canonical_root:
                continue
        except ValueError:
            # Containment could not be determined -> fail closed on this
            # candidate rather than executing a possibly-in-repo interpreter.
            continue
        return candidate
    raise ValueError("validation_js_node_interpreter_unavailable")


def _prepare_vitest_execution(
    argv: list[str],
    *,
    cwd_fd: int,
    root: Path,
) -> tuple[list[str], list[int], list[tuple[str, int, int]]]:
    """Resolve node+runner+config+targets by descriptor and build the node argv.

    Every filesystem object (the ``vitest.mjs`` runner, an optional config and
    each target) is opened O_NOFOLLOW as a regular file beneath the pinned cwd
    descriptor; the descriptors are held (CLOEXEC) so their inodes cannot be
    recycled, and ``(st_dev, st_ino)`` is recorded for a pre-launch equality
    recheck.  Returns ``(node_argv, held_fds, inode_bindings)``.
    """

    if len(argv) < 2 or argv[0] != VITEST_LOGICAL_RUNNER or argv[1] != "run":
        raise ValueError("validation_js_command_shape_invalid")
    targets = list(argv[2:])
    node_path = _resolve_validation_node_interpreter(root)
    held: list[int] = []
    bindings: list[tuple[str, int, int]] = []
    config_relpath: str | None = None
    try:
        runner_fd, runner_meta = _open_validation_regular_file_fd(cwd_fd, VITEST_RUNNER_RELPATH)
        held.append(runner_fd)
        bindings.append((VITEST_RUNNER_RELPATH, runner_meta.st_dev, runner_meta.st_ino))
        for candidate in VITEST_CONFIG_CANDIDATES:
            try:
                config_fd, config_meta = _open_validation_regular_file_fd(cwd_fd, candidate)
            except (OSError, ValueError):
                continue
            held.append(config_fd)
            bindings.append((candidate, config_meta.st_dev, config_meta.st_ino))
            config_relpath = candidate
            break
        for target in targets:
            if not isinstance(target, str) or target.startswith("-"):
                raise ValueError("validation_js_target_invalid")
            target_fd, target_meta = _open_validation_regular_file_fd(cwd_fd, target)
            held.append(target_fd)
            bindings.append((target, target_meta.st_dev, target_meta.st_ino))
    except BaseException:
        for fd in held:
            try:
                os.close(fd)
            except OSError:
                pass
        raise
    node_argv = [node_path, VITEST_RUNNER_RELPATH, *VITEST_INJECTED_RUN_FLAGS]
    if config_relpath is not None:
        node_argv += ["--config", config_relpath]
    if targets:
        node_argv += ["--", *targets]
    return node_argv, held, bindings


def _recheck_vitest_inode_bindings(cwd_fd: int, bindings: list[tuple[str, int, int]]) -> None:
    """Re-``fstatat`` each descriptor-verified path and assert the inode is stable."""

    for relpath, dev, ino in bindings:
        parts = [part for part in relpath.split("/") if part not in ("", ".")]
        if not parts:
            raise ValueError("validation_js_inode_binding_changed")
        current = cwd_fd
        intermediate: list[int] = []
        try:
            for name in parts[:-1]:
                child_fd, _ = open_child_directory(current, name)
                intermediate.append(child_fd)
                current = child_fd
            meta = os.stat(parts[-1], dir_fd=current, follow_symlinks=False)
        finally:
            for fd in intermediate:
                os.close(fd)
        if meta.st_dev != dev or meta.st_ino != ino or not stat.S_ISREG(meta.st_mode):
            raise ValueError("validation_js_inode_binding_changed")


def run_bounded_validation_process(
    argv: list[str],
    *,
    cwd: Path,
    root: Path,
    timeout_seconds: int,
    root_fd: int | None = None,
    normalized_cwd: str | None = None,
) -> ValidationProcessResult:
    """Run one validation from an anchored cwd with bounded output/processes."""

    if os.name != "posix" or threading.active_count() != 1:
        raise ValueError("secure_validation_process_isolation_not_supported")
    is_js_validation = bool(argv) and argv[0] == VITEST_LOGICAL_RUNNER
    cwd_fd = _open_validation_cwd_fd(
        root=root,
        cwd=cwd,
        root_fd=root_fd,
        normalized_cwd=normalized_cwd,
    )
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    held_validation_fds: list[int] = []
    try:
        if is_js_validation:
            try:
                exec_argv, held_validation_fds, inode_bindings = _prepare_vitest_execution(
                    argv, cwd_fd=cwd_fd, root=root
                )
            except OSError as exc:
                raise ValueError("validation_js_runner_resolution_failed") from exc
        else:
            exec_argv, inode_bindings = argv, []
        contained_argv, linux_seccomp, network_proof, host_sandbox_proof = _validation_containment_command(
            exec_argv, js_profile=is_js_validation, root=root
        )
        try:
            try:
                if is_js_validation:
                    # Immediately before launch, prove the validated inode is the
                    # inode that will execute (no swap during preparation).
                    _recheck_vitest_inode_bindings(cwd_fd, inode_bindings)
                process = subprocess.Popen(
                    contained_argv,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    env=validation_subprocess_environment(root),
                    start_new_session=True,
                    pass_fds=(cwd_fd,),
                    preexec_fn=lambda: _validation_child_setup(
                        cwd_fd, linux_seccomp, js_profile=is_js_validation, root=root
                    ),
                )
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                raise ValueError("validation_command_launch_failed") from exc
        finally:
            parent_cwd_fd = cwd_fd
            cwd_fd = -1
            os.close(parent_cwd_fd)

        # Everything after Popen returns remains inside this cleanup scope so
        # KeyboardInterrupt and setup failures cannot strand a validation.
        if process.stdout is None or process.stderr is None:
            raise ValueError("validation_command_pipe_setup_failed")

        stdout = bytearray()
        stderr = bytearray()
        total = 0
        timed_out = False
        output_limit_exceeded = False
        deadline = time.monotonic() + timeout_seconds
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
                _terminate_validation_process(process)
                break
            events = selector.select(min(0.1, remaining))
            for key, _ in events:
                fd = key.fileobj.fileno()
                try:
                    chunk = os.read(
                        fd,
                        min(VALIDATION_OUTPUT_CHUNK_BYTES, MAX_VALIDATION_OUTPUT_BYTES - total + 1),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                streams[fd].extend(chunk)
                total += len(chunk)
                if total > MAX_VALIDATION_OUTPUT_BYTES:
                    output_limit_exceeded = True
                    _terminate_validation_process(process)
                    break
            if output_limit_exceeded:
                break

        if not timed_out and not output_limit_exceeded:
            remaining = max(0.0, deadline - time.monotonic())
            try:
                process.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                timed_out = True
                _terminate_validation_process(process)
            else:
                # The leader exited; reap its process group.  Unlike the pytest
                # profile, the js_validation profile PERMITS spawning, so node
                # workers and git/bash/python3 children are expected — the group
                # kill (start_new_session=True) collects them.
                _terminate_validation_process(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate_validation_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired as exc:
                raise ValueError("validation_process_termination_failed") from exc

        # M-B: before the caller captures the post-run snapshot, best-effort reap
        # the ENTIRE process group/session (incl. setpgid escapees on Linux) so a
        # still-live descendant cannot mutate the tree AFTER the snapshot; the
        # setsid-orphan residual is documented on the helper.
        _reap_validation_process_tree(process)

        exit_code = int(process.returncode if process.returncode is not None else -1)
        if output_limit_exceeded:
            termination_reason = "output_limit"
        elif timed_out:
            termination_reason = "timeout"
            exit_code = -1
        elif exit_code < 0:
            termination_reason = "signal"
        else:
            termination_reason = "exited"
        return ValidationProcessResult(
            exit_code=exit_code,
            stdout=bytes(stdout[:MAX_VALIDATION_OUTPUT_BYTES]),
            stderr=bytes(stderr[:MAX_VALIDATION_OUTPUT_BYTES]),
            timed_out=timed_out,
            output_limit_exceeded=output_limit_exceeded,
            termination_reason=termination_reason,
            network_enforcement_proof=network_proof,
            host_sandbox_proof=host_sandbox_proof,
        )
    except BaseException:
        if process is not None:
            _terminate_validation_process(process)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _terminate_validation_process(process)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
        raise
    finally:
        if cwd_fd >= 0:
            os.close(cwd_fd)
        # The runner/config/target descriptors are held open in the parent for
        # the whole run so their inodes cannot be recycled; release them now.
        for held_fd in held_validation_fds:
            try:
                os.close(held_fd)
            except OSError:
                pass
        if selector is not None:
            selector.close()
        if process is not None:
            for pipe in (process.stdout, process.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()


VALIDATION_CONTROL_SURFACE_MAX_PATHS = 300_000
VALIDATION_CONTROL_SURFACE_MAX_BYTES = 512 * 1024 * 1024


def _git_worktree_common_dir(gitdir: Path) -> Path | None:
    """Resolve ``<gitdir>/commondir`` (``$GIT_COMMON_DIR``) if present, else ``None``.

    For a linked worktree git records the shared gitdir AUTHORITATIVELY in this
    file — a path that is absolute, or relative to the gitdir — and sources the
    shared ``hooks/``/``config`` from exactly there.  Covering this (rather than a
    structural ``parent.parent`` guess) means the digest and the seatbelt cover
    precisely where git executes hooks, even for a hand-crafted checkout whose
    ``commondir`` points somewhere non-standard.
    """

    try:
        text = (gitdir / "commondir").read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None
    if not text:
        return None
    common = Path(text)
    if not common.is_absolute():
        common = gitdir / common
    return lexical_absolute(common)


def _resolve_git_control_surface_dirs(canonical_root: Path) -> list[Path]:
    """Every directory whose contents form the git control surface for ``root``.

    A plain ``.git`` directory is walked in place.  A ``.git`` GITFILE
    (``gitdir: <path>`` — a linked worktree or submodule) points at an EXTERNAL
    gitdir living OUTSIDE the repo root, whose ``hooks/``/``config`` still execute
    against this working tree.  We resolve it and return both that gitdir and, for
    a worktree, its common gitdir (where the shared hooks live) — otherwise a
    hook planted in the external gitdir would be invisible to the digest.
    """

    dot_git = canonical_root / ".git"
    dirs: list[Path] = []
    try:
        meta = os.lstat(dot_git)
    except OSError:
        return dirs
    if stat.S_ISDIR(meta.st_mode):
        return [dot_git]
    if stat.S_ISREG(meta.st_mode):
        try:
            text = dot_git.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return dirs
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped.startswith("gitdir:"):
                continue
            raw = stripped[len("gitdir:"):].strip()
            if not raw:
                break
            gitdir = Path(raw)
            if not gitdir.is_absolute():
                gitdir = dot_git.parent / gitdir
            gitdir = lexical_absolute(gitdir)
            dirs.append(gitdir)
            # Cover the shared common gitdir where git sources shared hooks/config.
            # ``<gitdir>/commondir`` is the AUTHORITATIVE source git uses; prefer it
            # over the structural ``<common>/worktrees/<name>`` -> ``<common>`` guess
            # (an attacker-crafted checkout can point commondir at a non-standard
            # dir the guess would miss).  Fall back to the structural guess only
            # when commondir is absent.  A submodule (``<super>/.git/modules/<name>``)
            # has no commondir and is its own gitdir -> already covered.
            common = _git_worktree_common_dir(gitdir)
            if common is not None:
                dirs.append(common)
            elif gitdir.parent.name == "worktrees":
                dirs.append(gitdir.parent.parent)
            break
    seen: set[str] = set()
    unique: list[Path] = []
    for candidate in dirs:
        real = os.path.realpath(candidate)
        if real not in seen:
            seen.add(real)
            unique.append(Path(real))
    return unique


def _validation_control_surface_digest(root: Path) -> str:
    """Content digest of the VCS/control dirs that the normal baseline EXCLUDES.

    ``repository_state_digest`` deliberately skips ``.git/``, ``.codexqb/``,
    ``.pytest_cache/`` and ``__pycache__/``, so a validation target writing e.g.
    ``.git/hooks/pre-push`` or ``.git/config`` (persistent, sandbox-escaping RCE)
    would otherwise be invisible to the post-hoc mutation check.  For the
    VALIDATION integrity check specifically we snapshot these prefixes
    content-inclusive before and after the run — INCLUDING the external gitdir of
    a linked worktree/submodule — so any change fails the validation closed
    (``validation_command_mutated_repository``); a mutated repository can never
    produce a signed success receipt.  ``.codexqb/`` (the Apply run's own tree,
    written during validation and guaranteed by signed receipts / the hash-chained
    event log) is excluded to avoid false positives.  The walk is bounded — a
    pathological control surface fails closed (``validation_control_surface_unverifiable``)
    rather than being silently truncated or DoS-ing the controller.
    """

    canonical_root = lexical_absolute(root)
    bases: list[Path] = list(_resolve_git_control_surface_dirs(canonical_root))
    for prefix in WORKSPACE_BASELINE_EXCLUDED_PREFIXES:
        if prefix in (".codexqb/", ".git/"):
            continue
        bases.append(canonical_root / prefix.rstrip("/"))
    # A worktree's common gitdir already CONTAINS ``worktrees/<name>`` — drop any
    # base nested under another so its subtree is not walked (and byte-capped) twice.
    resolved_bases: list[tuple[str, Path]] = sorted(
        ((os.path.realpath(base), base) for base in bases), key=lambda item: len(item[0])
    )
    bases = []
    kept_reals: list[str] = []
    for real, base in resolved_bases:
        if any(real == kept or real.startswith(kept.rstrip(os.sep) + os.sep) for kept in kept_reals):
            continue
        kept_reals.append(real)
        bases.append(base)

    hasher = hashlib.sha256()
    entries: list[tuple[str, ...]] = []
    paths_seen = 0
    bytes_read = 0

    def _record(path: Path) -> None:
        nonlocal bytes_read
        # Pass the remaining byte budget so an over-budget file fails closed
        # BEFORE it is read (R2), then account the bytes actually hashed.
        entry = _control_surface_entry(
            canonical_root, path, max_bytes=VALIDATION_CONTROL_SURFACE_MAX_BYTES - bytes_read
        )
        if entry and entry[1] == "R" and len(entry) >= 4:
            try:
                bytes_read += int(entry[3])
            except (ValueError, IndexError):
                pass
            if bytes_read > VALIDATION_CONTROL_SURFACE_MAX_BYTES:
                raise ValueError("validation_control_surface_unverifiable")
        entries.append(entry)

    # Hash the ``.git`` node itself when it is a GITFILE/symlink (not a plain dir,
    # whose contents are already walked), so a target that REWRITES ``.git`` to
    # re-point at a different gitdir is caught directly.
    dot_git = canonical_root / ".git"
    try:
        dot_git_meta = os.lstat(dot_git)
    except OSError:
        dot_git_meta = None
    if dot_git_meta is not None and not stat.S_ISDIR(dot_git_meta.st_mode):
        _record(dot_git)
        paths_seen += 1
    for base in bases:
        try:
            meta = os.lstat(base)
        except OSError:
            continue
        if not stat.S_ISDIR(meta.st_mode):
            _record(base)
            paths_seen += 1
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames.sort()
            for name in sorted(dirnames) + sorted(filenames):
                paths_seen += 1
                if paths_seen > VALIDATION_CONTROL_SURFACE_MAX_PATHS:
                    raise ValueError("validation_control_surface_unverifiable")
                _record(Path(dirpath) / name)
    for entry in sorted(entries):
        # Length-prefixed, ASCII-safe field framing (no control-character
        # separators) so the digest is unambiguous without embedding bytes that
        # a secret/obfuscation scanner would flag.
        for field in entry:
            encoded = field.encode("utf-8", "surrogatepass")
            hasher.update(str(len(encoded)).encode("ascii"))
            hasher.update(b":")
            hasher.update(encoded)
        hasher.update(b";")
    return hasher.hexdigest()


def _control_surface_entry(
    root: Path, path: Path, *, max_bytes: int | None = None
) -> tuple[str, ...]:
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        rel = path.as_posix()
    try:
        st = os.lstat(path)
    except OSError:
        return (rel, "E")
    mode = str(stat.S_IMODE(st.st_mode))
    if stat.S_ISLNK(st.st_mode):
        try:
            return (rel, "L", mode, os.readlink(path))
        except OSError:
            return (rel, "L", mode, "?")
    if stat.S_ISDIR(st.st_mode):
        return (rel, "D", mode)
    if stat.S_ISREG(st.st_mode):
        # R2: fail closed on a single file that alone would blow the remaining
        # byte budget — BEFORE reading it — so the cap can never be overshot by
        # one file's own size.
        if max_bytes is not None and st.st_size > max_bytes:
            raise ValueError("validation_control_surface_unverifiable")
        file_hash = hashlib.sha256()
        try:
            with open(path, "rb", closefd=True) as handle:
                for chunk in iter(lambda: handle.read(1 << 16), b""):
                    file_hash.update(chunk)
        except OSError:
            return (rel, "R", mode, "unreadable")
        return (rel, "R", mode, str(st.st_size), file_hash.hexdigest())
    return (rel, "O", mode)


def execute_planned_validation(
    run_dir: Path,
    task_id: str,
    validation_id: str,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "validation_id": validation_id,
            "actor": actor,
            "evidence": evidence or [],
        }
    )
    if not actor.strip():
        raise ValueError("validation_actor_required")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        if task.get("state") not in {"IMPLEMENTED", "TASK_REVIEW", "SECURITY_REVIEW", "RE_REVIEW"}:
            raise ValueError(f"validation_requires_implemented_state={task_id}:{task.get('state')}")
        commands = [
            item
            for item in task.get("validation_commands", [])
            if isinstance(item, dict) and item.get("id") == validation_id
        ]
        if len(commands) != 1:
            raise ValueError(f"validation_command_not_planned={task_id}:{validation_id}")
        command = commands[0]
        # EXECUTE time: the command is about to run, so its targets MUST exist
        # (closes I-2 at the point of use).
        if not command_is_safe(command, handle.root, require_target_exists=True):
            raise ValueError(f"unsafe_validation_command={task_id}:{validation_id}")
        change_set, repository_evidence = load_current_change_set(handle, task)
        normalized_cwd, command_cwd = normalized_command_cwd(handle.root, command.get("cwd"))
        before_at = utc_now()
        before_snapshot = repository_receipt_snapshot(
            handle.root,
            run,
            repository_evidence,
            str(change_set["review_package_sha256"]),
            before_at,
        )
        # Snapshot the control dirs (.git/, .codexqb/, ...) that repository_state_digest
        # excludes, so a validation that writes e.g. .git/hooks is detected (C2).
        control_surface_before = _validation_control_surface_digest(handle.root)
        start_event = append_event_at(
            handle,
            {
                "event_type": "validation_execution_started",
                "task_id": task_id,
                "validation_id": validation_id,
                "actor": actor,
                "repository_state_digest": change_set["repository_state_digest"],
                "evidence": evidence or [],
            },
        )
        receipts = task.get("validation_receipts")
        receipts = receipts if isinstance(receipts, list) else []
        task["validation_receipts"] = [
            item
            for item in receipts
            if not isinstance(item, dict) or item.get("validation_id") != validation_id
        ]
        task["review_receipts"] = {}
        task["evidence_chain_status"] = "in_progress"
        task["verification_assurance"] = "controller_asserted"
        progress["events"] = [
            {
                "sequence": start_event["sequence"],
                "event_type": "validation_execution_started",
                "task_id": task_id,
                "validation_id": validation_id,
            }
        ]
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": start_event["sequence"],
        }
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        started_at = utc_now()
        process_result = run_bounded_validation_process(
            list(command["argv"]),
            cwd=command_cwd,
            root=handle.root,
            timeout_seconds=int(command["timeout_seconds"]),
            root_fd=handle.root_fd,
            normalized_cwd=normalized_cwd,
        )
        if process_result.output_limit_exceeded:
            raise ValueError(f"validation_output_limit_exceeded={task_id}:{validation_id}")
        exit_code = process_result.exit_code
        stdout = process_result.stdout
        stderr = process_result.stderr
        timed_out = process_result.timed_out
        termination_reason = process_result.termination_reason
        try:
            assert_safe_embedded_content_bytes(stdout)
            assert_safe_embedded_content_bytes(stderr)
        except ValueError as exc:
            raise ValueError(f"validation_output_secret_rejected={task_id}:{validation_id}") from exc
        finished_at = utc_now()
        current_change_set, current_repository_evidence = load_current_change_set(handle, task)
        if current_change_set.get("repository_state_digest") != change_set.get("repository_state_digest"):
            raise ValueError(f"validation_command_mutated_repository={task_id}:{validation_id}")
        # C2: a mutation of the excluded control dirs (e.g. .git/hooks/pre-push,
        # .git/config core.hooksPath) during validation fails closed — the signed
        # receipt can never attest success over a tampered repository, even when
        # Landlock preventive denial was unavailable.
        if _validation_control_surface_digest(handle.root) != control_surface_before:
            raise ValueError(f"validation_command_mutated_repository={task_id}:{validation_id}")
        after_at = utc_now()
        after_snapshot = repository_receipt_snapshot(
            handle.root,
            run,
            current_repository_evidence,
            str(change_set["review_package_sha256"]),
            after_at,
        )
        before_snapshot_state = {
            key: value for key, value in before_snapshot.items() if key != "captured_at"
        }
        after_snapshot_state = {
            key: value for key, value in after_snapshot.items() if key != "captured_at"
        }
        if before_snapshot_state != after_snapshot_state:
            raise ValueError(f"validation_command_mutated_repository={task_id}:{validation_id}")
        combined = stdout + stderr
        result_artifacts = [
            {"path": item["path"], "sha256": item["after_sha256"]}
            for item in changed_files_for_receipt(current_repository_evidence.get("manifest"))
            if item.get("after_sha256") is not None
        ]
        observed_event = append_event_at(
            handle,
            {
                "event_type": "validation_execution_observed",
                "task_id": task_id,
                "validation_id": validation_id,
                "actor": actor,
                "exit_code": exit_code,
                "timed_out": timed_out,
                "stdout_sha256": sha256_bytes(stdout),
                "stderr_sha256": sha256_bytes(stderr),
                "repository_state_digest": change_set["repository_state_digest"],
                "started_event_sequence": start_event["sequence"],
            },
        )
        producer_binding: dict[str, object]
        if run.get("mode") == "subagent_serial":
            producer, producer_error = current_completed_writer_record(handle, task)
            if producer_error or producer is None:
                raise ValueError(producer_error or f"validation_requires_completed_writer_agent_run={task_id}")
            with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
                _, agent_sha = agent_record_sha256_at(task_fd, producer)
            producer_binding = {
                "producer_kind": "agent",
                "identity_assurance": producer.get("identity_assurance"),
                "role": producer.get("role"),
                "agent_id": producer["agent_id"],
                "attempt": producer["attempt"],
                "completed_event_sequence": producer.get("completed_event_sequence"),
                "agent_run_sha256": agent_sha,
                "observed_after_event_sequence": observed_event["sequence"],
            }
        else:
            producer_binding = {
                "producer_kind": "controller_direct",
                "identity_assurance": "controller_asserted",
                "role": "controller",
                "agent_id": None,
                "attempt": None,
                "completed_event_sequence": None,
                "agent_run_sha256": None,
                "observed_after_event_sequence": observed_event["sequence"],
            }
        master_key = load_or_create_apply_run_trust_key(create=False)
        receipt_id = secrets.token_hex(32)
        receipt = sign_validation_receipt(
            {
                "receipt_kind": VALIDATION_RECEIPT_KIND,
                "receipt_version": VALIDATION_RECEIPT_VERSION,
                "receipt_id": receipt_id,
                "trust_key_id": receipt_trust_key_id(master_key),
                "issued_at": utc_now(),
                "observer": CONTROLLER_OBSERVER,
                "observation_scope": VALIDATION_OBSERVATION_SCOPE,
                "host_sandbox_proof": process_result.host_sandbox_proof,
                "approval_proof": NOT_OBSERVED,
                "network_enforcement_proof": process_result.network_enforcement_proof,
                "run_binding": receipt_run_binding(handle),
                "task_binding": receipt_task_binding(task),
                "producer_binding": producer_binding,
                "command": {
                    "validation_id": validation_id,
                    "planned_command_digest": planned_validation_key(command)[1],
                    "argv": command["argv"],
                    "cwd": normalized_cwd,
                    "expected_exit_code": command["expected_exit_code"],
                    "timeout_seconds": command["timeout_seconds"],
                    "planned_network": command["network"],
                    "probe_tier": command["probe_tier"],
                    "execution_nonce": secrets.token_hex(32),
                    "started_at": started_at,
                    "finished_at": finished_at,
                },
                "result": {
                    "exit_code": exit_code,
                    "timed_out": timed_out,
                    "termination_reason": termination_reason,
                    "stdout_sha256": sha256_bytes(stdout),
                    "stderr_sha256": sha256_bytes(stderr),
                    "combined_output_sha256": sha256_bytes(combined),
                    "stdout_bytes": len(stdout),
                    "stderr_bytes": len(stderr),
                    "combined_output_bytes": len(combined),
                    "artifacts": sorted(result_artifacts, key=lambda item: str(item["path"])),
                },
                "code_snapshot_before": before_snapshot,
                "code_snapshot_after": after_snapshot,
            },
            master_key,
        )
        file_name = f"Validation-Receipt-{validation_id}-{receipt_id[:12]}.json"
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
            write_regular_json_exclusive_at(task_fd, file_name, receipt)
            os.fsync(task_fd)
        published_event = append_event_at(
            handle,
            {
                "event_type": "validation_receipt_published",
                "task_id": task_id,
                "validation_id": validation_id,
                "receipt_id": receipt_id,
                "receipt_sha256": receipt_json_digest(receipt),
                "actor": actor,
                "exit_code": exit_code,
                "observed_event_sequence": observed_event["sequence"],
            },
        )
        receipts = task.get("validation_receipts")
        receipts = receipts if isinstance(receipts, list) else []
        receipts = [item for item in receipts if not isinstance(item, dict) or item.get("validation_id") != validation_id]
        receipts.append(
            {
                "validation_id": validation_id,
                "receipt_id": receipt_id,
                "path": file_name,
                "sha256": receipt_json_digest(receipt),
                "published_event_sequence": published_event["sequence"],
            }
        )
        task["validation_receipts"] = sorted(receipts, key=lambda item: str(item.get("validation_id", "")))
        task["review_receipts"] = {}
        task["evidence_chain_status"] = "in_progress"
        task["verification_assurance"] = "controller_asserted"
        progress["events"] = [
            {
                "sequence": published_event["sequence"],
                "event_type": "validation_receipt_published",
                "task_id": task_id,
                "validation_id": validation_id,
            }
        ]
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": published_event["sequence"],
        }
        secure_atomic_write_json_at(handle.run_fd, "Progress.json", progress, revalidate=handle.revalidate)
        return {
            "event": published_event,
            "receipt_path": (handle.run_dir / task_id / file_name).as_posix(),
            "receipt_id": receipt_id,
            "exit_code": exit_code,
        }


def validation_receipts_for_task(
    handle: ApplyMutationHandle,
    task: dict[str, object],
) -> tuple[list[dict[str, object]], list[dict[str, object]], list[str]]:
    task_id = str(task.get("task_id", ""))
    errors: list[str] = []
    references = task.get("validation_receipts")
    if not isinstance(references, list):
        references = []
    by_id: dict[str, list[dict[str, object]]] = {}
    for reference in references:
        if not isinstance(reference, dict):
            errors.append(f"validation_receipt_reference_invalid={task_id}")
            continue
        by_id.setdefault(str(reference.get("validation_id", "")), []).append(reference)
    planned = {
        str(command.get("id")): command
        for command in task.get("validation_commands", [])
        if isinstance(command, dict)
    }
    for validation_id in sorted(planned):
        if len(by_id.get(validation_id, [])) == 0:
            errors.append(f"verified_missing_validation_receipt={task_id}:{validation_id}")
        elif len(by_id[validation_id]) != 1:
            errors.append(f"validation_receipt_reused={task_id}:{validation_id}")
    for validation_id in sorted(set(by_id) - set(planned)):
        errors.append(f"validation_receipt_not_planned={task_id}:{validation_id or 'missing'}")
    loaded: list[dict[str, object]] = []
    normalized_references: list[dict[str, object]] = []
    master_key = load_or_create_apply_run_trust_key(create=False)
    try:
        change_set, repository_evidence = load_current_change_set(handle, task)
    except ValueError as exc:
        errors.append(str(exc))
        return loaded, normalized_references, errors
    current_snapshot_at = utc_now()
    current_snapshot = repository_receipt_snapshot(
        handle.root,
        handle.run,
        repository_evidence,
        str(change_set["review_package_sha256"]),
        current_snapshot_at,
    )
    try:
        events_by_sequence = receipt_events_by_sequence(handle)
    except ValueError:
        events_by_sequence = {}
        errors.append(f"validation_receipt_event_log_invalid={task_id}")
    latest_published_sequence: dict[str, int] = {}
    latest_started_sequence: dict[str, int] = {}
    for sequence, event in events_by_sequence.items():
        validation_id = event.get("validation_id")
        if (
            event.get("event_type") == "validation_execution_started"
            and event.get("task_id") == task_id
            and isinstance(validation_id, str)
            and (
                validation_id not in latest_started_sequence
                or sequence > latest_started_sequence[validation_id]
            )
        ):
            latest_started_sequence[validation_id] = sequence
        if (
            event.get("event_type") == "validation_receipt_published"
            and event.get("task_id") == task_id
            and isinstance(validation_id, str)
            and (
                validation_id not in latest_published_sequence
                or sequence > latest_published_sequence[validation_id]
            )
        ):
            latest_published_sequence[validation_id] = sequence
    receipt_ids: set[str] = set()
    for validation_id, command in planned.items():
        matches = by_id.get(validation_id, [])
        if len(matches) != 1:
            continue
        reference = matches[0]
        file_name = reference.get("path")
        receipt_id = reference.get("receipt_id")
        expected_prefix = f"Validation-Receipt-{validation_id}-"
        if (
            not isinstance(file_name, str)
            or not file_name.startswith(expected_prefix)
            or not file_name.endswith(".json")
            or not is_sha256(receipt_id)
        ):
            errors.append(f"validation_receipt_reference_invalid={task_id}:{validation_id}")
            continue
        try:
            with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
                receipt = secure_read_regular_json_at(task_fd, file_name)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"validation_receipt_missing_or_invalid={task_id}:{validation_id}:{exc}")
            continue
        receipt_sha = receipt_json_digest(receipt)
        if reference.get("sha256") != receipt_sha:
            errors.append(f"validation_receipt_digest_mismatch={task_id}:{validation_id}")
        if not verify_validation_receipt(receipt, master_key):
            errors.append(f"validation_receipt_mac_invalid={task_id}:{validation_id}")
            continue
        if receipt_id in receipt_ids:
            errors.append(f"validation_receipt_reused={task_id}:{validation_id}")
        receipt_ids.add(str(receipt_id))
        command_payload = receipt.get("command") if isinstance(receipt.get("command"), dict) else {}
        result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
        producer_binding = (
            receipt.get("producer_binding")
            if isinstance(receipt.get("producer_binding"), dict)
            else {}
        )
        if (
            receipt.get("receipt_id") != receipt_id
            or receipt.get("trust_key_id") != receipt_trust_key_id(master_key)
            or receipt.get("run_binding") != receipt_run_binding(handle)
            or receipt.get("task_binding") != receipt_task_binding(task)
            or command_payload.get("validation_id") != validation_id
            or command_payload.get("planned_command_digest") != planned_validation_key(command)[1]
            or command_payload.get("argv") != command.get("argv")
            or command_payload.get("cwd") != command.get("cwd")
            or command_payload.get("expected_exit_code") != command.get("expected_exit_code")
            or command_payload.get("timeout_seconds") != command.get("timeout_seconds")
            or command_payload.get("planned_network") != command.get("network")
            or command_payload.get("probe_tier") != command.get("probe_tier")
        ):
            errors.append(f"validation_receipt_context_mismatch={task_id}")
        if handle.run.get("mode") == "subagent_serial":
            producer, producer_error = current_completed_writer_record(handle, task)
            if producer_error or producer is None:
                errors.append(f"validation_receipt_producer_agent_run_missing={task_id}:{validation_id}")
                if producer_error:
                    errors.append(producer_error)
            else:
                try:
                    with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
                        _, producer_sha = agent_record_sha256_at(task_fd, producer)
                except ValueError:
                    errors.append(f"validation_receipt_producer_agent_run_missing={task_id}:{validation_id}")
                else:
                    if (
                        producer_binding.get("producer_kind") != "agent"
                        or producer_binding.get("identity_assurance")
                        != producer.get("identity_assurance")
                        or producer_binding.get("role") != producer.get("role")
                        or producer_binding.get("agent_id") != producer.get("agent_id")
                        or producer_binding.get("attempt") != producer.get("attempt")
                        or producer_binding.get("completed_event_sequence")
                        != producer.get("completed_event_sequence")
                        or producer_binding.get("agent_run_sha256") != producer_sha
                    ):
                        errors.append(f"validation_receipt_producer_agent_run_mismatch={task_id}:{validation_id}")
        elif (
            producer_binding.get("producer_kind") != "controller_direct"
            or producer_binding.get("identity_assurance") != "controller_asserted"
            or producer_binding.get("role") != "controller"
            or producer_binding.get("agent_id") is not None
            or producer_binding.get("attempt") is not None
            or producer_binding.get("completed_event_sequence") is not None
            or producer_binding.get("agent_run_sha256") is not None
        ):
            errors.append(f"validation_receipt_direct_producer_mismatch={task_id}:{validation_id}")
        observed_sequence = producer_binding.get("observed_after_event_sequence")
        published_sequence = reference.get("published_event_sequence")
        if (
            not isinstance(published_sequence, int)
            or isinstance(published_sequence, bool)
            or latest_published_sequence.get(validation_id) != published_sequence
            or latest_started_sequence.get(validation_id, published_sequence) >= published_sequence
        ):
            errors.append(f"validation_receipt_not_latest={task_id}:{validation_id}")
        observed_event = (
            events_by_sequence.get(observed_sequence)
            if isinstance(observed_sequence, int)
            else None
        )
        published_event = (
            events_by_sequence.get(published_sequence)
            if isinstance(published_sequence, int)
            else None
        )
        started_sequence = (
            observed_event.get("started_event_sequence")
            if isinstance(observed_event, dict)
            else None
        )
        started_event = (
            events_by_sequence.get(started_sequence)
            if isinstance(started_sequence, int)
            else None
        )
        if (
            not isinstance(started_event, dict)
            or started_event.get("event_type") != "validation_execution_started"
            or started_event.get("task_id") != task_id
            or started_event.get("validation_id") != validation_id
            or started_event.get("repository_state_digest") != change_set.get("repository_state_digest")
            or not isinstance(observed_event, dict)
            or observed_event.get("event_type") != "validation_execution_observed"
            or observed_event.get("task_id") != task_id
            or observed_event.get("validation_id") != validation_id
            or observed_event.get("repository_state_digest") != change_set.get("repository_state_digest")
            or observed_event.get("exit_code") != result.get("exit_code")
            or observed_event.get("timed_out") != result.get("timed_out")
            or observed_event.get("stdout_sha256") != result.get("stdout_sha256")
            or observed_event.get("stderr_sha256") != result.get("stderr_sha256")
            or not isinstance(published_event, dict)
            or published_event.get("event_type") != "validation_receipt_published"
            or published_event.get("task_id") != task_id
            or published_event.get("validation_id") != validation_id
            or published_event.get("receipt_id") != receipt_id
            or published_event.get("receipt_sha256") != receipt_sha
            or published_event.get("observed_event_sequence") != observed_sequence
            or not isinstance(started_sequence, int)
            or not isinstance(observed_sequence, int)
            or not isinstance(published_sequence, int)
            or not started_sequence < observed_sequence < published_sequence
            or latest_started_sequence.get(validation_id) != started_sequence
        ):
            errors.append(f"validation_receipt_event_binding_mismatch={task_id}:{validation_id}")
        if result.get("exit_code") != command.get("expected_exit_code") or result.get("timed_out") is not False:
            errors.append(f"validation_receipt_not_passing={task_id}:{validation_id}")
        for snapshot_name in ("code_snapshot_before", "code_snapshot_after"):
            snapshot = receipt.get(snapshot_name)
            if not isinstance(snapshot, dict):
                errors.append(f"validation_receipt_snapshot_invalid={task_id}:{validation_id}")
                continue
            expected_snapshot = dict(current_snapshot)
            expected_snapshot["captured_at"] = snapshot.get("captured_at")
            if snapshot != expected_snapshot:
                errors.append(f"verified_repository_state_digest_mismatch={task_id}")
                break
        artifacts = result.get("artifacts")
        current_artifacts = [
            {"path": item["path"], "sha256": item["after_sha256"]}
            for item in changed_files_for_receipt(repository_evidence.get("manifest"))
            if item.get("after_sha256") is not None
        ]
        if artifacts != sorted(current_artifacts, key=lambda item: str(item["path"])):
            errors.append(f"validation_receipt_artifact_hash_mismatch={task_id}:{validation_id}")
        loaded.append(receipt)
        normalized_references.append(
            {"receipt_id": str(receipt_id), "receipt_sha256": receipt_sha}
        )
    return (
        loaded,
        sorted(normalized_references, key=lambda item: item["receipt_id"]),
        list(dict.fromkeys(errors)),
    )


def review_report_verdict(phase: str, payload: object) -> str | None:
    if not isinstance(payload, dict) or payload.get("status") != "COMPLETE" or payload.get("phase") != phase:
        return None
    verdict = payload.get("verdict")
    return str(verdict) if isinstance(verdict, str) else None


def review_phase_expected_role(phase: str) -> str:
    return {
        "spec": "task_reviewer",
        "quality": "task_reviewer",
        "security": "security_reviewer",
        "final": "final_reviewer",
    }[phase]


def task_review_phase_receipt(
    handle: ApplyMutationHandle,
    task: dict[str, object],
    phase: str,
) -> tuple[dict[str, object] | None, list[str]]:
    task_id = str(task.get("task_id", ""))
    references = task.get("review_receipts")
    reference = references.get(phase) if isinstance(references, dict) else None
    if not isinstance(reference, dict):
        return None, [f"{phase}_review_receipt_missing={task_id}"]
    file_name = reference.get("path")
    if not isinstance(file_name, str) or not file_name.startswith(f"Review-Receipt-{phase}-"):
        return None, [f"{phase}_review_receipt_reference_invalid={task_id}"]
    try:
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
            receipt = secure_read_regular_json_at(task_fd, file_name)
            report_bytes = secure_read_regular_bytes_at(task_fd, f"Review-Report-{phase}.json")
            report = json.loads(report_bytes.decode("utf-8"))
    except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return None, [f"{phase}_review_receipt_missing_or_invalid={task_id}"]
    master_key = load_or_create_apply_run_trust_key(create=False)
    errors: list[str] = []
    if not verify_review_completion_receipt(receipt, master_key):
        errors.append(f"{phase}_review_receipt_mac_invalid={task_id}")
        return None, errors
    receipt_sha = receipt_json_digest(receipt)
    if reference.get("sha256") != receipt_sha or reference.get("receipt_id") != receipt.get("receipt_id"):
        errors.append(f"{phase}_review_receipt_digest_mismatch={task_id}")
    if receipt.get("run_binding") != receipt_run_binding(handle) or receipt.get("task_binding") != receipt_task_binding(task):
        errors.append(f"{phase}_review_receipt_context_mismatch={task_id}")
    binding = receipt.get("review_binding") if isinstance(receipt.get("review_binding"), dict) else {}
    if binding.get("task_review_sha256") != sha256_bytes(report_bytes):
        errors.append(f"{phase}_review_report_hash_mismatch={task_id}")
    verdict = review_report_verdict(phase, report)
    if verdict is None or binding.get("verdict") != verdict or reference.get("verdict") != verdict:
        errors.append(f"{phase}_review_verdict_mismatch={task_id}")
    try:
        change_set, _ = load_current_change_set(handle, task)
    except ValueError as exc:
        errors.append(str(exc))
        return receipt, errors
    if (
        binding.get("review_package_sha256") != change_set.get("review_package_sha256")
        or binding.get("code_snapshot_sha256") != change_set.get("repository_state_digest")
    ):
        errors.append(f"{phase}_review_change_set_mismatch={task_id}")
    _, validation_refs, validation_errors = validation_receipts_for_task(handle, task)
    errors.extend(validation_errors)
    if (
        binding.get("validation_receipts") != validation_refs
        or binding.get("validation_receipt_set_sha256") != receipt_json_digest(validation_refs)
    ):
        errors.append(f"{phase}_review_validation_receipt_set_mismatch={task_id}")
    reviewer = receipt.get("reviewer_binding") if isinstance(receipt.get("reviewer_binding"), dict) else {}
    role = review_phase_expected_role(phase)
    record: dict[str, object] | None = None
    if reviewer.get("reviewer_kind") != "agent" or reviewer.get("role") != role:
        errors.append(f"{phase}_reviewer_agent_run_missing={task_id}")
    else:
        record = completed_agent_record(task, role, phase)
        if record is None:
            errors.append(f"{phase}_reviewer_agent_run_missing={task_id}")
        else:
            if (
                record.get("report_path") != f"Review-Report-{phase}.json"
                or record.get("report_sha256") != sha256_bytes(report_bytes)
            ):
                errors.append(f"{phase}_review_report_completed_run_mismatch={task_id}")
            try:
                with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
                    _, agent_sha = agent_record_sha256_at(task_fd, record)
            except ValueError:
                errors.append(f"{phase}_reviewer_agent_run_missing={task_id}")
            else:
                if (
                    reviewer.get("agent_id") != record.get("agent_id")
                    or reviewer.get("identity_assurance") != record.get("identity_assurance")
                    or reviewer.get("attempt") != record.get("attempt")
                    or reviewer.get("agent_run_sha256") != agent_sha
                ):
                    errors.append(f"{phase}_reviewer_agent_run_mismatch={task_id}")
    if record is not None:
        ordering = receipt.get("ordering") if isinstance(receipt.get("ordering"), dict) else {}
        producer, producer_error = current_completed_writer_record(handle, task)
        if producer_error:
            errors.append(producer_error)
        validation_reference_values = task.get("validation_receipts")
        validation_publish_sequences = [
            item.get("published_event_sequence")
            for item in (validation_reference_values if isinstance(validation_reference_values, list) else [])
            if isinstance(item, dict)
            and isinstance(item.get("published_event_sequence"), int)
        ]
        expected_validation_sequence = (
            max(validation_publish_sequences) if validation_publish_sequences else None
        )
        expected_producer_sequence = producer.get("completed_event_sequence") if isinstance(producer, dict) else None
        dispatch_sequence = ordering.get("reviewer_dispatch_event_sequence")
        spawn_sequence = ordering.get("reviewer_spawned_event_sequence")
        completed_sequence = ordering.get("reviewer_completed_event_sequence")
        normalized_sequence = record.get("report_normalized_event_sequence")
        observed_sequence = ordering.get("receipt_issued_after_event_sequence")
        published_sequence = reference.get("published_event_sequence")
        try:
            events_by_sequence = receipt_events_by_sequence(handle)
        except ValueError:
            events_by_sequence = {}
            errors.append(f"{phase}_review_receipt_event_log_invalid={task_id}")
        latest_published_sequence = max(
            (
                sequence
                for sequence, event in events_by_sequence.items()
                if event.get("event_type") == "review_receipt_published"
                and event.get("task_id") == task_id
                and event.get("review_phase") == phase
            ),
            default=None,
        )
        if (
            not isinstance(published_sequence, int)
            or isinstance(published_sequence, bool)
            or published_sequence != latest_published_sequence
        ):
            errors.append(f"review_receipt_not_latest={task_id}:{phase}")
        dispatch_event = (
            events_by_sequence.get(dispatch_sequence)
            if isinstance(dispatch_sequence, int)
            else None
        )
        spawn_event = (
            events_by_sequence.get(spawn_sequence)
            if isinstance(spawn_sequence, int)
            else None
        )
        completed_event = (
            events_by_sequence.get(completed_sequence)
            if isinstance(completed_sequence, int)
            else None
        )
        normalized_event = (
            events_by_sequence.get(normalized_sequence)
            if isinstance(normalized_sequence, int)
            else None
        )
        observed_event = (
            events_by_sequence.get(observed_sequence)
            if isinstance(observed_sequence, int)
            else None
        )
        published_event = (
            events_by_sequence.get(published_sequence)
            if isinstance(published_sequence, int)
            else None
        )
        if (
            reviewer.get("dispatch_packet_sha256") != record.get("packet_sha256")
            or reviewer.get("completed_at") != record.get("completed_at")
            or ordering.get("producer_completed_event_sequence") != expected_producer_sequence
            or ordering.get("validation_receipts_published_event_sequence")
            != expected_validation_sequence
            or spawn_sequence != record.get("spawn_event_sequence")
            or completed_sequence != record.get("completed_event_sequence")
            or not isinstance(dispatch_event, dict)
            or dispatch_event.get("event_type") != "subagent_dispatch_packet_prepared"
            or dispatch_event.get("task_id") != task_id
            or dispatch_event.get("role") != role
            or dispatch_event.get("review_phase") != phase
            or dispatch_event.get("attempt") != record.get("attempt")
            or dispatch_event.get("packet_sha256") != reviewer.get("dispatch_packet_sha256")
            or not isinstance(spawn_event, dict)
            or spawn_event.get("event_type") != "subagent_dispatch_status_recorded"
            or spawn_event.get("task_id") != task_id
            or spawn_event.get("role") != role
            or spawn_event.get("review_phase") != phase
            or spawn_event.get("attempt") != record.get("attempt")
            or spawn_event.get("agent_id") != record.get("agent_id")
            or spawn_event.get("status") != "spawned"
            or not isinstance(normalized_event, dict)
            or normalized_event.get("event_type") != "review_report_normalized"
            or normalized_event.get("task_id") != task_id
            or normalized_event.get("review_phase") != phase
            or normalized_event.get("role") != role
            or normalized_event.get("agent_id") != record.get("agent_id")
            or normalized_event.get("attempt") != record.get("attempt")
            or normalized_event.get("report_path") != record.get("report_path")
            or normalized_event.get("report_sha256") != record.get("report_sha256")
            or normalized_event.get("host_completion_proof") != NOT_OBSERVED
            or not isinstance(completed_event, dict)
            or completed_event.get("event_type") != "subagent_dispatch_status_recorded"
            or completed_event.get("task_id") != task_id
            or completed_event.get("role") != role
            or completed_event.get("review_phase") != phase
            or completed_event.get("attempt") != record.get("attempt")
            or completed_event.get("agent_id") != record.get("agent_id")
            or completed_event.get("status") != "completed"
            or completed_event.get("report_path") != record.get("report_path")
            or completed_event.get("report_sha256") != record.get("report_sha256")
            or completed_event.get("report_normalized_event_sequence") != normalized_sequence
            or not isinstance(observed_event, dict)
            or observed_event.get("event_type") != "review_completion_observed"
            or observed_event.get("task_id") != task_id
            or observed_event.get("review_phase") != phase
            or observed_event.get("role") != role
            or observed_event.get("agent_id") != record.get("agent_id")
            or observed_event.get("verdict") != binding.get("verdict")
            or not isinstance(published_event, dict)
            or published_event.get("event_type") != "review_receipt_published"
            or published_event.get("task_id") != task_id
            or published_event.get("review_phase") != phase
            or published_event.get("role") != role
            or published_event.get("receipt_id") != receipt.get("receipt_id")
            or published_event.get("receipt_sha256") != receipt_sha
            or published_event.get("verdict") != binding.get("verdict")
            or published_event.get("observed_event_sequence") != observed_sequence
            or not isinstance(dispatch_sequence, int)
            or not isinstance(observed_sequence, int)
            or not isinstance(published_sequence, int)
            or not isinstance(normalized_sequence, int)
            or not isinstance(spawn_sequence, int)
            or not isinstance(completed_sequence, int)
            or not dispatch_sequence < spawn_sequence < normalized_sequence < completed_sequence
            or not completed_sequence < observed_sequence < published_sequence
        ):
            errors.append(f"{phase}_review_receipt_event_binding_mismatch={task_id}")
    return receipt, list(dict.fromkeys(errors))


def task_review_phase_is_current(
    handle: ApplyMutationHandle,
    task: dict[str, object],
    phase: str,
    verdict: str,
) -> bool:
    receipt, errors = task_review_phase_receipt(handle, task, phase)
    if errors or not isinstance(receipt, dict):
        return False
    binding = receipt.get("review_binding")
    return isinstance(binding, dict) and binding.get("verdict") == verdict


def task_verification_errors(
    handle: ApplyMutationHandle,
    task: dict[str, object],
    *,
    require_host_attestation: bool = True,
) -> list[str]:
    task_id = str(task.get("task_id", ""))
    errors: list[str] = []
    if handle.run.get("mode") != "subagent_serial":
        errors.append(f"verified_requires_subagent_reviewer_receipts={task_id}")
    if require_host_attestation:
        errors.append(f"trusted_verified_requires_host_agent_attestation={task_id}")
    writer_agent_ids = {
        str(item.get("agent_id"))
        for item in agent_runs(task)
        if isinstance(item, dict)
        and item.get("role") in {"implementer", "fixer"}
        and item.get("status") == "completed"
        and isinstance(item.get("agent_id"), str)
    }
    _, _, validation_errors = validation_receipts_for_task(handle, task)
    errors.extend(validation_errors)
    phases = ["spec", "quality"]
    if task.get("security_review_required") is True:
        phases.append("security")
    phases.append("final")
    publish_sequences: list[int] = []
    for phase in phases:
        receipt, phase_errors = task_review_phase_receipt(handle, task, phase)
        errors.extend(phase_errors)
        if phase in {"spec", "quality"} and (
            receipt is None or any("reviewer_agent_run_missing" in item for item in phase_errors)
        ):
            errors.append(f"task_reviewer_agent_run_missing={task_id}")
        if phase == "security" and (receipt is None or any("reviewer_agent_run_missing" in item for item in phase_errors)):
            errors.append(f"security_reviewer_agent_run_missing={task_id}")
        if phase == "final" and (receipt is None or any("reviewer_agent_run_missing" in item for item in phase_errors)):
            errors.append("final_reviewer_agent_run_missing")
        if isinstance(receipt, dict):
            binding = receipt.get("review_binding")
            if not isinstance(binding, dict) or binding.get("verdict") != "pass":
                errors.append(f"{phase}_review_must_pass={task_id}")
            reviewer = receipt.get("reviewer_binding")
            if isinstance(reviewer, dict) and reviewer.get("agent_id") in writer_agent_ids:
                errors.append(f"reviewer_agent_must_differ_from_writer={task_id}:{phase}")
        references = task.get("review_receipts")
        reference = references.get(phase) if isinstance(references, dict) else None
        if isinstance(reference, dict) and isinstance(reference.get("published_event_sequence"), int):
            publish_sequences.append(int(reference["published_event_sequence"]))
    if len(publish_sequences) == len(phases) and any(
        left >= right for left, right in zip(publish_sequences, publish_sequences[1:])
    ):
        errors.append(f"review_order_invalid={task_id}")
    return list(dict.fromkeys(errors))


def final_review_aggregate(tasks: object) -> dict[str, object]:
    typed_tasks = [item for item in tasks if isinstance(item, dict)] if isinstance(tasks, list) else []
    final_receipts = [
        item["review_receipts"]["final"]
        for item in typed_tasks
        if isinstance(item.get("review_receipts"), dict)
        and isinstance(item["review_receipts"].get("final"), dict)
    ]
    if not final_receipts:
        return {"status": "not_started"}
    reviewed = sorted(
        str(item.get("task_id"))
        for item in typed_tasks
        if isinstance(item.get("review_receipts"), dict)
        and isinstance(item["review_receipts"].get("final"), dict)
        and item["review_receipts"]["final"].get("verdict") == "pass"
    )
    all_ids = sorted(str(item.get("task_id")) for item in typed_tasks)
    return {
        "status": "pass" if reviewed == all_ids else "in_progress",
        "reviewed_task_ids": reviewed,
        "final_reviewer_receipts": final_receipts,
        "validation_receipts": [
            reference
            for item in typed_tasks
            for reference in item.get("validation_receipts", [])
            if isinstance(reference, dict)
        ],
        "evidence": ["controller-verified signed task review receipts"],
    }


def publish_review_completion(
    run_dir: Path,
    task_id: str,
    phase: str,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "phase": phase, "actor": actor, "evidence": evidence or []}
    )
    if phase not in REVIEW_PHASES:
        raise ValueError(f"invalid_review_phase={phase}")
    if not actor.strip():
        raise ValueError("review_receipt_actor_required")
    role = review_phase_expected_role(phase)
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        run = handle.run
        if run.get("mode") != "subagent_serial":
            raise ValueError(f"review_receipt_requires_subagent_serial_mode={run.get('mode')}")
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        invariant_errors = trusted_task_transition_errors(
            handle,
            progress,
            task,
            verified_candidate=False,
        )
        if invariant_errors:
            raise ValueError(";".join(invariant_errors))
        if phase == "quality" and not task_review_phase_is_current(handle, task, "spec", "pass"):
            raise ValueError(f"quality_review_requires_spec_pass={task_id}")
        if phase == "security" and not task_review_phase_is_current(handle, task, "quality", "pass"):
            raise ValueError(f"security_review_requires_quality_pass={task_id}")
        if phase == "final":
            if not task_review_phase_is_current(handle, task, "quality", "pass"):
                raise ValueError(f"final_review_requires_quality_pass={task_id}")
            if task.get("security_review_required") is True and not task_review_phase_is_current(
                handle, task, "security", "pass"
            ):
                raise ValueError(f"final_review_requires_security_pass={task_id}")
        reviewer_record = completed_agent_record(task, role, phase)
        if reviewer_record is None:
            raise ValueError(f"{phase}_reviewer_agent_run_missing={task_id}")
        if reviewer_record.get("identity_assurance") != "controller_asserted":
            raise ValueError(f"controller_asserted_reviewer_identity_required={task_id}:{phase}")
        planned_validations = task.get("validation_commands")
        if not isinstance(planned_validations, list) or not planned_validations:
            raise ValueError(f"review_requires_planned_validation_commands={task_id}")
        validation_receipts, validation_refs, validation_errors = validation_receipts_for_task(handle, task)
        if validation_errors:
            raise ValueError(";".join(validation_errors))
        if len(validation_receipts) != len(planned_validations):
            raise ValueError(f"review_requires_complete_validation_receipts={task_id}")
        change_set, _ = load_current_change_set(handle, task)
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
            report_name = f"Review-Report-{phase}.json"
            report_bytes = secure_read_regular_bytes_at(task_fd, report_name)
            try:
                report = json.loads(report_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError(f"review_report_invalid={task_id}:{phase}") from exc
            verdict = review_report_verdict(phase, report)
            if verdict not in {"pass", "fail", "cannot_verify", "needs_fixes"}:
                raise ValueError(f"review_report_incomplete={task_id}:{phase}")
            if report.get("task_id") != task_id or report.get("reviewer_agent_id") != reviewer_record.get("agent_id"):
                raise ValueError(f"review_report_agent_context_mismatch={task_id}:{phase}")
            if (
                reviewer_record.get("report_path") != report_name
                or reviewer_record.get("report_sha256") != sha256_bytes(report_bytes)
            ):
                raise ValueError(f"review_report_completed_run_mismatch={task_id}:{phase}")
            packet_bytes = secure_read_regular_bytes_at(task_fd, "Dispatch-Packet.json")
            _, agent_sha = agent_record_sha256_at(task_fd, reviewer_record)
        dispatch = task.get("dispatch") if isinstance(task.get("dispatch"), dict) else {}
        validation_publish_sequence = max(
            int(reference.get("published_event_sequence", 0))
            for reference in task.get("validation_receipts", [])
            if isinstance(reference, dict)
        )
        completion_sequence = reviewer_record.get("completed_event_sequence")
        spawn_sequence = reviewer_record.get("spawn_event_sequence")
        dispatch_sequence = dispatch.get("event_sequence")
        producer, producer_error = current_completed_writer_record(handle, task)
        if producer_error or producer is None:
            raise ValueError(producer_error or f"review_requires_completed_writer_agent_run={task_id}")
        producer_sequence = producer.get("completed_event_sequence")
        observed_event = append_event_at(
            handle,
            {
                "event_type": "review_completion_observed",
                "task_id": task_id,
                "review_phase": phase,
                "role": role,
                "agent_id": reviewer_record.get("agent_id"),
                "actor": actor,
                "verdict": verdict,
                "evidence": evidence or [],
            },
        )
        master_key = load_or_create_apply_run_trust_key(create=False)
        receipt_id = secrets.token_hex(32)
        receipt = sign_review_completion_receipt(
            {
                "receipt_kind": REVIEW_COMPLETION_RECEIPT_KIND,
                "receipt_version": REVIEW_COMPLETION_RECEIPT_VERSION,
                "receipt_id": receipt_id,
                "trust_key_id": receipt_trust_key_id(master_key),
                "issued_at": utc_now(),
                "observer": CONTROLLER_OBSERVER,
                "observation_scope": REVIEW_COMPLETION_OBSERVATION_SCOPE,
                "host_sandbox_proof": NOT_OBSERVED,
                "approval_proof": NOT_OBSERVED,
                "network_enforcement_proof": NOT_OBSERVED,
                "run_binding": receipt_run_binding(handle),
                "task_binding": receipt_task_binding(task),
                "reviewer_binding": {
                    "reviewer_kind": "agent",
                    "identity_assurance": reviewer_record.get("identity_assurance"),
                    "role": role,
                    "agent_id": reviewer_record["agent_id"],
                    "attempt": reviewer_record["attempt"],
                    "dispatch_packet_sha256": sha256_bytes(packet_bytes),
                    "agent_run_sha256": agent_sha,
                    "completed_at": reviewer_record["completed_at"],
                },
                "review_binding": {
                    "task_review_sha256": sha256_bytes(report_bytes),
                    "review_package_sha256": change_set["review_package_sha256"],
                    "code_snapshot_sha256": change_set["repository_state_digest"],
                    "validation_receipts": validation_refs,
                    "validation_receipt_set_sha256": receipt_json_digest(validation_refs),
                    "verdict": verdict,
                },
                "ordering": {
                    "producer_completed_event_sequence": producer_sequence,
                    "validation_receipts_published_event_sequence": validation_publish_sequence,
                    "reviewer_dispatch_event_sequence": dispatch_sequence,
                    "reviewer_spawned_event_sequence": spawn_sequence,
                    "reviewer_completed_event_sequence": completion_sequence,
                    "receipt_issued_after_event_sequence": observed_event["sequence"],
                },
            },
            master_key,
        )
        file_name = f"Review-Receipt-{phase}-{receipt_id[:12]}.json"
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, _):
            write_regular_json_exclusive_at(task_fd, file_name, receipt)
            os.fsync(task_fd)
        published_event = append_event_at(
            handle,
            {
                "event_type": "review_receipt_published",
                "task_id": task_id,
                "review_phase": phase,
                "role": role,
                "receipt_id": receipt_id,
                "receipt_sha256": receipt_json_digest(receipt),
                "actor": actor,
                "verdict": verdict,
                "observed_event_sequence": observed_event["sequence"],
            },
        )
        review_references = task.get("review_receipts")
        review_references = review_references if isinstance(review_references, dict) else {}
        review_references[phase] = {
            "receipt_id": receipt_id,
            "path": file_name,
            "sha256": receipt_json_digest(receipt),
            "verdict": verdict,
            "published_event_sequence": published_event["sequence"],
        }
        task["review_receipts"] = review_references
        task["evidence_chain_status"] = "complete_unattested" if phase == "final" else "in_progress"
        task["verification_assurance"] = "controller_asserted"
        aggregate = {
            "status": "COMPLETE" if phase == "final" else "IN_PROGRESS",
            "task_id": task_id,
            "brief_sha256": task.get("brief_sha256"),
            "implementation_contract_digest": task.get("implementation_contract_digest"),
            "task_contract_digest": task.get("task_contract_digest"),
            "review_receipts": review_references,
        }
        with open_apply_task_for_mutation(handle, task_id) as (task_fd, task_revalidate):
            secure_atomic_write_json_at(task_fd, "Task-Review.json", aggregate, revalidate=task_revalidate)
        if phase == "final":
            secure_atomic_write_json_at(
                handle.run_fd,
                "Final-Review.json",
                final_review_aggregate(progress.get("tasks")),
                revalidate=handle.revalidate,
            )
        progress["events"] = [
            {
                "sequence": published_event["sequence"],
                "event_type": "review_receipt_published",
                "task_id": task_id,
                "review_phase": phase,
            }
        ]
        progress["resume_cursor"] = {
            "task_id": task_id,
            "state": task.get("state"),
            "event_sequence": published_event["sequence"],
        }
        secure_atomic_write_json_at(handle.run_fd, "Progress.json", progress, revalidate=handle.revalidate)
        return {
            "event": published_event,
            "receipt_path": (handle.run_dir / task_id / file_name).as_posix(),
            "receipt_id": receipt_id,
            "phase": phase,
            "verdict": verdict,
        }


def recover_stale_writer_lock(
    run_dir: Path,
    task_id: str,
    to_state: str,
    actor: str,
    evidence: list[str] | None = None,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {
            "task_id": task_id,
            "to_state": to_state,
            "actor": actor,
            "evidence": evidence or [],
        }
    )
    if not safe_task_id(task_id):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    if to_state not in {"BLOCKED", "NEEDS_CONTEXT"}:
        raise ValueError(f"invalid_recovery_state={to_state}")
    if not actor.strip():
        raise ValueError("recovery_actor_required")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        task = find_task(progress, task_id)
        from_state = str(task.get("state", ""))
        if from_state != "IMPLEMENTING":
            raise ValueError(f"recovery_requires_implementing_state={from_state or 'missing'}")
        if regular_target_metadata_at(handle.run_fd, WRITER_LOCK_NAME) is None:
            raise ValueError("writer_lock_missing")
        lock = secure_read_regular_json_at(handle.run_fd, WRITER_LOCK_NAME)
        locks = progress.get("active_writer_locks", [])
        if not isinstance(locks, list) or len(locks) != 1 or locks[0] != lock or task.get("writer_lock") != lock:
            raise ValueError("writer_lock_recovery_requires_consistent_lock")
        if lock.get("task_id") != task_id:
            raise ValueError("writer_lock_task_mismatch")
        if lock_expiry(lock) is None:
            raise ValueError("writer_lock_expiry_invalid")
        if not lock_is_expired(lock):
            raise ValueError("writer_lock_not_expired")

        secure_unlink_regular_at(
            handle.run_fd,
            WRITER_LOCK_NAME,
            revalidate=handle.revalidate,
        )
        progress["active_writer_locks"] = []
        task["writer_lock"] = None
        task["state"] = to_state
        event = append_event_at(
            handle,
            {
                "event_type": "task_transition",
                "task_id": task_id,
                "from": from_state,
                "to": to_state,
                "actor": actor,
                "evidence": evidence or [],
                "writer_lock": {"recovered": True, "stale_lock": lock},
                "recovery": "stale_writer_lock",
            },
        )
        progress["resume_cursor"] = {"task_id": task_id, "state": to_state, "event_sequence": event["sequence"]}
        progress["events"] = [
            {
                "sequence": event["sequence"],
                "event_type": "task_transition",
                "task_id": task_id,
                "to": to_state,
                "recovery": "stale_writer_lock",
            }
        ]
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        return event


def finalize_apply_run(run_dir: Path, actor: str, evidence: list[str] | None = None) -> dict[str, object]:
    assert_safe_persistent_payload({"actor": actor, "evidence": evidence or []})
    if not actor.strip():
        raise ValueError("finalize_actor_required")
    with open_verified_apply_run_for_mutation(run_dir) as handle:
        for name in ("Progress.json", "Final-Review.json", "Result.json", "Events.jsonl"):
            if regular_target_metadata_at(handle.run_fd, name) is None:
                raise ValueError(f"missing_apply_artifact={name}")
        errors = validate_apply_run(handle.run_dir)
        if errors:
            raise ValueError(";".join(errors))
        if not handle.revalidate():
            raise ValueError("apply_run_mutation_identity_changed")
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        tasks = progress.get("tasks", [])
        if not isinstance(tasks, list):
            raise ValueError("progress_tasks_must_be_list")
        live_verification_errors: list[str] = []
        for task in tasks:
            if not isinstance(task, dict):
                live_verification_errors.append("progress_task_must_be_object")
                continue
            live_verification_errors.extend(
                trusted_task_transition_errors(
                    handle,
                    progress,
                    task,
                    verified_candidate=task.get("state") == "VERIFIED",
                )
            )
            if task.get("state") == "VERIFIED":
                live_verification_errors.extend(
                    task_verification_errors(handle, task, require_host_attestation=True)
                )
        if live_verification_errors:
            raise ValueError(";".join(dict.fromkeys(live_verification_errors)))
        completed = [
            str(task["task_id"])
            for task in tasks
            if isinstance(task, dict) and task.get("state") == "VERIFIED"
        ]
        blocked = [
            str(task["task_id"])
            for task in tasks
            if isinstance(task, dict) and task.get("state") in {"BLOCKED", "NEEDS_CONTEXT"}
        ]
        if run.get("mode") != "no_action" and (len(completed) != len(tasks) or blocked):
            raise ValueError("finalize_requires_all_tasks_verified")
        final_review = secure_read_regular_json_at(handle.run_fd, "Final-Review.json")
        if run.get("mode") != "no_action" and final_review.get("status") != "pass":
            raise ValueError("finalize_requires_final_review_pass")
        event = append_event_at(
            handle,
            {
                "event_type": "apply_run_finalized",
                "actor": actor,
                "completed_task_ids": completed,
                "blocked_task_ids": blocked,
                "evidence": evidence or [],
            },
        )
        result = {
            "apply_run_id": run["apply_run_id"],
            "status": "no_action" if run.get("mode") == "no_action" else "complete",
            "completed_tasks": completed,
            "blocked_tasks": blocked,
            "finalized_at": event["timestamp"],
            "finalized_by": actor,
            "event_sequence": event["sequence"],
            "budget_contract": run.get("budget_contract", default_budget_contract()),
            "token_usage": run.get("token_usage", token_usage_not_observed()),
            "next_action": "Apply run is finalized; start a new apply run for additional READY queue work.",
        }
        secure_atomic_write_json_at(
            handle.run_fd,
            "Result.json",
            result,
            revalidate=handle.revalidate,
        )
        progress["events"] = [{"sequence": event["sequence"], "event_type": "apply_run_finalized"}]
        secure_atomic_write_json_at(
            handle.run_fd,
            "Progress.json",
            progress,
            revalidate=handle.revalidate,
        )
        return event


def command_is_safe(
    command: object,
    root: Path | None = None,
    *,
    evidence: bool = False,
    require_target_exists: bool = False,
) -> bool:
    # ``require_target_exists`` closes I-2 by demanding the validation targets
    # exist — set only at execute time (they are about to run).  Create-time
    # queue validation leaves it False so plan-first "proposed" targets pass
    # well-formedness while their files are still to be written.
    return isinstance(command, dict) and safe_validation_command_item(
        command, root=root, evidence=evidence, require_target_exists=require_target_exists
    )


def validate_dispatch_packet(run_dir: Path, run: dict[str, object], task: dict[str, object], errors: list[str]) -> None:
    task_id = str(task.get("task_id", ""))
    if not safe_task_id(task_id):
        return
    task_dir = (run_dir / task_id).resolve()
    packet_path = task_dir / "Dispatch-Packet.json"
    state = str(task.get("state", ""))
    if run.get("mode") == "subagent_serial" and state not in {"BRIEFED", "BLOCKED", "NEEDS_CONTEXT"}:
        if not packet_path.is_file():
            errors.append(f"subagent_dispatch_packet_missing={task_id}")
            return
    if not packet_path.is_file():
        if isinstance(task.get("dispatch"), dict):
            errors.append(f"subagent_dispatch_packet_missing={task_id}")
        return
    packet_encoded = read_artifact_bytes(packet_path, errors, f"{task_id}_dispatch_packet")
    if packet_encoded is None:
        return
    packet = decode_json_artifact(packet_encoded, errors, f"{task_id}_dispatch_packet")
    if not isinstance(packet, dict):
        return
    role = str(packet.get("role", ""))
    review_phase = packet.get("review_phase")
    if packet.get("dispatch_packet_schema_version") != 1:
        errors.append(f"invalid_dispatch_packet_schema_version={task_id}")
    if packet.get("task_id") != task_id:
        errors.append(f"dispatch_packet_task_mismatch={task_id}")
    if role not in DISPATCH_ROLES:
        errors.append(f"invalid_dispatch_role={task_id}:{role or 'missing'}")
        return
    expected_phases = {
        "task_reviewer": {"spec", "quality"},
        "security_reviewer": {"security"},
        "final_reviewer": {"final"},
    }.get(role)
    if expected_phases is None and review_phase is not None:
        errors.append(f"dispatch_review_phase_not_applicable={task_id}:{role}")
    elif expected_phases is not None and review_phase not in expected_phases:
        errors.append(f"dispatch_review_phase_invalid={task_id}:{role}")
    if packet.get("spawn_tool") != "multi_agent_v1.spawn_agent":
        errors.append(f"dispatch_spawn_tool_mismatch={task_id}")
    spawn = packet.get("spawn_request")
    if not isinstance(spawn, dict):
        errors.append(f"dispatch_spawn_request_missing={task_id}")
        return
    if spawn.get("agent_type") != AGENT_PROFILES[role]["agent_type"]:
        errors.append(f"dispatch_agent_type_mismatch={task_id}")
    if spawn.get("fork_context") is not False:
        errors.append(f"dispatch_must_use_fresh_context={task_id}")
    message = spawn.get("message")
    if not isinstance(message, str) or not message.strip():
        errors.append(f"dispatch_prompt_missing={task_id}")
    elif packet.get("prompt_sha256") != sha256_bytes(message.encode("utf-8")):
        errors.append(f"dispatch_prompt_hash_mismatch={task_id}")
    brief_path = task_dir / "Brief.md"
    brief_text = read_artifact_text(
        brief_path,
        errors,
        f"{task_id}_dispatch_brief",
        required=False,
    )
    if brief_text is not None and packet.get("brief_sha256") != sha256_bytes(brief_text.encode("utf-8")):
        errors.append(f"dispatch_brief_hash_mismatch={task_id}")
    if packet.get("model_override") is not None:
        errors.append(f"dispatch_model_override_must_be_null={task_id}")
    if packet.get("model_profile") != AGENT_PROFILES[role]["model_profile"]:
        errors.append(f"dispatch_model_profile_mismatch={task_id}")
    if packet.get("sandbox") != AGENT_PROFILES[role]["sandbox"]:
        errors.append(f"dispatch_sandbox_mismatch={task_id}")
    if packet.get("run_relative_task_dir") != task_id:
        errors.append(f"dispatch_task_directory_mismatch={task_id}")
    if packet.get("expected_report_paths") != EXPECTED_REPORT_PATHS:
        errors.append(f"dispatch_expected_report_paths_mismatch={task_id}")
    for key in (
        "source_subplan_path",
        "source_subplan_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
    ):
        if packet.get(key) != task.get(key):
            errors.append(f"dispatch_{key}_mismatch={task_id}")
    if packet.get("attempt") is not None and not isinstance(packet.get("attempt"), int):
        errors.append(f"dispatch_attempt_invalid={task_id}")
    elif isinstance(packet.get("attempt"), int) and packet["attempt"] > budget_limit(apply_budget_contract(run), "max_agent_attempts_per_role"):
        errors.append(f"budget_max_agent_attempts_exceeded={task_id}:{role}")
    if isinstance(message, str) and brief_text is not None:
        expected_prompt = dispatch_prompt(
            run,
            task,
            role,
            brief_text,
            str(review_phase) if isinstance(review_phase, str) else None,
        )
        if message != expected_prompt:
            errors.append(f"dispatch_prompt_contract_mismatch={task_id}")
    dispatch = task.get("dispatch")
    if isinstance(dispatch, dict):
        status = dispatch.get("status")
        if status not in {"packet_ready", *DISPATCH_AGENT_STATUSES}:
            errors.append(f"invalid_dispatch_status={task_id}:{status}")
        if dispatch.get("role") not in DISPATCH_ROLES:
            errors.append(f"invalid_dispatch_role={task_id}:{dispatch.get('role')}")
        if dispatch.get("review_phase") != review_phase:
            errors.append(f"dispatch_review_phase_mismatch={task_id}")
        if dispatch.get("packet_sha256") != sha256_bytes(packet_encoded):
            errors.append(f"dispatch_packet_hash_mismatch={task_id}")
    elif run.get("mode") == "subagent_serial" and state not in {"BRIEFED", "BLOCKED", "NEEDS_CONTEXT"}:
        errors.append(f"subagent_dispatch_status_missing={task_id}")
    runs = task.get("agent_runs", [])
    if runs is not None and not isinstance(runs, list):
        errors.append(f"agent_runs_must_be_list={task_id}")
        runs = []
    for item in runs:
        if not isinstance(item, dict):
            errors.append(f"agent_run_must_be_object={task_id}")
            continue
        run_role = str(item.get("role", ""))
        run_status = str(item.get("status", ""))
        run_phase = item.get("review_phase")
        agent_id = str(item.get("agent_id", ""))
        if run_role not in DISPATCH_ROLES:
            errors.append(f"invalid_agent_run_role={task_id}:{run_role or 'missing'}")
        expected_run_phases = {
            "task_reviewer": {"spec", "quality"},
            "security_reviewer": {"security"},
            "final_reviewer": {"final"},
        }.get(run_role)
        if expected_run_phases is None and run_phase is not None:
            errors.append(f"agent_run_review_phase_not_applicable={task_id}:{run_role}")
        elif expected_run_phases is not None and run_phase not in expected_run_phases:
            errors.append(f"agent_run_review_phase_invalid={task_id}:{run_role}")
        if run_status not in DISPATCH_AGENT_STATUSES:
            errors.append(f"invalid_agent_run_status={task_id}:{run_status or 'missing'}")
        if not isinstance(item.get("attempt"), int) or item.get("attempt", 0) < 1:
            errors.append(f"invalid_agent_run_attempt={task_id}")
        elif item["attempt"] > budget_limit(apply_budget_contract(run), "max_agent_attempts_per_role"):
            errors.append(f"budget_max_agent_attempts_exceeded={task_id}:{run_role}")
        if not safe_agent_id(agent_id):
            errors.append(f"invalid_agent_run_agent_id={task_id}:{agent_id or 'missing'}")
        if item.get("identity_assurance") != "controller_asserted":
            errors.append(f"invalid_agent_run_identity_assurance={task_id}:{run_role or 'missing'}")
        if not item.get("packet_sha256"):
            errors.append(f"agent_run_packet_hash_missing={task_id}")
        if run_status == "spawned" and not item.get("spawned_at"):
            errors.append(f"agent_run_spawned_at_missing={task_id}")
        if run_status in {"completed", "failed"} and not item.get(f"{run_status}_at"):
            errors.append(f"agent_run_result_timestamp_missing={task_id}")
    if isinstance(dispatch, dict) and dispatch.get("status") in DISPATCH_AGENT_STATUSES:
        matching = [
            item
            for item in runs
            if isinstance(item, dict)
            and item.get("role") == dispatch.get("role")
            and item.get("review_phase") == dispatch.get("review_phase")
            and item.get("attempt") == dispatch.get("attempt")
            and item.get("agent_id") == dispatch.get("agent_id")
            and item.get("status") == dispatch.get("status")
            and item.get("packet_sha256") == dispatch.get("packet_sha256")
        ]
        if not matching:
            errors.append(f"dispatch_agent_run_missing={task_id}")
    if run.get("mode") == "subagent_serial" and state == "IMPLEMENTING":
        if not isinstance(dispatch, dict) or dispatch.get("role") != "implementer" or dispatch.get("status") not in {"spawned", "completed"}:
            errors.append(f"subagent_dispatch_spawn_required={task_id}")
    if run.get("mode") == "subagent_serial" and state in {"IMPLEMENTED", "TASK_REVIEW", "SECURITY_REVIEW", "FIXING", "RE_REVIEW", "VERIFIED"}:
        if not agent_run_completed(task, "implementer"):
            errors.append(f"subagent_dispatch_completion_required={task_id}")


def validate_writer_report_bindings(
    run_dir: Path,
    run: dict[str, object],
    task: dict[str, object],
    events: list[dict[str, object]],
    errors: list[str],
) -> None:
    task_id = str(task.get("task_id", ""))
    bindings = task.get("writer_report_bindings")
    if not isinstance(bindings, dict):
        errors.append(f"writer_report_bindings_invalid={task_id}")
        return
    for role in sorted(set(bindings) - {"implementer", "fixer"}):
        errors.append(f"writer_report_binding_role_invalid={task_id}:{role}")

    state = str(task.get("state", ""))
    fix_cycle_count = task.get("fix_cycle_count", 0)
    required_role: str | None = None
    if run.get("mode") == "subagent_serial" and state in {
        "IMPLEMENTED",
        "TASK_REVIEW",
        "FIXING",
        "RE_REVIEW",
        "SECURITY_REVIEW",
        "VERIFIED",
    }:
        required_role = (
            "fixer"
            if isinstance(fix_cycle_count, int) and fix_cycle_count > 0 and state != "FIXING"
            else "implementer"
        )
    if required_role is not None and not isinstance(bindings.get(required_role), dict):
        errors.append(f"writer_report_controller_normalization_required={task_id}:{required_role}")

    event_map = {
        event.get("sequence"): event
        for event in events
        if isinstance(event, dict)
        and isinstance(event.get("sequence"), int)
        and not isinstance(event.get("sequence"), bool)
    }
    for role in ("implementer", "fixer"):
        binding = bindings.get(role)
        if binding is None:
            continue
        if not isinstance(binding, dict):
            errors.append(f"writer_report_binding_invalid={task_id}:{role}")
            continue
        report_name = "Implementer-Report.json" if role == "implementer" else "Fix-Report.json"
        if binding.get("path") != report_name:
            errors.append(f"writer_report_binding_path_mismatch={task_id}:{role}")
            continue
        report_bytes = read_artifact_bytes(
            run_dir / task_id / report_name,
            errors,
            f"{task_id}_{role}_bound_report",
        )
        if report_bytes is None:
            continue
        report = decode_json_artifact(report_bytes, errors, f"{task_id}_{role}_bound_report")
        if not isinstance(report, dict):
            continue
        sequence = binding.get("normalized_event_sequence")
        event = event_map.get(sequence)
        matching_runs = [
            item
            for item in agent_runs(task)
            if isinstance(item, dict)
            and item.get("role") == role
            and item.get("review_phase") is None
            and item.get("agent_id") == binding.get("agent_id")
            and item.get("attempt") == binding.get("attempt")
        ]
        if (
            binding.get("sha256") != sha256_bytes(report_bytes)
            or binding.get("payload_sha256") != canonical_json_digest(report)
            or not matching_runs
            or not isinstance(event, dict)
            or event.get("event_type") != "writer_report_normalized"
            or event.get("task_id") != task_id
            or event.get("role") != role
            or event.get("agent_id") != binding.get("agent_id")
            or event.get("attempt") != binding.get("attempt")
            or event.get("report_path") != report_name
            or event.get("report_sha256") != binding.get("sha256")
            or event.get("controller_supplied_report_payload_sha256") != binding.get("payload_sha256")
        ):
            errors.append(f"writer_report_controller_normalization_required={task_id}:{role}")
            continue
        if role == required_role and not any(item.get("status") == "completed" for item in matching_runs):
            errors.append(f"writer_report_completed_agent_binding_required={task_id}:{role}")


def validate_task_source_binding(root: Path, task: dict[str, object], errors: list[str]) -> None:
    task_id = str(task.get("task_id", ""))
    source_path = task.get("source_subplan_path")
    if not isinstance(source_path, str) or not source_path.strip():
        errors.append(f"missing_source_subplan_path={task_id}")
        return
    binding = implementation_contract_source_binding(root, source_path)
    for error in binding.get("errors", []):
        errors.append(str(error))
    if task.get("source_subplan_sha256") != binding.get("source_subplan_sha256"):
        errors.append(f"source_subplan_sha256_mismatch={task_id}")
    if task.get("implementation_contract") != binding.get("implementation_contract"):
        errors.append(f"implementation_contract_source_mismatch={task_id}")
    if task.get("implementation_contract_digest") != binding.get("implementation_contract_digest"):
        errors.append(f"implementation_contract_digest_source_mismatch={task_id}")
    if task.get("validation_commands") != contract_validation_commands(
        binding.get("implementation_contract") if isinstance(binding.get("implementation_contract"), dict) else {}
    ):
        errors.append(f"validation_commands_source_mismatch={task_id}")
    if task.get("validation_command_ids", []) != binding.get("validation_command_ids", []):
        errors.append(f"validation_command_ids_source_mismatch={task_id}")
    if task.get("parent_acceptance_signal_ids", []) != binding.get("parent_acceptance_signal_ids", []):
        errors.append(f"parent_acceptance_signal_ids_source_mismatch={task_id}")
    if task.get("security_review_required") != binding.get("security_review_required"):
        errors.append(f"security_review_required_source_mismatch={task_id}")
    if task.get("risk_class", "") != binding.get("risk_class", ""):
        errors.append(f"risk_class_source_mismatch={task_id}")
    if task.get("risk_domains", []) != binding.get("risk_domains", []):
        errors.append(f"risk_domains_source_mismatch={task_id}")
    if task.get("task_contract_digest") != task_contract_digest(task):
        errors.append(f"task_contract_digest_mismatch={task_id}")


def validate_task_artifacts(
    run_dir: Path,
    task: dict[str, object],
    errors: list[str],
    *,
    root: Path | None,
    run: dict[str, object],
    task_index: int,
) -> None:
    task_id = str(task.get("task_id", ""))
    state = str(task.get("state", ""))
    if not safe_task_id(task_id):
        errors.append(f"invalid_task_id={task_id or 'missing'}")
        return
    if state not in TASK_STATES:
        errors.append(f"invalid_task_state={task_id}:{state or 'missing'}")
    if task.get("readiness_status") not in READY_STATUSES:
        errors.append(f"non_ready_queue_item={task_id}:{task.get('readiness_status')}")
    severities = {str(item).upper() for item in task.get("finding_ids", []) if isinstance(item, str)}
    if "P0" in severities or "P1" in severities:
        errors.append(f"p0_p1_queue_item_rejected={task_id}")
    for command in task.get("validation_commands", []):
        if not command_is_safe(command, root):
            errors.append(f"unsafe_validation_command={task_id}")
    implementation_contract = task.get("implementation_contract")
    if not isinstance(implementation_contract, dict):
        errors.append(f"implementation_contract_must_be_object={task_id}")
        implementation_contract = {}
    elif implementation_contract:
        expected_commands = contract_validation_commands(implementation_contract)
        if task.get("validation_commands") != expected_commands:
            errors.append(f"implementation_contract_validation_command_mismatch={task_id}")
        if task.get("validation_command_ids") != validation_command_ids(implementation_contract):
            errors.append(f"implementation_contract_validation_command_ids_mismatch={task_id}")
        if task.get("implementation_contract_digest") != canonical_json_digest(implementation_contract):
            errors.append(f"implementation_contract_digest_mismatch={task_id}")
        if task.get("task_contract_digest") != task_contract_digest(task):
            errors.append(f"task_contract_digest_mismatch={task_id}")
        expected_security = implementation_contract.get("security_review_required")
        if isinstance(expected_security, bool) and task.get("security_review_required") is not expected_security:
            errors.append(f"implementation_contract_security_flag_mismatch={task_id}")

    task_dir = run_dir / task_id
    if not is_inside(run_dir, lexical_absolute(task_dir)):
        errors.append(f"invalid_task_id={task_id or 'missing'}")
        return
    try:
        task_metadata = os.lstat(task_dir)
    except FileNotFoundError:
        errors.append(f"missing_task_dir={task_id}")
        return
    if not stat.S_ISDIR(task_metadata.st_mode):
        errors.append(f"invalid_artifact_directory={task_id}")
        return
    brief_text = read_artifact_text(
        task_dir / "Brief.md",
        errors,
        f"{task_id}_task_brief",
        required=False,
    )
    if brief_text is None:
        if f"invalid_artifact_file={task_id}_task_brief" not in errors:
            errors.append(f"missing_task_brief={task_id}")
    else:
        if task.get("brief_sha256") != sha256_bytes(brief_text.encode("utf-8")):
            errors.append(f"task_brief_hash_mismatch={task_id}")
        brief_mode = str(run.get("apply_requested_mode", run.get("mode", "")))
        if brief_text != task_brief_text(task_index, brief_mode, task):
            errors.append(f"task_brief_contract_mismatch={task_id}")

    report_error_count = len(errors)
    implementer = load_json(task_dir / "Implementer-Report.json", errors, f"{task_id}_implementer_report")
    review = load_json(task_dir / "Task-Review.json", errors, f"{task_id}_task_review")
    fix = load_json(task_dir / "Fix-Report.json", errors, f"{task_id}_fix_report")
    if len(errors) != report_error_count or not isinstance(implementer, dict) or not isinstance(review, dict) or not isinstance(fix, dict):
        return
    impl_status = implementer.get("status")
    if impl_status not in IMPLEMENTER_STATUSES and impl_status != "PENDING":
        errors.append(f"invalid_implementer_status={task_id}:{impl_status}")
    if impl_status == "DONE_WITH_CONCERNS" and not implementer.get("controller_decision"):
        errors.append(f"done_with_concerns_requires_controller_decision={task_id}")
    if impl_status == "BLOCKED" and state not in {"BLOCKED", "NEEDS_CONTEXT"}:
        errors.append(f"blocked_task_must_stop_or_replan={task_id}")
    if impl_status == "NEEDS_CONTEXT" and state != "NEEDS_CONTEXT":
        errors.append(f"needs_context_task_must_pause={task_id}")

    spec = review.get("spec_compliance")
    quality = review.get("task_quality")
    security = review.get("security_review", "not_required")
    if spec is not None and spec not in SPEC_VERDICTS and spec != "PENDING":
        errors.append(f"invalid_spec_compliance={task_id}:{spec}")
    if quality is not None and quality not in QUALITY_VERDICTS and quality != "PENDING":
        errors.append(f"invalid_task_quality={task_id}:{quality}")
    if security is not None and security not in SECURITY_VERDICTS and security != "PENDING":
        errors.append(f"invalid_security_review={task_id}:{security}")
    if spec in {"fail", "cannot_verify"} and not review.get("re_review_required"):
        errors.append(f"failed_spec_requires_re_review={task_id}")
    if quality == "needs_fixes" and not review.get("re_review_required"):
        errors.append(f"failed_quality_requires_re_review={task_id}")
    if review.get("re_review_required") is True and not fix.get("fixes"):
        errors.append(f"re_review_requires_fix_report={task_id}")
    fixes = fix.get("fixes")
    if isinstance(fixes, list) and len(fixes) > budget_limit(apply_budget_contract(run), "max_fix_cycles"):
        errors.append(f"budget_max_fix_cycles_exceeded={task_id}")
    review_receipt_map = task.get("review_receipts")
    evidence_chain_complete = (
        isinstance(review_receipt_map, dict)
        and isinstance(review_receipt_map.get("final"), dict)
    )
    if state == "VERIFIED" or evidence_chain_complete:
        for report_name, report in (("implementer", implementer), ("task_review", review)):
            if report.get("implementation_contract_digest") != task.get("implementation_contract_digest"):
                errors.append(f"{report_name}_contract_digest_mismatch={task_id}")
            if report.get("task_contract_digest") != task.get("task_contract_digest"):
                errors.append(f"{report_name}_task_contract_digest_mismatch={task_id}")
        if impl_status != "DONE":
            errors.append(f"verified_requires_done_implementer={task_id}")
        if not implementer.get("brief_sha256") or implementer.get("brief_sha256") != task.get("brief_sha256"):
            errors.append(f"verified_requires_matching_brief_hash={task_id}")
        if not implementer.get("implementer_agent_id"):
            errors.append(f"verified_requires_implementer_agent_id={task_id}")
        files_changed = implementer.get("files_changed")
        normalized_files = {
            normalized
            for normalized in (normalize_reported_repo_path(item) for item in files_changed)
            if normalized
        } if isinstance(files_changed, list) else set()
        if not isinstance(files_changed, list) or not files_changed:
            errors.append(f"verified_requires_files_changed={task_id}")
        elif len(normalized_files) != len(files_changed):
            errors.append(f"verified_files_changed_invalid={task_id}")
        contract_paths = implementation_contract_paths(task)
        for path in sorted(normalized_files - contract_paths):
            errors.append(f"verified_files_changed_not_contract_bound={task_id}:{path}")
        patch_path = task_dir / "Review-Package.patch"
        patch_text = read_artifact_text(
            patch_path,
            errors,
            f"{task_id}_review_package",
            required=False,
        )
        if patch_text is None:
            patch_text = ""
        if not patch_text.strip():
            errors.append(f"verified_requires_nonempty_review_patch={task_id}")
        else:
            patch_sha = sha256_bytes(patch_text.encode("utf-8"))
            if implementer.get("diff_sha256") != patch_sha:
                errors.append(f"verified_diff_hash_mismatch={task_id}")
            patch_files = patch_changed_paths(patch_text)
            if patch_files and normalized_files and patch_files != normalized_files:
                errors.append(f"verified_patch_files_mismatch={task_id}")
        receipt_refs = task.get("validation_receipts")
        receipt_ids = sorted(
            str(item.get("receipt_id"))
            for item in receipt_refs
            if isinstance(receipt_refs, list) and isinstance(item, dict)
        ) if isinstance(receipt_refs, list) else []
        if implementer.get("validation_receipt_ids") != receipt_ids:
            errors.append(f"implementer_validation_receipt_ids_mismatch={task_id}")
        change_set_ref = task.get("change_set")
        if not isinstance(change_set_ref, dict) or implementer.get("change_set_id") != change_set_ref.get("change_set_id"):
            errors.append(f"implementer_change_set_id_mismatch={task_id}")
        if review.get("brief_sha256") != task.get("brief_sha256"):
            errors.append(f"verified_requires_review_brief_hash={task_id}")
        if review.get("status") != "COMPLETE" or review.get("review_receipts") != task.get("review_receipts"):
            errors.append(f"verified_requires_review_receipt_aggregate={task_id}")


def validate_events(
    events: list[dict[str, object]],
    tasks: list[object],
    expected_apply_run_id: object,
    errors: list[str],
) -> None:
    if events and events[0].get("event_type") != "apply_run_initialized":
        errors.append("first_event_must_initialize_apply_run")
    elif events and events[0].get("apply_run_id") != expected_apply_run_id:
        errors.append("initial_event_apply_run_id_mismatch")
    last_state: dict[str, str] = {}
    latest_validation_publish: dict[tuple[str, str], int] = {}
    latest_review_publish: dict[tuple[str, str], int] = {}
    for event in events:
        sequence = event.get("sequence")
        event_task_id = event.get("task_id")
        if isinstance(sequence, int) and not isinstance(sequence, bool) and isinstance(event_task_id, str):
            validation_id = event.get("validation_id")
            if event.get("event_type") == "validation_receipt_published" and isinstance(validation_id, str):
                latest_validation_publish[(event_task_id, validation_id)] = sequence
            review_phase = event.get("review_phase")
            if event.get("event_type") == "review_receipt_published" and isinstance(review_phase, str):
                latest_review_publish[(event_task_id, review_phase)] = sequence
        if event.get("event_type") != "task_transition":
            continue
        task_id = str(event.get("task_id", ""))
        from_state = str(event.get("from", ""))
        to_state = str(event.get("to", ""))
        if not safe_task_id(task_id):
            errors.append(f"invalid_event_task_id={task_id or 'missing'}")
            continue
        if to_state not in STATE_TRANSITIONS.get(from_state, set()):
            errors.append(f"invalid_transition_event={task_id}:{from_state}->{to_state}")
        if task_id in last_state and last_state[task_id] != from_state:
            errors.append(f"non_contiguous_transition_event={task_id}")
        last_state[task_id] = to_state
        evidence = event.get("evidence", [])
        if not isinstance(evidence, list):
            errors.append(f"transition_evidence_must_be_list={task_id}")
    for task in tasks:
        if not isinstance(task, dict):
            continue
        task_id = str(task.get("task_id", ""))
        state = str(task.get("state", ""))
        if state == "BRIEFED" and task_id in last_state:
            errors.append(f"task_state_unexpected_transition_event={task_id}")
        elif state != "BRIEFED" and last_state.get(task_id) != state:
            errors.append(f"task_state_missing_transition_event={task_id}")
        validation_references = task.get("validation_receipts")
        if isinstance(validation_references, list):
            for reference in validation_references:
                if not isinstance(reference, dict):
                    continue
                validation_id = reference.get("validation_id")
                if not isinstance(validation_id, str):
                    continue
                error = f"validation_receipt_not_latest={task_id}:{validation_id}"
                if (
                    latest_validation_publish.get((task_id, validation_id))
                    != reference.get("published_event_sequence")
                    and error not in errors
                ):
                    errors.append(error)
        review_references = task.get("review_receipts")
        if isinstance(review_references, dict):
            for phase, reference in review_references.items():
                if not isinstance(phase, str) or not isinstance(reference, dict):
                    continue
                error = f"review_receipt_not_latest={task_id}:{phase}"
                if (
                    latest_review_publish.get((task_id, phase))
                    != reference.get("published_event_sequence")
                    and error not in errors
                ):
                    errors.append(error)


def validate_writer_lock(run_dir: Path, progress: dict[str, object], tasks: list[object], errors: list[str]) -> None:
    locks = progress.get("active_writer_locks", [])
    if not isinstance(locks, list):
        errors.append("active_writer_locks_must_be_list")
        locks = []
    if len(locks) > 1:
        errors.append("only_one_active_writer_lock_permitted")
    path = run_dir / WRITER_LOCK_NAME
    if locks and not path.is_file():
        errors.append("active_writer_lock_missing_file")
    if path.is_file():
        lock = load_json(path, errors, "writer_lock_json")
        if not isinstance(lock, dict):
            return
        if not locks:
            errors.append("writer_lock_file_without_progress_lock")
        elif lock != locks[0]:
            errors.append("writer_lock_file_progress_mismatch")
        task_id = str(lock.get("task_id", ""))
        owner = str(lock.get("owner", ""))
        if not safe_task_id(task_id):
            errors.append(f"invalid_writer_lock_task_id={task_id or 'missing'}")
        if not owner:
            errors.append("writer_lock_owner_required")
        matching = [task for task in tasks if isinstance(task, dict) and task.get("task_id") == task_id]
        if not matching:
            errors.append(f"writer_lock_unknown_task={task_id}")
            return
        task = matching[0]
        if task.get("writer_lock") != lock:
            errors.append(f"task_writer_lock_mismatch={task_id}")
        if task.get("state") != "IMPLEMENTING":
            errors.append(f"writer_lock_requires_implementing_state={task_id}")
        if lock_expiry(lock) is None:
            errors.append(f"writer_lock_expiry_invalid={task_id}")
        elif lock_is_expired(lock):
            errors.append(f"writer_lock_expired={task_id}")


def validate_agent_profiles(run: dict[str, object], errors: list[str]) -> None:
    profiles = run.get("agent_profiles")
    if not isinstance(profiles, dict):
        errors.append("agent_profiles_missing")
        return
    for role, expected in AGENT_PROFILES.items():
        actual = profiles.get(role)
        if not isinstance(actual, dict):
            errors.append(f"agent_profile_missing={role}")
            continue
        for key, value in expected.items():
            if actual.get(key) != value:
                errors.append(f"agent_profile_mismatch={role}:{key}")


def validate_apply_policy(
    root: Path | None,
    run: dict[str, object],
    mode: str,
    baseline: dict[str, object],
    ready_queue: list[dict[str, object]],
    errors: list[str],
) -> None:
    if root is None or mode not in APPLY_MODES:
        return
    try:
        validation = validate_step4_queue(root, mode)
    except ValueError as exc:
        errors.append(f"apply_policy_step4_readiness_unavailable={exc}")
        return
    readiness = step4_readiness_summary(root, mode, ready_queue, validation)
    expected = apply_policy_envelope(root, mode, baseline, readiness)
    expected_digest = canonical_json_digest(expected)
    if run.get("apply_policy_digest") != expected_digest:
        errors.append("apply_policy_digest_mismatch")
    for key, expected_value in expected.items():
        if key == "external_superpowers" and (
            external_superpowers_reconcile_is_valid(run) or external_superpowers_available_is_valid(run)
        ):
            continue
        if run.get(key) != expected_value:
            errors.append(f"apply_policy_mismatch={key}")


def validate_apply_run(run_dir: Path, root: Path | None = None) -> list[str]:
    errors: list[str] = []
    run_dir = lexical_absolute(run_dir)
    root = root.resolve() if root else infer_root(run_dir)
    if root is None:
        errors.append("source_binding_root_required")
    run = load_json(run_dir / "Apply-Run.json", errors, "apply_run_json")
    progress = load_json(run_dir / "Progress.json", errors, "progress_json")
    final_review = load_json(run_dir / "Final-Review.json", errors, "final_review_json")
    result = load_json(run_dir / "Result.json", errors, "result_json")
    events = load_events(run_dir, errors)
    if errors or not isinstance(run, dict) or not isinstance(progress, dict):
        return errors
    schema_version = run.get("apply_run_schema_version")
    if (
        (schema_version == APPLY_RUN_SCHEMA_VERSION or run.get("apply_run_registration_id") is not None)
        and root is not None
        and not current_apply_run_provenance_is_valid(root, run_dir, run)
    ):
        errors.append("apply_run_provenance_unverified")

    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in SUPPORTED_APPLY_RUN_SCHEMA_VERSIONS
    ):
        errors.append("invalid_apply_run_schema_version")
    if run.get("artifact_schema_version") != ARTIFACT_SCHEMA_VERSION:
        errors.append("invalid_artifact_schema_version")
    if run.get("handoff_contract_version") != HANDOFF_CONTRACT_VERSION:
        errors.append("invalid_handoff_contract_version")
    if run.get("plugin_version") != PLUGIN_VERSION:
        errors.append("invalid_plugin_version")
    if run.get("mode") not in APPLY_MODES:
        errors.append(f"invalid_mode={run.get('mode')}")
    requested_mode = str(run.get("apply_requested_mode", run.get("mode", "")))
    if requested_mode not in APPLY_MODES:
        errors.append(f"invalid_apply_requested_mode={requested_mode or 'missing'}")
    source_snapshot = run.get("source_snapshot")
    if not isinstance(source_snapshot, list):
        errors.append("invalid_source_snapshot")
        source_snapshot = []
    spec_inputs = run.get("apply_spec_inputs")
    ready_queue: list[dict[str, object]] = []
    spec_workspace_baseline: object = {}
    if isinstance(spec_inputs, dict) and isinstance(spec_inputs.get("ready_queue"), list):
        for item in spec_inputs["ready_queue"]:
            if isinstance(item, dict):
                ready_queue.append(json.loads(json.dumps(item, sort_keys=True)))
            else:
                errors.append("invalid_apply_spec_ready_queue")
                break
        spec_workspace_baseline = spec_inputs.get("workspace_baseline", {})
        if not isinstance(spec_workspace_baseline, dict):
            errors.append("invalid_apply_spec_workspace_baseline")
            spec_workspace_baseline = {}
        elif not spec_workspace_baseline:
            errors.append("missing_apply_spec_workspace_baseline")
    else:
        errors.append("missing_apply_spec_inputs")
    digest_schema_version = (
        schema_version if isinstance(schema_version, int) and not isinstance(schema_version, bool) else APPLY_RUN_SCHEMA_VERSION
    )
    spec_digest = apply_spec_digest(
        requested_mode,
        source_snapshot,
        spec_workspace_baseline,
        ready_queue,
        apply_run_schema_version=digest_schema_version,
    )
    if run.get("apply_spec_digest") != spec_digest:
        errors.append("stored_apply_spec_digest_mismatch")
    if run.get("apply_spec_id") != f"apply-spec-{requested_mode}-{spec_digest[:16]}":
        errors.append("stored_apply_spec_id_mismatch")
    invocation = str(run.get("apply_run_invocation_id", ""))
    if not invocation or invocation_suffix(invocation) != invocation:
        errors.append("invalid_apply_run_invocation_id")
    registration_id = run.get("apply_run_registration_id")
    if schema_version == APPLY_RUN_SCHEMA_VERSION and registration_id is None:
        errors.append("missing_apply_run_registration_id")
    elif registration_id is not None and (
        not isinstance(registration_id, str) or re.fullmatch(r"[a-f0-9]{64}", registration_id) is None
    ):
        errors.append("invalid_apply_run_registration_id")
    expected_run_id = f"apply-{requested_mode}-{spec_digest[:12]}-{invocation}" if invocation else ""
    if run.get("apply_run_id") != expected_run_id:
        errors.append("stored_apply_run_id_mismatch")
    if run.get("source_snapshot_digest") != snapshot_digest(source_snapshot):
        errors.append("stored_source_snapshot_digest_mismatch")
    tasks_for_drift = progress.get("tasks", [])
    if not isinstance(tasks_for_drift, list):
        tasks_for_drift = []
    try:
        implementation_drift = (
            implementation_workspace_drift(root, run_dir, tasks_for_drift, run)
            if root is not None
            else {"allowed": False, "changed_paths": set(), "allowed_paths": set()}
        )
    except (OSError, TypeError, ValueError) as exc:
        implementation_drift = {"allowed": False, "changed_paths": set(), "allowed_paths": set()}
        errors.append(f"workspace_scope_validation_unavailable={exc}")
    readiness = run.get("step4_readiness")
    if (
        not isinstance(readiness, dict)
        or not readiness.get("validator_command")
        or readiness.get("execution_gate") != "step4_validator_must_pass_before_product_changes"
    ):
        errors.append("step4_readiness_summary_missing")
    if run.get("commit_policy") != "none":
        errors.append("commit_policy_must_default_to_none")
    if run.get("push_allowed") is not False:
        errors.append("push_must_default_false")
    if run.get("pr_allowed") is not False:
        errors.append("pr_must_default_false")
    if run.get("max_writer_agents") != 1:
        errors.append("only_one_writer_permitted")
    if run.get("max_subagent_depth") != 1:
        errors.append("recursive_subagents_rejected")
    budget_contract = apply_budget_contract(run)
    errors.extend(validate_budget_contract(run.get("budget_contract")))
    errors.extend(validate_token_usage(run.get("token_usage")))
    if isinstance(result, dict):
        errors.extend(validate_budget_contract(result.get("budget_contract"), "result_budget_contract"))
        errors.extend(validate_token_usage(result.get("token_usage"), "result_token_usage"))
    if not isinstance(run.get("workspace_requested"), str):
        errors.append("workspace_requested_missing")
    if not isinstance(run.get("workspace_detected"), str):
        errors.append("workspace_detected_missing")
    if not isinstance(run.get("workspace_verified"), bool):
        errors.append("workspace_verified_must_be_boolean")
    if not isinstance(run.get("workspace_mode"), str):
        errors.append("workspace_mode_missing")
    if not isinstance(run.get("worktree_path"), str):
        errors.append("worktree_path_missing")
    if not isinstance(run.get("base_branch"), str):
        errors.append("base_branch_missing")
    if not isinstance(run.get("working_branch"), str):
        errors.append("working_branch_missing")
    if not isinstance(run.get("dirty_state"), str):
        errors.append("dirty_state_missing")
    if not isinstance(run.get("user_approval"), bool):
        errors.append("user_approval_must_be_boolean")
    validate_agent_profiles(run, errors)
    external = run.get("external_superpowers", {})
    if run.get("mode") == "external_superpowers":
        if not isinstance(external, dict):
            errors.append("external_superpowers_policy_missing")
        else:
            availability = external.get("availability")
            if availability == "not_checked":
                errors.append("external_superpowers_readiness_not_checked")
            elif availability == "unavailable":
                if external.get("fallback_mode") != "subagent_serial":
                    errors.append("external_superpowers_unavailable_requires_subagent_serial_fallback")
                errors.append("external_superpowers_unavailable_must_reconcile_mode")
            elif availability == "available":
                for key in ("version", "source_path", "adapter_policy"):
                    if not external.get(key):
                        errors.append(f"external_superpowers_available_metadata_missing={key}")
                if external.get("license_acknowledged") is not True:
                    errors.append("external_superpowers_license_acknowledgement_required")
            else:
                errors.append(f"external_superpowers_invalid_availability={availability}")
    elif isinstance(external, dict) and external.get("required") is True and external.get("availability") == "unavailable":
        if run.get("mode") != "subagent_serial" or external.get("reconciled_to") != "subagent_serial":
            errors.append("external_superpowers_unavailable_must_reconcile_mode")

    snapshot_baseline: dict[str, object] | None = None
    baseline = run.get("workspace_baseline")
    if not isinstance(baseline, dict):
        errors.append("workspace_baseline_missing")
    else:
        stored_workspace_manifest = run.get("workspace_file_manifest")
        if (
            workspace_file_manifest_map(stored_workspace_manifest) is None
            or stored_workspace_manifest != sorted(stored_workspace_manifest)
        ):
            errors.append("workspace_file_manifest_invalid")
        elif (
            hash_inventory(stored_workspace_manifest) != baseline.get("workspace_file_inventory_sha256")
            or len(stored_workspace_manifest) != baseline.get("workspace_file_count")
        ):
            errors.append("workspace_file_manifest_digest_mismatch")
        for key in WORKSPACE_BASELINE_KEYS:
            if key not in baseline:
                errors.append(f"workspace_baseline_missing={key}")
        if isinstance(spec_workspace_baseline, dict):
            for key in WORKSPACE_BASELINE_KEYS:
                if key in baseline and spec_workspace_baseline.get(key) != baseline.get(key):
                    errors.append(f"apply_spec_workspace_baseline_mismatch={key}")
        if run.get("workspace_detected") != baseline.get("vcs"):
            errors.append("workspace_detected_baseline_mismatch")
        expected_dirty_state = workspace_dirty_state(baseline)
        if run.get("dirty_state") != expected_dirty_state:
            errors.append("dirty_state_baseline_mismatch")
        if baseline.get("vcs") == "git" and run.get("working_branch") != baseline.get("branch"):
            errors.append("working_branch_baseline_mismatch")
        if run.get("mode") != "no_action" and baseline.get("vcs") == "non_git":
            if run.get("workspace_mode") != "non_git_unsafe":
                errors.append("non_git_workspace_requires_non_git_unsafe_mode")
            if run.get("user_approval") is not True:
                errors.append("non_git_workspace_requires_user_approval")
        if baseline.get("vcs") != "non_git" and run.get("workspace_mode") == "non_git_unsafe":
            errors.append("non_git_unsafe_mode_requires_non_git_workspace")
        if run.get("mode") != "no_action" and git_worktree_requires_approval(baseline):
            if run.get("workspace_mode") != "unverified_current_worktree":
                errors.append("git_workspace_requires_unverified_current_worktree_mode")
            if run.get("user_approval") is not True:
                errors.append("git_workspace_requires_user_approval")
        if root is not None:
            try:
                current_baseline = workspace_baseline(root)
            except (OSError, TypeError, ValueError) as exc:
                failure = f"workspace_scope_validation_unavailable={exc}"
                if failure not in errors:
                    errors.append(failure)
            else:
                snapshot_baseline = current_baseline
                for key in WORKSPACE_BASELINE_KEYS:
                    if key in baseline and baseline.get(key) != current_baseline.get(key):
                        if implementation_drift.get("allowed") is True and key in IMPLEMENTATION_DRIFT_BASELINE_KEYS:
                            continue
                        errors.append(f"workspace_baseline_mismatch={key}")
        validate_apply_policy(root, run, requested_mode, baseline, ready_queue, errors)

    if root is not None:
        try:
            current_snapshot = collect_snapshot(root, snapshot_baseline)
        except (OSError, TypeError, ValueError) as exc:
            failure = f"workspace_scope_validation_unavailable={exc}"
            if failure not in errors:
                errors.append(failure)
        else:
            if run.get("source_snapshot_digest") != snapshot_digest(current_snapshot):
                if not (
                    implementation_drift.get("allowed") is True
                    and snapshot_matches_except(source_snapshot, current_snapshot, IMPLEMENTATION_DRIFT_SNAPSHOT_PATHS)
                ):
                    errors.append("source_snapshot_mismatch")

    tasks = progress.get("tasks", [])
    if not isinstance(tasks, list):
        errors.append("progress_tasks_must_be_list")
        tasks = []
    if len(tasks) > budget_limit(budget_contract, "max_selected_tasks"):
        errors.append("budget_selected_tasks_exceeded")
    if run.get("verification_policy") != VERIFICATION_POLICY:
        errors.append("verification_policy_mismatch")
    repository_baselines = run.get("repository_baselines")
    if not isinstance(repository_baselines, list):
        errors.append("repository_baselines_missing")
        repository_baselines = []
    baseline_ids = [str(item.get("task_id", "")) for item in repository_baselines if isinstance(item, dict)]
    if len(baseline_ids) != len(set(baseline_ids)):
        errors.append("duplicate_repository_baseline_task_id")
    task_ids: set[str] = set()
    if run.get("mode") == "no_action" and tasks:
        errors.append("no_action_must_not_have_tasks")
    if run.get("mode") == "no_action":
        if progress.get("final_review_required") is not False:
            errors.append("no_action_final_review_must_be_false")
        if isinstance(result, dict) and result.get("status") != "no_action":
            errors.append("no_action_result_status_mismatch")
    for task in tasks:
        if not isinstance(task, dict):
            errors.append("progress_task_must_be_object")
            continue
        task_id = str(task.get("task_id", ""))
        if task_id in task_ids:
            errors.append(f"duplicate_task_id={task_id}")
        task_ids.add(task_id)
        evidence_status = task.get("evidence_chain_status")
        if evidence_status not in {"not_started", "in_progress", "complete_unattested"}:
            errors.append(f"invalid_evidence_chain_status={task_id}")
        if task.get("verification_assurance") != "controller_asserted":
            errors.append(f"invalid_verification_assurance={task_id}")
        receipt_map = task.get("review_receipts")
        has_final_receipt = isinstance(receipt_map, dict) and isinstance(receipt_map.get("final"), dict)
        if has_final_receipt and evidence_status != "complete_unattested":
            errors.append(f"complete_review_chain_must_remain_unattested={task_id}")
        if not has_final_receipt and evidence_status == "complete_unattested":
            errors.append(f"unattested_evidence_chain_requires_final_receipt={task_id}")
        fix_cycle_count = task.get("fix_cycle_count", 0)
        if not isinstance(fix_cycle_count, int) or isinstance(fix_cycle_count, bool) or fix_cycle_count < 0:
            errors.append(f"fix_cycle_count_invalid={task_id}")
        elif fix_cycle_count > budget_limit(budget_contract, "max_fix_cycles"):
            errors.append(f"budget_max_fix_cycles_exceeded={task_id}")
        runs = task.get("agent_runs", [])
        if isinstance(runs, list):
            for run_item in runs:
                if not isinstance(run_item, dict):
                    continue
                attempt = run_item.get("attempt")
                role = str(run_item.get("role", ""))
                if isinstance(attempt, int) and not isinstance(attempt, bool) and attempt > budget_limit(
                    budget_contract,
                    "max_agent_attempts_per_role",
                ):
                    errors.append(f"budget_max_agent_attempts_exceeded={task_id}:{role or 'missing'}")
        if task.get("state") == "VERIFIED" and task.get("redispatch_count", 0) not in {0, None}:
            errors.append(f"verified_task_not_redispatched={task_id}")
        task_baseline = repository_baseline_for_task(run, task_id)
        if task_baseline is None:
            errors.append(f"repository_baseline_missing={task_id}")
        else:
            try:
                if task_baseline.get("allowed_paths") != sorted(implementation_contract_paths(task)):
                    errors.append(f"repository_baseline_path_mismatch={task_id}")
                if task_baseline.get("implementation_contract_digest") != task.get("implementation_contract_digest"):
                    errors.append(f"repository_baseline_contract_mismatch={task_id}")
                if task_baseline.get("baseline_digest") != repository_baseline_digest(task_baseline.get("snapshot", [])):
                    errors.append(f"repository_baseline_digest_mismatch={task_id}")
                baseline_content_map(task_baseline)
            except (TypeError, ValueError) as exc:
                errors.append(f"repository_baseline_invalid={task_id}:{exc}")
    source_task_digests: dict[str, str] = {}
    for index, task in enumerate([item for item in tasks if isinstance(item, dict)], start=1):
        task_id = str(task.get("task_id", ""))
        if root is not None:
            validate_task_source_binding(root, task, errors)
        source_path = task.get("source_subplan_path")
        digest = task.get("task_contract_digest")
        if isinstance(source_path, str) and isinstance(digest, str):
            previous = source_task_digests.get(source_path)
            if previous is not None and previous != digest:
                errors.append(f"duplicate_task_source_subplan_mismatch={source_path}")
            source_task_digests[source_path] = digest
        validate_dispatch_packet(run_dir, run, task, errors)
        validate_task_artifacts(run_dir, task, errors, root=root, run=run, task_index=index)
        validate_writer_report_bindings(run_dir, run, task, events, errors)

    evidence_chain_tasks = [
        item
        for item in tasks
        if isinstance(item, dict)
        and (
            item.get("state") == "VERIFIED"
            or isinstance(item.get("review_receipts"), dict)
            and isinstance(item["review_receipts"].get("final"), dict)
        )
    ]
    if evidence_chain_tasks:
        try:
            with open_verified_apply_run_for_read(run_dir) as evidence_handle:
                evidence_progress = secure_read_regular_json_at(evidence_handle.run_fd, "Progress.json")
                for evidence_task in evidence_chain_tasks:
                    live_task = find_task(evidence_progress, str(evidence_task.get("task_id", "")))
                    errors.extend(
                        task_verification_errors(
                            evidence_handle,
                            live_task,
                            require_host_attestation=evidence_task.get("state") == "VERIFIED",
                        )
                    )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"evidence_receipt_validation_unavailable={exc}")

    validate_events(events, tasks, run.get("apply_run_id"), errors)
    validate_writer_lock(run_dir, progress, tasks, errors)
    if progress.get("final_review_required") is True:
        if not isinstance(final_review, dict) or final_review.get("status") not in {
            "pass",
            "in_progress",
            "not_started",
        }:
            errors.append("final_review_required")
        if all(isinstance(task, dict) and task.get("state") == "VERIFIED" for task in tasks) and final_review.get("status") != "pass":
            errors.append("final_review_required")
        if final_review.get("status") in {"in_progress", "pass"}:
            expected_reviewed = sorted(
                str(task.get("task_id"))
                for task in tasks
                if isinstance(task, dict)
                and isinstance(task.get("review_receipts"), dict)
                and isinstance(task["review_receipts"].get("final"), dict)
                and task["review_receipts"]["final"].get("verdict") == "pass"
            )
            expected_final_receipts = [
                task["review_receipts"]["final"]
                for task in tasks
                if isinstance(task, dict)
                and isinstance(task.get("review_receipts"), dict)
                and isinstance(task["review_receipts"].get("final"), dict)
            ]
            expected_validation_receipts = [
                reference
                for task in tasks
                if isinstance(task, dict)
                for reference in task.get("validation_receipts", [])
                if isinstance(reference, dict)
            ]
            if final_review.get("reviewed_task_ids") != expected_reviewed:
                errors.append("final_review_reviewed_tasks_mismatch")
            if final_review.get("final_reviewer_receipts") != expected_final_receipts:
                errors.append("final_review_reviewer_receipts_mismatch")
            if final_review.get("validation_receipts") != expected_validation_receipts:
                errors.append("final_review_validation_receipts_mismatch")
            if not isinstance(final_review.get("final_reviewer_receipts"), list) or not final_review.get(
                "final_reviewer_receipts"
            ):
                errors.append("final_review_requires_final_reviewer_receipts")
            if not isinstance(final_review.get("validation_receipts"), list) or not final_review.get(
                "validation_receipts"
            ):
                errors.append("final_review_requires_validation_receipts")
            if final_review.get("status") == "pass" and set(expected_reviewed) != task_ids:
                errors.append("final_review_must_cover_selected_tasks")
            if final_review.get("status") == "in_progress" and set(expected_reviewed) == task_ids:
                errors.append("final_review_complete_must_pass")
            if (
                final_review.get("status") == "pass"
                and len(expected_final_receipts) != len(task_ids)
                and "final_review_requires_final_reviewer_receipts" not in errors
            ):
                errors.append("final_review_requires_final_reviewer_receipts")
            if not expected_validation_receipts and "final_review_requires_validation_receipts" not in errors:
                errors.append("final_review_requires_validation_receipts")
    return errors


def print_safe_field(name: str, value: object, *, file=None) -> None:
    print(f"{name}={safe_log_text(value)}", file=file)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, f"{safe_log_text(self.prog)}: error: {safe_log_text(message)}\n")


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="apply_run.py", description="Manage CodexQB apply-run artifact contracts.")
    sub = parser.add_subparsers(dest="command", required=True)
    for command_name in ("init", "prepare"):
        prepare = sub.add_parser(command_name, help="Create an apply-run artifact directory.")
        prepare.add_argument("--root", default=".")
        prepare.add_argument("--mode", default="subagent_serial", choices=sorted(APPLY_MODES))
        prepare.add_argument("--output-dir")
        prepare.add_argument("--replace", action="store_true")
        prepare.add_argument("--resume", action="store_true")
        prepare.add_argument("--run-id-suffix")
        prepare.add_argument("--allow-non-git-unsafe", action="store_true")
        prepare.add_argument("--allow-unverified-git-worktree", action="store_true")
    check = sub.add_parser("validate", help="Validate an apply-run artifact directory.")
    check.add_argument("--run-dir", required=True)
    check.add_argument("--root")
    transition = sub.add_parser("transition", help="Apply one checked task state transition and append Events.jsonl.")
    transition.add_argument("--run-dir", required=True)
    transition.add_argument("--task-id", required=True)
    transition.add_argument("--to", required=True, choices=sorted(TASK_STATES))
    transition.add_argument("--actor", required=True)
    transition.add_argument("--evidence", action="append", default=[])
    dispatch = sub.add_parser("dispatch", help="Prepare a fresh-context Codex subagent dispatch packet.")
    dispatch.add_argument("--run-dir", required=True)
    dispatch.add_argument("--task-id", required=True)
    dispatch.add_argument("--role", default="implementer", choices=sorted(DISPATCH_ROLES))
    dispatch.add_argument("--review-phase", choices=sorted(REVIEW_PHASES))
    dispatch.add_argument("--actor", required=True)
    dispatch.add_argument("--evidence", action="append", default=[])
    record_agent = sub.add_parser("record-agent", help="Record a spawned/completed/failed Codex subagent result.")
    record_agent.add_argument("--run-dir", required=True)
    record_agent.add_argument("--task-id", required=True)
    record_agent.add_argument("--role", default="implementer", choices=sorted(DISPATCH_ROLES))
    record_agent.add_argument("--agent-id", required=True)
    record_agent.add_argument("--status", required=True, choices=sorted(DISPATCH_AGENT_STATUSES))
    record_agent.add_argument("--review-phase", choices=sorted(REVIEW_PHASES))
    record_agent.add_argument("--actor", required=True)
    record_agent.add_argument("--summary")
    record_agent.add_argument("--evidence", action="append", default=[])
    normalize_writer = sub.add_parser(
        "normalize-writer",
        help="Normalize a writer's structured JSON return through controller-owned artifact I/O.",
    )
    normalize_writer.add_argument("--run-dir", required=True)
    normalize_writer.add_argument("--task-id", required=True)
    normalize_writer.add_argument("--role", required=True, choices=["fixer", "implementer"])
    normalize_writer.add_argument("--agent-id", required=True)
    normalize_writer.add_argument("--report-json", required=True)
    normalize_writer.add_argument("--actor", required=True)
    normalize_writer.add_argument("--evidence", action="append", default=[])
    normalize_review = sub.add_parser(
        "normalize-review",
        help="Normalize a read-only reviewer's structured JSON return into its phase artifact.",
    )
    normalize_review.add_argument("--run-dir", required=True)
    normalize_review.add_argument("--task-id", required=True)
    normalize_review.add_argument("--review-phase", required=True, choices=sorted(REVIEW_PHASES))
    normalize_review.add_argument("--agent-id", required=True)
    normalize_review.add_argument("--report-json", required=True)
    normalize_review.add_argument("--actor", required=True)
    normalize_review.add_argument("--evidence", action="append", default=[])
    capture_evidence = sub.add_parser("capture-evidence", help="Capture a controller-owned live task change set.")
    capture_evidence.add_argument("--run-dir", required=True)
    capture_evidence.add_argument("--task-id", required=True)
    capture_evidence.add_argument("--actor", required=True)
    capture_evidence.add_argument("--evidence", action="append", default=[])
    run_validation = sub.add_parser("run-validation", help="Execute one exact planned command and publish its receipt.")
    run_validation.add_argument("--run-dir", required=True)
    run_validation.add_argument("--task-id", required=True)
    run_validation.add_argument("--validation-id", required=True)
    run_validation.add_argument("--actor", required=True)
    run_validation.add_argument("--evidence", action="append", default=[])
    publish_review = sub.add_parser("publish-review", help="Publish a signed completed reviewer receipt.")
    publish_review.add_argument("--run-dir", required=True)
    publish_review.add_argument("--task-id", required=True)
    publish_review.add_argument("--review-phase", required=True, choices=sorted(REVIEW_PHASES))
    publish_review.add_argument("--actor", required=True)
    publish_review.add_argument("--evidence", action="append", default=[])
    reconcile = sub.add_parser("reconcile", help="Reconcile external adapter readiness before dispatch.")
    reconcile.add_argument("--run-dir", required=True)
    recover = sub.add_parser("recover-lock", help="Recover an expired writer lock to BLOCKED or NEEDS_CONTEXT.")
    recover.add_argument("--run-dir", required=True)
    recover.add_argument("--task-id", required=True)
    recover.add_argument("--to", required=True, choices=["BLOCKED", "NEEDS_CONTEXT"])
    recover.add_argument("--actor", required=True)
    recover.add_argument("--evidence", action="append", default=[])
    finalize = sub.add_parser("finalize", help="Finalize a validated apply-run artifact directory.")
    finalize.add_argument("--run-dir", required=True)
    finalize.add_argument("--actor", required=True)
    finalize.add_argument("--evidence", action="append", default=[])
    args = parser.parse_args(argv)

    try:
        if args.command in {"init", "prepare"}:
            result = create_apply_run(
                Path(args.root),
                args.mode,
                Path(args.output_dir) if args.output_dir else None,
                replace=args.replace,
                resume=args.resume,
                run_id_suffix=args.run_id_suffix,
                allow_non_git_unsafe=args.allow_non_git_unsafe,
                allow_unverified_git_worktree=args.allow_unverified_git_worktree,
            )
            print("apply_run_status=initialized")
            print_safe_field("apply_run_id", result["apply_run_id"])
            print_safe_field("run_dir", result["run_dir"])
            return 0
        if args.command == "transition":
            event = transition_task_state(Path(args.run_dir), args.task_id, args.to, args.actor, args.evidence)
            print("apply_run_status=transitioned")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("state", args.to)
            return 0
        if args.command == "dispatch":
            result = prepare_dispatch_packet(
                Path(args.run_dir),
                args.task_id,
                args.role,
                args.actor,
                args.evidence,
                args.review_phase,
            )
            event = result["event"]
            print("apply_run_status=dispatch_packet_ready")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("role", args.role)
            print_safe_field("packet_path", result["packet_path"])
            print_safe_field("packet_sha256", result["packet_sha256"])
            return 0
        if args.command == "record-agent":
            event = record_agent_status(
                Path(args.run_dir),
                args.task_id,
                args.role,
                args.agent_id,
                args.status,
                args.actor,
                args.evidence,
                args.summary,
                args.review_phase,
            )
            print("apply_run_status=agent_recorded")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("role", args.role)
            print_safe_field("agent_id", args.agent_id)
            print_safe_field("agent_status", args.status)
            return 0
        if args.command == "normalize-writer":
            result = normalize_writer_report(
                Path(args.run_dir),
                args.task_id,
                args.role,
                args.agent_id,
                parse_safe_persistent_json(args.report_json),
                args.actor,
                args.evidence,
            )
            event = result["event"]
            print("apply_run_status=writer_report_normalized")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("role", args.role)
            print_safe_field("report_path", result["report_path"])
            print_safe_field("report_sha256", result["report_sha256"])
            return 0
        if args.command == "normalize-review":
            result = normalize_review_report(
                Path(args.run_dir),
                args.task_id,
                args.review_phase,
                args.agent_id,
                parse_safe_persistent_json(args.report_json),
                args.actor,
                args.evidence,
            )
            event = result["event"]
            print("apply_run_status=review_report_normalized")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("review_phase", args.review_phase)
            print_safe_field("report_path", result["report_path"])
            print_safe_field("report_sha256", result["report_sha256"])
            return 0
        if args.command == "capture-evidence":
            result = capture_task_change_set(
                Path(args.run_dir), args.task_id, args.actor, args.evidence
            )
            print("apply_run_status=change_set_captured")
            print_safe_field("task_id", args.task_id)
            print_safe_field("change_set_id", result["change_set_id"])
            print_safe_field("change_set_path", result["change_set_path"])
            print_safe_field("repository_state_digest", result["repository_state_digest"])
            return 0
        if args.command == "run-validation":
            result = execute_planned_validation(
                Path(args.run_dir),
                args.task_id,
                args.validation_id,
                args.actor,
                args.evidence,
            )
            print("apply_run_status=validation_receipt_published")
            print_safe_field("task_id", args.task_id)
            print_safe_field("validation_id", args.validation_id)
            print_safe_field("receipt_id", result["receipt_id"])
            print_safe_field("receipt_path", result["receipt_path"])
            print_safe_field("exit_code", result["exit_code"])
            return 0
        if args.command == "publish-review":
            result = publish_review_completion(
                Path(args.run_dir),
                args.task_id,
                args.review_phase,
                args.actor,
                args.evidence,
            )
            print("apply_run_status=review_receipt_published")
            print_safe_field("task_id", args.task_id)
            print_safe_field("review_phase", args.review_phase)
            print_safe_field("receipt_id", result["receipt_id"])
            print_safe_field("receipt_path", result["receipt_path"])
            return 0
        if args.command == "reconcile":
            result = reconcile_external_superpowers(Path(args.run_dir))
            print_safe_field("apply_run_status", result["state"])
            print_safe_field("mode", result["mode"])
            if "event_sequence" in result:
                print_safe_field("event_sequence", result["event_sequence"])
            return 0
        if args.command == "recover-lock":
            event = recover_stale_writer_lock(Path(args.run_dir), args.task_id, args.to, args.actor, args.evidence)
            print("apply_run_status=recovered")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("state", args.to)
            return 0
        if args.command == "finalize":
            event = finalize_apply_run(Path(args.run_dir), args.actor, args.evidence)
            print("apply_run_status=finalized")
            print_safe_field("event_sequence", event["sequence"])
            return 0
        errors = validate_apply_run(Path(args.run_dir), Path(args.root) if args.root else None)
    except Exception as exc:
        print("apply_run_status=failed", file=sys.stderr)
        print_safe_field("error", exc, file=sys.stderr)
        return 1
    if errors:
        print("apply_run_status=failed")
        for error in errors:
            print_safe_field("error", error)
        return 1
    print("apply_run_status=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
