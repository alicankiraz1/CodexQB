#!/usr/bin/env python3
"""Create and validate CodexQB Step 4 apply-run artifacts.

This script manages artifact contracts and can execute only the exact planned,
safe validation commands through ``run-validation``. It does not implement
code, call Codex tools, commit, push, create PRs, deploy, or mutate external
systems.
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

if __name__ == "__main__" and not _launcher_admission_is_valid("apply_run.py"):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\n"
    )
    raise SystemExit(2)


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
import re
import secrets
import stat
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
    implementation_contract_binding_from_bytes,
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
from evidence_contracts import (  # noqa: E402
    CONTROLLER_OBSERVER,
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
)
from repository_io import (  # noqa: E402
    ControllerRootProof,
    RepositoryIO,
    RepositoryIOPolicy,
    _controller_baseline_digest as controller_baseline_digest,
    _controller_canonical_root as canonical_repository_root,
    _controller_evidence_digest as controller_evidence_digest,
    _controller_evidence_from_snapshots as controller_evidence_from_snapshots,
    _controller_inventory as controller_inventory,
    _controller_normalize_path as controller_normalize_path,
    _controller_read_bytes as controller_read_bytes,
    _controller_root_proof as controller_root_proof,
    _controller_regular_paths as controller_regular_paths,
    _controller_snapshot_paths as controller_snapshot_paths,
    _controller_validation_cwd as controller_validation_cwd,
    _controller_workspace_proof as controller_workspace_proof,
    open_repository_io,
)
from controller_store import (  # noqa: E402
    APPLY_RUN_MUTATION,
    APPLY_RUN_COMPONENTS,
    CONTROLLER_O_CLOEXEC,
    CONTROLLER_O_CREAT,
    CONTROLLER_O_DIRECTORY,
    CONTROLLER_O_EXCL,
    CONTROLLER_O_NOFOLLOW,
    CONTROLLER_O_NONBLOCK,
    CONTROLLER_O_RDONLY,
    CONTROLLER_O_WRONLY,
    READ_ONLY_EVIDENCE,
    RUN_REPLACE_QUARANTINE_DELETE,
    ControllerStatResult,
    MountResolution,
    apply_runs_root as controller_apply_runs_root,
    canonical_repository_root as canonical_controller_repository_root,
    controller_atomic_write_bytes as secure_atomic_write_bytes_at,
    controller_atomic_write_json as secure_atomic_write_json_at,
    controller_atomic_write_text as secure_atomic_write_text_at,
    controller_directory_entry_matches as secure_directory_entry_matches,
    controller_chmod,
    controller_close,
    controller_dup,
    controller_effective_uid,
    controller_entry_exists,
    controller_fchmod,
    controller_fsencode,
    controller_fstat,
    controller_fsync,
    controller_lexical_absolute,
    controller_listdir,
    controller_lstat,
    controller_locked_directory as locked_directory,
    controller_mkdir,
    controller_open,
    open_controller_trust_root_fd,
    controller_path_is_mount,
    controller_path_normalized,
    controller_path_real_normalized,
    controller_process_id,
    controller_read,
    controller_read_bytes as secure_read_regular_bytes_at,
    controller_read_json as secure_read_regular_json_at,
    controller_read_text as secure_read_regular_text_at,
    controller_read_unvalidated_bytes as secure_read_regular_unvalidated_bytes_at,
    controller_regular_metadata as regular_target_metadata_at,
    controller_regular_entry_exists,
    controller_rmdir,
    controller_stat,
    controller_strerror,
    controller_require_mount_assurance as require_mount_assurance,
    controller_require_same_mount as require_same_mount,
    controller_resolve_mount_identity as resolve_mount_identity,
    controller_tree_is_private,
    controller_unlink,
    controller_unlink_regular as secure_unlink_regular_at,
    controller_write,
    legacy_apply_runs_root,
    open_controller_runs_root,
)
from execution_controller import (  # noqa: E402
    ValidationProcessResult,
    run_bounded_validation_process,
    run_step4_readiness_validator,
)


ARTIFACT_SCHEMA_VERSION = 3
HANDOFF_CONTRACT_VERSION = 2
APPLY_RUN_SCHEMA_VERSION = 3
SUPPORTED_APPLY_RUN_SCHEMA_VERSIONS = frozenset({APPLY_RUN_SCHEMA_VERSION})
PLUGIN_VERSION = "0.3.0"
MAX_WORKSPACE_INVENTORY_FILE_BYTES = DEFAULT_WORKSPACE_INVENTORY_MAX_FILE_BYTES
MAX_WORKSPACE_INVENTORY_TOTAL_BYTES = DEFAULT_WORKSPACE_INVENTORY_MAX_TOTAL_BYTES
MAX_WORKSPACE_INVENTORY_PATHS = DEFAULT_WORKSPACE_INVENTORY_MAX_PATHS
WORKSPACE_INVENTORY_TIMEOUT_SECONDS = DEFAULT_WORKSPACE_INVENTORY_TIMEOUT_SECONDS
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
    "controller_state_owner_only": True,
    "legacy_repository_apply_runs_archive_only": True,
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
CONTROLLER_STDIN_REQUEST_SCHEMA = "codexqb.controller-argv/v1"
MAX_CONTROLLER_STDIN_REQUEST_BYTES = MAX_APPLY_RUN_MARKER_BYTES + 64 * 1024
MAX_CONTROLLER_STDIN_ARGV_ITEMS = 256
MAX_CONTROLLER_STDIN_ARGUMENT_CHARACTERS = MAX_APPLY_RUN_MARKER_BYTES
APPLY_DELETE_QUARANTINE_PREFIX = ".codexqb-delete-"
APPLY_RUN_REGISTRY_DIR_NAME = ".codexqb-run-registry"
APPLY_RUN_REGISTRATION_KIND = "codexqb_apply_run_registration"
APPLY_RUN_REGISTRATION_VERSION = 2
CODEXQB_TRUST_DIR_NAME = "codexqb-trust"
CODEXQB_TRUST_KEY_NAME = "apply-run-hmac-v1.key"
CODEXQB_TRUST_STATE_NAME = "apply-run-hmac-v1.state.json"
CODEXQB_TRUST_KEY_BYTES = 32
APPLY_RUN_REGISTRATION_MAC_DOMAIN = b"codexqb.apply-run-registration.v1\0"
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


def repository_model_text(
    root: Path,
    relative_path: str,
    *,
    required: bool = False,
    repository: RepositoryIO | None = None,
) -> str | None:
    if repository is not None:
        return repository.read_text(relative_path, required=required, audience="model").text
    with open_repository_io(root) as opened:
        return opened.read_text(relative_path, required=required, audience="model").text


def repository_internal_text(
    root: Path,
    relative_path: str,
    *,
    required: bool = False,
    repository: RepositoryIO | None = None,
) -> str | None:
    if repository is not None:
        return repository.read_text(relative_path, required=required, audience="internal").text
    with open_repository_io(root) as opened:
        return opened.read_text(relative_path, required=required, audience="internal").text


def repository_workspace_evidence(
    root: Path,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return repository_workspace_evidence(root, opened)
    proof = controller_workspace_proof(
        repository,
        exclude_untracked=baseline_path_is_excluded,
        exclude_tracked=baseline_path_is_excluded,
    )
    return dict(proof.evidence)


def repository_contract_binding(
    root: Path,
    source_subplan_path: str,
    *,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return repository_contract_binding(root, source_subplan_path, repository=opened)
    source = controller_read_bytes(repository, source_subplan_path, required=False)
    if not source.exists or source.data is None:
        return {"errors": [f"missing_source_subplan={source_subplan_path}"]}
    authoritative = implementation_contract_binding_from_bytes(
        source_subplan_path,
        source.data,
    )
    projected = repository.read_text(
        source_subplan_path,
        required=False,
        audience="model",
    )
    if (
        not projected.exists
        or projected.text is None
        or projected.receipt.sha256 != source.receipt.sha256
    ):
        raise ValueError("repository_model_projection_identity_mismatch")
    projected_binding = implementation_contract_binding_from_bytes(
        source_subplan_path,
        projected.text.encode("utf-8"),
    )
    authoritative_semantics = {
        key: value
        for key, value in authoritative.items()
        if key != "source_subplan_sha256"
    }
    projected_semantics = {
        key: value
        for key, value in projected_binding.items()
        if key != "source_subplan_sha256"
    }
    if authoritative_semantics != projected_semantics:
        raise ValueError("repository_model_projection_semantic_mismatch")
    return authoritative


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


def atomic_write_text(path: Path, text: str, *, root: Path) -> None:
    secure_write_apply_artifact(path, text, root=root)


def atomic_write_json(path: Path, payload: object, *, root: Path) -> None:
    atomic_write_text(path, serialize_safe_persistent_json(payload), root=root)


def append_event(run_dir: Path, event: dict[str, object], *, root: Path) -> dict[str, object]:
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
        run_fd = controller_open(run_dir, secure_directory_open_flags())
        text = read_event_log_at(run_fd)
    except FileNotFoundError:
        errors.append("missing_events_jsonl")
        return []
    except (OSError, UnicodeDecodeError, ValueError):
        errors.append("invalid_events_jsonl_file")
        return []
    finally:
        if run_fd >= 0:
            controller_close(run_fd)
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
    return controller_lexical_absolute(path)


def repository_mount_relative_path(root: Path, path: Path) -> str:
    root = lexical_absolute(managed_apply_runs_root(root))
    path = lexical_absolute(path)
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected") from exc
    return relative.as_posix() if relative.parts else "."


def apply_run_logical_path(root: Path, run_dir: Path) -> str:
    relative = repository_mount_relative_path(root, run_dir)
    if "/" in relative or relative == ".":
        raise ValueError("invalid_apply_run_output_dir=managed_run_required")
    return (APPLY_RUNS_RELATIVE_DIR / relative).as_posix()


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


def linux_mountinfo_text() -> str | None:
    """Read only the fixed kernel mount table; never accept a caller path."""

    flags = CONTROLLER_O_RDONLY | CONTROLLER_O_CLOEXEC | CONTROLLER_O_NOFOLLOW
    try:
        descriptor = controller_open("/proc/self/mountinfo", flags)
    except OSError:
        return None
    chunks: list[bytes] = []
    remaining = 1024 * 1024
    try:
        while remaining > 0:
            chunk = controller_read(descriptor, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        if remaining == 0 and controller_read(descriptor, 1):
            return None
    except OSError:
        return None
    finally:
        controller_close(descriptor)
    return b"".join(chunks).decode("utf-8", errors="replace")


def path_is_mount_point(path: Path) -> bool:
    try:
        if controller_path_is_mount(path):
            return True
    except OSError:
        return True
    text = linux_mountinfo_text()
    if text is None:
        return sys.platform.startswith("linux")
    candidate = controller_path_real_normalized(path)
    for line in text.splitlines():
        fields = line.split(" - ", 1)[0].split()
        if len(fields) < 5:
            continue
        mounted_at = controller_path_normalized(decode_mountinfo_path(fields[4]))
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
        try:
            metadata = controller_lstat(current)
        except FileNotFoundError:
            continue
        except OSError:
            return True
        if stat.S_ISLNK(metadata.st_mode):
            return True
        if path_is_mount_point(current):
            return True
    return False


def managed_apply_runs_root(root: Path) -> Path:
    return controller_apply_runs_root(root)


def resolve_managed_apply_run_dir(
    root: Path,
    requested: Path | None,
    default_name: str | None = None,
    *,
    lexical_root: Path | None = None,
) -> Path:
    root = canonical_controller_repository_root(root)
    lexical_root = lexical_absolute(lexical_root or root)
    runs_root = managed_apply_runs_root(root)
    legacy_root = legacy_apply_runs_root(root)
    if requested is None:
        candidate = runs_root / str(default_name or "")
    elif requested.is_absolute():
        candidate = requested
    elif len(requested.parts) == 1:
        candidate = runs_root / requested.name
    elif requested.parts[:2] == APPLY_RUNS_RELATIVE_DIR.parts:
        raise ValueError("legacy_apply_run_archive_only")
    else:
        raise ValueError("invalid_apply_run_output_dir=managed_run_required")
    candidate_lexical = lexical_absolute(candidate)
    legacy_roots = {
        lexical_absolute(legacy_root),
        lexical_absolute(lexical_root / APPLY_RUNS_RELATIVE_DIR),
    }
    for legacy_candidate_root in legacy_roots:
        try:
            candidate_lexical.relative_to(legacy_candidate_root)
        except ValueError:
            continue
        raise ValueError("legacy_apply_run_archive_only")
    if path_has_indirect_component(runs_root.parent, candidate_lexical):
        raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    runs_root_lexical = lexical_absolute(runs_root)
    if candidate_lexical == runs_root_lexical:
        raise ValueError("invalid_apply_run_output_dir=run_directory_required")
    if candidate_lexical.parent != runs_root_lexical:
        raise ValueError("invalid_apply_run_output_dir=must_be_direct_child_of_controller_apply_runs")
    if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", candidate_lexical.name) is None:
        raise ValueError("invalid_apply_run_output_dir=invalid_run_directory_name")
    if has_secret_like(candidate_lexical.name):
        raise ValueError("invalid_apply_run_output_dir=secret_like_run_directory_name")
    return candidate_lexical


def secure_directory_open_flags() -> int:
    if CONTROLLER_O_DIRECTORY == 0 or CONTROLLER_O_NOFOLLOW == 0:
        raise ValueError("secure_apply_run_replace_not_supported")
    return CONTROLLER_O_RDONLY | CONTROLLER_O_DIRECTORY | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC


def same_file_identity(first: ControllerStatResult, second: ControllerStatResult) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def metadata_is_owner_controlled(metadata: ControllerStatResult) -> bool:
    expected_uid = controller_effective_uid()
    return metadata.st_uid == expected_uid and metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH) == 0


def open_child_directory(parent_fd: int, name: str) -> tuple[int, ControllerStatResult]:
    before = controller_stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(before.st_mode):
        raise ValueError("replace_requires_existing_apply_run")
    child_fd = controller_open(name, secure_directory_open_flags(), dir_fd=parent_fd)
    try:
        after = controller_fstat(child_fd)
    except Exception:
        controller_close(child_fd)
        raise
    if not same_file_identity(before, after):
        controller_close(child_fd)
        raise ValueError("replace_apply_run_identity_changed")
    return child_fd, after


def opened_directory_matches_path(path: Path, metadata: ControllerStatResult, *, reject_mount: bool) -> bool:
    try:
        before = controller_stat(path, follow_symlinks=False)
    except OSError:
        return False
    if not stat.S_ISDIR(before.st_mode) or not same_file_identity(before, metadata):
        return False
    if reject_mount and path_is_mount_point(path):
        return False
    try:
        after = controller_stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISDIR(after.st_mode) and same_file_identity(before, after) and same_file_identity(after, metadata)


def metadata_is_private_directory(metadata: ControllerStatResult) -> bool:
    return (
        stat.S_ISDIR(metadata.st_mode)
        and metadata_is_owner_controlled(metadata)
        and stat.S_IMODE(metadata.st_mode) == 0o700
    )


def metadata_is_private_regular_file(metadata: ControllerStatResult) -> bool:
    return (
        stat.S_ISREG(metadata.st_mode)
        and metadata.st_nlink == 1
        and metadata_is_owner_controlled(metadata)
        and stat.S_IMODE(metadata.st_mode) == 0o600
    )


def open_owned_child_directory(parent_fd: int, name: str, *, create: bool, private: bool) -> int:
    if create:
        try:
            controller_mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    try:
        child_fd, metadata = open_child_directory(parent_fd, name)
    except (OSError, ValueError) as exc:
        raise ValueError("codexqb_trust_store_unavailable") from exc
    valid = metadata_is_private_directory(metadata) if private else metadata_is_owner_controlled(metadata)
    if not valid:
        controller_close(child_fd)
        raise ValueError("codexqb_trust_store_permissions_invalid")
    return child_fd


def open_codexqb_trust_root_fd(*, create: bool) -> int:
    try:
        return open_controller_trust_root_fd(create=create)
    except OSError as exc:
        raise ValueError("codexqb_trust_store_unavailable") from exc


def load_apply_run_trust_state(trust_fd: int) -> dict[str, object] | None:
    try:
        metadata = controller_stat(CODEXQB_TRUST_STATE_NAME, dir_fd=trust_fd, follow_symlinks=False)
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
        flags = CONTROLLER_O_RDONLY | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC
        key_fd = controller_open(CODEXQB_TRUST_KEY_NAME, flags, dir_fd=trust_fd)
        metadata = controller_fstat(key_fd)
        if not metadata_is_private_regular_file(metadata):
            raise ValueError("codexqb_trust_key_permissions_invalid")
        if metadata.st_size != CODEXQB_TRUST_KEY_BYTES:
            raise ValueError("codexqb_trust_key_invalid")
        chunks: list[bytes] = []
        remaining = CODEXQB_TRUST_KEY_BYTES + 1
        while remaining > 0:
            chunk = controller_read(key_fd, remaining)
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
            controller_close(key_fd)


def create_apply_run_trust_key(trust_fd: int) -> bytes:
    key = secrets.token_bytes(CODEXQB_TRUST_KEY_BYTES)
    flags = CONTROLLER_O_WRONLY | CONTROLLER_O_CREAT | CONTROLLER_O_EXCL | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC
    key_fd = controller_open(CODEXQB_TRUST_KEY_NAME, flags, 0o600, dir_fd=trust_fd)
    try:
        controller_fchmod(key_fd, 0o600)
        offset = 0
        while offset < len(key):
            written = controller_write(key_fd, key[offset:])
            if written <= 0:
                raise OSError("short CodexQB trust-key write")
            offset += written
        controller_fsync(key_fd)
        controller_fsync(trust_fd)
    except Exception:
        controller_close(key_fd)
        key_fd = -1
        try:
            controller_unlink(CODEXQB_TRUST_KEY_NAME, dir_fd=trust_fd)
        except OSError:
            pass
        raise
    finally:
        if key_fd >= 0:
            controller_close(key_fd)
    return key


def load_or_create_apply_run_trust_key(*, create: bool) -> bytes:
    trust_fd = open_codexqb_trust_root_fd(create=create)
    try:
        with locked_directory(trust_fd):
            state = load_apply_run_trust_state(trust_fd)
            created_key = False
            try:
                key = read_apply_run_trust_key(trust_fd)
            except FileNotFoundError:
                if not create:
                    raise ValueError("codexqb_trust_key_unavailable")
                if state is not None:
                    raise ValueError("codexqb_trust_key_recovery_required")
                try:
                    key = create_apply_run_trust_key(trust_fd)
                    created_key = True
                except FileExistsError:
                    # A creator outside the shared lease raced or preseeded
                    # the key.  Never bind an unobserved key to fresh state.
                    raise ValueError("codexqb_trust_key_recovery_required") from None
            except OSError as exc:
                raise ValueError("codexqb_trust_key_unavailable") from exc
            expected_state = {
                "trust_state_version": 1,
                "trust_key_id": sha256_bytes(key)[:32],
            }
            if state is None:
                if not create or not created_key:
                    raise ValueError("codexqb_trust_key_recovery_required")
                try:
                    write_regular_json_exclusive_at(
                        trust_fd,
                        CODEXQB_TRUST_STATE_NAME,
                        expected_state,
                    )
                    controller_fsync(trust_fd)
                except FileExistsError:
                    raise ValueError("codexqb_trust_key_recovery_required") from None
                state = load_apply_run_trust_state(trust_fd)
            if state != expected_state:
                raise ValueError("codexqb_trust_key_recovery_required")
            return key
    finally:
        controller_close(trust_fd)


def signed_apply_run_registration(
    root_proof: ControllerRootProof,
    payload: dict[str, object],
    *,
    create_key: bool,
) -> dict[str, object]:
    key = load_or_create_apply_run_trust_key(create=create_key)
    signed = {
        **payload,
        "root_binding_sha256": root_proof.repository_identity_sha256,
        "root_device": root_proof.root_device,
        "root_inode": root_proof.root_inode,
        "trust_key_id": sha256_bytes(key)[:32],
    }
    encoded = json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signed["registration_mac"] = hmac.new(
        key,
        APPLY_RUN_REGISTRATION_MAC_DOMAIN + encoded,
        hashlib.sha256,
    ).hexdigest()
    return signed


def trusted_apply_run_registration(
    root_proof: ControllerRootProof,
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
    if registration.get("root_binding_sha256") != root_proof.repository_identity_sha256:
        return False
    if (
        registration.get("root_device") != root_proof.root_device
        or registration.get("root_inode") != root_proof.root_inode
    ):
        return False
    unsigned = {key_name: value for key_name, value in registration.items() if key_name != "registration_mac"}
    encoded = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    expected = hmac.new(
        key,
        APPLY_RUN_REGISTRATION_MAC_DOMAIN + encoded,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(registration_mac, expected)


def open_managed_apply_runs_root_fd(
    root: Path,
    *,
    create: bool,
    root_anchor_fd: int | None = None,
    root_mount_resolution: MountResolution | None = None,
    operation: str = APPLY_RUN_MUTATION,
) -> int:
    del root_anchor_fd, root_mount_resolution, operation
    try:
        with open_controller_runs_root(root, APPLY_RUN_COMPONENTS, create=create) as (
            runs_fd,
            runs_path,
        ):
            if runs_path != managed_apply_runs_root(root):
                raise ValueError("invalid_apply_run_output_dir=controller_state_mismatch")
            return controller_dup(runs_fd)
    except FileNotFoundError:
        raise ValueError("apply_run_controller_state_missing") from None


def load_regular_json_at(directory_fd: int, name: str) -> dict[str, object]:
    flags = CONTROLLER_O_RDONLY | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC
    file_fd = controller_open(name, flags, dir_fd=directory_fd)
    try:
        metadata = controller_fstat(file_fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_APPLY_RUN_MARKER_BYTES:
            raise ValueError("replace_requires_existing_apply_run")
        chunks: list[bytes] = []
        remaining = MAX_APPLY_RUN_MARKER_BYTES + 1
        while remaining > 0:
            chunk = controller_read(file_fd, min(65536, remaining))
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
        controller_close(file_fd)
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
        created = False
        try:
            controller_mkdir(APPLY_RUN_REGISTRY_DIR_NAME, mode=0o700, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            pass
        if created:
            controller_chmod(
                APPLY_RUN_REGISTRY_DIR_NAME,
                0o700,
                dir_fd=parent_fd,
                follow_symlinks=False,
            )
    try:
        registry_fd, registry_metadata = open_child_directory(parent_fd, APPLY_RUN_REGISTRY_DIR_NAME)
    except (OSError, ValueError) as exc:
        raise ValueError("replace_requires_registered_apply_run") from exc
    try:
        parent_metadata = controller_fstat(parent_fd)
        registry_path = managed_apply_runs_root(root) / APPLY_RUN_REGISTRY_DIR_NAME
        require_apply_same_mount(
            mount_resolution,
            registry_fd,
            repository_mount_relative_path(root, registry_path),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        if (
            registry_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_private_directory(registry_metadata)
            or not opened_directory_matches_path(registry_path, registry_metadata, reject_mount=True)
            or not controller_tree_is_private(registry_fd)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    except Exception:
        controller_close(registry_fd)
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
    flags = CONTROLLER_O_WRONLY | CONTROLLER_O_CREAT | CONTROLLER_O_EXCL | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC
    file_fd = controller_open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        controller_fchmod(file_fd, 0o600)
        offset = 0
        while offset < len(encoded):
            written = controller_write(file_fd, encoded[offset:])
            if written <= 0:
                raise OSError("short apply-run registration write")
            offset += written
        controller_fsync(file_fd)
    except Exception:
        controller_close(file_fd)
        file_fd = -1
        try:
            controller_unlink(name, dir_fd=directory_fd)
        except OSError:
            pass
        raise
    finally:
        if file_fd >= 0:
            controller_close(file_fd)


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
        "run_dir": apply_run_logical_path(root, run_dir),
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
    run_metadata: ControllerStatResult | None = None,
    root_proof: ControllerRootProof | None = None,
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
        or root_proof is None
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
    if registration.get("run_dir") != apply_run_logical_path(root, run_dir):
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
    if not trusted_apply_run_registration(root_proof, registration):
        return False
    return marker == apply_run_marker_payload(root, run_dir, run)


def apply_run_registration_payload(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
    *,
    root_proof: ControllerRootProof,
    run_metadata: ControllerStatResult,
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
        "run_dir": apply_run_logical_path(root, run_dir),
        "run_device": run_metadata.st_dev,
        "run_inode": run_metadata.st_ino,
        "manifest_claim_sha256": claim_digest,
        "manifest_sha256": manifest_digest,
        "refresh_stable_sha256": stable_digest,
    }
    return signed_apply_run_registration(root_proof, payload, create_key=create_key)


def create_apply_run_registration(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
    *,
    root_proof: ControllerRootProof,
    parent_fd: int,
    run_fd: int,
    run_metadata: ControllerStatResult,
    root_mount_resolution: MountResolution,
) -> None:
    registry_fd = -1
    try:
        parent_metadata = controller_fstat(parent_fd)
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
        current_run_metadata = controller_fstat(run_fd)
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
            root_proof=root_proof,
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
        controller_fsync(registry_fd)
    finally:
        if registry_fd >= 0:
            controller_close(registry_fd)


def refresh_apply_run_provenance(
    run_dir: Path,
    run: dict[str, object],
    *,
    root: Path,
) -> None:
    run_dir = lexical_absolute(run_dir)
    root = lexical_absolute(root)
    run_dir = resolve_managed_apply_run_dir(root, run_dir, lexical_root=root)
    repository_session = open_repository_io(root)
    repository = repository_session.__enter__()
    parent_fd = -1
    run_fd = -1
    registry_fd = -1
    try:
        root_proof = controller_root_proof(repository)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
        )
        root_mount_resolution = resolve_apply_mount_identity(parent_fd, APPLY_RUN_MUTATION)
        parent_metadata = controller_fstat(parent_fd)
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
            or not controller_tree_is_private(run_fd)
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
        registration_metadata = controller_stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        registration = load_regular_json_at(registry_fd, registration_name)
        current_registration_metadata = controller_stat(
            registration_name,
            dir_fd=registry_fd,
            follow_symlinks=False,
        )
        if (
            not metadata_is_private_regular_file(registration_metadata)
            or not same_file_identity(registration_metadata, current_registration_metadata)
            or not trusted_apply_run_registration(root_proof, registration)
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
            or registration.get("run_dir") != apply_run_logical_path(root, run_dir)
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
            root_proof=root_proof,
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
            root_proof,
        ):
            raise ValueError("apply_run_provenance_refresh_failed")
    finally:
        if registry_fd >= 0:
            controller_close(registry_fd)
        if run_fd >= 0:
            controller_close(run_fd)
        if parent_fd >= 0:
            controller_close(parent_fd)
        repository_session.__exit__(None, None, None)


def current_apply_run_provenance_is_valid(
    root: Path,
    run_dir: Path,
    run: dict[str, object],
) -> bool:
    repository_session = None
    parent_fd = -1
    run_fd = -1
    registry_fd = -1
    try:
        root = canonical_controller_repository_root(root)
        run_dir = resolve_managed_apply_run_dir(root, run_dir, lexical_root=root)
        repository_session = open_repository_io(root)
        repository = repository_session.__enter__()
        root_proof = controller_root_proof(repository)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            operation=READ_ONLY_EVIDENCE,
        )
        root_mount_resolution = resolve_apply_mount_identity(parent_fd, READ_ONLY_EVIDENCE)
        parent_metadata = controller_fstat(parent_fd)
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
            or not controller_tree_is_private(run_fd)
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
        registration_metadata = controller_stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        registration = load_regular_json_at(registry_fd, registration_name)
        current_registration_metadata = controller_stat(
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
            root_proof,
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    finally:
        if registry_fd >= 0:
            controller_close(registry_fd)
        if run_fd >= 0:
            controller_close(run_fd)
        if parent_fd >= 0:
            controller_close(parent_fd)
        if repository_session is not None:
            repository_session.__exit__(None, None, None)


def open_regular_child(parent_fd: int, name: str) -> tuple[int, ControllerStatResult]:
    before = controller_stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("replace_apply_run_tree_changed")
    flags = CONTROLLER_O_RDONLY | CONTROLLER_O_NOFOLLOW | CONTROLLER_O_CLOEXEC | CONTROLLER_O_NONBLOCK
    child_fd = controller_open(name, flags, dir_fd=parent_fd)
    try:
        after = controller_fstat(child_fd)
    except Exception:
        controller_close(child_fd)
        raise
    if not stat.S_ISREG(after.st_mode) or not same_file_identity(before, after):
        controller_close(child_fd)
        raise ValueError("replace_apply_run_tree_changed")
    return child_fd, after


def inventory_identity(metadata: ControllerStatResult, kind: str) -> dict[str, object]:
    return {
        "kind": kind,
        "device": metadata.st_dev,
        "inode": metadata.st_ino,
    }


def inventory_matches(metadata: ControllerStatResult, entry: dict[str, object], kind: str) -> bool:
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
    directory_metadata = controller_fstat(directory_fd)
    if directory_metadata.st_dev != expected_device or path_is_mount_point(logical_path):
        raise ValueError("replace_apply_run_tree_contains_indirect_target")
    inventory = inventory_identity(directory_metadata, "directory")
    entries: dict[str, object] = {}
    inventory["entries"] = entries
    for name in sorted(controller_listdir(directory_fd)):
        if name.startswith(APPLY_DELETE_QUARANTINE_PREFIX):
            raise ValueError(f"replace_apply_run_recovery_required={name}")
        entry_path = logical_path / name
        metadata = controller_stat(name, dir_fd=directory_fd, follow_symlinks=False)
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
                controller_close(child_fd)
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
                controller_close(child_fd)
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
            controller_mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue
        try:
            quarantine_fd, metadata = open_child_directory(parent_fd, name)
        except (OSError, ValueError) as exc:
            try:
                controller_rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise ValueError("replace_apply_run_tree_changed") from exc
        controller_fchmod(quarantine_fd, 0o700)
        metadata = controller_fstat(quarantine_fd)
        try:
            require_apply_same_mount(
                root_mount_resolution,
                quarantine_fd,
                repository_mount_relative_path(root, logical_parent / name),
                mismatch_error="replace_apply_run_tree_changed",
            )
        except Exception:
            controller_close(quarantine_fd)
            try:
                controller_rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise
        if metadata.st_dev != expected_device:
            controller_close(quarantine_fd)
            try:
                controller_rmdir(name, dir_fd=parent_fd)
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
        controller_fsencode(source),
        destination_dir_fd,
        controller_fsencode(destination),
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
        raise OSError(error_number, controller_strerror(error_number), destination)


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
            CONTROLLER_O_WRONLY
            | CONTROLLER_O_CREAT
            | CONTROLLER_O_EXCL
            | CONTROLLER_O_NOFOLLOW
            | CONTROLLER_O_CLOEXEC
        )
        source_fd = controller_open("probe-source", file_flags, 0o600, dir_fd=quarantine_fd)
        destination_fd = controller_open("probe-destination", file_flags, 0o600, dir_fd=quarantine_fd)
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
        controller_close(source_fd)
        source_fd = -1
        controller_close(destination_fd)
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
        source_metadata = controller_stat("probe-source", dir_fd=quarantine_fd, follow_symlinks=False)
        destination_metadata = controller_stat("probe-destination", dir_fd=quarantine_fd, follow_symlinks=False)
        if not stat.S_ISREG(source_metadata.st_mode) or not stat.S_ISREG(destination_metadata.st_mode):
            raise ValueError("secure_apply_run_replace_not_supported")
    except Exception as exc:
        probe_error = exc
    finally:
        if source_fd >= 0:
            controller_close(source_fd)
        if destination_fd >= 0:
            controller_close(destination_fd)
        cleanup_failed = False
        for probe_name in ("probe-source", "probe-destination"):
            try:
                controller_unlink(probe_name, dir_fd=quarantine_fd)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_failed = True
        controller_close(quarantine_fd)
        try:
            controller_rmdir(quarantine_name, dir_fd=parent_fd)
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
            controller_close(entry_fd)
    try:
        before = controller_stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
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
        after = controller_stat(original_name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as exc:
        raise ValueError(f"replace_apply_run_restore_failed={quarantine_name}") from exc
    if not same_file_identity(before, after):
        raise ValueError(f"replace_apply_run_restore_conflict={quarantine_name}")
    try:
        controller_rmdir(quarantine_name, dir_fd=parent_fd)
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
        metadata = controller_stat(name, dir_fd=parent_fd, follow_symlinks=False)
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
        quarantined_metadata = controller_stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
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
            current_fd_metadata = controller_fstat(entry_fd)
            current_path_metadata = controller_stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
            if (
                not inventory_matches(current_fd_metadata, entry, "directory")
                or not inventory_matches(current_path_metadata, entry, "directory")
                or path_is_mount_point(quarantined_path)
            ):
                raise ValueError("replace_apply_run_tree_changed")
            controller_rmdir("entry", dir_fd=quarantine_fd)
        else:
            entry_fd, opened_metadata = open_regular_child(quarantine_fd, "entry")
            require_apply_same_mount(
                root_mount_resolution,
                entry_fd,
                repository_mount_relative_path(root, quarantined_path),
                mismatch_error="replace_apply_run_tree_changed",
            )
            current_path_metadata = controller_stat("entry", dir_fd=quarantine_fd, follow_symlinks=False)
            if (
                not inventory_matches(opened_metadata, entry, "regular")
                or not inventory_matches(current_path_metadata, entry, "regular")
                or path_is_mount_point(quarantined_path)
            ):
                raise ValueError("replace_apply_run_tree_changed")
            controller_unlink("entry", dir_fd=quarantine_fd)
        removed = True
    except (OSError, ValueError) as exc:
        if entry_fd >= 0:
            controller_close(entry_fd)
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
                controller_rmdir(quarantine_name, dir_fd=parent_fd)
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
            controller_close(entry_fd)
        controller_close(quarantine_fd)
    try:
        controller_rmdir(quarantine_name, dir_fd=parent_fd)
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
    directory_metadata = controller_fstat(directory_fd)
    if (
        directory_metadata.st_dev != expected_device
        or not inventory_matches(directory_metadata, inventory, "directory")
        or path_is_mount_point(logical_path)
    ):
        raise ValueError("replace_apply_run_tree_changed")
    entries = inventory.get("entries")
    if not isinstance(entries, dict) or set(controller_listdir(directory_fd)) != set(entries):
        raise ValueError("replace_apply_run_tree_changed")
    ordered_names = sorted(entries)
    for index, name in enumerate(ordered_names):
        if set(controller_listdir(directory_fd)) != set(ordered_names[index:]):
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
    if controller_listdir(directory_fd):
        raise ValueError("replace_apply_run_tree_changed")


def require_no_managed_recovery_quarantine(parent_fd: int) -> None:
    recovery_names = sorted(
        name for name in controller_listdir(parent_fd) if name.startswith(APPLY_DELETE_QUARANTINE_PREFIX)
    )
    if recovery_names:
        raise ValueError(f"replace_apply_run_recovery_required={recovery_names[0]}")


def require_no_stale_apply_run_registration(root: Path, parent_fd: int, run_name: str) -> None:
    try:
        controller_stat(APPLY_RUN_REGISTRY_DIR_NAME, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ValueError("apply_run_registration_recovery_required") from exc
    registry_fd = open_apply_run_registry_fd(root, parent_fd, create=False)
    try:
        require_no_managed_recovery_quarantine(registry_fd)
        registration_name = apply_run_registration_file_name(run_name)
        try:
            controller_stat(registration_name, dir_fd=registry_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise ValueError(f"apply_run_registration_recovery_required={run_name}") from exc
        raise ValueError(f"apply_run_registration_recovery_required={run_name}")
    finally:
        controller_close(registry_fd)


def replace_existing_apply_run(
    root: Path,
    run_dir: Path,
    *,
    root_proof: ControllerRootProof,
) -> None:
    parent_fd = open_managed_apply_runs_root_fd(
        root,
        create=False,
        operation=RUN_REPLACE_QUARANTINE_DELETE,
    )
    root_mount_resolution = resolve_apply_mount_identity(
        parent_fd,
        RUN_REPLACE_QUARANTINE_DELETE,
    )
    require_mount_assurance(root_mount_resolution, RUN_REPLACE_QUARANTINE_DELETE)
    run_fd = -1
    registry_fd = -1
    try:
        parent_metadata = controller_fstat(parent_fd)
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
            registration_metadata = controller_stat(
                registration_name,
                dir_fd=registry_fd,
                follow_symlinks=False,
            )
            registration = load_regular_json_at(registry_fd, registration_name)
            current_registration_metadata = controller_stat(
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
            root_proof,
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
        controller_close(run_fd)
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
            controller_close(run_fd)
        if registry_fd >= 0:
            controller_close(registry_fd)
        controller_close(parent_fd)


def create_managed_apply_run_directory(
    root: Path,
    run_dir: Path,
    *,
    root_anchor_fd: int | None = None,
    root_mount_resolution: MountResolution | None = None,
) -> tuple[int, int, ControllerStatResult]:
    parent_fd = open_managed_apply_runs_root_fd(
        root,
        create=True,
        root_anchor_fd=root_anchor_fd,
    )
    run_fd = -1
    created = False
    try:
        require_no_managed_recovery_quarantine(parent_fd)
        require_no_stale_apply_run_registration(root, parent_fd, run_dir.name)
        controller_mkdir(run_dir.name, mode=0o700, dir_fd=parent_fd)
        created = True
        run_fd, run_metadata = open_child_directory(parent_fd, run_dir.name)
        controller_fchmod(run_fd, 0o700)
        run_metadata = controller_fstat(run_fd)
        mount_resolution = resolve_apply_mount_identity(
            parent_fd,
            APPLY_RUN_MUTATION,
        )
        require_apply_same_mount(
            mount_resolution,
            run_fd,
            repository_mount_relative_path(root, run_dir),
            mismatch_error="invalid_apply_run_output_dir=indirect_target_rejected",
        )
        parent_metadata = controller_fstat(parent_fd)
        if (
            run_metadata.st_dev != parent_metadata.st_dev
            or not metadata_is_private_directory(run_metadata)
            or not opened_directory_matches_path(run_dir, run_metadata, reject_mount=True)
        ):
            raise ValueError("invalid_apply_run_output_dir=indirect_target_rejected")
    except FileExistsError as exc:
        controller_close(parent_fd)
        raise ValueError(f"apply_run_already_exists={apply_run_logical_path(root, run_dir)}") from exc
    except Exception:
        if run_fd >= 0:
            controller_close(run_fd)
        if created:
            try:
                controller_rmdir(run_dir.name, dir_fd=parent_fd)
            except OSError:
                pass
        controller_close(parent_fd)
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
    return controller_evidence_digest(selected), len(selected)


def workspace_file_inventory_entries(
    root: Path,
    repository: RepositoryIO | None = None,
) -> list[str]:
    if repository is None:
        policy = RepositoryIOPolicy(
            name="apply-workspace-evidence/v1",
            max_file_bytes=MAX_WORKSPACE_INVENTORY_FILE_BYTES,
            # The legacy Apply contract defines this limit across the two
            # confirmation passes. RepositoryIO exposes a logical-content
            # budget, so halve it to preserve the existing physical ceiling.
            max_total_bytes=max(1, MAX_WORKSPACE_INVENTORY_TOTAL_BYTES // 2),
            max_paths=MAX_WORKSPACE_INVENTORY_PATHS,
            timeout_seconds=WORKSPACE_INVENTORY_TIMEOUT_SECONDS,
            model_max_file_bytes=max(
                1,
                min(256 * 1024, MAX_WORKSPACE_INVENTORY_FILE_BYTES),
            ),
            model_max_total_bytes=max(
                1,
                min(1024 * 1024, max(1, MAX_WORKSPACE_INVENTORY_TOTAL_BYTES // 2)),
            ),
            model_max_matches=max(1, min(512, MAX_WORKSPACE_INVENTORY_PATHS)),
            model_max_record_characters=4096,
        )
        with open_repository_io(root, policy) as opened:
            return workspace_file_inventory_entries(canonical_repository_root(opened), opened)
    try:
        snapshot = [
            item
            for item in controller_inventory(repository, "intake")
            if not baseline_path_is_excluded(str(item.get("path", "")))
        ]
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


def workspace_baseline_capture(
    root: Path,
    repository: RepositoryIO | None = None,
) -> tuple[dict[str, object], list[str]]:
    git_evidence = repository_workspace_evidence(root, repository)
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
        status_hash = controller_evidence_digest(status_entries)
        staged_hash = controller_evidence_digest(staged_changes)
        unstaged_hash = controller_evidence_digest(unstaged_changes)
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
    repository: RepositoryIO | None = None,
) -> bytes | None:
    """Compatibility wrapper over the mandatory repository I/O boundary."""

    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("repository_read_max_bytes_invalid")
    if repository is None:
        with open_repository_io(root) as opened:
            return read_repository_file_no_follow(
                canonical_repository_root(opened),
                relative_path,
                max_bytes=max_bytes,
                repository=opened,
            )
    evidence = controller_read_bytes(repository, relative_path, required=False)
    if not evidence.exists or evidence.data is None:
        return None
    if len(evidence.data) > max_bytes:
        raise ValueError("repository_baseline_content_too_large")
    return evidence.data


def capture_repository_io_evidence(
    root: Path,
    allowed_paths: list[str],
    baseline_snapshot: object,
    *,
    apply_run_id: str,
    task_id: str,
    apply_run_registration_id: str,
    contract_digest: str,
    generation: int,
    review_package_sha256: str,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return capture_repository_io_evidence(
                canonical_repository_root(opened),
                allowed_paths,
                baseline_snapshot,
                apply_run_id=apply_run_id,
                task_id=task_id,
                apply_run_registration_id=apply_run_registration_id,
                contract_digest=contract_digest,
                generation=generation,
                review_package_sha256=review_package_sha256,
                repository=opened,
            )
    if not isinstance(baseline_snapshot, list):
        raise ValueError("repository_baseline_invalid")
    current = controller_snapshot_paths(repository, allowed_paths)
    return controller_evidence_from_snapshots(
        allowed_paths,
        baseline_snapshot,
        current,
        apply_run_id=apply_run_id,
        task_id=task_id,
        apply_run_registration_id=apply_run_registration_id,
        contract_digest=contract_digest,
        generation=generation,
        review_package_sha256=review_package_sha256,
    )


def capture_repository_baselines(
    root: Path,
    tasks: list[dict[str, object]],
    repository: RepositoryIO | None = None,
) -> list[dict[str, object]]:
    if repository is None:
        with open_repository_io(root) as opened:
            return capture_repository_baselines(canonical_repository_root(opened), tasks, opened)
    baselines: list[dict[str, object]] = []
    for task in tasks:
        task_id = str(task.get("task_id", ""))
        paths = sorted(implementation_contract_paths(task))
        captured = [
            controller_read_bytes(repository, path, required=False)
            for path in paths
        ]
        snapshot = [
            {
                "path": evidence.path,
                "state": "present" if evidence.exists else "missing",
                "sha256": evidence.receipt.sha256,
                "size": evidence.receipt.size,
            }
            for evidence in captured
        ]
        contents: list[dict[str, object]] = []
        total_bytes = 0
        for entry, evidence in zip(snapshot, captured):
            if entry.get("state") != "present":
                continue
            path = str(entry["path"])
            content = evidence.data
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
                "baseline_digest": controller_baseline_digest(snapshot),
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
    parent_fd = controller_open(path.parent, secure_directory_open_flags())
    try:
        return parse_safe_persistent_json(secure_read_regular_text_at(parent_fd, path.name))
    finally:
        controller_close(parent_fd)


def implementation_report_files(run_dir: Path, task: dict[str, object]) -> set[str]:
    task_id = str(task.get("task_id", ""))
    if not safe_task_id(task_id):
        return set()
    report_path = run_dir / task_id / "Implementer-Report.json"
    if not controller_regular_entry_exists(report_path):
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
    if not controller_regular_entry_exists(report_path):
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
    git_evidence = repository_workspace_evidence(root)
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
    current_staged_digest = controller_evidence_digest(current_staged_changes)
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
    repository: RepositoryIO | None = None,
) -> list[dict[str, str]]:
    if repository is None:
        with open_repository_io(root) as opened:
            return collect_snapshot(canonical_repository_root(opened), baseline, opened)
    files = [
        path
        for path in controller_regular_paths(repository, "step3")
        if path.endswith(".md") and Path(path).name != "Planing-Ledger.md"
    ]
    captured = repository.read_many(files, required=True, audience="internal")
    snapshot = [
        {"path": evidence.path, "sha256": str(evidence.receipt.sha256)}
        for evidence in captured
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
    raw = value or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{controller_process_id()}"
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


@dataclass
class ApplyMutationHandle:
    root: Path
    run_dir: Path
    repository: RepositoryIO
    root_proof: ControllerRootProof
    parent_fd: int
    run_fd: int
    run_metadata: ControllerStatResult
    run: dict[str, object]
    root_mount_resolution: MountResolution
    mount_operation: str

    def revalidate(self) -> bool:
        try:
            current_root_proof = controller_root_proof(self.repository)
            parent_metadata = controller_fstat(self.parent_fd)
            require_mount_assurance(self.root_mount_resolution, self.mount_operation)
            require_same_mount(
                self.root_mount_resolution,
                self.parent_fd,
                ".",
            )
            require_same_mount(
                self.root_mount_resolution,
                self.run_fd,
                repository_mount_relative_path(self.root, self.run_dir),
            )
        except (OSError, TypeError, ValueError):
            return False
        return (
            current_root_proof.repository_identity_sha256
            == self.root_proof.repository_identity_sha256
            and current_root_proof.root_device == self.root_proof.root_device
            and current_root_proof.root_inode == self.root_proof.root_inode
            and self.run_metadata.st_dev == parent_metadata.st_dev
            and secure_directory_entry_matches(self.parent_fd, self.run_dir.name, self.run_metadata)
            and opened_directory_matches_path(self.run_dir, self.run_metadata, reject_mount=True)
            and controller_tree_is_private(self.run_fd)
        )


def lexical_managed_apply_run(
    root_candidate: Path,
    root: Path,
) -> tuple[Path, Path]:
    lexical_run_dir = lexical_absolute(root_candidate)
    selected_root = lexical_absolute(root)
    with open_repository_io(selected_root) as repository:
        root = canonical_repository_root(repository)
    run_dir = resolve_managed_apply_run_dir(
        root,
        lexical_run_dir,
        lexical_root=root,
    )
    return root, run_dir


@contextmanager
def open_verified_apply_run_for_mutation(
    run_dir: Path,
    *,
    root: Path,
    require_provenance: bool = True,
) -> Iterator[ApplyMutationHandle]:
    root, canonical_run_dir = lexical_managed_apply_run(run_dir, root)
    repository_session = open_repository_io(root)
    repository = repository_session.__enter__()
    parent_fd = -1
    opened_run_fd = -1
    try:
        root_proof = controller_root_proof(repository)
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
        )
        root_mount_resolution = resolve_apply_mount_identity(parent_fd, APPLY_RUN_MUTATION)
        parent_metadata = controller_fstat(parent_fd)
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
                repository=repository,
                root_proof=root_proof,
                parent_fd=parent_fd,
                run_fd=opened_run_fd,
                run_metadata=run_metadata,
                run=run,
                root_mount_resolution=root_mount_resolution,
                mount_operation=APPLY_RUN_MUTATION,
            )
            if not handle.revalidate() or load_regular_json_at(opened_run_fd, "Apply-Run.json") != run:
                raise ValueError("apply_run_mutation_identity_changed")
            yield handle
    finally:
        if opened_run_fd >= 0:
            controller_close(opened_run_fd)
        if parent_fd >= 0:
            controller_close(parent_fd)
        repository_session.__exit__(None, None, None)


@contextmanager
def open_verified_apply_run_for_read(
    run_dir: Path,
    *,
    root: Path,
) -> Iterator[ApplyMutationHandle]:
    """Open a registered run descriptor-relative without taking its writer lock."""

    root, canonical_run_dir = lexical_managed_apply_run(run_dir, root)
    repository_session = open_repository_io(root)
    repository = repository_session.__enter__()
    parent_fd = -1
    opened_run_fd = -1
    try:
        parent_fd = open_managed_apply_runs_root_fd(
            root,
            create=False,
            operation=READ_ONLY_EVIDENCE,
        )
        root_proof = controller_root_proof(repository)
        root_mount_resolution = resolve_apply_mount_identity(parent_fd, READ_ONLY_EVIDENCE)
        parent_metadata = controller_fstat(parent_fd)
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
            repository=repository,
            root_proof=root_proof,
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
            controller_close(opened_run_fd)
        if parent_fd >= 0:
            controller_close(parent_fd)
        repository_session.__exit__(None, None, None)


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
        controller_close(task_fd)


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
            controller_fsync(handle.run_fd)
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


def secure_write_apply_artifact(path: Path, text: str, *, root: Path) -> None:
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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


def _parse_ready_queue(text: str) -> list[dict[str, object]]:
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


def extract_ready_queue(
    root: Path,
    repository: RepositoryIO | None = None,
) -> list[dict[str, object]]:
    path = "Planner-docs/Sub-Planing-Audit.md"
    authoritative_text = repository_internal_text(
        root,
        path,
        repository=repository,
    )
    projected_text = repository_model_text(
        root,
        path,
        repository=repository,
    )
    if authoritative_text is None and projected_text is None:
        return []
    if authoritative_text is None or projected_text is None:
        raise ValueError("repository_model_projection_identity_mismatch")
    authoritative = _parse_ready_queue(authoritative_text)
    projected = _parse_ready_queue(projected_text)
    authority_keys = [
        (item["readiness_status"], item["subplan_path"])
        for item in authoritative
    ]
    projected_keys = [
        (item["readiness_status"], item["subplan_path"])
        for item in projected
    ]
    if authority_keys != projected_keys:
        raise ValueError("repository_model_projection_semantic_mismatch")
    return projected


def audit_text(root: Path, repository: RepositoryIO | None = None) -> str:
    return repository_internal_text(
        root,
        "Planner-docs/Sub-Planing-Audit.md",
        repository=repository,
    ) or ""


def run_step4_validator(root: Path) -> tuple[int, str]:
    # Bind the validator transcript to one canonical root spelling.  macOS can
    # expose a temporary directory through equivalent filesystem aliases;
    # hashing an alias without canonicalization makes an otherwise identical
    # readiness result appear stale on the next validation pass.
    root = canonical_controller_repository_root(root)
    return run_step4_readiness_validator(
        root=root,
    )


def validator_metric(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1].strip()
    return ""


def validate_step4_queue(
    root: Path,
    mode: str,
    repository: RepositoryIO | None = None,
) -> dict[str, str]:
    text = audit_text(root, repository)
    if not text:
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
    if not extract_ready_queue(root, repository):
        if "NO_ACTION_REQUIRED" in text:
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


def extract_subplan_contract(
    root: Path,
    subplan_path: str,
    repository: RepositoryIO | None = None,
) -> dict[str, list[str]]:
    text = repository_model_text(root, subplan_path, repository=repository)
    if text is None:
        return {key: [] for key in extract_contract_signals("").keys()}
    return extract_contract_signals(text)


def extract_implementation_contract(
    root: Path,
    subplan_path: str,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    binding = repository_contract_binding(root, subplan_path, repository=repository)
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


def default_tasks(
    root: Path,
    mode: str,
    run_id: str,
    ready_queue: list[dict[str, object]] | None = None,
    repository: RepositoryIO | None = None,
) -> list[dict[str, object]]:
    if mode == "no_action":
        return []
    queue = ready_queue if ready_queue is not None else extract_ready_queue(root, repository)
    tasks: list[dict[str, object]] = []
    for index, item in enumerate(queue, start=1):
        subplan_path = str(item["subplan_path"])
        binding = repository_contract_binding(root, subplan_path, repository=repository)
        contract = extract_subplan_contract(root, subplan_path, repository)
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
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    text = audit_text(root, repository)
    queue_state = validation.get("execution_queue_state", "")
    return {
        "audit_path": "Planner-docs/Sub-Planing-Audit.md",
        "audit_present": bool(text),
        "ready_queue_count": len(ready_queue),
        "no_action_required": queue_state == "NO_ACTION_REQUIRED" or "NO_ACTION_REQUIRED" in text,
        "validator_command": [
            "python3",
            "-I",
            "-S",
            "-B",
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
    with open_repository_io(root) as repository:
        root = canonical_repository_root(repository)
        root_proof = controller_root_proof(repository)
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
            root_proof=root_proof,
        )


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
    root_proof: ControllerRootProof,
) -> dict[str, object]:
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
    with open_repository_io(root) as repository:
        baseline, workspace_file_manifest = workspace_baseline_capture(root, repository)
        snapshot = collect_snapshot(root, baseline, repository)
        ready_queue = [] if mode == "no_action" else extract_ready_queue(root, repository)
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
        step4_validation = validate_step4_queue(root, mode, repository)
        step4_readiness = step4_readiness_summary(
            root,
            mode,
            ready_queue,
            step4_validation,
            repository,
        )
        policy = apply_policy_envelope(root, mode, baseline, step4_readiness)
        policy_digest = canonical_json_digest(policy)
        tasks = default_tasks(root, mode, run_id, ready_queue, repository)
        repository_baselines = capture_repository_baselines(root, tasks, repository)
    action_mode = mode != "no_action"
    non_git_action_mode = baseline["vcs"] == "non_git" and mode != "no_action"
    if non_git_action_mode and not allow_non_git_unsafe:
        raise ValueError("non_git_workspace_requires_explicit_approval")
    unverified_git_action_mode = action_mode and git_worktree_requires_approval(baseline)
    if unverified_git_action_mode and not allow_unverified_git_worktree:
        raise ValueError("git_workspace_requires_explicit_current_worktree_approval")
    if controller_entry_exists(run_dir) and not replace:
        raise ValueError(f"apply_run_already_exists={apply_run_logical_path(root, run_dir)}")

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
    if controller_entry_exists(run_dir) and replace:
        replace_existing_apply_run(
            root,
            run_dir,
            root_proof=root_proof,
        )
    parent_fd, run_fd, run_metadata = create_managed_apply_run_directory(
        root,
        run_dir,
    )
    state_mount_resolution = resolve_apply_mount_identity(parent_fd, APPLY_RUN_MUTATION)
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
            controller_mkdir(task_name, mode=0o700, dir_fd=run_fd)
            task_fd, task_metadata = open_child_directory(run_fd, task_name)
            try:
                controller_fchmod(task_fd, 0o700)
                task_metadata = controller_fstat(task_fd)
                require_apply_same_mount(
                    state_mount_resolution,
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
                controller_fsync(task_fd)
            finally:
                controller_close(task_fd)
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
        controller_fsync(run_fd)
        create_apply_run_registration(
            root,
            run_dir,
            run,
            root_proof=root_proof,
            parent_fd=parent_fd,
            run_fd=run_fd,
            run_metadata=run_metadata,
            root_mount_resolution=state_mount_resolution,
        )
        controller_fsync(parent_fd)
        if not controller_tree_is_private(run_fd):
            raise ValueError("apply_run_controller_state_not_private")
    finally:
        controller_close(run_fd)
        controller_close(parent_fd)
    return {"apply_run_id": run_id, "run_dir": run_dir.as_posix(), "state": result["status"]}


def reconcile_external_superpowers(
    run_dir: Path,
    *,
    root: Path,
) -> dict[str, object]:
    with open_verified_apply_run_for_mutation(
        run_dir,
        require_provenance=False,
        root=root,
    ) as handle:
        run_dir = handle.run_dir
        run = handle.run
        progress = secure_read_regular_json_at(handle.run_fd, "Progress.json")
        external = run.get("external_superpowers")
        if run.get("mode") != "external_superpowers":
            if external_superpowers_reconcile_is_valid(run):
                manifest_errors = apply_run_manifest_replace_errors(run)
                if manifest_errors:
                    raise ValueError(";".join(manifest_errors))
                refresh_apply_run_provenance(run_dir, run, root=handle.root)
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
            refresh_apply_run_provenance(run_dir, run, root=handle.root)
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
        refresh_apply_run_provenance(run_dir, run, root=handle.root)
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
        parent_fd = controller_open(path.parent, secure_directory_open_flags())
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
            controller_close(parent_fd)


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
    parent_fd = controller_open(path.parent, secure_directory_open_flags())
    try:
        return secure_read_regular_json_at(parent_fd, path.name)
    finally:
        controller_close(parent_fd)


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
    controller_fsync(handle.run_fd)
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
            if task_baseline.get("baseline_digest") != controller_baseline_digest(task_baseline.get("snapshot", [])):
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


def transition_task_state(
    run_dir: Path,
    task_id: str,
    to_state: str,
    actor: str,
    evidence: list[str] | None = None,
    *,
    root: Path,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "to_state": to_state, "actor": actor, "evidence": evidence or []}
    )
    if not safe_task_id(task_id):
        raise ValueError(f"invalid_task_id={task_id or 'missing'}")
    if to_state not in TASK_STATES:
        raise ValueError(f"invalid_target_state={to_state}")
    if not actor.strip():
        raise ValueError("transition_actor_required")
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
    return lexical_absolute(run_dir) / task_id


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
    *,
    root: Path,
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
    *,
    root: Path,
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
    *,
    root: Path,
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

    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
    *,
    root: Path,
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
    repository: RepositoryIO | None = None,
) -> str:
    if not isinstance(manifest, list):
        raise ValueError("repository_change_manifest_invalid")
    before_contents = baseline_content_map(baseline)
    sections: list[str] = []
    for item in manifest:
        if not isinstance(item, dict) or item.get("state") == "unchanged":
            continue
        path = controller_normalize_path(item.get("path"))
        state = str(item.get("state", ""))
        before = before_contents.get(path, b"")
        after = read_repository_file_no_follow(root, path, repository=repository)
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
    *,
    root: Path,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "actor": actor, "evidence": evidence or []}
    )
    if not actor.strip():
        raise ValueError("change_set_actor_required")
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
        with open_repository_io(handle.root) as repository:
            preliminary = capture_repository_io_evidence(
                handle.root,
                paths,
                baseline.get("snapshot", []),
                apply_run_id=str(run["apply_run_id"]),
                task_id=task_id,
                apply_run_registration_id=str(run["apply_run_registration_id"]),
                contract_digest=str(task["implementation_contract_digest"]),
                generation=generation,
                review_package_sha256=sha256_bytes(b""),
                repository=repository,
            )
            patch = controller_patch_for_manifest(
                handle.root,
                baseline,
                preliminary.get("manifest"),
                repository,
            )
            patch_sha = sha256_bytes(patch.encode("utf-8"))
            repository_evidence = capture_repository_io_evidence(
                handle.root,
                paths,
                baseline.get("snapshot", []),
                apply_run_id=str(run["apply_run_id"]),
                task_id=task_id,
                apply_run_registration_id=str(run["apply_run_registration_id"]),
                contract_digest=str(task["implementation_contract_digest"]),
                generation=generation,
                review_package_sha256=patch_sha,
                repository=repository,
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
            controller_fsync(task_fd)
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
    allowed_paths = baseline.get("allowed_paths", [])
    if not isinstance(allowed_paths, list) or not all(isinstance(path, str) for path in allowed_paths):
        raise ValueError(f"repository_baseline_path_mismatch={task_id}")
    with open_repository_io(handle.root) as repository:
        current = capture_repository_io_evidence(
            handle.root,
            allowed_paths,
            baseline.get("snapshot", []),
            apply_run_id=str(handle.run["apply_run_id"]),
            task_id=task_id,
            apply_run_registration_id=str(handle.run["apply_run_registration_id"]),
            contract_digest=str(task["implementation_contract_digest"]),
            generation=int(generation),
            review_package_sha256=patch_sha,
            repository=repository,
        )
        regenerated_patch = controller_patch_for_manifest(
            handle.root,
            baseline,
            current.get("manifest"),
            repository,
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
    if regenerated_patch != patch:
        raise ValueError(f"verified_live_diff_mismatch={task_id}")
    return payload, current


def receipt_run_binding(handle: ApplyMutationHandle) -> dict[str, object]:
    run = handle.run
    return {
        "root_binding_sha256": handle.root_proof.repository_identity_sha256,
        "root_device": handle.root_proof.root_device,
        "root_inode": handle.root_proof.root_inode,
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
    normalized = controller_normalize_path(value)
    path = lexical_absolute(root / normalized)
    try:
        metadata = controller_lstat(path)
    except FileNotFoundError as exc:
        raise ValueError("validation_cwd_missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or not is_inside(root, path):
        raise ValueError("validation_cwd_invalid")
    return normalized, path


def execute_planned_validation(
    run_dir: Path,
    task_id: str,
    validation_id: str,
    actor: str,
    evidence: list[str] | None = None,
    *,
    root: Path,
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
        if not command_is_safe(command, handle.root):
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
            repository=handle.repository,
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
        try:
            current_change_set, current_repository_evidence = load_current_change_set(handle, task)
        except ValueError as exc:
            # The validation process may mutate repository metadata before the
            # post-execution evidence pass can reopen the task through the
            # original repository identity.  That is itself mutation evidence,
            # not a reason to surface the lower-level handle error or publish a
            # receipt from an unobserved post-state.
            if str(exc) in {
                "apply_run_mutation_identity_changed",
                "apply_run_task_identity_changed",
            }:
                raise ValueError(
                    f"validation_command_mutated_repository={task_id}:{validation_id}"
                ) from exc
            raise
        if current_change_set.get("repository_state_digest") != change_set.get("repository_state_digest"):
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
                "host_sandbox_proof": NOT_OBSERVED,
                "approval_proof": NOT_OBSERVED,
                "network_enforcement_proof": NOT_OBSERVED,
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
            controller_fsync(task_fd)
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
    *,
    root: Path,
) -> dict[str, object]:
    assert_safe_persistent_payload(
        {"task_id": task_id, "phase": phase, "actor": actor, "evidence": evidence or []}
    )
    if phase not in REVIEW_PHASES:
        raise ValueError(f"invalid_review_phase={phase}")
    if not actor.strip():
        raise ValueError("review_receipt_actor_required")
    role = review_phase_expected_role(phase)
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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
            controller_fsync(task_fd)
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
    *,
    root: Path,
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
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
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


def finalize_apply_run(
    run_dir: Path,
    actor: str,
    evidence: list[str] | None = None,
    *,
    root: Path,
) -> dict[str, object]:
    assert_safe_persistent_payload({"actor": actor, "evidence": evidence or []})
    if not actor.strip():
        raise ValueError("finalize_actor_required")
    with open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
        for name in ("Progress.json", "Final-Review.json", "Result.json", "Events.jsonl"):
            if regular_target_metadata_at(handle.run_fd, name) is None:
                raise ValueError(f"missing_apply_artifact={name}")
        errors = validate_apply_run(handle.run_dir, handle.root, handle.repository)
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


def command_is_safe(command: object, root: Path | None = None, *, evidence: bool = False) -> bool:
    return isinstance(command, dict) and safe_validation_command_item(command, root=root, evidence=evidence)


def validate_dispatch_packet(run_dir: Path, run: dict[str, object], task: dict[str, object], errors: list[str]) -> None:
    task_id = str(task.get("task_id", ""))
    if not safe_task_id(task_id):
        return
    task_dir = lexical_absolute(run_dir) / task_id
    packet_path = task_dir / "Dispatch-Packet.json"
    state = str(task.get("state", ""))
    if run.get("mode") == "subagent_serial" and state not in {"BRIEFED", "BLOCKED", "NEEDS_CONTEXT"}:
        if not controller_regular_entry_exists(packet_path):
            errors.append(f"subagent_dispatch_packet_missing={task_id}")
            return
    if not controller_regular_entry_exists(packet_path):
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


def validate_task_source_binding(
    root: Path,
    task: dict[str, object],
    errors: list[str],
    repository: RepositoryIO | None = None,
) -> None:
    task_id = str(task.get("task_id", ""))
    source_path = task.get("source_subplan_path")
    if not isinstance(source_path, str) or not source_path.strip():
        errors.append(f"missing_source_subplan_path={task_id}")
        return
    binding = repository_contract_binding(root, source_path, repository=repository)
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
        task_metadata = controller_lstat(task_dir)
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
    if locks and not controller_regular_entry_exists(path):
        errors.append("active_writer_lock_missing_file")
    if controller_regular_entry_exists(path):
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
    repository: RepositoryIO | None = None,
) -> None:
    if root is None or mode not in APPLY_MODES:
        return
    try:
        validation = validate_step4_queue(root, mode, repository)
    except ValueError as exc:
        errors.append(f"apply_policy_step4_readiness_unavailable={exc}")
        return
    readiness = step4_readiness_summary(root, mode, ready_queue, validation, repository)
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


def validate_apply_run(
    run_dir: Path,
    root: Path,
    repository: RepositoryIO | None = None,
) -> list[str]:
    errors: list[str] = []
    run_dir = lexical_absolute(run_dir)
    root = lexical_absolute(root)
    if repository is None:
        try:
            with open_repository_io(root) as opened:
                canonical_root = canonical_repository_root(opened)
                managed_run_dir = resolve_managed_apply_run_dir(
                    canonical_root,
                    run_dir,
                    lexical_root=root,
                )
                return validate_apply_run(
                    managed_run_dir,
                    canonical_root,
                    opened,
                )
        except (OSError, TypeError, ValueError) as exc:
            return [f"repository_io_failed={str(exc).split('=', 1)[0]}"]
    try:
        root = canonical_repository_root(repository)
        run_dir = resolve_managed_apply_run_dir(
            root,
            run_dir,
            lexical_root=root,
        )
    except (OSError, TypeError, ValueError) as exc:
        return [f"apply_run_path_rejected={str(exc).split('=', 1)[0]}"]
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
        validate_apply_policy(
            root,
            run,
            requested_mode,
            baseline,
            ready_queue,
            errors,
            repository,
        )

    if root is not None:
        try:
            current_snapshot = collect_snapshot(root, snapshot_baseline, repository)
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
                if task_baseline.get("baseline_digest") != controller_baseline_digest(task_baseline.get("snapshot", [])):
                    errors.append(f"repository_baseline_digest_mismatch={task_id}")
                baseline_content_map(task_baseline)
            except (TypeError, ValueError) as exc:
                errors.append(f"repository_baseline_invalid={task_id}:{exc}")
    source_task_digests: dict[str, str] = {}
    for index, task in enumerate([item for item in tasks if isinstance(item, dict)], start=1):
        task_id = str(task.get("task_id", ""))
        if root is not None:
            validate_task_source_binding(root, task, errors, repository)
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
            with open_verified_apply_run_for_read(run_dir, root=root) as evidence_handle:
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
        del message
        self.exit(2, f"{safe_log_text(self.prog)}: error: controller_arguments_invalid\n")


def _read_controller_stdin_argv() -> list[str]:
    """Read one bounded argv array from process stdin, never from shell text."""

    raw = sys.stdin.buffer.read(MAX_CONTROLLER_STDIN_REQUEST_BYTES + 1)
    if len(raw) > MAX_CONTROLLER_STDIN_REQUEST_BYTES:
        raise ValueError("apply_controller_request_too_large")
    try:
        decoded = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("apply_controller_request_non_utf8") from None
    request = parse_safe_persistent_json(decoded)
    if (
        not isinstance(request, dict)
        or frozenset(request) != {"schema", "argv"}
        or request.get("schema") != CONTROLLER_STDIN_REQUEST_SCHEMA
    ):
        raise ValueError("apply_controller_request_invalid")
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
        raise ValueError("apply_controller_request_invalid")
    return list(raw_argv)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    stdin_request_mode = arguments == ["request-stdin"]
    if stdin_request_mode:
        try:
            arguments = _read_controller_stdin_argv()
        except (OSError, TypeError, ValueError):
            print("apply_run_status=failed", file=sys.stderr)
            print("error=controller_request_rejected", file=sys.stderr)
            return 1
    parser = SafeArgumentParser(prog="apply_run.py", description="Manage CodexQB apply-run artifact contracts.")
    sub = parser.add_subparsers(dest="command", required=True)
    for command_name in ("init", "prepare"):
        prepare = sub.add_parser(command_name, help="Create an apply-run artifact directory.")
        prepare.add_argument("--root", required=True)
        prepare.add_argument("--mode", default="subagent_serial", choices=sorted(APPLY_MODES))
        prepare.add_argument("--output-dir")
        prepare.add_argument("--replace", action="store_true")
        prepare.add_argument("--resume", action="store_true")
        prepare.add_argument("--run-id-suffix")
        prepare.add_argument("--allow-non-git-unsafe", action="store_true")
        prepare.add_argument("--allow-unverified-git-worktree", action="store_true")
    check = sub.add_parser("validate", help="Validate an apply-run artifact directory.")
    check.add_argument("--run-dir", required=True)
    check.add_argument("--root", required=True)
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
    for rooted_parser in (
        transition,
        dispatch,
        record_agent,
        normalize_writer,
        normalize_review,
        capture_evidence,
        run_validation,
        publish_review,
        reconcile,
        recover,
        finalize,
    ):
        rooted_parser.add_argument("--root", required=True)
    args = parser.parse_args(arguments)

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
            event = transition_task_state(
                Path(args.run_dir),
                args.task_id,
                args.to,
                args.actor,
                args.evidence,
                root=Path(args.root),
            )
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
                root=Path(args.root),
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
                root=Path(args.root),
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
                root=Path(args.root),
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
                root=Path(args.root),
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
                Path(args.run_dir),
                args.task_id,
                args.actor,
                args.evidence,
                root=Path(args.root),
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
                root=Path(args.root),
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
                root=Path(args.root),
            )
            print("apply_run_status=review_receipt_published")
            print_safe_field("task_id", args.task_id)
            print_safe_field("review_phase", args.review_phase)
            print_safe_field("receipt_id", result["receipt_id"])
            print_safe_field("receipt_path", result["receipt_path"])
            return 0
        if args.command == "reconcile":
            result = reconcile_external_superpowers(
                Path(args.run_dir),
                root=Path(args.root),
            )
            print_safe_field("apply_run_status", result["state"])
            print_safe_field("mode", result["mode"])
            if "event_sequence" in result:
                print_safe_field("event_sequence", result["event_sequence"])
            return 0
        if args.command == "recover-lock":
            event = recover_stale_writer_lock(
                Path(args.run_dir),
                args.task_id,
                args.to,
                args.actor,
                args.evidence,
                root=Path(args.root),
            )
            print("apply_run_status=recovered")
            print_safe_field("event_sequence", event["sequence"])
            print_safe_field("task_id", args.task_id)
            print_safe_field("state", args.to)
            return 0
        if args.command == "finalize":
            event = finalize_apply_run(
                Path(args.run_dir),
                args.actor,
                args.evidence,
                root=Path(args.root),
            )
            print("apply_run_status=finalized")
            print_safe_field("event_sequence", event["sequence"])
            return 0
        errors = validate_apply_run(Path(args.run_dir), Path(args.root))
    except Exception as exc:
        print("apply_run_status=failed", file=sys.stderr)
        if stdin_request_mode:
            print("error=controller_request_failed", file=sys.stderr)
        else:
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
