#!/usr/bin/env python3
"""Pure controller-observed evidence receipt contracts for CodexQB.

This module deliberately performs no filesystem or process I/O.  It defines
the canonical representation, strict shapes, and domain-separated HMACs used
by the Apply controller when it publishes validation and review receipts.
The receipts attest controller-observed results and hashes only; they do not
claim host sandbox, user approval, or network-enforcement proof.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
from datetime import datetime, timezone


VALIDATION_RECEIPT_KIND = "codexqb_validation_execution_receipt"
VALIDATION_RECEIPT_VERSION = 1
VALIDATION_OBSERVATION_SCOPE = "controller_observed_process_result_and_local_hashes"

REVIEW_COMPLETION_RECEIPT_KIND = "codexqb_review_completion_receipt"
REVIEW_COMPLETION_RECEIPT_VERSION = 1
REVIEW_COMPLETION_OBSERVATION_SCOPE = "controller_observed_reviewer_completion_and_artifact_hashes"

CONTROLLER_OBSERVER = "codexqb_controller"
NOT_OBSERVED = "not_observed"
# Network-enforcement proofs a *validation* receipt may carry when the
# cross-platform JavaScript validation profile kernel-denies outbound INET
# sockets: seccomp (Linux) or the sandbox-exec seatbelt (macOS).  Every other
# receipt proof field — and every review-completion receipt — stays fail-closed
# at ``not_observed``; arbitrary strings remain rejected.
ENFORCED_SECCOMP_INET_DENY = "enforced_seccomp_inet_deny"
ENFORCED_SEATBELT_DENY_NETWORK = "enforced_seatbelt_deny_network"
JS_VALIDATION_NETWORK_ENFORCEMENT_PROOFS = frozenset(
    {ENFORCED_SECCOMP_INET_DENY, ENFORCED_SEATBELT_DENY_NETWORK}
)
# Repository-write prevention status recorded in ``host_sandbox_proof`` of a
# *validation* receipt, so an ``enforced_*`` network claim is never mistaken for
# an *also*-enforced repo-write claim.  Repo writes must be PREVENTIVELY denied:
# on macOS the seatbelt does so; on Linux Landlock does so, and when the kernel
# lacks Landlock the JS validation FAILS CLOSED (no execution, no receipt) rather
# than relying on the post-hoc digest as a substitute — so a JS validation receipt
# can only ever attest to real prevention.  Every other proof field stays
# ``not_observed``.
ENFORCED_SEATBELT_REPO_WRITE_DENY = "enforced_seatbelt_repo_write_deny"
ENFORCED_LANDLOCK_REPO_WRITE_DENY = "enforced_landlock_repo_write_deny"
JS_VALIDATION_HOST_SANDBOX_PROOFS = frozenset(
    {
        ENFORCED_SEATBELT_REPO_WRITE_DENY,
        ENFORCED_LANDLOCK_REPO_WRITE_DENY,
    }
)
RECEIPT_MAC_FIELD = "receipt_mac"
MASTER_KEY_BYTES = 32

VALIDATION_KEY_DOMAIN = b"codexqb.validation-receipt.key.v1"
VALIDATION_MAC_DOMAIN = b"codexqb.validation-receipt.v1\0"
REVIEW_KEY_DOMAIN = b"codexqb.review-completion-receipt.key.v1"
REVIEW_MAC_DOMAIN = b"codexqb.review-completion-receipt.v1\0"

SHA256_RE = re.compile(r"[a-f0-9]{64}")
KEY_ID_RE = re.compile(r"[a-f0-9]{32}")
VALIDATION_ID_RE = re.compile(r"VAL-[A-Z0-9_.-]{1,60}")
APPLY_RUN_ID_RE = re.compile(
    r"apply-(?:direct|external_superpowers|no_action|subagent_serial)-[a-f0-9]{12}-[A-Za-z0-9_.-]+"
)
TASK_ID_RE = re.compile(r"AR-apply-[A-Za-z0-9_.-]+-T\d{3}")
AGENT_ID_RE = re.compile(r"[A-Za-z0-9_.:-]{3,160}")
UTC_TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")
SAFE_PATH_SEGMENT_RE = re.compile(r"[A-Za-z0-9._@+,=-]+")
RESERVED_ARTIFACT_SEGMENTS = frozenset({".codex", ".codexqb", ".git"})

WORKSPACE_MODES = frozenset(
    {"non_git_unsafe", "unverified_current_worktree", "verified_isolated_worktree"}
)
PRODUCER_ROLES = frozenset({"controller", "fixer", "implementer"})
REVIEWER_ROLES = frozenset({"controller", "final_reviewer", "security_reviewer", "task_reviewer"})
REVIEW_VERDICTS = frozenset({"cannot_verify", "fail", "needs_fixes", "pass"})
CHANGE_KINDS = frozenset({"added", "deleted", "modified"})
TERMINATION_REASONS = frozenset({"exited", "signal", "timeout"})

COMMON_TOP_LEVEL_FIELDS = frozenset(
    {
        "receipt_kind",
        "receipt_version",
        "receipt_id",
        "trust_key_id",
        "issued_at",
        "observer",
        "observation_scope",
        "host_sandbox_proof",
        "approval_proof",
        "network_enforcement_proof",
        "run_binding",
        "task_binding",
    }
)
RUN_BINDING_FIELDS = frozenset(
    {
        "root_binding_sha256",
        "root_device",
        "root_inode",
        "apply_run_registration_id",
        "apply_run_id",
        "apply_spec_digest",
        "workspace_mode",
    }
)
TASK_BINDING_FIELDS = frozenset(
    {
        "task_id",
        "brief_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
        "implementation_generation",
        "fix_cycle_count",
    }
)
PRODUCER_BINDING_FIELDS = frozenset(
    {
        "producer_kind",
        "identity_assurance",
        "role",
        "agent_id",
        "attempt",
        "completed_event_sequence",
        "agent_run_sha256",
        "observed_after_event_sequence",
    }
)
COMMAND_FIELDS = frozenset(
    {
        "validation_id",
        "planned_command_digest",
        "argv",
        "cwd",
        "expected_exit_code",
        "timeout_seconds",
        "planned_network",
        "probe_tier",
        "execution_nonce",
        "started_at",
        "finished_at",
    }
)
RESULT_FIELDS = frozenset(
    {
        "exit_code",
        "timed_out",
        "termination_reason",
        "stdout_sha256",
        "stderr_sha256",
        "combined_output_sha256",
        "stdout_bytes",
        "stderr_bytes",
        "combined_output_bytes",
        "artifacts",
    }
)
ARTIFACT_FIELDS = frozenset({"path", "sha256"})
SNAPSHOT_FIELDS = frozenset(
    {
        "captured_at",
        "vcs",
        "head_commit",
        "base_commit",
        "git_status_porcelain_sha256",
        "staged_diff_sha256",
        "unstaged_diff_sha256",
        "untracked_inventory_sha256",
        "review_package_sha256",
        "changed_files",
        "changed_files_sha256",
    }
)
CHANGED_FILE_FIELDS = frozenset({"path", "change", "before_sha256", "after_sha256"})
REVIEWER_BINDING_FIELDS = frozenset(
    {
        "reviewer_kind",
        "identity_assurance",
        "role",
        "agent_id",
        "attempt",
        "dispatch_packet_sha256",
        "agent_run_sha256",
        "completed_at",
    }
)
VALIDATION_RECEIPT_REFERENCE_FIELDS = frozenset({"receipt_id", "receipt_sha256"})
REVIEW_BINDING_FIELDS = frozenset(
    {
        "task_review_sha256",
        "review_package_sha256",
        "code_snapshot_sha256",
        "validation_receipts",
        "validation_receipt_set_sha256",
        "verdict",
    }
)
ORDERING_FIELDS = frozenset(
    {
        "producer_completed_event_sequence",
        "validation_receipts_published_event_sequence",
        "reviewer_dispatch_event_sequence",
        "reviewer_spawned_event_sequence",
        "reviewer_completed_event_sequence",
        "receipt_issued_after_event_sequence",
    }
)


class ReceiptValidationError(ValueError):
    """Raised when an unsigned receipt cannot be signed safely."""


def _validate_json_tree(value: object, path: str = "$") -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError(f"non_finite_json_number={path}")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _validate_json_tree(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError(f"json_object_key_must_be_string={path}")
            _validate_json_tree(item, f"{path}.{key}")
        return
    raise TypeError(f"unsupported_json_type={path}:{type(value).__name__}")


def canonical_json_bytes(value: object) -> bytes:
    """Return deterministic UTF-8 JSON bytes for the supported JSON tree."""

    _validate_json_tree(value)
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def canonical_json_digest(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def trust_key_id(master_key: bytes) -> str:
    _require_master_key(master_key)
    return hashlib.sha256(master_key).hexdigest()[:32]


def _require_master_key(master_key: bytes) -> None:
    if not isinstance(master_key, bytes):
        raise TypeError("receipt_master_key_must_be_bytes")
    if len(master_key) != MASTER_KEY_BYTES:
        raise ValueError("receipt_master_key_must_be_32_bytes")


def _derive_key(master_key: bytes, domain: bytes) -> bytes:
    _require_master_key(master_key)
    return hmac.new(master_key, domain, hashlib.sha256).digest()


def derive_validation_receipt_key(master_key: bytes) -> bytes:
    return _derive_key(master_key, VALIDATION_KEY_DOMAIN)


def derive_review_completion_receipt_key(master_key: bytes) -> bytes:
    return _derive_key(master_key, REVIEW_KEY_DOMAIN)


def is_safe_artifact_path(value: object, *, allow_dot: bool = False) -> bool:
    """Accept one canonical repository-relative POSIX path without traversal."""

    if not isinstance(value, str) or not value or value != value.strip():
        return False
    if value == ".":
        return allow_dot
    if "\\" in value or "\x00" in value or value.startswith("/") or value.endswith("/"):
        return False
    parts = value.split("/")
    if any(
        not part
        or part in {".", ".."}
        or part.casefold() in RESERVED_ARTIFACT_SEGMENTS
        or SAFE_PATH_SEGMENT_RE.fullmatch(part) is None
        for part in parts
    ):
        return False
    return True


def _is_int(value: object, *, minimum: int | None = None, maximum: int | None = None) -> bool:
    if not isinstance(value, int) or isinstance(value, bool):
        return False
    if minimum is not None and value < minimum:
        return False
    if maximum is not None and value > maximum:
        return False
    return True


def _is_hash(value: object, pattern: re.Pattern[str] = SHA256_RE) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _timestamp(value: object) -> datetime | None:
    if not isinstance(value, str) or UTC_TIMESTAMP_RE.fullmatch(value) is None:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc)


def _exact_object(
    value: object,
    fields: frozenset[str],
    path: str,
    errors: list[str],
) -> dict[str, object] | None:
    if not isinstance(value, dict):
        errors.append(f"invalid_object={path}")
        return None
    object_keys = {key for key in value if isinstance(key, str)}
    if len(object_keys) != len(value):
        errors.append(f"invalid_object_key={path}")
    missing = fields - object_keys
    unknown = object_keys - fields
    errors.extend(f"missing_field={path}.{field}" for field in sorted(missing))
    errors.extend(f"unknown_field={path}.{field}" for field in sorted(unknown))
    return value


def _validate_common(
    receipt: object,
    *,
    kind: str,
    version: int,
    observation_scope: str,
    domain_fields: frozenset[str],
    require_mac: bool,
    errors: list[str],
) -> dict[str, object] | None:
    fields = COMMON_TOP_LEVEL_FIELDS | domain_fields
    if require_mac:
        fields |= {RECEIPT_MAC_FIELD}
    value = _exact_object(receipt, frozenset(fields), "receipt", errors)
    if value is None:
        return None
    if value.get("receipt_kind") != kind:
        errors.append("invalid_receipt_kind")
    if value.get("receipt_version") != version or isinstance(value.get("receipt_version"), bool):
        errors.append("invalid_receipt_version")
    if not _is_hash(value.get("receipt_id")):
        errors.append("invalid_receipt_id")
    if not _is_hash(value.get("trust_key_id"), KEY_ID_RE):
        errors.append("invalid_trust_key_id")
    if _timestamp(value.get("issued_at")) is None:
        errors.append("invalid_timestamp=receipt.issued_at")
    if value.get("observer") != CONTROLLER_OBSERVER:
        errors.append("invalid_receipt_observer")
    if value.get("observation_scope") != observation_scope:
        errors.append("invalid_observation_scope")
    if value.get("approval_proof") != NOT_OBSERVED:
        errors.append("invalid_nonclaim=approval_proof")
    # A validation receipt may promote two fields beyond ``not_observed`` — and
    # only to recognized JS-profile proofs: ``network_enforcement_proof`` to a
    # kernel-network-denial proof, and ``host_sandbox_proof`` to a repo-write
    # prevention status.  Review-completion receipts (and any other value) stay
    # fail-closed.
    allowed_network_proofs = {NOT_OBSERVED}
    allowed_host_sandbox_proofs = {NOT_OBSERVED}
    if kind == VALIDATION_RECEIPT_KIND:
        allowed_network_proofs = allowed_network_proofs | JS_VALIDATION_NETWORK_ENFORCEMENT_PROOFS
        allowed_host_sandbox_proofs = allowed_host_sandbox_proofs | JS_VALIDATION_HOST_SANDBOX_PROOFS
    if value.get("network_enforcement_proof") not in allowed_network_proofs:
        errors.append("invalid_nonclaim=network_enforcement_proof")
    if value.get("host_sandbox_proof") not in allowed_host_sandbox_proofs:
        errors.append("invalid_nonclaim=host_sandbox_proof")
    if require_mac and not _is_hash(value.get(RECEIPT_MAC_FIELD)):
        errors.append("invalid_receipt_mac")
    _validate_run_binding(value.get("run_binding"), errors)
    _validate_task_binding(value.get("task_binding"), errors)
    return value


def _validate_run_binding(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, RUN_BINDING_FIELDS, "receipt.run_binding", errors)
    if obj is None:
        return
    for field in ("root_binding_sha256", "apply_run_registration_id", "apply_spec_digest"):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256=receipt.run_binding.{field}")
    if not _is_int(obj.get("root_device"), minimum=0):
        errors.append("invalid_integer=receipt.run_binding.root_device")
    if not _is_int(obj.get("root_inode"), minimum=1):
        errors.append("invalid_integer=receipt.run_binding.root_inode")
    if not isinstance(obj.get("apply_run_id"), str) or APPLY_RUN_ID_RE.fullmatch(str(obj.get("apply_run_id"))) is None:
        errors.append("invalid_apply_run_id")
    if obj.get("workspace_mode") not in WORKSPACE_MODES:
        errors.append("invalid_workspace_mode")


def _validate_task_binding(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, TASK_BINDING_FIELDS, "receipt.task_binding", errors)
    if obj is None:
        return
    if not isinstance(obj.get("task_id"), str) or TASK_ID_RE.fullmatch(str(obj.get("task_id"))) is None:
        errors.append("invalid_task_id")
    for field in ("brief_sha256", "implementation_contract_digest", "task_contract_digest"):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256=receipt.task_binding.{field}")
    for field in ("implementation_generation", "fix_cycle_count"):
        if not _is_int(obj.get(field), minimum=0):
            errors.append(f"invalid_integer=receipt.task_binding.{field}")


def _validate_producer_binding(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, PRODUCER_BINDING_FIELDS, "receipt.producer_binding", errors)
    if obj is None:
        return
    kind = obj.get("producer_kind")
    role = obj.get("role")
    if kind not in {"agent", "controller_direct"}:
        errors.append("invalid_producer_kind")
    if obj.get("identity_assurance") != "controller_asserted":
        errors.append("invalid_producer_identity_assurance")
    if role not in PRODUCER_ROLES:
        errors.append("invalid_producer_role")
    if not _is_int(obj.get("observed_after_event_sequence"), minimum=1):
        errors.append("invalid_integer=receipt.producer_binding.observed_after_event_sequence")
    if kind == "agent":
        if role not in {"fixer", "implementer"}:
            errors.append("invalid_agent_producer_role")
        if not isinstance(obj.get("agent_id"), str) or AGENT_ID_RE.fullmatch(str(obj.get("agent_id"))) is None:
            errors.append("invalid_producer_agent_id")
        if not _is_int(obj.get("attempt"), minimum=1):
            errors.append("invalid_integer=receipt.producer_binding.attempt")
        if not _is_int(obj.get("completed_event_sequence"), minimum=1):
            errors.append("invalid_integer=receipt.producer_binding.completed_event_sequence")
        if not _is_hash(obj.get("agent_run_sha256")):
            errors.append("invalid_sha256=receipt.producer_binding.agent_run_sha256")
        if _is_int(obj.get("completed_event_sequence"), minimum=1) and _is_int(
            obj.get("observed_after_event_sequence"), minimum=1
        ) and int(obj["completed_event_sequence"]) > int(obj["observed_after_event_sequence"]):
            errors.append("producer_observed_before_completion")
    elif kind == "controller_direct":
        if role != "controller":
            errors.append("invalid_direct_producer_role")
        if obj.get("identity_assurance") != "controller_asserted":
            errors.append("invalid_direct_producer_identity_assurance")
        for field in ("agent_id", "attempt", "completed_event_sequence", "agent_run_sha256"):
            if obj.get(field) is not None:
                errors.append(f"direct_producer_field_must_be_null={field}")


def _validate_command(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, COMMAND_FIELDS, "receipt.command", errors)
    if obj is None:
        return
    if not isinstance(obj.get("validation_id"), str) or VALIDATION_ID_RE.fullmatch(
        str(obj.get("validation_id"))
    ) is None:
        errors.append("invalid_validation_id")
    for field in ("planned_command_digest", "execution_nonce"):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256=receipt.command.{field}")
    argv = obj.get("argv")
    if not isinstance(argv, list) or len(argv) < 2 or any(not isinstance(item, str) or not item for item in argv):
        errors.append("invalid_command_argv")
    if not is_safe_artifact_path(obj.get("cwd"), allow_dot=True):
        errors.append("invalid_command_cwd")
    if obj.get("expected_exit_code") != 0 or isinstance(obj.get("expected_exit_code"), bool):
        errors.append("invalid_expected_exit_code")
    if not _is_int(obj.get("timeout_seconds"), minimum=1, maximum=3600):
        errors.append("invalid_integer=receipt.command.timeout_seconds")
    if obj.get("planned_network") != "deny":
        errors.append("invalid_planned_network")
    if obj.get("probe_tier") != 1 or isinstance(obj.get("probe_tier"), bool):
        errors.append("invalid_probe_tier")
    started = _timestamp(obj.get("started_at"))
    finished = _timestamp(obj.get("finished_at"))
    if started is None:
        errors.append("invalid_timestamp=receipt.command.started_at")
    if finished is None:
        errors.append("invalid_timestamp=receipt.command.finished_at")
    if started is not None and finished is not None and finished < started:
        errors.append("command_finished_before_started")


def _validate_artifact_list(value: object, errors: list[str], path: str) -> None:
    if not isinstance(value, list):
        errors.append(f"invalid_array={path}")
        return
    paths: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        obj = _exact_object(item, ARTIFACT_FIELDS, item_path, errors)
        if obj is None:
            continue
        artifact_path = obj.get("path")
        if not is_safe_artifact_path(artifact_path):
            errors.append(f"invalid_artifact_path={item_path}.path")
        elif isinstance(artifact_path, str):
            paths.append(artifact_path)
        if not _is_hash(obj.get("sha256")):
            errors.append(f"invalid_sha256={item_path}.sha256")
    if len(paths) != len(set(paths)):
        errors.append(f"duplicate_artifact_path={path}")
    if paths != sorted(paths):
        errors.append(f"unsorted_artifact_paths={path}")


def _validate_result(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, RESULT_FIELDS, "receipt.result", errors)
    if obj is None:
        return
    if not _is_int(obj.get("exit_code"), minimum=-(2**31), maximum=2**31 - 1):
        errors.append("invalid_integer=receipt.result.exit_code")
    if not isinstance(obj.get("timed_out"), bool):
        errors.append("invalid_boolean=receipt.result.timed_out")
    reason = obj.get("termination_reason")
    if reason not in TERMINATION_REASONS:
        errors.append("invalid_termination_reason")
    if isinstance(obj.get("timed_out"), bool) and (obj["timed_out"] is True) != (reason == "timeout"):
        errors.append("timeout_reason_mismatch")
    for field in ("stdout_sha256", "stderr_sha256", "combined_output_sha256"):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256=receipt.result.{field}")
    for field in ("stdout_bytes", "stderr_bytes", "combined_output_bytes"):
        if not _is_int(obj.get(field), minimum=0):
            errors.append(f"invalid_integer=receipt.result.{field}")
    if all(_is_int(obj.get(field), minimum=0) for field in ("stdout_bytes", "stderr_bytes", "combined_output_bytes")):
        if int(obj["stdout_bytes"]) + int(obj["stderr_bytes"]) != int(obj["combined_output_bytes"]):
            errors.append("combined_output_byte_count_mismatch")
    _validate_artifact_list(obj.get("artifacts"), errors, "receipt.result.artifacts")


def _validate_changed_files(value: object, digest: object, errors: list[str], path: str) -> None:
    if not isinstance(value, list):
        errors.append(f"invalid_array={path}")
        return
    paths: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        obj = _exact_object(item, CHANGED_FILE_FIELDS, item_path, errors)
        if obj is None:
            continue
        artifact_path = obj.get("path")
        if not is_safe_artifact_path(artifact_path):
            errors.append(f"invalid_artifact_path={item_path}.path")
        elif isinstance(artifact_path, str):
            paths.append(artifact_path)
        change = obj.get("change")
        if change not in CHANGE_KINDS:
            errors.append(f"invalid_change_kind={item_path}.change")
        before = obj.get("before_sha256")
        after = obj.get("after_sha256")
        if before is not None and not _is_hash(before):
            errors.append(f"invalid_sha256={item_path}.before_sha256")
        if after is not None and not _is_hash(after):
            errors.append(f"invalid_sha256={item_path}.after_sha256")
        if change == "added" and (before is not None or not _is_hash(after)):
            errors.append(f"malformed_changed_file={item_path}:added")
        elif change == "deleted" and (not _is_hash(before) or after is not None):
            errors.append(f"malformed_changed_file={item_path}:deleted")
        elif change == "modified" and (not _is_hash(before) or not _is_hash(after) or before == after):
            errors.append(f"malformed_changed_file={item_path}:modified")
    if len(paths) != len(set(paths)):
        errors.append(f"duplicate_artifact_path={path}")
    if paths != sorted(paths):
        errors.append(f"unsorted_artifact_paths={path}")
    try:
        actual_digest = canonical_json_digest(value)
    except (TypeError, ValueError):
        actual_digest = None
    if not _is_hash(digest) or digest != actual_digest:
        errors.append(f"changed_files_digest_mismatch={path}")


def _validate_snapshot(value: object, errors: list[str], path: str) -> None:
    obj = _exact_object(value, SNAPSHOT_FIELDS, path, errors)
    if obj is None:
        return
    if _timestamp(obj.get("captured_at")) is None:
        errors.append(f"invalid_timestamp={path}.captured_at")
    vcs = obj.get("vcs")
    if vcs not in {"git", "non_git"}:
        errors.append(f"invalid_vcs={path}.vcs")
    head = obj.get("head_commit")
    base = obj.get("base_commit")
    if vcs == "git":
        commit_re = re.compile(r"[a-f0-9]{40}|[a-f0-9]{64}")
        if not isinstance(head, str) or commit_re.fullmatch(head) is None:
            errors.append(f"invalid_git_commit={path}.head_commit")
        if not isinstance(base, str) or commit_re.fullmatch(base) is None:
            errors.append(f"invalid_git_commit={path}.base_commit")
    elif vcs == "non_git" and (head != "not_applicable" or base != "not_applicable"):
        errors.append(f"non_git_commit_must_be_not_applicable={path}")
    for field in (
        "git_status_porcelain_sha256",
        "staged_diff_sha256",
        "unstaged_diff_sha256",
        "untracked_inventory_sha256",
        "review_package_sha256",
    ):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256={path}.{field}")
    _validate_changed_files(obj.get("changed_files"), obj.get("changed_files_sha256"), errors, f"{path}.changed_files")


def validation_receipt_errors(receipt: object, *, require_mac: bool = True) -> list[str]:
    errors: list[str] = []
    value = _validate_common(
        receipt,
        kind=VALIDATION_RECEIPT_KIND,
        version=VALIDATION_RECEIPT_VERSION,
        observation_scope=VALIDATION_OBSERVATION_SCOPE,
        domain_fields=frozenset(
            {"producer_binding", "command", "result", "code_snapshot_before", "code_snapshot_after"}
        ),
        require_mac=require_mac,
        errors=errors,
    )
    if value is None:
        return errors
    _validate_producer_binding(value.get("producer_binding"), errors)
    _validate_command(value.get("command"), errors)
    _validate_result(value.get("result"), errors)
    _validate_snapshot(value.get("code_snapshot_before"), errors, "receipt.code_snapshot_before")
    _validate_snapshot(value.get("code_snapshot_after"), errors, "receipt.code_snapshot_after")

    issued = _timestamp(value.get("issued_at"))
    command = value.get("command") if isinstance(value.get("command"), dict) else {}
    before = value.get("code_snapshot_before") if isinstance(value.get("code_snapshot_before"), dict) else {}
    after = value.get("code_snapshot_after") if isinstance(value.get("code_snapshot_after"), dict) else {}
    started = _timestamp(command.get("started_at"))
    finished = _timestamp(command.get("finished_at"))
    before_at = _timestamp(before.get("captured_at"))
    after_at = _timestamp(after.get("captured_at"))
    if before_at is not None and started is not None and before_at > started:
        errors.append("snapshot_before_captured_after_command_started")
    if after_at is not None and finished is not None and after_at < finished:
        errors.append("snapshot_after_captured_before_command_finished")
    if issued is not None and after_at is not None and issued < after_at:
        errors.append("receipt_issued_before_snapshot_after")
    return errors


def _validate_reviewer_binding(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, REVIEWER_BINDING_FIELDS, "receipt.reviewer_binding", errors)
    if obj is None:
        return
    kind = obj.get("reviewer_kind")
    role = obj.get("role")
    if kind not in {"agent", "controller_direct"}:
        errors.append("invalid_reviewer_kind")
    if obj.get("identity_assurance") != "controller_asserted":
        errors.append("invalid_reviewer_identity_assurance")
    if role not in REVIEWER_ROLES:
        errors.append("invalid_reviewer_role")
    if _timestamp(obj.get("completed_at")) is None:
        errors.append("invalid_timestamp=receipt.reviewer_binding.completed_at")
    if kind == "agent":
        if role not in {"final_reviewer", "security_reviewer", "task_reviewer"}:
            errors.append("invalid_agent_reviewer_role")
        if not isinstance(obj.get("agent_id"), str) or AGENT_ID_RE.fullmatch(str(obj.get("agent_id"))) is None:
            errors.append("invalid_reviewer_agent_id")
        if not _is_int(obj.get("attempt"), minimum=1):
            errors.append("invalid_integer=receipt.reviewer_binding.attempt")
        for field in ("dispatch_packet_sha256", "agent_run_sha256"):
            if not _is_hash(obj.get(field)):
                errors.append(f"invalid_sha256=receipt.reviewer_binding.{field}")
    elif kind == "controller_direct":
        if role != "controller":
            errors.append("invalid_direct_reviewer_role")
        if obj.get("identity_assurance") != "controller_asserted":
            errors.append("invalid_direct_reviewer_identity_assurance")
        for field in ("agent_id", "attempt", "dispatch_packet_sha256", "agent_run_sha256"):
            if obj.get(field) is not None:
                errors.append(f"direct_reviewer_field_must_be_null={field}")


def _validate_validation_receipt_references(value: object, digest: object, errors: list[str]) -> None:
    path = "receipt.review_binding.validation_receipts"
    if not isinstance(value, list) or not value:
        errors.append(f"invalid_array={path}")
        return
    ids: list[str] = []
    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        obj = _exact_object(item, VALIDATION_RECEIPT_REFERENCE_FIELDS, item_path, errors)
        if obj is None:
            continue
        for field in VALIDATION_RECEIPT_REFERENCE_FIELDS:
            if not _is_hash(obj.get(field)):
                errors.append(f"invalid_sha256={item_path}.{field}")
        if isinstance(obj.get("receipt_id"), str):
            ids.append(str(obj["receipt_id"]))
    if len(ids) != len(set(ids)):
        errors.append("duplicate_validation_receipt_id")
    if ids != sorted(ids):
        errors.append("unsorted_validation_receipt_ids")
    try:
        actual_digest = canonical_json_digest(value)
    except (TypeError, ValueError):
        actual_digest = None
    if not _is_hash(digest) or digest != actual_digest:
        errors.append("validation_receipt_set_digest_mismatch")


def _validate_review_binding(value: object, errors: list[str]) -> None:
    obj = _exact_object(value, REVIEW_BINDING_FIELDS, "receipt.review_binding", errors)
    if obj is None:
        return
    for field in ("task_review_sha256", "review_package_sha256", "code_snapshot_sha256"):
        if not _is_hash(obj.get(field)):
            errors.append(f"invalid_sha256=receipt.review_binding.{field}")
    if obj.get("verdict") not in REVIEW_VERDICTS:
        errors.append("invalid_review_verdict")
    _validate_validation_receipt_references(
        obj.get("validation_receipts"),
        obj.get("validation_receipt_set_sha256"),
        errors,
    )


def _optional_positive_int(value: object) -> bool:
    return value is None or _is_int(value, minimum=1)


def _validate_ordering(value: object, reviewer_kind: object, errors: list[str]) -> None:
    obj = _exact_object(value, ORDERING_FIELDS, "receipt.ordering", errors)
    if obj is None:
        return
    for field in ORDERING_FIELDS:
        if not _optional_positive_int(obj.get(field)):
            errors.append(f"invalid_integer=receipt.ordering.{field}")
    validation_seq = obj.get("validation_receipts_published_event_sequence")
    issued_seq = obj.get("receipt_issued_after_event_sequence")
    for field in (
        "validation_receipts_published_event_sequence",
        "receipt_issued_after_event_sequence",
    ):
        if not _is_int(obj.get(field), minimum=1):
            errors.append(f"required_integer=receipt.ordering.{field}")
    if reviewer_kind == "agent":
        ordered_fields = (
            "producer_completed_event_sequence",
            "validation_receipts_published_event_sequence",
            "reviewer_dispatch_event_sequence",
            "reviewer_spawned_event_sequence",
            "reviewer_completed_event_sequence",
        )
        if not all(_is_int(obj.get(field), minimum=1) for field in ordered_fields):
            errors.append("agent_review_ordering_requires_all_sequences")
        else:
            ordered = [int(obj[field]) for field in ordered_fields]
            if any(left >= right for left, right in zip(ordered, ordered[1:])):
                errors.append("invalid_agent_review_event_order")
        if _is_int(obj.get("reviewer_completed_event_sequence"), minimum=1) and _is_int(issued_seq, minimum=1):
            if int(obj["reviewer_completed_event_sequence"]) > int(issued_seq):
                errors.append("review_receipt_issued_before_reviewer_completion")
    elif reviewer_kind == "controller_direct":
        if obj.get("producer_completed_event_sequence") is not None:
            errors.append("direct_review_producer_sequence_must_be_null")
        for field in (
            "reviewer_dispatch_event_sequence",
            "reviewer_spawned_event_sequence",
            "reviewer_completed_event_sequence",
        ):
            if obj.get(field) is not None:
                errors.append(f"direct_review_sequence_must_be_null={field}")
        if (
            _is_int(validation_seq, minimum=1)
            and _is_int(issued_seq, minimum=1)
            and int(validation_seq) > int(issued_seq)
        ):
            errors.append("review_receipt_issued_before_validation_receipts")


def review_completion_receipt_errors(receipt: object, *, require_mac: bool = True) -> list[str]:
    errors: list[str] = []
    value = _validate_common(
        receipt,
        kind=REVIEW_COMPLETION_RECEIPT_KIND,
        version=REVIEW_COMPLETION_RECEIPT_VERSION,
        observation_scope=REVIEW_COMPLETION_OBSERVATION_SCOPE,
        domain_fields=frozenset({"reviewer_binding", "review_binding", "ordering"}),
        require_mac=require_mac,
        errors=errors,
    )
    if value is None:
        return errors
    _validate_reviewer_binding(value.get("reviewer_binding"), errors)
    _validate_review_binding(value.get("review_binding"), errors)
    reviewer = value.get("reviewer_binding") if isinstance(value.get("reviewer_binding"), dict) else {}
    _validate_ordering(value.get("ordering"), reviewer.get("reviewer_kind"), errors)
    issued = _timestamp(value.get("issued_at"))
    completed = _timestamp(reviewer.get("completed_at"))
    if issued is not None and completed is not None and issued < completed:
        errors.append("review_receipt_issued_before_completed_at")
    return errors


def _sign(
    payload: object,
    master_key: bytes,
    *,
    validator,
    key_domain: bytes,
    mac_domain: bytes,
) -> dict[str, object]:
    _require_master_key(master_key)
    try:
        errors = validator(payload, require_mac=False)
    except (TypeError, ValueError) as exc:
        raise ReceiptValidationError(f"receipt_shape_validation_failed={exc}") from exc
    if errors:
        raise ReceiptValidationError(";".join(errors))
    if not isinstance(payload, dict):
        raise ReceiptValidationError("receipt_must_be_object")
    if payload.get("trust_key_id") != trust_key_id(master_key):
        raise ReceiptValidationError("receipt_trust_key_id_mismatch")
    unsigned = json.loads(canonical_json_bytes(payload).decode("utf-8"))
    derived_key = _derive_key(master_key, key_domain)
    mac = hmac.new(derived_key, mac_domain + canonical_json_bytes(unsigned), hashlib.sha256).hexdigest()
    return {**unsigned, RECEIPT_MAC_FIELD: mac}


def sign_validation_receipt(payload: object, master_key: bytes) -> dict[str, object]:
    return _sign(
        payload,
        master_key,
        validator=validation_receipt_errors,
        key_domain=VALIDATION_KEY_DOMAIN,
        mac_domain=VALIDATION_MAC_DOMAIN,
    )


def sign_review_completion_receipt(payload: object, master_key: bytes) -> dict[str, object]:
    return _sign(
        payload,
        master_key,
        validator=review_completion_receipt_errors,
        key_domain=REVIEW_KEY_DOMAIN,
        mac_domain=REVIEW_MAC_DOMAIN,
    )


def _verify(
    receipt: object,
    master_key: bytes,
    *,
    validator,
    key_domain: bytes,
    mac_domain: bytes,
) -> bool:
    try:
        _require_master_key(master_key)
    except (TypeError, ValueError):
        return False
    try:
        errors = validator(receipt, require_mac=True)
    except (TypeError, ValueError):
        return False
    if errors or not isinstance(receipt, dict):
        return False
    if receipt.get("trust_key_id") != trust_key_id(master_key):
        return False
    claimed = receipt.get(RECEIPT_MAC_FIELD)
    if not isinstance(claimed, str):
        return False
    unsigned = {key: value for key, value in receipt.items() if key != RECEIPT_MAC_FIELD}
    try:
        derived_key = _derive_key(master_key, key_domain)
        expected = hmac.new(
            derived_key,
            mac_domain + canonical_json_bytes(unsigned),
            hashlib.sha256,
        ).hexdigest()
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(claimed, expected)


def verify_validation_receipt(receipt: object, master_key: bytes) -> bool:
    return _verify(
        receipt,
        master_key,
        validator=validation_receipt_errors,
        key_domain=VALIDATION_KEY_DOMAIN,
        mac_domain=VALIDATION_MAC_DOMAIN,
    )


def verify_review_completion_receipt(receipt: object, master_key: bytes) -> bool:
    return _verify(
        receipt,
        master_key,
        validator=review_completion_receipt_errors,
        key_domain=REVIEW_KEY_DOMAIN,
        mac_domain=REVIEW_MAC_DOMAIN,
    )


__all__ = [
    "CONTROLLER_OBSERVER",
    "MASTER_KEY_BYTES",
    "NOT_OBSERVED",
    "RECEIPT_MAC_FIELD",
    "REVIEW_COMPLETION_OBSERVATION_SCOPE",
    "REVIEW_COMPLETION_RECEIPT_KIND",
    "REVIEW_COMPLETION_RECEIPT_VERSION",
    "ReceiptValidationError",
    "VALIDATION_OBSERVATION_SCOPE",
    "VALIDATION_RECEIPT_KIND",
    "VALIDATION_RECEIPT_VERSION",
    "canonical_json_bytes",
    "canonical_json_digest",
    "derive_review_completion_receipt_key",
    "derive_validation_receipt_key",
    "is_safe_artifact_path",
    "review_completion_receipt_errors",
    "sign_review_completion_receipt",
    "sign_validation_receipt",
    "trust_key_id",
    "validation_receipt_errors",
    "verify_review_completion_receipt",
    "verify_validation_receipt",
]
