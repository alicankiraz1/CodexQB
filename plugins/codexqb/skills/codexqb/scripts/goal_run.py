#!/usr/bin/env python3
"""Compile deterministic CodexQB Goal run previews.

This script is intentionally non-executing: it reads source contracts, hashes
source snapshots, validates a Goal-Run schema, and renders Goal prompts inside
the target repo.
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

if __name__ == "__main__" and not _launcher_admission_is_valid("goal_run.py"):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\n"
    )
    raise SystemExit(2)


import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fnmatch
import hashlib
import json
import re
from pathlib import Path
from collections.abc import Iterator

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from safety_contracts import (  # noqa: E402
    assert_safe_persistent_text,
    budget_limit,
    canonical_json_digest,
    default_budget_contract,
    glob_patterns_overlap,
    has_secret_like,
    implementation_contract_binding_from_bytes,
    implementation_contract_validation_command_ids,
    is_safe_repo_path,
    parse_safe_persistent_json,
    path_is_inside,
    redact_secret_like,
    safe_log_text,
    serialize_safe_persistent_json,
    token_usage_not_observed,
    validate_budget_contract,
    validate_token_usage,
)
from controller_store import (  # noqa: E402
    ControllerRunArtifacts,
    GOAL_RUN_COMPONENTS,
    canonical_repository_root as canonical_controller_repository_root,
    controller_lexical_absolute,
    controller_process_id,
    goal_runs_root,
    legacy_goal_runs_root,
    open_goal_run_artifacts,
)
from execution_controller import (  # noqa: E402
    read_goal_held_bytes,
    run_goal_planner_validator,
)
from repository_io import (  # noqa: E402
    RepositoryIO,
    _controller_canonical_root as canonical_repository_root,
    _controller_evidence_digest as controller_evidence_digest,
    _controller_inventory as controller_inventory,
    _controller_path_kind as controller_path_kind,
    _controller_read_bytes as controller_read_bytes,
    _controller_regular_paths as controller_regular_paths,
    _controller_workspace_proof as controller_workspace_proof,
    open_repository_io,
)


ARTIFACT_SCHEMA_VERSION = 3
HANDOFF_CONTRACT_VERSION = 2
GOAL_RUN_SCHEMA_VERSION = 1
PLUGIN_VERSION = "0.3.0"
GOAL_COMPILER_VERSION = 2
GOAL_RUNS_RELATIVE_DIR = Path("Planner-docs") / "Goal-Runs"
GOAL_RUN_DIRECTORY_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,159}")

STAGE_REFERENCES = {
    "step15": ["references/Autopsy-Planner.md", "references/goal-specs/step15.md"],
    "step2": ["references/handoffs/run-step2.md", "references/Second-Planner.md", "references/goal-specs/step2.md"],
    "step3": ["references/handoffs/run-step3.md", "references/Third-Planner.md", "references/goal-specs/step3.md"],
    "step4": ["references/handoffs/run-step4.md", "references/Fourth-Planner.md", "references/goal-specs/step4.md"],
}

STAGE_MODES = {
    "step15": {"wave", "autopsy", "refresh"},
    "step2": {"wave", "full", "refresh", "repair"},
    "step3": {"wave", "audit", "repair"},
    "step4": {"direct", "subagent_serial", "external_superpowers", "no_action"},
}

PLANNER_DOC_SOURCES = [
    "Planner-docs/Main-Planing.md",
    "Planner-docs/Autopsy.md",
    "Planner-docs/Project-Ontology.md",
    "Planner-docs/Project-Comprehension.md",
    "Planner-docs/Sub-Planing-Index.md",
    "Planner-docs/Sub-Planing-Audit.md",
    "Planner-docs/Planing-Ledger.md",
]
IMMUTABLE_PLANNER_DOCS_BY_STAGE = {
    "step15": [
        "Planner-docs/Main-Planing.md",
    ],
    "step2": [
        "Planner-docs/Main-Planing.md",
        "Planner-docs/Autopsy.md",
        "Planner-docs/Project-Ontology.md",
        "Planner-docs/Project-Comprehension.md",
    ],
    "step3": [
        "Planner-docs/Main-Planing.md",
        "Planner-docs/Autopsy.md",
        "Planner-docs/Project-Ontology.md",
        "Planner-docs/Project-Comprehension.md",
        "Planner-docs/Sub-Planing-Index.md",
        "Planner-docs/Planing-Ledger.md",
    ],
    "step4": [
        "Planner-docs/Main-Planing.md",
        "Planner-docs/Autopsy.md",
        "Planner-docs/Project-Ontology.md",
        "Planner-docs/Project-Comprehension.md",
        "Planner-docs/Sub-Planing-Index.md",
        "Planner-docs/Sub-Planing-Audit.md",
    ],
}
STEP2_MUTABLE_SUBPLAN_PATTERN = "Planner-docs/Faz-*-Plans/*.md"
MUTABLE_OUTPUTS_BY_STAGE = {
    "step15": [
        "Planner-docs/Autopsy.md",
        "Planner-docs/Project-Ontology.md",
        "Planner-docs/Project-Comprehension.md",
        "Planner-docs/Planing-Ledger.md",
    ],
    "step2": [
        "Planner-docs/Sub-Planing-Index.md",
        "Planner-docs/Planing-Ledger.md",
        STEP2_MUTABLE_SUBPLAN_PATTERN,
    ],
    "step3": [
        "Planner-docs/Sub-Planing-Audit.md",
    ],
    "step4": [
        "Planner-docs/Planing-Ledger.md",
        ".codexqb/apply-runs/**",
    ],
}
WORKSPACE_BASELINE_EXCLUDED_PREFIXES = (
    ".git/",
    ".codexqb/",
    "Planner-docs/Goal-Runs/",
    "__pycache__/",
    ".pytest_cache/",
    ".mypy_cache/",
    ".ruff_cache/",
)
WORKSPACE_BASELINE_EXCLUDED_NAMES = {"CodexQB-sanitized.zip"}
WORKSPACE_BASELINE_PRUNED_DIRS = {
    ".cache",
    ".venv",
    "artifacts",
    "build",
    "dist",
    "logs",
    "model-cache",
    "node_modules",
    "vendor",
}
GOAL_FORBIDDEN_WRITES = ["~/.codex/**", ".git/**", ".env", "**/*.key", "**/*.pem"]
GOAL_STOP_GATES = [
    "snapshot mismatch",
    "P0/P1 blocker",
    "unsafe path",
    "required user confirmation missing",
    "dirty unrelated worktree",
]
GOAL_FINAL_REPORT_CONTRACT = ["files changed", "validations", "blockers", "next action"]
GOAL_SAFETY = {
    "executes_commands": False,
    "allows_global_config_edits": False,
    "allows_commit_push_pr_deploy": False,
    "output_dir_must_be_inside_repo": False,
    "controller_state_owner_only": True,
    "legacy_repository_goal_runs_archive_only": True,
}
GOAL_AGENT_PROFILES = {
    "explorer": {"agent_type": "explorer", "model_profile": "fast", "sandbox": "read-only"},
    "implementer": {"agent_type": "worker", "model_profile": "balanced", "sandbox": "workspace-write"},
    "task_reviewer": {"agent_type": "default", "model_profile": "strong", "sandbox": "read-only"},
    "security_reviewer": {"agent_type": "default", "model_profile": "security_strong", "sandbox": "read-only"},
    "fixer": {"agent_type": "worker", "model_profile": "balanced", "sandbox": "workspace-write"},
    "final_reviewer": {"agent_type": "default", "model_profile": "strong", "sandbox": "read-only"},
}

def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def read_skill_bytes(relative_path: str) -> bytes:
    """Read one immutable resource only from launcher-held descriptor bytes."""

    return read_goal_held_bytes(relative_path)


def read_skill_text(relative_path: str) -> str:
    try:
        return read_skill_bytes(relative_path).decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("non_utf8_trusted_skill_resource") from None


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
    return dict(controller_workspace_proof(repository).evidence)


def _repository_path_kind(root: Path, relative_path: str) -> str:
    with open_repository_io(root) as repository:
        return controller_path_kind(repository, relative_path)


def repository_contract_binding(
    root: Path,
    source_subplan_path: str,
    *,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return repository_contract_binding(
                root,
                source_subplan_path,
                repository=opened,
            )
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


def is_inside(parent: Path, child: Path) -> bool:
    return path_is_inside(parent, child)


def lexical_absolute(path: Path) -> Path:
    return controller_lexical_absolute(path)


def resolve_managed_goal_run_dir(
    root: Path,
    requested: Path | None,
    default_name: str | None = None,
    *,
    lexical_root: Path | None = None,
) -> Path:
    canonical_root = canonical_controller_repository_root(root)
    lexical_root = lexical_absolute(lexical_root or canonical_root)
    managed_root = goal_runs_root(canonical_root)
    legacy_root = legacy_goal_runs_root(canonical_root)
    if requested is None:
        candidate = managed_root / str(default_name or "")
    else:
        if ".." in requested.parts:
            raise ValueError("invalid_goal_output_dir=path_traversal_rejected")
        if requested.is_absolute():
            lexical_requested = lexical_absolute(requested)
            candidate = lexical_requested
        else:
            if len(requested.parts) == 1:
                candidate = managed_root / requested.name
            elif requested.parts[:2] == GOAL_RUNS_RELATIVE_DIR.parts:
                raise ValueError("legacy_goal_run_archive_only")
            else:
                raise ValueError("invalid_goal_output_dir=managed_run_required")
    lexical_candidate = lexical_absolute(candidate)
    try:
        lexical_candidate.relative_to(legacy_root)
    except ValueError:
        pass
    else:
        raise ValueError("legacy_goal_run_archive_only")
    if lexical_candidate.parent != managed_root:
        raise ValueError("invalid_goal_output_dir=must_be_direct_child_of_controller_goal_runs")
    if GOAL_RUN_DIRECTORY_RE.fullmatch(lexical_candidate.name) is None:
        raise ValueError("invalid_goal_output_dir=invalid_run_directory_name")
    if has_secret_like(lexical_candidate.name):
        raise ValueError("invalid_goal_output_dir=secret_like_run_directory_name")
    return lexical_candidate


@contextmanager
def open_managed_goal_run_directory(
    root: Path,
    run_dir: Path,
    *,
    create: bool,
    allow_existing: bool,
) -> Iterator[ControllerRunArtifacts]:
    root = canonical_controller_repository_root(root)
    run_dir = resolve_managed_goal_run_dir(root, run_dir)
    try:
        with open_goal_run_artifacts(
            root,
            run_dir,
            create=create,
            allow_existing=allow_existing,
            name_pattern=GOAL_RUN_DIRECTORY_RE.pattern,
        ) as artifacts:
            yield artifacts
    except FileExistsError:
        raise ValueError(f"goal_run_already_exists={run_dir.name}") from None
    except FileNotFoundError:
        raise ValueError(f"goal_run_missing={run_dir.name}") from None


def safe_rel_path(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def selected_step4_subplan_paths(active_scope: dict[str, object] | None) -> set[str]:
    if not isinstance(active_scope, dict):
        return set()
    selected: set[str] = set()
    queue = active_scope.get("ready_queue")
    if not isinstance(queue, list):
        return selected
    for item in queue:
        if not isinstance(item, dict):
            continue
        path = item.get("source_subplan_path") or item.get("subplan_path")
        if isinstance(path, str) and path:
            selected.add(path)
    return selected


def step4_unselected_subplan_paths(
    root: Path,
    active_scope: dict[str, object] | None,
    repository: RepositoryIO | None = None,
) -> set[str]:
    selected = selected_step4_subplan_paths(active_scope)
    if not selected:
        return set()
    if repository is None:
        with open_repository_io(root) as opened:
            return step4_unselected_subplan_paths(root, active_scope, opened)
    all_subplans = {
        path
        for path in controller_regular_paths(repository, "step3")
        if re.fullmatch(r"Planner-docs/Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md", path)
    }
    return all_subplans - selected


def collect_sources(
    root: Path,
    stage: str,
    active_scope: dict[str, object] | None = None,
    git_evidence: dict[str, object] | None = None,
    repository: RepositoryIO | None = None,
) -> list[dict[str, str]]:
    if repository is None:
        with open_repository_io(root) as opened:
            return collect_sources(root, stage, active_scope, git_evidence, opened)
    sources: list[dict[str, str]] = []
    for rel in STAGE_REFERENCES[stage]:
        data = read_skill_bytes(rel)
        sources.append({"scope": "skill", "path": rel, "sha256": sha256_bytes(data)})

    for rel in IMMUTABLE_PLANNER_DOCS_BY_STAGE[stage]:
        evidence = controller_read_bytes(repository, rel, required=False)
        if evidence.exists:
            sources.append({"scope": "repo", "path": rel, "sha256": str(evidence.receipt.sha256)})

    if stage in {"step3", "step4"}:
        selected_step4_paths = selected_step4_subplan_paths(active_scope) if stage == "step4" else set()
        for rel_path in controller_regular_paths(repository, "step3"):
            if re.fullmatch(r"Planner-docs/Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md", rel_path) is None:
                continue
            if stage == "step4" and selected_step4_paths and rel_path not in selected_step4_paths:
                continue
            evidence = controller_read_bytes(repository, rel_path, required=True)
            sources.append({"scope": "repo", "path": rel_path, "sha256": str(evidence.receipt.sha256)})

    evidence = git_evidence or repository_workspace_evidence(root, repository)
    branch = str(evidence.get("branch") or "unknown")
    commit = str(evidence.get("head") or "unknown")
    sources.append({"scope": "git", "path": "branch", "sha256": sha256_bytes(branch.encode("utf-8")), "value": branch})
    sources.append({"scope": "git", "path": "commit", "sha256": sha256_bytes(commit.encode("utf-8")), "value": commit})
    return sources


def goal_mutable_output_patterns(stage: str, active_scope: dict[str, object] | None = None) -> list[str]:
    patterns = list(MUTABLE_OUTPUTS_BY_STAGE[stage])
    if stage == "step4" and isinstance(active_scope, dict):
        for item in active_scope.get("ready_queue", []):
            if not isinstance(item, dict):
                continue
            contract = item.get("implementation_contract")
            if not isinstance(contract, dict):
                continue
            paths = contract.get("implementation_paths")
            if not isinstance(paths, list):
                continue
            for entry in paths:
                if not isinstance(entry, dict):
                    continue
                path = entry.get("path")
                if isinstance(path, str) and is_safe_repo_path(path) and path not in patterns:
                    patterns.append(path)
    return patterns


def mutable_output_matches(rel_path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel_path, pattern) for pattern in patterns)


def mutable_output_baseline(
    root: Path,
    patterns: list[str],
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return mutable_output_baseline(root, patterns, opened)
    seen: set[str] = set()
    duplicates: list[str] = []
    for pattern in patterns:
        if pattern in seen:
            duplicates.append(pattern)
        seen.add(pattern)
    files: list[dict[str, object]] = []
    intake_paths = controller_regular_paths(repository, "intake")
    for pattern in patterns:
        if any(char in pattern for char in "*?[]"):
            matches = [path for path in intake_paths if fnmatch.fnmatch(path, pattern)]
        else:
            matches = [pattern]
        for path in matches:
            evidence = controller_read_bytes(repository, path, required=False)
            if evidence.exists:
                files.append(
                    {
                        "path": path,
                        "exists": True,
                        "sha256": evidence.receipt.sha256,
                    }
                )
            elif not any(char in pattern for char in "*?[]"):
                files.append({"path": pattern, "exists": False, "sha256": None})
    return {"declared": patterns, "duplicates": duplicates, "files": files}


def workspace_path_excluded(rel_path: str, mutable_patterns: list[str], excluded_paths: set[str] | None = None) -> bool:
    if excluded_paths and rel_path in excluded_paths:
        return True
    if rel_path in WORKSPACE_BASELINE_EXCLUDED_NAMES:
        return True
    if any(part in WORKSPACE_BASELINE_PRUNED_DIRS for part in Path(rel_path).parts):
        return True
    if any(rel_path == prefix.rstrip("/") or rel_path.startswith(prefix) for prefix in WORKSPACE_BASELINE_EXCLUDED_PREFIXES):
        return True
    if any(part == "__pycache__" for part in Path(rel_path).parts):
        return True
    return mutable_output_matches(rel_path, mutable_patterns)


def workspace_inventory(root: Path, mutable_patterns: list[str]) -> list[str]:
    return workspace_inventory_with_exclusions(root, mutable_patterns, set())


def workspace_inventory_with_exclusions(
    root: Path,
    mutable_patterns: list[str],
    excluded_paths: set[str],
    git_evidence: dict[str, object] | None = None,
    repository: RepositoryIO | None = None,
) -> list[str]:
    entries: list[str] = []
    evidence = git_evidence or repository_workspace_evidence(root, repository)
    if evidence.get("is_git") is True:
        raw_worktree = evidence.get("worktree_entries")
        raw_untracked = evidence.get("untracked_entries")
        if not isinstance(raw_worktree, list) or not isinstance(raw_untracked, list):
            raise ValueError("git_evidence_workspace_entries_missing")
        workspace_entries = [
            item
            for item in [*raw_worktree, *raw_untracked]
            if isinstance(item, dict) and isinstance(item.get("path"), str)
        ]
        if len(workspace_entries) != len(raw_worktree) + len(raw_untracked):
            raise ValueError("git_evidence_workspace_entries_invalid")
        for item in sorted(workspace_entries, key=lambda current: str(current["path"])):
            rel = str(item["path"])
            if workspace_path_excluded(rel, mutable_patterns, excluded_paths):
                continue
            if item.get("state") == "present":
                entries.append(f"{rel}\0{canonical_json_digest(item)}")
        return entries

    def excluded_from_inventory(rel_path: str) -> bool:
        return (
            any(part in WORKSPACE_BASELINE_PRUNED_DIRS for part in Path(rel_path).parts)
            or workspace_path_excluded(rel_path, mutable_patterns, excluded_paths)
        )

    if repository is None:
        with open_repository_io(root) as opened:
            return workspace_inventory_with_exclusions(
                root,
                mutable_patterns,
                excluded_paths,
                git_evidence,
                opened,
            )
    inventory = [
        item
        for item in controller_inventory(repository, "intake")
        if not excluded_from_inventory(str(item.get("path", "")))
    ]
    return [
        f"{item['path']}\0{item['fingerprint_sha256']}"
        for item in inventory
        if item.get("kind") != "directory"
    ]


def workspace_baseline(
    root: Path,
    mutable_patterns: list[str],
    excluded_paths: set[str] | None = None,
    git_evidence: dict[str, object] | None = None,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    excluded = excluded_paths or set()
    evidence = git_evidence or repository_workspace_evidence(root, repository)
    branch = str(evidence.get("branch") or "unknown")
    commit = str(evidence.get("head") or "unknown")
    inventory = workspace_inventory_with_exclusions(
        root,
        mutable_patterns,
        excluded,
        evidence,
        repository,
    )
    staged_changes = [
        item
        for item in evidence.get("staged_changes", [])
        if isinstance(item, dict)
        and not workspace_path_excluded(str(item.get("path", "")), mutable_patterns, excluded)
    ]
    unstaged_changes = [
        item
        for item in evidence.get("unstaged_changes", [])
        if isinstance(item, dict)
        and not workspace_path_excluded(str(item.get("path", "")), mutable_patterns, excluded)
    ]
    raw_untracked_entries = evidence.get("untracked_entries")
    if not isinstance(raw_untracked_entries, list):
        raise ValueError("git_evidence_untracked_entries_missing")
    if any(
        not isinstance(item, dict) or not isinstance(item.get("path"), str)
        for item in raw_untracked_entries
    ):
        raise ValueError("git_evidence_untracked_entries_invalid")
    untracked_entries = [
        item
        for item in raw_untracked_entries
        if not workspace_path_excluded(str(item["path"]), mutable_patterns, excluded)
    ]
    return {
        "branch": branch,
        "base_commit": commit,
        "staged_diff_hash": controller_evidence_digest(staged_changes),
        "unstaged_diff_hash": controller_evidence_digest(unstaged_changes),
        "untracked_inventory_hash": controller_evidence_digest(untracked_entries),
        "workspace_inventory_sha256": sha256_bytes("\n".join(inventory).encode("utf-8")),
        "workspace_inventory_count": len(inventory),
        "excluded_paths": sorted(excluded),
    }


def stage_snapshot(
    root: Path,
    stage: str,
    sources: list[dict[str, str]],
    mutable_patterns: list[str],
    *,
    template_bundle_digest: str,
    goal_spec_digest_value: str,
    baseline_excluded_paths: set[str] | None = None,
    git_evidence: dict[str, object] | None = None,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    evidence = git_evidence or repository_workspace_evidence(root, repository)
    return {
        "stage": stage,
        "branch": str(evidence.get("branch") or "unknown"),
        "base_commit": str(evidence.get("head") or "unknown"),
        "immutable_inputs": sources,
        "immutable_input_digest": snapshot_digest(stage, sources),
        "mutable_outputs": mutable_output_baseline(root, mutable_patterns, repository),
        "workspace_baseline": workspace_baseline(
            root,
            mutable_patterns,
            baseline_excluded_paths,
            evidence,
            repository,
        ),
        "template_bundle_digest": template_bundle_digest,
        "compiler_version": GOAL_COMPILER_VERSION,
        "goal_spec_digest": goal_spec_digest_value,
    }


def snapshot_digest(stage: str, sources: list[dict[str, str]]) -> str:
    payload = json.dumps({"stage": stage, "sources": sources}, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def run_id_for(stage: str, sources: list[dict[str, str]]) -> str:
    return f"goal-{stage}-{snapshot_digest(stage, sources)[:12]}"


def template_bundle(stage: str) -> dict[str, object]:
    templates = []
    for rel in STAGE_REFERENCES[stage]:
        templates.append({"path": rel, "sha256": sha256_bytes(read_skill_bytes(rel))})
    compiler = {
        "path": "scripts/goal_run.py",
        "version": GOAL_COMPILER_VERSION,
        "sha256": sha256_bytes(read_skill_bytes("scripts/goal_run.py")),
    }
    payload = {"templates": templates, "compiler": compiler}
    digest = sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return {"digest": digest, **payload}


def goal_spec_digest(stage: str, sources: list[dict[str, str]], mode: str, objective: str, active_scope: dict[str, object]) -> str:
    payload = {
        "stage": stage,
        "sources": sources,
        "mode": mode,
        "objective": objective,
        "active_scope": active_scope,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "handoff_contract_version": HANDOFF_CONTRACT_VERSION,
        "goal_run_schema_version": GOAL_RUN_SCHEMA_VERSION,
    }
    return sha256_bytes(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def context_token_budget_for(stage: str) -> dict[str, object]:
    return {"risk": "medium", "confirmation_required": stage in {"step2", "step4"}}


def goal_policy_envelope(
    stage: str,
    sources: list[dict[str, str]],
    mode: str,
    active_scope: dict[str, object],
) -> dict[str, object]:
    return {
        "required_inputs": [item["path"] for item in sources if item.get("scope") in {"repo", "skill"}],
        "allowed_writes": goal_mutable_output_patterns(stage, active_scope),
        "forbidden_writes": list(GOAL_FORBIDDEN_WRITES),
        "validation_checkpoints": validation_checkpoints_for(stage),
        "stop_gates": list(GOAL_STOP_GATES),
        "subagent_plan": build_subagent_plan(stage, mode, active_scope),
        "context_token_budget": context_token_budget_for(stage),
        "budget_contract": default_budget_contract(),
        "final_report_contract": list(GOAL_FINAL_REPORT_CONTRACT),
        "user_confirmation_required": stage in {"step2", "step4"},
        "safety": dict(GOAL_SAFETY),
    }


def goal_policy_digest(stage: str, sources: list[dict[str, str]], mode: str, active_scope: dict[str, object]) -> str:
    return canonical_json_digest(goal_policy_envelope(stage, sources, mode, active_scope))


def invocation_suffix(value: str | None = None) -> str:
    raw = value or f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')}-{controller_process_id()}"
    if has_secret_like(raw):
        raise ValueError("secret_like_run_id_suffix")
    suffix = re.sub(r"[^A-Za-z0-9_.-]+", "-", raw).strip("-._")
    if not suffix or has_secret_like(suffix):
        raise ValueError("invalid_run_id_suffix")
    return suffix[:64]


def goal_run_id_for(stage: str, spec_digest: str, run_id_suffix: str | None = None) -> str:
    return f"goal-{stage}-{spec_digest[:12]}-{invocation_suffix(run_id_suffix)}"


def run_bundled_validator(root: Path, mode: str, *, strict: bool = True) -> tuple[int, str]:
    return run_goal_planner_validator(
        root=root,
        mode=mode,
        strict=strict,
    )


def stage_validator_mode(stage: str) -> str:
    return {
        "step15": "step1",
        "step2": "step1",
        "step3": "step3-preflight",
        "step4": "step4",
    }[stage]


def stage_prerequisite_blockers(
    root: Path,
    stage: str,
    repository: RepositoryIO | None = None,
) -> list[str]:
    if repository is None:
        with open_repository_io(root) as opened:
            return stage_prerequisite_blockers(root, stage, opened)
    blockers: list[str] = []
    if stage in {"step15", "step2"} and controller_path_kind(repository, "Planner-docs/Main-Planing.md") != "regular":
        blockers.append("missing_prerequisite=Planner-docs/Main-Planing.md")
    if stage == "step3":
        if controller_path_kind(repository, "Planner-docs/Sub-Planing-Index.md") != "regular":
            blockers.append("missing_prerequisite=Planner-docs/Sub-Planing-Index.md")
        if not any(
            re.fullmatch(r"Planner-docs/Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md", path)
            for path in controller_regular_paths(repository, "step3")
        ):
            blockers.append("missing_prerequisite=active_subplans")
    if stage == "step4":
        audit_path = "Planner-docs/Sub-Planing-Audit.md"
        audit = repository.read_text(audit_path, required=False, audience="internal")
        if not audit.exists:
            blockers.append("missing_prerequisite=Planner-docs/Sub-Planing-Audit.md")
        else:
            text = audit.text or ""
            if "READY" not in text and "NO_ACTION_REQUIRED" not in text:
                blockers.append("missing_prerequisite=step4_ready_queue_or_no_action")
    if blockers:
        return blockers
    validator_mode = stage_validator_mode(stage)
    code, output = run_bundled_validator(root, validator_mode, strict=True)
    if code != 0:
        blockers.append(f"validator_failed={validator_mode}")
        blockers.append(f"validator_output_sha256={sha256_bytes(output.encode('utf-8'))}")
    return blockers


def project_name(root: Path, repository: RepositoryIO | None = None) -> str:
    text = repository_model_text(
        root,
        "Planner-docs/Main-Planing.md",
        repository=repository,
    )
    if text is not None:
        match = re.search(r"Project\s+Name\s*[:|-]\s*(.+)", text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()[:120]
    fallback = root.name[:120]
    try:
        assert_safe_persistent_text(fallback)
    except ValueError:
        return "Unnamed Project"
    return fallback if fallback and not has_secret_like(fallback) else "Unnamed Project"


def _parse_ready_queue(text: str) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
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
            items.append({"readiness_status": key[0], "subplan_path": path})
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
            items.append({"readiness_status": status, "subplan_path": path})
    return items


def extract_ready_queue(
    root: Path,
    repository: RepositoryIO | None = None,
) -> list[dict[str, str]]:
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


def extract_implementation_contract(
    root: Path,
    subplan_path: str,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    binding = repository_contract_binding(root, subplan_path, repository=repository)
    contract = binding.get("implementation_contract")
    return contract if isinstance(contract, dict) else {}


def validation_command_ids(implementation_contract: dict[str, object]) -> list[str]:
    return implementation_contract_validation_command_ids(implementation_contract)


def implementation_contract_digest(implementation_contract: dict[str, object]) -> str | None:
    if not implementation_contract:
        return None
    return canonical_json_digest(implementation_contract)


def subplan_scope_item(
    root: Path,
    subplan_path: str,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    text_value = repository_model_text(root, subplan_path, repository=repository)
    text = text_value or ""
    contract = extract_contract_signals(text)
    binding = repository_contract_binding(root, subplan_path, repository=repository)
    implementation_contract = binding.get("implementation_contract")
    implementation_contract = implementation_contract if isinstance(implementation_contract, dict) else {}
    item: dict[str, object] = {
        "subplan_path": subplan_path,
        "source_subplan_path": subplan_path,
        "subplan_sha256": binding.get("source_subplan_sha256") if text_value is not None else None,
        "source_subplan_sha256": binding.get("source_subplan_sha256") if text_value is not None else None,
        "contract_signals": contract,
        "implementation_contract": implementation_contract,
        "implementation_contract_digest": binding.get("implementation_contract_digest"),
    }
    structured_security = implementation_contract.get("security_review_required")
    item["security_review_required"] = (
        structured_security
        if isinstance(structured_security, bool)
        else any("required" in signal.lower() or "risk" in signal.lower() for signal in contract["security_requirements"])
    )
    item["validation_command_count"] = len(contract["structured_validation_commands"])
    structured_commands = implementation_contract.get("validation_commands")
    if isinstance(structured_commands, list):
        item["structured_validation_command_count"] = len([command for command in structured_commands if isinstance(command, dict)])
    else:
        item["structured_validation_command_count"] = 0
    item["validation_command_ids"] = binding.get("validation_command_ids", [])
    item["parent_acceptance_signal_ids"] = binding.get("parent_acceptance_signal_ids", [])
    item["risk_class"] = binding.get("risk_class", "")
    item["risk_domains"] = binding.get("risk_domains", [])
    return item


def collect_subplan_scope(
    root: Path,
    subplans: list[str],
    repository: RepositoryIO | None = None,
) -> list[dict[str, object]]:
    return [subplan_scope_item(root, path, repository) for path in subplans]


def markdown_section(text: str, section_number: int, title: str) -> str:
    pattern = re.compile(
        rf"^##\s*{section_number}\.?\s+{re.escape(title)}\s*$",
        flags=re.IGNORECASE | re.MULTILINE,
    )
    match = pattern.search(text)
    if not match:
        return ""
    next_heading = re.search(r"^##\s+", text[match.end() :], flags=re.MULTILINE)
    end = match.end() + next_heading.start() if next_heading else len(text)
    return text[match.end() : end].strip()


def parse_int_list(value: str) -> list[int]:
    return [int(item) for item in re.findall(r"\d+", value)]


def active_phases_from_notes(notes: str, detected_phases: list[int]) -> list[int]:
    detected = set(detected_phases)
    lowered = notes.lower()
    range_match = re.search(r"phases?\s+(\d+)\s*(?:-|–|—|to)\s*(\d+)", lowered)
    if range_match:
        start, end = int(range_match.group(1)), int(range_match.group(2))
        low, high = sorted((start, end))
        return [phase for phase in detected_phases if low <= phase <= high]
    list_match = re.search(r"phases?\s+([0-9,\s]+)\s+(?:first|active|initial|wave)", lowered)
    if list_match:
        listed = parse_int_list(list_match.group(1))
        return [phase for phase in detected_phases if phase in set(listed)]
    if len(detected_phases) <= 3:
        return detected_phases
    return [phase for phase in detected_phases if phase in set(detected_phases[:3]) and phase in detected]


def collect_step2_planning_horizon(
    root: Path,
    mode: str,
    existing_subplan_count: int,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    text = repository_model_text(
        root,
        "Planner-docs/Main-Planing.md",
        repository=repository,
    )
    if text is None:
        return {
            "planning_mode": mode,
            "detected_phases": [],
            "active_phases": [],
            "deferred_phases": [],
            "parent_acceptance_signals": [],
            "max_detailed_subplans": 10,
            "max_output_words": 12000,
            "goal_token_risk": "medium",
            "review_checkpoint": "after_active_wave",
            "confirmation_threshold": ">15_files_or_very_high_token_risk",
            "user_confirmation_required": False,
            "framework_ownership_required": False,
            "algorithmic_invariants_required": False,
        }
    roadmap = markdown_section(text, 6, "Phase-Based Master Roadmap")
    next_steps = markdown_section(text, 8, "Prioritized Next Steps")
    prep_notes = markdown_section(text, 9, "Step 2 Preparation Notes")
    detected_phases: list[int] = []
    parent_signals: list[str] = []
    for line in roadmap.splitlines():
        if "|" not in line or "---" in line.lower() or "phase" in line.lower() and "acceptance" in line.lower():
            continue
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not cells:
            continue
        phase_match = re.search(r"\d+", cells[0])
        if not phase_match:
            continue
        phase = int(phase_match.group(0))
        if phase not in detected_phases:
            detected_phases.append(phase)
        for signal in re.findall(r"\bMP-PH\d+-AS-\d+\b", line, flags=re.IGNORECASE):
            normalized = signal.upper()
            if normalized not in parent_signals:
                parent_signals.append(normalized)
    detected_phases.sort()

    if mode == "full":
        active_phases = detected_phases
    else:
        active_phases = active_phases_from_notes("\n".join([prep_notes, next_steps]), detected_phases)
    active_set = set(active_phases)
    deferred_phases = [phase for phase in detected_phases if phase not in active_set]
    max_detailed_subplans = 10
    estimated_subplans = existing_subplan_count if existing_subplan_count else min(max_detailed_subplans, max(1, len(active_phases) * 2))
    estimated_words = max(estimated_subplans * 1200, 1200 if active_phases else 0)
    if len(detected_phases) > 10 or estimated_subplans > 15 or estimated_words > 18000:
        risk = "very_high"
    elif len(detected_phases) > 6 or estimated_words > 10000:
        risk = "high"
    else:
        risk = "medium"
    combined = "\n".join([roadmap, next_steps, prep_notes]).lower()
    framework_required = any(keyword in combined for keyword in ["trl", "vllm", "peft", "framework ownership"])
    invariant_required = any(
        keyword in combined
        for keyword in ["grpo", "rollout", "policy fingerprint", "trainer-step", "stateful", "reinforcement learning", " rl "]
    )
    return {
        "planning_mode": mode,
        "detected_phases": detected_phases,
        "active_phases": active_phases,
        "deferred_phases": deferred_phases,
        "parent_acceptance_signals": parent_signals,
        "max_detailed_subplans": max_detailed_subplans,
        "max_output_words": 12000,
        "goal_token_risk": risk,
        "review_checkpoint": "after_active_wave",
        "estimated_subplans": estimated_subplans,
        "estimated_output_words": estimated_words,
        "confirmation_threshold": ">15_files_or_very_high_token_risk",
        "user_confirmation_required": estimated_subplans > 15 or risk == "very_high" or mode == "full",
        "framework_ownership_required": framework_required,
        "algorithmic_invariants_required": invariant_required,
        "source_sections": [
            "Planner-docs/Main-Planing.md::## 6. Phase-Based Master Roadmap",
            "Planner-docs/Main-Planing.md::## 8. Prioritized Next Steps",
            "Planner-docs/Main-Planing.md::## 9. Step 2 Preparation Notes",
        ],
    }


def collect_stage_scope(
    root: Path,
    stage: str,
    mode: str,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return collect_stage_scope(root, stage, mode, opened)
    subplans = [
        path
        for path in controller_regular_paths(repository, "step3")
        if re.fullmatch(r"Planner-docs/Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9-]+\.md", path)
    ]
    scope: dict[str, object] = {"stage": stage, "project_root": "."}
    if stage in {"step2", "step3"}:
        scope["detailed_subplans"] = subplans
        scope["subplan_contracts"] = collect_subplan_scope(root, subplans, repository)
        scope["subplan_count"] = len(subplans)
        scope["index_path"] = (
            "Planner-docs/Sub-Planing-Index.md"
            if controller_path_kind(repository, "Planner-docs/Sub-Planing-Index.md") == "regular"
            else None
        )
    if stage == "step2":
        scope["planning_horizon"] = collect_step2_planning_horizon(root, mode, len(subplans), repository)
    if stage == "step4":
        ready_queue = extract_ready_queue(root, repository)
        enriched_queue: list[dict[str, object]] = []
        for item in ready_queue:
            enriched = dict(item)
            enriched.update(subplan_scope_item(root, item["subplan_path"], repository))
            enriched_queue.append(enriched)
        scope["ready_queue"] = enriched_queue
        scope["ready_count"] = len(ready_queue)
        audit_text = repository_model_text(
            root,
            "Planner-docs/Sub-Planing-Audit.md",
            repository=repository,
        )
        scope["no_action_required"] = bool(audit_text and "NO_ACTION_REQUIRED" in audit_text)
    return scope


def join_contract_values(value: object) -> str:
    if isinstance(value, list):
        normalized: list[str] = []
        for item in value:
            if isinstance(item, dict) and isinstance(item.get("path"), str):
                normalized.append(item["path"])
            elif str(item).strip():
                normalized.append(str(item))
        return ",".join(normalized) or "none"
    if isinstance(value, str) and value.strip():
        return value.strip()
    return "none"


def command_id_summary(commands: object) -> str:
    if not isinstance(commands, list):
        return "none"
    ids = [
        str(command.get("id")).strip()
        for command in commands
        if isinstance(command, dict) and isinstance(command.get("id"), str) and str(command.get("id")).strip()
    ]
    return ",".join(ids) if ids else "none"


def contract_driven_work_steps(item: dict[str, object]) -> list[str]:
    path = str(item.get("subplan_path") or item.get("source_subplan_path") or "unknown")
    contract = item.get("implementation_contract")
    contract = contract if isinstance(contract, dict) else {}
    parent_signals = join_contract_values(contract.get("parent_signals"))
    implementation_paths = join_contract_values(contract.get("implementation_paths"))
    forbidden_paths = join_contract_values(contract.get("forbidden_paths"))
    validation_ids = command_id_summary(contract.get("validation_commands"))
    outputs = join_contract_values(contract.get("outputs"))
    security_required = contract.get("security_review_required")
    dependency_state = str(item.get("dependency_state") or "not_recorded")
    return [
        f"validate active snapshot for {path}",
        f"read {path} implementation contract and parent_signals={parent_signals}",
        f"permit writes only to implementation_paths={implementation_paths}; forbidden_paths={forbidden_paths}",
        f"dispatch implementer for {path} with validation_command_ids={validation_ids}, dependency_state={dependency_state}, security_review_required={json.dumps(security_required if isinstance(security_required, bool) else False)}",
        f"run task review and required security review for {path}; fix/re-review before VERIFIED",
        f"update ledger/result evidence for {path}; outputs={outputs}",
    ]


def stage_work_steps(stage: str, scope: dict[str, object]) -> list[str]:
    base = ["verify snapshot", "load canonical references"]
    if stage == "step2":
        horizon = scope.get("planning_horizon", {})
        horizon_step = (
            "derive active planning horizon from Main-Planing.md"
            if isinstance(horizon, dict)
            else "derive active planning horizon"
        )
        subplans = scope.get("detailed_subplans", [])
        return base + [horizon_step] + [f"detail active sub-plan {path}" for path in subplans] + ["run Step 2 validation checkpoints", "write final report"]
    if stage == "step3":
        subplans = scope.get("detailed_subplans", [])
        return base + [f"audit sub-plan {path}" for path in subplans] + ["run step3-preflight then step3 validation", "write final report"]
    if stage == "step4":
        queue = scope.get("ready_queue", [])
        if isinstance(queue, list) and queue:
            steps = base[:]
            for item in queue:
                if isinstance(item, dict):
                    steps.extend(contract_driven_work_steps(item))
            return steps + ["write final report"]
        return base + ["confirm NO_ACTION_REQUIRED or blocked Step 4 readiness", "write final report"]
    return base + ["perform stage-specific work", "run validation checkpoints", "write final report"]


def validation_checkpoints_for(stage: str) -> list[dict[str, object]]:
    mode = stage if stage != "step15" else "autopsy"
    modes = ["step3-preflight", "step3"] if stage == "step3" else [mode]
    return [
        {
            "id": f"VAL-{index:02d}",
            "argv": [
                "python3",
                "-I",
                "-S",
                "-B",
                "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
                "--root",
                ".",
                "--mode",
                checkpoint_mode,
                "--strict",
            ],
            "network": "deny",
            "probe_tier": 1,
        }
        for index, checkpoint_mode in enumerate(modes, start=1)
    ]


def checkpoint_is_safe(checkpoint: object) -> bool:
    if not isinstance(checkpoint, dict):
        return False
    argv = checkpoint.get("argv")
    if not isinstance(argv, list):
        return False
    expected_prefix = [
        "python3",
        "-I",
        "-S",
        "-B",
        "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
        "--root",
        ".",
        "--mode",
    ]
    if len(argv) != len(expected_prefix) + 2:
        return False
    if argv[: len(expected_prefix)] != expected_prefix:
        return False
    if not isinstance(argv[-2], str) or argv[-2] not in {"autopsy", "step2", "step3-preflight", "step3", "step4"}:
        return False
    if argv[-1] != "--strict":
        return False
    if checkpoint.get("network") != "deny":
        return False
    if checkpoint.get("probe_tier") != 1:
        return False
    return True


def goal_role(role: str, purpose: str, required: bool = True) -> dict[str, object]:
    profile = GOAL_AGENT_PROFILES[role]
    return {
        "role": role,
        "agent_type": profile["agent_type"],
        "model_profile": profile["model_profile"],
        "sandbox": profile["sandbox"],
        "fresh_context": True,
        "fork_context": False,
        "required": required,
        "purpose": purpose,
    }


def build_subagent_plan(stage: str, mode: str, active_scope: dict[str, object]) -> dict[str, object]:
    plan: dict[str, object] = {
        "max_depth": 1,
        "roles": [],
        "one_writer": True,
        "fresh_context_required": True,
        "dispatch_order": [],
    }
    if stage == "step2":
        plan["roles"] = [
            goal_role("explorer", "optional read-only repository evidence collection", required=False),
            goal_role("task_reviewer", "optional read-only planning consistency review", required=False),
        ]
        plan["dispatch_order"] = ["explorer", "task_reviewer"]
    if stage == "step3":
        plan["roles"] = [goal_role("task_reviewer", "read-only Step 3 audit review", required=False)]
        plan["dispatch_order"] = ["task_reviewer"]
    if stage == "step4" and mode in {"subagent_serial", "external_superpowers"}:
        queue = active_scope.get("ready_queue", [])
        security_required = any(
            isinstance(item, dict) and item.get("security_review_required") is True
            for item in queue
        )
        roles = [
            goal_role("implementer", "fresh-slice implementation writer"),
            goal_role("task_reviewer", "independent spec and quality review"),
        ]
        if security_required:
            roles.append(goal_role("security_reviewer", "independent security review for security-required slices"))
        roles.extend(
            [
                goal_role("fixer", "same-slice fixes when review requires changes", required=False),
                goal_role("final_reviewer", "batch-level final review before completion"),
            ]
        )
        plan["roles"] = roles
        plan["dispatch_order"] = [role["role"] for role in roles]
    return plan


def subagent_plan_is_valid(plan: object) -> bool:
    if not isinstance(plan, dict) or plan.get("max_depth") != 1:
        return False
    roles = plan.get("roles")
    if not isinstance(roles, list):
        return False
    for role in roles:
        if not isinstance(role, dict):
            return False
        name = role.get("role")
        if name not in GOAL_AGENT_PROFILES:
            return False
        profile = GOAL_AGENT_PROFILES[str(name)]
        for key in ("agent_type", "model_profile", "sandbox"):
            if role.get(key) != profile[key]:
                return False
        if role.get("fresh_context") is not True or role.get("fork_context") is not False:
            return False
    return True


def _scope_source_path(item: dict[str, object]) -> str:
    value = item.get("source_subplan_path") or item.get("subplan_path")
    return str(value) if isinstance(value, str) else ""


def _normalized_contract_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def _stored_goal_scope_binding(
    source_path: str,
    source_sha256: str,
    item: dict[str, object],
) -> dict[str, object]:
    contract = item.get("implementation_contract")
    contract = contract if isinstance(contract, dict) else {}
    return {
        "errors": [],
        "source_subplan_path": source_path,
        "source_subplan_sha256": source_sha256,
        "implementation_contract": contract,
        "implementation_contract_digest": canonical_json_digest(contract) if contract else None,
        "validation_command_ids": implementation_contract_validation_command_ids(contract),
        "parent_acceptance_signal_ids": _normalized_contract_strings(contract.get("parent_signals")),
        "security_review_required": (
            contract.get("security_review_required")
            if isinstance(contract.get("security_review_required"), bool)
            else False
        ),
        "risk_class": contract.get("risk_class") if isinstance(contract.get("risk_class"), str) else "",
        "risk_domains": _normalized_contract_strings(contract.get("risk_domains")),
    }


def _validate_goal_scope_source_items(
    root: Path,
    label: str,
    items: object,
    errors: list[str],
    *,
    mutable_source_baseline: dict[str, str] | None = None,
    repository: RepositoryIO | None = None,
) -> None:
    if items is None:
        return
    if not isinstance(items, list):
        errors.append(f"invalid_{label}")
        return
    mutable_source_baseline = mutable_source_baseline or {}
    seen: dict[str, str | None] = {}
    for item in items:
        if not isinstance(item, dict):
            errors.append(f"invalid_{label}_item")
            continue
        source_path = _scope_source_path(item)
        if not source_path:
            errors.append(f"missing_source_subplan_mapping={label}")
            continue
        subplan_path = item.get("subplan_path")
        if isinstance(subplan_path, str) and subplan_path != source_path:
            errors.append(f"subplan_source_path_mismatch={source_path}")
        binding = repository_contract_binding(root, source_path, repository=repository)
        baseline_sha256 = mutable_source_baseline.get(source_path)
        live_sha256 = binding.get("source_subplan_sha256")
        mutable_source_changed = (
            isinstance(baseline_sha256, str)
            and isinstance(live_sha256, str)
            and live_sha256 != baseline_sha256
        )
        if mutable_source_changed:
            # Step 2 owns these files as outputs. Keep the stored compile-time
            # contract internally bound while allowing the live output to evolve.
            binding = _stored_goal_scope_binding(source_path, baseline_sha256, item)
        for error in binding.get("errors", []):
            errors.append(str(error))
        source_digest = binding.get("implementation_contract_digest")
        if source_path in seen:
            if seen[source_path] != source_digest:
                errors.append(f"duplicate_source_subplan_mapping={source_path}")
            else:
                errors.append(f"duplicate_source_subplan_mapping={source_path}")
        seen[source_path] = source_digest if isinstance(source_digest, str) else None

        if item.get("source_subplan_path", source_path) != source_path:
            errors.append(f"source_subplan_path_mismatch={source_path}")
        for key in ("source_subplan_sha256", "subplan_sha256"):
            if key in item and item.get(key) != binding.get("source_subplan_sha256"):
                errors.append(f"{key}_mismatch={source_path}")
        if item.get("implementation_contract") != binding.get("implementation_contract"):
            errors.append(f"implementation_contract_source_mismatch={source_path}")
        if item.get("implementation_contract_digest") != binding.get("implementation_contract_digest"):
            errors.append(f"implementation_contract_digest_source_mismatch={source_path}")
        if item.get("validation_command_ids", []) != binding.get("validation_command_ids", []):
            errors.append(f"validation_command_ids_source_mismatch={source_path}")
        if item.get("security_review_required") != binding.get("security_review_required"):
            errors.append(f"security_review_required_source_mismatch={source_path}")
        if item.get("parent_acceptance_signal_ids", []) != binding.get("parent_acceptance_signal_ids", []):
            errors.append(f"parent_acceptance_signal_ids_source_mismatch={source_path}")
        if item.get("risk_class", "") != binding.get("risk_class", ""):
            errors.append(f"risk_class_source_mismatch={source_path}")
        if item.get("risk_domains", []) != binding.get("risk_domains", []):
            errors.append(f"risk_domains_source_mismatch={source_path}")


def validate_goal_scope_source_bindings(
    root: Path,
    run: dict[str, object],
    errors: list[str],
    repository: RepositoryIO | None = None,
) -> None:
    active_scope = run.get("active_scope")
    if not isinstance(active_scope, dict):
        errors.append("invalid_active_scope")
        return
    mutable_source_baseline: dict[str, str] = {}
    if run.get("stage") == "step2":
        snapshot = run.get("stage_snapshot")
        mutable = snapshot.get("mutable_outputs") if isinstance(snapshot, dict) else None
        files = mutable.get("files") if isinstance(mutable, dict) else None
        for item in files if isinstance(files, list) else []:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            sha256 = item.get("sha256")
            if (
                isinstance(path, str)
                and isinstance(sha256, str)
                and mutable_output_matches(path, [STEP2_MUTABLE_SUBPLAN_PATTERN])
            ):
                mutable_source_baseline[path] = sha256
    _validate_goal_scope_source_items(
        root,
        "subplan_contracts",
        active_scope.get("subplan_contracts"),
        errors,
        mutable_source_baseline=mutable_source_baseline,
        repository=repository,
    )
    _validate_goal_scope_source_items(
        root,
        "ready_queue",
        active_scope.get("ready_queue"),
        errors,
        repository=repository,
    )


def validate_stage_snapshot(
    root: Path,
    run: dict[str, object],
    errors: list[str],
    repository: RepositoryIO | None = None,
) -> None:
    stage = str(run.get("stage", ""))
    snapshot = run.get("stage_snapshot")
    active_scope = run.get("active_scope") if isinstance(run.get("active_scope"), dict) else {}
    mutable_patterns = goal_mutable_output_patterns(stage, active_scope)
    if not isinstance(snapshot, dict):
        errors.append("stage_snapshot_missing")
        return
    if snapshot.get("stage") != stage:
        errors.append("stage_snapshot_stage_mismatch")
    immutable = snapshot.get("immutable_inputs")
    if not isinstance(immutable, list):
        errors.append("stage_snapshot_immutable_inputs_invalid")
        immutable = []
    elif snapshot.get("immutable_input_digest") != snapshot_digest(stage, immutable):
        errors.append("stage_snapshot_immutable_digest_mismatch")
    if snapshot.get("immutable_input_digest") != run.get("source_snapshot_digest"):
        errors.append("stage_snapshot_source_digest_mismatch")
    if snapshot.get("template_bundle_digest") != run.get("template_bundle_digest"):
        errors.append("stage_snapshot_template_digest_mismatch")
    if snapshot.get("compiler_version") != GOAL_COMPILER_VERSION:
        errors.append("stage_snapshot_compiler_version_mismatch")
    if snapshot.get("goal_spec_digest") != run.get("goal_spec_digest"):
        errors.append("stage_snapshot_goal_spec_digest_mismatch")

    mutable = snapshot.get("mutable_outputs")
    if not isinstance(mutable, dict):
        errors.append("stage_snapshot_mutable_outputs_invalid")
    else:
        declared = mutable.get("declared")
        if declared != mutable_patterns:
            errors.append("stage_snapshot_mutable_outputs_mismatch")
        duplicates = mutable.get("duplicates")
        if duplicates:
            errors.append("duplicate_mutable_output_declarations")
        for item in mutable.get("files", []) if isinstance(mutable.get("files"), list) else []:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if (
                item.get("exists") is True
                and isinstance(path, str)
                and (
                    controller_path_kind(repository, path) if repository is not None else _repository_path_kind(root, path)
                ) != "regular"
            ):
                errors.append(f"mutable_output_removed={path}")

    baseline = snapshot.get("workspace_baseline")
    if not isinstance(baseline, dict):
        errors.append("stage_snapshot_workspace_baseline_missing")
        return
    current = workspace_baseline(
        root,
        mutable_patterns,
        step4_unselected_subplan_paths(root, active_scope, repository) if stage == "step4" else set(),
        repository=repository,
    )
    for key in (
        "branch",
        "base_commit",
        "staged_diff_hash",
        "unstaged_diff_hash",
        "untracked_inventory_hash",
        "workspace_inventory_sha256",
    ):
        if baseline.get(key) != current.get(key):
            errors.append(f"workspace_baseline_mismatch={key}")


def validate_goal_budget(run: dict[str, object], errors: list[str]) -> None:
    budget = run.get("budget_contract")
    errors.extend(validate_budget_contract(budget))
    errors.extend(validate_token_usage(run.get("token_usage")))
    if not isinstance(budget, dict):
        return
    if run.get("stage") == "step4":
        active_scope = run.get("active_scope")
        ready_queue = active_scope.get("ready_queue") if isinstance(active_scope, dict) else []
        if isinstance(ready_queue, list) and len(ready_queue) > budget_limit(budget, "max_selected_tasks"):
            errors.append("budget_selected_tasks_exceeded")
    subagent_plan = run.get("subagent_plan")
    if isinstance(subagent_plan, dict):
        roles = subagent_plan.get("roles")
        if isinstance(roles, list) and len(roles) > len(GOAL_AGENT_PROFILES):
            errors.append("budget_subagent_role_count_exceeded")


def validate_goal_policy(run: dict[str, object], errors: list[str]) -> None:
    stage = str(run.get("stage", ""))
    mode = str(run.get("mode", ""))
    sources = run.get("source_snapshot")
    active_scope = run.get("active_scope")
    if stage not in STAGE_REFERENCES or mode not in STAGE_MODES.get(stage, set()):
        return
    if not isinstance(sources, list) or not isinstance(active_scope, dict):
        return
    expected = goal_policy_envelope(stage, sources, mode, active_scope)
    expected_digest = canonical_json_digest(expected)
    if run.get("goal_policy_digest") != expected_digest:
        errors.append("goal_policy_digest_mismatch")
    for key, expected_value in expected.items():
        if run.get(key) != expected_value:
            errors.append(f"goal_policy_mismatch={key}")


def default_goal_run(
    root: Path,
    stage: str,
    mode: str | None = None,
    objective: str | None = None,
    run_id_suffix: str | None = None,
    repository: RepositoryIO | None = None,
) -> dict[str, object]:
    if repository is None:
        with open_repository_io(root) as opened:
            return default_goal_run(
                canonical_repository_root(opened),
                stage,
                mode,
                objective,
                run_id_suffix,
                opened,
            )
    selected_mode = mode or ("subagent_serial" if stage == "step4" else "wave")
    selected_objective = objective or f"Run CodexQB {stage} using current repository planning evidence."
    active_scope = collect_stage_scope(root, stage, selected_mode, repository)
    mutable_patterns = goal_mutable_output_patterns(stage, active_scope)
    baseline_excluded_paths = (
        step4_unselected_subplan_paths(root, active_scope, repository)
        if stage == "step4"
        else set()
    )
    git_evidence = repository_workspace_evidence(root, repository)
    sources = collect_sources(root, stage, active_scope, git_evidence, repository)
    digest = snapshot_digest(stage, sources)
    subagent_plan = build_subagent_plan(stage, selected_mode, active_scope)
    spec_digest = goal_spec_digest(stage, sources, selected_mode, selected_objective, active_scope)
    policy = goal_policy_envelope(stage, sources, selected_mode, active_scope)
    policy_digest = canonical_json_digest(policy)
    bundle = template_bundle(stage)
    token_usage = token_usage_not_observed()
    snapshot = stage_snapshot(
        root,
        stage,
        sources,
        mutable_patterns,
        template_bundle_digest=str(bundle["digest"]),
        goal_spec_digest_value=spec_digest,
        baseline_excluded_paths=baseline_excluded_paths,
        git_evidence=git_evidence,
        repository=repository,
    )
    suffix = invocation_suffix(run_id_suffix)
    run_id = goal_run_id_for(stage, spec_digest, suffix)
    allowed_writes = mutable_patterns
    return {
        "goal_run_schema_version": GOAL_RUN_SCHEMA_VERSION,
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "handoff_contract_version": HANDOFF_CONTRACT_VERSION,
        "goal_spec_id": f"spec-{stage}-{spec_digest[:16]}",
        "goal_spec_digest": spec_digest,
        "goal_policy_digest": policy_digest,
        "goal_run_id": run_id,
        "goal_run_invocation_id": suffix,
        "stage": stage,
        "stage_contract_version": HANDOFF_CONTRACT_VERSION,
        "plugin_version": PLUGIN_VERSION,
        "template_bundle": bundle["templates"],
        "template_bundle_digest": bundle["digest"],
        "compiler": bundle["compiler"],
        "project_name": project_name(root, repository),
        "mode": selected_mode,
        "objective": selected_objective,
        "source_snapshot": sources,
        "source_snapshot_digest": digest,
        "stage_snapshot": snapshot,
        "required_inputs": policy["required_inputs"],
        "allowed_writes": allowed_writes,
        "forbidden_writes": policy["forbidden_writes"],
        "active_scope": active_scope,
        "work_steps": stage_work_steps(stage, active_scope),
        "validation_checkpoints": policy["validation_checkpoints"],
        "stop_gates": policy["stop_gates"],
        "subagent_plan": subagent_plan,
        "context_token_budget": policy["context_token_budget"],
        "budget_contract": policy["budget_contract"],
        "token_usage": token_usage,
        "final_report_contract": policy["final_report_contract"],
        "user_confirmation_required": policy["user_confirmation_required"],
        "generated_at": f"invocation:{suffix}",
        "safety": policy["safety"],
    }


def validate_goal_run(
    root: Path,
    run: dict[str, object],
    repository: RepositoryIO | None = None,
) -> list[str]:
    if repository is None:
        try:
            with open_repository_io(root) as opened:
                return validate_goal_run(canonical_repository_root(opened), run, opened)
        except (OSError, TypeError, ValueError) as exc:
            return [f"repository_io_failed={str(exc).split('=', 1)[0]}"]
    errors: list[str] = []
    stage = str(run.get("stage", ""))
    if stage not in STAGE_REFERENCES:
        errors.append(f"invalid_stage={stage or 'missing'}")
        return errors
    if run.get("goal_run_schema_version") != GOAL_RUN_SCHEMA_VERSION:
        errors.append("invalid_goal_run_schema_version")
    if run.get("plugin_version") != PLUGIN_VERSION:
        errors.append("invalid_plugin_version")
    mode = str(run.get("mode", ""))
    if mode not in STAGE_MODES[stage]:
        errors.append(f"invalid_goal_mode={mode or 'missing'}")
    objective = run.get("objective")
    if not isinstance(objective, str) or not objective.strip():
        errors.append("objective_required")
    work_steps = run.get("work_steps")
    if (
        not isinstance(work_steps, list)
        or not work_steps
        or any(not isinstance(item, str) or not item.strip() for item in work_steps)
    ):
        errors.append("work_steps_required")
    elif isinstance(run.get("active_scope"), dict) and work_steps != stage_work_steps(stage, run["active_scope"]):
        errors.append("work_steps_mismatch")
    checkpoints = run.get("validation_checkpoints")
    if (
        not isinstance(checkpoints, list)
        or not checkpoints
        or any(not checkpoint_is_safe(item) for item in checkpoints)
    ):
        errors.append("invalid_validation_checkpoints")
    subagent_plan = run.get("subagent_plan")
    if not subagent_plan_is_valid(subagent_plan):
        errors.append("invalid_subagent_plan")
    token_budget = run.get("context_token_budget")
    if not isinstance(token_budget, dict) or token_budget.get("risk") not in {"low", "medium", "high"}:
        errors.append("invalid_context_token_budget")
    validate_goal_budget(run, errors)
    validate_goal_policy(run, errors)
    bundle = template_bundle(stage)
    if run.get("template_bundle") != bundle["templates"]:
        errors.append("template_bundle_mismatch")
    if run.get("template_bundle_digest") != bundle["digest"]:
        errors.append("template_bundle_digest_mismatch")
    if run.get("compiler") != bundle["compiler"]:
        errors.append("compiler_digest_mismatch")
    spec_digest = goal_spec_digest(
        stage,
        run.get("source_snapshot", []) if isinstance(run.get("source_snapshot"), list) else [],
        str(run.get("mode", "")),
        str(run.get("objective", "")),
        run.get("active_scope", {}) if isinstance(run.get("active_scope"), dict) else {},
    )
    if run.get("goal_spec_digest") != spec_digest:
        errors.append("stored_goal_spec_digest_mismatch")
    if run.get("goal_spec_id") != f"spec-{stage}-{spec_digest[:16]}":
        errors.append("stored_goal_spec_id_mismatch")
    invocation = str(run.get("goal_run_invocation_id", ""))
    if not invocation or invocation_suffix(invocation) != invocation:
        errors.append("invalid_goal_run_invocation_id")
    expected_run_id = f"goal-{stage}-{spec_digest[:12]}-{invocation}" if invocation else ""
    if run.get("goal_run_id") != expected_run_id:
        errors.append("stored_goal_run_id_mismatch")
    validate_goal_scope_source_bindings(root, run, errors, repository)
    validate_stage_snapshot(root, run, errors, repository)
    text = json.dumps(run, sort_keys=True)
    if has_secret_like(text):
        errors.append("secret_like_content")

    allowed = set(str(item) for item in run.get("allowed_writes", []) if isinstance(item, str))
    forbidden = set(str(item) for item in run.get("forbidden_writes", []) if isinstance(item, str))
    if allowed & forbidden or any(glob_patterns_overlap(left, right) for left in allowed for right in forbidden):
        errors.append("overlapping_allowed_forbidden_writes")
    for path in allowed:
        if not is_safe_repo_path(path, allow_glob=True):
            errors.append(f"unsafe_path={path}")
    for path in forbidden:
        if not is_safe_repo_path(path, allow_glob=True, allow_home=True):
            errors.append(f"unsafe_path={path}")

    stored_sources = run.get("source_snapshot")
    if not isinstance(stored_sources, list):
        errors.append("invalid_source_snapshot")
        stored_sources = []
    elif run.get("source_snapshot_digest") != snapshot_digest(stage, stored_sources):
        errors.append("stored_source_snapshot_digest_mismatch")

    current_sources = collect_sources(
        root,
        stage,
        run.get("active_scope", {}) if isinstance(run.get("active_scope"), dict) else {},
        repository=repository,
    )
    current_digest = snapshot_digest(stage, current_sources)
    if run.get("source_snapshot_digest") != current_digest:
        errors.append("source_snapshot_mismatch")
    return errors


def render_prompt_from_run(run: dict[str, object]) -> str:
    stage = str(run["stage"])
    spec = read_skill_text(f"references/goal-specs/{stage}.md")
    handoff = ""
    for rel in STAGE_REFERENCES[stage]:
        if "/handoffs/" in rel:
            handoff = read_skill_text(rel)
            break

    preview = [
        f"Stage: {stage}",
        f"Mode: {run['mode']}",
        f"Objective: {run['objective']}",
        f"Active phases/tasks: {json.dumps(run['active_scope'], sort_keys=True, separators=(',', ':'))}",
        "Deferred phases: see Planner-docs/Sub-Planing-Index.md when present",
        f"Expected writes: {', '.join(run['allowed_writes'])}",
        f"Validation: {len(run['validation_checkpoints'])} checkpoint(s)",
        f"Risk: context/token {run['context_token_budget']['risk']}",
        f"Budget contract: max_selected_tasks={run['budget_contract']['max_selected_tasks']} max_agent_attempts_per_role={run['budget_contract']['max_agent_attempts_per_role']} max_fix_cycles={run['budget_contract']['max_fix_cycles']} hard_total_token_limit={run['budget_contract']['hard_total_token_limit']} token_usage={run['token_usage']['status']}",
        f"Subagents: {json.dumps(run['subagent_plan'], sort_keys=True, separators=(',', ':'))}",
        f"User confirmation required: {run['user_confirmation_required']}",
        f"Stop gates: {', '.join(run['stop_gates'])}",
    ]

    lines = [
        f"# CodexQB Goal Prompt: {stage}",
        "",
        "Use $codexqb.",
        "",
        "## Goal Preview",
        "",
        *preview,
        "",
        "## Goal Compiler Safety",
        "",
        "- Treat this as a prompt preview, not an executor.",
        "- Do not install dependencies, commit, push, create pull requests, deploy, edit global Codex config, or sync plugin caches unless explicitly asked in the active run.",
        "- Recompute source snapshot hashes before starting or resuming; stop on mismatch.",
        "",
        "## Stage Spec",
        "",
        spec.strip(),
        "",
        "## Source Snapshot",
        "",
    ]
    for source in run["source_snapshot"]:
        visible = f" value={source['value']}" if source.get("scope") == "git" and "value" in source else ""
        lines.append(f"- {source['scope']}:{source['path']} sha256={source['sha256']}{visible}")
    if handoff:
        lines += ["", "## Canonical Handoff", "", handoff.strip()]
    return "\n".join(lines) + "\n"


def compile_goal(
    root: Path,
    stage: str,
    output_dir: Path | None = None,
    mode: str | None = None,
    objective: str | None = None,
    *,
    replace: bool = False,
    resume: bool = False,
    run_id_suffix: str | None = None,
) -> dict[str, object]:
    lexical_root = lexical_absolute(root)
    if stage not in STAGE_REFERENCES:
        raise ValueError(f"unsupported stage: {stage}")
    if resume and output_dir is None:
        raise ValueError("resume_requires_output_dir")
    with open_repository_io(root) as repository:
        root = canonical_repository_root(repository)
        run = default_goal_run(
            root,
            stage,
            mode,
            objective,
            run_id_suffix,
            repository,
        )
        errors = validate_goal_run(root, run, repository)
        if errors:
            raise ValueError(";".join(errors))
        blockers = stage_prerequisite_blockers(root, stage, repository) if not resume else []
    out_dir = resolve_managed_goal_run_dir(
        root,
        output_dir,
        str(run["goal_run_id"]),
        lexical_root=lexical_root,
    )
    with open_managed_goal_run_directory(
        root,
        out_dir,
        create=not resume,
        allow_existing=replace or resume,
    ) as artifacts:
        with artifacts.locked():
            if resume:
                try:
                    existing = artifacts.read_json("Goal-Run.json")
                except FileNotFoundError as exc:
                    raise ValueError(f"goal_run_resume_missing={out_dir.name}") from exc
                existing_errors = validate_goal_run(root, existing)
                if existing_errors:
                    raise ValueError(";".join(existing_errors))
                try:
                    result = artifacts.read_json("Goal-Result.json")
                except FileNotFoundError:
                    result = {
                        "goal_run_id": existing.get("goal_run_id"),
                        "stage": existing.get("stage"),
                        "status": "resumed",
                    }
                return {"run": existing, "result": result, "output_dir": out_dir.as_posix()}

            run_json = serialize_safe_persistent_json(run)
            for name in ("Goal-Run.json", "Goal-Prompt.md", "Goal-Result.json"):
                artifacts.has_regular(name)
            if blockers:
                result = {
                    "goal_run_id": run["goal_run_id"],
                    "stage": stage,
                    "status": "blocked",
                    "blockers": blockers,
                    "goal_run_sha256": sha256_bytes(run_json.encode("utf-8")),
                    "budget_contract": run["budget_contract"],
                    "token_usage": run["token_usage"],
                    "source_count": len(run["source_snapshot"]),
                    "next_action": "Repair missing prerequisites, then prepare this Goal run again.",
                }
                result_json = serialize_safe_persistent_json(result)
                artifacts.write_text("Goal-Run.json", run_json)
                artifacts.remove("Goal-Prompt.md", missing_ok=True)
                artifacts.write_text("Goal-Result.json", result_json)
                return {"run": run, "result": result, "output_dir": out_dir.as_posix()}

            prompt = assert_safe_persistent_text(render_prompt_from_run(run))
            result = {
                "goal_run_id": run["goal_run_id"],
                "stage": stage,
                "status": "ready",
                "goal_run_sha256": sha256_bytes(run_json.encode("utf-8")),
                "prompt_sha256": sha256_bytes(prompt.encode("utf-8")),
                "budget_contract": run["budget_contract"],
                "token_usage": run["token_usage"],
                "source_count": len(run["source_snapshot"]),
                "next_action": "Review Goal-Prompt.md, then paste it into Goal mode only if the stage and safety policy match the intended run.",
            }
            result_json = serialize_safe_persistent_json(result)
            artifacts.write_text("Goal-Run.json", run_json)
            artifacts.write_text("Goal-Prompt.md", prompt)
            artifacts.write_text("Goal-Result.json", result_json)
            return {"run": run, "result": result, "output_dir": out_dir.as_posix()}


def render_goal_file(root: Path, goal_run_path: Path, output: Path | None = None) -> str:
    lexical_root = lexical_absolute(root)
    with open_repository_io(root) as repository:
        root = canonical_repository_root(repository)
        if ".." in goal_run_path.parts:
            raise ValueError("invalid_goal_run_path=path_traversal_rejected")
        requested_run_path = (
            goal_run_path
            if goal_run_path.is_absolute()
            else goal_runs_root(root) / goal_run_path
        )
        lexical_run_path = lexical_absolute(requested_run_path)
        if lexical_run_path.name != "Goal-Run.json":
            raise ValueError("invalid_goal_run_path=Goal-Run.json_required")
        run_dir = resolve_managed_goal_run_dir(root, lexical_run_path.parent, lexical_root=lexical_root)
        with open_managed_goal_run_directory(root, run_dir, create=False, allow_existing=True) as artifacts:
            with artifacts.locked():
                run = artifacts.read_json("Goal-Run.json")
                errors = validate_goal_run(root, run, repository)
                if errors:
                    raise ValueError(";".join(errors))
                prompt = assert_safe_persistent_text(render_prompt_from_run(run))
                if output:
                    if ".." in output.parts:
                        raise ValueError("invalid_goal_render_output=path_traversal_rejected")
                    requested_output = output if output.is_absolute() else run_dir / output
                    lexical_output = lexical_absolute(requested_output)
                    output_run_dir = resolve_managed_goal_run_dir(
                        root,
                        lexical_output.parent,
                        lexical_root=lexical_root,
                    )
                    if output_run_dir != run_dir or lexical_output.name != "Goal-Prompt.md":
                        raise ValueError("invalid_goal_render_output=managed_Goal-Prompt.md_required")
                    artifacts.has_regular("Goal-Prompt.md")
                    artifacts.write_text("Goal-Prompt.md", prompt)
                return prompt


def load_goal_run(path: Path, root: Path) -> dict[str, object]:
    repository_root = canonical_controller_repository_root(root)
    lexical_path = lexical_absolute(
        path
        if path.is_absolute()
        else goal_runs_root(repository_root) / path
    )
    if lexical_path.name != "Goal-Run.json":
        raise ValueError("invalid_goal_run_path=Goal-Run.json_required")
    run_dir = resolve_managed_goal_run_dir(repository_root, lexical_path.parent)
    with open_managed_goal_run_directory(
        repository_root,
        run_dir,
        create=False,
        allow_existing=True,
    ) as artifacts:
        if not artifacts.revalidate():
            raise ValueError("invalid_goal_output_dir=directory_identity_changed")
        return artifacts.read_json("Goal-Run.json")


def print_safe_field(name: str, value: object, *, file=None) -> None:
    print(f"{name}={safe_log_text(value)}", file=file)


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        self.exit(2, f"{safe_log_text(self.prog)}: error: {safe_log_text(message)}\n")


def main(argv: list[str] | None = None) -> int:
    parser = SafeArgumentParser(prog="goal_run.py", description="Compile deterministic CodexQB Goal previews.")
    sub = parser.add_subparsers(dest="command")

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--root", required=True, help="Target repository root.")
        p.add_argument("--stage", required=True, choices=sorted(STAGE_REFERENCES), help="Goal stage.")

    collect = sub.add_parser("collect", help="Print source snapshot JSON.")
    add_common(collect)
    prepare = sub.add_parser("prepare", help="Write Goal-Run.json, Goal-Prompt.md, and Goal-Result.json.")
    add_common(prepare)
    prepare.add_argument("--mode")
    prepare.add_argument("--objective")
    prepare.add_argument("--output-dir")
    prepare.add_argument("--replace", action="store_true")
    prepare.add_argument("--resume", action="store_true")
    prepare.add_argument("--run-id-suffix")
    validate = sub.add_parser("validate", help="Validate Goal-Run.json against current snapshot.")
    validate.add_argument("--root", required=True)
    validate.add_argument("--goal-run", required=True)
    render = sub.add_parser("render", help="Render Goal-Prompt.md from Goal-Run.json.")
    render.add_argument("--root", required=True)
    render.add_argument("--goal-run", required=True)
    render.add_argument("--output")

    parser.add_argument("--root", help=argparse.SUPPRESS)
    parser.add_argument("--stage", choices=sorted(STAGE_REFERENCES), help=argparse.SUPPRESS)
    parser.add_argument("--output-dir", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        if args.command is None:
            if not args.stage:
                parser.error("--stage is required")
            if not args.root:
                parser.error("--root is required")
            compiled = compile_goal(Path(args.root), args.stage, Path(args.output_dir) if args.output_dir else None)
            print_safe_field("goal_run_status", compiled["result"]["status"])
            print_safe_field("goal_run_id", compiled["result"]["goal_run_id"])
            print_safe_field("output_dir", compiled["output_dir"])
            return 0 if compiled["result"]["status"] == "ready" else 1
        if args.command == "collect":
            root = canonical_controller_repository_root(Path(args.root))
            sources = collect_sources(root, args.stage)
            collected = json.dumps({"stage": args.stage, "source_snapshot": sources}, indent=2, sort_keys=True)
            try:
                collected = redact_secret_like(collected)
            except (TypeError, ValueError):
                collected = '{"error":"unsafe_console_payload"}'
            print(collected)
            return 0
        if args.command == "prepare":
            compiled = compile_goal(
                Path(args.root),
                args.stage,
                Path(args.output_dir) if args.output_dir else None,
                args.mode,
                args.objective,
                replace=args.replace,
                resume=args.resume,
                run_id_suffix=args.run_id_suffix,
            )
            print_safe_field("goal_run_status", compiled["result"]["status"])
            print_safe_field("goal_run_id", compiled["result"]["goal_run_id"])
            print_safe_field("output_dir", compiled["output_dir"])
            return 0 if compiled["result"]["status"] == "ready" else 1
        if args.command == "validate":
            errors = validate_goal_run(
                canonical_controller_repository_root(Path(args.root)),
                load_goal_run(Path(args.goal_run), Path(args.root)),
            )
            if errors:
                print("goal_run_status=failed")
                for error in errors:
                    print_safe_field("error", error)
                return 1
            print("goal_run_status=passed")
            return 0
        if args.command == "render":
            prompt = render_goal_file(Path(args.root), Path(args.goal_run), Path(args.output) if args.output else None)
            if not args.output:
                print(prompt, end="")
            return 0
    except Exception as exc:
        print("goal_run_status=failed", file=sys.stderr)
        print_safe_field("error", exc, file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
