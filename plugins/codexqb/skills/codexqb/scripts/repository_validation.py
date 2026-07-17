#!/usr/bin/env python3
"""Repository-bound hygiene checks used by the CodexQB validation gate.

All target-tree discovery and content reads pass through one RepositoryIO
session.  Diagnostics contain only stable rule names, offsets, and path
digests; repository bytes and raw paths are never printed.
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


import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from repository_io import (  # noqa: E402
    RepositoryIO,
    _controller_read_bytes as controller_read_bytes,
    _controller_validation_inventory as controller_validation_inventory,
    _controller_workspace_proof as controller_workspace_proof,
    open_repository_io,
)
from safety_contracts import (  # noqa: E402
    package_secret_match_locations,
    package_secret_path_match_locations,
)


_STALE_NEEDLES = tuple(
    value.encode("utf-8")
    for value in (
        "project-" + "planner",
        "Project " + "Planner",
        "$" + "project-" + "planner",
    )
)
_STALE_BLOCKED_SUFFIXES = frozenset({".key", ".pem", ".pyc", ".zip"})
_DENIED_PARTS = frozenset(
    {
        ".git",
        ".codexqb",
        "__macosx",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".cache",
        ".tox",
        ".venv",
        "artifacts",
        "build",
        "dist",
        "logs",
        "node_modules",
        "tmp",
        "venv",
    }
)
_DENIED_SUFFIXES = frozenset({".pyc", ".pem", ".key", ".tmp", ".zip"})
_REQUIRED_REGULAR_PATHS = frozenset(
    {
        ".agents/plugins/marketplace.json",
        "plugins/codexqb/.codex-plugin/plugin.json",
        "plugins/codexqb/skills/codexqb/SKILL.md",
        "plugins/codexqb/skills/codexqb/agents/openai.yaml",
        "plugins/codexqb/skills/codexqb/scripts/safety_contracts.py",
        "plugins/codexqb/skills/codexqb/scripts/artifact_io.py",
        "plugins/codexqb/skills/codexqb/scripts/evidence_contracts.py",
        "plugins/codexqb/skills/codexqb/scripts/repository_evidence.py",
        "plugins/codexqb/skills/codexqb/scripts/repository_io.py",
        "plugins/codexqb/skills/codexqb/scripts/controller_store.py",
        "plugins/codexqb/skills/codexqb/scripts/execution_controller.py",
        "plugins/codexqb/skills/codexqb/scripts/repository_io_policy.py",
        "plugins/codexqb/skills/codexqb/scripts/repository_validation.py",
        "plugins/codexqb/skills/codexqb/scripts/git_evidence.py",
        "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
        "plugins/codexqb/skills/codexqb/scripts/goal_run.py",
        "plugins/codexqb/skills/codexqb/scripts/apply_run.py",
        "plugins/codexqb/skills/codexqb/scripts/mount_identity.py",
        "plugins/codexqb/skills/codexqb/scripts/doctor.py",
        "plugins/codexqb/skills/codexqb/references/First-Planner.md",
        "plugins/codexqb/skills/codexqb/references/Autopsy-Planner.md",
        "plugins/codexqb/skills/codexqb/references/Second-Planner.md",
        "plugins/codexqb/skills/codexqb/references/Third-Planner.md",
        "plugins/codexqb/skills/codexqb/references/Fourth-Planner.md",
        "plugins/codexqb/skills/codexqb/references/goal-compiler.md",
        "plugins/codexqb/skills/codexqb/references/apply-orchestrator.md",
        "plugins/codexqb/skills/codexqb/references/apply-run-schema.json",
        "plugins/codexqb/skills/codexqb/references/apply/controller.md",
        "plugins/codexqb/skills/codexqb/references/apply/implementer.md",
        "plugins/codexqb/skills/codexqb/references/apply/task-reviewer.md",
        "plugins/codexqb/skills/codexqb/references/apply/security-reviewer.md",
        "plugins/codexqb/skills/codexqb/references/apply/fixer.md",
        "plugins/codexqb/skills/codexqb/references/apply/final-reviewer.md",
        "plugins/codexqb/skills/codexqb/references/goal-specs/step15.md",
        "plugins/codexqb/skills/codexqb/references/goal-specs/step2.md",
        "plugins/codexqb/skills/codexqb/references/goal-specs/step3.md",
        "plugins/codexqb/skills/codexqb/references/goal-specs/step4.md",
        "plugins/codexqb/skills/codexqb/references/handoffs/run-step2.md",
        "plugins/codexqb/skills/codexqb/references/handoffs/run-step3.md",
        "plugins/codexqb/skills/codexqb/references/handoffs/run-step4.md",
        "plugins/codexqb/skills/codexqb/references/repo-aware-intake.md",
        "plugins/codexqb/skills/codexqb/references/workflow-quality.md",
        "plugins/codexqb/skills/codexqb/references/vibecoding-principles.md",
        "plugins/codexqb/skills/codexqb/references/subagent-playbook.md",
        "plugins/codexqb/skills/codexqb/references/planning-ledger.md",
        "plugins/codexqb/skills/codexqb/references/project-ontology.md",
        "plugins/codexqb/skills/codexqb/references/project-comprehension-methods.md",
        "plugins/codexqb/skills/codexqb/references/probe-policy.md",
        "plugins/codexqb/skills/codexqb/references/assessment-and-budget.md",
        "plugins/codexqb/skills/codexqb/references/engineering-principles.md",
        "evals/run_apply_behavior_smoke.py",
        "evals/run_downstream_goal_apply_dry_run.py",
        "evals/run_goal_apply_metric_checks.py",
        "evals/run_fixture_corpus_checks.py",
        "evals/run_fixture_checks.py",
        "requirements-ci.txt",
        "scripts/export_sanitized.py",
        "scripts/extract_verified_package.py",
        "scripts/package_policy.py",
        "scripts/validate_openai_yaml.py",
        "scripts/verify_package_manifest.py",
        "scripts/validate_apply_schema.py",
        "scripts/check_repository_io_policy.py",
        "scripts/run_test_suite.py",
        "tests/test_package_manifest.py",
        "tests/test_package_extraction.py",
        "tests/test_apply_schema.py",
        "tests/test_apply_inventory.py",
        "tests/test_evidence_contracts.py",
        "tests/test_repository_evidence.py",
        "tests/test_repository_io.py",
        "tests/test_repository_io_policy.py",
        "tests/test_repository_validation.py",
        "tests/test_git_evidence.py",
        "tests/test_mount_identity.py",
        "tests/test_doctor.py",
        "tests/test_suite_partition.py",
        "tests/platform/run_mount_identity_probe.py",
        "README.md",
        "CHANGELOG.md",
        "docs/INSTALLATION.md",
        "docs/USAGE.md",
        "docs/MAINTAINING.md",
        "docs/FEEDBACK-CLOSURE-AUDIT.md",
        "docs/release-audits/0.3.0-feedback-closure.md",
        "LICENSE",
    }
)
_REQUIRED_JSON_PATHS = frozenset(
    {
        ".agents/plugins/marketplace.json",
        "plugins/codexqb/.codex-plugin/plugin.json",
    }
)
_MAX_FINDINGS = 1024


def _path_digest(relative: str) -> str:
    return hashlib.sha256(relative.encode("utf-8")).hexdigest()


def _stale_scan_allowed(relative: str) -> bool:
    path = PurePosixPath(relative)
    return not (
        path.suffix.casefold() in _STALE_BLOCKED_SUFFIXES
        or path.name == ".DS_Store"
        or path.name.startswith(".env")
        or path.name.endswith(".local")
        or ".local." in path.name
    )


def _path_denied(relative: str) -> bool:
    path = PurePosixPath(relative)
    folded_parts = tuple(part.casefold() for part in path.parts)
    folded_name = path.name.casefold()
    return (
        bool(_DENIED_PARTS.intersection(folded_parts))
        or any(
            part.startswith(".env")
            or part.endswith(".local")
            or ".local." in part
            for part in folded_parts
        )
        or folded_name == ".ds_store"
        or folded_name.startswith("._")
        or folded_name.startswith(".env")
        or folded_name.endswith(".local")
        or ".local." in folded_name
        or path.suffix.casefold() in _DENIED_SUFFIXES
    )


def _secret_matches(data: bytes, relative: str) -> list[tuple[str, int]]:
    """Delegate every repository payload to the canonical byte-safe scanner."""

    return package_secret_match_locations(
        data,
        PurePosixPath(relative).suffix,
    )


def _read_bound_bytes(repository: RepositoryIO, relative: str) -> bytes:
    evidence = controller_read_bytes(repository, relative, required=True)
    if evidence.data is None:
        raise ValueError("repository_validation_payload_missing")
    return evidence.data


def _strict_json_payload(data: bytes) -> bool:
    def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_json_key")
            result[key] = value
        return result

    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    return isinstance(value, dict)


def validate_repository(
    repository: RepositoryIO,
    *,
    require_shape: bool,
    workspace_mode: str,
) -> tuple[tuple[str, str, int], ...]:
    inventory = controller_validation_inventory(repository)
    findings: list[tuple[str, str, int]] = []

    def add_finding(rule: str, relative: str, offset: int = 0) -> None:
        if len(findings) >= _MAX_FINDINGS:
            raise ValueError("repository_validation_finding_limit_exceeded")
        findings.append((rule, _path_digest(relative), offset))

    paths = tuple(
        str(item["path"])
        for item in inventory
        if item.get("kind") == "regular"
    )
    path_set = frozenset(paths)
    if workspace_mode == "git":
        proof = controller_workspace_proof(repository)
        if proof.evidence.get("is_git") is not True:
            raise ValueError("repository_validation_git_root_required")
    elif workspace_mode == "external-package":
        if "PACKAGE-MANIFEST.json" not in path_set:
            raise ValueError("repository_validation_package_manifest_required")
    else:
        raise ValueError("repository_validation_workspace_mode_invalid")
    visible = tuple(
        str(item["path"])
        for item in inventory
        if item.get("kind") in {"directory", "regular"}
    )
    for relative in visible:
        path_secret_matches = package_secret_path_match_locations(relative)
        if len(path_secret_matches) > _MAX_FINDINGS - len(findings):
            raise ValueError("repository_validation_finding_limit_exceeded")
        for rule, offset in path_secret_matches:
            add_finding(f"package_path_{rule}", relative, offset)
        if _path_denied(relative):
            add_finding("blocked_path", relative)
    if require_shape:
        for relative in sorted(_REQUIRED_REGULAR_PATHS - path_set):
            add_finding("missing_required_file", relative)
    for relative in paths:
        data = _read_bound_bytes(repository, relative)
        if (
            require_shape
            and relative in _REQUIRED_JSON_PATHS
            and not _strict_json_payload(data)
        ):
            add_finding("invalid_required_json", relative)
        if _stale_scan_allowed(relative) and any(
            needle in data for needle in _STALE_NEEDLES
        ):
            add_finding("stale_invocation_text", relative)
        secret_matches = _secret_matches(data, relative)
        if len(secret_matches) > _MAX_FINDINGS - len(findings):
            raise ValueError("repository_validation_finding_limit_exceeded")
        for rule, offset in secret_matches:
            add_finding(rule, relative, offset)
    # Cached engine snapshots revalidate on every access.  A late create,
    # delete, replacement, or metadata change therefore fails this final pass.
    controller_validation_inventory(repository)
    return tuple(sorted(findings))


def _render(findings: tuple[tuple[str, str, int], ...]) -> int:
    rules = {item[0] for item in findings}
    if "stale_invocation_text" in rules:
        print("stale_invocation_references_found")
    if rules - {
        "blocked_path",
        "invalid_required_json",
        "missing_required_file",
        "stale_invocation_text",
    }:
        print("repository_secret_hygiene_failed")
    if "blocked_path" in rules:
        print("package_hygiene_failed")
    if rules.intersection({"invalid_required_json", "missing_required_file"}):
        print("repository_shape_validation_failed")
    for index, (rule, path_sha256, offset) in enumerate(findings, start=1):
        print(
            f"repository_validation_finding=index-{index}:"
            f"path_sha256:{path_sha256}:offset:{offset}:rule:{rule}"
        )
    if findings:
        return 1
    print("repository_validation=passed")
    return 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--contract", required=True, choices=("full", "hygiene"))
    parser.add_argument(
        "--workspace-mode",
        required=True,
        choices=("git", "external-package"),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.root != ".":
        print("repository_validation=failed")
        print("error=repository_root_requires_exact_dot")
        return 2
    try:
        with open_repository_io(".") as repository:
            return _render(
                validate_repository(
                    repository,
                    require_shape=args.contract == "full",
                    workspace_mode=args.workspace_mode,
                )
            )
    except (OSError, TypeError, ValueError) as exc:
        reason = str(exc).split("=", 1)[0].split(":", 1)[0]
        print("repository_validation=failed")
        print(f"error={reason}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
