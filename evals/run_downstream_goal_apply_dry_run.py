#!/usr/bin/env python3
"""Run a representative downstream Step 2 -> Step 4 Goal/Apply dry run.

This is a controller-protocol simulation/dry run, not proof of a real Codex
agent identity. The gate proves direct-mode trusted-finalization rejection,
then uses a disposable git repository to execute every planned validation and
publish the complete signed subagent-serial review receipt chain. It does not
call Codex, spawn real subagents, push, open a PR, deploy, or mutate external
systems.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]

if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())

from tests.controller_test_support import (  # noqa: E402
    assert_real_trust_store_unchanged,
    controller_cli_command,
    temporary_controller_home,
)
from tests.test_validate_planner_docs import write_audit, write_valid_step2_fixture  # noqa: E402


_CONTROLLER_TEST_HOME: Path | None = None
_SAFE_FAILURE_CODES = frozenset(
    {
        "apply_command_repository_root_mismatch",
        "command_failed",
        "command_unexpected_success",
        "controller_test_home_not_initialized",
        "expected_failure_missing",
        "unhandled_exception",
    }
)


def fail(message: str) -> None:
    candidate = message.partition("=")[0]
    code = candidate if candidate in _SAFE_FAILURE_CODES else "unspecified"
    detail_sha256 = hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest()
    print(f"downstream_goal_apply_dry_run_failed_code={code.lower()}")
    print(f"downstream_goal_apply_dry_run_failed_detail_sha256={detail_sha256}")
    raise SystemExit(1)


def run_command(args: list[str], *, cwd: Path, timeout: int = 30) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )
    if completed.returncode != 0:
        fail(f"command_failed={' '.join(args)} stdout={completed.stdout.strip()} stderr={completed.stderr.strip()}")
    return completed.stdout


def run_command_expect_failure(args: list[str], *, cwd: Path, expected: str) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    combined = f"{completed.stdout}\n{completed.stderr}"
    if completed.returncode == 0:
        fail(f"command_unexpected_success={' '.join(args)} stdout={completed.stdout.strip()}")
    if expected not in combined:
        fail(
            f"expected_failure_missing={expected} stdout={completed.stdout.strip()} "
            f"stderr={completed.stderr.strip()}"
        )
    return combined


def parse_key(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1]
    fail(f"missing_output_key={key}")
    raise AssertionError("unreachable")


def apply_controller_command(root: Path, args: list[str]) -> list[str]:
    if _CONTROLLER_TEST_HOME is None:
        fail("controller_test_home_not_initialized")
    rooted = list(args)
    root_positions = [index for index, value in enumerate(rooted) if value == "--root"]
    if not root_positions:
        rooted.extend(["--root", root.as_posix()])
    elif (
        len(root_positions) != 1
        or root_positions[0] + 1 >= len(rooted)
        or Path(rooted[root_positions[0] + 1]).resolve() != root.resolve()
    ):
        fail("apply_command_repository_root_mismatch")
    return controller_cli_command("apply", _CONTROLLER_TEST_HOME, rooted)


def write_downstream_code(root: Path) -> None:
    (root / "src").mkdir()
    (root / "tests").mkdir()
    (root / "src/__init__.py").write_text("", encoding="utf-8")
    (root / "src/feature_1_1.py").write_text(
        "\n".join(
            [
                "def normalize_signal(value: str) -> str:",
                "    return value.strip().lower().replace(' ', '-')",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "src/feature_2_1.py").write_text(
        "\n".join(
            [
                "def gateway_status(enabled: bool) -> str:",
                "    return 'ready' if enabled else 'blocked'",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "tests/test_feature_1_1.py").write_text(
        "\n".join(
            [
                "import unittest",
                "",
                "from src.feature_1_1 import normalize_signal",
                "",
                "",
                "class Feature11Tests(unittest.TestCase):",
                "    def test_normalize_signal(self) -> None:",
                "        self.assertEqual(normalize_signal(' Local Contract '), 'local-contract')",
                "",
                "",
                "if __name__ == '__main__':",
                "    unittest.main()",
                "",
            ]
        ),
        encoding="utf-8",
    )
    (root / "tests/test_feature_2_1.py").write_text(
        "\n".join(
            [
                "import unittest",
                "",
                "from src.feature_2_1 import gateway_status",
                "",
                "",
                "class Feature21Tests(unittest.TestCase):",
                "    def test_gateway_status(self) -> None:",
                "        self.assertEqual(gateway_status(True), 'ready')",
                "        self.assertEqual(gateway_status(False), 'blocked')",
                "",
                "",
                "if __name__ == '__main__':",
                "    unittest.main()",
                "",
            ]
        ),
        encoding="utf-8",
    )


def adapt_validation_commands(docs: Path) -> None:
    replacements = {
        "python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q": (
            "python3 -B -m unittest tests/test_feature_1_1.py"
        ),
        "python3 -B -m pytest -p no:cacheprovider tests/test_feature_2_1.py -q": (
            "python3 -B -m unittest tests/test_feature_2_1.py"
        ),
        '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]': (
            '"argv": ["python3", "-B", "-m", "unittest", "tests/test_feature_1_1.py"]'
        ),
        '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_2_1.py", "-q"]': (
            '"argv": ["python3", "-B", "-m", "unittest", "tests/test_feature_2_1.py"]'
        ),
    }
    for path in [docs / "Sub-Planing-Index.md", *sorted(docs.glob("Faz-*-Plans/*.md"))]:
        text = path.read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")


def run_validator(root: Path, mode: str) -> str:
    return run_command(
        controller_cli_command(
            "planner-validator",
            None,
            [
                "--root",
                root.as_posix(),
                "--mode",
                mode,
                "--strict",
            ],
        ),
        cwd=root,
    )


def prepare_goal(root: Path, stage: str, mode: str, suffix: str) -> Path:
    if _CONTROLLER_TEST_HOME is None:
        fail("controller_test_home_not_initialized")
    output = run_command(
        controller_cli_command(
            "goal",
            _CONTROLLER_TEST_HOME,
            [
            "prepare",
            "--root",
            root.as_posix(),
            "--stage",
            stage,
            "--mode",
            mode,
            "--run-id-suffix",
            suffix,
            ],
        ),
        cwd=root,
    )
    if "goal_run_status=ready" not in output:
        fail(f"goal_not_ready={stage}:{mode}")
    out_dir = Path(parse_key(output, "output_dir"))
    goal_run = out_dir / "Goal-Run.json"
    prompt = out_dir / "Goal-Prompt.md"
    if not goal_run.is_file() or not prompt.is_file():
        fail(f"goal_outputs_missing={stage}:{mode}")
    run_command(
        controller_cli_command(
            "goal",
            _CONTROLLER_TEST_HOME,
            [
            "validate",
            "--root",
            root.as_posix(),
            "--goal-run",
            goal_run.as_posix(),
            ],
        ),
        cwd=root,
    )
    return out_dir


def git_checkpoint(root: Path) -> None:
    run_command(["git", "init"], cwd=root)
    run_command(["git", "checkout", "-b", "codex/downstream-dry-run"], cwd=root)
    run_command(["git", "add", "."], cwd=root)
    run_command(
        [
            "git",
            "-c",
            "user.name=CodexQB Dry Run",
            "-c",
            "user.email=codexqb-dry-run@example.invalid",
            "commit",
            "-m",
            "Initial downstream dry run fixture",
        ],
        cwd=root,
    )
    status = run_command(["git", "status", "--porcelain=v1"], cwd=root)
    if status.strip():
        fail(f"git_fixture_dirty={status.strip()}")


def prepare_apply(root: Path) -> Path:
    output = run_command(
        apply_controller_command(
            root,
            [
            "prepare",
            "--root",
            root.as_posix(),
            "--mode",
            "subagent_serial",
            "--run-id-suffix",
            "downstream-dry-run",
            ],
        ),
        cwd=root,
    )
    run_dir = Path(parse_key(output, "run_dir"))
    run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
    if run.get("workspace_detected") != "git":
        fail("apply_run_not_git_backed")
    if run.get("dirty_state") != "clean":
        fail(f"apply_run_dirty_state={run.get('dirty_state')}")
    if run.get("user_approval") is not False:
        fail("apply_run_unexpected_user_approval")
    return run_dir


def first_task(run_dir: Path) -> tuple[str, str, str, str, bool, list[object]]:
    progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
    tasks = progress.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 1:
        fail("expected_one_downstream_task")
    task = tasks[0]
    if not isinstance(task, dict):
        fail("invalid_downstream_task")
    task_id = str(task.get("task_id", ""))
    brief_sha = str(task.get("brief_sha256", ""))
    security_required = task.get("security_review_required") is True
    implementation_contract_digest = str(task.get("implementation_contract_digest", ""))
    task_contract_digest = str(task.get("task_contract_digest", ""))
    validation_commands = task.get("validation_commands", [])
    if not isinstance(validation_commands, list):
        validation_commands = []
    if not task_id or not brief_sha:
        fail("task_missing_id_or_brief_hash")
    if "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md" != task.get("source_subplan_path"):
        fail(f"unexpected_task_subplan={task.get('source_subplan_path')}")
    return (
        task_id,
        brief_sha,
        implementation_contract_digest,
        task_contract_digest,
        security_required,
        validation_commands,
    )


def run_apply(root: Path, args: list[str]) -> str:
    return run_command(
        apply_controller_command(root, args),
        cwd=root,
    )


def run_apply_expect_failure(root: Path, args: list[str], expected: str) -> str:
    return run_command_expect_failure(
        apply_controller_command(root, args),
        cwd=root,
        expected=expected,
    )


def current_task(run_dir: Path) -> dict[str, object]:
    progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
    tasks = progress.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 1 or not isinstance(tasks[0], dict):
        fail("expected_one_downstream_task")
    return tasks[0]


def assert_signed_receipt(path: Path, expected_kind: str) -> dict[str, object]:
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if receipt.get("receipt_kind") != expected_kind:
        fail(f"unexpected_receipt_kind={receipt.get('receipt_kind')}")
    mac = receipt.get("receipt_mac")
    if not isinstance(mac, str) or len(mac) != 64:
        fail(f"receipt_mac_missing={path.name}")
    for field in ("host_sandbox_proof", "approval_proof", "network_enforcement_proof"):
        if receipt.get(field) != "not_observed":
            fail(f"receipt_nonclaim_invalid={path.name}:{field}")
    return receipt


def drive_direct_rejection(root: Path) -> Path:
    output = run_apply(
        root,
        [
            "prepare",
            "--root",
            root.as_posix(),
            "--mode",
            "direct",
            "--run-id-suffix",
            "downstream-direct-rejection",
            "--allow-non-git-unsafe",
        ],
    )
    run_dir = Path(parse_key(output, "run_dir"))
    task_id = str(current_task(run_dir).get("task_id", ""))
    run_apply(root, ["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()])
    for state in ("IMPLEMENTING", "IMPLEMENTED", "TASK_REVIEW"):
        run_apply(
            root,
            [
                "transition",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--to",
                state,
                "--actor",
                "downstream-direct-controller",
                "--evidence",
                "direct dry-run lane advances only to prove trusted rejection",
            ],
        )
    run_apply_expect_failure(
        root,
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "VERIFIED",
            "--actor",
            "downstream-direct-controller",
            "--evidence",
            "direct mode must not claim trusted verification",
        ],
        f"verified_requires_subagent_reviewer_receipts={task_id}",
    )
    run_apply_expect_failure(
        root,
        [
            "finalize",
            "--run-dir",
            run_dir.as_posix(),
            "--actor",
            "downstream-direct-controller",
            "--evidence",
            "direct mode must not finalize without trusted verification",
        ],
        "finalize_requires_all_tasks_verified",
    )
    result = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))
    if result.get("status") == "complete" or current_task(run_dir).get("state") == "VERIFIED":
        fail("downstream_direct_lane_fabricated_trusted_success")
    return run_dir


def write_live_downstream_change(root: Path) -> None:
    (root / "src/feature_1_1.py").write_text(
        "def normalize_signal(value: str) -> str:\n"
        "    normalized = value.strip().lower()\n"
        "    return normalized.replace(' ', '-')\n",
        encoding="utf-8",
    )


def normalize_implementer_report(
    root: Path,
    run_dir: Path,
    task_id: str,
    agent_id: str,
    *,
    files_changed: list[str] | None = None,
    enriched: bool = False,
) -> None:
    task = current_task(run_dir)
    report = {
        "status": "DONE",
        "task_id": task_id,
        "implementer_agent_id": agent_id,
        "files_changed": sorted(files_changed or []),
        "concerns": [],
    }
    if enriched:
        change_reference = task.get("change_set")
        receipts = task.get("validation_receipts")
        commands = task.get("validation_commands")
        if not isinstance(change_reference, dict) or not isinstance(receipts, list):
            fail("downstream_controller_evidence_references_missing")
        if not isinstance(commands, list) or len(receipts) != len(commands) or not receipts:
            fail("downstream_not_every_planned_validation_has_receipt")
        change_path = run_dir / task_id / str(change_reference.get("path", ""))
        change_set = json.loads(change_path.read_text(encoding="utf-8"))
        changed_files = change_set.get("changed_files")
        if not isinstance(changed_files, list) or not changed_files:
            fail("downstream_live_change_set_is_empty")
        report["brief_sha256"] = task.get("brief_sha256")
        report["implementation_contract_digest"] = task.get(
            "implementation_contract_digest"
        )
        report["task_contract_digest"] = task.get("task_contract_digest")
        report["files_changed"] = sorted(
            str(item.get("path")) for item in changed_files if isinstance(item, dict)
        )
        report["validation_receipt_ids"] = sorted(
            str(item.get("receipt_id")) for item in receipts if isinstance(item, dict)
        )
        patch = (run_dir / task_id / "Review-Package.patch").read_bytes()
        report["change_set_id"] = change_reference.get("change_set_id")
        report["diff_sha256"] = hashlib.sha256(patch).hexdigest()

    run_apply(
        root,
        [
            "normalize-writer",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--agent-id",
            agent_id,
            "--report-json",
            json.dumps(report, sort_keys=True),
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            (
                "controller normalized the receipt-enriched simulated implementer return"
                if enriched
                else "controller normalized the initial simulated implementer return"
            ),
        ],
    )


def complete_review_phase(
    root: Path,
    run_dir: Path,
    task_id: str,
    *,
    role: str,
    phase: str,
    agent_id: str,
) -> None:
    packet_output = run_apply(
        root,
        [
            "dispatch",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            role,
            "--review-phase",
            phase,
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller-protocol dry run prepared reviewer packet",
        ],
    )
    if not Path(parse_key(packet_output, "packet_path")).is_file():
        fail(f"downstream_review_dispatch_packet_missing={phase}")
    run_apply(root, ["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()])
    run_apply(
        root,
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            role,
            "--review-phase",
            phase,
            "--agent-id",
            agent_id,
            "--status",
            "spawned",
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "protocol simulation recorded reviewer spawn; this is not identity proof",
        ],
    )
    report = {
        "status": "COMPLETE",
        "phase": phase,
        "verdict": "pass",
        "task_id": task_id,
        "reviewer_agent_id": agent_id,
        "evidence": [
            "Controller-protocol dry run reviewed live changes and signed validation receipts; "
            "no real Codex agent identity is claimed."
        ],
    }
    run_apply(
        root,
        [
            "normalize-review",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--review-phase",
            phase,
            "--agent-id",
            agent_id,
            "--report-json",
            json.dumps(report, sort_keys=True),
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller normalized simulated reviewer output; host completion proof is not observed",
        ],
    )
    run_apply(
        root,
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            role,
            "--review-phase",
            phase,
            "--agent-id",
            agent_id,
            "--status",
            "completed",
            "--actor",
            "downstream-protocol-controller",
            "--summary",
            f"{phase} protocol-simulation review completed",
            "--evidence",
            "controller observed the simulated reviewer lifecycle completion",
        ],
    )
    receipt_output = run_apply(
        root,
        [
            "publish-review",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--review-phase",
            phase,
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller published a signed protocol-simulation review receipt",
        ],
    )
    assert_signed_receipt(
        Path(parse_key(receipt_output, "receipt_path")),
        "codexqb_review_completion_receipt",
    )


def drive_subagent_apply(root: Path, run_dir: Path) -> None:
    task_id, _, _, _, security_required, validation_commands = first_task(run_dir)
    if not validation_commands:
        fail("downstream_missing_planned_validation_commands")
    run_apply(root, ["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()])
    packet_output = run_apply(
        root,
        [
            "dispatch",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller-protocol dry run prepared fresh implementer packet",
        ],
    )
    packet = json.loads(Path(parse_key(packet_output, "packet_path")).read_text(encoding="utf-8"))
    message = packet.get("spawn_request", {}).get("message")
    if not isinstance(message, str) or "Use only this fresh task context" not in message:
        fail("downstream_dispatch_not_fresh_context")
    if "Structured Implementation Contract" not in message:
        fail("downstream_dispatch_missing_contract")
    implementer_id = "downstream-simulated-implementer"
    run_apply(
        root,
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--agent-id",
            implementer_id,
            "--status",
            "spawned",
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "protocol simulation recorded implementer spawn; this is not identity proof",
        ],
    )
    run_apply(
        root,
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTING",
            "--actor",
            implementer_id,
            "--evidence",
            "simulated implementer accepted the fresh brief",
        ],
    )
    write_live_downstream_change(root)
    normalize_implementer_report(
        root,
        run_dir,
        task_id,
        implementer_id,
        files_changed=["src/feature_1_1.py"],
    )
    run_apply(
        root,
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--agent-id",
            implementer_id,
            "--status",
            "completed",
            "--actor",
            "downstream-protocol-controller",
            "--summary",
            "downstream protocol-simulation implementation completed",
            "--evidence",
            "controller observed simulated implementer completion",
        ],
    )
    run_apply(
        root,
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTED",
            "--actor",
            implementer_id,
            "--evidence",
            "simulated implementation produced a live repository change",
        ],
    )
    capture_output = run_apply(
        root,
        [
            "capture-evidence",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller captured the live downstream change set",
        ],
    )
    if not Path(parse_key(capture_output, "change_set_path")).is_file():
        fail("downstream_controller_change_set_missing")
    for command in validation_commands:
        if not isinstance(command, dict) or not isinstance(command.get("id"), str):
            fail("downstream_invalid_planned_validation_command")
        receipt_output = run_apply(
            root,
            [
                "run-validation",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--validation-id",
                str(command["id"]),
                "--actor",
                "downstream-protocol-controller",
                "--evidence",
                "controller executed the exact planned validation command",
            ],
        )
        if parse_key(receipt_output, "exit_code") != "0":
            fail(f"downstream_planned_validation_failed={command['id']}")
        assert_signed_receipt(
            Path(parse_key(receipt_output, "receipt_path")),
            "codexqb_validation_execution_receipt",
        )
    normalize_implementer_report(
        root,
        run_dir,
        task_id,
        implementer_id,
        enriched=True,
    )
    run_apply(
        root,
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "TASK_REVIEW",
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller-owned evidence is ready for simulated review phases",
        ],
    )
    complete_review_phase(
        root,
        run_dir,
        task_id,
        role="task_reviewer",
        phase="spec",
        agent_id="downstream-simulated-spec-reviewer",
    )
    complete_review_phase(
        root,
        run_dir,
        task_id,
        role="task_reviewer",
        phase="quality",
        agent_id="downstream-simulated-quality-reviewer",
    )
    if security_required:
        run_apply(
            root,
            [
                "transition",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--to",
                "SECURITY_REVIEW",
                "--actor",
                "downstream-protocol-controller",
                "--evidence",
                "quality receipt permits the simulated security review phase",
            ],
        )
        complete_review_phase(
            root,
            run_dir,
            task_id,
            role="security_reviewer",
            phase="security",
            agent_id="downstream-simulated-security-reviewer",
        )
    complete_review_phase(
        root,
        run_dir,
        task_id,
        role="final_reviewer",
        phase="final",
        agent_id="downstream-simulated-final-reviewer",
    )
    run_apply(root, ["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()])
    run_apply_expect_failure(
        root,
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "VERIFIED",
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller evidence is complete but host agent attestation is absent",
        ],
        f"trusted_verified_requires_host_agent_attestation={task_id}",
    )
    run_apply_expect_failure(
        root,
        [
            "finalize",
            "--run-dir",
            run_dir.as_posix(),
            "--actor",
            "downstream-protocol-controller",
            "--evidence",
            "controller-protocol evidence cannot substitute for host attestation",
        ],
        "finalize_requires_all_tasks_verified",
    )
    run_apply(root, ["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()])
    result = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))
    task = current_task(run_dir)
    review_receipts = task.get("review_receipts")
    if result.get("status") != "initialized" or task.get("state") == "VERIFIED":
        fail(f"downstream_apply_must_remain_unattested={result.get('status')}:{task.get('state')}")
    if not isinstance(review_receipts, dict) or "final" not in review_receipts:
        fail("downstream_signed_final_review_receipt_missing")
    final_review = json.loads((run_dir / "Final-Review.json").read_text(encoding="utf-8"))
    if final_review.get("status") != "pass":
        fail("downstream_final_review_aggregate_not_pass")


def main() -> int:
    global _CONTROLLER_TEST_HOME
    with (
        assert_real_trust_store_unchanged(),
        tempfile.TemporaryDirectory() as temp_dir,
        tempfile.TemporaryDirectory() as direct_dir,
        temporary_controller_home() as controller_home,
    ):
        root = Path(temp_dir)
        direct_root = Path(direct_dir)
        _CONTROLLER_TEST_HOME = Path(controller_home)

        write_downstream_code(direct_root)
        direct_docs = write_valid_step2_fixture(direct_root)
        adapt_validation_commands(direct_docs)
        write_audit(direct_docs, "PASS")
        direct_run_dir = drive_direct_rejection(direct_root)

        write_downstream_code(root)
        docs = write_valid_step2_fixture(root)
        adapt_validation_commands(docs)

        unit_output = run_command([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=root)
        if "FAILED" in unit_output:
            fail("downstream_unit_tests_failed")

        step2_output = run_validator(root, "step2")
        if "validation_mode=step2" not in step2_output:
            fail("step2_validator_missing_mode")
        preflight_output = run_validator(root, "step3-preflight")
        if "validation_mode=step3-preflight" not in preflight_output:
            fail("step3_preflight_missing_mode")

        write_audit(docs, "PASS")
        step3_output = run_validator(root, "step3")
        if "validation_mode=step3" not in step3_output:
            fail("step3_validator_missing_mode")
        step4_output = run_validator(root, "step4")
        if "validation_mode=step4" not in step4_output:
            fail("step4_validator_missing_mode")

        prepare_goal(root, "step2", "wave", "downstream-step2")
        prepare_goal(root, "step3", "audit", "downstream-step3")
        step4_goal_dir = prepare_goal(root, "step4", "subagent_serial", "downstream-step4")
        step4_prompt = (step4_goal_dir / "Goal-Prompt.md").read_text(encoding="utf-8")
        if "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md" not in step4_prompt:
            fail("step4_goal_missing_ready_subplan")
        if "subagent_serial" not in step4_prompt:
            fail("step4_goal_missing_subagent_mode")

        git_checkpoint(root)
        apply_run_dir = prepare_apply(root)
        drive_subagent_apply(root, apply_run_dir)

        print("downstream_goal_apply_dry_run=passed")
        print("downstream_stage_validations=step2,step3-preflight,step3,step4")
        print(
            "downstream_protocol_scope=controller-protocol simulation/dry run; "
            "not real Codex agent identity proof"
        )
        print("downstream_direct_lane=trusted_verification_and_finalize_rejected")
        print("downstream_serial_lane=controller_evidence_complete_unattested;trusted_verification_rejected")
        print(f"downstream_direct_rejection_run_id={direct_run_dir.name}")
        print(f"downstream_apply_run_id={apply_run_dir.name}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"unhandled_exception={type(exc).__name__}:{exc}")
