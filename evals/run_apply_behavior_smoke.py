#!/usr/bin/env python3
"""Exercise the apply-run controller through its public CLI.

This is a controller-protocol simulation/dry run, not proof of a real Codex
agent identity. It uses disposable repositories to prove that direct mode
cannot claim trusted verification or finalization, then drives the complete
subagent-serial receipt protocol with live changes and real local validation.
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
    print(f"apply_behavior_smoke_failed_code={code.lower()}")
    print(f"apply_behavior_smoke_failed_detail_sha256={detail_sha256}")
    raise SystemExit(1)


def subprocess_error_digest(*streams: str) -> str:
    """Commit to one bounded controller error code without logging its value."""

    candidates = {
        candidate
        for stream in streams
        for line in stream.splitlines()
        if line.startswith("error=")
        for candidate in (line.removeprefix("error="),)
        if 1 <= len(candidate) <= 128
        and candidate.isascii()
        and all(
            character.islower() or character.isdigit() or character == "_"
            for character in candidate
        )
    }
    selected = next(iter(candidates)) if len(candidates) == 1 else "unclassified"
    return hashlib.sha256(
        f"codexqb-controller-error-v1:{selected}".encode("ascii")
    ).hexdigest()


def apply_controller_command(args: list[str], *, root: Path) -> list[str]:
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


def run_apply(args: list[str], *, cwd: Path) -> str:
    completed = subprocess.run(
        apply_controller_command(args, root=cwd),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
    )
    if completed.returncode != 0:
        print(
            "apply_behavior_smoke_failed_command_error_sha256="
            f"{subprocess_error_digest(completed.stdout, completed.stderr)}"
        )
        fail(f"command_failed={' '.join(args)} stdout={completed.stdout.strip()} stderr={completed.stderr.strip()}")
    return completed.stdout


def run_apply_expect_failure(args: list[str], *, cwd: Path, expected: str) -> str:
    completed = subprocess.run(
        apply_controller_command(args, root=cwd),
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=20,
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


def write_fixture(root: Path) -> None:
    docs = write_valid_step2_fixture(root)
    subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
    subplan.write_text(
        subplan.read_text(encoding="utf-8")
        + "\n".join(
            [
                "",
                "Additional Apply smoke signals:",
                "- behavioral acceptance: smoke artifact reaches complete state.",
                "- allowed write paths: src/smoke.py",
                "- forbidden paths: .env",
                "- parent acceptance signal: PAS-SMOKE-1",
                "- depends_on: none",
                "- validation command argv: python3 -m unittest",
                "- security review: not required",
                "- algorithmic invariant: task transition order remains monotonic.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    write_audit(docs, "PASS")

    replacements = {
        "python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q": (
            "python3 -B -m unittest tests/test_feature_1_1.py"
        ),
        '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", '
        '"tests/test_feature_1_1.py", "-q"]': (
            '"argv": ["python3", "-B", "-m", "unittest", "tests/test_feature_1_1.py"]'
        ),
    }
    for path in [docs / "Sub-Planing-Index.md", *sorted(docs.glob("Faz-*-Plans/*.md"))]:
        text = path.read_text(encoding="utf-8")
        for old, new in replacements.items():
            text = text.replace(old, new)
        path.write_text(text, encoding="utf-8")


def current_task(run_dir: Path) -> dict[str, object]:
    progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
    tasks = progress.get("tasks")
    if not isinstance(tasks, list) or len(tasks) != 1 or not isinstance(tasks[0], dict):
        fail("expected_one_task")
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


def write_protocol_product_change(root: Path) -> None:
    (root / "src").mkdir(exist_ok=True)
    (root / "tests").mkdir(exist_ok=True)
    (root / "src/feature_1_1.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "tests/test_feature_1_1.py").write_text(
        "import unittest\n\n"
        "from src.feature_1_1 import VALUE\n\n\n"
        "class Feature11Tests(unittest.TestCase):\n"
        "    def test_value(self) -> None:\n"
        "        self.assertEqual(VALUE, 1)\n\n\n"
        "if __name__ == '__main__':\n"
        "    unittest.main()\n",
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
            fail("controller_evidence_references_missing")
        if not isinstance(commands, list) or len(receipts) != len(commands) or not receipts:
            fail("not_every_planned_validation_has_receipt")
        change_path = run_dir / task_id / str(change_reference.get("path", ""))
        change_set = json.loads(change_path.read_text(encoding="utf-8"))
        changed_files = change_set.get("changed_files")
        if not isinstance(changed_files, list) or not changed_files:
            fail("live_change_set_is_empty")
        report["brief_sha256"] = task.get("brief_sha256")
        report["implementation_contract_digest"] = task.get(
            "implementation_contract_digest"
        )
        report["task_contract_digest"] = task.get("task_contract_digest")
        report["files_changed"] = sorted(
            str(item.get("path")) for item in changed_files if isinstance(item, dict)
        )
        patch = (run_dir / task_id / "Review-Package.patch").read_bytes()
        report["validation_receipt_ids"] = sorted(
            str(item.get("receipt_id")) for item in receipts if isinstance(item, dict)
        )
        report["change_set_id"] = change_reference.get("change_set_id")
        report["diff_sha256"] = hashlib.sha256(patch).hexdigest()

    run_apply(
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
            "smoke-protocol-controller",
            "--evidence",
            (
                "controller normalized the receipt-enriched simulated implementer return"
                if enriched
                else "controller normalized the initial simulated implementer return"
            ),
        ],
        cwd=root,
    )


def complete_protocol_review_phase(
    root: Path,
    run_dir: Path,
    task_id: str,
    *,
    role: str,
    phase: str,
    agent_id: str,
) -> None:
    packet_output = run_apply(
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
            "smoke-protocol-controller",
            "--evidence",
            "controller-protocol simulation prepared a reviewer packet",
        ],
        cwd=root,
    )
    packet_path = Path(parse_key(packet_output, "packet_path"))
    if not packet_path.is_file():
        fail(f"review_dispatch_packet_missing={phase}")
    run_apply(
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
            "smoke-protocol-controller",
            "--evidence",
            "protocol simulation recorded reviewer spawn; this is not identity proof",
        ],
        cwd=root,
    )
    report = {
        "status": "COMPLETE",
        "phase": phase,
        "verdict": "pass",
        "task_id": task_id,
        "reviewer_agent_id": agent_id,
        "evidence": [
            "Controller-protocol simulation reviewed live change and signed validation receipts; "
            "no real Codex agent identity is claimed."
        ],
    }
    run_apply(
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
            "smoke-protocol-controller",
            "--evidence",
            "controller normalized simulated reviewer output; host completion proof is not observed",
        ],
        cwd=root,
    )
    run_apply(
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
            "smoke-protocol-controller",
            "--summary",
            f"{phase} protocol-simulation review completed",
            "--evidence",
            "controller observed the simulated reviewer lifecycle completion",
        ],
        cwd=root,
    )
    receipt_output = run_apply(
        [
            "publish-review",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--review-phase",
            phase,
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller published a signed protocol-simulation review receipt",
        ],
        cwd=root,
    )
    assert_signed_receipt(
        Path(parse_key(receipt_output, "receipt_path")),
        "codexqb_review_completion_receipt",
    )


def drive_direct_rejection(root: Path) -> Path:
    output = run_apply(
        [
            "prepare",
            "--root",
            root.as_posix(),
            "--mode",
            "direct",
            "--run-id-suffix",
            "direct-rejection-smoke",
            "--allow-non-git-unsafe",
        ],
        cwd=root,
    )
    run_dir = Path(parse_key(output, "run_dir"))
    task_id = str(current_task(run_dir).get("task_id", ""))
    run_apply(["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()], cwd=root)
    for state, actor in (
        ("IMPLEMENTING", "direct-protocol-controller"),
        ("IMPLEMENTED", "direct-protocol-controller"),
        ("TASK_REVIEW", "direct-protocol-controller"),
    ):
        run_apply(
            [
                "transition",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--to",
                state,
                "--actor",
                actor,
                "--evidence",
                "direct lane advances only to demonstrate trusted verification rejection",
            ],
            cwd=root,
        )
    run_apply_expect_failure(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "VERIFIED",
            "--actor",
            "direct-protocol-controller",
            "--evidence",
            "direct mode must not claim trusted verification",
        ],
        cwd=root,
        expected=f"verified_requires_subagent_reviewer_receipts={task_id}",
    )
    run_apply_expect_failure(
        [
            "finalize",
            "--run-dir",
            run_dir.as_posix(),
            "--actor",
            "direct-protocol-controller",
            "--evidence",
            "direct mode must not finalize without trusted verification",
        ],
        cwd=root,
        expected="finalize_requires_all_tasks_verified",
    )
    result = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))
    if result.get("status") == "complete" or current_task(run_dir).get("state") == "VERIFIED":
        fail("direct_lane_fabricated_trusted_success")
    return run_dir


def drive_subagent_protocol_simulation(root: Path) -> Path:
    output = run_apply(
        [
            "prepare",
            "--root",
            root.as_posix(),
            "--mode",
            "subagent_serial",
            "--run-id-suffix",
            "controller-protocol-smoke",
            "--allow-non-git-unsafe",
        ],
        cwd=root,
    )
    run_dir = Path(parse_key(output, "run_dir"))
    task = current_task(run_dir)
    task_id = str(task.get("task_id", ""))
    commands = task.get("validation_commands")
    if not isinstance(commands, list) or not commands:
        fail("protocol_simulation_missing_planned_validation")
    run_apply_expect_failure(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTING",
            "--actor",
            "smoke-simulated-implementer",
            "--evidence",
            "missing dispatch must fail",
        ],
        cwd=root,
        expected=f"subagent_dispatch_packet_missing={task_id}",
    )
    packet_output = run_apply(
        [
            "dispatch",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller-protocol simulation prepared an implementer packet",
        ],
        cwd=root,
    )
    packet = json.loads(Path(parse_key(packet_output, "packet_path")).read_text(encoding="utf-8"))
    if packet.get("spawn_tool") != "multi_agent_v1.spawn_agent":
        fail("protocol_dispatch_packet_missing_spawn_tool")
    if packet.get("spawn_request", {}).get("fork_context") is not False:
        fail("protocol_dispatch_packet_not_fresh_context")
    run_apply_expect_failure(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTING",
            "--actor",
            "smoke-simulated-implementer",
            "--evidence",
            "missing spawn observation must fail",
        ],
        cwd=root,
        expected=f"subagent_dispatch_spawn_required={task_id}",
    )
    run_apply(
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--agent-id",
            "smoke-simulated-implementer",
            "--status",
            "spawned",
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "protocol simulation recorded implementer spawn; this is not identity proof",
        ],
        cwd=root,
    )
    run_apply(["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()], cwd=root)
    run_apply(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTING",
            "--actor",
            "smoke-simulated-implementer",
            "--evidence",
            "simulated implementer accepted the isolated brief",
        ],
        cwd=root,
    )
    write_protocol_product_change(root)
    run_apply_expect_failure(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTED",
            "--actor",
            "smoke-simulated-implementer",
            "--evidence",
            "missing completion observation must fail",
        ],
        cwd=root,
        expected=f"subagent_dispatch_completion_required={task_id}",
    )
    normalize_implementer_report(
        root,
        run_dir,
        task_id,
        "smoke-simulated-implementer",
        files_changed=["src/feature_1_1.py", "tests/test_feature_1_1.py"],
    )
    run_apply(
        [
            "record-agent",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--agent-id",
            "smoke-simulated-implementer",
            "--status",
            "completed",
            "--actor",
            "smoke-protocol-controller",
            "--summary",
            "protocol-simulation implementation completed",
            "--evidence",
            "controller observed simulated implementer completion",
        ],
        cwd=root,
    )
    run_apply(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "IMPLEMENTED",
            "--actor",
            "smoke-simulated-implementer",
            "--evidence",
            "simulated implementation produced a live repository change",
        ],
        cwd=root,
    )
    capture_output = run_apply(
        [
            "capture-evidence",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller captured the live change set",
        ],
        cwd=root,
    )
    if not Path(parse_key(capture_output, "change_set_path")).is_file():
        fail("controller_change_set_missing")
    for command in commands:
        if not isinstance(command, dict) or not isinstance(command.get("id"), str):
            fail("invalid_planned_validation_command")
        receipt_output = run_apply(
            [
                "run-validation",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--validation-id",
                str(command["id"]),
                "--actor",
                "smoke-protocol-controller",
                "--evidence",
                "controller executed the exact planned validation command",
            ],
            cwd=root,
        )
        if parse_key(receipt_output, "exit_code") != "0":
            fail(f"planned_validation_failed={command['id']}")
        assert_signed_receipt(
            Path(parse_key(receipt_output, "receipt_path")),
            "codexqb_validation_execution_receipt",
        )
    normalize_implementer_report(
        root,
        run_dir,
        task_id,
        "smoke-simulated-implementer",
        enriched=True,
    )
    run_apply(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "TASK_REVIEW",
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller-owned evidence is ready for simulated review phases",
        ],
        cwd=root,
    )
    complete_protocol_review_phase(
        root,
        run_dir,
        task_id,
        role="task_reviewer",
        phase="spec",
        agent_id="smoke-simulated-spec-reviewer",
    )
    complete_protocol_review_phase(
        root,
        run_dir,
        task_id,
        role="task_reviewer",
        phase="quality",
        agent_id="smoke-simulated-quality-reviewer",
    )
    if task.get("security_review_required") is True:
        run_apply(
            [
                "transition",
                "--run-dir",
                run_dir.as_posix(),
                "--task-id",
                task_id,
                "--to",
                "SECURITY_REVIEW",
                "--actor",
                "smoke-protocol-controller",
                "--evidence",
                "quality receipt permits the simulated security phase",
            ],
            cwd=root,
        )
        complete_protocol_review_phase(
            root,
            run_dir,
            task_id,
            role="security_reviewer",
            phase="security",
            agent_id="smoke-simulated-security-reviewer",
        )
    complete_protocol_review_phase(
        root,
        run_dir,
        task_id,
        role="final_reviewer",
        phase="final",
        agent_id="smoke-simulated-final-reviewer",
    )
    run_apply(["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()], cwd=root)
    run_apply_expect_failure(
        [
            "transition",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--to",
            "VERIFIED",
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller evidence is complete but host agent attestation is absent",
        ],
        cwd=root,
        expected=f"trusted_verified_requires_host_agent_attestation={task_id}",
    )
    run_apply_expect_failure(
        [
            "finalize",
            "--run-dir",
            run_dir.as_posix(),
            "--actor",
            "smoke-protocol-controller",
            "--evidence",
            "controller-protocol evidence cannot substitute for host attestation",
        ],
        cwd=root,
        expected="finalize_requires_all_tasks_verified",
    )
    run_apply(["validate", "--run-dir", run_dir.as_posix(), "--root", root.as_posix()], cwd=root)
    result = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))
    task = current_task(run_dir)
    review_receipts = task.get("review_receipts")
    if result.get("status") != "initialized" or task.get("state") == "VERIFIED":
        fail(f"protocol_simulation_must_remain_unattested={result.get('status')}:{task.get('state')}")
    if not isinstance(review_receipts, dict) or "final" not in review_receipts:
        fail("signed_final_review_receipt_missing")
    final_review = json.loads((run_dir / "Final-Review.json").read_text(encoding="utf-8"))
    if final_review.get("status") != "pass":
        fail("controller_final_review_aggregate_not_pass")
    events = [
        json.loads(line)
        for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    if [event.get("sequence") for event in events] != list(range(1, len(events) + 1)):
        fail("non_contiguous_event_sequence")
    if events[-1].get("event_type") == "apply_run_finalized":
        fail("unattested_protocol_published_finalize_event")
    return run_dir


def main() -> int:
    global _CONTROLLER_TEST_HOME
    with (
        assert_real_trust_store_unchanged(),
        temporary_controller_home() as controller_home,
        tempfile.TemporaryDirectory(
            prefix=".codexqb-behavior-workspaces-",
            dir=REPO_ROOT.parent,
        ) as workspace_dir,
    ):
        _CONTROLLER_TEST_HOME = Path(controller_home)
        workspace_root = Path(workspace_dir)
        direct_root = workspace_root / "direct"
        protocol_root = workspace_root / "protocol"
        outside_root = workspace_root / "outside"
        workspace_root.chmod(0o700)
        for root in (direct_root, protocol_root, outside_root):
            root.mkdir(mode=0o700)
        write_fixture(direct_root)
        write_fixture(protocol_root)

        drive_direct_rejection(direct_root)
        drive_subagent_protocol_simulation(protocol_root)
        root = direct_root

        recovery_output = run_apply(
            [
                "prepare",
                "--root",
                root.as_posix(),
                "--mode",
                "direct",
                "--run-id-suffix",
                "recovery-smoke",
                "--allow-non-git-unsafe",
            ],
            cwd=root,
        )
        recovery_run_dir = Path(parse_key(recovery_output, "run_dir"))
        recovery_progress = json.loads((recovery_run_dir / "Progress.json").read_text(encoding="utf-8"))
        recovery_task = recovery_progress["tasks"][0]
        recovery_task_id = recovery_task["task_id"]
        run_apply(
            [
                "transition",
                "--run-dir",
                recovery_run_dir.as_posix(),
                "--task-id",
                recovery_task_id,
                "--to",
                "IMPLEMENTING",
                "--actor",
                "stale-impl",
                "--evidence",
                "behavior smoke starts stale lock scenario",
            ],
            cwd=root,
        )
        lock_path = recovery_run_dir / "Writer-Lock.json"
        stale_lock = json.loads(lock_path.read_text(encoding="utf-8"))
        stale_lock["acquired_at"] = "2000-01-01T00:00:00Z"
        lock_path.write_text(json.dumps(stale_lock, sort_keys=True), encoding="utf-8")
        recovery_progress = json.loads((recovery_run_dir / "Progress.json").read_text(encoding="utf-8"))
        recovery_progress["active_writer_locks"] = [stale_lock]
        recovery_progress["tasks"][0]["writer_lock"] = stale_lock
        (recovery_run_dir / "Progress.json").write_text(
            json.dumps(recovery_progress, sort_keys=True),
            encoding="utf-8",
        )
        run_apply_expect_failure(
            ["validate", "--run-dir", recovery_run_dir.as_posix(), "--root", root.as_posix()],
            cwd=root,
            expected=f"writer_lock_expired={recovery_task_id}",
        )
        run_apply(
            [
                "recover-lock",
                "--run-dir",
                recovery_run_dir.as_posix(),
                "--task-id",
                recovery_task_id,
                "--to",
                "NEEDS_CONTEXT",
                "--actor",
                "smoke-controller",
                "--evidence",
                "behavior smoke recovered expired writer lock",
            ],
            cwd=root,
        )
        run_apply(["validate", "--run-dir", recovery_run_dir.as_posix(), "--root", root.as_posix()], cwd=root)
        recovery_progress = json.loads((recovery_run_dir / "Progress.json").read_text(encoding="utf-8"))
        if recovery_progress["tasks"][0]["state"] != "NEEDS_CONTEXT":
            fail("recovery_state_not_needs_context")
        if lock_path.exists():
            fail("recovery_left_writer_lock_file")

        hostile_output = run_apply(
            [
                "prepare",
                "--root",
                root.as_posix(),
                "--mode",
                "direct",
                "--run-id-suffix",
                "events-symlink-smoke",
                "--allow-non-git-unsafe",
            ],
            cwd=root,
        )
        hostile_run_dir = Path(parse_key(hostile_output, "run_dir"))
        hostile_progress_path = hostile_run_dir / "Progress.json"
        hostile_progress_before = hostile_progress_path.read_bytes()
        hostile_progress = json.loads(hostile_progress_before)
        hostile_task_id = hostile_progress["tasks"][0]["task_id"]
        victim_content = "external event victim must remain unchanged\n"
        victim_path = outside_root / "events-victim.jsonl"
        victim_path.write_text(victim_content, encoding="utf-8")
        hostile_events_path = hostile_run_dir / "Events.jsonl"
        hostile_events_path.unlink()
        hostile_events_path.symlink_to(victim_path)
        run_apply_expect_failure(
            [
                "transition",
                "--run-dir",
                hostile_run_dir.as_posix(),
                "--task-id",
                hostile_task_id,
                "--to",
                "BLOCKED",
                "--actor",
                "smoke-controller",
                "--evidence",
                "external Events symlink must fail closed",
            ],
            cwd=root,
            expected="apply_run_provenance_unverified",
        )
        if victim_path.read_text(encoding="utf-8") != victim_content:
            fail("events_symlink_modified_external_victim")
        if hostile_progress_path.read_bytes() != hostile_progress_before:
            fail("events_symlink_failure_mutated_progress")
        if not hostile_events_path.is_symlink():
            fail("events_symlink_failure_replaced_link")

    print("apply_behavior_smoke=passed")
    print(
        "apply_behavior_protocol_scope=controller-protocol simulation/dry run; "
        "not real Codex agent identity proof"
    )
    print("apply_behavior_direct_lane=trusted_verification_and_finalize_rejected")
    print("apply_behavior_serial_lane=controller_evidence_complete_unattested;trusted_verification_rejected")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"unhandled_exception={type(exc).__name__}:{exc}")
