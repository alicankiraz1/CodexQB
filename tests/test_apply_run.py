from __future__ import annotations

import importlib.util
import io
import json
import multiprocessing
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from tests.controller_test_support import (
    controller_cli_command,
    real_trust_store_snapshot,
)
from tests.held_runtime_test_support import held_runtime_test_provider
from tests.test_validate_planner_docs import write_audit, write_ledger, write_valid_step2_fixture


REPO_ROOT = Path(__file__).resolve().parents[1]
APPLY_RUN = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/apply_run.py"


def load_apply_module():
    spec = importlib.util.spec_from_file_location("codexqb_apply_run", APPLY_RUN)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load apply_run from {APPLY_RUN}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


APPLY_MODULE = load_apply_module()
EXECUTION_MODULE = sys.modules["execution_controller"]
CONTROLLER_STORE_MODULE = sys.modules["controller_store"]
SAFETY_MODULE = sys.modules["safety_contracts"]
SAFE_TEST_HOME_PARENT = Path(
    CONTROLLER_STORE_MODULE.pwd.getpwuid(
        CONTROLLER_STORE_MODULE.controller_effective_uid()
    ).pw_dir
).resolve()
VALIDATION_OUTPUT_SHA256 = APPLY_MODULE.sha256_bytes(b"validation passed\n")


def temporary_safe_home() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(
        prefix=".codexqb-test-home-",
        dir=SAFE_TEST_HOME_PARENT,
    )


def append_event_worker(root: str, run_dir: str, index: int, barrier) -> None:
    barrier.wait()
    APPLY_MODULE.append_event(
        Path(run_dir),
        {"event_type": "parallel_probe", "actor": f"worker-{index}"},
        root=Path(root),
    )


def serialize_rechained_events(events: list[dict[str, object]]) -> str:
    """Recompute the public unkeyed chain so deeper receipt bindings are exercised."""

    previous = APPLY_MODULE.EVENT_CHAIN_GENESIS_SHA256
    lines: list[str] = []
    for sequence, source in enumerate(events, start=1):
        event = dict(source)
        event["event_chain_version"] = APPLY_MODULE.EVENT_CHAIN_VERSION
        event["sequence"] = sequence
        event["previous_event_sha256"] = previous
        event.pop("event_sha256", None)
        event["event_sha256"] = APPLY_MODULE.canonical_json_digest(event)
        previous = str(event["event_sha256"])
        lines.append(json.dumps(event, sort_keys=True) + "\n")
    return "".join(lines)


def serialize_rehashed_events(events: list[dict[str, object]]) -> str:
    """Rehash a chain while preserving intentionally malformed core fields."""

    previous = APPLY_MODULE.EVENT_CHAIN_GENESIS_SHA256
    lines: list[str] = []
    for source in events:
        event = dict(source)
        event["previous_event_sha256"] = previous
        event.pop("event_sha256", None)
        event["event_sha256"] = APPLY_MODULE.canonical_json_digest(event)
        previous = str(event["event_sha256"])
        lines.append(json.dumps(event, sort_keys=True) + "\n")
    return "".join(lines)


class ApplyRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._real_trust_store_before_class = real_trust_store_snapshot()
        cls._home_directory = temporary_safe_home()
        cls._home_path = Path(cls._home_directory.name).resolve()
        os.chmod(cls._home_path, 0o700)
        cls._controller_store_module = CONTROLLER_STORE_MODULE
        cls._home_provider = mock.patch.object(
            cls._controller_store_module,
            "controller_home_directory",
            return_value=cls._home_path,
        )
        cls._home_provider.start()
        cls._held_runtime_provider = held_runtime_test_provider()
        cls._held_runtime_provider.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._held_runtime_provider.__exit__(None, None, None)
            cls._home_provider.stop()
            cls._home_directory.cleanup()
            if real_trust_store_snapshot() != cls._real_trust_store_before_class:
                raise AssertionError("real_controller_trust_store_changed_during_apply_tests")
        finally:
            super().tearDownClass()

    def setUp(self) -> None:
        self._real_trust_store_before_test = real_trust_store_snapshot()

    def tearDown(self) -> None:
        if real_trust_store_snapshot() != self._real_trust_store_before_test:
            raise AssertionError("real_controller_trust_store_changed_during_apply_test")

    def test_stdin_request_keeps_agent_report_out_of_shell_and_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "SHELL_MARKER"
            hostile = "reviewer's note'; touch SHELL_MARKER; #"
            report = json.dumps(
                {
                    "status": "DONE",
                    "task_id": "TASK-001",
                    "implementer_agent_id": "agent-001",
                    "files_changed": [hostile],
                    "concerns": [],
                },
                sort_keys=True,
            )
            request = json.dumps(
                {
                    "schema": "codexqb.controller-argv/v1",
                    "argv": [
                        "normalize-writer",
                        "--root",
                        ".",
                        "--run-dir",
                        "missing-run",
                        "--task-id",
                        "TASK-001",
                        "--role",
                        "implementer",
                        "--agent-id",
                        "agent-001",
                        "--report-json",
                        report,
                        "--actor",
                        "controller",
                    ],
                },
                sort_keys=True,
            )
            completed = subprocess.run(
                controller_cli_command(
                    "apply", self._home_path, ["request-stdin"]
                ),
                cwd=root,
                input=request,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertFalse(marker.exists())
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                completed.stderr,
                "apply_run_status=failed\nerror=controller_request_failed\n",
            )
            self.assertNotIn(hostile, completed.stderr)
            self.assertNotIn(request, completed.stderr)

    def test_stdin_request_rejects_duplicate_recursive_and_oversize_envelopes(self) -> None:
        cases = (
            '{"schema":"codexqb.controller-argv/v1","schema":"duplicate","argv":[]}',
            json.dumps(
                {
                    "schema": "codexqb.controller-argv/v1",
                    "argv": ["request-stdin"],
                }
            ),
            "x" * (APPLY_MODULE.MAX_CONTROLLER_STDIN_REQUEST_BYTES + 1),
        )
        for request in cases:
            with self.subTest(prefix=request[:24]), tempfile.TemporaryDirectory() as temp_dir:
                completed = subprocess.run(
                    controller_cli_command(
                        "apply", self._home_path, ["request-stdin"]
                    ),
                    cwd=temp_dir,
                    input=request,
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertEqual(
                    completed.stderr,
                    "apply_run_status=failed\nerror=controller_request_rejected\n",
                )
                self.assertNotIn(request[:128], completed.stderr)

    def write_apply_fixture(self, root: Path) -> None:
        docs = write_valid_step2_fixture(root)
        subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
        subplan.write_text(
            subplan.read_text(encoding="utf-8")
            + "\n".join(
                [
                    "",
                    "Additional Apply fresh-context signals:",
                    "- behavioral acceptance: API returns durable state.",
                    "- allowed write paths: src/example.py",
                    "- forbidden paths: .env",
                    "- parent acceptance signal: PAS-1",
                    "- depends_on: none",
                    "- validation command argv: python3 -m unittest",
                    "- security review: not required",
                    "- algorithmic invariant: state transition order remains monotonic.",
                    "",
                ]
            ),
            encoding="utf-8",
        )
        write_audit(docs, "PASS")

    def test_create_apply_run_rejects_group_writable_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            root.mkdir()
            root.chmod(0o777)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_owner_controlled_root_failed",
                ):
                    self.create_apply_run(root, "subagent_serial")
            finally:
                root.chmod(0o700)

    def write_no_action_fixture(self, root: Path) -> None:
        docs = write_valid_step2_fixture(root)
        write_audit(
            docs,
            "PASS",
            readiness_rows=[
                "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                "|---|---|---|---|---|---|",
                "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | COMPLETE | none | satisfied | Already verified. | none |",
                "| Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | SUPERSEDED | none | satisfied | Replaced by later plan. | none |",
            ],
        )

    def init_git_repo(self, root: Path) -> None:
        subprocess.run(["git", "init"], cwd=root, check=True, capture_output=True, text=True)

    def create_apply_run(self, root: Path, mode: str, *args, **kwargs) -> dict[str, object]:
        kwargs.setdefault("allow_non_git_unsafe", True)
        kwargs.setdefault("allow_unverified_git_worktree", True)
        return APPLY_MODULE.create_apply_run(root, mode, *args, **kwargs)

    def first_task_id(self, run_dir: Path) -> str:
        progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
        return progress["tasks"][0]["task_id"]

    def mark_task_verified(
        self,
        root: Path,
        run_dir: Path,
        security: str = "not_required",
    ) -> None:
        """Write an intentionally untrusted VERIFIED claim for negative tests."""

        progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
        task = progress["tasks"][0]
        task_id = task["task_id"]
        security_verdict = "pass" if security == "pass" or task.get("security_review_required") is True else security
        task["state"] = "VERIFIED"
        task["security_review_required"] = security_verdict == "pass"
        task["writer_lock"] = None
        progress["active_writer_locks"] = []
        progress["verified_task_ids"] = [task_id]
        (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
        chain = [
            ("BRIEFED", "IMPLEMENTING"),
            ("IMPLEMENTING", "IMPLEMENTED"),
            ("IMPLEMENTED", "TASK_REVIEW"),
        ]
        if security_verdict == "pass":
            chain.extend([("TASK_REVIEW", "SECURITY_REVIEW"), ("SECURITY_REVIEW", "VERIFIED")])
        else:
            chain.append(("TASK_REVIEW", "VERIFIED"))
        for from_state, to_state in chain:
            APPLY_MODULE.append_event(
                run_dir,
                {
                    "event_type": "task_transition",
                    "task_id": task_id,
                    "from": from_state,
                    "to": to_state,
                    "actor": "untrusted-test-claim",
                    "evidence": ["synthetic negative fixture"],
                    "writer_lock": None,
                },
            root=root,
            )
        brief_hash = task["brief_sha256"]
        patch = "\n".join(
            [
                "diff --git a/src/feature_1_1.py b/src/feature_1_1.py",
                "--- a/src/feature_1_1.py",
                "+++ b/src/feature_1_1.py",
                "@@ -0,0 +1 @@",
                "+VALUE = 1",
                "",
            ]
        )
        patch_sha = APPLY_MODULE.sha256_bytes(patch.encode("utf-8"))
        (run_dir / task_id / "Review-Package.patch").write_text(patch, encoding="utf-8")
        validation_evidence = [
            {**command, "exit_code": 0, "output_sha256": VALIDATION_OUTPUT_SHA256}
            for command in task.get("validation_commands", [])
            if isinstance(command, dict)
        ]
        (run_dir / task_id / "Implementer-Report.json").write_text(
            json.dumps(
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "brief_sha256": brief_hash,
                    "implementation_contract_digest": task.get("implementation_contract_digest"),
                    "task_contract_digest": task.get("task_contract_digest"),
                    "implementer_agent_id": "impl-1",
                    "files_changed": ["src/feature_1_1.py"],
                    "validation_evidence": validation_evidence,
                    "diff_sha256": patch_sha,
                }
            ),
            encoding="utf-8",
        )
        task_review = {
            "task_id": task_id,
            "brief_sha256": brief_hash,
            "implementation_contract_digest": task.get("implementation_contract_digest"),
            "task_contract_digest": task.get("task_contract_digest"),
            "reviewer_agent_id": "review-1",
            "spec_compliance": "pass",
            "task_quality": "approved",
            "security_review": security_verdict,
            "evidence": ["reviewed diff and validation evidence"],
        }
        if security_verdict == "pass":
            task_review["security_reviewer_agent_id"] = "security-review-1"
        (run_dir / task_id / "Task-Review.json").write_text(json.dumps(task_review), encoding="utf-8")
        (run_dir / "Final-Review.json").write_text(
            json.dumps(
                {
                    "status": "pass",
                    "reviewed_task_ids": [task_id],
                    "global_validations": validation_evidence,
                    "evidence": ["repo gate passed"],
                }
            ),
            encoding="utf-8",
        )

    def complete_subagent_serial_verification(
        self,
        root: Path,
        run_dir: Path,
        *,
        stop_before_reviews: bool = False,
        stop_after_quality: bool = False,
        transition_verified: bool = False,
    ) -> None:
        """Simulate controller evidence collection with real local command execution."""

        run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
        self.assertEqual(run["mode"], "subagent_serial")
        progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
        task = progress["tasks"][0]
        task_id = task["task_id"]

        APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
        APPLY_MODULE.record_agent_status(
            run_dir, task_id, "implementer", "impl-1", "spawned", "controller",
            root=root
        )
        APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", root=root)
        (root / "src").mkdir(exist_ok=True)
        (root / "tests").mkdir(exist_ok=True)
        (root / "src" / "feature_1_1.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "tests" / "test_feature_1_1.py").write_text(
            "from src.feature_1_1 import VALUE\n\n"
            "def test_value():\n"
            "    assert VALUE == 1\n",
            encoding="utf-8",
        )
        APPLY_MODULE.normalize_writer_report(
            run_dir,
            task_id,
            "implementer",
            "impl-1",
            {
                "status": "DONE",
                "task_id": task_id,
                "implementer_agent_id": "impl-1",
                "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                "concerns": [],
            },
            "controller",
        root=root,
        )
        APPLY_MODULE.record_agent_status(
            run_dir,
            task_id,
            "implementer",
            "impl-1",
            "completed",
            "controller",
            summary="implementation complete",
        root=root,
        )
        APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "impl-1", root=root)
        APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)

        with tempfile.TemporaryDirectory() as command_bin:
            python_link = Path(command_bin) / "python3"
            python_link.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            python_link.chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{command_bin}:{os.environ.get('PATH', '')}"}):
                progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
                for command in progress["tasks"][0]["validation_commands"]:
                    receipt = APPLY_MODULE.execute_planned_validation(
                        run_dir, task_id, command["id"], "controller",
                        root=root
                    )
                    self.assertEqual(receipt["exit_code"], 0)

        progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
        task = progress["tasks"][0]
        patch = (run_dir / task_id / "Review-Package.patch").read_text(encoding="utf-8")
        receipt_ids = sorted(item["receipt_id"] for item in task["validation_receipts"])
        APPLY_MODULE.normalize_writer_report(
            run_dir,
            task_id,
            "implementer",
            "impl-1",
            {
                "status": "DONE",
                "task_id": task_id,
                "brief_sha256": task["brief_sha256"],
                "implementation_contract_digest": task["implementation_contract_digest"],
                "task_contract_digest": task["task_contract_digest"],
                "implementer_agent_id": "impl-1",
                "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                "concerns": [],
                "validation_receipt_ids": receipt_ids,
                "change_set_id": task["change_set"]["change_set_id"],
                "diff_sha256": APPLY_MODULE.sha256_bytes(patch.encode("utf-8")),
            },
            "controller",
        root=root,
        )
        APPLY_MODULE.transition_task_state(run_dir, task_id, "TASK_REVIEW", "controller", root=root)
        if stop_before_reviews:
            return

        def complete_review(role: str, phase: str, agent_id: str) -> None:
            APPLY_MODULE.prepare_dispatch_packet(
                run_dir, task_id, role, "controller", review_phase=phase,
                root=root
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                role,
                agent_id,
                "spawned",
                "controller",
                review_phase=phase,
            root=root,
            )
            APPLY_MODULE.normalize_review_report(
                run_dir,
                task_id,
                phase,
                agent_id,
                {
                    "status": "COMPLETE",
                    "phase": phase,
                    "verdict": "pass",
                    "task_id": task_id,
                    "reviewer_agent_id": agent_id,
                    "evidence": [f"{phase} review completed"],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                role,
                agent_id,
                "completed",
                "controller",
                summary=f"{phase} review complete",
                review_phase=phase,
            root=root,
            )
            APPLY_MODULE.publish_review_completion(run_dir, task_id, phase, "controller", root=root)

        complete_review("task_reviewer", "spec", "spec-review-1")
        complete_review("task_reviewer", "quality", "quality-review-1")
        if stop_after_quality:
            return
        if task.get("security_review_required") is True:
            APPLY_MODULE.transition_task_state(run_dir, task_id, "SECURITY_REVIEW", "controller", root=root)
            complete_review("security_reviewer", "security", "security-review-1")
        complete_review("final_reviewer", "final", "final-review-1")
        if transition_verified:
            APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "controller", root=root)

    def prepare_task_for_validation(
        self,
        root: Path,
        test_source: str,
    ) -> tuple[Path, str]:
        run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
        task_id = self.first_task_id(run_dir)
        APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
        APPLY_MODULE.record_agent_status(
            run_dir, task_id, "implementer", "validation-impl", "spawned", "controller",
            root=root
        )
        APPLY_MODULE.transition_task_state(
            run_dir, task_id, "IMPLEMENTING", "validation-impl",
            root=root
        )
        (root / "src").mkdir(exist_ok=True)
        (root / "tests").mkdir(exist_ok=True)
        (root / "src" / "feature_1_1.py").write_text("VALUE = 1\n", encoding="utf-8")
        (root / "tests" / "test_feature_1_1.py").write_text(test_source, encoding="utf-8")
        APPLY_MODULE.normalize_writer_report(
            run_dir,
            task_id,
            "implementer",
            "validation-impl",
            {
                "status": "DONE",
                "task_id": task_id,
                "implementer_agent_id": "validation-impl",
                "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                "concerns": [],
            },
            "controller",
        root=root,
        )
        APPLY_MODULE.record_agent_status(
            run_dir,
            task_id,
            "implementer",
            "validation-impl",
            "completed",
            "controller",
        root=root,
        )
        APPLY_MODULE.transition_task_state(
            run_dir, task_id, "IMPLEMENTED", "validation-impl",
            root=root
        )
        APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)
        return run_dir, task_id

    def test_init_subagent_serial_creates_safe_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)

            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])

            self.assertTrue((run_dir / "Apply-Run.json").is_file())
            self.assertTrue((run_dir / "Progress.json").is_file())
            self.assertTrue((run_dir / "Final-Review.json").is_file())
            self.assertTrue((run_dir / "Result.json").is_file())
            task_id = self.first_task_id(run_dir)
            self.assertRegex(task_id, r"^AR-apply-subagent_serial-[A-Za-z0-9_.-]+-T001$")
            self.assertTrue((run_dir / task_id / "Brief.md").is_file())
            self.assertTrue((run_dir / task_id / "Implementer-Report.json").is_file())
            self.assertTrue((run_dir / task_id / "Review-Package.patch").is_file())
            self.assertTrue((run_dir / task_id / "Task-Review.json").is_file())
            self.assertTrue((run_dir / task_id / "Fix-Report.json").is_file())
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["apply_run_schema_version"], APPLY_MODULE.APPLY_RUN_SCHEMA_VERSION)
            self.assertEqual(run["mode"], "subagent_serial")
            self.assertIn("apply_policy_digest", run)
            self.assertEqual(run["commit_policy"], "none")
            self.assertFalse(run["push_allowed"])
            self.assertFalse(run["pr_allowed"])
            self.assertEqual(run["max_writer_agents"], 1)
            self.assertEqual(run["max_subagent_depth"], 1)
            self.assertEqual(run["budget_contract"]["max_selected_tasks"], 4)

            self.assertEqual(run["budget_contract"]["max_agent_attempts_per_role"], 2)
            self.assertEqual(run["budget_contract"]["max_fix_cycles"], 2)
            self.assertEqual(run["token_usage"]["status"], "not_observed")
            self.assertEqual(run["workspace_mode"], "non_git_unsafe")
            self.assertTrue(run["user_approval"])
            self.assertEqual(run["worktree_path"], ".")
            self.assertEqual(run["working_branch"], "unknown")
            self.assertEqual(run["dirty_state"], "non_git")
            self.assertEqual(run["workspace_baseline"]["vcs"], "non_git")
            self.assertIn("git_status_porcelain_sha256", run["workspace_baseline"])
            self.assertIn("untracked_inventory_sha256", run["workspace_baseline"])
            self.assertIn("workspace_file_inventory_sha256", run["workspace_baseline"])
            self.assertEqual(run["agent_profiles"]["implementer"]["model_profile"], "balanced")
            self.assertEqual(run["agent_profiles"]["task_reviewer"]["sandbox"], "read-only")
            self.assertEqual(run["agent_profiles"]["security_reviewer"]["model_profile"], "security_strong")
            self.assertFalse(run["safety"]["executes_implementation"])
            self.assertFalse(run["safety"]["allows_commit_push_pr_deploy"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(
                progress["tasks"][0]["source_subplan_path"],
                "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md",
            )
            contract = progress["tasks"][0]["fresh_context_contract"]
            self.assertTrue(any("behavioral acceptance" in item for item in contract["acceptance_criteria"]))
            self.assertTrue(any("allowed write paths" in item for item in contract["allowed_paths"]))
            self.assertTrue(any("validation command argv" in item for item in contract["structured_validation_commands"]))
            self.assertTrue(progress["tasks"][0]["security_review_required"])
            self.assertEqual(progress["tasks"][0]["finding_ids"], [])
            self.assertEqual(progress["tasks"][0]["dependency_state"], "independent")
            implementation_contract = progress["tasks"][0]["implementation_contract"]
            self.assertEqual(implementation_contract["contract_version"], 1)
            self.assertEqual(implementation_contract["parent_signals"], ["MP-PH1-AS-01"])
            self.assertEqual(implementation_contract["outputs"], ["reports/faz1-1-readiness.md"])
            self.assertEqual(
                implementation_contract["dependencies"]["activation_conditions"],
                ["local fixture files exist"],
            )
            self.assertEqual(implementation_contract["implementation_paths"][0]["path"], "src/feature_1_1.py")
            self.assertEqual(progress["tasks"][0]["validation_commands"][0]["id"], "VAL-01")
            self.assertEqual(
                progress["tasks"][0]["validation_commands"][0]["argv"],
                ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"],
            )
            self.assertEqual(progress["tasks"][0]["validation_command_ids"], ["VAL-01"])
            brief = (run_dir / task_id / "Brief.md").read_text(encoding="utf-8")
            self.assertIn("Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", brief)
            self.assertIn("fresh_context_contract", brief)
            self.assertIn("implementation_contract", brief)
            self.assertIn('"outputs":["reports/faz1-1-readiness.md"]', brief)
            self.assertIn("security_review_required: true", brief)
            self.assertIn("validation_command_ids: VAL-01", brief)
            self.assertIn('"id":"VAL-01"', brief)
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_apply_model_facing_repository_evidence_is_projected_before_artifacts(self) -> None:
        fixture = "sk-" + "Q" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
            audit.write_text(
                audit.read_text(encoding="utf-8").replace(
                    "| none | independent | Contract complete",
                    f"| none | dependency-{fixture} | Contract complete",
                    1,
                ),
                encoding="utf-8",
            )
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            subplan.write_text(
                subplan.read_text(encoding="utf-8")
                + f"\n- security requirement: credential {fixture}\n",
                encoding="utf-8",
            )
            audiences: list[tuple[str, object]] = []
            original = APPLY_MODULE.RepositoryIO.read_text

            def audited_read_text(repository, path, **kwargs):
                audiences.append((str(path), kwargs.get("audience")))
                return original(repository, path, **kwargs)

            validation = {
                "validator_status": "passed",
                "execution_queue_state": "READY",
                "validator_output_sha256": "a" * 64,
            }
            with (
                mock.patch.object(
                    APPLY_MODULE.RepositoryIO,
                    "read_text",
                    new=audited_read_text,
                ),
                mock.patch.object(
                    APPLY_MODULE,
                    "validate_step4_queue",
                    return_value=validation,
                ),
            ):
                result = self.create_apply_run(
                    root,
                    "subagent_serial",
                    run_id_suffix="model-projection",
                )

            run_dir = Path(result["run_dir"])
            rendered = b"\n".join(
                path.read_bytes()
                for path in sorted(run_dir.rglob("*"))
                if path.is_file()
            ).decode("utf-8")
            self.assertNotIn(fixture, rendered)
            self.assertIn("<redacted:openai_api_key>", rendered)
            self.assertTrue(
                any(
                    path.endswith("Sub-Planing-Audit.md") and audience == "model"
                    for path, audience in audiences
                )
            )
            self.assertTrue(
                any(
                    path.endswith("Faz1.1-local-contract.md") and audience == "model"
                    for path, audience in audiences
                )
            )

    def test_model_projection_cannot_create_readiness_or_contract_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            audit = root / "Planner-docs" / "Sub-Planing-Audit.md"
            audit.write_text(
                audit.read_text(encoding="utf-8").replace(
                    " | READY | ", " | R&#69;ADY | ", 1
                ),
                encoding="utf-8",
            )
            with APPLY_MODULE.open_repository_io(root) as repository:
                internal = APPLY_MODULE.repository_internal_text(
                    root,
                    "Planner-docs/Sub-Planing-Audit.md",
                    required=True,
                    repository=repository,
                )
                projected = APPLY_MODULE.repository_model_text(
                    root,
                    "Planner-docs/Sub-Planing-Audit.md",
                    required=True,
                    repository=repository,
                )
                self.assertIn("R&#69;ADY", internal or "")
                self.assertNotIn("R&#69;ADY", projected or "")
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_model_projection_semantic_mismatch",
                ):
                    APPLY_MODULE.extract_ready_queue(root, repository)

            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            subplan.write_text(
                subplan.read_text(encoding="utf-8").replace(
                    '"contract_version"',
                    "&#34;contract_version&#34;",
                    1,
                ),
                encoding="utf-8",
            )
            with APPLY_MODULE.open_repository_io(root) as repository:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_model_projection_semantic_mismatch",
                ):
                    APPLY_MODULE.repository_contract_binding(
                        root,
                        "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md",
                        repository=repository,
                    )

    def test_apply_rejects_policy_envelope_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            run_path = run_dir / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["workspace_verified"] = True
            run["worktree_path"] = "../../outside"
            run["step4_readiness"]["validator_status"] = "failed"
            run["step4_readiness"]["validator_output_sha256"] = "0" * 64
            run["safety"]["allows_commit_push_pr_deploy"] = True
            run["budget_contract"]["max_selected_tasks"] = 3
            run["apply_policy_digest"] = APPLY_MODULE.canonical_json_digest(
                {
                    "workspace_verified": run["workspace_verified"],
                    "worktree_path": run["worktree_path"],
                    "step4_readiness": run["step4_readiness"],
                    "safety": run["safety"],
                    "budget_contract": run["budget_contract"],
                }
            )
            run_path.write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("apply_policy_digest_mismatch", errors)
            self.assertIn("apply_policy_mismatch=workspace_verified", errors)
            self.assertIn("apply_policy_mismatch=worktree_path", errors)
            self.assertIn("apply_policy_mismatch=step4_readiness", errors)
            self.assertIn("apply_policy_mismatch=safety", errors)
            self.assertIn("apply_policy_mismatch=budget_contract", errors)

    def test_apply_budget_rejects_invalid_limits_and_selected_task_overflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run_path = run_dir / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["budget_contract"]["max_agent_attempts_per_role"] = -1
            run["budget_contract"]["hard_total_token_limit"] = 1
            run["budget_contract"]["soft_input_token_limit"] = 2
            run_path.write_text(json.dumps(run), encoding="utf-8")
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            template = progress["tasks"][0]
            progress["tasks"] = [json.loads(json.dumps(template)) for _ in range(5)]
            for index, task in enumerate(progress["tasks"], start=1):
                task["task_id"] = f"{template['task_id'][:-3]}{index:03d}"
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("invalid_budget_contract=max_agent_attempts_per_role", errors)
            self.assertIn("budget_contract_hard_below_soft", errors)
            self.assertIn("budget_selected_tasks_exceeded", errors)

    def test_subagent_attempt_budget_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)

            for attempt in range(1, 3):
                APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", [f"packet {attempt}"], root=root)
                APPLY_MODULE.record_agent_status(
                    run_dir,
                    task_id,
                    "implementer",
                    f"agent-impl-{attempt}",
                    "spawned",
                    "controller",
                    [f"spawn {attempt}"],
                root=root,
                )
                APPLY_MODULE.record_agent_status(
                    run_dir,
                    task_id,
                    "implementer",
                    f"agent-impl-{attempt}",
                    "failed",
                    "controller",
                    [f"failure {attempt}"],
                    "recoverable setup failure",
                root=root,
                )

            with self.assertRaisesRegex(ValueError, f"budget_max_agent_attempts_exceeded={task_id}:implementer"):
                APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", ["third packet"], root=root)

    def test_apply_validator_rejects_attempt_and_fix_cycle_over_budget(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            task_id = task["task_id"]
            task["fix_cycle_count"] = 3
            task["agent_runs"] = [
                {
                    "task_id": task_id,
                    "role": "implementer",
                    "attempt": 3,
                    "agent_id": "agent-impl-3",
                    "status": "failed",
                    "packet_sha256": "a" * 64,
                    "prompt_sha256": "b" * 64,
                    "spawn_tool": "multi_agent_v1.spawn_agent",
                    "summary": "attempt exceeds budget",
                    "failed_at": "2026-01-01T00:00:00Z",
                }
            ]
            progress_path.write_text(json.dumps(progress), encoding="utf-8")
            (run_dir / task_id / "Fix-Report.json").write_text(
                json.dumps({"fixes": [{"finding": "a"}, {"finding": "b"}, {"finding": "c"}]}),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"budget_max_fix_cycles_exceeded={task_id}", errors)
            self.assertIn(f"budget_max_agent_attempts_exceeded={task_id}:implementer", errors)

    def test_apply_unknown_runtime_token_usage_is_reported_honestly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            result_payload = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))

            self.assertEqual(run["token_usage"]["total_tokens"], "not_observed")
            self.assertEqual(result_payload["token_usage"]["source"], "runtime_not_available")
            run["token_usage"] = {"status": "observed", "input_tokens": 10, "output_tokens": 5, "total_tokens": 99, "source": "test"}
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")
            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("token_usage_total_mismatch", errors)

    def test_apply_task_contract_is_bound_to_source_subplan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task = progress["tasks"][0]

            self.assertEqual(task["source_subplan_path"], "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md")
            self.assertTrue(task["source_subplan_sha256"])
            self.assertTrue(task["implementation_contract_digest"])
            self.assertTrue(task["task_contract_digest"])
            self.assertEqual(task["parent_acceptance_signal_ids"], ["MP-PH1-AS-01"])
            self.assertEqual(task["risk_class"], "low")
            self.assertEqual(task["risk_domains"], ["none"])
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])

    def test_apply_rejects_task_contract_divergent_from_source_subplan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            task["implementation_contract"]["outputs"] = ["reports/tampered.md"]
            task["implementation_contract_digest"] = APPLY_MODULE.canonical_json_digest(task["implementation_contract"])
            task["task_contract_digest"] = APPLY_MODULE.task_contract_digest(task)
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"implementation_contract_source_mismatch={task['task_id']}", errors)
            self.assertIn(f"implementation_contract_digest_source_mismatch={task['task_id']}", errors)

    def test_apply_rejects_source_subplan_hash_and_path_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            task["source_subplan_sha256"] = "0" * 64
            task["source_subplan_path"] = "Planner-docs/Missing.md"
            task["task_contract_digest"] = APPLY_MODULE.task_contract_digest(task)
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("missing_source_subplan=Planner-docs/Missing.md", errors)
            self.assertIn(f"source_subplan_sha256_mismatch={task['task_id']}", errors)

    def test_apply_rejects_validation_ids_divergent_from_source_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            task["validation_command_ids"] = ["VAL-99"]
            task["task_contract_digest"] = APPLY_MODULE.task_contract_digest(task)
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"validation_command_ids_source_mismatch={task['task_id']}", errors)
            self.assertIn(f"implementation_contract_validation_command_ids_mismatch={task['task_id']}", errors)

    def test_apply_brief_contract_hash_matches_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            brief_path = run_dir / task["task_id"] / "Brief.md"
            brief_path.write_text(
                brief_path.read_text(encoding="utf-8").replace("reports/faz1-1-readiness.md", "reports/tampered.md"),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"task_brief_hash_mismatch={task['task_id']}", errors)
            self.assertIn(f"task_brief_contract_mismatch={task['task_id']}", errors)

    def test_apply_dispatch_contract_hash_matches_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", ["packet ready"], root=root)
            packet_path = run_dir / task_id / "Dispatch-Packet.json"
            packet = json.loads(packet_path.read_text(encoding="utf-8"))
            self.assertEqual(
                packet["expected_report_paths"],
                {
                    "implementer": "Implementer-Report.json",
                    "task_reviewer_spec": "Review-Report-spec.json",
                    "task_reviewer_quality": "Review-Report-quality.json",
                    "security_reviewer": "Review-Report-security.json",
                    "fixer": "Fix-Report.json",
                    "final_reviewer": "Review-Report-final.json",
                },
            )
            packet["spawn_request"]["message"] = packet["spawn_request"]["message"].replace(
                "reports/faz1-1-readiness.md",
                "reports/tampered.md",
            )
            packet["expected_report_paths"]["implementer"] = "unexpected.json"
            packet["prompt_sha256"] = APPLY_MODULE.sha256_bytes(packet["spawn_request"]["message"].encode("utf-8"))
            packet_path.write_text(json.dumps(packet, sort_keys=True), encoding="utf-8")
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            progress["tasks"][0]["dispatch"]["packet_sha256"] = APPLY_MODULE.sha256_bytes(packet_path.read_bytes())
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"dispatch_prompt_contract_mismatch={task_id}", errors)
            self.assertIn(f"dispatch_expected_report_paths_mismatch={task_id}", errors)

    def test_dispatch_rejects_task_directory_swap_without_writing_outside(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            task_dir = run_dir / task_id
            held_task_dir = run_dir / f".{task_id}-held"
            outside_task_dir = Path(outside_dir) / "outside-task"
            outside_task_dir.mkdir()
            before_events = (run_dir / "Events.jsonl").read_bytes()
            before_progress = (run_dir / "Progress.json").read_bytes()
            original_write = APPLY_MODULE.secure_atomic_write_json_at
            swapped = {"done": False}

            def swap_task_before_write(directory_fd, name, payload, *, revalidate=None):
                if name == "Dispatch-Packet.json" and not swapped["done"]:
                    task_dir.rename(held_task_dir)
                    task_dir.symlink_to(outside_task_dir, target_is_directory=True)
                    swapped["done"] = True
                return original_write(directory_fd, name, payload, revalidate=revalidate)

            with mock.patch.object(
                APPLY_MODULE,
                "secure_atomic_write_json_at",
                side_effect=swap_task_before_write,
            ):
                with self.assertRaisesRegex(ValueError, "artifact_directory_identity_changed"):
                    APPLY_MODULE.prepare_dispatch_packet(
                        run_dir,
                        task_id,
                        "implementer",
                        "controller",
                        ["probe"],
                    root=root,
                    )

            self.assertTrue(swapped["done"])
            self.assertFalse((outside_task_dir / "Dispatch-Packet.json").exists())
            self.assertFalse((held_task_dir / "Dispatch-Packet.json").exists())
            self.assertEqual((run_dir / "Events.jsonl").read_bytes(), before_events)
            self.assertEqual((run_dir / "Progress.json").read_bytes(), before_progress)

    def test_apply_report_and_review_reference_expected_contract_hash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            self.mark_task_verified(root, run_dir, "pass")
            task_id = self.first_task_id(run_dir)
            report_path = run_dir / task_id / "Implementer-Report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["task_contract_digest"] = "0" * 64
            report_path.write_text(json.dumps(report), encoding="utf-8")
            review_path = run_dir / task_id / "Task-Review.json"
            review = json.loads(review_path.read_text(encoding="utf-8"))
            review["implementation_contract_digest"] = "1" * 64
            review_path.write_text(json.dumps(review), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"implementer_task_contract_digest_mismatch={task_id}", errors)
            self.assertIn(f"task_review_contract_digest_mismatch={task_id}", errors)

    def test_validate_rejects_symlinked_verified_report_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            report_path = run_dir / task_id / "Implementer-Report.json"
            victim = Path(outside_dir) / "implementer-report-victim.json"
            victim.write_bytes(report_path.read_bytes())
            report_path.unlink()
            report_path.symlink_to(victim)
            before_events = (run_dir / "Events.jsonl").read_bytes()

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"invalid_artifact_file={task_id}_implementer_report", errors)
            with self.assertRaisesRegex(
                ValueError,
                "invalid_artifact_file|apply_run_provenance_unverified",
            ):
                APPLY_MODULE.finalize_apply_run(run_dir, "controller", ["probe"], root=root)
            self.assertEqual((run_dir / "Events.jsonl").read_bytes(), before_events)

    def test_validate_rejects_symlinked_verified_review_patch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            self.mark_task_verified(root, run_dir)
            task_id = self.first_task_id(run_dir)
            patch_path = run_dir / task_id / "Review-Package.patch"
            victim = Path(outside_dir) / "review-package-victim.patch"
            victim.write_bytes(patch_path.read_bytes())
            patch_path.unlink()
            patch_path.symlink_to(victim)

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"invalid_artifact_file={task_id}_review_package", errors)

    def test_subagent_serial_requires_dispatch_packet_before_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)

            with self.assertRaisesRegex(ValueError, "subagent_dispatch_packet_missing"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)

            prepared = APPLY_MODULE.prepare_dispatch_packet(
                run_dir,
                task_id,
                "implementer",
                "controller",
                ["controller prepared fresh implementer dispatch"],
            root=root,
            )
            packet_path = Path(prepared["packet_path"])
            packet = json.loads(packet_path.read_text(encoding="utf-8"))

            self.assertEqual(packet["spawn_tool"], "multi_agent_v1.spawn_agent")
            self.assertEqual(packet["spawn_request"]["agent_type"], "worker")
            self.assertFalse(packet["spawn_request"]["fork_context"])
            self.assertIn("Use only this fresh task context", packet["spawn_request"]["message"])
            self.assertIn("## Structured Implementation Contract", packet["spawn_request"]["message"])
            self.assertIn('"outputs": [', packet["spawn_request"]["message"])
            self.assertIsNone(packet["model_override"])
            with self.assertRaisesRegex(ValueError, "subagent_dispatch_spawn_required"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-1",
                "spawned",
                "controller",
                ["spawned implementer"],
            root=root,
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)
            with self.assertRaisesRegex(ValueError, "subagent_dispatch_completion_required"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "impl-1", ["done"], root=root)
            APPLY_MODULE.normalize_writer_report(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-1",
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "implementer_agent_id": "agent-impl-1",
                    "files_changed": [],
                    "concerns": [],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-1",
                "completed",
                "controller",
                ["implementer completed"],
                "implementation finished",
            root=root,
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "impl-1", ["done"], root=root)
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_failed_subagent_dispatch_can_be_redispatched_before_implementation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)

            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", ["first packet"], root=root)
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-1",
                "spawned",
                "controller",
                ["first spawn"],
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-1",
                "failed",
                "controller",
                ["agent failed before code changes"],
                "spawn failed before implementation",
            root=root,
            )
            second = APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", ["second packet"], root=root)
            packet = json.loads(Path(second["packet_path"]).read_text(encoding="utf-8"))
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "agent-impl-2",
                "spawned",
                "controller",
                ["second spawn"],
            root=root,
            )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task = progress["tasks"][0]

            self.assertEqual(packet["attempt"], 2)
            self.assertEqual([run["status"] for run in task["agent_runs"]], ["failed", "spawned"])
            self.assertEqual(task["dispatch"]["agent_id"], "agent-impl-2")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_no_action_mode_has_no_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            result = self.create_apply_run(root, "no_action")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"], [])
            self.assertEqual(run["mode"], "no_action")
            self.assertEqual(run["step4_readiness"]["execution_queue_state"], "NO_ACTION_REQUIRED")

    def test_apply_run_rejects_output_dir_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside:
            with self.assertRaises(ValueError):
                self.create_apply_run(Path(temp_dir), "direct", Path(outside))

    def test_apply_replace_rejects_repository_root_and_unmanaged_repo_directory(self) -> None:
        for target_name in ("repo-root", "unmanaged-directory"):
            with self.subTest(target=target_name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_no_action_fixture(root)
                target = root if target_name == "repo-root" else root / "src"
                target.mkdir(parents=True, exist_ok=True)
                sentinel = target / "sentinel.txt"
                sentinel.write_text("preserve me\n", encoding="utf-8")

                with mock.patch.object(
                    shutil,
                    "rmtree",
                    side_effect=AssertionError("unsafe recursive delete reached"),
                ):
                    with self.assertRaisesRegex(ValueError, "invalid_apply_run_output_dir"):
                        self.create_apply_run(root, "no_action", target, replace=True)

                self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_cli_rejects_dot_output_and_external_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            sentinel = root / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            previous_cwd = Path.cwd()
            try:
                os.chdir(root)
                with mock.patch.object(
                    shutil,
                    "rmtree",
                    side_effect=AssertionError("unsafe recursive delete reached"),
                ):
                    status = APPLY_MODULE.main(
                        ["prepare", "--root", ".", "--mode", "no_action", "--output-dir", ".", "--replace"]
                    )
            finally:
                os.chdir(previous_cwd)

            self.assertEqual(status, 1)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

            for candidate in (root.parent, Path.home(), Path(root.anchor)):
                with self.subTest(candidate=candidate):
                    with self.assertRaisesRegex(ValueError, "invalid_apply_run_output_dir"):
                        APPLY_MODULE.resolve_managed_apply_run_dir(root.resolve(), candidate, lexical_root=root)

    def test_apply_replace_rejects_managed_parent_nested_and_markerless_directories(self) -> None:
        candidates = ("managed-parent", "nested-child", "markerless-child")
        for candidate in candidates:
            with self.subTest(candidate=candidate), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_no_action_fixture(root)
                managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
                bootstrap = managed_parent / "bootstrap"
                self.create_apply_run(
                    root,
                    "no_action",
                    bootstrap,
                    run_id_suffix="bootstrap",
                )
                if candidate == "managed-parent":
                    target = managed_parent
                elif candidate == "nested-child":
                    target = bootstrap / "nested"
                else:
                    target = managed_parent / "markerless"
                target.mkdir(parents=True, exist_ok=True, mode=0o700)
                target.chmod(0o700)
                sentinel = target / "sentinel.txt"
                sentinel.write_text("preserve me\n", encoding="utf-8")
                sentinel.chmod(0o600)

                with mock.patch.object(
                    shutil,
                    "rmtree",
                    side_effect=AssertionError("unsafe recursive delete reached"),
                ):
                    expected = "replace_requires_existing_apply_run" if candidate == "markerless-child" else "invalid_apply_run_output_dir"
                    with self.assertRaisesRegex(ValueError, expected):
                        self.create_apply_run(root, "no_action", target, replace=True)

                self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_rejects_symlinked_run_and_managed_parent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            victim = root / "victim"
            victim.mkdir()
            sentinel = victim / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            with mock.patch.object(
                self._controller_store_module,
                "controller_home_directory",
                return_value=self._home_path,
            ):
                with self._controller_store_module.open_controller_runs_root(
                    root,
                    self._controller_store_module.APPLY_RUN_COMPONENTS,
                    create=True,
                ) as (_runs_fd, managed_parent):
                    pass
            self.assertTrue(managed_parent.is_relative_to(self._home_path))
            linked_run = managed_parent / "linked"
            linked_run.symlink_to(victim, target_is_directory=True)

            with mock.patch.object(
                shutil,
                "rmtree",
                side_effect=AssertionError("unsafe recursive delete reached"),
            ):
                with self.assertRaisesRegex(ValueError, "invalid_apply_run_output_dir=indirect_target_rejected"):
                    self.create_apply_run(root, "no_action", linked_run, replace=True)

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            indirect = Path(outside_dir) / "indirect-controller-store"
            indirect.mkdir(mode=0o700)
            sentinel = indirect / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            linked_store = Path(outside_dir) / "controller-store-link"
            linked_store.symlink_to(indirect, target_is_directory=True)

            with mock.patch.dict(
                os.environ,
                {"CODEXQB_CONTROLLER_STORE_ROOT": str(linked_store)},
            ), mock.patch.object(
                self._controller_store_module,
                "controller_home_directory",
                return_value=self._home_path,
            ):
                with self._controller_store_module.open_controller_store(create=True) as (
                    _fd,
                    opened_store,
                ):
                    self.assertTrue(opened_store.is_relative_to(self._home_path))

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_requires_valid_regular_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            marker = fixed / ".codexqb-apply-run.json"
            self.assertTrue(marker.is_file())
            marker.write_text("{}\n", encoding="utf-8")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_rejects_symlink_marker_and_forged_unmanaged_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            marker = fixed / ".codexqb-apply-run.json"
            marker_target = root / "marker-target.json"
            marker_target.write_bytes(marker.read_bytes())
            marker.unlink()
            marker.symlink_to(marker_target)
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            legitimate = APPLY_MODULE.managed_apply_runs_root(root) / "legitimate"
            self.create_apply_run(root, "no_action", legitimate, run_id_suffix="first")
            forged = root / "src"
            forged.mkdir()
            shutil.copy2(legitimate / "Apply-Run.json", forged / "Apply-Run.json")
            shutil.copy2(legitimate / ".codexqb-apply-run.json", forged / ".codexqb-apply-run.json")
            sentinel = forged / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")

            with mock.patch.object(
                shutil,
                "rmtree",
                side_effect=AssertionError("unsafe recursive delete reached"),
            ):
                with self.assertRaisesRegex(ValueError, "invalid_apply_run_output_dir"):
                    self.create_apply_run(root, "no_action", forged, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_regenerates_only_valid_canonical_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
            fixed = managed_parent / "fixed"
            first = self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            stale = fixed / "stale.txt"
            stale.write_text("remove me\n", encoding="utf-8")
            sibling = managed_parent / "sibling-sentinel.txt"
            sibling.write_text("preserve me\n", encoding="utf-8")

            second = self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertNotEqual(first["apply_run_id"], second["apply_run_id"])
            self.assertFalse(stale.exists())
            self.assertEqual(sibling.read_text(encoding="utf-8"), "preserve me\n")
            self.assertTrue((fixed / ".codexqb-apply-run.json").is_file())
            self.assertTrue((fixed / "Apply-Run.json").is_file())

    def test_apply_run_creation_keeps_registration_bound_to_created_inode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            victim = root / "arbitrary-victim"
            victim.mkdir()
            sentinel = victim / "sentinel.txt"
            sentinel.write_text("preserve victim\n", encoding="utf-8")
            stashed = root / "created-run-stashed"
            original_registration = APPLY_MODULE.create_apply_run_registration
            state = {"swapped": False}

            def swap_before_registration(*args, **kwargs):
                fixed.rename(stashed)
                victim.rename(fixed)
                state["swapped"] = True
                return original_registration(*args, **kwargs)

            with mock.patch.object(
                APPLY_MODULE,
                "create_apply_run_registration",
                side_effect=swap_before_registration,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "indirect_target_rejected|replace_apply_run_tree_contains_indirect_target",
                ):
                    self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")

            self.assertTrue(state["swapped"])
            self.assertEqual((fixed / "sentinel.txt").read_text(encoding="utf-8"), "preserve victim\n")
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            self.assertFalse(registration.exists())

    def test_receipt_publish_failure_leaves_current_run_unusable_but_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"

            with mock.patch.object(
                APPLY_MODULE,
                "create_apply_run_registration",
                side_effect=OSError("synthetic_receipt_publish_failure"),
            ):
                with self.assertRaisesRegex(OSError, "synthetic_receipt_publish_failure"):
                    self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")

            self.assertTrue((fixed / "Apply-Run.json").is_file())
            self.assertTrue((fixed / APPLY_MODULE.APPLY_RUN_MARKER_NAME).is_file())
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            self.assertFalse(registration.exists())
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve incomplete run\n", encoding="utf-8")

            self.assertIn("apply_run_provenance_unverified", APPLY_MODULE.validate_apply_run(fixed, root))
            with self.assertRaisesRegex(ValueError, "apply_run_provenance_unverified"):
                self.create_apply_run(root, "no_action", fixed, resume=True)
            run_path = fixed / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            del run["apply_run_registration_id"]
            run_path.write_text(json.dumps(run), encoding="utf-8")
            downgraded_errors = APPLY_MODULE.validate_apply_run(fixed, root)
            self.assertIn("missing_apply_run_registration_id", downgraded_errors)
            self.assertIn("apply_run_provenance_unverified", downgraded_errors)
            with self.assertRaisesRegex(ValueError, "apply_run_provenance_unverified"):
                self.create_apply_run(root, "no_action", fixed, resume=True)
            with self.assertRaisesRegex(ValueError, r"replace_requires_(?:existing|registered)_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="replacement")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve incomplete run\n")

    def test_current_schema_run_cannot_downgrade_to_recomputed_schema_v1(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve current run\n", encoding="utf-8")
            run_path = fixed / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))

            self.assertEqual(run["apply_run_schema_version"], APPLY_MODULE.APPLY_RUN_SCHEMA_VERSION)
            run["apply_run_schema_version"] = 1
            del run["apply_run_registration_id"]
            spec_inputs = run["apply_spec_inputs"]
            spec_digest = APPLY_MODULE.apply_spec_digest(
                run["apply_requested_mode"],
                run["source_snapshot"],
                spec_inputs["workspace_baseline"],
                spec_inputs["ready_queue"],
                apply_run_schema_version=1,
            )
            run["apply_spec_digest"] = spec_digest
            run["apply_spec_id"] = f"apply-spec-{run['apply_requested_mode']}-{spec_digest[:16]}"
            run["apply_run_id"] = (
                f"apply-{run['apply_requested_mode']}-{spec_digest[:12]}-{run['apply_run_invocation_id']}"
            )
            run_path.write_text(json.dumps(run), encoding="utf-8")
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            registration.unlink()
            (fixed / APPLY_MODULE.APPLY_RUN_MARKER_NAME).unlink()

            errors = APPLY_MODULE.validate_apply_run(fixed, root)
            self.assertIn("invalid_apply_run_schema_version", errors)
            with self.assertRaisesRegex(ValueError, "invalid_apply_run_schema_version"):
                self.create_apply_run(root, "no_action", fixed, resume=True)
            with self.assertRaisesRegex(ValueError, r"replace_requires_(?:existing|registered)_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="replacement")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve current run\n")

    def test_apply_run_rejects_stale_registration_before_recreating_run_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            shutil.rmtree(fixed)
            self.assertTrue(registration.is_file())

            with self.assertRaisesRegex(ValueError, "apply_run_registration_recovery_required=fixed"):
                self.create_apply_run(root, "no_action", fixed, run_id_suffix="second")

            self.assertFalse(fixed.exists())
            self.assertTrue(registration.is_file())

    def test_apply_replace_registry_delete_failure_does_not_mutate_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve run\n", encoding="utf-8")
            before = fixed.stat()

            with mock.patch.object(
                APPLY_MODULE,
                "delete_inventory_entry",
                side_effect=ValueError("synthetic_registry_delete_failure"),
            ):
                with self.assertRaisesRegex(ValueError, "synthetic_registry_delete_failure"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            after = fixed.stat()
            self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve run\n")

    def test_opened_directory_mount_check_revalidates_path_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "target"
            target.mkdir()
            original_metadata = target.stat()
            stashed = root / "target-stashed"

            def swap_during_mount_check(_path):
                target.rename(stashed)
                target.mkdir()
                return False

            with mock.patch.object(
                APPLY_MODULE,
                "path_is_mount_point",
                side_effect=swap_during_mount_check,
            ):
                self.assertFalse(
                    APPLY_MODULE.opened_directory_matches_path(
                        target,
                        original_metadata,
                        reject_mount=True,
                    )
                )

    def test_apply_replace_rejects_same_device_descendant_mount_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            mounted = fixed / "mounted"
            mounted.mkdir()
            sentinel = mounted / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")

            with mock.patch.object(
                APPLY_MODULE,
                "path_is_mount_point",
                side_effect=lambda path: Path(path).name == "mounted",
            ):
                with self.assertRaisesRegex(ValueError, "replace_apply_run_tree_contains_indirect_target"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_rejects_post_inventory_nested_directory_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
            fixed = managed_parent / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            nested = fixed / ".000-nested"
            nested.mkdir()
            original_sentinel = nested / "original-sentinel.txt"
            original_sentinel.write_text("preserve original\n", encoding="utf-8")
            moved_original = managed_parent / "moved-original"
            original_clear = APPLY_MODULE.clear_directory_fd
            state = {"swapped": False}

            def swap_then_clear(
                directory_fd,
                expected_device,
                logical_path,
                inventory,
                *,
                root,
                root_mount_resolution,
            ):
                if not state["swapped"]:
                    state["swapped"] = True
                    active_nested = Path(logical_path) / ".000-nested"
                    active_nested.rename(moved_original)
                    active_nested.mkdir()
                    (active_nested / "replacement-sentinel.txt").write_text(
                        "preserve replacement\n",
                        encoding="utf-8",
                    )
                return original_clear(
                    directory_fd,
                    expected_device,
                    logical_path,
                    inventory,
                    root=root,
                    root_mount_resolution=root_mount_resolution,
                )

            with mock.patch.object(APPLY_MODULE, "clear_directory_fd", side_effect=swap_then_clear):
                with self.assertRaisesRegex(ValueError, "replace_apply_run_tree_changed"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(
                (moved_original / "original-sentinel.txt").read_text(encoding="utf-8"),
                "preserve original\n",
            )
            replacement_sentinel = fixed / ".000-nested" / "replacement-sentinel.txt"
            self.assertEqual(replacement_sentinel.read_text(encoding="utf-8"), "preserve replacement\n")

    def test_apply_replace_quarantines_regular_file_before_identity_bound_delete(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            target = fixed / ".000-target.txt"
            target.write_text("preserve original\n", encoding="utf-8")
            external_victim = root / "external-victim.txt"
            external_victim.write_text("preserve external victim\n", encoding="utf-8")
            original_quarantine_rename = APPLY_MODULE.atomic_rename_no_replace
            original_rename = os.rename
            state = {"swapped": False}

            def swap_then_quarantine(
                source,
                destination,
                *,
                source_dir_fd,
                destination_dir_fd,
            ):
                if source == ".000-target.txt" and not state["swapped"]:
                    state["swapped"] = True
                    original_rename(
                        source,
                        ".moved-original.txt",
                        src_dir_fd=source_dir_fd,
                        dst_dir_fd=source_dir_fd,
                    )
                    original_rename(external_victim, source, dst_dir_fd=source_dir_fd)
                return original_quarantine_rename(
                    source,
                    destination,
                    source_dir_fd=source_dir_fd,
                    destination_dir_fd=destination_dir_fd,
                )

            with mock.patch.object(
                APPLY_MODULE,
                "atomic_rename_no_replace",
                side_effect=swap_then_quarantine,
            ):
                with self.assertRaisesRegex(ValueError, "replace_apply_run_tree_changed"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertTrue(state["swapped"])
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve external victim\n")
            self.assertEqual(
                (fixed / ".moved-original.txt").read_text(encoding="utf-8"),
                "preserve original\n",
            )

    def test_apply_replace_quarantine_rename_never_overwrites_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = root / "source.txt"
            destination = root / "destination.txt"
            source.write_text("preserve source\n", encoding="utf-8")
            destination.write_text("preserve destination\n", encoding="utf-8")
            root_fd = os.open(root, APPLY_MODULE.secure_directory_open_flags())
            try:
                with self.assertRaises(OSError):
                    APPLY_MODULE.atomic_rename_no_replace(
                        source.name,
                        destination.name,
                        source_dir_fd=root_fd,
                        destination_dir_fd=root_fd,
                    )
            finally:
                os.close(root_fd)

            self.assertEqual(source.read_text(encoding="utf-8"), "preserve source\n")
            self.assertEqual(destination.read_text(encoding="utf-8"), "preserve destination\n")

            destination.unlink()
            root_fd = os.open(root, APPLY_MODULE.secure_directory_open_flags())
            try:
                APPLY_MODULE.atomic_rename_no_replace(
                    source.name,
                    destination.name,
                    source_dir_fd=root_fd,
                    destination_dir_fd=root_fd,
                )
            finally:
                os.close(root_fd)
            self.assertFalse(source.exists())
            self.assertEqual(destination.read_text(encoding="utf-8"), "preserve source\n")

    def test_apply_replace_fails_before_run_mutation_when_no_replace_is_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
            fixed = managed_parent / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            before = {path.name for path in managed_parent.iterdir()}

            with mock.patch.object(
                APPLY_MODULE,
                "atomic_no_replace_backend",
                side_effect=ValueError("secure_apply_run_replace_not_supported"),
            ):
                with self.assertRaisesRegex(ValueError, "secure_apply_run_replace_not_supported"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")
            self.assertEqual({path.name for path in managed_parent.iterdir()}, before)

    def test_apply_replace_restore_conflict_preserves_all_inodes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            target = fixed / ".000-target.txt"
            target.write_text("preserve original\n", encoding="utf-8")
            external_victim = root / "external-victim.txt"
            external_victim.write_text("preserve external victim\n", encoding="utf-8")
            original_quarantine_rename = APPLY_MODULE.atomic_rename_no_replace
            original_rename = os.rename
            state = {"source_swapped": False, "restore_conflicted": False}

            def race_source_and_restore(
                source,
                destination,
                *,
                source_dir_fd,
                destination_dir_fd,
            ):
                if source == ".000-target.txt" and not state["source_swapped"]:
                    state["source_swapped"] = True
                    original_rename(
                        source,
                        ".moved-original.txt",
                        src_dir_fd=source_dir_fd,
                        dst_dir_fd=source_dir_fd,
                    )
                    original_rename(external_victim, source, dst_dir_fd=source_dir_fd)
                elif (
                    source == "entry"
                    and destination == ".000-target.txt"
                    and state["source_swapped"]
                    and not state["restore_conflicted"]
                ):
                    state["restore_conflicted"] = True
                    conflict_fd = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                        dir_fd=destination_dir_fd,
                    )
                    try:
                        os.write(conflict_fd, b"preserve conflict occupant\n")
                    finally:
                        os.close(conflict_fd)
                return original_quarantine_rename(
                    source,
                    destination,
                    source_dir_fd=source_dir_fd,
                    destination_dir_fd=destination_dir_fd,
                )

            with mock.patch.object(
                APPLY_MODULE,
                "atomic_rename_no_replace",
                side_effect=race_source_and_restore,
            ):
                with self.assertRaisesRegex(ValueError, "replace_apply_run_restore_conflict"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertTrue(state["source_swapped"])
            self.assertTrue(state["restore_conflicted"])
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve conflict occupant\n")
            self.assertEqual(
                (fixed / ".moved-original.txt").read_text(encoding="utf-8"),
                "preserve original\n",
            )
            quarantined_entries = list(fixed.glob(".codexqb-delete-*/entry"))
            self.assertEqual(len(quarantined_entries), 1)
            self.assertEqual(quarantined_entries[0].read_text(encoding="utf-8"), "preserve external victim\n")

            with self.assertRaisesRegex(ValueError, "replace_apply_run_recovery_required"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="third")
            self.assertEqual(target.read_text(encoding="utf-8"), "preserve conflict occupant\n")
            self.assertEqual(quarantined_entries[0].read_text(encoding="utf-8"), "preserve external victim\n")

    def test_apply_replace_top_level_restore_conflict_blocks_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
            fixed = managed_parent / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve original run\n", encoding="utf-8")
            backup = root / "valid-run-backup"
            shutil.copytree(fixed, backup)
            original_quarantine_rename = APPLY_MODULE.atomic_rename_no_replace
            state = {"restore_conflicted": False}

            def occupy_public_name_before_restore(
                source,
                destination,
                *,
                source_dir_fd,
                destination_dir_fd,
            ):
                if source == "entry" and destination == "fixed" and not state["restore_conflicted"]:
                    state["restore_conflicted"] = True
                    shutil.copytree(backup, fixed)
                return original_quarantine_rename(
                    source,
                    destination,
                    source_dir_fd=source_dir_fd,
                    destination_dir_fd=destination_dir_fd,
                )

            with mock.patch.object(
                APPLY_MODULE,
                "atomic_rename_no_replace",
                side_effect=occupy_public_name_before_restore,
            ), mock.patch.object(
                APPLY_MODULE,
                "clear_directory_fd",
                side_effect=ValueError("replace_apply_run_tree_changed"),
            ):
                with self.assertRaisesRegex(ValueError, "replace_apply_run_restore_conflict"):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertTrue(state["restore_conflicted"])
            top_level_quarantines = list(managed_parent.glob(".codexqb-delete-*/entry"))
            self.assertEqual(len(top_level_quarantines), 1)
            self.assertEqual(
                (top_level_quarantines[0] / "sentinel.txt").read_text(encoding="utf-8"),
                "preserve original run\n",
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve original run\n")

            with self.assertRaisesRegex(ValueError, "replace_apply_run_recovery_required"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="third")
            self.assertEqual(
                (top_level_quarantines[0] / "sentinel.txt").read_text(encoding="utf-8"),
                "preserve original run\n",
            )
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve original run\n")

    def test_apply_replace_rejects_synthetic_self_attested_marker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            legitimate = APPLY_MODULE.managed_apply_runs_root(root) / "legitimate"
            self.create_apply_run(root, "no_action", legitimate, run_id_suffix="legitimate")
            synthetic_run = json.loads((legitimate / "Apply-Run.json").read_text(encoding="utf-8"))
            forged = APPLY_MODULE.managed_apply_runs_root(root) / "forged"
            forged.mkdir(mode=0o700)
            marker = APPLY_MODULE.apply_run_marker_payload(root, forged, synthetic_run)
            (forged / "Apply-Run.json").write_text(json.dumps(synthetic_run), encoding="utf-8")
            (forged / ".codexqb-apply-run.json").write_text(json.dumps(marker), encoding="utf-8")
            sentinel = forged / "sentinel.txt"
            sentinel.write_text("preserve synthetic victim\n", encoding="utf-8")
            forged_metadata = forged.stat()
            unsigned_registration = {
                "registration_kind": APPLY_MODULE.APPLY_RUN_REGISTRATION_KIND,
                "registration_version": APPLY_MODULE.APPLY_RUN_REGISTRATION_VERSION,
                "registration_id": synthetic_run["apply_run_registration_id"],
                "run_name": forged.name,
                "run_dir": APPLY_MODULE.apply_run_logical_path(root, forged),
                "run_device": forged_metadata.st_dev,
                "run_inode": forged_metadata.st_ino,
                "manifest_claim_sha256": APPLY_MODULE.apply_run_manifest_claim_digest(synthetic_run),
                "manifest_sha256": APPLY_MODULE.apply_run_manifest_digest(synthetic_run),
                "refresh_stable_sha256": APPLY_MODULE.apply_run_refresh_stable_digest(synthetic_run),
            }
            registration_path = (
                forged.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(forged.name)
            )
            registration_path.write_text(json.dumps(unsigned_registration), encoding="utf-8")
            registration_path.chmod(0o600)

            self.assertFalse(
                APPLY_MODULE.recognized_apply_run_manifest(
                    root,
                    forged,
                    marker,
                    synthetic_run,
                    unsigned_registration,
                    forged_metadata,
                    root.stat(),
                )
            )
            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", forged, replace=True, run_id_suffix="replacement")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve synthetic victim\n")

    def test_apply_replace_rejects_tampered_out_of_run_registration(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            payload = json.loads(registration.read_text(encoding="utf-8"))
            payload["run_inode"] = int(payload["run_inode"]) + 1
            registration.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_rejects_tampered_registration_mac(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            registration = (
                fixed.parent
                / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
            )
            payload = json.loads(registration.read_text(encoding="utf-8"))
            payload["registration_mac"] = "0" * 64
            registration.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_registration_mac_is_domain_separated(self) -> None:
        key = b"K" * APPLY_MODULE.CODEXQB_TRUST_KEY_BYTES
        proof = mock.Mock(
            repository_identity_sha256="a" * 64,
            root_device=17,
            root_inode=23,
        )
        with mock.patch.object(
            APPLY_MODULE,
            "load_or_create_apply_run_trust_key",
            return_value=key,
        ):
            signed = APPLY_MODULE.signed_apply_run_registration(
                proof,
                {"run_name": "fixed"},
                create_key=False,
            )
            self.assertTrue(APPLY_MODULE.trusted_apply_run_registration(proof, signed))
            unsigned = {
                name: value
                for name, value in signed.items()
                if name != "registration_mac"
            }
            encoded = json.dumps(
                unsigned,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            legacy = dict(signed)
            legacy["registration_mac"] = APPLY_MODULE.hmac.new(
                key,
                encoded,
                APPLY_MODULE.hashlib.sha256,
            ).hexdigest()
            self.assertFalse(APPLY_MODULE.trusted_apply_run_registration(proof, legacy))

    def test_apply_replace_fails_closed_when_external_trust_key_is_not_private(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, temporary_safe_home() as home_dir:
            root = Path(temp_dir)
            home = Path(home_dir).resolve()
            home.chmod(0o700)
            trust_root = home / ".codex" / "codexqb-trust"
            self.write_no_action_fixture(root)
            with mock.patch.object(
                self._controller_store_module,
                "controller_home_directory",
                return_value=home,
            ):
                APPLY_MODULE.load_or_create_apply_run_trust_key(create=True)
                (trust_root / APPLY_MODULE.CODEXQB_TRUST_KEY_NAME).chmod(0o644)

                with self.assertRaisesRegex(ValueError, "codexqb_trust_key_permissions_invalid"):
                    APPLY_MODULE.load_or_create_apply_run_trust_key(create=False)

    def test_missing_initialized_trust_key_requires_recovery_instead_of_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, temporary_safe_home() as home_dir:
            root = Path(temp_dir)
            home = Path(home_dir).resolve()
            home.chmod(0o700)
            trust_root = home / ".codex" / "codexqb-trust"
            self.write_no_action_fixture(root)
            with mock.patch.object(
                self._controller_store_module,
                "controller_home_directory",
                return_value=home,
            ):
                APPLY_MODULE.load_or_create_apply_run_trust_key(create=True)
                self.assertTrue((trust_root / APPLY_MODULE.CODEXQB_TRUST_STATE_NAME).is_file())
                (trust_root / APPLY_MODULE.CODEXQB_TRUST_KEY_NAME).unlink()

                with self.assertRaisesRegex(ValueError, "codexqb_trust_key_recovery_required"):
                    APPLY_MODULE.load_or_create_apply_run_trust_key(create=True)

    def test_preseeded_or_crash_orphan_trust_key_is_never_adopted(self) -> None:
        with temporary_safe_home() as home_dir:
            home = Path(home_dir).resolve()
            home.chmod(0o700)
            trust_root = home / ".codex" / "codexqb-trust"
            with mock.patch.object(
                self._controller_store_module,
                "controller_home_directory",
                return_value=home,
            ):
                trust_fd = APPLY_MODULE.open_codexqb_trust_root_fd(create=True)
                try:
                    APPLY_MODULE.create_apply_run_trust_key(trust_fd)
                finally:
                    os.close(trust_fd)
                self.assertFalse(
                    (trust_root / APPLY_MODULE.CODEXQB_TRUST_STATE_NAME).exists()
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "codexqb_trust_key_recovery_required",
                ):
                    APPLY_MODULE.load_or_create_apply_run_trust_key(create=True)
                self.assertFalse(
                    (trust_root / APPLY_MODULE.CODEXQB_TRUST_STATE_NAME).exists()
                )

    def test_trust_root_fstat_failure_closes_open_descriptor(self) -> None:
        with mock.patch.object(
            APPLY_MODULE,
            "open_controller_trust_root_fd",
            side_effect=OSError("synthetic_trust_root_open_failure"),
        ):
                with self.assertRaisesRegex(ValueError, "codexqb_trust_store_unavailable"):
                    APPLY_MODULE.open_codexqb_trust_root_fd(create=False)

    def test_trust_root_environment_overrides_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as hostile_dir:
            hostile = Path(hostile_dir).resolve()
            hostile.chmod(0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(hostile),
                    "CODEXQB_TRUST_ROOT": str(hostile),
                    "CODEXQB_CONTROLLER_STORE_ROOT": str(hostile),
                },
            ):
                descriptor = APPLY_MODULE.open_codexqb_trust_root_fd(create=True)
                try:
                    opened = os.fstat(descriptor)
                    expected = (
                        self._home_path / ".codex" / "codexqb-trust"
                    ).stat()
                    self.assertEqual((opened.st_dev, opened.st_ino), (expected.st_dev, expected.st_ino))
                finally:
                    os.close(descriptor)

    def test_child_open_helpers_close_descriptor_when_fstat_fails(self) -> None:
        cases = (("directory", APPLY_MODULE.open_child_directory), ("regular", APPLY_MODULE.open_regular_child))
        for kind, helper in cases:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                child = root / "child"
                if kind == "directory":
                    child.mkdir()
                else:
                    child.write_text("sentinel\n", encoding="utf-8")
                parent_fd = os.open(root, APPLY_MODULE.secure_directory_open_flags())
                original_open = os.open
                original_fstat = os.fstat
                opened = {"fd": None}

                def track_child_open(path, flags, *args, **kwargs):
                    descriptor = original_open(path, flags, *args, **kwargs)
                    if path == "child" and kwargs.get("dir_fd") == parent_fd:
                        opened["fd"] = descriptor
                    return descriptor

                def fail_child_fstat(descriptor):
                    if descriptor == opened["fd"]:
                        raise OSError("synthetic_child_fstat_failure")
                    return original_fstat(descriptor)

                try:
                    with mock.patch.object(
                        APPLY_MODULE,
                        "controller_open",
                        side_effect=track_child_open,
                    ), mock.patch.object(
                        APPLY_MODULE,
                        "controller_fstat",
                        side_effect=fail_child_fstat,
                    ):
                        with self.assertRaisesRegex(OSError, "synthetic_child_fstat_failure"):
                            helper(parent_fd, "child")
                    self.assertIsNotNone(opened["fd"])
                    with self.assertRaises(OSError):
                        original_fstat(opened["fd"])
                finally:
                    os.close(parent_fd)

    def test_registry_parent_fstat_failure_closes_registry_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            managed_parent = APPLY_MODULE.managed_apply_runs_root(root)
            registry = managed_parent / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
            registry.mkdir(parents=True, mode=0o700)
            parent_fd = os.open(managed_parent, APPLY_MODULE.secure_directory_open_flags())
            original_open = os.open
            original_fstat = os.fstat
            opened = {"fd": None}

            def track_registry_open(path, flags, *args, **kwargs):
                descriptor = original_open(path, flags, *args, **kwargs)
                if path == APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME and kwargs.get("dir_fd") == parent_fd:
                    opened["fd"] = descriptor
                return descriptor

            def fail_parent_fstat(descriptor):
                if descriptor == parent_fd:
                    raise OSError("synthetic_registry_parent_fstat_failure")
                return original_fstat(descriptor)

            try:
                with mock.patch.object(
                    APPLY_MODULE,
                    "controller_open",
                    side_effect=track_registry_open,
                ), mock.patch.object(
                    APPLY_MODULE,
                    "controller_fstat",
                    side_effect=fail_parent_fstat,
                ):
                    with self.assertRaisesRegex(OSError, "synthetic_registry_parent_fstat_failure"):
                        APPLY_MODULE.open_apply_run_registry_fd(root, parent_fd, create=False)
                self.assertIsNotNone(opened["fd"])
                with self.assertRaises(OSError):
                    original_fstat(opened["fd"])
            finally:
                os.close(parent_fd)

    def test_apply_replace_rejects_manifest_missing_required_field(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            run_path = fixed / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            del run["mode"]
            run_path.write_text(json.dumps(run), encoding="utf-8")

            self.assertIn("apply_run_manifest_missing=mode", APPLY_MODULE.apply_run_manifest_replace_errors(run))
            with self.assertRaisesRegex(ValueError, "replace_requires_existing_apply_run"):
                self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_binds_destructive_open_to_entry_root_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            container = Path(temp_dir)
            root_a = container / "repo-a"
            root_b = container / "repo-b"
            root_a.mkdir()
            root_b.mkdir()
            fixed_by_label: dict[str, Path] = {}
            for root, label in ((root_a, "A"), (root_b, "B")):
                self.write_no_action_fixture(root)
                fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
                self.create_apply_run(root, "no_action", fixed, run_id_suffix=f"first-{label}")
                (fixed / "sentinel.txt").write_text(label, encoding="utf-8")
                fixed_by_label[label] = fixed
            stashed_a = container / "repo-a-stashed"
            original_open = APPLY_MODULE.open_managed_apply_runs_root_fd
            state = {"swapped": False}

            def swap_before_managed_open(
                root,
                *,
                create,
                root_anchor_fd=None,
                root_mount_resolution=None,
                operation=APPLY_MODULE.APPLY_RUN_MUTATION,
            ):
                if not create and not state["swapped"]:
                    state["swapped"] = True
                    root_a.rename(stashed_a)
                    root_b.rename(root_a)
                return original_open(
                    root,
                    create=create,
                    root_anchor_fd=root_anchor_fd,
                    root_mount_resolution=root_mount_resolution,
                    operation=operation,
                )

            with mock.patch.object(
                APPLY_MODULE,
                "open_managed_apply_runs_root_fd",
                side_effect=swap_before_managed_open,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "root_identity_changed|apply_run_controller_state_missing",
                ):
                    self.create_apply_run(
                        root_a,
                        "no_action",
                        APPLY_MODULE.managed_apply_runs_root(root_a) / "fixed",
                        replace=True,
                        run_id_suffix="second",
                    )

            self.assertTrue(state["swapped"])
            self.assertEqual(
                (fixed_by_label["A"] / "sentinel.txt").read_text(encoding="utf-8"),
                "A",
            )
            self.assertEqual(
                (fixed_by_label["B"] / "sentinel.txt").read_text(encoding="utf-8"),
                "B",
            )

    def test_apply_replace_rechecks_late_managed_parent_mount_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            original_match = APPLY_MODULE.opened_directory_matches_path

            def reject_late_parent(path, metadata, *, reject_mount):
                if Path(path).name == "fixed" and reject_mount:
                    return False
                return original_match(path, metadata, reject_mount=reject_mount)

            with mock.patch.object(
                APPLY_MODULE,
                "opened_directory_matches_path",
                side_effect=reject_late_parent,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "indirect_target_rejected|replace_apply_run_tree_contains_indirect_target",
                ):
                    self.create_apply_run(root, "no_action", fixed, replace=True, run_id_suffix="second")

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_requires_destructive_mount_assurance_before_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            real_require = APPLY_MODULE.require_mount_assurance
            operations: list[str] = []

            def reject_destructive(resolution, operation):
                operations.append(operation)
                if operation == APPLY_MODULE.RUN_REPLACE_QUARANTINE_DELETE:
                    raise ValueError("secure_repository_mount_identity_unavailable")
                return real_require(resolution, operation)

            with mock.patch.object(
                APPLY_MODULE,
                "require_mount_assurance",
                side_effect=reject_destructive,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_repository_mount_identity_unavailable",
                ):
                    self.create_apply_run(
                        root,
                        "no_action",
                        fixed,
                        replace=True,
                        run_id_suffix="second",
                    )

            self.assertIn(APPLY_MODULE.RUN_REPLACE_QUARANTINE_DELETE, operations)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_replace_rejects_descriptor_bound_descendant_mount_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            self.create_apply_run(root, "no_action", fixed, run_id_suffix="first")
            mounted = fixed / "mounted"
            mounted.mkdir()
            sentinel = mounted / "sentinel.txt"
            sentinel.write_text("preserve me\n", encoding="utf-8")
            real_require_same_mount = APPLY_MODULE.require_same_mount

            def reject_mounted_child(root_resolution, child_fd, relative_path, **kwargs):
                if str(relative_path).endswith("/mounted"):
                    raise ValueError(f"repository_nested_mount_rejected={relative_path}")
                return real_require_same_mount(
                    root_resolution,
                    child_fd,
                    relative_path,
                    **kwargs,
                )

            with mock.patch.object(
                APPLY_MODULE,
                "require_same_mount",
                side_effect=reject_mounted_child,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "replace_apply_run_tree_contains_indirect_target",
                ):
                    self.create_apply_run(
                        root,
                        "no_action",
                        fixed,
                        replace=True,
                        run_id_suffix="second",
                    )

            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me\n")

    def test_apply_mutation_handle_revalidates_descriptor_mount_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            created = self.create_apply_run(root, "no_action", run_id_suffix="mount-revalidate")
            run_dir = Path(str(created["run_dir"]))

            with APPLY_MODULE.open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
                with mock.patch.object(
                    APPLY_MODULE,
                    "require_same_mount",
                    side_effect=ValueError(
                        "repository_nested_mount_rejected=.codexqb/apply-runs"
                    ),
                ):
                    self.assertFalse(handle.revalidate())

    def test_apply_run_requires_step4_audit_for_action_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaisesRegex(ValueError, "missing_step4_audit"):
                self.create_apply_run(Path(temp_dir), "direct")

    def test_apply_run_blocks_non_git_action_without_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)

            with self.assertRaisesRegex(ValueError, "non_git_workspace_requires_explicit_approval"):
                APPLY_MODULE.create_apply_run(root, "direct")

            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["workspace_mode"], "non_git_unsafe")
            self.assertTrue(run["user_approval"])
            run["user_approval"] = False
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("non_git_workspace_requires_user_approval", errors)

    def test_apply_run_blocks_dirty_or_protected_git_without_explicit_approval(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            self.init_git_repo(root)

            with self.assertRaisesRegex(ValueError, "git_workspace_requires_explicit_current_worktree_approval"):
                APPLY_MODULE.create_apply_run(root, "direct")

            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["workspace_mode"], "unverified_current_worktree")
            self.assertTrue(run["user_approval"])
            self.assertEqual(run["worktree_path"], ".")
            self.assertIn(run["dirty_state"], {"clean", "dirty"})
            self.assertEqual(run["working_branch"], run["workspace_baseline"]["branch"])
            run["user_approval"] = False
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("git_workspace_requires_user_approval", errors)

    def test_apply_run_rejects_unsafe_queue_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task_id = progress["tasks"][0]["task_id"]
            base = dict(progress["tasks"][0]["validation_commands"][0])
            outside_link = root / "outside-link"
            outside_link.symlink_to(Path(outside_dir), target_is_directory=True)
            unsafe_commands = [
                {**base, "argv": ["ruff", "check", "--fix", "."]},
                {**base, "argv": ["pytest", "--basetemp=.git"]},
                {**base, "argv": ["pytest", "--junitxml=.env"]},
                {
                    **base,
                    "argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "--unknown-option"],
                },
                {**base, "argv": ["python3", "-B", "-m", "unittest", "--unknown-option"]},
                {**base, "argv": ["ruff", "check", "--no-fix", "--no-cache", "--unknown-option", "."]},
                {**base, "argv": ["python3.999", "-B", "-m", "unittest", "tests.test_example"]},
                {**base, "exit_code": 0, "output_sha256": VALIDATION_OUTPUT_SHA256},
                {**base, "cwd": "../outside"},
                {**base, "cwd": "outside-link"},
                {**base, "network": "allow", "probe_tier": 3},
                {**base, "probe_tier": 2},
                {**base, "shell": True},
                {"argv": ["sh", "-c", "touch /tmp/codexqb-owned"]},
                ["python3", "-B", "-m", "unittest", "tests.test_example"],
            ]
            for unsafe in unsafe_commands:
                with self.subTest(command=unsafe):
                    progress["tasks"][0]["validation_commands"] = [unsafe]
                    (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
                    errors = APPLY_MODULE.validate_apply_run(run_dir, root)
                    self.assertIn(f"unsafe_validation_command={task_id}", errors)

    def test_apply_validation_binds_evidence_to_the_full_command_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            (root / "safe-subdir").mkdir()
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            reference = progress["tasks"][0]["validation_receipts"][0]
            receipt_path = run_dir / task_id / reference["path"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["command"]["cwd"] = "safe-subdir"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"validation_receipt_mac_invalid={task_id}:VAL-01", errors)
            self.assertNotIn(f"unsafe_validation_command={task_id}", errors)

    def test_apply_final_review_rejects_incomplete_validation_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            final_path = run_dir / "Final-Review.json"
            final = json.loads(final_path.read_text(encoding="utf-8"))
            final["validation_receipts"] = []
            final_path.write_text(json.dumps(final), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("final_review_requires_validation_receipts", errors)

    def test_apply_run_rejects_agent_profile_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            run["agent_profiles"]["task_reviewer"]["sandbox"] = "workspace-write"
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("agent_profile_mismatch=task_reviewer:sandbox", errors)

    def test_transition_cli_appends_events_and_manages_writer_lock(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])

            code = APPLY_MODULE.main(
                [
                    "transition",
                    "--root",
                    str(root),
                    "--run-dir",
                    str(run_dir),
                    "--task-id",
                    self.first_task_id(run_dir),
                    "--to",
                    "IMPLEMENTING",
                    "--actor",
                    "impl-1",
                    "--evidence",
                    "brief accepted",
                ]
            )
            self.assertEqual(code, 0)
            self.assertTrue((run_dir / "Writer-Lock.json").is_file())
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task_id = progress["tasks"][0]["task_id"]
            self.assertEqual(progress["tasks"][0]["state"], "IMPLEMENTING")
            self.assertEqual(progress["active_writer_locks"][0]["task_id"], task_id)

            with self.assertRaisesRegex(ValueError, "invalid_transition=IMPLEMENTING->VERIFIED"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "impl-1", [], root=root)

            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "impl-1", ["implementation complete"], root=root)
            self.assertFalse((run_dir / "Writer-Lock.json").exists())
            events = [
                json.loads(line)
                for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual([event["sequence"] for event in events], [1, 2, 3])
            self.assertEqual(events[-1]["from"], "IMPLEMENTING")
            self.assertEqual(events[-1]["to"], "IMPLEMENTED")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_runtime_predictable_temp_symlink_cannot_modify_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            victim = Path(outside_dir) / "victim.txt"
            victim.write_text("preserve apply victim\n", encoding="utf-8")
            predictable = run_dir / f".Progress.json.tmp-{os.getpid()}"
            predictable.symlink_to(victim)
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            progress["resume_cursor"] = {"probe": "secure-write"}
            before_progress = progress_path.read_bytes()

            with self.assertRaisesRegex(ValueError, "apply_run_provenance_unverified"):
                APPLY_MODULE.atomic_write_json(progress_path, progress, root=root)

            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve apply victim\n")
            self.assertFalse(progress_path.is_symlink())
            self.assertEqual(progress_path.read_bytes(), before_progress)

    def test_event_append_rejects_symlink_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            victim = Path(outside_dir) / "events-victim.jsonl"
            victim.write_text("preserve events victim\n", encoding="utf-8")
            events = run_dir / "Events.jsonl"
            events.unlink()
            events.symlink_to(victim)

            with self.assertRaises(ValueError):
                APPLY_MODULE.append_event(run_dir, {"event_type": "probe", "actor": "test"}, root=root)

            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve events victim\n")
            errors: list[str] = []
            self.assertEqual(APPLY_MODULE.load_events(run_dir, errors), [])
            self.assertEqual(errors, ["invalid_events_jsonl_file"])

    def test_event_append_failure_preserves_existing_log_and_cleans_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            events_path = run_dir / "Events.jsonl"
            before_events = events_path.read_bytes()
            artifact_os = APPLY_MODULE.secure_atomic_write_text_at.__globals__["os"]
            real_replace = artifact_os.replace

            def fail_event_replace(source, destination, *args, **kwargs):
                if destination == "Events.jsonl":
                    raise OSError("synthetic event replace failure")
                return real_replace(source, destination, *args, **kwargs)

            with mock.patch.object(artifact_os, "replace", side_effect=fail_event_replace):
                with self.assertRaisesRegex(OSError, "synthetic event replace failure"):
                    APPLY_MODULE.append_event(run_dir, {"event_type": "probe", "actor": "test"}, root=root)

            self.assertEqual(events_path.read_bytes(), before_events)
            self.assertEqual(
                [path.name for path in run_dir.iterdir() if path.name.startswith(".codexqb-artifact-")],
                [],
            )

    def test_event_append_reconciles_transient_post_replace_directory_fsync_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            artifact_os = APPLY_MODULE.secure_atomic_write_text_at.__globals__["os"]
            real_fsync = artifact_os.fsync
            run_identity = (run_dir.stat().st_dev, run_dir.stat().st_ino)
            failed = False

            def fail_first_run_directory_fsync(file_descriptor):
                nonlocal failed
                metadata = artifact_os.fstat(file_descriptor)
                if (metadata.st_dev, metadata.st_ino) == run_identity and not failed:
                    failed = True
                    raise OSError("synthetic transient directory fsync failure")
                return real_fsync(file_descriptor)

            with mock.patch.object(artifact_os, "fsync", side_effect=fail_first_run_directory_fsync):
                record = APPLY_MODULE.append_event(
                    run_dir,
                    {"event_type": "probe", "actor": "test"},
                root=root,
                )

            events, errors = APPLY_MODULE.parse_chained_event_log(
                (run_dir / "Events.jsonl").read_text(encoding="utf-8")
            )
            self.assertTrue(failed)
            self.assertEqual(errors, [])
            self.assertEqual([event["sequence"] for event in events], [1, 2])
            self.assertEqual(record, events[-1])

    def test_event_append_reports_unknown_state_after_persistent_post_replace_fsync_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            artifact_os = APPLY_MODULE.secure_atomic_write_text_at.__globals__["os"]
            real_fsync = artifact_os.fsync
            run_identity = (run_dir.stat().st_dev, run_dir.stat().st_ino)

            def fail_run_directory_fsync(file_descriptor):
                metadata = artifact_os.fstat(file_descriptor)
                if (metadata.st_dev, metadata.st_ino) == run_identity:
                    raise OSError("synthetic persistent directory fsync failure")
                return real_fsync(file_descriptor)

            with (
                mock.patch.object(artifact_os, "fsync", side_effect=fail_run_directory_fsync),
                mock.patch.object(
                    APPLY_MODULE,
                    "controller_fsync",
                    side_effect=fail_run_directory_fsync,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "^event_log_commit_state_unknown$"):
                    APPLY_MODULE.append_event(
                        run_dir,
                        {"event_type": "probe", "actor": "test"},
                    root=root,
                    )

            events, errors = APPLY_MODULE.parse_chained_event_log(
                (run_dir / "Events.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual(errors, [])
            self.assertEqual([event["sequence"] for event in events], [1, 2])

    def test_transition_unknown_commit_state_is_detected_as_progress_event_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            task_id = self.first_task_id(run_dir)
            artifact_os = APPLY_MODULE.secure_atomic_write_text_at.__globals__["os"]
            real_fsync = artifact_os.fsync
            run_identity = (run_dir.stat().st_dev, run_dir.stat().st_ino)

            def fail_run_directory_fsync(file_descriptor):
                metadata = artifact_os.fstat(file_descriptor)
                if (metadata.st_dev, metadata.st_ino) == run_identity:
                    raise OSError("synthetic persistent directory fsync failure")
                return real_fsync(file_descriptor)

            with (
                mock.patch.object(artifact_os, "fsync", side_effect=fail_run_directory_fsync),
                mock.patch.object(
                    APPLY_MODULE,
                    "controller_fsync",
                    side_effect=fail_run_directory_fsync,
                ),
            ):
                with self.assertRaisesRegex(ValueError, "^event_log_commit_state_unknown$"):
                    APPLY_MODULE.transition_task_state(
                        run_dir,
                        task_id,
                        "BLOCKED",
                        "test",
                        ["synthetic durability fault"],
                    root=root,
                    )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            events, event_errors = APPLY_MODULE.parse_chained_event_log(
                (run_dir / "Events.jsonl").read_text(encoding="utf-8")
            )
            self.assertEqual(progress["tasks"][0]["state"], "BRIEFED")
            self.assertEqual(event_errors, [])
            self.assertEqual([event["sequence"] for event in events], [1, 2])
            self.assertIn(
                f"task_state_unexpected_transition_event={task_id}",
                APPLY_MODULE.validate_apply_run(run_dir, root),
            )

    def test_event_actor_summary_and_evidence_secrets_fail_closed_without_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            events_path = run_dir / "Events.jsonl"
            before = events_path.read_bytes()
            fixture = "sk-" + "E" * 40
            try:
                APPLY_MODULE.append_event(
                    run_dir,
                    {
                        "event_type": "secret_probe",
                        "actor": fixture,
                        "summary": {"evidence": [fixture]},
                    },
                root=root,
                )
            except ValueError as exc:
                if fixture in str(exc):
                    self.fail("event rejection leaked secret fixture")
            else:
                self.fail("event append accepted secret fixture")
            self.assertEqual(events_path.read_bytes(), before)

    def test_external_agent_report_with_secret_is_rejected_on_read_without_echo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            task_id = self.first_task_id(run_dir)
            fixture = "hf" + "_" + "F" * 32
            (run_dir / task_id / "Implementer-Report.json").write_text(
                json.dumps({"status": "PENDING", "summary": fixture}),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)
            joined = "\n".join(errors)
            if fixture in joined:
                self.fail("artifact validation leaked secret fixture")
            self.assertIn(f"invalid_artifact_file={task_id}_implementer_report", errors)

    def test_repository_baseline_rejects_secret_before_base64_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            source = root / "src" / "feature_1_1.py"
            source.parent.mkdir(exist_ok=True)
            fixture = "gl" + "pat-" + "G" * 32
            source.write_text("TOKEN = '" + fixture + "'\n", encoding="utf-8")
            try:
                self.create_apply_run(root, "subagent_serial")
            except ValueError as exc:
                if fixture in str(exc):
                    self.fail("baseline rejection leaked secret fixture")
                self.assertIn("embedded_artifact_secret_rejected", str(exc))
            else:
                self.fail("repository baseline accepted secret fixture")

    def test_repository_baseline_rejects_utf16_secret_before_base64_serialization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            source = root / "src" / "feature_1_1.py"
            source.parent.mkdir(exist_ok=True)
            fixture = "gl" + "pat-" + "U" * 32
            source.write_bytes(fixture.encode("utf-16-le"))
            try:
                self.create_apply_run(root, "subagent_serial")
            except ValueError as exc:
                self.assertNotIn(fixture, str(exc))
                self.assertIn("embedded_artifact_secret_rejected", str(exc))
            else:
                self.fail("UTF-16 repository baseline secret was accepted")

    def test_decoded_repository_baseline_secret_is_rejected_without_echo(self) -> None:
        fixture = ("xox" + "b-" + "H" * 32).encode("utf-8")
        baseline = {
            "snapshot": [
                {
                    "path": "src/example.py",
                    "state": "present",
                    "sha256": APPLY_MODULE.sha256_bytes(fixture),
                    "size": len(fixture),
                }
            ],
            "contents": [
                {
                    "path": "src/example.py",
                    "sha256": APPLY_MODULE.sha256_bytes(fixture),
                    "size": len(fixture),
                    "content_base64": APPLY_MODULE.base64.b64encode(fixture).decode("ascii"),
                }
            ],
        }
        try:
            APPLY_MODULE.baseline_content_map(baseline)
        except ValueError as exc:
            if fixture.decode("utf-8") in str(exc):
                self.fail("decoded baseline rejection leaked secret fixture")
            self.assertEqual(str(exc), "repository_baseline_secret_rejected")
        else:
            self.fail("decoded repository baseline accepted secret fixture")

    def test_apply_cli_exception_output_redacts_secret(self) -> None:
        fixture = "sk-" + "I" * 40
        stderr = io.StringIO()
        with mock.patch.object(APPLY_MODULE, "create_apply_run", side_effect=ValueError("failure=" + fixture)):
            with redirect_stderr(stderr):
                status = APPLY_MODULE.main(["prepare", "--root", "."])
        self.assertEqual(status, 1)
        output = stderr.getvalue()
        if fixture in output:
            self.fail("Apply CLI leaked secret fixture")
        self.assertIn("<redacted:openai_api_key>", output)

    def test_apply_cli_parser_and_help_never_echo_raw_program_or_invalid_secret(self) -> None:
        fixture = "sk-" + "J" * 40
        stderr = io.StringIO()
        with mock.patch.object(sys, "argv", [fixture]):
            with redirect_stderr(stderr):
                with self.assertRaises(SystemExit):
                    APPLY_MODULE.main(["prepare", "--mode", fixture])
        self.assertNotIn(fixture, stderr.getvalue())

        stdout = io.StringIO()
        with mock.patch.object(sys, "argv", [fixture]):
            with redirect_stdout(stdout):
                with self.assertRaisesRegex(SystemExit, "0"):
                    APPLY_MODULE.main(["--help"])
        self.assertNotIn(fixture, stdout.getvalue())

    def test_normalize_writer_rejects_secret_without_partial_artifact_or_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "impl-secret", "spawned", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-secret", root=root)
            report_path = run_dir / task_id / "Implementer-Report.json"
            events_path = run_dir / "Events.jsonl"
            progress_path = run_dir / "Progress.json"
            before = (report_path.read_bytes(), events_path.read_bytes(), progress_path.read_bytes())
            fixture = "hf" + "_" + "K" * 32
            try:
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "impl-secret",
                    {
                        "status": "DONE",
                        "task_id": task_id,
                        "implementer_agent_id": "impl-secret",
                        "files_changed": [],
                        "concerns": [fixture],
                    },
                    "controller",
                root=root,
                )
            except ValueError as exc:
                self.assertNotIn(fixture, str(exc))
            else:
                self.fail("normalize-writer accepted secret-shaped report content")
            self.assertEqual(
                (report_path.read_bytes(), events_path.read_bytes(), progress_path.read_bytes()),
                before,
            )

    def test_normalize_writer_rejects_unknown_schema_fields_without_partial_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "impl-schema", "spawned", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-schema", root=root)
            report_path = run_dir / task_id / "Implementer-Report.json"
            events_path = run_dir / "Events.jsonl"
            progress_path = run_dir / "Progress.json"
            before = (report_path.read_bytes(), events_path.read_bytes(), progress_path.read_bytes())

            with self.assertRaisesRegex(ValueError, "writer_report_unknown_field"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "impl-schema",
                    {
                        "status": "DONE",
                        "task_id": task_id,
                        "implementer_agent_id": "impl-schema",
                        "files_changed": [],
                        "concerns": [],
                        "unexpected_writer_field": "must fail",
                    },
                    "controller",
                root=root,
                )
            self.assertEqual(
                (report_path.read_bytes(), events_path.read_bytes(), progress_path.read_bytes()),
                before,
            )

    def test_validate_rejects_writer_report_changed_after_controller_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir, stop_before_reviews=True)
            task_id = self.first_task_id(run_dir)
            report_path = run_dir / task_id / "Implementer-Report.json"

            baseline_errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)
            self.assertFalse(
                any("writer_report_controller_normalization_required" in item for item in baseline_errors),
                baseline_errors,
            )
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["concerns"] = ["post-normalization mutation"]
            report_path.write_text(json.dumps(report), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)
            self.assertIn(
                f"writer_report_controller_normalization_required={task_id}:implementer",
                errors,
            )

    def test_apply_secret_run_names_fail_before_directory_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            runs_root = APPLY_MODULE.managed_apply_runs_root(root)
            before = set(runs_root.iterdir()) if runs_root.exists() else set()
            fixture = "gl" + "pat-" + "L" * 32
            with self.assertRaisesRegex(ValueError, "secret_like_run_id_suffix"):
                self.create_apply_run(root, "subagent_serial", run_id_suffix=fixture)
            explicit = runs_root / ("apply-" + fixture)
            with self.assertRaisesRegex(ValueError, "secret_like_run_directory_name"):
                self.create_apply_run(
                    root,
                    "subagent_serial",
                    explicit,
                    run_id_suffix="safe-name",
                )
            after = set(runs_root.iterdir()) if runs_root.exists() else set()
            self.assertEqual(after, before)

    def test_secret_rejected_replacement_preserves_existing_apply_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed-secret-preflight"
            self.create_apply_run(root, "subagent_serial", fixed, run_id_suffix="first")
            sentinel = fixed / "sentinel.txt"
            sentinel.write_text("preserve existing run\n", encoding="utf-8")
            before_run = (fixed / "Apply-Run.json").read_bytes()
            fixture = "sk-" + "M" * 40
            source = root / "src" / "feature_1_1.py"
            source.parent.mkdir(exist_ok=True)
            source.write_text("TOKEN = '" + fixture + "'\n", encoding="utf-8")
            try:
                self.create_apply_run(
                    root,
                    "subagent_serial",
                    fixed,
                    replace=True,
                    run_id_suffix="replacement",
                )
            except ValueError as exc:
                self.assertNotIn(fixture, str(exc))
                self.assertIn("embedded_artifact_secret_rejected", str(exc))
            else:
                self.fail("secret-bearing replacement candidate was accepted")
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve existing run\n")
            self.assertEqual((fixed / "Apply-Run.json").read_bytes(), before_run)

    def test_runtime_mutation_rejects_unmanaged_copied_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            copied = Path(outside_dir) / "copied-run"
            shutil.copytree(run_dir, copied)
            task_id = self.first_task_id(copied)
            before_events = (copied / "Events.jsonl").read_text(encoding="utf-8")

            with self.assertRaises(ValueError):
                APPLY_MODULE.transition_task_state(copied, task_id, "IMPLEMENTING", "impl-1", ["probe"], root=root)

            self.assertEqual((copied / "Events.jsonl").read_text(encoding="utf-8"), before_events)
            progress = json.loads((copied / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"][0]["state"], "BRIEFED")
            self.assertFalse((copied / "Writer-Lock.json").exists())

    def test_parallel_event_appends_are_unique_and_contiguous(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            worker_count = 16
            context = multiprocessing.get_context("fork")
            barrier = context.Barrier(worker_count)
            processes = [
                context.Process(
                    target=append_event_worker,
                    args=(str(root), str(run_dir), index, barrier),
                )
                for index in range(worker_count)
            ]
            for process in processes:
                process.start()
            for process in processes:
                process.join(15)
                if process.is_alive():
                    process.terminate()
                    process.join(5)
                self.assertEqual(process.exitcode, 0)

            events = [
                json.loads(line)
                for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual([event["sequence"] for event in events], list(range(1, worker_count + 2)))
            previous_hash = APPLY_MODULE.EVENT_CHAIN_GENESIS_SHA256
            for event in events:
                self.assertEqual(event["event_chain_version"], APPLY_MODULE.EVENT_CHAIN_VERSION)
                self.assertEqual(event["previous_event_sha256"], previous_hash)
                claimed_hash = event["event_sha256"]
                digest_input = dict(event)
                digest_input.pop("event_sha256")
                self.assertEqual(claimed_hash, APPLY_MODULE.canonical_json_digest(digest_input))
                previous_hash = claimed_hash

    def test_event_chain_rejects_tamper_and_reserved_field_injection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            APPLY_MODULE.append_event(run_dir, {"event_type": "probe-one", "actor": "test"}, root=root)
            APPLY_MODULE.append_event(run_dir, {"event_type": "probe-two", "actor": "test"}, root=root)

            with self.assertRaisesRegex(ValueError, "event_reserved_field_forbidden"):
                APPLY_MODULE.append_event(
                    run_dir,
                    {"event_type": "probe-three", "actor": "test", "sequence": 99},
                root=root,
                )

            events_path = run_dir / "Events.jsonl"
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
            events[1]["actor"] = "tampered"
            events_path.write_text(
                "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                encoding="utf-8",
            )

            self.assertIn("invalid_event_hash=line-2", APPLY_MODULE.validate_apply_run(run_dir, root))
            with self.assertRaisesRegex(ValueError, "invalid_event_hash=line-2"):
                APPLY_MODULE.append_event(run_dir, {"event_type": "must-not-append", "actor": "test"}, root=root)

    def test_event_chain_rejects_rehashed_schema_invalid_core_fields(self) -> None:
        cases = (
            ("sequence", True, "invalid_event_sequence=line-1"),
            ("event_chain_version", True, "invalid_event_chain_version=line-1"),
            ("timestamp", "bad", "invalid_event_timestamp=line-1"),
            ("event_type", 7, "invalid_event_type=line-1"),
            ("actor", 7, "invalid_event_actor=line-1"),
            ("apply_run_id", "bad", "invalid_event_apply_run_id=line-1"),
            ("task_id", "bad", "invalid_event_task_id=line-1"),
        )
        for field, value, expected in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
                events_path = run_dir / "Events.jsonl"
                events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
                events[0][field] = value
                events_path.write_text(serialize_rehashed_events(events), encoding="utf-8")
                self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))
                with self.assertRaisesRegex(ValueError, expected):
                    APPLY_MODULE.append_event(
                        run_dir,
                        {"event_type": "must-not-append", "actor": "test"},
                    root=root,
                    )

    def test_event_chain_binds_initial_event_to_run_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            events_path = run_dir / "Events.jsonl"
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
            events[0]["apply_run_id"] = "apply-direct-000000000000-other"
            events_path.write_text(serialize_rehashed_events(events), encoding="utf-8")

            self.assertIn(
                "initial_event_apply_run_id_mismatch",
                APPLY_MODULE.validate_apply_run(run_dir, root),
            )
            with self.assertRaisesRegex(ValueError, "^initial_event_apply_run_id_mismatch$"):
                APPLY_MODULE.append_event(
                    run_dir,
                    {"event_type": "must-not-append", "actor": "test"},
                root=root,
                )

    def test_event_append_rejects_schema_invalid_optional_fields_before_write(self) -> None:
        cases = (
            ({"event_type": "probe", "actor": 7}, "event_actor_invalid"),
            ({"event_type": "probe", "apply_run_id": "bad"}, "event_apply_run_id_invalid"),
            ({"event_type": "probe", "task_id": "bad"}, "event_task_id_invalid"),
        )
        for event, expected in cases:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
                events_path = run_dir / "Events.jsonl"
                before = events_path.read_bytes()

                with self.assertRaisesRegex(ValueError, f"^{expected}$"):
                    APPLY_MODULE.append_event(run_dir, event, root=root)

                self.assertEqual(events_path.read_bytes(), before)

    def test_event_log_rejects_partial_bad_json_and_sequence_collision(self) -> None:
        cases = (
            ("partial", lambda text: text.rstrip("\n"), "invalid_event_log_partial_line"),
            ("bad-json", lambda text: text + "{bad-json}\n", "invalid_event_json=line-2"),
            (
                "sequence-collision",
                lambda text: text + text.splitlines()[0] + "\n",
                "invalid_event_sequence=line-2",
            ),
        )
        for label, mutate, expected in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
                events_path = run_dir / "Events.jsonl"
                events_path.write_text(mutate(events_path.read_text(encoding="utf-8")), encoding="utf-8")
                self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))
                before = events_path.read_bytes()
                with self.assertRaisesRegex(ValueError, expected):
                    APPLY_MODULE.append_event(run_dir, {"event_type": "must-not-append", "actor": "test"}, root=root)
                self.assertEqual(events_path.read_bytes(), before)

    def test_event_log_rejects_duplicate_key_blank_line_broken_link_and_invalid_utf8(self) -> None:
        text_cases = (
            (
                "duplicate-key",
                lambda text: text.splitlines()[0][:-1] + ',"sequence":999}\n',
                "invalid_event_json=line-1",
            ),
            ("blank-line", lambda text: text + "\n", "invalid_event_blank_line=line-2"),
        )
        for label, mutate, expected in text_cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
                events_path = run_dir / "Events.jsonl"
                events_path.write_text(
                    mutate(events_path.read_text(encoding="utf-8")),
                    encoding="utf-8",
                )
                self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))
                before = events_path.read_bytes()
                with self.assertRaisesRegex(ValueError, expected):
                    APPLY_MODULE.append_event(run_dir, {"event_type": "must-not-append", "actor": "test"}, root=root)
                self.assertEqual(events_path.read_bytes(), before)

        with self.subTest(label="broken-previous-hash"), tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            APPLY_MODULE.append_event(run_dir, {"event_type": "probe", "actor": "test"}, root=root)
            events_path = run_dir / "Events.jsonl"
            events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines()]
            events[1]["previous_event_sha256"] = "f" * 64
            events[1].pop("event_sha256")
            events[1]["event_sha256"] = APPLY_MODULE.canonical_json_digest(events[1])
            events_path.write_text(
                "".join(json.dumps(event, sort_keys=True) + "\n" for event in events),
                encoding="utf-8",
            )
            expected = "invalid_event_previous_hash=line-2"
            self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))
            with self.assertRaisesRegex(ValueError, expected):
                APPLY_MODULE.append_event(run_dir, {"event_type": "must-not-append", "actor": "test"}, root=root)

        with self.subTest(label="invalid-utf8"), tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            events_path = run_dir / "Events.jsonl"
            events_path.write_bytes(b"\xff\n")
            before = events_path.read_bytes()
            self.assertIn("invalid_events_jsonl_file", APPLY_MODULE.validate_apply_run(run_dir, root))
            with self.assertRaisesRegex(ValueError, "^invalid_event_log_utf8$"):
                APPLY_MODULE.append_event(run_dir, {"event_type": "must-not-append", "actor": "test"}, root=root)
            self.assertEqual(events_path.read_bytes(), before)

    def test_unkeyed_event_chain_does_not_claim_valid_tail_truncation_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "direct")["run_dir"])
            APPLY_MODULE.append_event(run_dir, {"event_type": "probe-one", "actor": "test"}, root=root)
            APPLY_MODULE.append_event(run_dir, {"event_type": "probe-two", "actor": "test"}, root=root)
            events_path = run_dir / "Events.jsonl"
            complete_lines = events_path.read_text(encoding="utf-8").splitlines()
            events_path.write_text("\n".join(complete_lines[:-1]) + "\n", encoding="utf-8")

            events, errors = APPLY_MODULE.parse_chained_event_log(
                events_path.read_text(encoding="utf-8")
            )
            self.assertEqual(errors, [])
            self.assertEqual(len(events), 2)
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])

    def test_validate_rejects_state_without_transition_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task_id = progress["tasks"][0]["task_id"]
            progress["tasks"][0]["state"] = "IMPLEMENTED"
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn(f"task_state_missing_transition_event={task_id}", errors)

    def test_validate_rejects_missing_writer_lock_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)
            (run_dir / "Writer-Lock.json").unlink()

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("active_writer_lock_missing_file", errors)

    def test_recover_stale_writer_lock_moves_task_to_needs_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)

            lock_path = run_dir / "Writer-Lock.json"
            stale_lock = json.loads(lock_path.read_text(encoding="utf-8"))
            stale_lock["acquired_at"] = "2000-01-01T00:00:00Z"
            lock_path.write_text(json.dumps(stale_lock), encoding="utf-8")
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["active_writer_locks"] = [stale_lock]
            progress["tasks"][0]["writer_lock"] = stale_lock
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")

            self.assertIn(f"writer_lock_expired={task_id}", APPLY_MODULE.validate_apply_run(run_dir, root=root))
            event = APPLY_MODULE.recover_stale_writer_lock(
                run_dir,
                task_id,
                "NEEDS_CONTEXT",
                "controller",
                ["implementation worker abandoned stale lock"],
            root=root,
            )
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))

            self.assertEqual(event["recovery"], "stale_writer_lock")
            self.assertEqual(event["from"], "IMPLEMENTING")
            self.assertEqual(event["to"], "NEEDS_CONTEXT")
            self.assertFalse(lock_path.exists())
            self.assertEqual(progress["tasks"][0]["state"], "NEEDS_CONTEXT")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_recover_stale_writer_lock_rejects_unmanaged_copy_before_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)

            lock_path = run_dir / "Writer-Lock.json"
            stale_lock = json.loads(lock_path.read_text(encoding="utf-8"))
            stale_lock["acquired_at"] = "2000-01-01T00:00:00Z"
            lock_path.write_text(json.dumps(stale_lock), encoding="utf-8")
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            progress["active_writer_locks"] = [stale_lock]
            progress["tasks"][0]["writer_lock"] = stale_lock
            progress_path.write_text(json.dumps(progress), encoding="utf-8")
            copied = Path(outside_dir) / "copied-run"
            shutil.copytree(run_dir, copied)
            before_events = (copied / "Events.jsonl").read_bytes()
            before_progress = (copied / "Progress.json").read_bytes()

            with self.assertRaises(ValueError):
                APPLY_MODULE.recover_stale_writer_lock(
                    copied,
                    task_id,
                    "NEEDS_CONTEXT",
                    "controller",
                    ["probe"],
                root=root,
                )

            self.assertTrue((copied / "Writer-Lock.json").is_file())
            self.assertEqual((copied / "Events.jsonl").read_bytes(), before_events)
            self.assertEqual((copied / "Progress.json").read_bytes(), before_progress)

    def test_recover_stale_writer_lock_rejects_symlink_lock_without_touching_victim(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", ["started"], root=root)

            lock_path = run_dir / "Writer-Lock.json"
            stale_lock = json.loads(lock_path.read_text(encoding="utf-8"))
            stale_lock["acquired_at"] = "2000-01-01T00:00:00Z"
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            progress["active_writer_locks"] = [stale_lock]
            progress["tasks"][0]["writer_lock"] = stale_lock
            progress_path.write_text(json.dumps(progress), encoding="utf-8")
            victim = Path(outside_dir) / "writer-lock-victim.json"
            victim.write_text(json.dumps(stale_lock), encoding="utf-8")
            before_victim = victim.read_bytes()
            before_events = (run_dir / "Events.jsonl").read_bytes()
            lock_path.unlink()
            lock_path.symlink_to(victim)

            with self.assertRaises(ValueError):
                APPLY_MODULE.recover_stale_writer_lock(
                    run_dir,
                    task_id,
                    "NEEDS_CONTEXT",
                    "controller",
                    ["probe"],
                root=root,
                )

            self.assertTrue(lock_path.is_symlink())
            self.assertEqual(victim.read_bytes(), before_victim)
            self.assertEqual((run_dir / "Events.jsonl").read_bytes(), before_events)

    def test_apply_run_enforces_review_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task_id = progress["tasks"][0]["task_id"]
            progress["tasks"][0]["state"] = "TASK_REVIEW"
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            review = {
                "spec_compliance": "fail",
                "task_quality": "needs_fixes",
                "blocking_findings": ["missing acceptance behavior"],
                "re_review_required": True,
            }
            (run_dir / task_id / "Task-Review.json").write_text(json.dumps(review), encoding="utf-8")
            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)
            self.assertIn(f"re_review_requires_fix_report={task_id}", errors)

    def test_apply_run_rejects_non_ready_p0_p1_and_policy_violations(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            run["max_writer_agents"] = 2
            run["max_subagent_depth"] = 2
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["tasks"][0]["readiness_status"] = "BLOCKED"
            progress["tasks"][0]["finding_ids"] = ["P1"]
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            task_id = progress["tasks"][0]["task_id"]

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("only_one_writer_permitted", errors)
            self.assertIn("recursive_subagents_rejected", errors)
            self.assertIn(f"non_ready_queue_item={task_id}:BLOCKED", errors)
            self.assertIn(f"p0_p1_queue_item_rejected={task_id}", errors)

    def test_apply_run_requires_security_review_and_final_review_for_verified_task(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["tasks"][0]["state"] = "VERIFIED"
            progress["tasks"][0]["security_review_required"] = True
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            task_id = progress["tasks"][0]["task_id"]
            (run_dir / task_id / "Implementer-Report.json").write_text(
                json.dumps({"status": "DONE", "implementer_agent_id": "impl-1"}),
                encoding="utf-8",
            )
            (run_dir / task_id / "Task-Review.json").write_text(
                json.dumps({"spec_compliance": "pass", "task_quality": "approved", "security_review": "not_required"}),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn(f"security_review_receipt_missing={task_id}", errors)
            self.assertIn(f"security_reviewer_agent_run_missing={task_id}", errors)
            self.assertIn("final_review_required", errors)

            trusted = self.create_apply_run(root, "subagent_serial", run_id_suffix="trusted-review")
            trusted_dir = Path(trusted["run_dir"])
            self.complete_subagent_serial_verification(root, trusted_dir)
            self.assertEqual(APPLY_MODULE.validate_apply_run(trusted_dir, root=root), [])

    def test_finalize_rejects_controller_evidence_without_host_agent_attestation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])

            with self.assertRaisesRegex(ValueError, "finalize_requires_all_tasks_verified"):
                APPLY_MODULE.finalize_apply_run(run_dir, "controller", ["attempted early finalize"], root=root)

            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])
            with self.assertRaisesRegex(
                ValueError,
                f"trusted_verified_requires_host_agent_attestation={task_id}",
            ):
                APPLY_MODULE.transition_task_state(
                    run_dir,
                    task_id,
                    "VERIFIED",
                    "controller",
                    ["controller evidence complete but unattested"],
                root=root,
                )
            with self.assertRaisesRegex(ValueError, "finalize_requires_all_tasks_verified"):
                APPLY_MODULE.finalize_apply_run(run_dir, "controller", ["host proof absent"], root=root)
            result_payload = json.loads((run_dir / "Result.json").read_text(encoding="utf-8"))

            self.assertEqual(result_payload["status"], "initialized")
            self.assertEqual(result_payload["completed_tasks"], [])
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])

    def test_finalize_rejects_result_symlink_before_publishing_event(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            result = self.create_apply_run(root, "no_action")
            run_dir = Path(result["run_dir"])
            result_path = run_dir / "Result.json"
            victim = Path(outside_dir) / "result-victim.json"
            victim.write_bytes(result_path.read_bytes())
            before_victim = victim.read_bytes()
            before_events = (run_dir / "Events.jsonl").read_bytes()
            before_progress = (run_dir / "Progress.json").read_bytes()
            result_path.unlink()
            result_path.symlink_to(victim)

            with self.assertRaises(ValueError):
                APPLY_MODULE.finalize_apply_run(run_dir, "controller", ["probe"], root=root)

            self.assertTrue(result_path.is_symlink())
            self.assertEqual(victim.read_bytes(), before_victim)
            self.assertEqual((run_dir / "Events.jsonl").read_bytes(), before_events)
            self.assertEqual((run_dir / "Progress.json").read_bytes(), before_progress)

    def test_apply_run_snapshot_mismatch_blocks_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            docs = root / "Planner-docs"
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            (docs / "Sub-Planing-Audit.md").write_text("changed\n", encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("source_snapshot_mismatch", errors)

    def test_apply_validation_rejects_unmanaged_copy_before_artifact_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            copied = Path(outside_dir) / "copied-apply-run"
            shutil.copytree(run_dir, copied)

            with mock.patch.object(
                APPLY_MODULE,
                "load_json",
                side_effect=AssertionError("unmanaged artifact was read"),
            ) as reader:
                errors = APPLY_MODULE.validate_apply_run(copied, root=root)
            reader.assert_not_called()
            self.assertTrue(
                any(
                    error.startswith("repository_io_failed=invalid_apply_run_output_dir")
                    for error in errors
                )
            )

    def test_repository_local_legacy_apply_run_is_archive_only_and_unread(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            legacy = root / ".codexqb" / "apply-runs" / "legacy-run"
            legacy.mkdir(parents=True)
            (legacy / "Apply-Run.json").write_text(
                '{"sentinel":"must-not-be-read"}\n',
                encoding="utf-8",
            )
            with mock.patch.object(
                APPLY_MODULE,
                "load_json",
                side_effect=AssertionError("legacy artifact was read"),
            ) as reader:
                errors = APPLY_MODULE.validate_apply_run(legacy, root=root)
            reader.assert_not_called()
            self.assertIn(
                "repository_io_failed=legacy_apply_run_archive_only",
                errors,
            )

    def test_apply_run_workspace_baseline_detects_non_git_source_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            (root / "src").mkdir()
            (root / "src" / "example.py").write_text("print('before')\n", encoding="utf-8")
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            (root / "src" / "example.py").write_text("print('after')\n", encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=workspace_file_inventory_sha256", errors)

    def test_step4_ledger_update_does_not_break_apply_resume(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            docs = root / "Planner-docs"
            write_ledger(docs)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            ledger = docs / "Planing-Ledger.md"
            ledger.write_text(ledger.read_text(encoding="utf-8") + "\nStep 4 expected ledger update.\n", encoding="utf-8")

            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])

    def test_apply_run_workspace_baseline_detects_git_untracked_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            self.init_git_repo(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])
            (root / "notes.txt").write_text("new local note\n", encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=git_status_porcelain_sha256", errors)
            self.assertIn("workspace_baseline_mismatch=untracked_inventory_sha256", errors)

    def test_apply_git_evidence_never_executes_configured_external_diff(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_git_repo(root)
            tracked = root / "tracked.txt"
            tracked.write_text("before\n", encoding="utf-8")
            subprocess.run(["git", "add", "tracked.txt"], cwd=root, check=True, capture_output=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
            )
            marker = root / "external-diff-ran"
            external_diff = root / "external-diff"
            external_diff.write_text(
                "#!/bin/sh\n"
                f"touch '{marker.as_posix()}'\n"
                "exit 0\n",
                encoding="utf-8",
            )
            external_diff.chmod(0o755)
            subprocess.run(
                ["git", "config", "diff.external", external_diff.as_posix()],
                cwd=root,
                check=True,
                capture_output=True,
            )
            tracked.write_text("after\n", encoding="utf-8")

            with self.assertRaisesRegex(
                ValueError,
                "repository_io_workspace_proof_failed",
            ):
                APPLY_MODULE.workspace_baseline(root)

            self.assertFalse(marker.exists())

    def test_apply_run_allows_contract_bound_tracked_implementation_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            (root / "src").mkdir()
            (root / "tests").mkdir()
            (root / "src" / "feature_1_1.py").write_text("VALUE = 'before'\n", encoding="utf-8")
            (root / "src" / "outside.py").write_text("VALUE = 'outside-before'\n", encoding="utf-8")
            (root / "tests" / "test_feature_1_1.py").write_text(
                "import unittest\n\nclass FeatureTests(unittest.TestCase):\n    def test_placeholder(self):\n        self.assertTrue(True)\n",
                encoding="utf-8",
            )
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)

            (root / "src" / "__pycache__").mkdir()
            (root / "src" / "__pycache__" / "feature_1_1.cpython-314.pyc").write_bytes(b"cache")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])

            (root / "src" / "outside.py").write_text("VALUE = 'outside-after'\n", encoding="utf-8")
            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=git_status_porcelain_sha256", errors)
            self.assertIn("source_snapshot_mismatch", errors)

    def test_apply_run_allows_contract_bound_proposed_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)

            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])

            (root / "src" / "outside_new.py").write_text("VALUE = 'outside'\n", encoding="utf-8")
            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=untracked_inventory_sha256", errors)
            self.assertIn("source_snapshot_mismatch", errors)

    def test_apply_run_verified_task_is_not_redispatched(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["tasks"][0]["state"] = "VERIFIED"
            progress["tasks"][0]["redispatch_count"] = 1
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            task_id = progress["tasks"][0]["task_id"]

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn(f"verified_task_not_redispatched={task_id}", errors)

    def test_external_superpowers_unavailable_requires_safe_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "external_superpowers")
            run_dir = Path(result["run_dir"])
            self.assertIn("external_superpowers_readiness_not_checked", APPLY_MODULE.validate_apply_run(run_dir, root=root))
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            run["external_superpowers"]["availability"] = "unavailable"
            run["external_superpowers"]["fallback_mode"] = "direct"
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("external_superpowers_unavailable_requires_subagent_serial_fallback", errors)
            self.assertIn("external_superpowers_unavailable_must_reconcile_mode", errors)
            run["external_superpowers"]["fallback_mode"] = "subagent_serial"
            (run_dir / "Apply-Run.json").write_text(json.dumps(run), encoding="utf-8")
            self.assertIn("external_superpowers_unavailable_must_reconcile_mode", APPLY_MODULE.validate_apply_run(run_dir, root=root))
            reconciled = APPLY_MODULE.reconcile_external_superpowers(run_dir, root=root)

            self.assertEqual(reconciled["state"], "reconciled")
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))
            self.assertEqual(run["mode"], "subagent_serial")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])
            replacement = self.create_apply_run(
                root,
                "direct",
                run_dir,
                replace=True,
                run_id_suffix="replacement",
            )
            self.assertEqual(replacement["state"], "initialized")

    def test_external_superpowers_available_refreshes_replace_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "external_superpowers")
            run_dir = Path(result["run_dir"])
            run_path = run_dir / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["external_superpowers"].update(
                {
                    "availability": "available",
                    "version": "synthetic-test-version",
                    "source_path": "/synthetic/test/adapter",
                    "license_acknowledged": True,
                }
            )
            run_path.write_text(json.dumps(run), encoding="utf-8")

            reconciled = APPLY_MODULE.reconcile_external_superpowers(run_dir, root=root)

            self.assertEqual(reconciled, {"state": "ready", "mode": "external_superpowers"})
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])
            replacement = self.create_apply_run(
                root,
                "direct",
                run_dir,
                replace=True,
                run_id_suffix="replacement",
            )
            self.assertEqual(replacement["state"], "initialized")

    def test_external_superpowers_reconcile_recovers_partial_provenance_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "external_superpowers")
            run_dir = Path(result["run_dir"])
            run_path = run_dir / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["external_superpowers"]["availability"] = "unavailable"
            run["external_superpowers"]["fallback_mode"] = "subagent_serial"
            run_path.write_text(json.dumps(run), encoding="utf-8")
            registration_name = APPLY_MODULE.apply_run_registration_file_name(run_dir.name)
            original_replace = APPLY_MODULE.write_regular_json_replace_at
            state = {"failed": False}

            def fail_registration_refresh_once(directory_fd, name, payload):
                if name == registration_name and not state["failed"]:
                    state["failed"] = True
                    raise OSError("synthetic_registration_refresh_failure")
                return original_replace(directory_fd, name, payload)

            with mock.patch.object(
                APPLY_MODULE,
                "write_regular_json_replace_at",
                side_effect=fail_registration_refresh_once,
            ):
                with self.assertRaisesRegex(OSError, "synthetic_registration_refresh_failure"):
                    APPLY_MODULE.reconcile_external_superpowers(run_dir, root=root)

            recovered = APPLY_MODULE.reconcile_external_superpowers(run_dir, root=root)

            self.assertTrue(state["failed"])
            self.assertEqual(recovered["state"], "reconciled")
            self.assertTrue(recovered["recovered"])
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root=root), [])
            replacement = self.create_apply_run(
                root,
                "direct",
                run_dir,
                replace=True,
                run_id_suffix="replacement",
            )
            self.assertEqual(replacement["state"], "initialized")

    def test_apply_run_rejects_task_id_traversal_and_no_action_queue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_no_action_fixture(root)
            no_action = self.create_apply_run(root, "no_action")
            run_dir = Path(no_action["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["tasks"] = [{"task_id": "../../outside-task", "state": "BRIEFED", "readiness_status": "READY"}]
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("no_action_must_not_have_tasks", errors)
            self.assertIn("invalid_task_id=../../outside-task", errors)

    def test_apply_run_does_not_overwrite_existing_progress_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            first = self.create_apply_run(root, "direct", run_id_suffix="one")
            second = self.create_apply_run(root, "direct", run_id_suffix="two")
            first_run = json.loads((Path(first["run_dir"]) / "Apply-Run.json").read_text(encoding="utf-8"))
            second_run = json.loads((Path(second["run_dir"]) / "Apply-Run.json").read_text(encoding="utf-8"))

            self.assertEqual(first_run["apply_spec_inputs"]["workspace_baseline"], first_run["workspace_baseline"])
            self.assertEqual(first_run["apply_spec_id"], second_run["apply_spec_id"])
            self.assertNotEqual(first["apply_run_id"], second["apply_run_id"])

            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
            fixed_result = self.create_apply_run(root, "direct", fixed)
            with self.assertRaises(ValueError):
                self.create_apply_run(root, "direct", fixed)

            resumed = self.create_apply_run(root, "direct", fixed, resume=True)
            self.assertEqual(resumed["run_dir"], fixed_result["run_dir"])

    def test_legacy_schema_v1_and_v2_runs_are_archive_only(self) -> None:
        for legacy_version in (1, 2):
            with self.subTest(legacy_version=legacy_version), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"
                with mock.patch.object(APPLY_MODULE, "APPLY_RUN_SCHEMA_VERSION", legacy_version):
                    self.create_apply_run(root, "direct", fixed)
                run_path = fixed / "Apply-Run.json"
                run = json.loads(run_path.read_text(encoding="utf-8"))
                self.assertEqual(run["apply_run_schema_version"], legacy_version)

                errors = APPLY_MODULE.validate_apply_run(fixed, root)
                self.assertIn("invalid_apply_run_schema_version", errors)
                with self.assertRaisesRegex(ValueError, "invalid_apply_run_schema_version"):
                    self.create_apply_run(root, "direct", fixed, resume=True)
                with self.assertRaisesRegex(
                    ValueError,
                    r"(?:invalid_apply_run_schema_version|apply_run_provenance_unverified)",
                ):
                    APPLY_MODULE.finalize_apply_run(fixed, "controller", root=root)

                del run["apply_run_registration_id"]
                run_path.write_text(json.dumps(run), encoding="utf-8")
                registration = (
                    fixed.parent
                    / APPLY_MODULE.APPLY_RUN_REGISTRY_DIR_NAME
                    / APPLY_MODULE.apply_run_registration_file_name(fixed.name)
                )
                registration.unlink()
                (fixed / APPLY_MODULE.APPLY_RUN_MARKER_NAME).unlink()
                sentinel = fixed / "sentinel.txt"
                sentinel.write_text("preserve legacy run\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, r"replace_requires_(?:existing|registered)_apply_run"):
                    self.create_apply_run(root, "direct", fixed, replace=True, run_id_suffix="replacement")
                self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve legacy run\n")

    def test_apply_spec_digest_includes_workspace_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            run_path = run_dir / "Apply-Run.json"
            run = json.loads(run_path.read_text(encoding="utf-8"))
            run["apply_spec_inputs"]["workspace_baseline"]["untracked_count"] = 999
            run_path.write_text(json.dumps(run), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn("stored_apply_spec_digest_mismatch", errors)
            self.assertIn("stored_apply_spec_id_mismatch", errors)
            self.assertIn("stored_apply_run_id_mismatch", errors)
            self.assertIn("apply_spec_workspace_baseline_mismatch=untracked_count", errors)

    def test_verified_task_requires_evidence_bearing_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            progress["tasks"][0]["state"] = "VERIFIED"
            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            task_id = progress["tasks"][0]["task_id"]
            (run_dir / task_id / "Implementer-Report.json").write_text(json.dumps({"status": "DONE"}), encoding="utf-8")
            (run_dir / task_id / "Task-Review.json").write_text(
                json.dumps({"spec_compliance": "pass", "task_quality": "approved", "security_review": "not_required"}),
                encoding="utf-8",
            )
            (run_dir / "Final-Review.json").write_text(json.dumps({"status": "pass"}), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root=root)

            self.assertIn(f"verified_requires_files_changed={task_id}", errors)
            self.assertIn(f"verified_missing_validation_receipt={task_id}:VAL-01", errors)
            self.assertIn(f"change_set_missing={task_id}", errors)
            self.assertIn(f"verified_requires_review_receipt_aggregate={task_id}", errors)

    def test_verified_task_rejects_inconsistent_patch_and_validation_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            report_path = run_dir / task_id / "Implementer-Report.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["files_changed"] = ["src/unapproved.py"]
            report["diff_sha256"] = "0" * 64
            report_path.write_text(json.dumps(report), encoding="utf-8")
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            reference = progress["tasks"][0]["validation_receipts"][0]
            receipt_path = run_dir / task_id / reference["path"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["command"]["validation_id"] = "VAL-99"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            (run_dir / task_id / "Review-Package.patch").write_text(
                "diff --git a/src/feature_1_1.py b/src/feature_1_1.py\n--- a/src/feature_1_1.py\n+++ b/src/feature_1_1.py\n@@ -0,0 +1 @@\n+VALUE = 1\n",
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"verified_diff_hash_mismatch={task_id}", errors)
            self.assertIn(f"verified_files_changed_not_contract_bound={task_id}:src/unapproved.py", errors)
            self.assertIn(f"verified_patch_files_mismatch={task_id}", errors)
            self.assertIn(f"verified_live_diff_mismatch={task_id}", errors)

    def test_verified_rejects_fabricated_patch_when_live_diff_is_empty(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            claimed_path = root / "src" / "feature_1_1.py"
            if claimed_path.exists():
                claimed_path.unlink()

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"verified_live_diff_mismatch={task_id}", errors)

    def test_verified_invalidates_evidence_after_contract_file_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            self.init_git_repo(root)
            subprocess.run(["git", "config", "user.name", "CodexQB Test"], cwd=root, check=True)
            subprocess.run(["git", "config", "user.email", "codexqb-test@example.invalid"], cwd=root, check=True)
            subprocess.run(["git", "add", "."], cwd=root, check=True)
            subprocess.run(["git", "commit", "-m", "fixture"], cwd=root, check=True, capture_output=True, text=True)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            target = root / "src" / "feature_1_1.py"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("VALUE = 'changed-after-evidence'\n", encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"verified_repository_state_digest_mismatch={task_id}", errors)

    def test_verified_requires_receipt_for_every_planned_validation_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            text = subplan.read_text(encoding="utf-8")
            needle = '      "probe_tier": 1\n    }\n  ],'
            second = "\n".join(
                [
                    '      "probe_tier": 1',
                    "    },",
                    "    {",
                    '      "id": "VAL-02",',
                    '      "argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"],',
                    '      "cwd": ".",',
                    '      "expected_exit_code": 0,',
                    '      "timeout_seconds": 120,',
                    '      "network": "deny",',
                    '      "probe_tier": 1',
                    "    }",
                    "  ],",
                ]
            )
            self.assertIn(needle, text)
            subplan.write_text(text.replace(needle, second, 1), encoding="utf-8")
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            progress["tasks"][0]["validation_receipts"] = [
                item
                for item in progress["tasks"][0]["validation_receipts"]
                if item.get("validation_id") != "VAL-02"
            ]
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"verified_missing_validation_receipt={task_id}:VAL-02", errors)

    def test_verified_rejects_cross_run_validation_receipt_reuse(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            first = self.create_apply_run(root, "subagent_serial", run_id_suffix="receipt-a")
            second = self.create_apply_run(root, "subagent_serial", run_id_suffix="receipt-b")
            first_dir = Path(first["run_dir"])
            second_dir = Path(second["run_dir"])
            self.complete_subagent_serial_verification(root, first_dir)
            self.complete_subagent_serial_verification(root, second_dir)
            first_task_id = self.first_task_id(first_dir)
            second_task_id = self.first_task_id(second_dir)
            first_progress = json.loads((first_dir / "Progress.json").read_text(encoding="utf-8"))
            second_progress_path = second_dir / "Progress.json"
            second_progress = json.loads(second_progress_path.read_text(encoding="utf-8"))
            first_reference = first_progress["tasks"][0]["validation_receipts"][0]
            first_receipt_path = first_dir / first_task_id / first_reference["path"]
            copied_receipt_path = second_dir / second_task_id / first_reference["path"]
            copied_receipt_path.write_bytes(first_receipt_path.read_bytes())
            copied_receipt_path.chmod(0o600)
            second_progress["tasks"][0]["validation_receipts"][0] = first_reference
            second_progress_path.write_text(json.dumps(second_progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(second_dir, root)

            self.assertIn(f"validation_receipt_context_mismatch={second_task_id}", errors)

    def test_verified_rejects_receipt_carried_from_another_planned_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            text = subplan.read_text(encoding="utf-8")
            needle = '      "probe_tier": 1\n    }\n  ],'
            second = "\n".join(
                [
                    '      "probe_tier": 1',
                    "    },",
                    "    {",
                    '      "id": "VAL-02",',
                    '      "argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"],',
                    '      "cwd": ".",',
                    '      "expected_exit_code": 0,',
                    '      "timeout_seconds": 120,',
                    '      "network": "deny",',
                    '      "probe_tier": 1',
                    "    }",
                    "  ],",
                ]
            )
            self.assertIn(needle, text)
            subplan.write_text(text.replace(needle, second, 1), encoding="utf-8")
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            references = progress["tasks"][0]["validation_receipts"]
            source = next(item for item in references if item["validation_id"] == "VAL-01")
            target = next(item for item in references if item["validation_id"] == "VAL-02")
            source_path = run_dir / task_id / source["path"]
            target_path = run_dir / task_id / target["path"]
            target_path.write_bytes(source_path.read_bytes())
            target["receipt_id"] = source["receipt_id"]
            target["sha256"] = source["sha256"]
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"validation_receipt_context_mismatch={task_id}", errors)
            self.assertIn(
                f"validation_receipt_event_binding_mismatch={task_id}:VAL-02",
                errors,
            )

    def test_validation_receipt_rejects_stale_pass_after_newer_failed_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir, stop_before_reviews=True)
            task_id = self.first_task_id(run_dir)
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            old_reference = dict(progress["tasks"][0]["validation_receipts"][0])

            with tempfile.TemporaryDirectory() as command_bin:
                python_wrapper = Path(command_bin) / "python3"
                python_wrapper.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
                python_wrapper.chmod(0o755)
                with mock.patch.dict(
                    os.environ,
                    {"PATH": f"{command_bin}:{os.environ.get('PATH', '')}"},
                ):
                    failed = APPLY_MODULE.execute_planned_validation(
                        run_dir,
                        task_id,
                        "VAL-01",
                        "controller",
                    root=root,
                    )
            self.assertEqual(failed["exit_code"], 1)

            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            new_reference = progress["tasks"][0]["validation_receipts"][0]
            self.assertGreater(
                new_reference["published_event_sequence"],
                old_reference["published_event_sequence"],
            )
            progress["tasks"][0]["validation_receipts"] = [old_reference]
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            with APPLY_MODULE.open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
                live_progress = APPLY_MODULE.secure_read_regular_json_at(
                    handle.run_fd,
                    "Progress.json",
                )
                live_task = APPLY_MODULE.find_task(live_progress, task_id)
                _, _, receipt_errors = APPLY_MODULE.validation_receipts_for_task(
                    handle,
                    live_task,
                )

            expected = f"validation_receipt_not_latest={task_id}:VAL-01"
            self.assertIn(expected, receipt_errors)
            self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))

    def test_review_receipt_rejects_stale_pass_after_newer_failed_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            rollback_paths = (
                run_dir / "Progress.json",
                run_dir / "Final-Review.json",
                run_dir / task_id / "Dispatch-Packet.json",
                run_dir / task_id / "Review-Report-final.json",
                run_dir / task_id / "Task-Review.json",
            )
            saved = {path: path.read_bytes() for path in rollback_paths}
            old_progress = json.loads(saved[run_dir / "Progress.json"].decode("utf-8"))
            old_reference = dict(old_progress["tasks"][0]["review_receipts"]["final"])

            APPLY_MODULE.prepare_dispatch_packet(
                run_dir,
                task_id,
                "final_reviewer",
                "controller",
                review_phase="final",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "final_reviewer",
                "final-review-2",
                "spawned",
                "controller",
                review_phase="final",
            root=root,
            )
            APPLY_MODULE.normalize_review_report(
                run_dir,
                task_id,
                "final",
                "final-review-2",
                {
                    "status": "COMPLETE",
                    "phase": "final",
                    "verdict": "fail",
                    "task_id": task_id,
                    "reviewer_agent_id": "final-review-2",
                    "evidence": ["newer final review failed"],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "final_reviewer",
                "final-review-2",
                "completed",
                "controller",
                summary="newer final review failed",
                review_phase="final",
            root=root,
            )
            APPLY_MODULE.publish_review_completion(run_dir, task_id, "final", "controller", root=root)

            new_progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            new_reference = new_progress["tasks"][0]["review_receipts"]["final"]
            self.assertEqual(new_reference["verdict"], "fail")
            self.assertGreater(
                new_reference["published_event_sequence"],
                old_reference["published_event_sequence"],
            )
            for path, content in saved.items():
                path.write_bytes(content)

            expected = f"review_receipt_not_latest={task_id}:final"
            self.assertIn(expected, APPLY_MODULE.validate_apply_run(run_dir, root))

    def test_subagent_verified_requires_completed_reviewer_runs(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.mark_task_verified(root, run_dir, security="pass")
            task_id = self.first_task_id(run_dir)

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"task_reviewer_agent_run_missing={task_id}", errors)
            self.assertIn(f"security_reviewer_agent_run_missing={task_id}", errors)
            self.assertIn("final_reviewer_agent_run_missing", errors)

    def test_validation_command_does_not_inherit_parent_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as command_bin:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir, task_id = self.prepare_task_for_validation(
                root,
                "import os\n\n"
                "def test_environment_isolated():\n"
                "    assert 'CODEXQB_PARENT_ONLY_SENTINEL' not in os.environ\n"
                "    assert 'PYTEST_ADDOPTS' not in os.environ\n"
                "    assert os.environ.get('PYTEST_DISABLE_PLUGIN_AUTOLOAD') == '1'\n",
            )
            python_wrapper = Path(command_bin) / "python3"
            python_wrapper.write_text(
                "#!/bin/sh\n"
                "[ -z \"${CODEXQB_PARENT_ONLY_SENTINEL:-}\" ] || exit 41\n"
                "[ -z \"${PYTEST_ADDOPTS:-}\" ] || exit 42\n"
                "[ -z \"${PYTHONPATH:-}\" ] || exit 43\n"
                "[ -z \"${HTTPS_PROXY:-}\" ] || exit 44\n"
                "[ -z \"${GIT_CONFIG_COUNT:-}\" ] || exit 45\n"
                "[ \"${PYTEST_DISABLE_PLUGIN_AUTOLOAD:-}\" = 1 ] || exit 46\n"
                "exit 0\n",
                encoding="utf-8",
            )
            python_wrapper.chmod(0o755)
            inherited_path = f"{command_bin}:{os.environ.get('PATH', '')}"

            with mock.patch.dict(
                os.environ,
                {
                    "PATH": inherited_path,
                    "CODEXQB_PARENT_ONLY_SENTINEL": "synthetic-parent-value",
                    "PYTEST_ADDOPTS": "--maxfail=1",
                    "PYTHONPATH": "/synthetic/import/path",
                    "HTTPS_PROXY": "http://127.0.0.1:9",
                    "GIT_CONFIG_COUNT": "1",
                },
                clear=False,
            ):
                receipt = APPLY_MODULE.execute_planned_validation(
                    run_dir, task_id, "VAL-01", "controller",
                    root=root
                )

            self.assertEqual(receipt["exit_code"], 0)

    def test_validation_output_limit_blocks_receipt_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as command_bin:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir, task_id = self.prepare_task_for_validation(
                root,
                "def test_output_limit():\n"
                "    assert False, 'A' * 10000\n",
            )
            python_wrapper = Path(command_bin) / "python3"
            python_wrapper.write_text(
                "#!/bin/sh\n"
                "i=0\n"
                "while [ \"$i\" -lt 10000 ]; do printf A; i=$((i + 1)); done\n"
                "exit 1\n",
                encoding="utf-8",
            )
            python_wrapper.chmod(0o755)
            inherited_path = f"{command_bin}:{os.environ.get('PATH', '')}"

            with mock.patch.dict(os.environ, {"PATH": inherited_path}, clear=False):
                with mock.patch.object(
                    EXECUTION_MODULE,
                    "MAX_VALIDATION_OUTPUT_BYTES",
                    1024,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        f"validation_output_limit_exceeded={task_id}:VAL-01",
                    ):
                        APPLY_MODULE.execute_planned_validation(
                            run_dir, task_id, "VAL-01", "controller",
                            root=root
                        )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"][0]["validation_receipts"], [])
            self.assertEqual(
                list((run_dir / task_id).glob("Validation-Receipt-*.json")),
                [],
            )
            events = [
                json.loads(line)
                for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertFalse(
                any(
                    event.get("event_type") == "validation_receipt_published"
                    and event.get("validation_id") == "VAL-01"
                    for event in events
                )
            )

    def test_validation_cwd_swap_cannot_execute_external_code_or_publish_receipt(self) -> None:
        with (
            tempfile.TemporaryDirectory() as temp_dir,
            tempfile.TemporaryDirectory() as external_dir,
            tempfile.TemporaryDirectory() as marker_dir,
        ):
            root = Path(temp_dir)
            external = Path(external_dir)
            safe_marker = Path(marker_dir) / "safe-code-ran"
            external_marker = Path(marker_dir) / "external-code-ran"
            self.write_apply_fixture(root)
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            text = subplan.read_text(encoding="utf-8")
            planned = (
                '      "argv": ["python3", "-B", "-m", "pytest", "-p", '
                '"no:cacheprovider", "tests/test_feature_1_1.py", "-q"],\n'
                '      "cwd": ".",'
            )
            cwd_bound = (
                '      "argv": ["python3", "-B", "-m", "unittest", '
                '"test_feature_1_1.py", "-q"],\n'
                '      "cwd": "tests",'
            )
            self.assertIn(planned, text)
            subplan.write_text(text.replace(planned, cwd_bound, 1), encoding="utf-8")
            (root / "tests").mkdir()
            run_dir, task_id = self.prepare_task_for_validation(
                root,
                "from pathlib import Path\n"
                "import unittest\n\n"
                "class SafeCodeTest(unittest.TestCase):\n"
                "    def test_safe_code(self):\n"
                f"        Path({str(safe_marker)!r}).write_text('safe\\n', encoding='utf-8')\n",
            )

            held_cwd = root / "tests-before-swap"
            external.joinpath("test_feature_1_1.py").write_text(
                "from pathlib import Path\n"
                "import unittest\n\n"
                "class ExternalCodeTest(unittest.TestCase):\n"
                "    def test_external_code(self):\n"
                f"        Path({str(external_marker)!r}).write_text('external\\n', encoding='utf-8')\n"
                f"        Path({str(root / 'tests')!r}).unlink()\n"
                f"        Path({str(held_cwd)!r}).rename(Path({str(root / 'tests')!r}))\n",
                encoding="utf-8",
            )
            real_popen = subprocess.Popen
            swapped = False

            def swap_cwd_at_validation_launch(*args, **kwargs):
                nonlocal swapped
                argv = args[0] if args else kwargs.get("args")
                if (
                    not swapped
                    and kwargs.get("start_new_session") is True
                    and isinstance(argv, list)
                    and "python3" in argv
                ):
                    swapped = True
                    (root / "tests").rename(held_cwd)
                    (root / "tests").symlink_to(external, target_is_directory=True)
                return real_popen(*args, **kwargs)

            with mock.patch.object(
                EXECUTION_MODULE.subprocess,
                "Popen",
                side_effect=swap_cwd_at_validation_launch,
            ):
                with self.assertRaises(ValueError):
                    APPLY_MODULE.execute_planned_validation(
                        run_dir, task_id, "VAL-01", "controller",
                        root=root
                    )

            self.assertTrue(swapped)
            self.assertTrue(safe_marker.exists())
            self.assertFalse(external_marker.exists())
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"][0]["validation_receipts"], [])
            self.assertEqual(list((run_dir / task_id).glob("Validation-Receipt-*.json")), [])
            events = [
                json.loads(line)
                for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertFalse(
                any(
                    event.get("event_type") == "validation_receipt_published"
                    and event.get("validation_id") == "VAL-01"
                    for event in events
                )
            )

    def test_validation_runner_rejects_cross_device_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            cwd = root / "tests"
            cwd.mkdir()
            repository_io_globals = (
                EXECUTION_MODULE._controller_validation_cwd.__wrapped__.__globals__
            )
            real_require_same_mount = repository_io_globals["require_same_repository_mount"]

            def reject_cross_device_child(anchor, child_fd, relative_path):
                if relative_path == "tests":
                    raise ValueError("repository_nested_mount_rejected=tests")
                return real_require_same_mount(anchor, child_fd, relative_path)

            with (
                mock.patch.dict(
                    repository_io_globals,
                    {"require_same_repository_mount": reject_cross_device_child},
                ),
                mock.patch.object(EXECUTION_MODULE.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "validation_cwd_nested_mount_rejected",
                ):
                    EXECUTION_MODULE.run_bounded_validation_process(
                        ["/usr/bin/true"],
                        cwd=cwd,
                        root=root,
                        timeout_seconds=5,
                        normalized_cwd="tests",
                    )
            popen.assert_not_called()

    def test_validation_runner_rejects_same_device_nested_mount_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "tests"
            nested.mkdir()
            root_metadata = os.stat(root, follow_symlinks=False)
            nested_metadata = os.stat(nested, follow_symlinks=False)
            self.assertEqual(root_metadata.st_dev, nested_metadata.st_dev)
            repository_io_globals = (
                EXECUTION_MODULE._controller_validation_cwd.__wrapped__.__globals__
            )
            mount_globals = repository_io_globals["require_same_repository_mount"].__globals__
            real_mount_identity = mount_globals["_descriptor_mount_identity"]

            def simulated_bind_mount(file_fd: int):
                metadata = os.fstat(file_fd)
                if metadata.st_ino == nested_metadata.st_ino:
                    return ("simulated_bind_mount", 2)
                return real_mount_identity(file_fd)

            with (
                mock.patch.dict(
                    mount_globals,
                    {"_descriptor_mount_identity": simulated_bind_mount},
                ),
                mock.patch.object(EXECUTION_MODULE.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "validation_cwd_nested_mount_rejected",
                ):
                    EXECUTION_MODULE.run_bounded_validation_process(
                        ["/usr/bin/true"],
                        cwd=nested,
                        root=root,
                        timeout_seconds=5,
                        normalized_cwd="tests",
                    )
            popen.assert_not_called()

    def test_validation_runner_fails_closed_without_safe_fork_context(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with (
                mock.patch.object(EXECUTION_MODULE.threading, "active_count", return_value=2),
                mock.patch.object(EXECUTION_MODULE.subprocess, "Popen") as popen,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_validation_process_isolation_not_supported",
                ):
                    EXECUTION_MODULE.run_bounded_validation_process(
                        ["/usr/bin/true"],
                        cwd=root,
                        root=root,
                        timeout_seconds=5,
                    )
            popen.assert_not_called()

    def test_validation_timeout_terminates_the_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            marker = root / "descendant-survived"

            result = APPLY_MODULE.run_bounded_validation_process(
                [
                    sys.executable,
                    "-c",
                    "import time\n"
                    "from pathlib import Path\n"
                    "time.sleep(2)\n"
                    f"Path({str(marker)!r}).write_text('late', encoding='utf-8')\n",
                ],
                cwd=root,
                root=root,
                timeout_seconds=1,
            )
            time.sleep(1.5)

            self.assertTrue(result.timed_out)
            self.assertEqual(result.termination_reason, "timeout")
            self.assertEqual(result.exit_code, -1)
            self.assertFalse(marker.exists())

    def test_validation_containment_allows_threads_and_normal_unittest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)

            result = APPLY_MODULE.run_bounded_validation_process(
                [
                    sys.executable,
                    "-c",
                    "import threading\n"
                    "import unittest\n"
                    "observed = []\n"
                    "class ThreadTest(unittest.TestCase):\n"
                    "    def test_thread(self):\n"
                    "        worker = threading.Thread(target=lambda: observed.append('ok'))\n"
                    "        worker.start()\n"
                    "        worker.join()\n"
                    "        self.assertEqual(observed, ['ok'])\n"
                    "unittest.main()\n",
                ],
                cwd=root,
                root=root,
                timeout_seconds=5,
            )

            self.assertFalse(result.timed_out)
            self.assertEqual(result.termination_reason, "exited")
            self.assertEqual(result.exit_code, 0)

    def test_validation_descendant_escape_is_blocked_before_receipt_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as marker_dir:
            root = Path(temp_dir)
            double_fork_marker = Path(marker_dir) / "double-fork-survived"
            spawn_marker = Path(marker_dir) / "posix-spawn-survived"
            self.write_apply_fixture(root)
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            text = subplan.read_text(encoding="utf-8")
            planned = (
                '      "argv": ["python3", "-B", "-m", "pytest", "-p", '
                '"no:cacheprovider", "tests/test_feature_1_1.py", "-q"],'
            )
            unittest_command = (
                '      "argv": ["python3", "-B", "-m", "unittest", '
                '"tests/test_feature_1_1.py", "-q"],'
            )
            self.assertIn(planned, text)
            subplan.write_text(
                text.replace(planned, unittest_command, 1),
                encoding="utf-8",
            )
            run_dir, task_id = self.prepare_task_for_validation(
                root,
                "import os\n"
                "import time\n"
                "import unittest\n"
                "from pathlib import Path\n\n"
                "class EscapeAttemptTest(unittest.TestCase):\n"
                "  def test_escape_attempt_is_contained(self):\n"
                "    try:\n"
                "        child = os.fork()\n"
                "    except OSError:\n"
                "        child = -1\n"
                "    if child == 0:\n"
                "        os.setsid()\n"
                "        grandchild = os.fork()\n"
                "        if grandchild != 0:\n"
                "            os._exit(0)\n"
                "        os.close(1)\n"
                "        os.close(2)\n"
                "        time.sleep(0.5)\n"
                f"        Path({str(double_fork_marker)!r}).write_text('escaped', encoding='utf-8')\n"
                "        os._exit(0)\n"
                "    if child > 0:\n"
                "        os.waitpid(child, 0)\n"
                "    try:\n"
                "        os.posix_spawn(\n"
                "            '/bin/sh',\n"
                "            ['/bin/sh', '-c', "
                f"'sleep 0.5; printf escaped > {spawn_marker.as_posix()}'],\n"
                "            os.environ,\n"
                "        )\n"
                "    except OSError:\n"
                "        pass\n",
            )

            receipt = APPLY_MODULE.execute_planned_validation(
                run_dir, task_id, "VAL-01", "controller",
                root=root
            )
            time.sleep(0.75)

            self.assertEqual(receipt["exit_code"], 0)
            self.assertFalse(double_fork_marker.exists())
            self.assertFalse(spawn_marker.exists())

    def test_validation_interrupt_after_popen_kills_and_reaps_child(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            spawned: list[subprocess.Popen] = []
            real_popen = subprocess.Popen

            def record_popen(*args, **kwargs):
                process = real_popen(*args, **kwargs)
                spawned.append(process)
                return process

            with (
                mock.patch.object(EXECUTION_MODULE.subprocess, "Popen", side_effect=record_popen),
                mock.patch.object(
                    EXECUTION_MODULE.selectors,
                    "DefaultSelector",
                    side_effect=KeyboardInterrupt,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    EXECUTION_MODULE.run_bounded_validation_process(
                        [sys.executable, "-c", "import time; time.sleep(30)"],
                        cwd=root,
                        root=root,
                        timeout_seconds=60,
                    )

            self.assertEqual(len(spawned), 1)
            self.assertIsNotNone(spawned[0].poll())

    def test_validation_cwd_anchor_is_promoted_when_standard_input_is_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            try:
                saved_stdin = os.dup(0)
            except OSError:
                saved_stdin = None
            try:
                try:
                    os.close(0)
                except OSError:
                    pass
                result = APPLY_MODULE.run_bounded_validation_process(
                    [sys.executable, "-c", "import os; print(os.getcwd())"],
                    cwd=root,
                    root=root,
                    timeout_seconds=5,
                )
            finally:
                if saved_stdin is not None:
                    os.dup2(saved_stdin, 0)
                    os.close(saved_stdin)

            self.assertEqual(result.exit_code, 0)
            self.assertTrue(
                os.path.samefile(result.stdout.decode("utf-8").strip(), root)
            )

    def test_validation_containment_rejects_unknown_linux_architecture(self) -> None:
        with (
            mock.patch.object(EXECUTION_MODULE.sys, "platform", "linux"),
            mock.patch.object(
                EXECUTION_MODULE.os,
                "uname",
                return_value=mock.Mock(machine="mips64"),
            ),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "secure_validation_process_isolation_not_supported",
            ):
                EXECUTION_MODULE._containment_command(["/usr/bin/true"])

    def test_failed_validation_rerun_invalidates_prior_receipts_and_reviews(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as command_bin:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress_path = run_dir / "Progress.json"
            before = json.loads(progress_path.read_text(encoding="utf-8"))
            old_reference = dict(before["tasks"][0]["validation_receipts"][0])
            self.assertTrue(before["tasks"][0]["review_receipts"])

            python_wrapper = Path(command_bin) / "python3"
            python_wrapper.write_text(
                "#!/bin/sh\n"
                "i=0\n"
                "while [ \"$i\" -lt 10000 ]; do printf A; i=$((i + 1)); done\n"
                "exit 1\n",
                encoding="utf-8",
            )
            python_wrapper.chmod(0o755)
            with mock.patch.dict(
                os.environ,
                {"PATH": f"{command_bin}:{os.environ.get('PATH', '')}"},
                clear=False,
            ):
                with mock.patch.object(EXECUTION_MODULE, "MAX_VALIDATION_OUTPUT_BYTES", 1024):
                    with self.assertRaisesRegex(
                        ValueError,
                        f"validation_output_limit_exceeded={task_id}:VAL-01",
                    ):
                        APPLY_MODULE.execute_planned_validation(
                            run_dir, task_id, "VAL-01", "controller",
                            root=root
                        )

            after = json.loads(progress_path.read_text(encoding="utf-8"))
            self.assertEqual(after["tasks"][0]["validation_receipts"], [])
            self.assertEqual(after["tasks"][0]["review_receipts"], {})

            # Even a local rollback of the old reference cannot make it current:
            # the durable newer start event invalidates the older publication.
            after["tasks"][0]["validation_receipts"] = [old_reference]
            progress_path.write_text(json.dumps(after), encoding="utf-8")
            with APPLY_MODULE.open_verified_apply_run_for_mutation(run_dir, root=root) as handle:
                live_progress = APPLY_MODULE.secure_read_regular_json_at(
                    handle.run_fd, "Progress.json"
                )
                live_task = APPLY_MODULE.find_task(live_progress, task_id)
                _, _, errors = APPLY_MODULE.validation_receipts_for_task(handle, live_task)
            self.assertIn(
                f"validation_receipt_not_latest={task_id}:VAL-01",
                errors,
            )

    def test_validation_receipt_records_complete_controller_observation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            reference = progress["tasks"][0]["validation_receipts"][0]
            receipt = json.loads((run_dir / task_id / reference["path"]).read_text(encoding="utf-8"))
            run = json.loads((run_dir / "Apply-Run.json").read_text(encoding="utf-8"))

            self.assertEqual(receipt["command"]["validation_id"], "VAL-01")
            self.assertEqual(receipt["command"]["cwd"], ".")
            self.assertEqual(receipt["result"]["exit_code"], 0)
            self.assertIn("started_at", receipt["command"])
            self.assertIn("finished_at", receipt["command"])
            self.assertRegex(receipt["result"]["stdout_sha256"], r"^[a-f0-9]{64}$")
            self.assertRegex(receipt["result"]["stderr_sha256"], r"^[a-f0-9]{64}$")
            self.assertEqual(receipt["host_sandbox_proof"], "not_observed")
            self.assertEqual(receipt["approval_proof"], "not_observed")
            self.assertEqual(receipt["network_enforcement_proof"], "not_observed")
            self.assertTrue(run["user_approval"])
            self.assertEqual(receipt["command"]["planned_network"], "deny")
            self.assertEqual(
                {item["path"] for item in receipt["result"]["artifacts"]},
                {"src/feature_1_1.py", "tests/test_feature_1_1.py"},
            )

    def test_validation_command_repository_mutation_cannot_publish_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(
                run_dir, task_id, "implementer", "controller",
                root=root
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "mutating-impl",
                "spawned",
                "controller",
            root=root,
            )
            APPLY_MODULE.transition_task_state(
                run_dir, task_id, "IMPLEMENTING", "mutating-impl",
                root=root
            )
            source = root / "src" / "feature_1_1.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            test_file = root / "tests" / "test_feature_1_1.py"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text(
                "from pathlib import Path\n"
                "from src.feature_1_1 import VALUE\n\n"
                "def test_value():\n"
                "    Path('unplanned-output.txt').write_text('side effect', encoding='utf-8')\n"
                "    assert VALUE == 1\n",
                encoding="utf-8",
            )
            APPLY_MODULE.normalize_writer_report(
                run_dir,
                task_id,
                "implementer",
                "mutating-impl",
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "implementer_agent_id": "mutating-impl",
                    "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                    "concerns": [],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "implementer",
                "mutating-impl",
                "completed",
                "controller",
            root=root,
            )
            APPLY_MODULE.transition_task_state(
                run_dir, task_id, "IMPLEMENTED", "mutating-impl",
                root=root
            )
            APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)

            with tempfile.TemporaryDirectory() as command_bin:
                python_wrapper = Path(command_bin) / "python3"
                python_wrapper.write_text(
                    "#!/bin/sh\nprintf 'side effect' > unplanned-output.txt\nexit 0\n",
                    encoding="utf-8",
                )
                python_wrapper.chmod(0o755)
                with mock.patch.dict(
                    os.environ,
                    {"PATH": f"{command_bin}:{os.environ.get('PATH', '')}"},
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        f"validation_command_mutated_repository={task_id}:VAL-01",
                    ):
                        APPLY_MODULE.execute_planned_validation(
                            run_dir, task_id, "VAL-01", "controller",
                            root=root
                        )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"][0]["validation_receipts"], [])
            self.assertEqual(
                list((run_dir / task_id).glob("Validation-Receipt-*.json")),
                [],
            )
            events = [
                json.loads(line)
                for line in (run_dir / "Events.jsonl").read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            validation_events = [
                event.get("event_type")
                for event in events
                if event.get("validation_id") == "VAL-01"
            ]
            self.assertIn("validation_execution_started", validation_events)
            self.assertNotIn("validation_execution_observed", validation_events)
            self.assertNotIn("validation_receipt_published", validation_events)

    def test_validation_secret_output_is_rejected_before_receipt_or_raw_output_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            run_dir = Path(self.create_apply_run(root, "subagent_serial")["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "output-impl", "spawned", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "output-impl", root=root)
            (root / "src").mkdir(exist_ok=True)
            (root / "tests").mkdir(exist_ok=True)
            (root / "src" / "feature_1_1.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests" / "test_feature_1_1.py").write_text(
                "from src.feature_1_1 import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
                encoding="utf-8",
            )
            APPLY_MODULE.normalize_writer_report(
                run_dir,
                task_id,
                "implementer",
                "output-impl",
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "implementer_agent_id": "output-impl",
                    "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                    "concerns": [],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "output-impl", "completed", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "output-impl", root=root)
            APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)
            fixture = "xox" + "b-" + "N" * 32
            completed = APPLY_MODULE.ValidationProcessResult(
                exit_code=0,
                stdout=("result=" + fixture + "\n").encode("utf-8"),
                stderr=b"",
                timed_out=False,
                output_limit_exceeded=False,
                termination_reason="exited",
            )

            try:
                with mock.patch.object(
                    APPLY_MODULE,
                    "run_bounded_validation_process",
                    return_value=completed,
                ):
                    APPLY_MODULE.execute_planned_validation(
                        run_dir, task_id, "VAL-01", "controller",
                        root=root
                    )
            except ValueError as exc:
                self.assertNotIn(fixture, str(exc))
                self.assertEqual(
                    str(exc),
                    f"validation_output_secret_rejected={task_id}:VAL-01",
                )
            else:
                self.fail("validation command secret output was accepted")
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(progress["tasks"][0]["validation_receipts"], [])
            self.assertEqual(list((run_dir / task_id).glob("Validation-Receipt-*.json")), [])
            self.assertNotIn(fixture.encode("utf-8"), (run_dir / "Events.jsonl").read_bytes())

    def test_review_receipt_requires_unchanged_completed_agent_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            agent_run = run_dir / task_id / "Agent-Run-task_reviewer-spec-01.json"
            payload = json.loads(agent_run.read_text(encoding="utf-8"))
            payload["agent_id"] = "forged-reviewer"
            agent_run.write_text(json.dumps(payload), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"spec_reviewer_agent_run_missing={task_id}", errors)

    def test_tampered_review_receipt_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            reference = progress["tasks"][0]["review_receipts"]["spec"]
            receipt_path = run_dir / task_id / reference["path"]
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["review_binding"]["verdict"] = "fail"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"spec_review_receipt_mac_invalid={task_id}", errors)

    def test_validation_receipt_is_bound_to_controller_observation_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            events_path = run_dir / "Events.jsonl"
            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            observed = next(
                event
                for event in events
                if event.get("event_type") == "validation_execution_observed"
                and event.get("validation_id") == "VAL-01"
            )
            observed["stdout_sha256"] = "0" * 64
            events_path.write_text(
                serialize_rechained_events(events),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(
                f"validation_receipt_event_binding_mismatch={task_id}:VAL-01",
                errors,
            )

    def test_review_receipt_is_bound_to_reviewer_lifecycle_events(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            events_path = run_dir / "Events.jsonl"
            events = [
                json.loads(line)
                for line in events_path.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            completed = next(
                event
                for event in events
                if event.get("event_type") == "subagent_dispatch_status_recorded"
                and event.get("review_phase") == "spec"
                and event.get("status") == "completed"
            )
            completed["agent_id"] = "forged-agent"
            events_path.write_text(
                serialize_rechained_events(events),
                encoding="utf-8",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(
                f"spec_review_receipt_event_binding_mismatch={task_id}",
                errors,
            )

    def test_review_report_cannot_change_after_reviewer_completion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            report_path = run_dir / task_id / "Review-Report-spec.json"
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["evidence"] = ["substituted after reviewer completion"]
            report_path.write_text(json.dumps(report), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(
                f"spec_review_report_completed_run_mismatch={task_id}",
                errors,
            )
            self.assertIn(f"spec_review_report_hash_mismatch={task_id}", errors)

    def test_cross_run_review_receipt_reuse_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            first = self.create_apply_run(root, "subagent_serial", run_id_suffix="review-a")
            second = self.create_apply_run(root, "subagent_serial", run_id_suffix="review-b")
            first_dir = Path(first["run_dir"])
            second_dir = Path(second["run_dir"])
            self.complete_subagent_serial_verification(root, first_dir)
            self.complete_subagent_serial_verification(root, second_dir)
            first_task_id = self.first_task_id(first_dir)
            second_task_id = self.first_task_id(second_dir)
            first_progress = json.loads((first_dir / "Progress.json").read_text(encoding="utf-8"))
            second_progress = json.loads((second_dir / "Progress.json").read_text(encoding="utf-8"))
            first_reference = first_progress["tasks"][0]["review_receipts"]["spec"]
            second_reference = second_progress["tasks"][0]["review_receipts"]["spec"]
            source = first_dir / first_task_id / first_reference["path"]
            destination = second_dir / second_task_id / second_reference["path"]
            destination.write_bytes(source.read_bytes())

            errors = APPLY_MODULE.validate_apply_run(second_dir, root)

            self.assertIn(f"spec_review_receipt_context_mismatch={second_task_id}", errors)

    def test_review_receipt_order_tampering_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)
            task_id = self.first_task_id(run_dir)
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            refs = progress["tasks"][0]["review_receipts"]
            refs["quality"]["published_event_sequence"] = refs["spec"]["published_event_sequence"] - 1
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn(f"review_order_invalid={task_id}", errors)

    def test_verified_transition_rejects_post_run_out_of_contract_file_with_git_baseline_delta(self) -> None:
        for initially_dirty in (False, True):
            with self.subTest(initially_dirty=initially_dirty), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_apply_fixture(root)
                self.init_git_repo(root)
                subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
                subprocess.run(
                    [
                        "git",
                        "-c",
                        "user.name=CodexQB Test",
                        "-c",
                        "user.email=codexqb-test@example.invalid",
                        "commit",
                        "-m",
                        "fixture",
                    ],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                if initially_dirty:
                    (root / "preexisting-local-note.txt").write_text(
                        "present before apply-run initialization\n",
                        encoding="utf-8",
                    )

                result = self.create_apply_run(root, "subagent_serial")
                run_dir = Path(result["run_dir"])
                task_id = self.first_task_id(run_dir)
                self.complete_subagent_serial_verification(
                    root,
                    run_dir,
                    transition_verified=False,
                )

                self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])
                (root / "post-run-out-of-contract.txt").write_text(
                    "created after the signed apply-run baseline\n",
                    encoding="utf-8",
                )

                with self.assertRaises(ValueError) as blocked:
                    APPLY_MODULE.transition_task_state(
                        run_dir,
                        task_id,
                        "VERIFIED",
                        "controller",
                    root=root,
                    )
                self.assertIn("workspace_baseline_mismatch=", str(blocked.exception))

                progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
                self.assertNotEqual(progress["tasks"][0]["state"], "VERIFIED")
                errors = APPLY_MODULE.validate_apply_run(run_dir, root)
                self.assertTrue(
                    any(error.startswith("workspace_baseline_mismatch=") for error in errors),
                    errors,
                )

    def test_contract_tampering_blocks_review_publication_and_verified_transition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(
                root,
                run_dir,
                stop_after_quality=True,
            )

            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            self.assertTrue(task["security_review_required"])
            task["security_review_required"] = False
            task["risk_class"] = "tampered-after-quality-review"
            progress_path.write_text(json.dumps(progress), encoding="utf-8")

            APPLY_MODULE.prepare_dispatch_packet(
                run_dir,
                task_id,
                "final_reviewer",
                "controller",
                review_phase="final",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "final_reviewer",
                "final-review-1",
                "spawned",
                "controller",
                review_phase="final",
            root=root,
            )
            with self.assertRaises(ValueError) as normalize_error:
                APPLY_MODULE.normalize_review_report(
                    run_dir,
                    task_id,
                    "final",
                    "final-review-1",
                    {
                        "status": "COMPLETE",
                        "phase": "final",
                        "verdict": "pass",
                        "task_id": task_id,
                        "reviewer_agent_id": "final-review-1",
                        "evidence": ["tamper regression probe"],
                    },
                    "controller",
                root=root,
                )
            self.assertRegex(
                str(normalize_error.exception),
                "(security_review_required|risk_class|task_contract).*mismatch",
            )

            with self.assertRaises(ValueError) as publish_error:
                APPLY_MODULE.publish_review_completion(
                    run_dir,
                    task_id,
                    "final",
                    "controller",
                root=root,
                )
            self.assertRegex(
                str(publish_error.exception),
                "(security_review_required|risk_class|task_contract).*mismatch",
            )

            with self.assertRaises(ValueError) as verified_error:
                APPLY_MODULE.transition_task_state(
                    run_dir,
                    task_id,
                    "VERIFIED",
                    "controller",
                root=root,
                )
            self.assertRegex(
                str(verified_error.exception),
                "(security_review_required|risk_class|task_contract).*mismatch",
            )
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            self.assertNotEqual(progress["tasks"][0]["state"], "VERIFIED")

    def test_reviewer_identity_cannot_reuse_implementer_agent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(
                root,
                run_dir,
                stop_before_reviews=True,
            )

            APPLY_MODULE.prepare_dispatch_packet(
                run_dir,
                task_id,
                "task_reviewer",
                "controller",
                review_phase="spec",
            root=root,
            )
            packet_text = (run_dir / task_id / "Dispatch-Packet.json").read_text(encoding="utf-8")
            self.assertGreater(len(packet_text), 10_000)
            scan_started = time.perf_counter()
            self.assertEqual(SAFETY_MODULE.secret_findings(packet_text), [])
            self.assertLess(time.perf_counter() - scan_started, 1.0)
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "task_reviewer",
                "impl-1",
                "spawned",
                "controller",
                review_phase="spec",
            root=root,
            )
            APPLY_MODULE.normalize_review_report(
                run_dir,
                task_id,
                "spec",
                "impl-1",
                {
                    "status": "COMPLETE",
                    "phase": "spec",
                    "verdict": "pass",
                    "task_id": task_id,
                    "reviewer_agent_id": "impl-1",
                    "evidence": ["identity separation regression probe"],
                },
                "controller",
            root=root,
            )

            with self.assertRaises(ValueError):
                APPLY_MODULE.record_agent_status(
                    run_dir,
                    task_id,
                    "task_reviewer",
                    "impl-1",
                    "completed",
                    "controller",
                    review_phase="spec",
                root=root,
                )
            with self.assertRaises(ValueError):
                APPLY_MODULE.publish_review_completion(
                    run_dir,
                    task_id,
                    "spec",
                    "controller",
                root=root,
                )
            with self.assertRaises(ValueError):
                APPLY_MODULE.transition_task_state(
                    run_dir,
                    task_id,
                    "VERIFIED",
                    "controller",
                root=root,
                )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertNotEqual(progress["tasks"][0]["state"], "VERIFIED")

    def test_reviewer_completion_requires_controller_normalized_read_only_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(
                root,
                run_dir,
                stop_before_reviews=True,
            )
            APPLY_MODULE.prepare_dispatch_packet(
                run_dir,
                task_id,
                "task_reviewer",
                "controller",
                review_phase="spec",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "task_reviewer",
                "spec-review-1",
                "spawned",
                "controller",
                review_phase="spec",
            root=root,
            )
            report = {
                "status": "COMPLETE",
                "phase": "spec",
                "verdict": "pass",
                "task_id": task_id,
                "reviewer_agent_id": "spec-review-1",
                "evidence": ["read-only reviewer result"],
            }
            (run_dir / task_id / "Review-Report-spec.json").write_text(
                json.dumps(report),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(
                ValueError,
                f"review_report_controller_normalization_missing={task_id}:spec",
            ):
                APPLY_MODULE.record_agent_status(
                    run_dir,
                    task_id,
                    "task_reviewer",
                    "spec-review-1",
                    "completed",
                    "controller",
                    review_phase="spec",
                root=root,
                )

            normalized = APPLY_MODULE.normalize_review_report(
                run_dir,
                task_id,
                "spec",
                "spec-review-1",
                report,
                "controller",
            root=root,
            )
            self.assertEqual(normalized["event"]["host_completion_proof"], "not_observed")
            completed = APPLY_MODULE.record_agent_status(
                run_dir,
                task_id,
                "task_reviewer",
                "spec-review-1",
                "completed",
                "controller",
                review_phase="spec",
            root=root,
            )
            self.assertEqual(completed["status"], "completed")

    def test_direct_mode_cannot_transition_to_trusted_verified(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "controller", root=root)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "controller", root=root)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "TASK_REVIEW", "controller", root=root)

            with self.assertRaisesRegex(ValueError, "verified_requires_subagent_reviewer_receipts"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "controller", root=root)

    def test_receipt_cli_rejects_direct_reviewer_and_unplanned_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "direct")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)

            with mock.patch.object(sys, "stderr"):
                dispatch_status = APPLY_MODULE.main(
                    [
                        "dispatch",
                        "--root",
                        str(root),
                        "--run-dir",
                        str(run_dir),
                        "--task-id",
                        task_id,
                        "--role",
                        "task_reviewer",
                        "--review-phase",
                        "spec",
                        "--actor",
                        "controller",
                    ]
                )
            self.assertEqual(dispatch_status, 1)

            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "controller", root=root)
            source = root / "src" / "feature_1_1.py"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("VALUE = 1\n", encoding="utf-8")
            test_file = root / "tests" / "test_feature_1_1.py"
            test_file.parent.mkdir(parents=True, exist_ok=True)
            test_file.write_text(
                "from src.feature_1_1 import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
                encoding="utf-8",
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "controller", root=root)
            APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)
            with mock.patch.object(sys, "stderr"):
                validation_status = APPLY_MODULE.main(
                    [
                        "run-validation",
                        "--root",
                        str(root),
                        "--run-dir",
                        str(run_dir),
                        "--task-id",
                        task_id,
                        "--validation-id",
                        "VAL-99",
                        "--actor",
                        "controller",
                    ]
                )
            self.assertEqual(validation_status, 1)

    def test_apply_prepare_requires_passing_step4_validator(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            (root / "Planner-docs" / "Sub-Planing-Audit.md").write_text("# broken audit\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "step4_validator_failed="):
                self.create_apply_run(root, "direct")

    def test_apply_prepare_rejects_unsafe_validation_before_creating_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            subplan = root / "Planner-docs" / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            canonical = '["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]'
            unsafe = '["ruff", "check", "--fix", "."]'
            content = subplan.read_text(encoding="utf-8")
            self.assertIn(canonical, content)
            subplan.write_text(content.replace(canonical, unsafe, 1), encoding="utf-8")
            fixed = APPLY_MODULE.managed_apply_runs_root(root) / "fixed"

            with self.assertRaisesRegex(ValueError, "step4_validator_failed="):
                self.create_apply_run(root, "direct", fixed)

            self.assertFalse(fixed.exists())

    def test_git_assume_unchanged_cannot_hide_contract_external_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            outside = root / "outside.txt"
            outside.write_text("baseline\n", encoding="utf-8")
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "outside.txt"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            outside.write_text("hidden mutation\n", encoding="utf-8")
            hidden_diff = subprocess.run(
                ["git", "diff", "--", "outside.txt"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(hidden_diff.stdout, "")

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=workspace_file_inventory_sha256", errors)

    def test_git_assume_unchanged_cannot_hide_contract_external_mode_change(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            outside = root / "outside.sh"
            outside.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            outside.chmod(0o644)
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(root, run_dir)
            subprocess.run(
                ["git", "update-index", "--assume-unchanged", "outside.sh"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            outside.chmod(0o755)
            self.assertEqual(
                subprocess.run(
                    ["git", "diff", "--", "outside.sh"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
                "",
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=workspace_file_inventory_sha256", errors)
            with self.assertRaisesRegex(ValueError, "workspace_baseline_mismatch=workspace_file_inventory_sha256"):
                APPLY_MODULE.publish_review_completion(run_dir, task_id, "final", "controller", root=root)
            with self.assertRaisesRegex(ValueError, "workspace_baseline_mismatch=workspace_file_inventory_sha256"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "controller", root=root)

    def test_git_ignored_untracked_cannot_hide_contract_external_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            (root / ".gitignore").write_text(".env\n", encoding="utf-8")
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(root, run_dir)
            (root / ".env").write_text("SYNTHETIC_SETTING=changed\n", encoding="utf-8")
            self.assertNotIn(
                ".env",
                subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
            )

            errors = APPLY_MODULE.validate_apply_run(run_dir, root)

            self.assertIn("workspace_baseline_mismatch=workspace_file_inventory_sha256", errors)
            with self.assertRaisesRegex(ValueError, "workspace_baseline_mismatch=workspace_file_inventory_sha256"):
                APPLY_MODULE.publish_review_completion(run_dir, task_id, "final", "controller", root=root)
            with self.assertRaisesRegex(ValueError, "workspace_baseline_mismatch=workspace_file_inventory_sha256"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "controller", root=root)

    def test_unreadable_contract_external_directory_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            self.init_git_repo(root)
            subprocess.run(["git", "add", "."], cwd=root, check=True, capture_output=True, text=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb-test@example.invalid",
                    "commit",
                    "-m",
                    "fixture",
                ],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(root, run_dir)
            hidden = root / "unreadable-new"
            hidden.mkdir()
            (hidden / "payload.txt").write_text("contract external\n", encoding="utf-8")
            hidden.chmod(0)
            try:
                errors = APPLY_MODULE.validate_apply_run(run_dir, root)
                self.assertTrue(
                    any(
                        error.startswith("workspace_baseline_mismatch=workspace_file_")
                        or error.startswith("workspace_scope_validation_unavailable=workspace_inventory_walk_failed")
                        or error.startswith(
                            "workspace_scope_validation_unavailable=repository_io_inventory_failed="
                        )
                        or error
                        == "workspace_scope_validation_unavailable=repository_path_parent_identity_changed"
                        or error
                        == "workspace_scope_validation_unavailable=repository_io_workspace_proof_failed"
                        for error in errors
                    ),
                    errors,
                )
                rejection = (
                    r"workspace_(?:baseline_mismatch|inventory_walk_failed)"
                    r"|repository_io_inventory_failed=repository_inventory_walk_failed"
                    r"|repository_io_workspace_proof_failed"
                    r"|workspace_scope_validation_unavailable="
                    r"(?:workspace_inventory_walk_failed|repository_path_parent_identity_changed"
                    r"|repository_io_inventory_failed=repository_inventory_walk_failed)"
                )
                with self.assertRaisesRegex(ValueError, rejection):
                    APPLY_MODULE.publish_review_completion(run_dir, task_id, "final", "controller", root=root)
                with self.assertRaisesRegex(ValueError, rejection):
                    APPLY_MODULE.transition_task_state(run_dir, task_id, "VERIFIED", "controller", root=root)
            finally:
                hidden.chmod(0o700)

    def test_controller_cannot_promote_agent_identity_to_host_attested(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "impl-1", "spawned", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTING", "impl-1", root=root)
            (root / "src").mkdir(exist_ok=True)
            (root / "tests").mkdir(exist_ok=True)
            (root / "src" / "feature_1_1.py").write_text("VALUE = 1\n", encoding="utf-8")
            (root / "tests" / "test_feature_1_1.py").write_text(
                "from src.feature_1_1 import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
                encoding="utf-8",
            )
            APPLY_MODULE.normalize_writer_report(
                run_dir,
                task_id,
                "implementer",
                "impl-1",
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "implementer_agent_id": "impl-1",
                    "files_changed": ["src/feature_1_1.py", "tests/test_feature_1_1.py"],
                    "concerns": [],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "implementer", "impl-1", "completed", "controller",
                root=root
            )
            progress_path = run_dir / "Progress.json"
            progress = json.loads(progress_path.read_text(encoding="utf-8"))
            agent_run = progress["tasks"][0]["agent_runs"][0]
            agent_run["identity_assurance"] = "host_attested"
            progress_path.write_text(json.dumps(progress), encoding="utf-8")
            agent_path = run_dir / task_id / "Agent-Run-implementer-01.json"
            artifact = json.loads(agent_path.read_text(encoding="utf-8"))
            artifact["identity_assurance"] = "host_attested"
            agent_path.write_text(json.dumps(artifact), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "controller_asserted_writer_identity_required"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "IMPLEMENTED", "impl-1", root=root)

    def test_finalize_rechecks_live_host_attestation_after_validation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)

            def race_progress_after_validation(_run_dir: Path, *_args, **_kwargs) -> list[str]:
                progress_path = run_dir / "Progress.json"
                progress = json.loads(progress_path.read_text(encoding="utf-8"))
                task = progress["tasks"][0]
                task["state"] = "VERIFIED"
                progress["verified_task_ids"] = [task["task_id"]]
                progress_path.write_text(json.dumps(progress), encoding="utf-8")
                return []

            with mock.patch.object(
                APPLY_MODULE,
                "validate_apply_run",
                side_effect=race_progress_after_validation,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "trusted_verified_requires_host_agent_attestation",
                ):
                    APPLY_MODULE.finalize_apply_run(run_dir, "controller", root=root)

    def test_fix_cycle_requires_current_fixer_and_binds_new_receipts_to_fixer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            task_id = self.first_task_id(run_dir)
            self.complete_subagent_serial_verification(root, run_dir, stop_after_quality=True)
            APPLY_MODULE.transition_task_state(run_dir, task_id, "FIXING", "controller", root=root)
            with self.assertRaisesRegex(ValueError, "current_fixer_completion_required"):
                APPLY_MODULE.transition_task_state(run_dir, task_id, "RE_REVIEW", "controller", root=root)

            APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "fixer", "controller", root=root)
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "fixer", "fixer-1", "spawned", "controller",
                root=root
            )
            (root / "src" / "feature_1_1.py").write_text("VALUE = 2\n", encoding="utf-8")
            (root / "tests" / "test_feature_1_1.py").write_text(
                "from src.feature_1_1 import VALUE\n\ndef test_value():\n    assert VALUE == 2\n",
                encoding="utf-8",
            )
            APPLY_MODULE.normalize_writer_report(
                run_dir,
                task_id,
                "fixer",
                "fixer-1",
                {
                    "status": "DONE",
                    "task_id": task_id,
                    "fixer_agent_id": "fixer-1",
                    "fixes": [
                        {
                            "finding": "quality correction",
                            "files_changed": [
                                "src/feature_1_1.py",
                                "tests/test_feature_1_1.py",
                            ],
                        }
                    ],
                    "evidence": ["focused behavior updated"],
                },
                "controller",
            root=root,
            )
            APPLY_MODULE.record_agent_status(
                run_dir, task_id, "fixer", "fixer-1", "completed", "controller",
                root=root
            )
            APPLY_MODULE.transition_task_state(run_dir, task_id, "RE_REVIEW", "controller", root=root)
            APPLY_MODULE.capture_task_change_set(run_dir, task_id, "controller", root=root)
            with tempfile.TemporaryDirectory() as command_bin:
                python_wrapper = Path(command_bin) / "python3"
                python_wrapper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                python_wrapper.chmod(0o755)
                with mock.patch.dict(
                    os.environ,
                    {"PATH": f"{command_bin}:{os.environ.get('PATH', '')}"},
                ):
                    progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
                    for command in progress["tasks"][0]["validation_commands"]:
                        APPLY_MODULE.execute_planned_validation(
                            run_dir, task_id, command["id"], "controller",
                            root=root
                        )

            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            task = progress["tasks"][0]
            reference = task["validation_receipts"][0]
            receipt = json.loads(
                (run_dir / task_id / reference["path"]).read_text(encoding="utf-8")
            )
            self.assertEqual(task["implementation_generation"], 2)
            self.assertEqual(receipt["producer_binding"]["role"], "fixer")
            self.assertEqual(receipt["producer_binding"]["agent_id"], "fixer-1")

    def test_multi_task_partial_final_review_is_valid_and_resumable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_apply_fixture(root)
            write_audit(
                root / "Planner-docs",
                "PASS",
                readiness_rows=[
                    "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                    "|---|---|---|---|---|---|",
                    "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | READY | none | independent | Contract complete. | none |",
                    "| Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | READY | none | independent | Contract complete. | none |",
                ],
            )
            result = self.create_apply_run(root, "subagent_serial")
            run_dir = Path(result["run_dir"])
            self.complete_subagent_serial_verification(root, run_dir)

            final_review = json.loads((run_dir / "Final-Review.json").read_text(encoding="utf-8"))
            self.assertEqual(final_review["status"], "in_progress")
            self.assertEqual(APPLY_MODULE.validate_apply_run(run_dir, root), [])


if __name__ == "__main__":
    unittest.main()
