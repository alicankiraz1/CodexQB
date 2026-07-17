from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.controller_test_support import real_trust_store_snapshot, temporary_controller_home
from tests.held_runtime_test_support import held_runtime_test_provider
from tests.test_apply_run import APPLY_MODULE, CONTROLLER_STORE_MODULE
from tests.test_validate_planner_docs import write_audit, write_valid_step2_fixture


class ApplyInventoryBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._real_trust_store_before_class = real_trust_store_snapshot()
        cls._controller_home = temporary_controller_home()
        cls._controller_home_provider = mock.patch.object(
            CONTROLLER_STORE_MODULE,
            "controller_home_directory",
            return_value=Path(cls._controller_home.name).resolve(),
        )
        cls._controller_home_provider.start()
        cls._held_runtime_provider = held_runtime_test_provider()
        cls._held_runtime_provider.__enter__()

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            cls._held_runtime_provider.__exit__(None, None, None)
            cls._controller_home_provider.stop()
            cls._controller_home.cleanup()
            if real_trust_store_snapshot() != cls._real_trust_store_before_class:
                raise AssertionError("real_controller_trust_store_changed_during_apply_inventory_tests")
        finally:
            super().tearDownClass()

    def setUp(self) -> None:
        self._real_trust_store_before_test = real_trust_store_snapshot()

    def tearDown(self) -> None:
        if real_trust_store_snapshot() != self._real_trust_store_before_test:
            raise AssertionError("real_controller_trust_store_changed_during_apply_inventory_test")

    def git(self, root: Path, *arguments: str) -> None:
        subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def test_explicit_runtime_exclusions_are_pruned_before_file_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.git(root, "init", "-q")
            (root / "visible.txt").write_bytes(b"ok")
            runtime = root / ".codexqb"
            runtime.mkdir()
            (runtime / "oversized.bin").write_bytes(b"x" * 128)

            with mock.patch.object(APPLY_MODULE, "MAX_WORKSPACE_INVENTORY_FILE_BYTES", 4):
                baseline, entries = APPLY_MODULE.workspace_baseline_capture(root)

            self.assertEqual(len(entries), 1)
            self.assertTrue(entries[0].startswith("visible.txt\t"))
            self.assertEqual(baseline["untracked_count"], 1)

    def test_gitignored_contract_external_file_remains_subject_to_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.git(root, "init", "-q")
            (root / ".gitignore").write_text("ignored.bin\n", encoding="utf-8")
            (root / "ignored.bin").write_bytes(b"x" * 17)

            with mock.patch.object(APPLY_MODULE, "MAX_WORKSPACE_INVENTORY_FILE_BYTES", 16):
                with self.assertRaisesRegex(ValueError, "repository_evidence_file_too_large"):
                    APPLY_MODULE.workspace_baseline(root)

    def test_tracked_runtime_exclusion_is_pruned_before_git_content_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.git(root, "init", "-q")
            runtime = root / ".codexqb"
            runtime.mkdir()
            excluded = runtime / "tracked.bin"
            included = root / "tracked.bin"
            excluded.write_bytes(b"small")
            included.write_bytes(b"small")
            self.git(root, "add", ".codexqb/tracked.bin", "tracked.bin")
            self.git(
                root,
                "-c",
                "user.name=CodexQB Test",
                "-c",
                "user.email=codexqb-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            oversized = APPLY_MODULE.DEFAULT_WORKSPACE_INVENTORY_MAX_FILE_BYTES + 1
            with excluded.open("r+b") as handle:
                handle.truncate(oversized)

            baseline = APPLY_MODULE.workspace_baseline(root)
            self.assertEqual(baseline["workspace_file_count"], 1)

            with included.open("r+b") as handle:
                handle.truncate(oversized)
            with self.assertRaisesRegex(ValueError, "repository_io_workspace_proof_failed"):
                APPLY_MODULE.workspace_baseline(root)

    def test_workspace_inventory_path_and_shared_total_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "one.txt").write_bytes(b"1234")
            (root / "two.txt").write_bytes(b"5678")
            (root / "three.txt").write_bytes(b"9")

            with mock.patch.object(APPLY_MODULE, "MAX_WORKSPACE_INVENTORY_PATHS", 2):
                with self.assertRaisesRegex(ValueError, "repository_evidence_path_count_exceeded"):
                    APPLY_MODULE.workspace_baseline(root)
            with mock.patch.object(APPLY_MODULE, "MAX_WORKSPACE_INVENTORY_TOTAL_BYTES", 17):
                with self.assertRaisesRegex(ValueError, "repository_evidence_total_bytes_exceeded"):
                    APPLY_MODULE.workspace_baseline(root)

    def test_git_untracked_content_mode_and_kind_change_baseline_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.git(root, "init", "-q")
            tracked = root / "tracked.txt"
            tracked.write_text("tracked\n", encoding="utf-8")
            self.git(root, "add", "tracked.txt")
            self.git(
                root,
                "-c",
                "user.name=CodexQB Test",
                "-c",
                "user.email=codexqb-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            local = root / "local.txt"
            local.write_text("first\n", encoding="utf-8")
            first = APPLY_MODULE.workspace_baseline(root)

            local.write_text("second\n", encoding="utf-8")
            content_changed = APPLY_MODULE.workspace_baseline(root)
            self.assertNotEqual(
                first["untracked_inventory_sha256"],
                content_changed["untracked_inventory_sha256"],
            )

            local.chmod(0o755)
            mode_changed = APPLY_MODULE.workspace_baseline(root)
            self.assertNotEqual(
                content_changed["untracked_inventory_sha256"],
                mode_changed["untracked_inventory_sha256"],
            )

            local.unlink()
            local.symlink_to("tracked.txt")
            kind_changed = APPLY_MODULE.workspace_baseline(root)
            self.assertNotEqual(
                mode_changed["untracked_inventory_sha256"],
                kind_changed["untracked_inventory_sha256"],
            )

    def test_manifest_schema_and_normal_drift_remain_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "value.txt"
            target.write_text("before\n", encoding="utf-8")
            target.chmod(0o644)
            first_baseline, first_manifest = APPLY_MODULE.workspace_baseline_capture(root)

            self.assertIsNotNone(APPLY_MODULE.workspace_file_manifest_map(first_manifest))
            self.assertEqual(
                APPLY_MODULE.hash_inventory(first_manifest),
                first_baseline["workspace_file_inventory_sha256"],
            )

            target.write_text("after\n", encoding="utf-8")
            target.chmod(0o755)
            second_baseline, second_manifest = APPLY_MODULE.workspace_baseline_capture(root)
            self.assertNotEqual(first_manifest, second_manifest)
            self.assertNotEqual(
                first_baseline["workspace_file_inventory_sha256"],
                second_baseline["workspace_file_inventory_sha256"],
            )

    def test_apply_run_mutation_rejects_low_mount_assurance_before_writes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            low_assurance = object()
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

            with mock.patch.object(
                APPLY_MODULE,
                "resolve_mount_identity",
                return_value=low_assurance,
            ), mock.patch.object(
                APPLY_MODULE,
                "require_mount_assurance",
                side_effect=ValueError("secure_repository_mount_identity_unavailable"),
            ) as require_assurance:
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_repository_mount_identity_unavailable",
                ):
                    APPLY_MODULE.create_apply_run(
                        root,
                        "no_action",
                        allow_non_git_unsafe=True,
                        allow_unverified_git_worktree=True,
                    )

            require_assurance.assert_any_call(low_assurance, APPLY_MODULE.APPLY_RUN_MUTATION)
            self.assertFalse((root / ".codexqb").exists())


if __name__ == "__main__":
    unittest.main()
