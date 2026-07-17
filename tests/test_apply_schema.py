from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from tests import test_apply_run as apply_test_helpers
from scripts import validate_apply_schema as schema_validation


try:
    from jsonschema import Draft202012Validator
except ImportError:  # pragma: no cover - CI installs the schema validation extra.
    Draft202012Validator = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPO_ROOT / "plugins/codexqb/skills/codexqb/references/apply-run-schema.json"
APPLY_MODULE = apply_test_helpers.APPLY_MODULE


@unittest.skipIf(Draft202012Validator is None, "jsonschema validation extra is not installed")
class ApplySchemaParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        apply_test_helpers.ApplyRunTests.setUpClass()
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        assert Draft202012Validator is not None
        Draft202012Validator.check_schema(cls.schema)

    @classmethod
    def tearDownClass(cls) -> None:
        apply_test_helpers.ApplyRunTests.tearDownClass()
        super().tearDownClass()

    def validator(self, definition: str):
        assert Draft202012Validator is not None
        return Draft202012Validator(
            {
                "$schema": self.schema["$schema"],
                "$defs": self.schema["$defs"],
                "$ref": f"#/$defs/{definition}",
            }
        )

    def schema_errors(self, definition: str, instance: object) -> list[object]:
        return list(self.validator(definition).iter_errors(instance))

    def create_writer_run(
        self,
        root: Path,
    ) -> tuple[apply_test_helpers.ApplyRunTests, Path, str]:
        case = apply_test_helpers.ApplyRunTests("test_init_subagent_serial_creates_safe_artifacts")
        case.write_apply_fixture(root)
        run_dir = Path(case.create_apply_run(root, "subagent_serial")["run_dir"])
        task_id = case.first_task_id(run_dir)
        APPLY_MODULE.prepare_dispatch_packet(run_dir, task_id, "implementer", "controller", root=root)
        APPLY_MODULE.record_agent_status(
            run_dir,
            task_id,
            "implementer",
            "schema-impl-1",
            "spawned",
            "controller",
        root=root,
        )
        APPLY_MODULE.transition_task_state(
            run_dir,
            task_id,
            "IMPLEMENTING",
            "schema-impl-1",
        root=root,
        )
        return case, run_dir, task_id

    def normalize_implementer(
        self,
        root: Path,
        run_dir: Path,
        task_id: str,
        **extra: object,
    ) -> dict[str, object]:
        payload: dict[str, object] = {
            "status": "DONE",
            "task_id": task_id,
            "implementer_agent_id": "schema-impl-1",
            "files_changed": [],
            "concerns": [],
        }
        payload.update(extra)
        APPLY_MODULE.normalize_writer_report(
            run_dir,
            task_id,
            "implementer",
            "schema-impl-1",
            payload,
            "controller",
        root=root,
        )
        return json.loads((run_dir / task_id / "Implementer-Report.json").read_text(encoding="utf-8"))

    def test_real_writer_report_lifecycle_validates_against_intended_definition(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)

            placeholder = {"status": "PENDING"}
            self.assertEqual(self.schema_errors("ImplementerReport", placeholder), [])

            normalized = self.normalize_implementer(root, run_dir, task_id)
            self.assertEqual(self.schema_errors("ImplementerReport", normalized), [])

            digest = "a" * 64
            evidence_bound = self.normalize_implementer(
                root,
                run_dir,
                task_id,
                files_changed=["src/example.py"],
                brief_sha256=digest,
                implementation_contract_digest=digest,
                task_contract_digest=digest,
                validation_receipt_ids=["b" * 64],
                change_set_id="c" * 64,
                diff_sha256="d" * 64,
            )
            self.assertEqual(self.schema_errors("ImplementerReport", evidence_bound), [])

            blocked = self.normalize_implementer(
                root,
                run_dir,
                task_id,
                status="BLOCKED",
                blocker="synthetic blocker",
            )
            self.assertEqual(self.schema_errors("ImplementerReport", blocked), [])

    def test_progress_schema_rejects_invalid_writer_report_bindings_like_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)
            self.normalize_implementer(root, run_dir, task_id)
            progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
            self.assertEqual(self.schema_errors("Progress", progress), [])

            progress["tasks"][0]["writer_report_bindings"] = "invalid"
            self.assertTrue(self.schema_errors("Progress", progress))

            (run_dir / "Progress.json").write_text(json.dumps(progress), encoding="utf-8")
            self.assertTrue(
                any("writer_report_bindings_invalid" in error for error in APPLY_MODULE.validate_apply_run(run_dir, root=root))
            )

    def test_root_union_cannot_accept_malformed_implementer_as_another_report_type(self) -> None:
        malformed = {
            "status": "DONE",
            "task_id": "AR-apply-subagent_serial-abcdef123456-demo-T001",
            "implementer_agent_id": "schema-impl-1",
            "files_changed": [],
            "concerns": [],
            "unexpected_writer_field": "must fail",
        }
        self.assertTrue(self.schema_errors("ImplementerReport", malformed))
        assert Draft202012Validator is not None
        self.assertTrue(list(Draft202012Validator(self.schema).iter_errors(malformed)))

    def test_not_observed_token_usage_requires_exact_runtime_sentinels(self) -> None:
        invalid = {
            "status": "not_observed",
            "input_tokens": 0,
            "output_tokens": 0,
            "total_tokens": 0,
            "source": "runtime_not_available",
        }
        self.assertTrue(self.schema_errors("TokenUsage", invalid))
        self.assertTrue(APPLY_MODULE.validate_token_usage(invalid))

    def test_fix_report_lifecycle_and_event_shape_use_intended_definitions(self) -> None:
        self.assertEqual(self.schema_errors("FixReport", {"status": "PENDING"}), [])
        normalized = {
            "status": "DONE",
            "task_id": "AR-apply-subagent_serial-abcdef123456-demo-T001",
            "fixer_agent_id": "schema-fixer-1",
            "fixes": [{"path": "src/example.py", "summary": "bounded correction"}],
            "concerns": [],
        }
        self.assertEqual(self.schema_errors("FixReport", normalized), [])
        malformed = dict(normalized)
        malformed["unexpected_writer_field"] = "must fail"
        self.assertTrue(self.schema_errors("FixReport", malformed))
        concern_without_decision = {
            **normalized,
            "status": "DONE_WITH_CONCERNS",
        }
        self.assertTrue(self.schema_errors("FixReport", concern_without_decision))

        event = {
            "event_chain_version": 1,
            "sequence": 1,
            "timestamp": "2026-07-14T12:00:00Z",
            "event_type": "run_initialized",
            "previous_event_sha256": "0" * 64,
            "event_sha256": "a" * 64,
        }
        self.assertEqual(self.schema_errors("Event", event), [])
        event.pop("timestamp")
        self.assertTrue(self.schema_errors("Event", event))

    def test_writer_normalizer_rejects_fields_not_declared_by_schema(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)
            with self.assertRaisesRegex(ValueError, "writer_report_unknown_field"):
                self.normalize_implementer(
                    root,
                    run_dir,
                    task_id,
                    unexpected_writer_field="must fail",
                )

    def test_writer_normalizer_rejects_schema_invalid_required_and_typed_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)
            base = {
                "status": "DONE",
                "task_id": task_id,
                "implementer_agent_id": "schema-impl-1",
                "files_changed": [],
            }
            with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "schema-impl-1",
                    base,
                    "controller",
                root=root,
                )
            invalid_evidence = {**base, "concerns": [], "evidence": 7}
            with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "schema-impl-1",
                    invalid_evidence,
                    "controller",
                root=root,
                )
            for invalid_paths in (["../escape"], ["src/example.py", "src/example.py"]):
                with self.subTest(invalid_paths=invalid_paths):
                    payload = {**base, "files_changed": invalid_paths, "concerns": []}
                    self.assertTrue(self.schema_errors("ImplementerReport", payload))
                    with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                        APPLY_MODULE.normalize_writer_report(
                            run_dir,
                            task_id,
                            "implementer",
                            "schema-impl-1",
                            payload,
                            "controller",
                        root=root,
                        )

    def test_implementer_evidence_fields_are_all_or_none_and_nonempty(self) -> None:
        digest = "a" * 64
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)
            partial = {
                "status": "DONE",
                "task_id": task_id,
                "implementer_agent_id": "schema-impl-1",
                "files_changed": [],
                "concerns": [],
                "brief_sha256": digest,
            }
            self.assertTrue(self.schema_errors("ImplementerReport", partial))
            with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "schema-impl-1",
                    partial,
                    "controller",
                root=root,
                )

            empty_bound = {
                **partial,
                "implementation_contract_digest": digest,
                "task_contract_digest": digest,
                "validation_receipt_ids": [],
                "change_set_id": digest,
                "diff_sha256": digest,
            }
            self.assertTrue(self.schema_errors("ImplementerReport", empty_bound))
            with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "schema-impl-1",
                    empty_bound,
                    "controller",
                root=root,
                )

            empty_decision = {
                "status": "DONE_WITH_CONCERNS",
                "task_id": task_id,
                "implementer_agent_id": "schema-impl-1",
                "files_changed": [],
                "concerns": ["bounded concern"],
                "controller_decision": "",
            }
            self.assertTrue(self.schema_errors("ImplementerReport", empty_decision))
            with self.assertRaisesRegex(ValueError, "writer_report_invalid"):
                APPLY_MODULE.normalize_writer_report(
                    run_dir,
                    task_id,
                    "implementer",
                    "schema-impl-1",
                    empty_decision,
                    "controller",
                root=root,
                )

    def test_filename_mapped_validator_checks_real_run_directory(self) -> None:
        self.assertEqual(schema_validation.check_schema_bundle(self.schema), [])
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)
            self.assertEqual(schema_validation.validate_run_directory(self.schema, run_dir), [])
            self.normalize_implementer(root, run_dir, task_id)
            self.assertEqual(schema_validation.validate_run_directory(self.schema, run_dir), [])

    def test_run_directory_validator_rejects_symlinks_and_missing_runtime_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            _, run_dir, task_id = self.create_writer_run(root)

            (run_dir / task_id / "Implementer-Report.json").unlink()
            (run_dir / "Writer-Lock.json").unlink()
            errors = schema_validation.validate_run_directory(self.schema, run_dir)
            self.assertIn("apply_schema_required_task_artifact_missing=Implementer-Report.json", errors)
            self.assertIn("apply_schema_writer_lock_missing", errors)

            apply_run_path = run_dir / "Apply-Run.json"
            outside = Path(outside_dir) / "outside.json"
            outside.write_bytes(apply_run_path.read_bytes())
            apply_run_path.unlink()
            apply_run_path.symlink_to(outside)
            errors = schema_validation.validate_run_directory(self.schema, run_dir)
            self.assertIn("apply_schema_symlink_artifact=Apply-Run.json", errors)

    def test_complete_runtime_receipt_chain_validates_every_emitted_json_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            case = apply_test_helpers.ApplyRunTests(
                "test_init_subagent_serial_creates_safe_artifacts"
            )
            case.write_apply_fixture(root)
            run_dir = Path(case.create_apply_run(root, "subagent_serial")["run_dir"])
            case.complete_subagent_serial_verification(root, run_dir)

            self.assertEqual(schema_validation.validate_run_directory(self.schema, run_dir), [])
            emitted_definitions = {
                schema_validation.definition_for_filename(path.name)
                for path in run_dir.rglob("*")
                if path.is_file() and path.suffix in {".json", ".jsonl"}
            }
            for definition in {
                "AgentRun",
                "ChangeSet",
                "ValidationReceipt",
                "ReviewReport",
                "ReviewReceipt",
                "Progress",
                "FinalReview",
                "Event",
            }:
                self.assertIn(definition, emitted_definitions)

            receipt_path = next(run_dir.rglob("Validation-Receipt-*.json"))
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            receipt["receipt_id"] = "invalid"
            receipt_path.write_text(json.dumps(receipt), encoding="utf-8")
            self.assertTrue(
                any(
                    error.startswith("schema_instance_invalid=ValidationReceipt:")
                    for error in schema_validation.validate_run_directory(self.schema, run_dir)
                )
            )


if __name__ == "__main__":
    unittest.main()
