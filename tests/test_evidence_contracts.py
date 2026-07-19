from __future__ import annotations

import copy
import hashlib
import hmac
import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/evidence_contracts.py"
SPEC = importlib.util.spec_from_file_location("codexqb_evidence_contracts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
EVIDENCE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EVIDENCE)

MASTER_KEY = b"k" * EVIDENCE.MASTER_KEY_BYTES
OTHER_KEY = b"o" * EVIDENCE.MASTER_KEY_BYTES


def sha(character: str) -> str:
    assert len(character) == 1 and character in "0123456789abcdef"
    return character * 64


def changed_files() -> list[dict[str, object]]:
    return [
        {
            "path": "src/example.py",
            "change": "modified",
            "before_sha256": sha("1"),
            "after_sha256": sha("2"),
        }
    ]


def snapshot(captured_at: str, *, marker: str) -> dict[str, object]:
    manifest = changed_files()
    return {
        "captured_at": captured_at,
        "vcs": "git",
        "head_commit": "a" * 40,
        "base_commit": "b" * 40,
        "git_status_porcelain_sha256": sha(marker),
        "staged_diff_sha256": sha("3"),
        "unstaged_diff_sha256": sha("4"),
        "untracked_inventory_sha256": sha("5"),
        "review_package_sha256": sha("6"),
        "changed_files": manifest,
        "changed_files_sha256": EVIDENCE.canonical_json_digest(manifest),
    }


def run_binding() -> dict[str, object]:
    return {
        "root_binding_sha256": sha("7"),
        "root_device": 16777234,
        "root_inode": 123456,
        "apply_run_registration_id": sha("8"),
        "apply_run_id": "apply-direct-abcdef012345-unit",
        "apply_spec_digest": sha("9"),
        "workspace_mode": "verified_isolated_worktree",
    }


def task_binding() -> dict[str, object]:
    return {
        "task_id": "AR-apply-direct-abcdef012345-unit-T001",
        "brief_sha256": sha("a"),
        "implementation_contract_digest": sha("b"),
        "task_contract_digest": sha("c"),
        "implementation_generation": 2,
        "fix_cycle_count": 1,
    }


def common_receipt(*, kind: str, version: int, scope: str, issued_at: str) -> dict[str, object]:
    return {
        "receipt_kind": kind,
        "receipt_version": version,
        "receipt_id": sha("d"),
        "trust_key_id": EVIDENCE.trust_key_id(MASTER_KEY),
        "issued_at": issued_at,
        "observer": EVIDENCE.CONTROLLER_OBSERVER,
        "observation_scope": scope,
        "host_sandbox_proof": EVIDENCE.NOT_OBSERVED,
        "approval_proof": EVIDENCE.NOT_OBSERVED,
        "network_enforcement_proof": EVIDENCE.NOT_OBSERVED,
        "run_binding": run_binding(),
        "task_binding": task_binding(),
    }


def validation_receipt() -> dict[str, object]:
    payload = common_receipt(
        kind=EVIDENCE.VALIDATION_RECEIPT_KIND,
        version=EVIDENCE.VALIDATION_RECEIPT_VERSION,
        scope=EVIDENCE.VALIDATION_OBSERVATION_SCOPE,
        issued_at="2026-07-14T10:00:04Z",
    )
    payload.update(
        {
            "producer_binding": {
                "producer_kind": "agent",
                "identity_assurance": "controller_asserted",
                "role": "implementer",
                "agent_id": "implementer:unit-01",
                "attempt": 1,
                "completed_event_sequence": 4,
                "agent_run_sha256": sha("e"),
                "observed_after_event_sequence": 5,
            },
            "command": {
                "validation_id": "VAL-UNIT-01",
                "planned_command_digest": sha("f"),
                "argv": ["python3", "-B", "-m", "unittest", "tests.test_example"],
                "cwd": ".",
                "expected_exit_code": 0,
                "timeout_seconds": 120,
                "planned_network": "deny",
                "probe_tier": 1,
                "execution_nonce": sha("0"),
                "started_at": "2026-07-14T10:00:01Z",
                "finished_at": "2026-07-14T10:00:02Z",
            },
            "result": {
                "exit_code": 0,
                "timed_out": False,
                "termination_reason": "exited",
                "stdout_sha256": sha("1"),
                "stderr_sha256": sha("2"),
                "combined_output_sha256": sha("3"),
                "stdout_bytes": 3,
                "stderr_bytes": 2,
                "combined_output_bytes": 5,
                "artifacts": [
                    {"path": "reports/a.txt", "sha256": sha("4")},
                    {"path": "reports/b.txt", "sha256": sha("5")},
                ],
            },
            "code_snapshot_before": snapshot("2026-07-14T10:00:00Z", marker="6"),
            "code_snapshot_after": snapshot("2026-07-14T10:00:03Z", marker="7"),
        }
    )
    return payload


def review_completion_receipt() -> dict[str, object]:
    references = [
        {"receipt_id": sha("1"), "receipt_sha256": sha("2")},
        {"receipt_id": sha("3"), "receipt_sha256": sha("4")},
    ]
    payload = common_receipt(
        kind=EVIDENCE.REVIEW_COMPLETION_RECEIPT_KIND,
        version=EVIDENCE.REVIEW_COMPLETION_RECEIPT_VERSION,
        scope=EVIDENCE.REVIEW_COMPLETION_OBSERVATION_SCOPE,
        issued_at="2026-07-14T10:01:00Z",
    )
    payload.update(
        {
            "reviewer_binding": {
                "reviewer_kind": "agent",
                "identity_assurance": "controller_asserted",
                "role": "security_reviewer",
                "agent_id": "security-reviewer:unit-01",
                "attempt": 1,
                "dispatch_packet_sha256": sha("5"),
                "agent_run_sha256": sha("6"),
                "completed_at": "2026-07-14T10:00:59Z",
            },
            "review_binding": {
                "task_review_sha256": sha("7"),
                "review_package_sha256": sha("8"),
                "code_snapshot_sha256": sha("9"),
                "validation_receipts": references,
                "validation_receipt_set_sha256": EVIDENCE.canonical_json_digest(references),
                "verdict": "pass",
            },
            "ordering": {
                "producer_completed_event_sequence": 10,
                "validation_receipts_published_event_sequence": 11,
                "reviewer_dispatch_event_sequence": 12,
                "reviewer_spawned_event_sequence": 13,
                "reviewer_completed_event_sequence": 14,
                "receipt_issued_after_event_sequence": 15,
            },
        }
    )
    return payload


class EvidenceContractsTests(unittest.TestCase):
    def test_canonical_json_is_stable_and_rejects_ambiguous_values(self) -> None:
        left = {"z": [3, 2, 1], "a": {"b": "Türkçe", "a": True}}
        right = {"a": {"a": True, "b": "Türkçe"}, "z": [3, 2, 1]}
        self.assertEqual(EVIDENCE.canonical_json_bytes(left), EVIDENCE.canonical_json_bytes(right))
        self.assertEqual(EVIDENCE.canonical_json_digest(left), EVIDENCE.canonical_json_digest(right))
        self.assertNotIn(b" ", EVIDENCE.canonical_json_bytes(left))
        with self.assertRaises(TypeError):
            EVIDENCE.canonical_json_bytes({1: "non-string key"})
        with self.assertRaises(ValueError):
            EVIDENCE.canonical_json_bytes({"number": float("nan")})
        with self.assertRaises(TypeError):
            EVIDENCE.canonical_json_bytes({"bytes": b"not-json"})

    def test_validation_receipt_sign_verify_and_tamper_detection(self) -> None:
        payload = validation_receipt()
        self.assertEqual([], EVIDENCE.validation_receipt_errors(payload, require_mac=False))
        signed = EVIDENCE.sign_validation_receipt(payload, MASTER_KEY)
        self.assertEqual([], EVIDENCE.validation_receipt_errors(signed))
        self.assertTrue(EVIDENCE.verify_validation_receipt(signed, MASTER_KEY))
        self.assertFalse(EVIDENCE.verify_validation_receipt(signed, OTHER_KEY))

        tampered_payload = copy.deepcopy(signed)
        tampered_payload["result"]["exit_code"] = 1
        self.assertFalse(EVIDENCE.verify_validation_receipt(tampered_payload, MASTER_KEY))
        tampered_mac = copy.deepcopy(signed)
        tampered_mac[EVIDENCE.RECEIPT_MAC_FIELD] = sha("0")
        self.assertFalse(EVIDENCE.verify_validation_receipt(tampered_mac, MASTER_KEY))

    def test_validation_receipt_accepts_js_network_enforcement_proofs(self) -> None:
        # The JS validation profile kernel-denies outbound INET sockets, so a
        # validation receipt may promote `network_enforcement_proof` to a
        # recognized enforced value while every other proof stays not_observed.
        for proof in (
            EVIDENCE.ENFORCED_SECCOMP_INET_DENY,
            EVIDENCE.ENFORCED_SEATBELT_DENY_NETWORK,
        ):
            with self.subTest(proof=proof):
                payload = validation_receipt()
                payload["network_enforcement_proof"] = proof
                self.assertEqual([], EVIDENCE.validation_receipt_errors(payload, require_mac=False))
                signed = EVIDENCE.sign_validation_receipt(payload, MASTER_KEY)
                self.assertEqual([], EVIDENCE.validation_receipt_errors(signed))
                self.assertTrue(EVIDENCE.verify_validation_receipt(signed, MASTER_KEY))

        # The other two proof fields stay fail-closed even on a validation receipt.
        for field in ("host_sandbox_proof", "approval_proof"):
            with self.subTest(field=field):
                payload = validation_receipt()
                payload[field] = EVIDENCE.ENFORCED_SEATBELT_DENY_NETWORK
                self.assertIn(f"invalid_nonclaim={field}", EVIDENCE.validation_receipt_errors(payload, require_mac=False))

        # Review-completion receipts may never claim network enforcement.
        review = review_completion_receipt()
        review["network_enforcement_proof"] = EVIDENCE.ENFORCED_SECCOMP_INET_DENY
        self.assertIn(
            "invalid_nonclaim=network_enforcement_proof",
            EVIDENCE.review_completion_receipt_errors(review, require_mac=False),
        )

    def test_review_receipt_sign_verify_and_hmac_domains_are_separate(self) -> None:
        payload = review_completion_receipt()
        self.assertEqual([], EVIDENCE.review_completion_receipt_errors(payload, require_mac=False))
        signed = EVIDENCE.sign_review_completion_receipt(payload, MASTER_KEY)
        self.assertTrue(EVIDENCE.verify_review_completion_receipt(signed, MASTER_KEY))
        self.assertFalse(EVIDENCE.verify_review_completion_receipt(signed, OTHER_KEY))
        self.assertFalse(EVIDENCE.verify_validation_receipt(signed, MASTER_KEY))
        self.assertNotEqual(
            EVIDENCE.derive_validation_receipt_key(MASTER_KEY),
            EVIDENCE.derive_review_completion_receipt_key(MASTER_KEY),
        )

        forged = copy.deepcopy(signed)
        unsigned = {key: value for key, value in forged.items() if key != EVIDENCE.RECEIPT_MAC_FIELD}
        forged[EVIDENCE.RECEIPT_MAC_FIELD] = hmac.new(
            EVIDENCE.derive_validation_receipt_key(MASTER_KEY),
            EVIDENCE.REVIEW_MAC_DOMAIN + EVIDENCE.canonical_json_bytes(unsigned),
            hashlib.sha256,
        ).hexdigest()
        self.assertFalse(EVIDENCE.verify_review_completion_receipt(forged, MASTER_KEY))

    def test_missing_unknown_type_tricks_and_nonclaims_fail_closed(self) -> None:
        cases: list[dict[str, object]] = []
        missing = validation_receipt()
        del missing["task_binding"]
        cases.append(missing)
        unknown = validation_receipt()
        unknown["command"]["shell"] = True
        cases.append(unknown)
        bool_version = validation_receipt()
        bool_version["receipt_version"] = True
        cases.append(bool_version)
        bool_device = validation_receipt()
        bool_device["run_binding"]["root_device"] = True
        cases.append(bool_device)
        bool_timeout = validation_receipt()
        bool_timeout["command"]["timeout_seconds"] = True
        cases.append(bool_timeout)
        bool_exit = validation_receipt()
        bool_exit["result"]["exit_code"] = True
        cases.append(bool_exit)
        false_claim = validation_receipt()
        false_claim["host_sandbox_proof"] = "enforced"
        cases.append(false_claim)
        approval_boolean_claim = validation_receipt()
        approval_boolean_claim["approval_proof"] = True
        cases.append(approval_boolean_claim)
        approval_label_claim = validation_receipt()
        approval_label_claim["approval_proof"] = "approved"
        cases.append(approval_label_claim)
        sandbox_label_claim = validation_receipt()
        sandbox_label_claim["host_sandbox_proof"] = "read-only"
        cases.append(sandbox_label_claim)
        network_label_claim = validation_receipt()
        network_label_claim["network_enforcement_proof"] = "deny"
        cases.append(network_label_claim)
        controller_promoted_identity = validation_receipt()
        controller_promoted_identity["producer_binding"]["identity_assurance"] = "host_attested"
        cases.append(controller_promoted_identity)
        non_string_key = validation_receipt()
        non_string_key["command"][1] = "not allowed"
        cases.append(non_string_key)

        for payload in cases:
            with self.subTest(payload=payload), self.assertRaises(EVIDENCE.ReceiptValidationError):
                EVIDENCE.sign_validation_receipt(payload, MASTER_KEY)

        promoted_reviewer = review_completion_receipt()
        promoted_reviewer["reviewer_binding"]["identity_assurance"] = "host_attested"
        with self.assertRaises(EVIDENCE.ReceiptValidationError):
            EVIDENCE.sign_review_completion_receipt(promoted_reviewer, MASTER_KEY)

    def test_artifact_paths_reject_traversal_duplicates_and_ambiguity(self) -> None:
        self.assertTrue(EVIDENCE.is_safe_artifact_path("reports/qa-result.json"))
        self.assertTrue(EVIDENCE.is_safe_artifact_path(".", allow_dot=True))
        for path in (
            "../secret",
            "reports/../../secret",
            "/tmp/result",
            "reports\\result",
            ".git/config",
            ".Git/config",
            ".codexqb/secret",
            "reports//result",
            "reports/result ",
            "C:/result",
        ):
            with self.subTest(path=path):
                self.assertFalse(EVIDENCE.is_safe_artifact_path(path))

        for paths in (
            ["../secret"],
            ["reports/b.txt", "reports/a.txt"],
            ["reports/a.txt", "reports/a.txt"],
        ):
            with self.subTest(paths=paths):
                payload = validation_receipt()
                payload["result"]["artifacts"] = [
                    {"path": path, "sha256": sha("1")} for path in paths
                ]
                self.assertTrue(EVIDENCE.validation_receipt_errors(payload, require_mac=False))
                with self.assertRaises(EVIDENCE.ReceiptValidationError):
                    EVIDENCE.sign_validation_receipt(payload, MASTER_KEY)

    def test_changed_file_manifest_is_conditional_unique_sorted_and_hashed(self) -> None:
        base = validation_receipt()
        malformed_manifests: list[object] = [
            [
                {
                    "path": "src/new.py",
                    "change": "added",
                    "before_sha256": sha("1"),
                    "after_sha256": sha("2"),
                }
            ],
            [
                {
                    "path": "src/old.py",
                    "change": "deleted",
                    "before_sha256": sha("1"),
                    "after_sha256": sha("2"),
                }
            ],
            [
                {
                    "path": "src/same.py",
                    "change": "modified",
                    "before_sha256": sha("1"),
                    "after_sha256": sha("1"),
                }
            ],
            [
                {
                    "path": "src/z.py",
                    "change": "added",
                    "before_sha256": None,
                    "after_sha256": sha("2"),
                },
                {
                    "path": "src/a.py",
                    "change": "deleted",
                    "before_sha256": sha("1"),
                    "after_sha256": None,
                },
            ],
            [
                {
                    "path": "src/a.py",
                    "change": "added",
                    "before_sha256": None,
                    "after_sha256": sha("2"),
                },
                {
                    "path": "src/a.py",
                    "change": "deleted",
                    "before_sha256": sha("1"),
                    "after_sha256": None,
                },
            ],
            [{"path": "src/a.py", "change": "added", "before_sha256": None, "after_sha256": object()}],
        ]
        for manifest in malformed_manifests:
            with self.subTest(manifest=manifest):
                payload = copy.deepcopy(base)
                payload["code_snapshot_after"]["changed_files"] = manifest
                try:
                    payload["code_snapshot_after"]["changed_files_sha256"] = EVIDENCE.canonical_json_digest(manifest)
                except (TypeError, ValueError):
                    payload["code_snapshot_after"]["changed_files_sha256"] = sha("0")
                self.assertTrue(EVIDENCE.validation_receipt_errors(payload, require_mac=False))
                with self.assertRaises(EVIDENCE.ReceiptValidationError):
                    EVIDENCE.sign_validation_receipt(payload, MASTER_KEY)

        digest_mismatch = validation_receipt()
        digest_mismatch["code_snapshot_after"]["changed_files_sha256"] = sha("0")
        self.assertIn(
            "changed_files_digest_mismatch=receipt.code_snapshot_after.changed_files",
            EVIDENCE.validation_receipt_errors(digest_mismatch, require_mac=False),
        )

    def test_validation_timestamp_order_is_strictly_observed(self) -> None:
        mutations = [
            ("command", "finished_at", "2026-07-14T10:00:00Z"),
            ("code_snapshot_before", "captured_at", "2026-07-14T10:00:02Z"),
            ("code_snapshot_after", "captured_at", "2026-07-14T10:00:01Z"),
        ]
        for section, field, value in mutations:
            with self.subTest(section=section, field=field):
                payload = validation_receipt()
                payload[section][field] = value
                self.assertTrue(EVIDENCE.validation_receipt_errors(payload, require_mac=False))

        issued_too_early = validation_receipt()
        issued_too_early["issued_at"] = "2026-07-14T10:00:02Z"
        self.assertIn(
            "receipt_issued_before_snapshot_after",
            EVIDENCE.validation_receipt_errors(issued_too_early, require_mac=False),
        )

    def test_review_references_ordering_and_completion_time_fail_closed(self) -> None:
        invalid_order = review_completion_receipt()
        invalid_order["ordering"]["reviewer_dispatch_event_sequence"] = 10
        self.assertIn(
            "invalid_agent_review_event_order",
            EVIDENCE.review_completion_receipt_errors(invalid_order, require_mac=False),
        )

        missing_issue_sequence = review_completion_receipt()
        missing_issue_sequence["ordering"]["receipt_issued_after_event_sequence"] = None
        self.assertTrue(EVIDENCE.review_completion_receipt_errors(missing_issue_sequence, require_mac=False))

        completed_too_late = review_completion_receipt()
        completed_too_late["reviewer_binding"]["completed_at"] = "2026-07-14T10:01:01Z"
        self.assertIn(
            "review_receipt_issued_before_completed_at",
            EVIDENCE.review_completion_receipt_errors(completed_too_late, require_mac=False),
        )

        duplicate_references = review_completion_receipt()
        references = duplicate_references["review_binding"]["validation_receipts"]
        references[1]["receipt_id"] = references[0]["receipt_id"]
        duplicate_references["review_binding"]["validation_receipt_set_sha256"] = (
            EVIDENCE.canonical_json_digest(references)
        )
        self.assertIn(
            "duplicate_validation_receipt_id",
            EVIDENCE.review_completion_receipt_errors(duplicate_references, require_mac=False),
        )

    def test_controller_direct_shapes_are_explicit_and_valid(self) -> None:
        validation = validation_receipt()
        validation["producer_binding"] = {
            "producer_kind": "controller_direct",
            "identity_assurance": "controller_asserted",
            "role": "controller",
            "agent_id": None,
            "attempt": None,
            "completed_event_sequence": None,
            "agent_run_sha256": None,
            "observed_after_event_sequence": 5,
        }
        self.assertEqual([], EVIDENCE.validation_receipt_errors(validation, require_mac=False))

        review = review_completion_receipt()
        review["reviewer_binding"] = {
            "reviewer_kind": "controller_direct",
            "identity_assurance": "controller_asserted",
            "role": "controller",
            "agent_id": None,
            "attempt": None,
            "dispatch_packet_sha256": None,
            "agent_run_sha256": None,
            "completed_at": "2026-07-14T10:00:59Z",
        }
        review["ordering"] = {
            "producer_completed_event_sequence": None,
            "validation_receipts_published_event_sequence": 11,
            "reviewer_dispatch_event_sequence": None,
            "reviewer_spawned_event_sequence": None,
            "reviewer_completed_event_sequence": None,
            "receipt_issued_after_event_sequence": 15,
        }
        self.assertEqual([], EVIDENCE.review_completion_receipt_errors(review, require_mac=False))


if __name__ == "__main__":
    unittest.main()
