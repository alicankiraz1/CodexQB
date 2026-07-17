from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.controller_test_support import real_trust_store_snapshot


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb"
OPENAI_YAML_VALIDATOR_PATH = REPO_ROOT / "scripts/validate_openai_yaml.py"


def load_openai_yaml_validator():
    spec = importlib.util.spec_from_file_location(
        "codexqb_validate_openai_yaml",
        OPENAI_YAML_VALIDATOR_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load validator from {OPENAI_YAML_VALIDATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


OPENAI_YAML_VALIDATOR = load_openai_yaml_validator()


class SkillContentTests(unittest.TestCase):
    def test_skill_references_repo_aware_intake(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("references/repo-aware-intake.md", skill)
        self.assertIn("repo-aware", skill.lower())

    def test_openai_yaml_semantics_are_canonical_and_explicit_only(self) -> None:
        yaml_text = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        values, errors = OPENAI_YAML_VALIDATOR.validate_openai_yaml_text(yaml_text)

        self.assertEqual(errors, [])
        self.assertEqual(values["display_name"], "CodexQB")
        self.assertLessEqual(len(values["short_description"]), 80)
        self.assertIn("vibecoding", values["short_description"].lower())
        self.assertIn("$codexqb", values["default_prompt"])
        self.assertLessEqual(len(values["default_prompt"]), 220)

        commented = "# activation metadata\r\n\r\n" + yaml_text.replace("\n", "\r\n").rstrip("\r\n")
        _commented_values, commented_errors = OPENAI_YAML_VALIDATOR.validate_openai_yaml_text(
            commented
        )
        self.assertEqual(commented_errors, [])

    def test_openai_yaml_rejects_duplicate_wrong_type_and_noncanonical_policy(self) -> None:
        interface = (
            "interface:\n"
            '  display_name: "CodexQB"\n'
            '  short_description: "Vibecoding evidence"\n'
            '  default_prompt: "Use $codexqb explicitly."\n'
        )
        invalid_samples = {
            "missing": interface,
            "true": interface + "policy:\n  allow_implicit_invocation: true\n",
            "quoted_double": interface + 'policy:\n  allow_implicit_invocation: "false"\n',
            "quoted_single": interface + "policy:\n  allow_implicit_invocation: 'false'\n",
            "case_varied": interface + "policy:\n  allow_implicit_invocation: False\n",
            "numeric": interface + "policy:\n  allow_implicit_invocation: 0\n",
            "null": interface + "policy:\n  allow_implicit_invocation: null\n",
            "inline_comment": interface + "policy:\n  allow_implicit_invocation: false # unsafe ambiguity\n",
            "duplicate_section_false_true": (
                interface
                + "policy:\n  allow_implicit_invocation: false\n"
                + "policy:\n  allow_implicit_invocation: true\n"
            ),
            "duplicate_section_true_false": (
                interface
                + "policy:\n  allow_implicit_invocation: true\n"
                + "policy:\n  allow_implicit_invocation: false\n"
            ),
            "duplicate_key": (
                interface
                + "policy:\n  allow_implicit_invocation: false\n"
                + "  allow_implicit_invocation: true\n"
            ),
            "extra_policy_key": (
                interface
                + "policy:\n  allow_implicit_invocation: false\n  extra: value\n"
            ),
            "merge_key": (
                interface
                + "policy:\n  <<: *defaults\n  allow_implicit_invocation: false\n"
            ),
            "flow_mapping": interface + "policy: {allow_implicit_invocation: false}\n",
            "wrong_nesting": interface + "  policy:\n    allow_implicit_invocation: false\n",
            "tab_indent": interface + "policy:\n\tallow_implicit_invocation: false\n",
            "second_document": (
                interface
                + "policy:\n  allow_implicit_invocation: false\n"
                + "---\npolicy:\n  allow_implicit_invocation: true\n"
            ),
            "bare_interface_colon": interface.replace(
                '  default_prompt: "Use $codexqb explicitly."\n',
                "  default_prompt: Use $codexqb: true\n",
            )
            + "policy:\n  allow_implicit_invocation: false\n",
            "single_quoted_interface": interface.replace(
                '  display_name: "CodexQB"\n',
                "  display_name: 'CodexQB'\n",
            )
            + "policy:\n  allow_implicit_invocation: false\n",
            "raw_control_interface": interface.replace(
                '  default_prompt: "Use $codexqb explicitly."\n',
                '  default_prompt: "Use $codexqb ' + chr(1) + '"\n',
            )
            + "policy:\n  allow_implicit_invocation: false\n",
        }
        slash = chr(92)
        for name, escape in {
            "surrogate_high": "ud800",
            "surrogate_low": "udfff",
            "surrogate_pair": "ud83d" + slash + "ude00",
        }.items():
            invalid_samples[name] = interface.replace(
                '  default_prompt: "Use $codexqb explicitly."\n',
                f'  default_prompt: "Use $codexqb {slash}{escape}"\n',
            ) + "policy:\n  allow_implicit_invocation: false\n"
        for name, sample in invalid_samples.items():
            with self.subTest(name=name):
                _values, errors = OPENAI_YAML_VALIDATOR.validate_openai_yaml_text(sample)
                self.assertTrue(errors)

        validate_script = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/check_repository_io_policy.py", validate_script)

    def test_language_contract_is_documented(self) -> None:
        required_phrases = [
            "CodexQB asks intake questions in the user's language when practical.",
            "Generated Planner-docs artifacts are English by default unless the user explicitly requests another content language.",
            "Required document headings remain English for validator stability.",
        ]
        checked_files = [
            REPO_ROOT / "README.md",
            REPO_ROOT / "docs/USAGE.md",
            SKILL_ROOT / "SKILL.md",
        ]
        for path in checked_files:
            text = path.read_text(encoding="utf-8")
            for phrase in required_phrases:
                self.assertIn(phrase, text, path.name)

        for path in [
            SKILL_ROOT / "references/First-Planner.md",
            SKILL_ROOT / "references/Second-Planner.md",
            SKILL_ROOT / "references/Third-Planner.md",
        ]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("English by default unless the user explicitly requests another content language", text, path.name)
            self.assertIn("Required document headings remain English", text, path.name)

        for path in [REPO_ROOT / "README.md", REPO_ROOT / "docs/USAGE.md", REPO_ROOT / "docs/MAINTAINING.md"]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("PLANNER_DOC_LANGUAGE", text, path.name)

    def test_repo_aware_intake_keeps_stable_four_fields(self) -> None:
        intake = (SKILL_ROOT / "references/repo-aware-intake.md").read_text(encoding="utf-8")
        for field in ["PROJECT_NAME", "PROJECT_INTENT", "TARGET_END_STATE", "KNOWN_CONSTRAINTS"]:
            self.assertIn(field, intake)
        for number in range(1, 5):
            self.assertIn(f"Question {number} / 4", intake)
        self.assertIn("Use plain text only", intake)
        self.assertIn("Pre-Intake Scan", intake)

    def test_first_planner_required_placeholders_remain_stable(self) -> None:
        first_planner = (SKILL_ROOT / "references/First-Planner.md").read_text(encoding="utf-8")
        headings = re.findall(r"^([A-Z_]+):$", first_planner, flags=re.MULTILINE)
        required = ["PROJECT_NAME", "PROJECT_INTENT", "TARGET_END_STATE", "KNOWN_CONSTRAINTS"]
        for field in required:
            self.assertIn(field, headings)
        positions = [headings.index(field) for field in required]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn("INTAKE_EVIDENCE_SUMMARY:", first_planner)

    def test_autopsy_planner_is_wired_into_skill_and_step2(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        second = (SKILL_ROOT / "references/Second-Planner.md").read_text(encoding="utf-8")
        autopsy = (SKILL_ROOT / "references/Autopsy-Planner.md").read_text(encoding="utf-8")

        self.assertIn("references/Autopsy-Planner.md", skill)
        self.assertIn("Step 1.5", skill)
        self.assertIn("Planner-docs/Autopsy.md", second)
        self.assertIn("Autopsy.md is not a replacement for Main-Planing.md", second)

        required_headings = [
            "# Project Autopsy",
            "## 1. Executive Summary",
            "## 2. Reviewed Sources",
            "## 3. Project Areas and Ownership Boundaries",
            "## 4. Feature Inventory",
            "## 5. Placeholder, Stub, and Skeleton Analysis",
            "## 6. Technical Debt and Maintenance Risks",
            "## 7. Broken or Missing Integrations",
            "## 8. Test, CI, and Validation Gaps",
            "## 9. Security, Secret, and Governance Findings",
            "## 10. Operational Readiness and Observability",
            "## 11. Alignment Analysis with the Main Plan",
            "## 12. Autopsy Feedback for Step 2",
            "## 13. Priority Fix and Planning Signals",
        ]
        for heading in required_headings:
            self.assertIn(heading, autopsy)

    def test_validator_guidance_does_not_assume_global_skill_path(self) -> None:
        checked_files = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/workflow-quality.md",
            SKILL_ROOT / "references/Second-Planner.md",
            SKILL_ROOT / "references/Third-Planner.md",
        ]
        for path in checked_files:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("~/.codex/skills/codexqb/scripts/validate_planner_docs.py", text, path.name)
            self.assertIn("bundled", text, path.name)
            self.assertIn(
                '"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"',
                text,
                path.name,
            )
            self.assertIn("--controller planner-validator", text, path.name)
            self.assertNotIn(
                '"<CODEXQB_SKILL_ROOT>/scripts/validate_planner_docs.py"',
                text,
                path.name,
            )
            self.assertNotIn(
                "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py",
                text,
                path.name,
            )
            self.assertIn("`BLOCKED`", text, path.name)
            self.assertNotIn("equivalent all-file validation", text, path.name)

    def test_fourth_planner_external_skills_are_optional(self) -> None:
        fourth = (SKILL_ROOT / "references/handoffs/run-step4.md").read_text(encoding="utf-8")
        self.assertIn("if installed/available", fourth.lower())
        self.assertIn("superpowers:executing-plans", fourth)
        self.assertIn("codex-security", fourth)
        self.assertIn("continue using the audit", fourth)

    def test_fourth_planner_runs_queue_continuously_with_stop_gates(self) -> None:
        fourth = (SKILL_ROOT / "references/handoffs/run-step4.md").read_text(encoding="utf-8")
        self.assertIn("Build an ordered implementation queue", fourth)
        self.assertIn("Default Goal batch", fourth)
        self.assertIn("instead of stopping", fourth)
        self.assertIn("Stop only when one of these stop gates is hit", fourth)
        self.assertIn("token/context budget too low to continue safely", fourth)

    def test_fourth_planner_has_mechanical_per_slice_loop(self) -> None:
        fourth = (SKILL_ROOT / "references/handoffs/run-step4.md").read_text(encoding="utf-8")
        for phrase in [
            "For each implementation slice:",
            "Name the active phase/sub-plan",
            "Read AGENTS.md",
            "Revalidate the Apply controller's workspace proof and baseline",
            "Inspect relevant files before editing",
            "focused failing test",
            "smallest change",
            "run `capture-evidence`",
            "run every planned command through `run-validation`",
            "If targeted validation fails and the source is unclear, stop",
            "Run the repo-level gate",
            "Do not batch unrelated sub-plans in one diff",
            "Summarize:",
            "scope would exceed the selected sub-plan",
        ]:
            self.assertIn(phrase, fourth)

    def test_step3_direct_guidance_starts_with_preflight(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        step3 = skill.split("## Step 3 Handoff", 1)[1].split("## Step 4 Handoff", 1)[0]
        self.assertIn("--mode step3-preflight --strict", step3)
        self.assertIn("Then, after `Planner-docs/Sub-Planing-Audit.md` is written", step3)
        self.assertLess(step3.index("--mode step3-preflight --strict"), step3.index("--mode step3 --strict"))

    def test_step4_documents_apply_modes_and_review_loop(self) -> None:
        fourth = (SKILL_ROOT / "references/handoffs/run-step4.md").read_text(encoding="utf-8")
        for phrase in [
            "Step 4 apply modes:",
            "`direct`",
            "`subagent_serial`",
            "`external_superpowers`",
            "`no_action`",
            "fresh-slice implementer",
            "`DONE_WITH_CONCERNS`",
            "`NEEDS_CONTEXT`",
            "`BLOCKED`",
            "`verdict: pass|fail|cannot_verify`",
            "`verdict: pass|fail|needs_fixes|cannot_verify`",
            "fix only the active slice and re-run spec review",
            "fix only the active slice and re-run the relevant review",
            "final review",
                "Do not commit, push, open PRs, deploy, or mutate external systems unless the user explicitly opts into that action",
        ]:
            self.assertIn(phrase, fourth)

    def test_apply_role_templates_and_durable_controller_contract_are_wired(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        apply_ref = (SKILL_ROOT / "references/apply-orchestrator.md").read_text(encoding="utf-8")
        apply_schema = json.loads((SKILL_ROOT / "references/apply-run-schema.json").read_text(encoding="utf-8"))
        validate_script = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        repository_validation = (
            SKILL_ROOT / "scripts/repository_validation.py"
        ).read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        usage = (REPO_ROOT / "docs/USAGE.md").read_text(encoding="utf-8")
        maintaining = (REPO_ROOT / "docs/MAINTAINING.md").read_text(encoding="utf-8")
        self.assertEqual(apply_schema["$id"], "https://codexqb.local/schemas/apply-run-schema.json")
        self.assertIn("anyOf", apply_schema)
        schema_defs = apply_schema["$defs"]
        for name in [
            "ApplyRun",
            "BudgetContract",
            "TokenUsage",
            "WorkspaceBaseline",
            "Progress",
            "DispatchPacket",
            "AgentRun",
            "ImplementerReport",
            "TaskReview",
            "FixReport",
            "FinalReview",
            "Result",
            "ChangeSet",
            "ValidationReceipt",
            "ReviewReceipt",
            "ReviewReport",
        ]:
            self.assertIn(name, schema_defs)
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["apply_run_schema_version"]["const"], 3)
        self.assertIn("apply_run_registration_id", schema_defs["ApplyRun"]["required"])
        planned_validation = schema_defs["PlannedValidationCommand"]
        self.assertEqual(
            set(planned_validation["required"]),
            {"id", "argv", "cwd", "expected_exit_code", "timeout_seconds", "network", "probe_tier"},
        )
        self.assertEqual(planned_validation["properties"]["network"]["const"], "deny")
        self.assertEqual(planned_validation["properties"]["probe_tier"]["const"], 1)
        self.assertEqual(planned_validation["properties"]["expected_exit_code"]["const"], 0)
        self.assertEqual(planned_validation["properties"]["timeout_seconds"]["maximum"], 3600)
        self.assertFalse(planned_validation["additionalProperties"])
        self.assertNotIn("exit_code", planned_validation["properties"])
        validation_receipt = schema_defs["ValidationReceipt"]
        for field in [
            "run_binding",
            "task_binding",
            "producer_binding",
            "command",
            "result",
            "code_snapshot_before",
            "code_snapshot_after",
            "receipt_mac",
        ]:
            self.assertIn(field, validation_receipt["required"])
        producer_binding = schema_defs["ProducerBinding"]
        self.assertIn("identity_assurance", producer_binding["required"])
        self.assertEqual(
            producer_binding["properties"]["identity_assurance"]["const"],
            "controller_asserted",
        )
        self.assertFalse(validation_receipt["additionalProperties"])
        receipt_command = schema_defs["ValidationReceiptCommand"]
        for field in ["argv", "cwd", "started_at", "finished_at", "planned_network"]:
            self.assertIn(field, receipt_command["required"])
        receipt_result = schema_defs["ValidationReceiptResult"]
        for field in ["exit_code", "stdout_sha256", "stderr_sha256", "combined_output_sha256", "artifacts"]:
            self.assertIn(field, receipt_result["required"])
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["artifact_schema_version"]["const"], 3)
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["handoff_contract_version"]["const"], 2)
        self.assertIn("apply_policy_digest", schema_defs["ApplyRun"]["required"])
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["apply_policy_digest"]["$ref"], "#/$defs/Sha256")
        self.assertIn("budget_contract", schema_defs["ApplyRun"]["required"])
        self.assertIn("token_usage", schema_defs["ApplyRun"]["required"])
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["budget_contract"]["$ref"], "#/$defs/BudgetContract")
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["token_usage"]["$ref"], "#/$defs/TokenUsage")
        budget_contract = schema_defs["BudgetContract"]
        self.assertEqual(budget_contract["properties"]["budget_schema_version"]["const"], 1)
        self.assertEqual(budget_contract["properties"]["max_agent_attempts_per_role"]["maximum"], 10)
        self.assertEqual(budget_contract["properties"]["pause_on_soft_limit"]["const"], True)
        step4_readiness = schema_defs["ApplyRun"]["properties"]["step4_readiness"]
        self.assertIn("validator_output_sha256", step4_readiness["required"])
        self.assertIn("execution_queue_state", step4_readiness["required"])
        apply_spec_inputs = schema_defs["ApplyRun"]["properties"]["apply_spec_inputs"]
        self.assertIn("workspace_baseline", apply_spec_inputs["required"])
        self.assertEqual(apply_spec_inputs["properties"]["workspace_baseline"]["$ref"], "#/$defs/WorkspaceBaseline")
        self.assertIn("workspace_baseline", schema_defs["ApplyRun"]["required"])
        for name in ["workspace_requested", "workspace_detected", "workspace_verified", "workspace_mode", "worktree_path", "base_branch", "working_branch", "dirty_state"]:
            self.assertIn(name, schema_defs["ApplyRun"]["required"])
        self.assertIn("user_approval", schema_defs["ApplyRun"]["required"])
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["workspace_baseline"]["$ref"], "#/$defs/WorkspaceBaseline")
        self.assertEqual(
            schema_defs["WorkspaceMode"]["enum"],
            ["non_git_unsafe", "unverified_current_worktree", "verified_isolated_worktree"],
        )
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["dirty_state"]["enum"], ["clean", "dirty", "non_git", "unknown"])
        self.assertEqual(schema_defs["ApplyRun"]["properties"]["user_approval"]["type"], "boolean")
        workspace_baseline = schema_defs["WorkspaceBaseline"]
        self.assertIn("git_status_porcelain_sha256", workspace_baseline["required"])
        self.assertIn("untracked_inventory_sha256", workspace_baseline["required"])
        self.assertIn("workspace_file_inventory_sha256", workspace_baseline["required"])
        self.assertIn("implementation_contract", schema_defs["Task"]["required"])
        self.assertIn("implementation_contract_digest", schema_defs["Task"]["required"])
        self.assertIn("task_contract_digest", schema_defs["Task"]["required"])
        self.assertIn("validation_command_ids", schema_defs["Task"]["required"])
        for field in [
            "implementation_generation",
            "change_set",
            "validation_receipts",
            "review_receipts",
            "evidence_chain_status",
            "verification_assurance",
        ]:
            self.assertIn(field, schema_defs["Task"]["required"])
        self.assertEqual(schema_defs["Task"]["properties"]["implementation_contract"]["type"], "object")
        self.assertEqual(schema_defs["Task"]["properties"]["task_contract_digest"]["$ref"], "#/$defs/Sha256")
        self.assertEqual(schema_defs["Task"]["properties"]["fix_cycle_count"]["minimum"], 0)
        self.assertEqual(schema_defs["Task"]["properties"]["validation_commands"]["items"]["$ref"], "#/$defs/PlannedValidationCommand")
        self.assertEqual(
            schema_defs["Task"]["properties"]["validation_command_ids"]["items"]["$ref"],
            "#/$defs/ValidationId",
        )
        self.assertEqual(schema_defs["ValidationId"]["pattern"], "^VAL-[A-Z0-9_.-]{1,60}$")
        self.assertEqual(
            schema_defs["ImplementerReport"]["properties"]["validation_receipt_ids"]["items"]["$ref"],
            "#/$defs/Sha256",
        )
        self.assertEqual(
            schema_defs["ImplementerReport"]["properties"]["change_set_id"]["$ref"],
            "#/$defs/Sha256",
        )
        complete_final_review = schema_defs["FinalReview"]["oneOf"][1]
        self.assertEqual(
            complete_final_review["properties"]["validation_receipts"]["items"]["$ref"],
            "#/$defs/TaskValidationReceiptReference",
        )
        self.assertEqual(
            complete_final_review["properties"]["final_reviewer_receipts"]["items"]["$ref"],
            "#/$defs/ReviewReceiptReference",
        )
        self.assertEqual(schema_defs["DispatchPacket"]["properties"]["spawn_tool"]["const"], "multi_agent_v1.spawn_agent")
        self.assertIn("task_contract_digest", schema_defs["DispatchPacket"]["required"])
        self.assertIn("review_phase", schema_defs["DispatchPacket"]["required"])
        self.assertEqual(
            set(schema_defs["ExpectedReportPaths"]["required"]),
            {
                "implementer",
                "task_reviewer_spec",
                "task_reviewer_quality",
                "security_reviewer",
                "fixer",
                "final_reviewer",
            },
        )
        self.assertIn("identity_assurance", schema_defs["AgentRun"]["required"])
        self.assertEqual(
            schema_defs["AgentRun"]["properties"]["identity_assurance"]["const"],
            "controller_asserted",
        )
        self.assertIn("report_normalized_event_sequence", schema_defs["AgentRun"]["properties"])
        complete_review_report = schema_defs["ReviewReport"]["oneOf"][1]
        self.assertIn("evidence", complete_review_report["required"])
        self.assertEqual(complete_review_report["properties"]["evidence"]["minItems"], 1)
        self.assertEqual(
            complete_review_report["allOf"][0]["then"]["properties"]["verdict"]["enum"],
            ["cannot_verify", "fail", "pass"],
        )
        verification_policy = schema_defs["VerificationPolicy"]
        self.assertEqual(
            verification_policy["properties"]["trusted_verified_mode"]["const"],
            "host_attested_subagent",
        )
        self.assertTrue(verification_policy["properties"]["host_agent_attestation_required"]["const"])
        self.assertEqual(schema_defs["Result"]["properties"]["budget_contract"]["$ref"], "#/$defs/BudgetContract")
        self.assertEqual(schema_defs["Result"]["properties"]["token_usage"]["$ref"], "#/$defs/TokenUsage")
        self.assertIn("references/apply-run-schema.json", skill)
        self.assertIn("repository_validation.py", validate_script)
        self.assertIn("--contract full", validate_script)
        self.assertIn(
            "plugins/codexqb/skills/codexqb/references/apply-run-schema.json",
            repository_validation,
        )
        self.assertIn("check-schema:", makefile)
        self.assertIn("scripts/validate_apply_schema.py", makefile)
        self.assertIn("tests.test_apply_schema", makefile)
        self.assertIn("references/apply-run-schema.json", maintaining)
        role_files = [
            "controller.md",
            "implementer.md",
            "task-reviewer.md",
            "security-reviewer.md",
            "fixer.md",
            "final-reviewer.md",
        ]
        for name in role_files:
            rel = f"references/apply/{name}"
            path = SKILL_ROOT / rel
            self.assertTrue(path.is_file(), rel)
            text = path.read_text(encoding="utf-8")
            self.assertIn("model_profile", text, rel)
            self.assertIn(rel, skill)
            self.assertIn(
                f"plugins/codexqb/skills/codexqb/{rel}",
                repository_validation,
            )
        for phrase in [
            "Events.jsonl",
            "Writer-Lock.json",
            '"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"',
            "--controller apply -- request-stdin",
            '"schema":"codexqb.controller-argv/v1"',
            "launcher-backed Apply `prepare` operation",
            "Use `dispatch`",
            "use `record-agent`",
            "normalize-writer",
            "normalize-review",
            "capture-evidence",
            "run-validation",
            "publish-review",
            "Use `transition`",
            "Use `recover-lock`",
            "`finalize` remains fail-closed",
            "strict Step 4 validation",
            "validator output hash",
            "Dispatch-Packet.json",
            "Agent-Run-<role>[-<review-phase>]-<nn>.json",
            "multi_agent_v1.spawn_agent",
            "record-agent --status spawned",
            "append-only transition truth",
            "agent_profiles",
            "security_strong",
            "allow-non-git-unsafe",
            "non_git_unsafe",
            "allow-unverified-git-worktree",
            "dirty_state",
            "working_branch",
            "controller_asserted",
            "trusted_verified_requires_host_agent_attestation",
        ]:
            self.assertIn(phrase, apply_ref)
        for phrase in [
            "--controller apply -- request-stdin",
            "codexqb.controller-argv/v1",
            "prepare",
            "dispatch",
            "record",
            "normalize-writer",
            "normalize-review",
            "capture-evidence",
            "run-validation",
            "publish-review",
            "finalize",
            "Events.jsonl",
            "strict Step 4 validation",
            "apply-run-schema.json",
            "controller_asserted",
            "trusted_verified_requires_host_agent_attestation",
            "validation_command_ids",
        ]:
            self.assertIn(phrase, readme)
            self.assertIn(phrase, usage)
        self.assertIn("recover-lock", usage)
        for phrase in [
            "missing dispatch packets",
            "missing spawned/completed agent lifecycle records",
            "agent profile drift",
            "host agent attestation",
        ]:
            self.assertIn(phrase, usage)

    def test_event_integrity_and_recovery_boundaries_are_documented(self) -> None:
        documents = {
            "README.md": (REPO_ROOT / "README.md").read_text(encoding="utf-8"),
            "docs/USAGE.md": (REPO_ROOT / "docs/USAGE.md").read_text(encoding="utf-8"),
            "docs/MAINTAINING.md": (REPO_ROOT / "docs/MAINTAINING.md").read_text(encoding="utf-8"),
            "apply-orchestrator.md": (
                SKILL_ROOT / "references/apply-orchestrator.md"
            ).read_text(encoding="utf-8"),
        }
        for name, text in documents.items():
            self.assertIn("event_log_commit_state_unknown", text, name)
            self.assertIn("trusted external head anchor", text, name)
            self.assertIn("pre-chain v3", text, name)
            self.assertIn("blind", text, name)
            self.assertIn("fresh run", text, name)

    def test_validate_script_covers_archive_and_secret_hygiene(self) -> None:
        validate_script = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        repository_validation = (
            SKILL_ROOT / "scripts/repository_validation.py"
        ).read_text(encoding="utf-8")
        for phrase in [
            "scripts/check_repository_io_policy.py",
            "repository_validation.py",
            "--workspace-mode git",
            "scripts/export_sanitized.py",
            "scripts/verify_package_manifest.py",
            "scripts/extract_verified_package.py",
            "package_secret_match_locations",
            "package_secret_path_match_locations",
            "package_path_",
            "CODEXQB_VALIDATE_SKIP_UNITTESTS",
            "__MACOSX",
            ".local",
            "from safety_contracts",
            "sanitized_zip_hygiene=passed",
            "sanitized_zip_hygiene_failed",
            "PACKAGE-MANIFEST.json",
            "evals/run_apply_behavior_smoke.py",
            "evals/run_downstream_goal_apply_dry_run.py",
            "downstream_goal_apply_dry_run=passed",
            "evals/run_goal_apply_metric_checks.py",
            "goal_apply_metric_checks=passed",
            "apply_behavior_smoke=passed",
        ]:
            self.assertIn(phrase, validate_script)
        for phrase in ("zip_hygiene_finding=index-", "path_sha256:"):
            self.assertIn(phrase, validate_script)
        self.assertIn(
            'expected_manifest.encode("utf-8")',
            validate_script,
        )
        self.assertIn('findings.append(("blocked_path", path_sha256, 0))', validate_script)
        self.assertNotIn('findings.append(("missing_package_manifest", "0" * 64, 0))', validate_script)
        self.assertNotIn("blocked_package_path", validate_script)
        self.assertLess(
            validate_script.index("package_secret_path_match_locations(name)"),
            validate_script.index("if bad.search(name):"),
        )
        self.assertEqual(validate_script.count("scripts/run_test_suite.py behavior"), 1)
        self.assertIn("repository_validation_finding=index-", repository_validation)
        self.assertIn("path_sha256:", repository_validation)
        self.assertNotIn('findings.append(f"{path}:', validate_script)
        self.assertNotIn('print(f"blocked_path={offender}")', validate_script)
        self.assertNotIn('print(f"secret_like_content={offender}")', validate_script)

        closure_audit = (REPO_ROOT / "docs/FEEDBACK-CLOSURE-AUDIT.md").read_text(encoding="utf-8")
        for phrase in [
            "Release Blocker Items",
            "Goal Compiler Items",
            "Apply Orchestrator Items",
            "Subagent Methodology Items",
            "Eval And Release Evidence",
            "Remaining",
            "goal_apply_metric_checks=passed",
            "downstream_goal_apply_dry_run=passed",
            "docs/release-evidence/0.3.0-live-subagent-smoke.md",
            "0.3.0-live-subagent-smoke.md",
            "live docs-scope subagent smoke",
            "bounded live multi-role Apply e2e fixture",
        ]:
            self.assertIn(phrase, closure_audit)
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("docs/release-evidence/0.3.0-live-subagent-smoke.md", readme)
        matrix = (REPO_ROOT / "docs/release-audits/0.3.0-feedback-closure.md").read_text(encoding="utf-8")
        for phrase in [
            "Allowed status values",
            "contract implemented",
            "artifact validated",
            "behavior smoke passed",
            "live Codex behavior observed",
            "bounded live Apply e2e passed",
            "FB-001",
            "FB-006",
            "FB-007",
            "FB-012",
            "collect_step2_planning_horizon",
            "contract_driven_work_steps",
            "PARTIAL",
            "full Ralph 40-plan live regression",
            "0.3.0 release-integrity candidate",
        ]:
            self.assertIn(phrase, matrix)

    def test_live_subagent_smoke_audit_records_bounded_e2e_without_release_tag(self) -> None:
        smoke_path = REPO_ROOT / "docs/release-evidence/0.3.0-live-subagent-smoke.md"
        self.assertTrue(smoke_path.is_file())

        smoke = smoke_path.read_text(encoding="utf-8")
        for phrase in [
            "Evidence date: 2026-06-21",
            "Baseline commit for docs-scope smoke",
            "Repo commit at live Apply e2e capture start",
            "Plugin version: `0.3.0`",
            "Codex CLI version: `codex-cli 0.141.0`",
            "Sandbox / approval mode",
            "Goal / Apply Run IDs",
            "Docs-scope smoke Goal run ID: not produced for the initial smoke",
            "Live Apply run ID: `<apply-run-id-redacted>`",
            "Live Apply task ID: `<apply-task-id-redacted>`",
            "Security review required: `true`",
            "`multi_agent_v1.spawn_agent`",
            "agent ID redacted",
            "`STATUS: DONE`",
            "Wrote docs and content test files",
            "Live Multi-Role Apply E2E Evidence",
            "<agent-id-redacted>",
            "Result.json status=complete",
            "`event_sequence=33`",
            "`finalized_by=live-e2e-controller`",
            "`PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v`: passed",
            "Apply-Run.json_sha256=2a3a52598b9caffe3ca3260f1272f970652b88b6caf80a798dd3f8fa34e26efc",
            "`FB-011` is partial for bounded live Apply e2e evidence",
            "remains open until changelog",
            "not a full Ralph 40-plan live regression",
            "No commit, push, PR, deploy, dependency install, or external credential action",
        ]:
            self.assertIn(phrase, smoke)

        manifest = REPO_ROOT / "docs/release-evidence/0.3.0-live-apply-e2e/Evidence-Manifest.json"
        events = REPO_ROOT / "docs/release-evidence/0.3.0-live-apply-e2e/Events.summary.json"
        self.assertTrue(manifest.is_file())
        self.assertTrue(events.is_file())
        manifest_payload = json.loads(manifest.read_text(encoding="utf-8"))
        self.assertEqual(manifest_payload["fb_011_status"], "PARTIAL")
        self.assertFalse(manifest_payload["raw_artifact_access"]["available_in_repository"])

        matrix = (REPO_ROOT / "docs/release-audits/0.3.0-feedback-closure.md").read_text(encoding="utf-8")
        audit = (REPO_ROOT / "docs/FEEDBACK-CLOSURE-AUDIT.md").read_text(encoding="utf-8")
        combined = "\n".join([smoke, matrix, audit])
        self.assertIn("FB-011 | Observe real subagent invocation behavior. | PARTIAL", matrix)
        self.assertIn("Ralph-scale regression remains separate", audit)
        self.assertIn("full Ralph 40-plan live regression", matrix)
        self.assertIn("FB-012 | Align changelog/tag/release state. | OPEN", matrix)
        self.assertNotIn("full downstream apply/ralph multi-role e2e closed", combined.lower())
        self.assertNotIn("0.3.0 final release", combined.lower())
        self.assertNotIn("apply-subagent_serial-f794", combined)
        self.assertNotIn("AR-apply-subagent_serial-f794", combined)
        self.assertNotRegex(combined, r"/Us" r"ers/|/private/(?:tmp|var)|\\.codex/attachments")
        self.assertNotRegex(combined, r"\b019e[a-f0-9]{28}\b")

    def test_shared_safety_contracts_are_wired(self) -> None:
        safety = SKILL_ROOT / "scripts/safety_contracts.py"
        self.assertTrue(safety.is_file())
        for path in [
            REPO_ROOT / "scripts/export_sanitized.py",
            SKILL_ROOT / "scripts/validate_planner_docs.py",
            SKILL_ROOT / "scripts/goal_run.py",
            SKILL_ROOT / "scripts/apply_run.py",
        ]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("safety_contracts", text, path.as_posix())

    def test_secure_artifact_io_is_packaged_wired_and_documented(self) -> None:
        artifact_io = SKILL_ROOT / "scripts/artifact_io.py"
        self.assertTrue(artifact_io.is_file())
        validator = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        self.assertIn("scripts/check_repository_io_policy.py", validator)
        self.assertIn("scripts/repository_validation.py", validator)
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("scripts/artifact_io.py", skill)
        controller_store = SKILL_ROOT / "scripts/controller_store.py"
        self.assertTrue(controller_store.is_file())
        self.assertIn("artifact_io", controller_store.read_text(encoding="utf-8"))
        for path in [SKILL_ROOT / "scripts/goal_run.py", SKILL_ROOT / "scripts/apply_run.py"]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("controller_store", text, path.as_posix())
            self.assertNotIn("from artifact_io import", text, path.as_posix())

        goal_contract = (SKILL_ROOT / "references/goal-compiler.md").read_text(encoding="utf-8")
        apply_contract = (SKILL_ROOT / "references/apply-orchestrator.md").read_text(encoding="utf-8")
        public_contract = "\n".join(
            [
                (REPO_ROOT / "README.md").read_text(encoding="utf-8"),
                (REPO_ROOT / "docs/USAGE.md").read_text(encoding="utf-8"),
                (REPO_ROOT / "docs/MAINTAINING.md").read_text(encoding="utf-8"),
                skill,
                goal_contract,
                apply_contract,
            ]
        )
        self.assertIn("external controller-state `goal-runs/", public_contract)
        self.assertIn("Legacy in-repository", public_contract)
        self.assertIn("registered and HMAC-verified direct", public_contract)
        for phrase in [
            "`O_EXCL | O_NOFOLLOW`",
            "full write loop",
            "run-directory `flock`",
            "full-file atomic replace",
            "unique, contiguous",
            "not a multi-file transaction",
            "fail closed",
        ]:
            self.assertIn(phrase, public_contract)

    def test_no_exec_git_evidence_is_packaged_wired_and_documented(self) -> None:
        git_evidence = SKILL_ROOT / "scripts/git_evidence.py"
        self.assertTrue(git_evidence.is_file())
        validator = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        self.assertIn(
            "plugins/codexqb/skills/codexqb/scripts/git_evidence.py",
            validator,
        )
        self.assertIn("tests/test_git_evidence.py", validator)
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("scripts/git_evidence.py", skill)
        for path in [SKILL_ROOT / "scripts/goal_run.py", SKILL_ROOT / "scripts/apply_run.py"]:
            self.assertIn("git_evidence", path.read_text(encoding="utf-8"), path.as_posix())

    def test_plugin_metadata_reflects_030_goal_apply_release(self) -> None:
        plugin_text = (REPO_ROOT / "plugins/codexqb/.codex-plugin/plugin.json").read_text(encoding="utf-8")
        self.assertIn('"version": "0.3.0"', plugin_text)
        for phrase in [
            "project comprehension",
            "evidence",
            "traceability",
            "vibecoding",
            "ontology",
            "ledger",
            "gate",
            "semantic",
            "adaptive",
            "goal",
            "apply",
        ]:
            self.assertIn(phrase, plugin_text.lower())

        yaml_text = (SKILL_ROOT / "agents/openai.yaml").read_text(encoding="utf-8")
        values, errors = OPENAI_YAML_VALIDATOR.validate_openai_yaml_text(yaml_text)
        self.assertEqual(errors, [])
        default_prompt = values["default_prompt"]
        short_description = values["short_description"]
        self.assertIn("$codexqb", default_prompt)
        self.assertIn("comprehension", default_prompt.lower())
        self.assertIn("evidence", default_prompt.lower())
        self.assertLessEqual(len(short_description), 80)
        self.assertLessEqual(len(default_prompt), 220)

    def test_second_planner_keeps_security_and_ontology_out_of_scope_clean(self) -> None:
        second = (SKILL_ROOT / "references/Second-Planner.md").read_text(encoding="utf-8")
        scope = second.split("## 4. Scope", 1)[1].split("## 5. Out of Scope", 1)[0]
        out_of_scope = second.split("## 5. Out of Scope", 1)[1].split("## 6. Current Repository Evidence", 1)[0]

        self.assertIn("secure coding and secure-by-design expectations where relevant", scope)
        self.assertIn("ontology, lifecycle, or invariant consistency where relevant", scope)
        self.assertNotIn("secure coding and secure-by-design expectations where relevant", out_of_scope)
        self.assertNotIn("ontology, lifecycle, or invariant consistency where relevant", out_of_scope)

    def test_autopsy_sensitive_discovery_uses_named_redacted_repository_profile(self) -> None:
        autopsy = (SKILL_ROOT / "references/Autopsy-Planner.md").read_text(encoding="utf-8")
        self.assertIn(
            '"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"',
            autopsy,
        )
        self.assertIn("--controller repository-io -- request-stdin", autopsy)
        self.assertIn(
            '"argv": ["--root", ".", "inspect", "--profile", "autopsy"]',
            autopsy,
        )
        self.assertIn(
            '"argv": ["--root", ".", "search", "--profile", "autopsy"]',
            autopsy,
        )
        self.assertNotIn('"<CODEXQB_SKILL_ROOT>/scripts/repository_io.py"', autopsy)
        self.assertIn("safe metadata, never matching lines", autopsy)
        self.assertNotRegex(autopsy, r"(?m)^\s*(?:rg|grep|cat)\b")

    def test_step1_publish_uses_the_bundled_repository_io_entrypoint(self) -> None:
        first = (SKILL_ROOT / "references/First-Planner.md").read_text(encoding="utf-8")
        self.assertIn(
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/'
            'skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" '
            '--controller repository-io -- request-stdin',
            first,
        )
        self.assertIn(
            '"argv":["--root",".","write-planner","--stage","step1"',
            first,
        )
        self.assertNotIn('"<CODEXQB_SKILL_ROOT>/scripts/repository_io.py"', first)

    def test_project_comprehension_reference_and_prompts_are_wired(self) -> None:
        ref = SKILL_ROOT / "references/project-comprehension-methods.md"
        self.assertTrue(ref.is_file())
        ref_text = ref.read_text(encoding="utf-8")
        for phrase in [
            "question-driven comprehension",
            "why/how/what hypotheses",
            "Evidence Register",
            "Domain-to-Code Trace Map",
            "Architecture Reflexion",
            "QAW/ATAM-lite",
            "Goal/Question/Evidence",
        ]:
            self.assertIn(phrase, ref_text)

        checked_files = [
            SKILL_ROOT / "SKILL.md",
            SKILL_ROOT / "references/Autopsy-Planner.md",
            SKILL_ROOT / "references/Second-Planner.md",
            SKILL_ROOT / "references/Third-Planner.md",
            SKILL_ROOT / "references/Fourth-Planner.md",
        ]
        for path in checked_files:
            text = path.read_text(encoding="utf-8")
            self.assertIn("Project-Comprehension.md", text, path.name)
            self.assertIn("project-comprehension-methods.md", text, path.name)

    def test_goal_run_contract_uses_canonical_handoff_sources(self) -> None:
        handoff_root = SKILL_ROOT / "references/handoffs"
        for name in ["run-step2.md", "run-step3.md", "run-step4.md"]:
            path = handoff_root / name
            self.assertTrue(path.is_file(), name)
            text = path.read_text(encoding="utf-8")
            self.assertIn("contract_version: 2", text)
            self.assertIn("Goal Run Contract", text)
            self.assertIn("Resume / Recovery Protocol", text)
            for phrase in [
                "Outcome",
                "Inputs",
                "Boundaries",
                "Source precedence",
                "Validation gates",
                "Stop gates",
                "Context budget",
                "Subagent policy",
            ]:
                self.assertIn(phrase, text, name)

        references = {
            "SKILL.md": SKILL_ROOT / "SKILL.md",
            "Second-Planner.md": SKILL_ROOT / "references/Second-Planner.md",
            "Third-Planner.md": SKILL_ROOT / "references/Third-Planner.md",
            "Fourth-Planner.md": SKILL_ROOT / "references/Fourth-Planner.md",
        }
        for name, path in references.items():
            text = path.read_text(encoding="utf-8")
            self.assertIn("references/handoffs/", text, name)
            self.assertNotIn("Goal Run Contract:\n- Outcome:", text, name)

    def test_step2_adaptive_horizon_and_step3_handoff_do_not_regress(self) -> None:
        step2_handoff = (SKILL_ROOT / "references/handoffs/run-step2.md").read_text(encoding="utf-8")
        second = (SKILL_ROOT / "references/Second-Planner.md").read_text(encoding="utf-8")

        self.assertIn("active planning horizon", step2_handoff)
        self.assertIn("deferred roadmap cards", step2_handoff)
        self.assertIn("Planning modes", step2_handoff)
        self.assertNotIn("Do not stop until all phases are covered", step2_handoff)

        self.assertIn("exact canonical Step 3 handoff from `references/handoffs/run-step3.md`", second)
        self.assertNotIn("Use $codexqb. Run Step 3 according to references/Third-Planner.md.", second)
        self.assertNotIn("Do not stop until all phases and sub-plans have been reviewed.", (SKILL_ROOT / "references/handoffs/run-step3.md").read_text(encoding="utf-8"))

    def test_comprehension_validator_contract_is_documented(self) -> None:
        validator = (SKILL_ROOT / "scripts/validate_planner_docs.py").read_text(encoding="utf-8")
        for phrase in [
            "COMPREHENSION_HEADINGS",
            "Project-Comprehension.md",
            "ALLOWED_EVIDENCE_TYPES",
            "ALLOWED_CONFIDENCE_VALUES",
            "ALLOWED_CLAIM_TYPES",
            "ALLOWED_ARCHITECTURE_STATUSES",
            "ALLOWED_ONTOLOGY_QUESTION_STATUSES",
            "markdown_headings",
            "validate_optional_comprehension_doc",
            "NOT_APPLICABLE",
            "NO_UNRESOLVED_HYPOTHESES",
        ]:
            self.assertIn(phrase, validator)

    def test_planning_ledger_v3_is_documented_and_legacy_remains_supported(self) -> None:
        ledger_ref = (SKILL_ROOT / "references/planning-ledger.md").read_text(encoding="utf-8")
        validator = (SKILL_ROOT / "scripts/validate_planner_docs.py").read_text(encoding="utf-8")
        for phrase in ["Plan Snapshot Registry", "Sub-Plan Status Matrix", "Ledger v3", "legacy v1", "Planning Evidence", "Implementation Evidence", "Superseded By", "Updated At"]:
            self.assertIn(phrase, ledger_ref)
        self.assertIn("LEDGER_V3_HEADINGS", validator)
        self.assertIn("LEDGER_V2_HEADINGS", validator)
        self.assertIn("LEDGER_LEGACY_HEADINGS", validator)
        self.assertIn("ALLOWED_LEDGER_STATUSES", validator)

    def test_ci_and_export_sanitized_are_hardened(self) -> None:
        workflow = (REPO_ROOT / ".github/workflows/validate.yml").read_text(encoding="utf-8")
        dependabot = (REPO_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        validate_script = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        privacy_checker = (REPO_ROOT / "scripts/check_public_privacy.py").read_text(encoding="utf-8")
        bug_template = (REPO_ROOT / ".github/ISSUE_TEMPLATE/bug_report.yml").read_text(encoding="utf-8")
        requirements_ci = (REPO_ROOT / "requirements-ci.txt").read_text(encoding="utf-8")
        schema_validator = REPO_ROOT / "scripts/validate_apply_schema.py"
        package_manifest_validator = REPO_ROOT / "scripts/verify_package_manifest.py"
        self.assertIn("workflow_dispatch:", workflow)
        self.assertIn("push:", workflow)
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("branches: [main]", workflow)
        self.assertNotIn("actions/checkout@v6", workflow)
        self.assertNotIn("actions/setup-python@v6", workflow)
        self.assertEqual(
            workflow.count("actions/checkout@df4cb1c069e1874edd31b4311f1884172cec0e10"),
            4,
        )
        self.assertEqual(
            workflow.count("actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1"),
            4,
        )
        self.assertEqual(workflow.count("fetch-depth: 0"), 4)
        self.assertEqual(workflow.count("persist-credentials: false"), 4)
        self.assertEqual(workflow.count("name: Harden ephemeral Linux runner home chain"), 4)
        self.assertEqual(
            workflow.count(
                'sudo setfacl --remove-all --remove-default -- "${account_home_chain[@]}"'
            ),
            4,
        )
        self.assertEqual(
            workflow.count('sudo chmod go-w -- "${account_home_chain[@]}"'),
            4,
        )
        self.assertEqual(
            workflow.count('install -d -m 0700 -- "$private_tmp"'),
            4,
        )
        self.assertEqual(
            workflow.count("printf 'TMPDIR=%s\\n' \"$private_tmp\" >> \"$GITHUB_ENV\""),
            4,
        )
        self.assertIn("name: required / CodexQB", workflow)
        self.assertIn("needs: [portability, behavior, package]", workflow)
        self.assertIn("package-ecosystem: github-actions", dependabot)
        self.assertIn("package-ecosystem: pip", dependabot)
        self.assertIn("matrix:", workflow)
        for os_name, version in (
            ("ubuntu-24.04", "3.12"),
            ("ubuntu-24.04", "3.13"),
            ("ubuntu-24.04", "3.14"),
            ("macos-15", "3.13"),
            ("macos-15", "3.14"),
        ):
            self.assertIn(
                f'- os: {os_name}\n            python-version: "{version}"',
                workflow,
            )
        self.assertIn("python-version: ${{ matrix.python-version }}", workflow)
        self.assertIn("run: make check-fast", workflow)
        self.assertIn("run: make check-unit", workflow)
        self.assertIn(
            "run: PLATFORM_POLICY=required make check-platform",
            workflow,
        )
        self.assertIn("pip install --requirement requirements-ci.txt", workflow)
        self.assertIn("make check-schema", workflow)
        self.assertIn("run: make check-behavior", workflow)
        self.assertIn("run: make check-package", workflow)
        self.assertIn("make check-public-privacy", workflow)
        self.assertIn("Validate an extracted Gitless source package", workflow)
        self.assertIn("scripts/run_extracted_validation.py", workflow)
        workflow_target_validate = workflow.index(
            "scripts/run_extracted_validation.py"
        )
        self.assertLess(
            workflow.index('--root "$tmpdir/source/CodexQB"'),
            workflow_target_validate,
        )
        self.assertIn('--zip "$tmpdir/CodexQB-source-worktree.zip"', workflow)
        self.assertIn('--expected-head "$GITHUB_SHA"', workflow)
        self.assertIn('--profile static', workflow)
        self.assertIn("--skip-unit-tests", workflow)
        self.assertIn("--skip-behavior-smoke", workflow)
        self.assertIn("--artifact-type plugin", workflow)
        self.assertIn("--artifact-type source", workflow)
        self.assertIn("--provenance-mode worktree", workflow)
        self.assertIn("codexqb-plugin-worktree.zip", workflow)
        self.assertIn("CodexQB-source-worktree.zip", workflow)
        self.assertIn("startsWith(github.ref, 'refs/tags/v')", workflow)
        self.assertIn("inputs.run_release_gate", workflow)
        self.assertIn("run: make check-release", workflow)
        self.assertLess(
            workflow.index("pip install --requirement requirements-ci.txt"),
            workflow.index("run: make check-schema"),
        )
        self.assertEqual(requirements_ci.strip(), "jsonschema==4.26.0")
        self.assertTrue(schema_validator.is_file())
        self.assertTrue(package_manifest_validator.is_file())
        self.assertIn("check-schema:", makefile)
        self.assertIn("scripts/validate_apply_schema.py", makefile)
        self.assertIn("tests.test_apply_schema", makefile)
        self.assertIn("scripts/export_sanitized.py", makefile)
        for target in (
            "check-fast:",
            "check-static:",
            "check-unit:",
            "check-platform:",
            "check-schema:",
            "check-behavior:",
            "check-package:",
            "check-release:",
        ):
            self.assertIn(target, makefile)
        self.assertIn("check-public-privacy", makefile)
        self.assertIn("--scope all --require-empty-baseline", makefile)
        self.assertIn("scripts/run_extracted_validation.py", makefile)
        make_target_validate = makefile.index("scripts/run_extracted_validation.py")
        self.assertLess(
            makefile.index('--root "$$tmpdir/source/CodexQB"'),
            make_target_validate,
        )
        self.assertIn('--zip "$$tmpdir/CodexQB-source-release.zip"', makefile)
        self.assertIn('--expected-head "$$(git rev-parse --verify HEAD)"', makefile)
        self.assertIn('--profile static', makefile)
        self.assertIn("check: check-static check-unit check-platform check-behavior check-package", makefile)
        check_fast = makefile.split("check-fast:", 1)[1].split("\n\n", 1)[0]
        self.assertIn("scripts/run_test_suite.py fast", check_fast)
        self.assertNotIn("check-platform", check_fast)
        self.assertNotIn("check-release", check_fast)
        self.assertIn("export-sanitized-worktree", makefile)
        self.assertIn("export-sanitized-source-package", makefile)
        self.assertIn("export-sanitized: export-source", makefile)
        self.assertIn("export-sanitized-worktree: export-source-worktree", makefile)
        self.assertIn("export-sanitized-source-package: export-source-package", makefile)
        self.assertIn("--artifact-type plugin --provenance-mode strict-release", makefile)
        self.assertIn("--artifact-type source --provenance-mode strict-release", makefile)
        self.assertIn("codexqb-plugin-release.zip", makefile)
        self.assertIn("CodexQB-source-release.zip", makefile)
        self.assertNotIn("CodexQB-sanitized.zip", makefile)
        self.assertIn("--artifact-type plugin", validate_script)
        self.assertIn("--artifact-type source", validate_script)
        self.assertIn('--provenance-mode "$PACKAGE_PROVENANCE_MODE"', validate_script)
        self.assertIn("codexqb-plugin-worktree.zip", validate_script)
        self.assertIn("CodexQB-source-worktree.zip", validate_script)
        self.assertIn("export PYTHONDONTWRITEBYTECODE=1", validate_script)
        self.assertIn("repository_validation.py", validate_script)
        self.assertIn("--workspace-mode git", validate_script)
        self.assertNotIn("CODEXQB_EXTERNAL_PACKAGE", validate_script)
        self.assertIn(
            'scripts/verify_package_manifest.py --zip "$PLUGIN_PACKAGE"',
            validate_script,
        )
        self.assertIn(
            'scripts/verify_package_manifest.py --zip "$SOURCE_PACKAGE"',
            validate_script,
        )
        self.assertIn('"docs/FEEDBACK-CLOSURE-AUDIT.md"', privacy_checker)
        self.assertIn('"docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md"', privacy_checker)
        self.assertIn('choices=("current", "history", "all")', privacy_checker)
        self.assertIn('choices=("text", "json")', privacy_checker)
        self.assertIn("history_scan_shallow_repository", privacy_checker)
        self.assertNotIn("0.2.1", bug_template)
        self.assertIn("vX.Y.Z or commit SHA", bug_template)
        export_script = (REPO_ROOT / "scripts/export_sanitized.py").read_text(encoding="utf-8")
        self.assertNotIn("CodexQB-sanitized.zip", export_script)
        self.assertIn('"--artifact-type"', export_script)
        self.assertIn('"--provenance-mode"', export_script)
        self.assertIn('choices=("strict-release", "worktree", "filesystem")', export_script)
        self.assertIn('"--source-package"', export_script)
        self.assertIn("IGNORED_PARTS", export_script)
        self.assertIn("BLOCKED_SUFFIXES", export_script)
        self.assertIn("PACKAGE_MANIFEST_NAME", export_script)
        package_policy = (REPO_ROOT / "scripts/package_policy.py").read_text(encoding="utf-8")
        self.assertIn('PACKAGE_MANIFEST_NAME = "PACKAGE-MANIFEST.json"', package_policy)
        self.assertIn("working_tree_dirty", export_script)
        self.assertIn("head_mismatch_origin_main", export_script)
        self.assertIn("git_metadata_required_for_strict_export", export_script)
        self.assertIn("changelog_version_unreleased", export_script)
        self.assertIn("release_tag_missing", export_script)
        self.assertIn("release_tag_head_mismatch", export_script)
        self.assertIn("SOURCE_PACKAGE_MODE", export_script)

    def test_fixture_corpus_infrastructure_is_present(self) -> None:
        runner = REPO_ROOT / "evals/run_fixture_corpus_checks.py"
        wrapper = REPO_ROOT / "evals/run_fixture_checks.py"
        apply_smoke = REPO_ROOT / "evals/run_apply_behavior_smoke.py"
        downstream_smoke = REPO_ROOT / "evals/run_downstream_goal_apply_dry_run.py"
        metric_smoke = REPO_ROOT / "evals/run_goal_apply_metric_checks.py"
        self.assertTrue(runner.is_file())
        self.assertTrue(wrapper.is_file())
        self.assertTrue(apply_smoke.is_file())
        self.assertTrue(downstream_smoke.is_file())
        self.assertTrue(metric_smoke.is_file())
        runner_text = runner.read_text(encoding="utf-8")
        smoke_text = apply_smoke.read_text(encoding="utf-8")
        downstream_text = downstream_smoke.read_text(encoding="utf-8")
        metric_text = metric_smoke.read_text(encoding="utf-8")
        self.assertIn("fixture_corpus_checks=passed", runner_text)
        self.assertIn("apply_behavior_smoke=passed", smoke_text)
        self.assertIn("apply_run_finalized", smoke_text)
        for phrase in [
            "downstream_goal_apply_dry_run=passed",
            "step3-preflight",
            "subagent_serial",
            "Use only this fresh task context",
            "Structured Implementation Contract",
        ]:
            self.assertIn(phrase, downstream_text)
        for phrase in [
            "goal_apply_metric_checks=passed",
            "static_step4_handoff",
            "dynamic_step4_goal_direct",
            "dynamic_step4_goal_subagent_serial",
            "apply_direct_brief",
            "apply_subagent_dispatch_message",
        ]:
            self.assertIn(phrase, metric_text)
        self.assertNotIn("fixture_eval_checks=passed", runner_text)
        fixture_root = REPO_ROOT / "evals/fixtures"
        for fixture in [
            "adaptive-wave-planning",
            "clean-layered-service",
            "drifted-architecture",
            "distributed-domain-feature",
            "hidden-coupling-signal",
            "stale-ledger",
            "runtime-only-behavior",
            "security-boundary-risk",
            "dynamic-step2-goal",
            "dynamic-step3-goal",
            "dynamic-step4-goal",
            "apply-happy-path",
            "apply-review-fix-rereview",
            "apply-security-gate",
            "apply-interrupted-resume",
            "apply-stale-snapshot",
            "apply-run-id-collision",
            "apply-no-action",
            "export-untracked-secret",
            "export-external-symlink",
        ]:
            self.assertTrue((fixture_root / fixture / "expected.json").is_file(), fixture)

        validate_script = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        self.assertIn(
            "python3 -I -S -B evals/run_fixture_corpus_checks.py",
            validate_script,
        )
        self.assertIn(
            "python3 -I -S -B evals/run_downstream_goal_apply_dry_run.py",
            validate_script,
        )
        self.assertIn('--provenance-mode "$PACKAGE_PROVENANCE_MODE"', validate_script)

    def test_probe_policy_and_schema_versions_are_documented(self) -> None:
        probe = SKILL_ROOT / "references/probe-policy.md"
        self.assertTrue(probe.is_file())
        probe_text = probe.read_text(encoding="utf-8")
        for phrase in ["Tier 0", "Tier 1", "Tier 2", "Tier 3", "approval", "timeout", "cleanup"]:
            self.assertIn(phrase, probe_text)

        for path in [REPO_ROOT / "README.md", REPO_ROOT / "docs/USAGE.md", REPO_ROOT / "docs/MAINTAINING.md"]:
            text = path.read_text(encoding="utf-8")
            self.assertIn("artifact_schema_version: 3", text, path.name)
            self.assertIn("handoff_contract_version: 2", text, path.name)
            self.assertIn("fixture corpus", text.lower(), path.name)
            self.assertIn("compiler version", text.lower(), path.name)
            self.assertIn("template bundle digest", text.lower(), path.name)
            self.assertIn("implementation contract digest", text.lower(), path.name)

    def test_local_skill_sync_docs_exclude_python_caches(self) -> None:
        install = (REPO_ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")
        maintaining = (REPO_ROOT / "docs/MAINTAINING.md").read_text(encoding="utf-8")
        for text in [install, maintaining]:
            self.assertIn("--exclude '__pycache__/'", text)
            self.assertIn("--exclude '*.pyc'", text)
            self.assertIn("diff -ru -x __pycache__", text)

    def test_installation_documents_unattested_subagent_boundary(self) -> None:
        install = (REPO_ROOT / "docs/INSTALLATION.md").read_text(encoding="utf-8")
        self.assertIn("complete but unattested", install)
        self.assertIn("trusted `VERIFIED` and `finalize` remain blocked", install)
        self.assertIn("host-issued agent attestation", install)
        self.assertIn(
            "Summarize this project's README without using any plugin or skill.",
            install,
        )
        self.assertIn("separate fresh task", install)
        self.assertNotIn(
            "use `subagent_serial` when the run must reach trusted `VERIFIED` and finalize",
            install,
        )

    def test_validate_script_runs_without_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            # The external controller intentionally refuses a dirty selected
            # checkout. Build a clean, private checkout from the exact tracked
            # worktree bytes under test, then prove that its extracted target
            # needs no Git metadata and executes no target-owned controller.
            trusted_checkout = Path(temp_dir) / "trusted-checkout"
            shutil.copytree(
                REPO_ROOT,
                trusted_checkout,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    "*.pyc",
                    "*.pyo",
                    "artifacts",
                    "build",
                    "dist",
                ),
            )
            subprocess.run(["git", "init", "-q"], cwd=trusted_checkout, check=True)
            subprocess.run(["git", "add", "."], cwd=trusted_checkout, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb@example.invalid",
                    "commit",
                    "-qm",
                    "gitless extracted validation fixture",
                ],
                cwd=trusted_checkout,
                check=True,
            )
            expected_head = subprocess.check_output(
                ["git", "rev-parse", "--verify", "HEAD"],
                cwd=trusted_checkout,
                text=True,
            ).strip()
            archive_path = Path(temp_dir) / "CodexQB-source-package.zip"
            export_result = subprocess.run(
                [
                    "python3",
                    "-B",
                    "scripts/export_sanitized.py",
                    "--root",
                    ".",
                    "--output",
                    str(archive_path),
                    "--source-package",
                ],
                cwd=trusted_checkout,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(export_result.returncode, 0, export_result.stdout + export_result.stderr)
            with zipfile.ZipFile(archive_path) as archive:
                archive.extractall(temp_dir)
                for info in archive.infolist():
                    if info.is_dir():
                        continue
                    extracted = Path(temp_dir) / info.filename
                    extracted.chmod(stat.S_IMODE(info.external_attr >> 16))
            package_root = Path(temp_dir) / "CodexQB"
            env = os.environ.copy()
            env["CODEXQB_VALIDATE_SKIP_UNITTESTS"] = "1"
            env["CODEXQB_VALIDATE_SKIP_BEHAVIOR_SMOKE"] = "1"

            # The extracted shell may report that authentication is missing,
            # but it must not execute even its own Python verifier first.
            verifier = package_root / "scripts/verify_package_manifest.py"
            original_verifier = verifier.read_bytes()
            marker = Path(temp_dir) / "target-verifier-executed"
            verifier.write_text(
                verifier.read_text(encoding="utf-8").replace(
                    "from __future__ import annotations\n",
                    "from __future__ import annotations\n"
                    "from pathlib import Path as _CodexQBMarkerPath\n"
                    f"_CodexQBMarkerPath({str(marker)!r}).write_text('executed')\n",
                    1,
                ),
                encoding="utf-8",
            )
            unauthenticated = subprocess.run(
                ["bash", "scripts/validate.sh"],
                cwd=package_root,
                env=env,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertNotEqual(unauthenticated.returncode, 0)
            self.assertFalse((package_root / "scripts/validate.sh").exists())
            self.assertFalse(
                (package_root / "scripts/run_extracted_validation.py").exists()
            )
            self.assertFalse(marker.exists())

            # A trusted-checkout verifier rejects the mutated target before
            # target-owned validate/verifier code is admitted for execution.
            rejected = subprocess.run(
                [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    str(trusted_checkout / "scripts/verify_package_manifest.py"),
                    "--root",
                    str(package_root),
                    "--strict-artifact",
                    "--expected-artifact-type",
                    "source",
                ],
                cwd=trusted_checkout,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(marker.exists())

            verifier.write_bytes(original_verifier)
            verifier.chmod(0o644)
            external_manifest = subprocess.run(
                [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    str(trusted_checkout / "scripts/verify_package_manifest.py"),
                    "--root",
                    str(package_root),
                    "--strict-artifact",
                    "--expected-artifact-type",
                    "source",
                ],
                cwd=trusted_checkout,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                external_manifest.returncode,
                0,
                external_manifest.stdout + external_manifest.stderr,
            )
            result = subprocess.run(
                [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    str(trusted_checkout / "scripts/run_extracted_validation.py"),
                    "--expected-head",
                    expected_head,
                    "--zip",
                    str(archive_path),
                    "--root",
                    str(package_root),
                    "--profile",
                    "static",
                    "--skip-unit-tests",
                    "--skip-behavior-smoke",
                ],
                cwd=trusted_checkout,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                0,
                result.stdout + result.stderr,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("extracted_package_admission=passed", result.stdout)
            self.assertRegex(result.stdout, r"(?m)^pair_digest=[0-9a-f]{64}$")
            self.assertIn("external_pair_diagnostic_schema_version=1", result.stdout)
            self.assertIn("target_code_executed=false", result.stdout)
            self.assertIn("host_attested=false", result.stdout)
            self.assertIn("verified=false", result.stdout)
            self.assertIn("finalization_allowed=false", result.stdout)
            self.assertNotIn("apply_behavior_smoke=passed", result.stdout)

            (package_root / "PACKAGE-MANIFEST.json").unlink()
            missing_manifest = subprocess.run(
                [
                    "python3",
                    "-I",
                    "-S",
                    "-B",
                    str(trusted_checkout / "scripts/run_extracted_validation.py"),
                    "--expected-head",
                    expected_head,
                    "--zip",
                    str(archive_path),
                    "--root",
                    str(package_root),
                    "--profile",
                    "static",
                ],
                cwd=trusted_checkout,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(missing_manifest.returncode, 0)
            self.assertIn("extracted_package_admission=failed", missing_manifest.stdout)

    def test_validate_guard_detects_static_checker_mutation_before_recapture(self) -> None:
        validate_text = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        capture = (
            'python3 -I -S -B "$TRUST_GUARD_HELD" capture '
            '--output "$TRUST_GUARD_BASELINE"'
        )
        checker = (
            "python3 -I -S -B scripts/check_repository_io_policy.py "
            "--root . --layout repository-plugin"
        )
        self.assertLess(validate_text.index("trap cleanup_validate EXIT"), validate_text.index(capture))
        self.assertLess(validate_text.index(capture), validate_text.index(checker))

        real_before = real_trust_store_snapshot()
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            repo = base / "repo"
            shutil.copytree(
                REPO_ROOT,
                repo,
                ignore=shutil.ignore_patterns(
                    ".git",
                    "__pycache__",
                    "*.pyc",
                    "*.pyo",
                    "artifacts",
                    "build",
                    "dist",
                ),
            )
            fake_trust = base / "private-test-trust"
            fake_trust.mkdir(mode=0o700)
            (fake_trust / "state").write_bytes(b"before")

            # Test-only held provider: production keeps using passwd-home and
            # does not accept this environment variable or any root override.
            (repo / "tests/controller_test_support.py").write_text(
                """from __future__ import annotations
import argparse
import hashlib
import os
from pathlib import Path

def snapshot() -> str:
    root = Path(os.environ["CODEXQB_SYNTHETIC_GUARD_ROOT"])
    digest = hashlib.sha256()
    for path in sorted(root.iterdir(), key=lambda item: item.name):
        digest.update(path.name.encode("utf-8"))
        digest.update(path.read_bytes())
    return digest.hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("command", choices=("capture", "verify"))
parser.add_argument("--output")
parser.add_argument("--baseline")
args = parser.parse_args()
if args.command == "capture":
    Path(args.output).write_text(snapshot(), encoding="ascii")
    print("real_controller_trust_guard=captured")
else:
    if Path(args.baseline).read_text(encoding="ascii") != snapshot():
        print("synthetic_guard_detected_change", file=__import__("sys").stderr)
        raise SystemExit(2)
    print("real_controller_trust_guard=unchanged")
""",
                encoding="utf-8",
            )
            (repo / "scripts/check_repository_io_policy.py").write_text(
                """from pathlib import Path
import os

root = Path(os.environ["CODEXQB_SYNTHETIC_GUARD_ROOT"])
(root / "checker-mutation").write_bytes(b"mutated")
print("synthetic_checker_mutated_private_test_trust")
raise SystemExit(23)
""",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["CODEXQB_SYNTHETIC_GUARD_ROOT"] = str(fake_trust)
            completed = subprocess.run(
                ["bash", "scripts/validate.sh", "static"],
                cwd=repo,
                env=environment,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("real_controller_trust_guard=captured", completed.stdout)
            self.assertIn("synthetic_checker_mutated_private_test_trust", completed.stdout)
            self.assertIn("synthetic_guard_detected_change", completed.stderr)
            self.assertIn("real_controller_trust_guard=changed", completed.stderr)

        self.assertEqual(real_trust_store_snapshot(), real_before)

    def test_archive_hygiene_pattern_matches_forbidden_paths(self) -> None:
        pattern = re.compile(
            r"(^|/)(\.git|__pycache__|\.env|artifacts|logs|tmp|__MACOSX)(/|$)"
            r"|\.pyc$|\.pem$|\.key$|\.local($|\.)"
        )
        forbidden = [
            ".git/config",
            "pkg/__pycache__/module.pyc",
            ".env",
            "artifacts/build.log",
            "logs/run.txt",
            "tmp/cache.txt",
            "__MACOSX/file",
            "keys/prod.pem",
            "keys/prod.key",
            "settings.local",
            "settings.local.json",
        ]
        allowed = [
            "README.md",
            "docs/MAINTAINING.md",
            "plugins/codexqb/skills/codexqb/SKILL.md",
        ]
        for path in forbidden:
            self.assertRegex(path, pattern)
        for path in allowed:
            self.assertNotRegex(path, pattern)

    def test_public_release_docs_reject_private_user_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            evidence = root / "docs" / "release-evidence"
            evidence.mkdir(parents=True)
            private_path = "/Us" + "ers/example/private"
            (evidence / "leak.md").write_text(f"path: {private_path}\n", encoding="utf-8")
            result = subprocess.run(
                [os.environ.get("PYTHON", "python3"), str(REPO_ROOT / "scripts/check_public_privacy.py"), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            path_hash = hashlib.sha256(b"docs/release-evidence/leak.md").hexdigest()
            self.assertIn(
                f"path_sha256:{path_hash}:line:1:rule:mac_user_path",
                result.stdout,
            )
            self.assertNotIn("docs/release-evidence/leak.md", result.stdout)
            self.assertNotIn(private_path, result.stdout)

    def test_untracked_explicit_public_report_is_privacy_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(root), "add", "README.md"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(root),
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb@example.invalid",
                    "-c",
                    "commit.gpgsign=false",
                    "commit",
                    "-q",
                    "-m",
                    "baseline",
                ],
                check=True,
            )
            report = root / "docs" / "revision" / "CODEXQB-0.3-RELEASE-FOUNDATION.md"
            report.parent.mkdir(parents=True)
            private_path = "/Us" + "ers/example/private"
            report.write_text(f"path: {private_path}\n", encoding="utf-8")

            result = subprocess.run(
                [os.environ.get("PYTHON", "python3"), str(REPO_ROOT / "scripts/check_public_privacy.py"), "--root", str(root)],
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertNotEqual(result.returncode, 0)
            relative = "docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md"
            path_hash = hashlib.sha256(relative.encode("utf-8")).hexdigest()
            self.assertIn(
                f"path_sha256:{path_hash}:line:1:rule:mac_user_path",
                result.stdout,
            )
            self.assertNotIn(relative, result.stdout)
            self.assertNotIn(private_path, result.stdout)

    def test_autopsy_validator_mode_is_documented(self) -> None:
        validator = (SKILL_ROOT / "scripts/validate_planner_docs.py").read_text(encoding="utf-8")
        autopsy = (SKILL_ROOT / "references/Autopsy-Planner.md").read_text(encoding="utf-8")
        maintaining = (REPO_ROOT / "docs/MAINTAINING.md").read_text(encoding="utf-8")
        self.assertIn('"autopsy"', validator)
        self.assertIn("--mode autopsy --strict", autopsy)
        self.assertIn("--mode autopsy --strict", maintaining)

    def test_vibecoding_and_subagent_references_are_wired(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
        usage = (REPO_ROOT / "docs/USAGE.md").read_text(encoding="utf-8")

        expected_refs = [
            "vibecoding-principles.md",
            "subagent-playbook.md",
            "planning-ledger.md",
            "project-ontology.md",
            "assessment-and-budget.md",
            "engineering-principles.md",
        ]
        for ref in expected_refs:
            self.assertTrue((SKILL_ROOT / "references" / ref).is_file(), ref)
            self.assertIn(ref, skill, ref)

        for text_blob in [skill, readme, usage]:
            self.assertIn("vibecoding-first", text_blob.lower())
            self.assertIn("subagent", text_blob.lower())

    def test_planning_ledger_and_ontology_are_documented(self) -> None:
        skill = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        usage = (REPO_ROOT / "docs/USAGE.md").read_text(encoding="utf-8")
        second = (SKILL_ROOT / "references/Second-Planner.md").read_text(encoding="utf-8")
        fourth = (SKILL_ROOT / "references/Fourth-Planner.md").read_text(encoding="utf-8")

        for artifact in ["Planner-docs/Planing-Ledger.md", "Planner-docs/Project-Ontology.md"]:
            self.assertIn(artifact, skill)
            self.assertIn(artifact, usage)

        self.assertIn("Planing-Ledger.md", second)
        self.assertIn("Project-Ontology.md", second)
        self.assertIn("Planing-Ledger.md", fourth)

    def test_prompt_secret_scans_do_not_print_secret_values(self) -> None:
        prompt_paths = list((SKILL_ROOT / "references").glob("*.md")) + [SKILL_ROOT / "SKILL.md"]
        for path in prompt_paths:
            text = path.read_text(encoding="utf-8")
            self.assertNotIn('rg -n "sk-', text, path.name)
        workflow_quality = (SKILL_ROOT / "references/workflow-quality.md").read_text(encoding="utf-8")
        self.assertIn("named\n  repository I/O search profiles", workflow_quality)
        self.assertIn("Do not print secret values", workflow_quality)

    def test_fourth_planner_mentions_subagent_roles_and_ledger(self) -> None:
        fourth = (SKILL_ROOT / "references/Fourth-Planner.md").read_text(encoding="utf-8")
        for phrase in [
            "explorer maps relevant files and risks",
            "tester/verifier identifies validation path",
            "implementer/worker makes the smallest change",
            "reviewer/security reviews the diff",
            "Only one writer should modify files per slice",
            "Planner-docs/Planing-Ledger.md",
        ]:
            self.assertIn(phrase, fourth)

    def test_validator_supports_optional_ontology_and_ledger_headings(self) -> None:
        validator = (SKILL_ROOT / "scripts/validate_planner_docs.py").read_text(encoding="utf-8")
        for phrase in [
            "ONTOLOGY_HEADINGS",
            "LEDGER_HEADINGS",
            "Project-Ontology.md",
            "Planing-Ledger.md",
            "validate_optional_continuity_docs",
        ]:
            self.assertIn(phrase, validator)


if __name__ == "__main__":
    unittest.main()
