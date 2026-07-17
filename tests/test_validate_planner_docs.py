from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from tests.controller_test_support import controller_cli_command


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"
CLI_TIMEOUT_SECONDS = 30


@dataclass
class ValidatorResult:
    returncode: int
    stdout: str
    stderr: str


def load_validator_module():
    spec = importlib.util.spec_from_file_location("codexqb_validate_planner_docs", VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load validator module from {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR_MODULE = load_validator_module()

SECRET_OUTPUT_RE = re.compile(
    r"sk-or-v1-[A-Za-z0-9_-]+"
    r"|sk-[A-Za-z0-9_-]{20,}"
    r"|github_pat_[A-Za-z0-9_]{20,}"
    r"|ghp_[A-Za-z0-9]{20,}"
)

STEP1_HEADINGS = [
    "# Main Planing",
    "## 1. Executive Summary",
    "## 2. Project Vision",
    "## 3. Current State Analysis",
    "## 4. Target End State",
    "## 5. Architecture Direction and Key Decisions",
    "## 6. Phase-Based Master Roadmap",
    "## 7. Critical Risks and Gaps",
    "## 8. Prioritized Next Steps",
    "## 9. Step 2 Preparation Notes",
    "## 10. Repository Review Notes",
]

AUTOPSY_HEADINGS = [
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

COMPREHENSION_HEADINGS = [
    "# Project Comprehension",
    "## 1. Understanding Goals and Competency Questions",
    "## 2. Evidence Register and Confidence",
    "## 3. Domain-to-Code Trace Map",
    "## 4. Structure, Data, and Runtime Flow Model",
    "## 5. Intended vs Implemented Architecture",
    "## 6. Change History, Hotspots, and Ownership Signals",
    "## 7. Quality Attribute Scenarios and Tradeoffs",
    "## 8. Open Hypotheses and Validation Probes",
]

INDEX_HEADINGS = [
    "# Sub-Planing Index",
    "## 1. Purpose",
    "## 2. Source Main Plan",
    "## 3. Planning Scope Manifest",
    "## 4. Phase and Sub-Plan Map",
    "## 5. Execution Waves",
    "## 6. Parent Acceptance Traceability",
    "## 7. Decision Register",
    "## 8. Priority Detailing Order",
    "## 9. Out-of-Scope or Deferred Topics",
    "## 10. Coverage Check",
    "## 11. Repository Review Notes",
]

SUBPLAN_HEADINGS = [
    "## 1. Context",
    "## 2. Goal",
    "## 3. Description",
    "## 4. Scope",
    "## 5. Out of Scope",
    "## 6. Current Repository Evidence",
    "## 7. Planned Work Breakdown",
    "## 8. Acceptance Criteria",
    "## 9. Validation and Test Approach",
    "## 10. Dependencies and Sequencing",
    "## 11. Risks and Mitigations",
    "## 12. Desired End State",
    "## 13. Next Sub-Phase Transition Criteria",
]

AUDIT_HEADINGS = [
    "# Sub-Planing Audit",
    "## 1. Audit Summary",
    "## 2. Reviewed Sources",
    "## 3. Main Phase Coverage Analysis",
    "## 4. Sub-Plan File Inventory",
    "## 5. Naming and Sequencing Check",
    "## 6. Index Consistency Check",
    "## 7. Required Section Structure Check",
    "## 8. Content Quality and Implementability Analysis",
    "## 9. Scope Drift and Architectural Consistency Analysis",
    "## 10. Readiness Realism",
    "## 11. Security and Governance Findings",
    "## 12. Step 4 Readiness Assessment",
    "## 13. Priority Fix List",
    "## 14. Recommended Next Command / Prompt",
    "## 15. Audit Result",
]


def body(label: str) -> str:
    clean_label = label.lstrip("# ").replace("|", " ").strip()
    return f"{clean_label} section has enough length, verifiable detail, and English fixture content."


def artifact_frontmatter() -> list[str]:
    return ["---", "artifact_schema_version: 3", "generated_by: codexqb", "plugin_version: 0.3.0", "---", ""]


def normalize_output(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def redact_output(value: str) -> str:
    return SECRET_OUTPUT_RE.sub("<redacted>", value)


def run_validator(root: Path, mode: str, strict: bool = False) -> ValidatorResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = VALIDATOR_MODULE.run_validation(root, mode, strict)
        except SystemExit as exc:
            code = int(exc.code or 0) if isinstance(exc.code, int) else 1
    return ValidatorResult(code, stdout.getvalue(), stderr.getvalue())


def run_validator_cli(
    root: Path,
    mode: str,
    strict: bool = False,
    timeout: int = CLI_TIMEOUT_SECONDS,
) -> ValidatorResult:
    command = controller_cli_command(
        "planner-validator",
        None,
        ["--root", str(root), "--mode", mode],
    )
    if strict:
        command.append("--strict")
    try:
        completed = subprocess.run(command, text=True, capture_output=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        stdout = redact_output(normalize_output(exc.stdout))
        stderr = redact_output(normalize_output(exc.stderr))
        raise AssertionError(
            f"validator timed out after {timeout}s\n"
            f"mode={mode}\n"
            f"root={root}\n"
            f"command={' '.join(command)}\n"
            f"stdout={stdout}\n"
            f"stderr={stderr}"
        ) from exc
    return ValidatorResult(completed.returncode, completed.stdout, completed.stderr)


def write_main_plan(
    docs: Path,
    headings: list[str] | None = None,
    include_phase_table: bool = True,
) -> None:
    lines: list[str] = []
    for heading in headings or STEP1_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 6. Phase-Based Master Roadmap" and include_phase_table:
            lines += [
                "The existing repo includes historical Faz 0B-10 plans and Phase 11 security notes.",
                "",
                "| Phase | Phase name | Goal | Approximate maturity | Main acceptance signals |",
                "|---|---|---|---|---|",
                "| 1 | Local Contract Stabilization | Clarify baseline | M3 | MP-PH1-AS-01 make check passes. |",
                "| 2 | Live Gateway Activation | ready_live evidence | M4 | MP-PH2-AS-01 make smoke passes. |",
                "",
            ]
    (docs / "Main-Planing.md").write_text("\n".join(lines), encoding="utf-8")


def write_autopsy(docs: Path, headings: list[str] | None = None) -> None:
    lines: list[str] = []
    for heading in headings or AUTOPSY_HEADINGS:
        lines += [heading, "", body(heading), ""]
    (docs / "Autopsy.md").write_text("\n".join(lines), encoding="utf-8")


def write_subplan(path: Path, phase: int, subphase: int) -> None:
    lines = artifact_frontmatter() + [f"# Faz {phase}.{subphase} — Test Sub-Plan", ""]
    for heading in SUBPLAN_HEADINGS:
        text = body(heading)
        if heading == "## 3. Description":
            text += f" Artifact: reports/faz{phase}-{subphase}-readiness.md is produced for review."
        if heading == "## 6. Current Repository Evidence":
            text += " `configs/example.placeholder` is a normal example filename."
        if heading == "## 7. Planned Work Breakdown":
            text += f" Implementation surface: proposed `src/feature_{phase}_{subphase}.py`, proposed `tests/test_feature_{phase}_{subphase}.py`, and proposed `examples/feature-{phase}-{subphase}.yaml`."
        if heading == "## 8. Acceptance Criteria":
            text += f"\n- MP-PH{phase}-AS-01 accepts a valid fixture and exits zero.\n- MP-PH{phase}-AS-02 rejects an invalid fixture without printing secrets."
        if heading == "## 9. Validation and Test Approach":
            text += f"\nRun: `python3 -B -m pytest -p no:cacheprovider tests/test_feature_{phase}_{subphase}.py -q`.\nExpected: PASS with the focused fixture checks."
        if heading == "## 10. Dependencies and Sequencing":
            text += "\ndepends_on: []\nblocks: []\ncan_run_in_parallel_with: []\nactivation_conditions: local fixture files exist."
        if heading == "## 11. Risks and Mitigations":
            text += f" Risk: feature_{phase}_{subphase} schema drift can break the local validation fixture; mitigation is to pin the fixture contract before Step 4. placeholder-safe command wording is not a real placeholder."
        if heading == "## 12. Desired End State":
            text += f" Output: reports/faz{phase}-{subphase}-readiness.md documents the validated behavior."
        lines += [heading, "", text, ""]
    lines += [
        "### Implementation Contract",
        "",
        "```json",
        "{",
        '  "contract_version": 1,',
        '  "implementation_paths": [',
        f'    {{"path": "src/feature_{phase}_{subphase}.py", "state": "proposed"}},',
        f'    {{"path": "tests/test_feature_{phase}_{subphase}.py", "state": "proposed"}}',
        "  ],",
        '  "validation_commands": [',
        "    {",
        '      "id": "VAL-01",',
        f'      "argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_{phase}_{subphase}.py", "-q"],',
        '      "cwd": ".",',
        '      "expected_exit_code": 0,',
        '      "timeout_seconds": 120,',
        '      "network": "deny",',
        '      "probe_tier": 1',
        "    }",
        "  ],",
        f'  "parent_signals": ["MP-PH{phase}-AS-01"],',
        '  "dependencies": {',
        '    "depends_on": [],',
        '    "blocks": [],',
        '    "can_run_in_parallel_with": [],',
        '    "activation_conditions": ["local fixture files exist"]',
        "  },",
        f'  "outputs": ["reports/faz{phase}-{subphase}-readiness.md"],',
        '  "risk_class": "low",',
        '  "risk_domains": ["none"],',
        '  "security_review_required": true',
        "}",
        "```",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_index(docs: Path, relative_refs: bool = False) -> None:
    refs = [
        "Faz-1-Plans/Faz1.1-local-contract.md",
        "./Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md",
    ] if relative_refs else [
        "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md",
        "Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md",
    ]

    lines: list[str] = artifact_frontmatter()
    for heading in INDEX_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 3. Planning Scope Manifest":
            lines += [
                "```yaml",
                "planning_mode: wave",
                "active_phases: [1, 2]",
                "deferred_phases: []",
                "max_detailed_subplans: 12",
                "max_output_words: 12000",
                "goal_token_risk: low",
                "review_checkpoint: after_wave_1",
                "```",
                "",
            ]
        if heading == "## 4. Phase and Sub-Plan Map":
            lines += [f"- {ref}" for ref in refs] + [""]
        if heading == "## 5. Execution Waves":
            lines += [
                "| Wave | Sub-Plan Path | Purpose | Dependencies |",
                "|---|---|---|---|",
                "| wave-1 | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | Validate local contract. | none |",
                "| wave-1 | Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | Validate gateway activation. | Faz 1.1 |",
                "",
            ]
        if heading == "## 6. Parent Acceptance Traceability":
            lines += [
                "| Parent Signal | Covered By | Validation Command | Status |",
                "|---|---|---|---|",
                "| MP-PH1-AS-01 | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q | planned |",
                "| MP-PH2-AS-01 | Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | python3 -B -m pytest -p no:cacheprovider tests/test_feature_2_1.py -q | planned |",
                "",
            ]
        if heading == "## 7. Decision Register":
            lines += [
                "| Decision ID | Decision | Required By | Status | Next Action |",
                "|---|---|---|---|---|",
                "| DEC-001 | Select live provider only after local fixture pass. | Phase 2 | open | Ask before live activation. |",
                "",
            ]
    (docs / "Sub-Planing-Index.md").write_text("\n".join(lines), encoding="utf-8")


def write_ontology(docs: Path, headings: list[str] | None = None) -> None:
    ontology_headings = headings or [
        "# Project Ontology",
        "## 1. Purpose",
        "## 2. Domain Vocabulary",
        "## 3. Core Entities and Concepts",
        "## 4. Module and Boundary Map",
        "## 5. Workflows and Lifecycles",
        "## 6. Integrations and External Systems",
        "## 7. Invariants and Constraints",
        "## 8. Open Ontology Questions",
    ]
    lines: list[str] = artifact_frontmatter()
    for heading in ontology_headings:
        lines += [heading, "", body(heading), ""]
        if heading == "## 2. Domain Vocabulary":
            lines += [
                "| Term | Meaning | Provenance | Confidence |",
                "|---|---|---|---|",
                "| Task lease | Worker ownership interval. | plan_derived | probable |",
                "",
            ]
    (docs / "Project-Ontology.md").write_text("\n".join(lines), encoding="utf-8")


def write_ontology_with_competency_status(docs: Path, status: str) -> None:
    lines: list[str] = artifact_frontmatter()
    for heading in [
        "# Project Ontology",
        "## 1. Purpose",
        "## 2. Domain Vocabulary",
        "## 3. Core Entities and Concepts",
        "## 4. Module and Boundary Map",
        "## 5. Workflows and Lifecycles",
        "## 6. Integrations and External Systems",
        "## 7. Invariants and Constraints",
        "## 8. Open Ontology Questions",
    ]:
        lines += [heading, "", body(heading), ""]
        if heading == "## 8. Open Ontology Questions":
            lines += [
                "| Term | Provenance | Confidence |",
                "|---|---|---|",
                "| Task lease | plan_derived | probable |",
                "",
                "### Competency Questions",
                "",
                "| Question ID | Question | Status | Evidence |",
                "|---|---|---|---|",
                f"| OQ-01 | Which component owns task lease renewal? | {status} | docs/architecture.md |",
                "",
            ]
    (docs / "Project-Ontology.md").write_text("\n".join(lines), encoding="utf-8")


def write_ledger(
    docs: Path,
    headings: list[str] | None = None,
    version: int = 3,
    status: str = "verified",
    planning_status: str = "approved",
    execution_status: str = "verified",
    run_id: str = "RUN-001",
    validation_evidence: str = "make check",
    blocker: str = "none",
    next_action: str = "none",
    superseded_by: str = "",
) -> None:
    legacy_headings = [
        "# Planing Ledger",
        "## 1. Purpose",
        "## 2. Planning Runs",
        "## 3. Implementation Runs",
        "## 4. Current State Snapshot",
        "## 5. Replanning Inputs",
        "## 6. Open Decisions and Follow-Ups",
    ]
    v2_headings = [
        "# Planing Ledger",
        "## 1. Purpose",
        "## 2. Planning Runs",
        "## 3. Plan Snapshot Registry",
        "## 4. Sub-Plan Status Matrix",
        "## 5. Implementation Runs",
        "## 6. Current State Snapshot",
        "## 7. Replanning Inputs",
        "## 8. Open Decisions and Follow-Ups",
    ]
    v3_headings = [
        "# Planing Ledger",
        "## 1. Purpose",
        "## 2. Planning Runs",
        "## 3. Plan Snapshot Registry",
        "## 4. Sub-Plan Status Matrix",
        "## 5. Planning Evidence",
        "## 6. Implementation Evidence",
        "## 7. Implementation Runs",
        "## 8. Current State Snapshot",
        "## 9. Replanning Inputs",
        "## 10. Open Decisions and Follow-Ups",
    ]
    ledger_headings = headings or (v3_headings if version == 3 else v2_headings if version == 2 else legacy_headings)
    lines: list[str] = artifact_frontmatter()
    for heading in ledger_headings:
        lines += [heading, "", body(heading), ""]
        if heading == "## 4. Sub-Plan Status Matrix":
            if version == 3:
                lines += [
                    "| Sub-plan Path | Planning Status | Execution Status | Snapshot ID | Run ID | Planning Evidence | Implementation Evidence | Blocker | Next Action | Superseded By | Updated At |",
                    "|---|---|---|---|---|---|---|---|---|---|---|",
                    f"| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | {planning_status} | {execution_status} | SNAP-001 | {run_id} | Planner-docs/Sub-Planing-Audit.md | {validation_evidence} | {blocker} | {next_action} | {superseded_by} | 2026-06-19 |",
                    "",
                ]
            else:
                lines += [
                    "| Sub-plan Path | Status | Snapshot ID | Run ID | Validation Evidence | Blocker | Next Action | Superseded By | Updated At |",
                    "|---|---|---|---|---|---|---|---|---|",
                    f"| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | {status} | SNAP-001 | {run_id} | {validation_evidence} | {blocker} | {next_action} | {superseded_by} | 2026-06-19 |",
                    "",
                ]
    (docs / "Planing-Ledger.md").write_text("\n".join(lines), encoding="utf-8")


def write_comprehension(
    docs: Path,
    headings: list[str] | None = None,
    evidence_confidence: str = "confirmed",
    evidence_type: str = "source",
    architecture_status: str = "convergent",
    evidence_source: str = "src/service.py",
    trace_entry: str = "api/routes.py",
    trace_core: str = "src/service.py",
    trace_tests: str = "tests/test_service.py",
    hypothesis_next_probe: str = "Run focused unit test for service boundary.",
    claim_type: str = "structural",
    trace_marker: str = "",
    architecture_marker: str = "",
    hypothesis_marker: str = "",
) -> None:
    lines: list[str] = []
    for heading in headings or COMPREHENSION_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 1. Understanding Goals and Competency Questions":
            lines += [
                "| Question ID | Question | Priority | Answer Criterion |",
                "|---|---|---|---|",
                "| CQ-01 | Which service boundary owns task lease renewal? | high | Source and tests identify a single owner. |",
                "",
            ]
        if heading == "## 2. Evidence Register and Confidence":
            lines += [
                "| Evidence ID | Claim Type | Claim | Evidence source | Evidence type | Confidence | Freshness | Contradiction | Next probe |",
                "|---|---|---|---|---|---|---|---|---|",
                f"| EV-01 | {claim_type} | Service routes through a boundary layer. | {evidence_source} | {evidence_type} | {evidence_confidence} | current | none | Inspect service tests. |",
                "",
            ]
        if heading == "## 3. Domain-to-Code Trace Map":
            if trace_marker:
                lines += [trace_marker, ""]
            else:
                lines += [
                    "| Trace ID | Domain concept / feature | Entry points | Core implementation | State/data | Tests | Docs | Confidence |",
                    "|---|---|---|---|---|---|---|---|",
                    f"| TRACE-01 | Task lease renewal | {trace_entry} | {trace_core} | db/tasks.sql | {trace_tests} | docs/architecture.md | probable |",
                    "",
                ]
        if heading == "## 5. Intended vs Implemented Architecture":
            if architecture_marker:
                lines += [architecture_marker, ""]
            else:
                lines += [
                    "| Relation ID | Intended relation | Source evidence | Status | Impact |",
                    "|---|---|---|---|---|",
                    f"| ARC-01 | API -> service -> repository | api/routes.py -> src/service.py | {architecture_status} | none |",
                    "",
                ]
        if heading == "## 8. Open Hypotheses and Validation Probes":
            if hypothesis_marker:
                lines += [hypothesis_marker, ""]
            else:
                lines += [
                    "| Hypothesis ID | Type | Claim | Confidence | Supporting evidence | Contradicting evidence | Next probe |",
                    "|---|---|---|---|---|---|---|",
                    f"| HYP-01 | how | Retry behavior is idempotent. | tentative | src/service.py | none | {hypothesis_next_probe} |",
                    "",
                ]
    (docs / "Project-Comprehension.md").write_text("\n".join(lines), encoding="utf-8")


def write_audit(
    docs: Path,
    status: str,
    fixes: list[str] | None = None,
    readiness_rows: list[str] | None = None,
) -> None:
    lines: list[str] = []
    default_readiness = [
        "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
        "|---|---|---|---|---|---|",
        "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | READY | none | independent | Contract complete and validation path exists. | none |",
    ]
    for heading in AUDIT_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 1. Audit Summary":
            lines += [f"Audit status: {status}", ""]
        if heading == "## 12. Step 4 Readiness Assessment":
            lines += readiness_rows or default_readiness
            lines += [""]
        if heading == "## 13. Priority Fix List":
            if fixes:
                lines += [
                    "| Finding ID | Severity | Status | Affected Files | Issue | Required Action |",
                    "|---|---|---|---|---|---|",
                    *fixes,
                    "",
                ]
            else:
                lines += ["No open findings.", ""]
        if heading == "## 15. Audit Result":
            lines += [f"Final status: {status}", ""]
    (docs / "Sub-Planing-Audit.md").write_text("\n".join(lines), encoding="utf-8")


def write_valid_step2_fixture(root: Path, relative_refs: bool = False) -> Path:
    docs = root / "Planner-docs"
    (docs / "Faz-1-Plans").mkdir(parents=True)
    (docs / "Faz-2-Plans").mkdir(parents=True)
    write_main_plan(docs)
    write_index(docs, relative_refs=relative_refs)
    write_subplan(docs / "Faz-1-Plans/Faz1.1-local-contract.md", 1, 1)
    write_subplan(docs / "Faz-2-Plans/Faz2.1-live-gateway.md", 2, 1)
    return docs


def write_main_plan_with_phases(docs: Path, phases: list[int]) -> None:
    lines: list[str] = []
    for heading in STEP1_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 6. Phase-Based Master Roadmap":
            lines += [
                "| Phase | Phase name | Goal | Approximate maturity | Main acceptance signals |",
                "|---|---|---|---|---|",
            ]
            for phase in phases:
                lines.append(f"| {phase} | Phase {phase} | Deliver phase {phase}. | M2 | MP-PH{phase}-AS-01 passes. |")
            lines.append("")
        if heading == "## 9. Step 2 Preparation Notes":
            lines += ["Detail phases 0-4 first; keep later phases deferred until the first wave is audited.", ""]
    (docs / "Main-Planing.md").write_text("\n".join(lines), encoding="utf-8")


def write_index_for_refs(
    docs: Path,
    refs: list[str],
    active: list[int],
    deferred: list[int] | None = None,
    extra_note: str = "",
) -> None:
    lines: list[str] = artifact_frontmatter()
    for heading in INDEX_HEADINGS:
        lines += [heading, "", body(heading), ""]
        if heading == "## 3. Planning Scope Manifest":
            lines += [
                "```yaml",
                "planning_mode: wave",
                f"active_phases: {active}",
                f"deferred_phases: {deferred or []}",
                "max_detailed_subplans: 12",
                "max_output_words: 12000",
                "goal_token_risk: high",
                "review_checkpoint: after_wave_1",
                "```",
                extra_note,
                "",
            ]
        if heading == "## 4. Phase and Sub-Plan Map":
            lines += [f"- {ref}" for ref in refs] + [""]
        if heading == "## 5. Execution Waves":
            lines += [
                "| Wave | Sub-Plan Path | Purpose | Dependencies |",
                "|---|---|---|---|",
                *[
                    f"| wave-1 | Planner-docs/Faz-{phase}-Plans/Faz{phase}.1-wave-plan.md | Detail active phase {phase}. | manifest active horizon |"
                    for phase in active
                ],
                "",
            ]
        if heading == "## 6. Parent Acceptance Traceability":
            lines += [
                "| Parent Signal | Covered By | Validation Command | Status |",
                "|---|---|---|---|",
                *[
                    f"| MP-PH{phase}-AS-01 | Planner-docs/Faz-{phase}-Plans/Faz{phase}.1-wave-plan.md | python3 -B -m pytest -p no:cacheprovider tests/test_feature_{phase}_1.py -q | planned |"
                    for phase in active
                ],
                "",
            ]
        if heading == "## 7. Decision Register":
            lines += [
                "| Decision ID | Decision | Required By | Status | Next Action |",
                "|---|---|---|---|---|",
                "| DEC-001 | Continue deferred phases only after audit. | later phases | open | Review wave audit. |",
                "",
            ]
        if heading == "## 9. Out-of-Scope or Deferred Topics" and deferred:
            lines += [
                "| Phase | Status | Deferral Reason | Activation Trigger | Earliest Wave |",
                "|---|---|---|---|---|",
                *[
                    f"| {phase} | deferred | Outside active planning horizon. | Step 3 audit approves wave 1. | wave-2 |"
                    for phase in deferred
                ],
                "",
            ]
    (docs / "Sub-Planing-Index.md").write_text("\n".join(lines), encoding="utf-8")


class ValidatePlannerDocsTests(unittest.TestCase):

    def test_validation_state_revalidates_inventory_after_each_listing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            docs = root / "Planner-docs"
            docs.mkdir()
            (docs / "initial.md").write_text("safe\n", encoding="utf-8")

            with VALIDATOR_MODULE.open_repository_io(root) as repository:
                state = VALIDATOR_MODULE.ValidationState(
                    root=root,
                    mode="all",
                    strict=False,
                    repository=repository,
                )
                self.assertIn(
                    "Planner-docs/initial.md",
                    state.regular_paths("step3"),
                )
                (docs / "late-secret.md").write_text(
                    "sk-" + "R" * 40 + "\n",
                    encoding="utf-8",
                )

                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_inventory_changed",
                ):
                    VALIDATOR_MODULE.scan_secrets(state)

    def test_step1_valid_main_plan_reports_phase_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)

            result = run_validator(Path(temp_dir), "step1", strict=True)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_phase_count=2", result.stdout)
            self.assertIn("validation_mode=step1", result.stdout)

    def test_step1_missing_heading_reports_expected_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            headings = [heading for heading in STEP1_HEADINGS if heading != "## 2. Project Vision"]
            write_main_plan(docs, headings=headings)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing_heading=Planner-docs/Main-Planing.md::## 2. Project Vision", result.stdout)

    def test_step1_heading_order_error_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            headings = STEP1_HEADINGS.copy()
            headings[2], headings[3] = headings[3], headings[2]
            write_main_plan(docs, headings=headings)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("heading_out_of_order=Planner-docs/Main-Planing.md", result.stdout)

    def test_step1_without_roadmap_phases_reports_expected_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs, include_phase_table=False)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_plan_has_no_detected_phases=Planner-docs/Main-Planing.md", result.stdout)

    def test_step1_rejects_empty_main_plan_section_bodies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            lines: list[str] = []
            for heading in STEP1_HEADINGS:
                lines += [heading, ""]
                if heading == "## 6. Phase-Based Master Roadmap":
                    lines += [
                        "| Phase | Phase name | Goal | Approximate maturity | Main acceptance signals |",
                        "|---|---|---|---|---|",
                        "| 1 | Foundation | Stabilize planning. | M2 | Validator passes. |",
                        "",
                    ]
            (docs / "Main-Planing.md").write_text("\n".join(lines), encoding="utf-8")

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(
                "empty_or_too_short_section=Planner-docs/Main-Planing.md::## 1. Executive Summary",
                result.stdout,
            )

    def test_autopsy_mode_validates_main_autopsy_and_optional_ontology(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)
            write_autopsy(docs)
            write_ontology(docs)
            result = run_validator(Path(temp_dir), "autopsy", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("autopsy_exists=true", result.stdout)
            self.assertIn("ontology_exists=true", result.stdout)

    def test_autopsy_mode_requires_autopsy_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)
            result = run_validator(Path(temp_dir), "autopsy", strict=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing_file=Planner-docs/Autopsy.md", result.stdout)

    def test_step2_passes_when_autopsy_is_absent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("autopsy_exists=false", result.stdout)

    def test_step2_wave_mode_allows_active_phases_and_deferred_roadmap_cards(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            docs = root / "Planner-docs"
            docs.mkdir()
            write_main_plan_with_phases(docs, list(range(10)))
            refs: list[str] = []
            for phase in range(5):
                folder = docs / f"Faz-{phase}-Plans"
                folder.mkdir()
                path = folder / f"Faz{phase}.1-wave-plan.md"
                write_subplan(path, phase, 1)
                unique_text = path.read_text(encoding="utf-8")
                concept = ["atlas", "bridge", "cipher", "delta", "ember"][phase]
                replacements = {
                    "## 3. Description": f"The {concept} capability turns the wave slice into a unique delivery checkpoint with domain-specific state and review evidence. The work proves {concept} behavior before later roadmap cards activate. Artifact: reports/{concept}-wave.md records the phase-specific result.",
                    "## 6. Current Repository Evidence": f"{concept.title()} evidence comes from docs/{concept}-notes.md and examples/{concept}-fixture.yaml. The validator fixture treats those anchors as proposed evidence for MP-PH{phase}-AS-01.",
                    "## 8. Acceptance Criteria": f"- MP-PH{phase}-AS-01 accepts {concept} fixture data and exits zero.\n- MP-PH{phase}-AS-02 rejects malformed {concept} input without printing secrets.\n- MP-PH{phase}-AS-03 produces reports/{concept}-wave.md.",
                    "## 11. Risks and Mitigations": f"Risk: {concept} behavior can drift from its parent acceptance signal if deferred phases are expanded too early. Mitigation: keep {concept} validation tied to python3 -B -m pytest -p no:cacheprovider tests/test_feature_{phase}_1.py -q before Step 3.",
                }
                for heading, replacement in replacements.items():
                    unique_text = re.sub(
                        rf"({re.escape(heading)}\n\n).*?(\n\n##)",
                        rf"\1{replacement}\2",
                        unique_text,
                        flags=re.DOTALL,
                    )
                path.write_text(unique_text, encoding="utf-8")
                refs.append(f"Planner-docs/Faz-{phase}-Plans/Faz{phase}.1-wave-plan.md")
            write_index_for_refs(
                docs,
                refs,
                active=[0, 1, 2, 3, 4],
                deferred=[5, 6, 7, 8, 9],
                extra_note="uniform_subplan_count_justification: first wave uses one vertical-slice plan per phase.",
            )

            result = run_validator(root, "step2", strict=True)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_phase_count=10", result.stdout)
            self.assertIn("active_phase_count=5", result.stdout)
            self.assertIn("deferred_phase_count=5", result.stdout)
            self.assertNotIn("missing_phase_folder=Planner-docs/Faz-5-Plans", result.stdout)

    def test_strict_step2_rejects_active_subplan_without_implementation_ready_signals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            bad_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            lines = [f"# Faz 1.1 — Test Sub-Plan", ""]
            for heading in SUBPLAN_HEADINGS:
                lines += [heading, "", body(heading), ""]
            bad_path.write_text("\n".join(lines), encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_missing_implementation_path=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)
            self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)
            self.assertIn("strict_warning=subplan_missing_dependency_label=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::depends_on", result.stdout)

    def test_strict_step2_rejects_high_normalized_duplicate_ratio(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            docs = root / "Planner-docs"
            docs.mkdir()
            write_main_plan_with_phases(docs, [1])
            refs: list[str] = []
            folder = docs / "Faz-1-Plans"
            folder.mkdir()
            for subphase in range(1, 6):
                path = folder / f"Faz1.{subphase}-dup-plan.md"
                write_subplan(path, 1, subphase)
                repeated = path.read_text(encoding="utf-8").replace(
                    "section has enough length, verifiable detail, and English fixture content.",
                    "This implementation slice repeats the same generic readiness sentence across files to test normalized duplicate detection.",
                )
                path.write_text(repeated, encoding="utf-8")
                refs.append(f"Planner-docs/Faz-1-Plans/Faz1.{subphase}-dup-plan.md")
            write_index_for_refs(docs, refs, active=[1], deferred=[], extra_note="uniform_subplan_count_justification: single active phase.")

            result = run_validator(root, "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("normalized_duplicate_ratio_too_high=", result.stdout)

    def test_strict_step2_flags_uniform_subplan_count_without_rationale(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            docs = root / "Planner-docs"
            docs.mkdir()
            write_main_plan_with_phases(docs, [1, 2, 3])
            refs: list[str] = []
            for phase in [1, 2, 3]:
                folder = docs / f"Faz-{phase}-Plans"
                folder.mkdir()
                path = folder / f"Faz{phase}.1-wave-plan.md"
                write_subplan(path, phase, 1)
                refs.append(f"Planner-docs/Faz-{phase}-Plans/Faz{phase}.1-wave-plan.md")
            write_index_for_refs(docs, refs, active=[1, 2, 3], deferred=[])

            result = run_validator(root, "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=uniform_subplan_count_anomaly=count:1::phases:3", result.stdout)

    def test_strict_step2_rejects_scope_manifest_limit_and_coverage_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            index_path = docs / "Sub-Planing-Index.md"
            index_text = index_path.read_text(encoding="utf-8")
            index_text = index_text.replace("max_detailed_subplans: 12", "max_detailed_subplans: 1")
            index_path.write_text(index_text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=planning_scope_exceeds_max_detailed_subplans=2>1", result.stdout)

    def test_strict_step2_enforces_max_output_words_and_full_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            index_path = docs / "Sub-Planing-Index.md"
            index_text = index_path.read_text(encoding="utf-8")
            index_text = index_text.replace("planning_mode: wave", "planning_mode: full")
            index_text = index_text.replace("max_output_words: 12000", "max_output_words: 100")
            index_path.write_text(index_text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=full_mode_missing_user_explicit_authorization=Planner-docs/Sub-Planing-Index.md", result.stdout)
            self.assertIn("strict_warning=planning_scope_exceeds_max_output_words=", result.stdout)

    def test_strict_step2_validates_artifact_plugin_version_frontmatter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            subplan_path.write_text(
                subplan_path.read_text(encoding="utf-8").replace("plugin_version: 0.3.0", "plugin_version: 0.2.1"),
                encoding="utf-8",
            )

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=missing_or_invalid_plugin_version=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::0.2.1", result.stdout)

    def test_strict_step2_requires_deferred_cards_for_deferred_phases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            docs = root / "Planner-docs"
            docs.mkdir()
            write_main_plan_with_phases(docs, [1, 2])
            folder = docs / "Faz-1-Plans"
            folder.mkdir()
            write_subplan(folder / "Faz1.1-wave-plan.md", 1, 1)
            write_index_for_refs(
                docs,
                ["Planner-docs/Faz-1-Plans/Faz1.1-wave-plan.md"],
                active=[1],
                deferred=[2],
            )
            index_path = docs / "Sub-Planing-Index.md"
            index_text = index_path.read_text(encoding="utf-8")
            index_text = re.sub(
                r"\| Phase \| Status \| Deferral Reason \| Activation Trigger \| Earliest Wave \|.*?(?=\n\n## 10\.)",
                "",
                index_text,
                flags=re.DOTALL,
            )
            index_path.write_text(index_text, encoding="utf-8")

            result = run_validator(root, "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=deferred_cards_table_missing=Planner-docs/Sub-Planing-Index.md", result.stdout)
            self.assertIn("strict_warning=missing_deferred_card=Faz-2", result.stdout)

    def test_strict_step2_rejects_structured_contract_bypass_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace('"path": "src/feature_1_1.py"', '"path": "Planner-docs/notes.md"')
            text = text.replace(
                '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]',
                '"command": "make"',
            )
            text = text.replace('"parent_signals": ["MP-PH1-AS-01"]', '"parent_signals": ["Parent Signal"]')
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_invalid_implementation_path=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::Planner-docs/notes.md", result.stdout)
            self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)
            self.assertIn("strict_warning=subplan_invalid_parent_acceptance_signal=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::Parent Signal", result.stdout)

    def test_strict_step2_rejects_shell_chained_validation_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace(
                '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]',
                '"command": "python3 -m pytest tests/test_feature_1_1.py -q && rm -rf /tmp/codexqb-owned"',
            )
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)

    def test_strict_step2_rejects_command_substitution_validation_command(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace(
                '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]',
                '"command": "python3 -m pytest tests/test_feature_1_1.py -q $(touch /tmp/codexqb-owned)"',
            )
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)

    def test_strict_step2_rejects_arbitrary_python_bash_make_and_npm_commands(self) -> None:
        unsafe_commands = [
            ["python3", "-c", "open('/tmp/codexqb-owned','w').write('x')"],
            ["uv", "run", "python3", "-c", "open('/tmp/codexqb-owned','w').write('x')"],
            ["bash", "scripts/verify.sh"],
            ["make", "clean"],
            ["npm", "run", "custom-destructive-script"],
            ["python3", "-m", "pytest", "--rootdir=/tmp"],
        ]
        for argv in unsafe_commands:
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as temp_dir:
                docs = write_valid_step2_fixture(Path(temp_dir))
                subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
                text = subplan.read_text(encoding="utf-8")
                safe = json.dumps(
                    ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]
                )
                text = text.replace(safe, json.dumps(argv))
                subplan.write_text(text, encoding="utf-8")

                result = run_validator(Path(temp_dir), "step2", strict=True)

                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)

    def test_strict_step2_rejects_sec002_command_and_envelope_matrix(self) -> None:
        canonical = json.dumps(
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]
        )
        cases = [
            ("ruff_fix", (canonical, json.dumps(["ruff", "check", "--fix", "."]))),
            ("pytest_basetemp", (canonical, json.dumps(["pytest", "--basetemp=.git"]))),
            ("pytest_basetemp_split", (canonical, json.dumps(["pytest", "--basetemp", ".git"]))),
            ("pytest_junit", (canonical, json.dumps(["pytest", "--junitxml=.env"]))),
            ("pytest_unknown", (canonical, json.dumps(["pytest", "--unknown-output=.env"]))),
            (
                "canonical_pytest_unknown",
                (
                    canonical,
                    json.dumps(
                        ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "--unknown-option"]
                    ),
                ),
            ),
            (
                "canonical_unittest_unknown",
                (canonical, json.dumps(["python3", "-B", "-m", "unittest", "--unknown-option"])),
            ),
            (
                "canonical_ruff_unknown",
                (canonical, json.dumps(["ruff", "check", "--no-fix", "--no-cache", "--unknown-option", "."])),
            ),
            (
                "unknown_python_executable",
                (canonical, json.dumps(["python3.999", "-B", "-m", "unittest", "tests.test_example"])),
            ),
            (
                "planned_evidence_fields",
                (
                    '"probe_tier": 1',
                    '"probe_tier": 1,\n      "exit_code": 0,\n      "output_sha256": "' + "a" * 64 + '"',
                ),
            ),
            ('cwd_git', ['"cwd": "."', '"cwd": ".git"']),
            ('cwd_escape', ['"cwd": "."', '"cwd": "../outside"']),
            ('network_local', ['"network": "deny"', '"network": "local"']),
            ('network_allow', ['"network": "deny"', '"network": "allow"']),
            ('probe_tier_2', ['"probe_tier": 1', '"probe_tier": 2']),
            ('probe_tier_bool', ['"probe_tier": 1', '"probe_tier": true']),
            ('expected_exit_bool', ['"expected_exit_code": 0', '"expected_exit_code": true']),
            ('timeout_bool', ['"timeout_seconds": 120', '"timeout_seconds": true']),
            (
                "unknown_shell_field",
                ['"probe_tier": 1', '"probe_tier": 1,\n      "shell": true'],
            ),
            (
                "argv_and_command",
                ['"probe_tier": 1', '"probe_tier": 1,\n      "command": "rm -rf ."'],
            ),
            ('missing_network', ['      "network": "deny",\n', ""]),
        ]
        for name, replacements in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                docs = write_valid_step2_fixture(root)
                subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
                text = subplan.read_text(encoding="utf-8")
                old, new = replacements
                self.assertIn(old, text)
                subplan.write_text(text.replace(old, new), encoding="utf-8")

                result = run_validator(root, "step2", strict=True)

                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(
                    "strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md",
                    result.stdout,
                )

    def test_strict_step2_rejects_validation_cwd_symlink_escape(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            (root / "outside-link").symlink_to(Path(outside_dir), target_is_directory=True)
            docs = write_valid_step2_fixture(root)
            subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
            text = subplan.read_text(encoding="utf-8").replace('"cwd": "."', '"cwd": "outside-link"')
            subplan.write_text(text, encoding="utf-8")

            result = run_validator(root, "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_validation_command_invalid_cwd=", result.stdout)

    def test_strict_step2_accepts_canonical_read_only_validation_profiles(self) -> None:
        canonical = json.dumps(
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]
        )
        positive = [
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            ["ruff", "check", "--no-fix", "--no-cache", "."],
        ]
        for argv in positive:
            with self.subTest(argv=argv), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                docs = write_valid_step2_fixture(root)
                subplan = docs / "Faz-1-Plans" / "Faz1.1-local-contract.md"
                text = subplan.read_text(encoding="utf-8")
                self.assertIn(canonical, text)
                subplan.write_text(text.replace(canonical, json.dumps(argv)), encoding="utf-8")

                result = run_validator(root, "step2", strict=True)

                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_strict_step2_rejects_mutating_validation_command_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace(
                '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]',
                '"argv": ["npm", "run", "deploy"]',
            )
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_missing_exact_validation_command=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)

    def test_step2_accepts_safe_legacy_validation_command_only_outside_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace(
                '"argv": ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_feature_1_1.py", "-q"]',
                '"command": "python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q"',
            )
            text = re.sub(r',\n      "cwd": "\\.",\n      "expected_exit_code": 0,\n      "timeout_seconds": 120,\n      "network": "deny",\n      "probe_tier": 1', ',\n      "expected_result": "exit_code_0"', text)
            subplan_path.write_text(text, encoding="utf-8")

            compatible = run_validator(Path(temp_dir), "step2", strict=False)
            self.assertEqual(compatible.returncode, 0, compatible.stdout + compatible.stderr)

            strict = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(strict.returncode, 0, strict.stdout + strict.stderr)
            self.assertIn("strict_warning=subplan_validation_command_requires_structured_argv=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::VAL-01", strict.stdout)

    def test_strict_step2_requires_security_review_for_high_risk_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace('"risk_class": "low"', '"risk_class": "high"')
            text = text.replace('"risk_domains": ["none"]', '"risk_domains": ["credential"]')
            text = text.replace('"security_review_required": true', '"security_review_required": false')
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_security_review_required_for_risk=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)

    def test_strict_step2_rejects_blank_dependencies_and_unknown_parent_signal(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            text = subplan_path.read_text(encoding="utf-8")
            text = text.replace('"parent_signals": ["MP-PH1-AS-01"]', '"parent_signals": ["MP-PH99-AS-01"]')
            text = text.replace('"depends_on": []', '"depends_on": [""]')
            subplan_path.write_text(text, encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=subplan_unknown_parent_acceptance_signal=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::MP-PH99-AS-01", result.stdout)
            self.assertIn("strict_warning=subplan_blank_dependency_value=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::depends_on", result.stdout)

    def test_strict_step2_validates_execution_wave_and_decision_references(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            index_path = docs / "Sub-Planing-Index.md"
            index_text = index_path.read_text(encoding="utf-8")
            duplicate = "| wave-1 | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | Duplicate assignment. | none |"
            index_text = index_text.replace(
                "| wave-1 | Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | Validate gateway activation. | Faz 1.1 |",
                duplicate + "\n| wave-1 | Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | Validate gateway activation. | Faz 1.1 |",
            )
            index_path.write_text(index_text, encoding="utf-8")
            subplan_path = docs / "Faz-1-Plans/Faz1.1-local-contract.md"
            subplan_path.write_text(subplan_path.read_text(encoding="utf-8") + "\nBlocked by DEC-999.\n", encoding="utf-8")

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=execution_waves_duplicate_subplan=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", result.stdout)
            self.assertIn("strict_warning=decision_reference_missing_register_entry=DEC-999", result.stdout)

    def test_strict_step2_requires_framework_matrix_and_algorithmic_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            main_path = docs / "Main-Planing.md"
            main_path.write_text(
                main_path.read_text(encoding="utf-8")
                + "\nThe implementation plan uses TRL, vLLM, PEFT, and GRPO rollout groups.\n",
                encoding="utf-8",
            )

            result = run_validator(Path(temp_dir), "step2", strict=True)

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("strict_warning=framework_ownership_matrix_missing=Planner-docs/Sub-Planing-Index.md", result.stdout)
            self.assertIn("strict_warning=algorithmic_invariant_register_missing=Planner-docs/Sub-Planing-Index.md", result.stdout)

            index_path = docs / "Sub-Planing-Index.md"
            index_path.write_text(
                index_path.read_text(encoding="utf-8")
                + "\n### Framework Ownership Matrix\n\nFramework ownership is discussed here.\n"
                + "\n### Algorithmic Invariant Register\n\nInvariant notes are discussed here.\n",
                encoding="utf-8",
            )
            heading_only = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(heading_only.returncode, 0, heading_only.stdout + heading_only.stderr)
            self.assertIn("strict_warning=framework_ownership_matrix_table_missing=Planner-docs/Sub-Planing-Index.md", heading_only.stdout)
            self.assertIn("strict_warning=algorithmic_invariant_register_table_missing=Planner-docs/Sub-Planing-Index.md", heading_only.stdout)

            index_path.write_text(
                index_path.read_text(encoding="utf-8")
                .replace(
                    "Framework ownership is discussed here.",
                    "\n".join(
                        [
                            "| Capability | External Framework Owns | Project Owns | Wrapper Boundary | Validation |",
                            "|---|---|---|---|---|",
                            "| | | | | |",
                        ]
                    ),
                )
                .replace(
                    "Invariant notes are discussed here.",
                    "\n".join(
                        [
                            "| Invariant ID | Scope | Required Condition | Violation Risk | Validation Probe |",
                            "|---|---|---|---|---|",
                            "| | | | | |",
                        ]
                    ),
                ),
                encoding="utf-8",
            )
            blank_rows = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(blank_rows.returncode, 0, blank_rows.stdout + blank_rows.stderr)
            self.assertIn("strict_warning=framework_matrix_missing_capability=Planner-docs/Sub-Planing-Index.md::unknown", blank_rows.stdout)
            self.assertIn("strict_warning=algorithmic_invariant_invalid_id=Planner-docs/Sub-Planing-Index.md::missing", blank_rows.stdout)
            self.assertIn("strict_warning=framework_ownership_matrix_table_missing=Planner-docs/Sub-Planing-Index.md", blank_rows.stdout)
            self.assertIn("strict_warning=algorithmic_invariant_register_table_missing=Planner-docs/Sub-Planing-Index.md", blank_rows.stdout)

            index_path.write_text(heading_only_root := index_path.read_text(encoding="utf-8"), encoding="utf-8")
            index_text = heading_only_root
            index_text = re.sub(
                r"### Framework Ownership Matrix\n\n.*?\n### Algorithmic Invariant Register",
                "### Framework Ownership Matrix\n\nFramework ownership is discussed here.\n\n### Algorithmic Invariant Register",
                index_text,
                flags=re.DOTALL,
            )
            index_text = re.sub(
                r"### Algorithmic Invariant Register\n\n.*$",
                "### Algorithmic Invariant Register\n\nInvariant notes are discussed here.\n",
                index_text,
                flags=re.DOTALL,
            )
            index_path.write_text(index_text, encoding="utf-8")
            index_text = index_path.read_text(encoding="utf-8")
            index_text = index_text.replace(
                "Framework ownership is discussed here.",
                "\n".join(
                    [
                        "| Capability | External Framework Owns | Project Owns | Wrapper Boundary | Validation |",
                        "|---|---|---|---|---|",
                        "| Training loop | TRL trainer semantics | Project policy glue. | src/training/adapter.py | python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q |",
                    ]
                ),
            )
            index_text = index_text.replace(
                "Invariant notes are discussed here.",
                "\n".join(
                    [
                        "| Invariant ID | Scope | Required Condition | Violation Risk | Validation Probe |",
                        "|---|---|---|---|---|",
                        "| INV-001 | GRPO rollout group | Policy and trainer-step fingerprints match. | stale reward reuse | python3 -B -m pytest -p no:cacheprovider tests/test_feature_1_1.py -q |",
                    ]
                ),
            )
            index_path.write_text(index_text, encoding="utf-8")
            valid = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

    def test_cli_step2_success_smoke_uses_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            result = run_validator_cli(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("planner_docs_validation=passed", result.stdout)

    def test_cli_step4_gate_smoke_uses_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(
                docs,
                "PASS_WITH_WARNINGS",
                ["| AUDIT-FIX-01 | P1 | open | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | repair before implementation | Fix before Step 4. |"],
            )
            result = run_validator_cli(Path(temp_dir), "step4")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("step4_blocked_by_high_severity_findings=P0:0,P1:1", result.stdout)

    def test_cli_timeout_failure_is_readable_and_redacted(self) -> None:
        fake_key = "sk-or-v1-" + "A" * 64
        timeout = subprocess.TimeoutExpired(
            cmd=["validator"],
            timeout=1,
            output=f"partial stdout {fake_key}".encode("utf-8"),
            stderr=None,
        )
        with mock.patch("subprocess.run", side_effect=timeout):
            with self.assertRaises(AssertionError) as raised:
                run_validator_cli(Path("/tmp/example-root"), "step2", timeout=1)

        message = str(raised.exception)
        self.assertIn("validator timed out after 1s", message)
        self.assertIn("mode=step2", message)
        self.assertIn("root=/tmp/example-root", message)
        self.assertIn("command=", message)
        self.assertIn("stdout=partial stdout <redacted>", message)
        self.assertIn("stderr=", message)
        self.assertNotIn(fake_key, message)

    def test_step2_validates_optional_autopsy_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_autopsy(docs)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("autopsy_exists=true", result.stdout)


    def test_step2_validates_optional_ontology_and_ledger_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_ontology(docs)
            write_ledger(docs)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("ontology_exists=true", result.stdout)
            self.assertIn("ledger_exists=true", result.stdout)

    def test_step2_accepts_legacy_v2_and_v3_ledger_headings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_ledger(docs, version=1)
            legacy_result = run_validator(Path(temp_dir), "step2")
            self.assertEqual(legacy_result.returncode, 0, legacy_result.stdout + legacy_result.stderr)
            self.assertIn("warning=legacy_ledger_schema=Planner-docs/Planing-Ledger.md", legacy_result.stdout)

            write_ledger(docs, version=2)
            v2_result = run_validator(Path(temp_dir), "step2")
            self.assertEqual(v2_result.returncode, 0, v2_result.stdout + v2_result.stderr)
            self.assertIn("ledger_schema=v2", v2_result.stdout)
            self.assertIn("warning=legacy_ledger_schema_v2=Planner-docs/Planing-Ledger.md", v2_result.stdout)

            write_ledger(docs, version=3)
            v3_result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(v3_result.returncode, 0, v3_result.stdout + v3_result.stderr)
            self.assertIn("ledger_schema=v3", v3_result.stdout)

    def test_step2_validates_optional_project_comprehension_when_present(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_comprehension(docs)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("comprehension_exists=true", result.stdout)

    def test_step2_rejects_optional_comprehension_heading_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            bad_headings = COMPREHENSION_HEADINGS.copy()
            bad_headings[2], bad_headings[3] = bad_headings[3], bad_headings[2]
            write_comprehension(docs, headings=bad_headings)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("heading_out_of_order=Planner-docs/Project-Comprehension.md", result.stdout)

    def test_strict_comprehension_rejects_headings_only_and_bad_markers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)
            write_autopsy(docs)
            lines: list[str] = []
            for heading in COMPREHENSION_HEADINGS:
                lines += [heading, ""]
            (docs / "Project-Comprehension.md").write_text("\n".join(lines), encoding="utf-8")
            headings_only = run_validator(Path(temp_dir), "autopsy", strict=True)
            self.assertNotEqual(headings_only.returncode, 0, headings_only.stdout + headings_only.stderr)
            self.assertIn("strict_warning=comprehension_missing_question=Planner-docs/Project-Comprehension.md", headings_only.stdout)
            self.assertIn("strict_warning=comprehension_missing_evidence_row=Planner-docs/Project-Comprehension.md", headings_only.stdout)

            write_comprehension(
                docs,
                trace_marker="NOT_APPLICABLE:",
                architecture_marker="UNKNOWN: relation cannot be inferred.",
                hypothesis_marker="NO_UNRESOLVED_HYPOTHESES:",
            )
            bad_markers = run_validator(Path(temp_dir), "autopsy", strict=True)
            self.assertNotEqual(bad_markers.returncode, 0, bad_markers.stdout + bad_markers.stderr)
            self.assertIn("strict_warning=invalid_not_applicable_marker=Planner-docs/Project-Comprehension.md::## 3. Domain-to-Code Trace Map", bad_markers.stdout)
            self.assertIn("strict_warning=unknown_marker_missing_next_probe=Planner-docs/Project-Comprehension.md::## 5. Intended vs Implemented Architecture", bad_markers.stdout)
            self.assertIn("strict_warning=invalid_no_unresolved_hypotheses_marker=Planner-docs/Project-Comprehension.md", bad_markers.stdout)

    def test_comprehension_claim_class_evidence_rules(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_comprehension(
                docs,
                claim_type="structural",
                evidence_confidence="confirmed",
                evidence_type="source",
                evidence_source="plugins/codexqb/.codex-plugin/plugin.json",
            )
            structural = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(structural.returncode, 0, structural.stdout + structural.stderr)

            write_comprehension(
                docs,
                claim_type="behavioral",
                evidence_confidence="confirmed",
                evidence_type="source",
                evidence_source="src/service.py",
            )
            behavioral = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(behavioral.returncode, 0, behavioral.stdout + behavioral.stderr)
            self.assertIn("strict_warning=confirmed_behavioral_claim_needs_test_or_runtime=Planner-docs/Project-Comprehension.md::EV-01", behavioral.stdout)

            write_comprehension(
                docs,
                claim_type="historical",
                evidence_confidence="confirmed",
                evidence_type="source",
                evidence_source="src/service.py",
            )
            historical = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(historical.returncode, 0, historical.stdout + historical.stderr)
            self.assertIn("strict_warning=historical_claim_requires_history_evidence=Planner-docs/Project-Comprehension.md::EV-01", historical.stdout)

            write_comprehension(
                docs,
                evidence_confidence="tentative",
                hypothesis_next_probe="",
            )
            tentative = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(tentative.returncode, 0, tentative.stdout + tentative.stderr)
            self.assertIn("strict_warning=open_hypothesis_missing_next_probe=Planner-docs/Project-Comprehension.md::HYP-01", tentative.stdout)

    def test_heading_parser_ignores_fenced_code_and_detects_duplicate_headings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            fenced = [
                "```markdown",
                "# Project Ontology",
                "## 1. Purpose",
                "## 2. Domain Vocabulary",
                "## 3. Core Entities and Concepts",
                "## 4. Module and Boundary Map",
                "## 5. Workflows and Lifecycles",
                "## 6. Integrations and External Systems",
                "## 7. Invariants and Constraints",
                "## 8. Open Ontology Questions",
                "```",
            ]
            (docs / "Project-Ontology.md").write_text("\n".join(fenced), encoding="utf-8")
            fenced_result = run_validator(Path(temp_dir), "step2")
            self.assertNotEqual(fenced_result.returncode, 0, fenced_result.stdout + fenced_result.stderr)
            self.assertIn("missing_heading=Planner-docs/Project-Ontology.md::# Project Ontology", fenced_result.stdout)

            write_ontology(
                docs,
                headings=[
                    "# Project Ontology",
                    "## 1. Purpose",
                    "## 1. Purpose",
                    "## 2. Domain Vocabulary",
                    "## 3. Core Entities and Concepts",
                    "## 4. Module and Boundary Map",
                    "## 5. Workflows and Lifecycles",
                    "## 6. Integrations and External Systems",
                    "## 7. Invariants and Constraints",
                    "## 8. Open Ontology Questions",
                ],
            )
            duplicate_result = run_validator(Path(temp_dir), "step2")
            self.assertNotEqual(duplicate_result.returncode, 0, duplicate_result.stdout + duplicate_result.stderr)
            self.assertIn("duplicate_heading=Planner-docs/Project-Ontology.md::## 1. Purpose::2", duplicate_result.stdout)

    def test_comprehension_invalid_statuses_warn_and_strict_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_comprehension(
                docs,
                evidence_confidence="certain",
                evidence_type="guess",
                architecture_status="aligned",
            )
            relaxed = run_validator(Path(temp_dir), "step2")
            self.assertEqual(relaxed.returncode, 0, relaxed.stdout + relaxed.stderr)
            self.assertIn("warning=invalid_evidence_type=Planner-docs/Project-Comprehension.md::guess", relaxed.stdout)
            self.assertIn("warning=invalid_confidence=Planner-docs/Project-Comprehension.md::certain", relaxed.stdout)
            self.assertIn("warning=invalid_architecture_status=Planner-docs/Project-Comprehension.md::aligned", relaxed.stdout)

            strict = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(strict.returncode, 0, strict.stdout + strict.stderr)
            self.assertIn("strict_warning=invalid_evidence_type=Planner-docs/Project-Comprehension.md::guess", strict.stdout)

    def test_comprehension_quality_warnings_fail_in_strict_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_comprehension(
                docs,
                evidence_source="",
                trace_entry="unknown",
                trace_core="unknown",
                trace_tests="unknown",
                hypothesis_next_probe="",
            )
            relaxed = run_validator(Path(temp_dir), "step2")
            self.assertEqual(relaxed.returncode, 0, relaxed.stdout + relaxed.stderr)
            self.assertIn("warning=high_confidence_without_evidence=Planner-docs/Project-Comprehension.md::EV-01", relaxed.stdout)
            self.assertIn("warning=trace_missing_code_or_test_anchor=Planner-docs/Project-Comprehension.md::TRACE-01", relaxed.stdout)
            self.assertIn("warning=open_hypothesis_missing_next_probe=Planner-docs/Project-Comprehension.md::HYP-01", relaxed.stdout)

            strict = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(strict.returncode, 0, strict.stdout + strict.stderr)
            self.assertIn("strict_warning=high_confidence_without_evidence=Planner-docs/Project-Comprehension.md::EV-01", strict.stdout)

    def test_ledger_v2_status_semantics_and_step4_legacy_requirement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_ledger(docs, version=2, status="banana")
            invalid = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(invalid.returncode, 0, invalid.stdout + invalid.stderr)
            self.assertIn("strict_warning=invalid_ledger_status=Planner-docs/Planing-Ledger.md::banana", invalid.stdout)

            write_ledger(docs, version=2, status="in_progress", run_id="")
            in_progress = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(in_progress.returncode, 0, in_progress.stdout + in_progress.stderr)
            self.assertIn("strict_warning=ledger_in_progress_missing_run_id=Planner-docs/Planing-Ledger.md::Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", in_progress.stdout)

            write_ledger(docs, version=2, status="superseded", superseded_by="")
            superseded = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(superseded.returncode, 0, superseded.stdout + superseded.stderr)
            self.assertIn("strict_warning=ledger_superseded_missing_target=Planner-docs/Planing-Ledger.md::Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", superseded.stdout)

            write_audit(docs, "PASS")
            write_ledger(docs, version=1)
            legacy_step4 = run_validator(Path(temp_dir), "step4", strict=True)
            self.assertNotEqual(legacy_step4.returncode, 0, legacy_step4.stdout + legacy_step4.stderr)
            self.assertIn("legacy_ledger_requires_v2_for_step4=Planner-docs/Planing-Ledger.md", legacy_step4.stdout)

    def test_ontology_competency_question_status_is_validated(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_ontology_with_competency_status(docs, "answered")
            valid = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(valid.returncode, 0, valid.stdout + valid.stderr)

            write_ontology_with_competency_status(docs, "resolved")
            invalid = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(invalid.returncode, 0, invalid.stdout + invalid.stderr)
            self.assertIn("strict_warning=invalid_ontology_question_status=Planner-docs/Project-Ontology.md::resolved", invalid.stdout)

    def test_step2_rejects_optional_ontology_heading_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_ontology(docs, headings=["# Project Ontology", "## 2. Domain Vocabulary", "## 1. Purpose"])
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("heading_out_of_order=Planner-docs/Project-Ontology.md", result.stdout)

    def test_step2_rejects_autopsy_heading_order_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            bad_headings = AUTOPSY_HEADINGS.copy()
            bad_headings[3], bad_headings[4] = bad_headings[4], bad_headings[3]
            write_autopsy(docs, headings=bad_headings)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("heading_out_of_order=Planner-docs/Autopsy.md", result.stdout)

    def test_roadmap_table_ignores_historical_phase_mentions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_phase_count=2", result.stdout)
            self.assertNotIn("Faz-10-Plans", result.stdout)
            self.assertNotIn("Faz-11-Plans", result.stdout)

    def test_placeholder_safe_and_example_placeholder_are_not_false_positive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn("placeholder_text=", result.stdout)

    def test_relative_index_refs_are_normalized(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir), relative_refs=True)
            result = run_validator(Path(temp_dir), "step2", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("index_reference_count=2", result.stdout)

    def test_long_secret_is_detected_but_short_task_spec_like_text_is_not(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            (docs / "task-spec.yaml").write_text("name: task-spec.yaml\nexample: sk-short\n", encoding="utf-8")
            short_result = run_validator(Path(temp_dir), "step2")
            self.assertEqual(short_result.returncode, 0, short_result.stdout + short_result.stderr)
            self.assertIn("secret_findings=0", short_result.stdout)

            (docs / "leak.md").write_text("fake test token: sk-" + "A" * 24 + "\n", encoding="utf-8")
            long_result = run_validator(Path(temp_dir), "step2")
            self.assertNotEqual(long_result.returncode, 0, long_result.stdout + long_result.stderr)
            self.assertIn("secret_pattern=openai_api_key", long_result.stdout)
            self.assertNotIn("A" * 24, long_result.stdout)

    def test_openrouter_secret_is_detected_but_placeholders_pass(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            env_name = "OPENROUTER" + "_API_KEY"
            (docs / "safe-env.md").write_text(
                "\n".join(
                    [
                        f"{env_name}=your_openrouter_api_key",
                        f"{env_name}=<redacted>",
                        f"{env_name}=${env_name}",
                    ]
                ),
                encoding="utf-8",
            )
            placeholder_result = run_validator(Path(temp_dir), "step2")
            self.assertEqual(placeholder_result.returncode, 0, placeholder_result.stdout + placeholder_result.stderr)

            fake_key = "sk-or-v1-" + "B" * 64
            (docs / "leak.md").write_text(f"{env_name}={fake_key}\n", encoding="utf-8")
            leak_result = run_validator(Path(temp_dir), "step2")
            self.assertNotEqual(leak_result.returncode, 0, leak_result.stdout + leak_result.stderr)
            self.assertIn("secret_pattern=openrouter_api_key", leak_result.stdout)
            self.assertNotIn(fake_key, leak_result.stdout)

    def test_step4_missing_audit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            result = run_validator(Path(temp_dir), "step4")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing_file=Planner-docs/Sub-Planing-Audit.md", result.stdout)

    def test_step3_preflight_passes_without_audit_but_step3_requires_audit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            write_valid_step2_fixture(Path(temp_dir))
            preflight = run_validator(Path(temp_dir), "step3-preflight", strict=True)
            self.assertEqual(preflight.returncode, 0, preflight.stdout + preflight.stderr)
            self.assertIn("audit_exists=false", preflight.stdout)

            post_audit = run_validator(Path(temp_dir), "step3", strict=True)
            self.assertNotEqual(post_audit.returncode, 0, post_audit.stdout + post_audit.stderr)
            self.assertIn("missing_file=Planner-docs/Sub-Planing-Audit.md", post_audit.stdout)

    def test_step4_headings_only_audit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            lines: list[str] = []
            for heading in AUDIT_HEADINGS:
                lines += [heading, ""]
                if heading == "## 1. Audit Summary":
                    lines += ["Audit status: PASS", ""]
                if heading == "## 15. Audit Result":
                    lines += ["Final status: PASS", ""]
            (docs / "Sub-Planing-Audit.md").write_text("\n".join(lines), encoding="utf-8")
            result = run_validator(Path(temp_dir), "step4", strict=True)
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("audit_readiness_table_missing=Planner-docs/Sub-Planing-Audit.md", result.stdout)
            self.assertIn("empty_or_too_short_audit_section=Planner-docs/Sub-Planing-Audit.md::## 2. Reviewed Sources", result.stdout)

    def test_step4_blocked_audit_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(docs, "BLOCKED")
            result = run_validator(Path(temp_dir), "step4")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("step4_blocked_by_audit_status=BLOCKED", result.stdout)

    def test_step4_pass_audit_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(docs, "PASS")
            result = run_validator(Path(temp_dir), "step4")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("audit_status=PASS", result.stdout)
            self.assertIn("execution_queue_state=READY", result.stdout)

    def test_step4_no_action_required_passes_without_ready_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(
                docs,
                "PASS",
                readiness_rows=[
                    "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                    "|---|---|---|---|---|---|",
                    "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | COMPLETE | none | satisfied | Already verified in ledger. | none |",
                    "| Planner-docs/Faz-2-Plans/Faz2.1-live-gateway.md | SUPERSEDED | none | satisfied | Replaced by later plan. | none |",
                ],
            )
            result = run_validator(Path(temp_dir), "step4", strict=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("execution_queue_state=NO_ACTION_REQUIRED", result.stdout)

    def test_step4_pass_with_warnings_blocks_on_p0_or_p1(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(
                docs,
                "PASS_WITH_WARNINGS",
                ["| AUDIT-FIX-01 | P1 | open | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | repair before implementation | Fix before Step 4. |"],
            )
            result = run_validator(Path(temp_dir), "step4")
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("step4_blocked_by_high_severity_findings=P0:0,P1:1", result.stdout)

    def test_step4_pass_with_only_p2_or_p3_warns_but_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(
                docs,
                "PASS_WITH_WARNINGS",
                ["| AUDIT-FIX-02 | P2 | open | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | nonblocking wording repair | Track during Step 4. |"],
                readiness_rows=[
                    "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                    "|---|---|---|---|---|---|",
                    "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | READY_WITH_WARNINGS | AUDIT-FIX-02 | independent | Contract complete with warning. | none |",
                ],
            )
            result = run_validator(Path(temp_dir), "step4")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("warning=step4_has_nonblocking_warnings=P2:1,P3:0", result.stdout)

    def test_step4_pass_rejects_open_p2_but_accepts_resolved_p2(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(
                docs,
                "PASS",
                ["| AUDIT-FIX-02 | P2 | open | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | nonblocking wording repair | Track during Step 4. |"],
            )
            open_result = run_validator(Path(temp_dir), "step4")
            self.assertNotEqual(open_result.returncode, 0, open_result.stdout + open_result.stderr)
            self.assertIn("audit_status_inconsistent_with_open_warnings=PASS::P2:1,P3:0", open_result.stdout)

            write_audit(
                docs,
                "PASS",
                ["| AUDIT-FIX-02 | P2 | resolved | Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | nonblocking wording repair | none |"],
            )
            resolved_result = run_validator(Path(temp_dir), "step4", strict=True)
            self.assertEqual(resolved_result.returncode, 0, resolved_result.stdout + resolved_result.stderr)
            self.assertIn("p2_findings=0", resolved_result.stdout)

    def test_step4_readiness_rejects_unsafe_unknown_or_conflicting_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            scenarios = [
                ("absolute", "/tmp/Faz1.1-local-contract.md", "READY", "independent", "unsafe_subplan_path"),
                ("traversal", "../Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", "READY", "independent", "unsafe_subplan_path"),
                ("missing", "Planner-docs/Faz-1-Plans/Faz1.99-missing.md", "READY", "independent", "missing_readiness_subplan"),
                ("unknown_status", "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", "BANANA", "independent", "invalid_readiness_status"),
                ("blocked_dependency", "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md", "READY", "blocked", "ready_row_has_blocked_dependency"),
            ]
            for label, path, status, dependency, expected in scenarios:
                write_audit(
                    docs,
                    "PASS",
                    readiness_rows=[
                        "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                        "|---|---|---|---|---|---|",
                        f"| {path} | {status} | none | {dependency} | {label} case. | none |",
                    ],
                )
                result = run_validator(Path(temp_dir), "step4")
                self.assertNotEqual(result.returncode, 0, label + result.stdout + result.stderr)
                self.assertIn(expected, result.stdout, label)

            write_audit(
                docs,
                "PASS_WITH_WARNINGS",
                readiness_rows=[
                    "| Sub-Plan Path | Status | Finding IDs | Dependency State | Reason | Required Repair |",
                    "|---|---|---|---|---|---|",
                    "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | READY | none | independent | First row. | none |",
                    "| Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md | BLOCKED | none | blocked | Second row. | Fix blocker. |",
                ],
            )
            duplicate = run_validator(Path(temp_dir), "step4")
            self.assertNotEqual(duplicate.returncode, 0, duplicate.stdout + duplicate.stderr)
            self.assertIn("conflicting_readiness_status=Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md::READY,BLOCKED", duplicate.stdout)

    def test_step4_pass_with_warnings_no_findings_text_does_not_count_as_findings(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = write_valid_step2_fixture(Path(temp_dir))
            write_audit(docs, "PASS_WITH_WARNINGS", ["No P0/P1 findings. No P2/P3 findings."])
            result = run_validator(Path(temp_dir), "step4")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("p0_findings=0", result.stdout)
            self.assertIn("p1_findings=0", result.stdout)
            self.assertIn("p2_findings=0", result.stdout)
            self.assertIn("p3_findings=0", result.stdout)


if __name__ == "__main__":
    unittest.main()
