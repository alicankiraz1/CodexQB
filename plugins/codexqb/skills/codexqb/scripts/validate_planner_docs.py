#!/usr/bin/env python3
"""Validate CodexQB Planner-docs outputs.

This helper is intentionally read-only. It checks the planning documents that
CodexQB generates without editing or normalizing them.
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

if __name__ == "__main__" and not _launcher_admission_is_valid(
    "validate_planner_docs.py"
):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\n"
    )
    raise SystemExit(2)


import argparse
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from safety_contracts import (  # noqa: E402
    exact_validation_command as shared_exact_validation_command,
    safe_log_text,
    safe_validation_cwd as shared_safe_validation_cwd,
    safe_validation_argv as shared_safe_validation_argv,
    safe_validation_command_item as shared_safe_validation_command_item,
    secret_match_locations,
)
from repository_io import (  # noqa: E402
    RepositoryIO,
    _controller_canonical_root as canonical_repository_root,
    _controller_directories as controller_directories,
    _controller_regular_paths as controller_regular_paths,
    open_repository_io,
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

ONTOLOGY_HEADINGS = [
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

LEDGER_LEGACY_HEADINGS = [
    "# Planing Ledger",
    "## 1. Purpose",
    "## 2. Planning Runs",
    "## 3. Implementation Runs",
    "## 4. Current State Snapshot",
    "## 5. Replanning Inputs",
    "## 6. Open Decisions and Follow-Ups",
]

LEDGER_V2_HEADINGS = [
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

LEDGER_V3_HEADINGS = [
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

LEDGER_HEADINGS = LEDGER_V3_HEADINGS

ARTIFACT_SCHEMA_VERSION = 3
HANDOFF_CONTRACT_VERSION = 2
PLUGIN_VERSION = "0.3.0"

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

FOLDER_RE = re.compile(r"^Faz-(\d+)-Plans$")
SUBPLAN_RE = re.compile(r"^Faz(\d+)\.(\d+)-[a-z0-9]+(?:-[a-z0-9]+)*\.md$")
INDEX_REF_RE = re.compile(
    r"(?:\./)?(?:Planner-docs/)?Faz-\d+-Plans/Faz\d+\.\d+-[a-z0-9]+(?:-[a-z0-9]+)*\.md"
)
MAIN_PHASE_RE = re.compile(r"\b(?:Faz|Phase|Stage)\s*-?\s*(\d+)\b", re.IGNORECASE)
ROADMAP_HEADING = "## 6. Phase-Based Master Roadmap"
ROADMAP_TABLE_ROW_RE = re.compile(r"^\|\s*(\d+)\s*\|", re.MULTILINE)
ROADMAP_HEADING_PHASE_RE = re.compile(r"^#{3,6}\s*(?:Faz|Phase|Stage)\s*-?\s*(\d+)\b", re.MULTILINE | re.IGNORECASE)
H1_SUBPLAN_RE = re.compile(r"^# Faz\s+(\d+)\.(\d+)\s+[—-]\s+.+$", re.MULTILINE)
SECTION_RE = re.compile(r"^(##\s+\d+\.\s+.+)$", re.MULTILINE)
AUDIT_FIX_RE = re.compile(
    r"^\s*(?:[-*]\s*)?\|?\s*(AUDIT-FIX-\d+)\s*(?:\||:|\u2014|\u2013|-)\s*(P0|P1|P2|P3)\b",
    re.MULTILINE,
)

PLACEHOLDER_PATTERNS = [
    ("todo", re.compile(r"\bTODO\b", re.IGNORECASE)),
    ("tbd", re.compile(r"\bTBD\b", re.IGNORECASE)),
    ("fixme", re.compile(r"\bFIXME\b", re.IGNORECASE)),
    ("lorem_ipsum", re.compile(r"\blorem ipsum\b", re.IGNORECASE)),
    ("to_be_filled", re.compile(r"\bto be filled\b|\bto_be_filled\b", re.IGNORECASE)),
    ("angle_placeholder", re.compile(r"<(?:TODO|TBD|PLACEHOLDER|TO_BE_FILLED)[^>]*>", re.IGNORECASE)),
    ("brace_placeholder", re.compile(r"\{\{[^{}]*(?:TODO|TBD|PLACEHOLDER|TO_BE_FILLED)[^{}]*\}\}", re.IGNORECASE)),
]

REPEATED_SENTENCE_MIN_COUNT = 5
REPEATED_SENTENCE_MIN_LENGTH = 80
NORMALIZED_DUPLICATE_WARNING_RATIO = 0.30
NORMALIZED_DUPLICATE_STRICT_FAILURE_RATIO = 0.45
ALLOWED_REPEATED_SENTENCE_FRAGMENTS = (
    "secret",
    "token",
    "credential",
    "private key",
    "local env",
    "source code",
    "config, test",
    "planning file",
    "planning files",
    "real secret",
)

ALLOWED_EVIDENCE_TYPES = {
    "source",
    "test",
    "runtime",
    "history",
    "configuration",
    "documentation",
    "user-confirmed",
}
ALLOWED_CONFIDENCE_VALUES = {"confirmed", "probable", "tentative", "contradicted"}
ALLOWED_CLAIM_TYPES = {
    "structural",
    "behavioral",
    "historical",
    "configuration",
    "user_intent",
    "architectural",
}
ALLOWED_ARCHITECTURE_STATUSES = {"convergent", "divergent", "absent", "unmodeled", "uncertain"}
ALLOWED_ONTOLOGY_QUESTION_STATUSES = {"answered", "partially_answered", "open", "contradicted"}
ALLOWED_LEDGER_STATUSES = {
    "planned",
    "ready",
    "ready_with_warnings",
    "in_progress",
    "implemented",
    "verified",
    "blocked",
    "superseded",
}
ALLOWED_LEDGER_PLANNING_STATUSES = {"draft", "audited", "needs_repair", "approved", "superseded"}
ALLOWED_LEDGER_EXECUTION_STATUSES = {
    "not_started",
    "ready",
    "ready_with_warnings",
    "in_progress",
    "implemented",
    "verified",
    "blocked",
    "superseded",
}
ALLOWED_PLANNING_MODES = {"wave", "full", "refresh", "repair"}
ALLOWED_GOAL_TOKEN_RISKS = {"low", "medium", "high", "very_high"}
ALLOWED_IMPLEMENTATION_PATH_STATES = {"proposed", "actual"}
ALLOWED_DECISION_STATUSES = {"open", "decided", "blocked", "superseded", "not_applicable"}
ALLOWED_ONTOLOGY_PROVENANCE = {
    "user_confirmed",
    "plan_derived",
    "framework_verified",
    "code_confirmed",
    "runtime_confirmed",
}
ALLOWED_FINDING_STATUSES = {"open", "accepted", "resolved", "not_applicable"}
OPEN_FINDING_STATUSES = {"open", "accepted"}
ALLOWED_READINESS_STATUSES = {
    "READY",
    "READY_WITH_WARNINGS",
    "NEEDS_REPAIR",
    "BLOCKED",
    "COMPLETE",
    "SUPERSEDED",
    "DEFERRED",
}
READY_READINESS_STATUSES = {"READY", "READY_WITH_WARNINGS"}
COMPLETED_READINESS_STATUSES = {"COMPLETE", "SUPERSEDED", "DEFERRED"}
ALLOWED_DEPENDENCY_STATES = {"satisfied", "independent", "blocked", "unknown"}
READINESS_HEADERS = [
    "Sub-Plan Path",
    "Status",
    "Finding IDs",
    "Dependency State",
    "Reason",
    "Required Repair",
]
FINDING_HEADERS = ["Finding ID", "Severity", "Status", "Affected Files", "Issue", "Required Action"]
LEDGER_V2_STATUS_HEADERS = [
    "Sub-plan Path",
    "Status",
    "Snapshot ID",
    "Run ID",
    "Validation Evidence",
    "Blocker",
    "Next Action",
    "Superseded By",
    "Updated At",
]
LEDGER_V3_STATUS_HEADERS = [
    "Sub-plan Path",
    "Planning Status",
    "Execution Status",
    "Snapshot ID",
    "Run ID",
    "Planning Evidence",
    "Implementation Evidence",
    "Blocker",
    "Next Action",
    "Superseded By",
    "Updated At",
]
IMPLEMENTATION_PATH_RE = re.compile(
    r"(?:proposed|actual|implementation surface|implementation path|files?|paths?|artifact)\b"
    r".{0,160}\b(?:src|tests|test|scripts|configs|examples|app|apps|packages|services|infra|docs)/"
    r"|[A-Za-z0-9_.-]+(?:/[\w.-]+)+\.(?:py|ts|tsx|js|json|ya?ml|toml|md|sql|sh)",
    re.IGNORECASE | re.DOTALL,
)
PARENT_SIGNAL_RE = re.compile(r"\bMP-PH\d+-AS-\d{2}\b", re.IGNORECASE)
DEPENDENCY_LABELS = ("depends_on", "blocks", "can_run_in_parallel_with", "activation_conditions")
DEFERRED_CARD_HEADERS = ["Phase", "Status", "Deferral Reason", "Activation Trigger", "Earliest Wave"]
PARENT_TRACE_HEADERS = ["Parent Signal", "Covered By", "Validation Command", "Status"]
DECISION_REGISTER_HEADERS = ["Decision ID", "Decision", "Required By", "Status", "Next Action"]
FRAMEWORK_MATRIX_HEADERS = ["Capability", "External Framework Owns", "Project Owns", "Wrapper Boundary", "Validation"]
ALGORITHMIC_INVARIANT_HEADERS = [
    "Invariant ID",
    "Scope",
    "Required Condition",
    "Violation Risk",
    "Validation Probe",
]
NOT_APPLICABLE_PREFIX = "NOT_APPLICABLE:"
NO_UNRESOLVED_HYPOTHESES_PREFIX = "NO_UNRESOLVED_HYPOTHESES:"
UNKNOWN_PREFIX = "UNKNOWN:"
UNKNOWN_CELL_VALUES = {"", "-", "n/a", "na", "none", "unknown", "unclear", "not found", "not evidenced"}
ALLOWED_RISK_CLASSES = {"low", "medium", "high", "critical"}
ALLOWED_RISK_DOMAINS = {
    "auth",
    "authorization",
    "credential",
    "secret",
    "external_provider",
    "network",
    "command_execution",
    "deployment",
    "migration",
    "stateful_runtime",
    "distributed_runtime",
    "online_learning",
    "reinforcement_learning",
    "cache",
    "resume",
    "checkpoint",
    "payment",
    "personal_data",
    "algorithmic_invariant",
    "none",
}
SECURITY_REVIEW_DOMAINS = ALLOWED_RISK_DOMAINS - {"none"}
ALLOWED_VALIDATION_NETWORK = {"deny"}
SECURITY_REVIEW_SIGNAL_RE = re.compile(
    r"\b(?:security|secret|credential|token|auth|authorization|permission|policy|live|external|provider|network|"
    r"stateful|distributed|online|\brl\b|grpo|rollout|trainer-step|vllm|trl|peft|deploy|production|migration|"
    r"cache|resume|checkpoint|payment|personal data|destructive|command execution)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class MarkdownHeading:
    text: str
    level: int
    line: int
    start: int
    end: int


@dataclass
class ValidationState:
    root: Path
    mode: str
    strict: bool
    repository: RepositoryIO
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, int | str] = field(default_factory=dict)

    @property
    def planner_docs(self) -> Path:
        return self.root / "Planner-docs"

    def rel(self, path: Path) -> str:
        try:
            return path.relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()

    def error(self, message: str) -> None:
        self.errors.append(message)

    def warning(self, message: str) -> None:
        self.warnings.append(message)

    def regular_paths(self, profile: str) -> tuple[str, ...]:
        return controller_regular_paths(self.repository, profile)

    def directories(self, profile: str) -> tuple[str, ...]:
        return controller_directories(self.repository, profile)

    def path_kind(self, path: Path | str) -> str:
        relative = path if isinstance(path, str) else self.rel(path)
        candidate = Path(relative)
        if (
            not relative
            or candidate.is_absolute()
            or "\\" in relative
            or candidate.as_posix() != relative
            or any(part in {"", ".", ".."} for part in candidate.parts)
        ):
            raise ValueError("repository_path_must_be_relative")
        if relative in self.regular_paths("step3"):
            return "regular"
        if relative in self.directories("step3"):
            return "directory"
        return "missing"

    def file_exists(self, path: Path | str) -> bool:
        return self.path_kind(path) == "regular"

    def directory_exists(self, path: Path | str) -> bool:
        return self.path_kind(path) == "directory"


def read_text(path: Path, state: ValidationState) -> str | None:
    try:
        evidence = state.repository.read_text(
            state.rel(path),
            required=False,
            audience="internal",
        )
        if not evidence.exists:
            state.error(f"missing_file={state.rel(path)}")
            return None
        return evidence.text
    except ValueError as exc:
        if str(exc).startswith("repository_io_non_utf8_text="):
            state.error(f"non_utf8_file={state.rel(path)}")
        else:
            state.error(f"read_error={state.rel(path)}:{str(exc).split('=', 1)[0]}")
    except OSError as exc:
        state.error(f"read_error={state.rel(path)}:{type(exc).__name__}")
    return None


def markdown_headings(text: str) -> list[MarkdownHeading]:
    headings: list[MarkdownHeading] = []
    in_fence = False
    fence_marker = ""
    offset = 0
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        stripped = line.strip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            marker = stripped[:3]
            if not in_fence:
                in_fence = True
                fence_marker = marker
            elif marker == fence_marker:
                in_fence = False
                fence_marker = ""
            offset += len(line)
            continue

        if not in_fence:
            raw = line.rstrip("\r\n")
            match = re.match(r"^(#{1,6})\s+(.+?)\s*$", raw)
            if match:
                heading_text = f"{match.group(1)} {match.group(2).strip()}"
                headings.append(
                    MarkdownHeading(
                        text=heading_text,
                        level=len(match.group(1)),
                        line=line_number,
                        start=offset,
                        end=offset + len(raw),
                    )
                )
        offset += len(line)
    return headings


def validate_heading_order(text: str, headings: list[str], path: Path, state: ValidationState) -> None:
    parsed = markdown_headings(text)
    positions_by_heading: dict[str, list[MarkdownHeading]] = defaultdict(list)
    for parsed_heading in parsed:
        positions_by_heading[parsed_heading.text].append(parsed_heading)

    last_pos = -1
    for heading in headings:
        matches = positions_by_heading.get(heading, [])
        if not matches:
            state.error(f"missing_heading={state.rel(path)}::{heading}")
            continue
        if len(matches) > 1:
            state.error(f"duplicate_heading={state.rel(path)}::{heading}::{len(matches)}")
        pos = matches[0].start
        if pos < last_pos:
            state.error(f"heading_out_of_order={state.rel(path)}::{heading}")
        last_pos = pos


def markdown_section(text: str, heading: str) -> str:
    parsed = markdown_headings(text)
    current_index = next((index for index, item in enumerate(parsed) if item.text == heading), None)
    if current_index is None:
        return ""
    current = parsed[current_index]
    body_start = text.find("\n", current.end)
    body_start = len(text) if body_start == -1 else body_start + 1
    next_heading = next((item for item in parsed[current_index + 1 :] if item.level <= current.level), None)
    body_end = next_heading.start if next_heading else len(text)
    return text[body_start:body_end].strip()


def markdown_tables(section: str) -> list[tuple[list[str], list[dict[str, str]]]]:
    tables: list[tuple[list[str], list[dict[str, str]]]] = []
    lines = section.splitlines()
    index = 0
    while index < len(lines):
        if not lines[index].lstrip().startswith("|"):
            index += 1
            continue
        block: list[str] = []
        while index < len(lines) and lines[index].lstrip().startswith("|"):
            block.append(lines[index].strip())
            index += 1
        if len(block) < 2:
            continue
        headers = [cell.strip() for cell in block[0].strip("|").split("|")]
        separator = [cell.strip() for cell in block[1].strip("|").split("|")]
        if not all(re.fullmatch(r":?-{3,}:?", cell) for cell in separator):
            continue
        rows: list[dict[str, str]] = []
        for line in block[2:]:
            cells = [cell.strip() for cell in line.strip("|").split("|")]
            if len(cells) < len(headers):
                cells.extend([""] * (len(headers) - len(cells)))
            rows.append(dict(zip(headers, cells)))
        tables.append((headers, rows))
    return tables


def canonical_header(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.strip().lower())


def headers_match(headers: list[str], required: list[str]) -> bool:
    return [canonical_header(item) for item in headers[: len(required)]] == [
        canonical_header(item) for item in required
    ]


def row_value(row: dict[str, str], *names: str) -> str:
    canonical = {canonical_header(key): value for key, value in row.items()}
    for name in names:
        value = canonical.get(canonical_header(name))
        if value is not None:
            return value.strip()
    return ""


def split_cell_values(value: str | None) -> list[str]:
    if value is None:
        return []
    items = re.split(r"[,;/]+|\band\b", value, flags=re.IGNORECASE)
    return [item.strip().lower() for item in items if item.strip()]


def normalized_cell(value: object | None) -> str:
    return ("" if value is None else str(value)).strip().strip("`").lower()


def cell_has_evidence(value: object | None) -> bool:
    return normalized_cell(value) not in UNKNOWN_CELL_VALUES


def markdown_link_target(value: str) -> str:
    match = re.fullmatch(r"\[[^\]]+\]\(([^)]+)\)", value.strip())
    return match.group(1).strip() if match else value.strip()


def frontmatter(text: str) -> dict[str, str]:
    if not text.startswith("---\n"):
        return {}
    end = text.find("\n---", 4)
    if end == -1:
        return {}
    data: dict[str, str] = {}
    for line in text[4:end].splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        data[key.strip()] = value.strip().strip("'\"")
    return data


def validate_artifact_frontmatter(text: str, path: Path, state: ValidationState) -> None:
    data = frontmatter(text)
    if data.get("artifact_schema_version") != str(ARTIFACT_SCHEMA_VERSION):
        state.warning(
            f"missing_or_invalid_artifact_schema_version={state.rel(path)}::{data.get('artifact_schema_version') or 'missing'}"
        )
    if data.get("generated_by") != "codexqb":
        state.warning(f"missing_or_invalid_generated_by={state.rel(path)}::{data.get('generated_by') or 'missing'}")
    if data.get("plugin_version") != PLUGIN_VERSION:
        state.warning(
            f"missing_or_invalid_plugin_version={state.rel(path)}::{data.get('plugin_version') or 'missing'}"
        )


def resolve_within_root(root: Path, rel_path: str) -> Path | None:
    target_text = markdown_link_target(rel_path)
    target = Path(target_text)
    if target.is_absolute() or ".." in target.parts:
        return None
    return root / target


def safe_subplan_path(state: ValidationState, value: str) -> tuple[Path | None, str | None]:
    target_text = markdown_link_target(value)
    target = Path(target_text)
    if target.is_absolute() or ".." in target.parts:
        return None, "unsafe"
    if len(target.parts) != 3 or target.parts[0] != "Planner-docs":
        return None, "unsafe"
    if not FOLDER_RE.match(target.parts[1]) or not SUBPLAN_RE.match(target.name):
        return None, "unsafe"
    resolved = resolve_within_root(state.root, target_text)
    if resolved is None:
        return None, "unsafe"
    if state.path_kind(target_text) == "missing":
        return resolved, "missing"
    if state.path_kind(target_text) != "regular":
        return None, "unsafe"
    return resolved, None


def safe_repo_path(value: str) -> str | None:
    target_text = markdown_link_target(value).strip().strip("`")
    target = Path(target_text)
    if not target_text or target.is_absolute() or ".." in target.parts:
        return None
    if len(target.parts) < 2:
        return None
    return target.as_posix()


def safe_repo_cwd(value: str, root: Path | None = None) -> bool:
    return shared_safe_validation_cwd(value, root=root)


def implementation_surface_path(value: str) -> str | None:
    target = safe_repo_path(value)
    if target is None:
        return None
    allowed_roots = {
        "src",
        "test",
        "tests",
        "scripts",
        "configs",
        "examples",
        "app",
        "apps",
        "packages",
        "services",
        "infra",
        "migrations",
    }
    if Path(target).parts[0] not in allowed_roots:
        return None
    return target


def exact_validation_command(value: str) -> bool:
    return shared_exact_validation_command(value)


def safe_validation_argv(argv: object) -> bool:
    return shared_safe_validation_argv(argv)


def safe_validation_command_item(
    item: dict[str, object],
    *,
    root: Path | None = None,
    allow_legacy: bool = False,
) -> bool:
    return shared_safe_validation_command_item(item, root=root, allow_legacy=allow_legacy)


def validation_probe_is_safe(value: str) -> bool:
    probe = value.strip()
    if re.fullmatch(r"VAL-\d{2}", probe):
        return True
    return exact_validation_command(probe)


def extract_fenced_json_after_heading(text: str, heading: str) -> tuple[object | None, str | None]:
    section = markdown_section(text, heading)
    if not section:
        return None, "missing_section"
    match = re.search(r"```json\s*(.*?)\s*```", section, flags=re.DOTALL | re.IGNORECASE)
    if not match:
        return None, "missing_json_block"
    try:
        return json.loads(match.group(1)), None
    except json.JSONDecodeError as exc:
        return None, f"invalid_json:{exc.lineno}:{exc.colno}"


def parent_signal_ids(text: str) -> set[str]:
    return {match.group(0).upper() for match in PARENT_SIGNAL_RE.finditer(text)}


def section_has_table(section: str) -> bool:
    return any(rows for _, rows in markdown_tables(section))


def marker_reason(value: str, prefix: str) -> str | None:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip()
    return None


def valid_marker_reason(value: str, prefix: str) -> bool:
    reason = marker_reason(value, prefix)
    return reason is not None and cell_has_evidence(reason) and len(reason) >= 8


def unknown_marker_has_next_probe(value: str) -> bool:
    reason = marker_reason(value, UNKNOWN_PREFIX)
    if reason is None or not cell_has_evidence(reason):
        return False
    return "next probe" in reason.lower() and len(reason) >= 12


def evidence_is_direct_for_claim(claim_type: str, evidence_type: str, evidence_source: str) -> bool:
    if not cell_has_evidence(evidence_source):
        return False
    if claim_type == "structural":
        return evidence_type == "source"
    if claim_type == "configuration":
        return evidence_type == "configuration"
    return False


def has_independent_evidence(evidence_type: str, evidence_source: str) -> bool:
    evidence_types = {item for item in split_cell_values(evidence_type) if item in ALLOWED_EVIDENCE_TYPES}
    locators = {item for item in split_cell_values(evidence_source) if cell_has_evidence(item)}
    return len(evidence_types) >= 2 and len(locators) >= 2


def extract_main_phase_numbers(text: str) -> list[int]:
    roadmap = markdown_section(text, ROADMAP_HEADING)
    if roadmap:
        table_numbers = sorted({int(match.group(1)) for match in ROADMAP_TABLE_ROW_RE.finditer(roadmap)})
        if table_numbers:
            return table_numbers

        heading_numbers = sorted({int(match.group(1)) for match in ROADMAP_HEADING_PHASE_RE.finditer(roadmap)})
        if heading_numbers:
            return heading_numbers

        return sorted({int(match.group(1)) for match in MAIN_PHASE_RE.finditer(roadmap)})

    return []


def collect_phase_folders(state: ValidationState) -> dict[int, Path]:
    folders: dict[int, Path] = {}
    if not state.directory_exists("Planner-docs"):
        state.error("missing_directory=Planner-docs")
        return folders

    directories = state.directories("step3")
    for relative in sorted(
        path
        for path in directories
        if path.startswith("Planner-docs/Faz-") and path.count("/") == 1
    ):
        folder = state.root / relative
        match = FOLDER_RE.match(folder.name)
        if not match:
            state.error(f"invalid_phase_folder={state.rel(folder)}")
            continue
        phase = int(match.group(1))
        if phase in folders:
            state.error(f"duplicate_phase_folder=Faz-{phase}-Plans")
        folders[phase] = folder
    return folders


def collect_subplans(state: ValidationState) -> list[tuple[int | None, int | None, Path]]:
    result: list[tuple[int | None, int | None, Path]] = []
    directories = state.directories("step3")
    paths = state.regular_paths("step3")
    folders = sorted(
        path
        for path in directories
        if path.startswith("Planner-docs/Faz-") and path.count("/") == 1
    )
    for folder_relative in folders:
        folder = state.root / folder_relative
        folder_match = FOLDER_RE.match(folder.name)
        folder_phase = int(folder_match.group(1)) if folder_match else None
        for relative in sorted(
            path
            for path in paths
            if path.startswith(f"{folder_relative}/")
            and path.count("/") == 2
            and path.endswith(".md")
        ):
            path = state.root / relative
            match = SUBPLAN_RE.match(path.name)
            if not match:
                state.error(f"invalid_subplan_filename={state.rel(path)}")
                result.append((folder_phase, None, path))
                continue
            file_phase = int(match.group(1))
            subphase = int(match.group(2))
            if folder_phase is not None and file_phase != folder_phase:
                state.error(
                    f"folder_file_phase_mismatch={state.rel(path)}::folder={folder_phase}::file={file_phase}"
                )
            result.append((file_phase, subphase, path))
    return result


def section_body(text: str, heading: str) -> str:
    return markdown_section(text, heading)


def normalized_body(text: str) -> str:
    return re.sub(r"\s+", " ", text.strip()).lower()


def normalize_semantic_sentence(text: str) -> str:
    lowered = normalized_body(text)
    lowered = re.sub(r"\bplanner-docs/faz-\d+-plans/faz\d+\.\d+-[a-z0-9-]+\.md\b", "<subplan>", lowered)
    lowered = re.sub(r"\bfaz[-\s]?\d+(?:\.\d+)?\b", "<phase>", lowered)
    lowered = re.sub(r"\bphase[-\s]?\d+(?:\.\d+)?\b", "<phase>", lowered)
    lowered = re.sub(r"\bmp-[a-z]+\d+-as-\d+\b", "<parent-signal>", lowered)
    lowered = re.sub(r"\b(?:dec|cq|trace|arc|hyp|ev)-\d+\b", "<id>", lowered)
    lowered = re.sub(r"\b\d+(?:\.\d+)?\b", "<number>", lowered)
    lowered = re.sub(r"\b[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+\b", "<path>", lowered)
    return lowered


def split_sentences(text: str) -> list[str]:
    compact = re.sub(r"\s+", " ", text.replace("\n", " ")).strip()
    return [item.strip() for item in re.split(r"(?<=[.!?])\s+", compact) if item.strip()]


def parse_inline_int_list(value: str) -> list[int]:
    if not value:
        return []
    return [int(item) for item in re.findall(r"\d+", value)]


def parse_scope_manifest(text: str, path: Path, state: ValidationState) -> dict[str, object]:
    section = markdown_section(text, "## 3. Planning Scope Manifest")
    manifest: dict[str, object] = {
        "planning_mode": "",
        "active_phases": [],
        "deferred_phases": [],
        "max_detailed_subplans": None,
        "max_output_words": None,
        "goal_token_risk": "",
        "review_checkpoint": "",
        "full_mode_authorization": "",
        "refreshed_phases": [],
        "repair_targets": "",
    }
    if not section:
        state.warning(f"missing_planning_scope_manifest={state.rel(path)}")
        return manifest

    for line in section.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("```") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip().lower()
        value = value.strip().strip("'\"")
        if key not in manifest:
            continue
        if key in {"active_phases", "deferred_phases", "refreshed_phases"}:
            manifest[key] = parse_inline_int_list(value)
        elif key in {"max_detailed_subplans", "max_output_words"}:
            numbers = parse_inline_int_list(value)
            manifest[key] = numbers[0] if numbers else None
        else:
            manifest[key] = value

    mode = str(manifest["planning_mode"])
    if mode not in ALLOWED_PLANNING_MODES:
        state.warning(f"invalid_planning_mode={state.rel(path)}::{mode or 'missing'}")
    if not manifest["active_phases"] and mode in {"wave", "refresh", "repair"}:
        state.warning(f"planning_scope_missing_active_phases={state.rel(path)}")
    if mode == "full" and manifest.get("full_mode_authorization") != "user_explicit":
        state.warning(f"full_mode_missing_user_explicit_authorization={state.rel(path)}")
    if mode == "refresh" and not manifest.get("refreshed_phases"):
        state.warning(f"refresh_mode_missing_refreshed_phases={state.rel(path)}")
    if mode == "repair" and not cell_has_evidence(str(manifest.get("repair_targets", ""))):
        state.warning(f"repair_mode_missing_repair_targets={state.rel(path)}")
    if manifest.get("goal_token_risk") and str(manifest.get("goal_token_risk")) not in ALLOWED_GOAL_TOKEN_RISKS:
        state.warning(f"invalid_goal_token_risk={state.rel(path)}::{manifest.get('goal_token_risk')}")
    for key in ("max_detailed_subplans", "max_output_words", "goal_token_risk", "review_checkpoint"):
        if not manifest[key]:
            state.warning(f"planning_scope_missing_{key}={state.rel(path)}")
    return manifest


def count_behavioral_acceptance_items(section: str) -> int:
    behavior_re = re.compile(
        r"\b(accepts?|rejects?|returns?|fails?|passes?|produces?|emits?|exits?|loads?|saves?|does not|must not|when)\b",
        re.IGNORECASE,
    )
    return sum(1 for line in section.splitlines() if line.strip().startswith(("-", "*")) and behavior_re.search(line))


def has_domain_specific_risk(section: str) -> bool:
    lowered = section.lower()
    if "risk:" not in lowered and "risk -" not in lowered and "risk |" not in lowered:
        return False
    generic_markers = (
        "local readiness is mistaken for live provider readiness",
        "source code is created by step 2",
        "required human decisions remain unresolved",
    )
    return not all(marker in lowered for marker in generic_markers)


def has_concrete_output_or_artifact(text: str) -> bool:
    lowered = text.lower()
    if "artifact:" in lowered or "output:" in lowered or "produces " in lowered:
        return True
    return bool(re.search(r"\b(?:reports|artifacts|outputs|examples|configs|tests|docs)/[\w./-]+", lowered))


def validate_implementation_contract(
    state: ValidationState,
    path: Path,
    text: str,
    known_parent_signals: set[str],
) -> None:
    contract, error = extract_fenced_json_after_heading(text, "### Implementation Contract")
    if error:
        state.warning(f"subplan_missing_implementation_contract={state.rel(path)}::{error}")
        state.warning(f"subplan_missing_implementation_path={state.rel(path)}")
        state.warning(f"subplan_missing_exact_validation_command={state.rel(path)}")
        return
    if not isinstance(contract, dict):
        state.warning(f"subplan_invalid_implementation_contract={state.rel(path)}::not_object")
        return

    if contract.get("contract_version") != 1:
        state.warning(f"subplan_invalid_contract_version={state.rel(path)}::{contract.get('contract_version') or 'missing'}")

    implementation_paths = contract.get("implementation_paths")
    if not isinstance(implementation_paths, list) or not implementation_paths:
        state.warning(f"subplan_missing_implementation_path={state.rel(path)}")
    else:
        valid_paths = 0
        for item in implementation_paths:
            if not isinstance(item, dict):
                state.warning(f"subplan_invalid_implementation_path_entry={state.rel(path)}::not_object")
                continue
            impl_path = implementation_surface_path(str(item.get("path", "")))
            state_value = str(item.get("state", "")).strip()
            if impl_path is None:
                state.warning(f"subplan_invalid_implementation_path={state.rel(path)}::{item.get('path') or 'missing'}")
            else:
                valid_paths += 1
            if state_value not in ALLOWED_IMPLEMENTATION_PATH_STATES:
                state.warning(f"subplan_invalid_implementation_path_state={state.rel(path)}::{state_value or 'missing'}")
        if valid_paths == 0:
            state.warning(f"subplan_missing_implementation_path={state.rel(path)}")

    validation_commands = contract.get("validation_commands")
    if not isinstance(validation_commands, list) or not validation_commands:
        state.warning(f"subplan_missing_exact_validation_command={state.rel(path)}")
    else:
        exact_commands = 0
        for item in validation_commands:
            if not isinstance(item, dict):
                state.warning(f"subplan_invalid_validation_command_entry={state.rel(path)}::not_object")
                continue
            command_id = str(item.get("id", ""))
            command = str(item.get("command", ""))
            expected = item.get("expected_result", item.get("expected_exit_code", ""))
            if not re.fullmatch(r"VAL-\d{2}", command_id):
                state.warning(f"subplan_invalid_validation_command_id={state.rel(path)}::{command_id or 'missing'}")
            if safe_validation_command_item(item, root=state.root, allow_legacy=not state.strict):
                exact_commands += 1
            else:
                state.warning(f"subplan_missing_exact_validation_command={state.rel(path)}")
            if state.strict and "argv" not in item:
                state.warning(f"subplan_validation_command_requires_structured_argv={state.rel(path)}::{command_id or 'unknown'}")
            if "argv" in item:
                cwd = str(item.get("cwd", ""))
                timeout = item.get("timeout_seconds")
                network = item.get("network")
                probe_tier = item.get("probe_tier")
                expected_exit = item.get("expected_exit_code")
                if not safe_repo_cwd(cwd, state.root):
                    state.warning(f"subplan_validation_command_invalid_cwd={state.rel(path)}::{command_id or 'unknown'}")
                if not isinstance(expected_exit, int) or isinstance(expected_exit, bool) or expected_exit != 0:
                    state.warning(f"subplan_validation_command_invalid_expected_exit_code={state.rel(path)}::{command_id or 'unknown'}")
                if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1 or timeout > 3600:
                    state.warning(f"subplan_validation_command_invalid_timeout={state.rel(path)}::{command_id or 'unknown'}")
                if network not in ALLOWED_VALIDATION_NETWORK:
                    state.warning(f"subplan_validation_command_invalid_network={state.rel(path)}::{command_id or 'unknown'}")
                if not isinstance(probe_tier, int) or isinstance(probe_tier, bool) or probe_tier != 1:
                    state.warning(f"subplan_validation_command_invalid_probe_tier={state.rel(path)}::{command_id or 'unknown'}")
            if not cell_has_evidence(expected):
                state.warning(f"subplan_validation_command_missing_expected_result={state.rel(path)}::{command_id or 'unknown'}")
        if exact_commands == 0:
            state.warning(f"subplan_missing_exact_validation_command={state.rel(path)}")

    parent_signals = contract.get("parent_signals")
    if not isinstance(parent_signals, list) or not parent_signals:
        state.warning(f"subplan_missing_parent_acceptance_signal={state.rel(path)}")
    else:
        for signal in parent_signals:
            normalized = str(signal).upper()
            if not PARENT_SIGNAL_RE.fullmatch(normalized):
                state.warning(f"subplan_invalid_parent_acceptance_signal={state.rel(path)}::{signal}")
            elif known_parent_signals and normalized not in known_parent_signals:
                state.warning(f"subplan_unknown_parent_acceptance_signal={state.rel(path)}::{normalized}")

    dependencies = contract.get("dependencies")
    if not isinstance(dependencies, dict):
        state.warning(f"subplan_missing_dependency_object={state.rel(path)}")
    else:
        for label in DEPENDENCY_LABELS:
            value = dependencies.get(label)
            if not isinstance(value, list):
                state.warning(f"subplan_missing_dependency_label={state.rel(path)}::{label}")
                continue
            for item in value:
                if not cell_has_evidence(str(item)):
                    state.warning(f"subplan_blank_dependency_value={state.rel(path)}::{label}")
            if label == "activation_conditions" and not any(cell_has_evidence(str(item)) for item in value):
                state.warning(f"subplan_missing_dependency_label={state.rel(path)}::{label}")

    outputs = contract.get("outputs")
    if not isinstance(outputs, list) or not outputs:
        state.warning(f"subplan_missing_concrete_output_artifact={state.rel(path)}")
    else:
        valid_outputs = 0
        for item in outputs:
            output_path = safe_repo_path(str(item))
            if output_path is None or not re.search(r"\.[a-z0-9]+$", output_path, flags=re.IGNORECASE):
                state.warning(f"subplan_invalid_output_artifact={state.rel(path)}::{item}")
            else:
                valid_outputs += 1
        if valid_outputs == 0:
            state.warning(f"subplan_missing_concrete_output_artifact={state.rel(path)}")

    security_review_required = contract.get("security_review_required")
    if not isinstance(security_review_required, bool):
        state.warning(f"subplan_invalid_security_review_flag={state.rel(path)}")

    risk_class = normalized_cell(str(contract.get("risk_class", "")))
    if risk_class not in ALLOWED_RISK_CLASSES:
        state.warning(f"subplan_invalid_risk_class={state.rel(path)}::{risk_class or 'missing'}")

    raw_domains = contract.get("risk_domains")
    risk_domains: set[str] = set()
    if not isinstance(raw_domains, list) or not raw_domains:
        state.warning(f"subplan_invalid_risk_domains={state.rel(path)}::missing")
    else:
        for raw_domain in raw_domains:
            domain = normalized_cell(str(raw_domain))
            if domain not in ALLOWED_RISK_DOMAINS:
                state.warning(f"subplan_invalid_risk_domain={state.rel(path)}::{domain or 'missing'}")
            else:
                risk_domains.add(domain)

    implementation_text = json.dumps(contract, sort_keys=True)
    requires_security_review = (
        risk_class in {"high", "critical"}
        or bool(risk_domains & SECURITY_REVIEW_DOMAINS)
        or bool(SECURITY_REVIEW_SIGNAL_RE.search(text))
        or bool(SECURITY_REVIEW_SIGNAL_RE.search(implementation_text))
    )
    if requires_security_review and security_review_required is not True:
        state.warning(f"subplan_security_review_required_for_risk={state.rel(path)}")


def is_allowed_repeated_sentence(sentence: str) -> bool:
    lowered = sentence.lower()
    return any(fragment in lowered for fragment in ALLOWED_REPEATED_SENTENCE_FRAGMENTS)


def add_repeated_sentence_candidates(
    state: ValidationState,
    path: Path,
    text: str,
    repeated_sentences: dict[str, list[str]],
) -> None:
    for sentence in split_sentences(text):
        if len(sentence) < REPEATED_SENTENCE_MIN_LENGTH:
            continue
        if is_allowed_repeated_sentence(sentence):
            continue
        repeated_sentences[sentence].append(state.rel(path))


def add_normalized_duplicate_candidates(
    state: ValidationState,
    path: Path,
    text: str,
    normalized_sentences: dict[str, list[str]],
) -> None:
    for sentence in split_sentences(text):
        if len(sentence) < 60 or is_allowed_repeated_sentence(sentence):
            continue
        normalized = normalize_semantic_sentence(sentence)
        if len(normalized) < 50:
            continue
        normalized_sentences[normalized].append(state.rel(path))


def validate_implementation_ready_subplan(
    state: ValidationState,
    path: Path,
    text: str,
    known_parent_signals: set[str],
) -> None:
    validate_implementation_contract(state, path, text, known_parent_signals)
    acceptance_count = count_behavioral_acceptance_items(section_body(text, "## 8. Acceptance Criteria"))
    if acceptance_count < 2:
        state.warning(f"subplan_insufficient_behavioral_acceptance={state.rel(path)}::count={acceptance_count}")
    if not PARENT_SIGNAL_RE.search(text):
        state.warning(f"subplan_missing_parent_acceptance_signal={state.rel(path)}")
    if not has_domain_specific_risk(section_body(text, "## 11. Risks and Mitigations")):
        state.warning(f"subplan_missing_domain_specific_risk={state.rel(path)}")
    if not has_concrete_output_or_artifact(text):
        state.warning(f"subplan_missing_concrete_output_artifact={state.rel(path)}")

    dependency_section = section_body(text, "## 10. Dependencies and Sequencing").lower()
    for label in DEPENDENCY_LABELS:
        if label not in dependency_section:
            state.warning(f"subplan_missing_dependency_label={state.rel(path)}::{label}")


def validate_step1(state: ValidationState) -> list[int]:
    main_path = state.planner_docs / "Main-Planing.md"
    text = read_text(main_path, state)
    if text is None:
        state.metrics["main_phase_count"] = 0
        return []

    validate_heading_order(text, STEP1_HEADINGS, main_path, state)
    for required in STEP1_HEADINGS[1:]:
        body = section_body(text, required)
        if required in text and len(body) < 20:
            state.error(f"empty_or_too_short_section={state.rel(main_path)}::{required}")

    phases = extract_main_phase_numbers(text)
    state.metrics["main_phase_count"] = len(phases)
    if not phases:
        state.error("main_plan_has_no_detected_phases=Planner-docs/Main-Planing.md")
    return phases


def validate_autopsy_optional(state: ValidationState) -> None:
    autopsy_path = state.planner_docs / "Autopsy.md"
    exists = state.file_exists(autopsy_path)
    state.metrics["autopsy_exists"] = "true" if exists else "false"
    if not exists:
        return

    text = read_text(autopsy_path, state)
    if text is None:
        return

    validate_heading_order(text, AUTOPSY_HEADINGS, autopsy_path, state)


def validate_autopsy_required(state: ValidationState) -> None:
    autopsy_path = state.planner_docs / "Autopsy.md"
    exists = state.file_exists(autopsy_path)
    state.metrics["autopsy_exists"] = "true" if exists else "false"
    if not exists:
        state.error("missing_file=Planner-docs/Autopsy.md")
        return

    text = read_text(autopsy_path, state)
    if text is not None:
        validate_heading_order(text, AUTOPSY_HEADINGS, autopsy_path, state)


def validate_ontology_competency_questions(text: str, path: Path, state: ValidationState) -> None:
    question_section = markdown_section(text, "## 8. Open Ontology Questions")
    if "Competency Questions" not in question_section:
        return
    for _, rows in markdown_tables(question_section):
        for row in rows:
            status = normalized_cell(row.get("Status"))
            question_id = row.get("Question ID") or row.get("ID") or row.get("Question") or "unknown"
            if status and status not in ALLOWED_ONTOLOGY_QUESTION_STATUSES:
                state.warning(f"invalid_ontology_question_status={state.rel(path)}::{status}")
            if status in {"answered", "partially_answered"} and not cell_has_evidence(row.get("Evidence")):
                state.warning(f"ontology_question_missing_evidence={state.rel(path)}::{question_id}")


def validate_ontology_provenance_tables(text: str, path: Path, state: ValidationState) -> None:
    found_provenance_table = False
    for heading in ONTOLOGY_HEADINGS[1:]:
        for headers, rows in markdown_tables(markdown_section(text, heading)):
            normalized_headers = {canonical_header(header) for header in headers}
            if "provenance" not in normalized_headers or "confidence" not in normalized_headers:
                continue
            found_provenance_table = True
            for row in rows:
                subject = row_value(row, "Term", "Entity", "Concept", "Question ID", "ID") or "unknown"
                provenance = normalized_cell(row_value(row, "Provenance"))
                confidence = normalized_cell(row_value(row, "Confidence"))
                if provenance not in ALLOWED_ONTOLOGY_PROVENANCE:
                    state.warning(f"invalid_ontology_provenance={state.rel(path)}::{subject}::{provenance or 'missing'}")
                if confidence not in ALLOWED_CONFIDENCE_VALUES:
                    state.warning(f"invalid_ontology_confidence={state.rel(path)}::{subject}::{confidence or 'missing'}")
    if not found_provenance_table:
        state.warning(f"ontology_provisional_without_provenance_confidence={state.rel(path)}")


def validate_optional_comprehension_doc(state: ValidationState) -> None:
    path = state.planner_docs / "Project-Comprehension.md"
    exists = state.file_exists(path)
    state.metrics["comprehension_exists"] = "true" if exists else "false"
    if not exists:
        return

    text = read_text(path, state)
    if text is None:
        return

    validate_heading_order(text, COMPREHENSION_HEADINGS, path, state)

    question_section = markdown_section(text, "## 1. Understanding Goals and Competency Questions")
    if "CQ-" not in question_section and "question id" not in question_section.lower():
        state.warning(f"comprehension_missing_question={state.rel(path)}")

    evidence_section = markdown_section(text, "## 2. Evidence Register and Confidence")
    evidence_rows: list[dict[str, str]] = []
    for _, rows in markdown_tables(evidence_section):
        evidence_rows.extend(rows)
        for row in rows:
            evidence_id = row.get("Evidence ID") or row.get("ID") or "unknown"
            evidence_type = normalized_cell(row_value(row, "Evidence type", "Evidence Type"))
            evidence_source = row_value(row, "Evidence source", "Evidence Source")
            confidence = normalized_cell(row.get("Confidence"))
            claim_type = normalized_cell(row_value(row, "Claim Type", "Type")) or "structural"
            if claim_type not in ALLOWED_CLAIM_TYPES:
                state.warning(f"invalid_claim_type={state.rel(path)}::{claim_type}")
            if evidence_type and evidence_type not in ALLOWED_EVIDENCE_TYPES:
                state.warning(f"invalid_evidence_type={state.rel(path)}::{evidence_type}")
            if confidence and confidence not in ALLOWED_CONFIDENCE_VALUES:
                state.warning(f"invalid_confidence={state.rel(path)}::{confidence}")
            if confidence == "confirmed" and not cell_has_evidence(evidence_source):
                state.warning(f"high_confidence_without_evidence={state.rel(path)}::{evidence_id}")
            if confidence == "confirmed" and cell_has_evidence(evidence_source):
                if claim_type == "behavioral" and evidence_type not in {"test", "runtime"}:
                    if not has_independent_evidence(evidence_type, evidence_source):
                        state.warning(
                            f"confirmed_behavioral_claim_needs_test_or_runtime={state.rel(path)}::{evidence_id}"
                        )
                elif claim_type == "historical" and evidence_type != "history":
                    state.warning(f"historical_claim_requires_history_evidence={state.rel(path)}::{evidence_id}")
                elif claim_type == "user_intent" and evidence_type != "user-confirmed":
                    state.warning(f"user_intent_claim_requires_user_confirmed_evidence={state.rel(path)}::{evidence_id}")
                elif claim_type == "architectural":
                    if evidence_type not in {"source", "configuration"} and not has_independent_evidence(
                        evidence_type, evidence_source
                    ):
                        state.warning(f"architectural_claim_needs_relation_evidence={state.rel(path)}::{evidence_id}")
                elif claim_type in {"structural", "configuration"}:
                    if not evidence_is_direct_for_claim(claim_type, evidence_type, evidence_source):
                        if not has_independent_evidence(evidence_type, evidence_source):
                            state.warning(f"confirmed_{claim_type}_claim_needs_direct_evidence={state.rel(path)}::{evidence_id}")
    if not evidence_rows:
        state.warning(f"comprehension_missing_evidence_row={state.rel(path)}")

    trace_section = markdown_section(text, "## 3. Domain-to-Code Trace Map")
    trace_has_rows = False
    if marker_reason(trace_section, NOT_APPLICABLE_PREFIX) is not None and not valid_marker_reason(
        trace_section, NOT_APPLICABLE_PREFIX
    ):
        state.warning(f"invalid_not_applicable_marker={state.rel(path)}::## 3. Domain-to-Code Trace Map")
    if marker_reason(trace_section, UNKNOWN_PREFIX) is not None and not unknown_marker_has_next_probe(trace_section):
        state.warning(f"unknown_marker_missing_next_probe={state.rel(path)}::## 3. Domain-to-Code Trace Map")
    for _, rows in markdown_tables(trace_section):
        trace_has_rows = trace_has_rows or bool(rows)
        for row in rows:
            trace_id = row.get("Trace ID") or row.get("ID") or "unknown"
            confidence = normalized_cell(row.get("Confidence"))
            if confidence and confidence not in ALLOWED_CONFIDENCE_VALUES:
                state.warning(f"invalid_confidence={state.rel(path)}::{confidence}")
            has_code_anchor = cell_has_evidence(row.get("Entry points")) or cell_has_evidence(row.get("Core implementation"))
            has_test_anchor = cell_has_evidence(row.get("Tests"))
            if not has_code_anchor and not has_test_anchor:
                state.warning(f"trace_missing_code_or_test_anchor={state.rel(path)}::{trace_id}")
    if not trace_has_rows and not valid_marker_reason(trace_section, NOT_APPLICABLE_PREFIX):
        state.warning(f"comprehension_missing_trace={state.rel(path)}")

    architecture_section = markdown_section(text, "## 5. Intended vs Implemented Architecture")
    architecture_has_rows = False
    if marker_reason(architecture_section, NOT_APPLICABLE_PREFIX) is not None and not valid_marker_reason(
        architecture_section, NOT_APPLICABLE_PREFIX
    ):
        state.warning(f"invalid_not_applicable_marker={state.rel(path)}::## 5. Intended vs Implemented Architecture")
    if marker_reason(architecture_section, UNKNOWN_PREFIX) is not None and not unknown_marker_has_next_probe(
        architecture_section
    ):
        state.warning(
            f"unknown_marker_missing_next_probe={state.rel(path)}::## 5. Intended vs Implemented Architecture"
        )
    for _, rows in markdown_tables(architecture_section):
        architecture_has_rows = architecture_has_rows or bool(rows)
        for row in rows:
            status = normalized_cell(row.get("Status"))
            if status and status not in ALLOWED_ARCHITECTURE_STATUSES:
                state.warning(f"invalid_architecture_status={state.rel(path)}::{status}")
    if not architecture_has_rows and not valid_marker_reason(architecture_section, NOT_APPLICABLE_PREFIX):
        state.warning(f"comprehension_missing_architecture={state.rel(path)}")

    hypothesis_section = markdown_section(text, "## 8. Open Hypotheses and Validation Probes")
    hypothesis_has_rows = False
    if marker_reason(hypothesis_section, NO_UNRESOLVED_HYPOTHESES_PREFIX) is not None and not valid_marker_reason(
        hypothesis_section, NO_UNRESOLVED_HYPOTHESES_PREFIX
    ):
        state.warning(f"invalid_no_unresolved_hypotheses_marker={state.rel(path)}")
    if marker_reason(hypothesis_section, UNKNOWN_PREFIX) is not None and not unknown_marker_has_next_probe(
        hypothesis_section
    ):
        state.warning(
            f"unknown_marker_missing_next_probe={state.rel(path)}::## 8. Open Hypotheses and Validation Probes"
        )
    for _, rows in markdown_tables(hypothesis_section):
        hypothesis_has_rows = hypothesis_has_rows or bool(rows)
        for row in rows:
            hypothesis_id = row.get("Hypothesis ID") or row.get("ID") or "unknown"
            confidence = normalized_cell(row.get("Confidence"))
            if confidence and confidence not in ALLOWED_CONFIDENCE_VALUES:
                state.warning(f"invalid_confidence={state.rel(path)}::{confidence}")
            if not cell_has_evidence(row.get("Next probe")):
                state.warning(f"open_hypothesis_missing_next_probe={state.rel(path)}::{hypothesis_id}")
    if not hypothesis_has_rows and not valid_marker_reason(hypothesis_section, NO_UNRESOLVED_HYPOTHESES_PREFIX):
        state.warning(f"comprehension_missing_hypothesis_or_marker={state.rel(path)}")


def validate_ledger_v2_rows(text: str, path: Path, state: ValidationState) -> None:
    section = markdown_section(text, "## 4. Sub-Plan Status Matrix")
    found_table = False
    active_rows: dict[str, str] = {}
    for headers, rows in markdown_tables(section):
        if not headers_match(headers, LEDGER_V2_STATUS_HEADERS):
            continue
        found_table = True
        for row in rows:
            subplan = row_value(row, "Sub-plan Path", "Sub-plan", "Sub-Plan Path")
            status = normalized_cell(row_value(row, "Status"))
            run_id = row_value(row, "Run ID")
            validation = row_value(row, "Validation Evidence", "Validation evidence")
            blocker = row_value(row, "Blocker")
            next_action = row_value(row, "Next Action")
            superseded_by = row_value(row, "Superseded By")

            if status not in ALLOWED_LEDGER_STATUSES:
                state.warning(f"invalid_ledger_status={state.rel(path)}::{status or 'missing'}")
                continue
            if subplan:
                resolved, reason = safe_subplan_path(state, subplan)
                if reason == "unsafe":
                    state.warning(f"unsafe_ledger_subplan_path={state.rel(path)}::{subplan}")
                elif reason == "missing":
                    state.warning(f"missing_ledger_subplan={state.rel(path)}::{subplan}")
                key = state.rel(resolved) if resolved is not None else subplan
                previous = active_rows.get(key)
                if previous and previous != status and status not in {"superseded"} and previous not in {"superseded"}:
                    state.warning(f"conflicting_ledger_status={state.rel(path)}::{key}::{previous},{status}")
                active_rows[key] = status

            if status == "in_progress" and not cell_has_evidence(run_id):
                state.warning(f"ledger_in_progress_missing_run_id={state.rel(path)}::{subplan or 'unknown'}")
            if status == "implemented" and not cell_has_evidence(validation):
                state.warning(f"ledger_implemented_missing_validation={state.rel(path)}::{subplan or 'unknown'}")
            if status == "verified" and not cell_has_evidence(validation):
                state.warning(f"ledger_verified_missing_validation={state.rel(path)}::{subplan or 'unknown'}")
            if status == "blocked":
                if not cell_has_evidence(blocker):
                    state.warning(f"ledger_blocked_missing_blocker={state.rel(path)}::{subplan or 'unknown'}")
                if not cell_has_evidence(next_action):
                    state.warning(f"ledger_blocked_missing_next_action={state.rel(path)}::{subplan or 'unknown'}")
            if status == "superseded" and not cell_has_evidence(superseded_by):
                state.warning(f"ledger_superseded_missing_target={state.rel(path)}::{subplan or 'unknown'}")
    if not found_table:
        state.warning(f"ledger_v2_status_matrix_missing_table={state.rel(path)}")


def validate_ledger_v3_rows(text: str, path: Path, state: ValidationState) -> None:
    section = markdown_section(text, "## 4. Sub-Plan Status Matrix")
    found_table = False
    active_rows: dict[str, tuple[str, str]] = {}
    for headers, rows in markdown_tables(section):
        if not headers_match(headers, LEDGER_V3_STATUS_HEADERS):
            continue
        found_table = True
        for row in rows:
            subplan = row_value(row, "Sub-plan Path", "Sub-plan", "Sub-Plan Path")
            planning_status = normalized_cell(row_value(row, "Planning Status"))
            execution_status = normalized_cell(row_value(row, "Execution Status"))
            run_id = row_value(row, "Run ID")
            planning_evidence = row_value(row, "Planning Evidence")
            implementation_evidence = row_value(row, "Implementation Evidence")
            blocker = row_value(row, "Blocker")
            next_action = row_value(row, "Next Action")
            superseded_by = row_value(row, "Superseded By")

            if planning_status not in ALLOWED_LEDGER_PLANNING_STATUSES:
                state.warning(f"invalid_ledger_planning_status={state.rel(path)}::{planning_status or 'missing'}")
            if execution_status not in ALLOWED_LEDGER_EXECUTION_STATUSES:
                state.warning(f"invalid_ledger_execution_status={state.rel(path)}::{execution_status or 'missing'}")
            if planning_status in {"audited", "approved"} and not cell_has_evidence(planning_evidence):
                state.warning(f"ledger_planning_status_missing_planning_evidence={state.rel(path)}::{subplan or 'unknown'}")
            if execution_status in {"implemented", "verified"} and not cell_has_evidence(implementation_evidence):
                state.warning(f"ledger_execution_status_missing_implementation_evidence={state.rel(path)}::{subplan or 'unknown'}")
            if execution_status == "in_progress" and not cell_has_evidence(run_id):
                state.warning(f"ledger_in_progress_missing_run_id={state.rel(path)}::{subplan or 'unknown'}")
            if execution_status == "blocked" or planning_status == "needs_repair":
                if not cell_has_evidence(blocker):
                    state.warning(f"ledger_blocked_missing_blocker={state.rel(path)}::{subplan or 'unknown'}")
                if not cell_has_evidence(next_action):
                    state.warning(f"ledger_blocked_missing_next_action={state.rel(path)}::{subplan or 'unknown'}")
            if "DEC-" in blocker and not cell_has_evidence(next_action):
                state.warning(f"ledger_decision_blocker_missing_next_action={state.rel(path)}::{subplan or 'unknown'}")
            if planning_status == "superseded" or execution_status == "superseded":
                if not cell_has_evidence(superseded_by):
                    state.warning(f"ledger_superseded_missing_target={state.rel(path)}::{subplan or 'unknown'}")

            if subplan:
                resolved, reason = safe_subplan_path(state, subplan)
                if reason == "unsafe":
                    state.warning(f"unsafe_ledger_subplan_path={state.rel(path)}::{subplan}")
                elif reason == "missing":
                    state.warning(f"missing_ledger_subplan={state.rel(path)}::{subplan}")
                key = state.rel(resolved) if resolved is not None else subplan
                previous = active_rows.get(key)
                current = (planning_status, execution_status)
                if previous and previous != current and "superseded" not in previous and "superseded" not in current:
                    state.warning(f"conflicting_ledger_status={state.rel(path)}::{key}::{previous},{current}")
                active_rows[key] = current
    if not found_table:
        state.warning(f"ledger_v3_status_matrix_missing_table={state.rel(path)}")


def validate_optional_continuity_docs(state: ValidationState) -> None:
    ontology_path = state.planner_docs / "Project-Ontology.md"
    ledger_path = state.planner_docs / "Planing-Ledger.md"

    ontology_exists = state.file_exists(ontology_path)
    ledger_exists = state.file_exists(ledger_path)
    state.metrics["ontology_exists"] = "true" if ontology_exists else "false"
    state.metrics["ledger_exists"] = "true" if ledger_exists else "false"
    state.metrics["comprehension_exists"] = "true" if state.file_exists("Planner-docs/Project-Comprehension.md") else "false"

    if ontology_exists:
        text = read_text(ontology_path, state)
        if text is not None:
            validate_artifact_frontmatter(text, ontology_path, state)
            validate_heading_order(text, ONTOLOGY_HEADINGS, ontology_path, state)
            validate_ontology_competency_questions(text, ontology_path, state)
            validate_ontology_provenance_tables(text, ontology_path, state)

    if ledger_exists:
        text = read_text(ledger_path, state)
        if text is not None:
            validate_artifact_frontmatter(text, ledger_path, state)
            headings = {item.text for item in markdown_headings(text)}
            has_v3 = all(heading in headings for heading in LEDGER_V3_HEADINGS)
            has_v2 = all(heading in headings for heading in LEDGER_V2_HEADINGS)
            has_legacy = all(heading in headings for heading in LEDGER_LEGACY_HEADINGS)
            if has_v3:
                state.metrics["ledger_schema"] = "v3"
                validate_heading_order(text, LEDGER_V3_HEADINGS, ledger_path, state)
                validate_ledger_v3_rows(text, ledger_path, state)
            elif has_v2:
                state.metrics["ledger_schema"] = "v2"
                validate_heading_order(text, LEDGER_V2_HEADINGS, ledger_path, state)
                validate_ledger_v2_rows(text, ledger_path, state)
                if state.mode == "step4" and state.strict:
                    state.error("ledger_v2_requires_v3_for_step4=Planner-docs/Planing-Ledger.md")
                else:
                    state.warning("legacy_ledger_schema_v2=Planner-docs/Planing-Ledger.md")
            elif has_legacy:
                state.metrics["ledger_schema"] = "legacy_v1"
                validate_heading_order(text, LEDGER_LEGACY_HEADINGS, ledger_path, state)
                if state.mode == "step4" and state.strict:
                    state.error("legacy_ledger_requires_v2_for_step4=Planner-docs/Planing-Ledger.md")
                else:
                    state.warning("legacy_ledger_schema=Planner-docs/Planing-Ledger.md")
            else:
                state.metrics["ledger_schema"] = "unknown"
                validate_heading_order(text, LEDGER_V2_HEADINGS, ledger_path, state)

    validate_optional_comprehension_doc(state)


def all_tables_for_heading(text: str, heading: str) -> list[tuple[list[str], list[dict[str, str]]]]:
    return markdown_tables(markdown_section(text, heading))


def meaningful_rationale(value: str) -> bool:
    lowered = value.lower().strip()
    if len(lowered) < 40:
        return False
    generic = {"because consistent", "same count", "standard template", "n/a", "none", "unknown"}
    return not any(item == lowered for item in generic)


def has_uniform_subplan_count_rationale(index_text: str) -> bool:
    for line in index_text.splitlines():
        if "uniform_subplan_count_justification" in line.lower():
            return meaningful_rationale(line.split(":", 1)[1] if ":" in line else line)
        if "uniform sub-plan count rationale" in line.lower():
            return meaningful_rationale(line.split(":", 1)[1] if ":" in line else line)
    return False


def phase_number_from_value(value: str) -> int | None:
    match = re.search(r"\d+", value)
    return int(match.group(0)) if match else None


def validate_deferred_cards(state: ValidationState, index_text: str, deferred_phases: set[int]) -> None:
    section = markdown_section(index_text, "## 9. Out-of-Scope or Deferred Topics")
    card_phases: set[int] = set()
    found_table = False
    for headers, rows in markdown_tables(section):
        if not headers_match(headers, DEFERRED_CARD_HEADERS):
            continue
        found_table = True
        for row in rows:
            phase = phase_number_from_value(row_value(row, "Phase"))
            if phase is None:
                state.warning("deferred_card_missing_phase=Planner-docs/Sub-Planing-Index.md")
                continue
            card_phases.add(phase)
            status = normalized_cell(row_value(row, "Status"))
            if status != "deferred":
                state.warning(f"deferred_card_invalid_status=Faz-{phase}::{status or 'missing'}")
            for column in ("Deferral Reason", "Activation Trigger", "Earliest Wave"):
                if not cell_has_evidence(row_value(row, column)):
                    state.warning(f"deferred_card_missing_{canonical_header(column)}=Faz-{phase}")
    if deferred_phases and not found_table:
        state.warning("deferred_cards_table_missing=Planner-docs/Sub-Planing-Index.md")
    for phase in sorted(deferred_phases - card_phases):
        state.warning(f"missing_deferred_card=Faz-{phase}")
    for phase in sorted(card_phases - deferred_phases):
        state.warning(f"deferred_card_phase_not_in_manifest=Faz-{phase}")


def validate_execution_waves(state: ValidationState, index_text: str, active_refs: set[str]) -> None:
    section = markdown_section(index_text, "## 5. Execution Waves")
    refs: list[str] = []
    for match in INDEX_REF_RE.finditer(section):
        ref = match.group(0)
        if ref.startswith("./"):
            ref = ref[2:]
        if not ref.startswith("Planner-docs/"):
            ref = f"Planner-docs/{ref}"
        refs.append(ref)
    ref_set = set(refs)
    if active_refs and not refs:
        state.warning("execution_waves_missing_active_subplans=Planner-docs/Sub-Planing-Index.md")
        return
    for ref in sorted(active_refs - ref_set):
        state.warning(f"execution_waves_missing_subplan={ref}")
    for ref in sorted(ref_set - active_refs):
        state.warning(f"execution_waves_non_active_subplan={ref}")
    for ref in sorted(ref for ref in ref_set if refs.count(ref) > 1):
        state.warning(f"execution_waves_duplicate_subplan={ref}")


def validate_parent_traceability(
    state: ValidationState,
    index_text: str,
    index_path: Path,
    known_parent_signals: set[str],
    active_refs: set[str],
) -> None:
    section = markdown_section(index_text, "## 6. Parent Acceptance Traceability")
    covered_refs: set[str] = set()
    found_table = False
    for headers, rows in markdown_tables(section):
        if not headers_match(headers, PARENT_TRACE_HEADERS):
            continue
        found_table = True
        for row in rows:
            signal = row_value(row, "Parent Signal").upper()
            covered_by = row_value(row, "Covered By")
            command = row_value(row, "Validation Command")
            status = normalized_cell(row_value(row, "Status"))
            if not PARENT_SIGNAL_RE.fullmatch(signal):
                state.warning(f"parent_trace_invalid_signal={state.rel(index_path)}::{signal or 'missing'}")
            elif known_parent_signals and signal not in known_parent_signals:
                state.warning(f"parent_trace_unknown_signal={state.rel(index_path)}::{signal}")
            resolved, reason = safe_subplan_path(state, covered_by)
            if reason:
                state.warning(f"parent_trace_invalid_subplan={state.rel(index_path)}::{covered_by or 'missing'}")
            elif resolved is not None:
                covered_refs.add(state.rel(resolved))
            if not exact_validation_command(command):
                state.warning(f"parent_trace_invalid_validation_command={state.rel(index_path)}::{signal or 'unknown'}")
            if not cell_has_evidence(status):
                state.warning(f"parent_trace_missing_status={state.rel(index_path)}::{signal or 'unknown'}")
    if active_refs and not found_table:
        state.warning(f"parent_traceability_table_missing={state.rel(index_path)}")
    for ref in sorted(active_refs - covered_refs):
        state.warning(f"parent_trace_missing_active_subplan={ref}")


def validate_decision_register(state: ValidationState, index_text: str, index_path: Path) -> set[str]:
    section = markdown_section(index_text, "## 7. Decision Register")
    seen: set[str] = set()
    found_table = False
    for headers, rows in markdown_tables(section):
        if not headers_match(headers, DECISION_REGISTER_HEADERS):
            continue
        found_table = True
        for row in rows:
            decision_id = row_value(row, "Decision ID")
            status = normalized_cell(row_value(row, "Status"))
            next_action = row_value(row, "Next Action")
            if not re.fullmatch(r"DEC-\d{3}", decision_id):
                state.warning(f"decision_register_invalid_id={state.rel(index_path)}::{decision_id or 'missing'}")
            elif decision_id in seen:
                state.warning(f"decision_register_duplicate_id={state.rel(index_path)}::{decision_id}")
            else:
                seen.add(decision_id)
            if status not in ALLOWED_DECISION_STATUSES:
                state.warning(f"decision_register_invalid_status={state.rel(index_path)}::{status or 'missing'}")
            if status in {"open", "blocked"} and not cell_has_evidence(next_action):
                state.warning(f"decision_register_missing_next_action={state.rel(index_path)}::{decision_id or 'unknown'}")
    if not found_table:
        state.warning(f"decision_register_table_missing={state.rel(index_path)}")
    return seen


def validate_decision_references(state: ValidationState, subplan_texts: list[str], decision_ids: set[str]) -> None:
    referenced = {match.group(0) for text in subplan_texts for match in re.finditer(r"\bDEC-\d{3}\b", text)}
    for decision_id in sorted(referenced - decision_ids):
        state.warning(f"decision_reference_missing_register_entry={decision_id}")


def validate_framework_matrix_rows(state: ValidationState, index_path: Path, headers: list[str], rows: list[dict[str, str]]) -> int:
    if not headers_match(headers, FRAMEWORK_MATRIX_HEADERS):
        return 0
    valid_rows = 0
    seen_capabilities: set[str] = set()
    for row in rows:
        capability = row_value(row, "Capability")
        external_owns = row_value(row, "External Framework Owns")
        project_owns = row_value(row, "Project Owns")
        wrapper = row_value(row, "Wrapper Boundary")
        validation = row_value(row, "Validation")
        row_id = capability or "unknown"
        if not cell_has_evidence(capability):
            state.warning(f"framework_matrix_missing_capability={state.rel(index_path)}::{row_id}")
            continue
        normalized_capability = normalize_semantic_sentence(capability)
        if normalized_capability in seen_capabilities:
            state.warning(f"framework_matrix_duplicate_capability={state.rel(index_path)}::{capability}")
        seen_capabilities.add(normalized_capability)
        missing_columns = [
            name
            for name, value in [
                ("externalframeworkowns", external_owns),
                ("projectowns", project_owns),
                ("wrapperboundary", wrapper),
                ("validation", validation),
            ]
            if not cell_has_evidence(value)
        ]
        for column in missing_columns:
            state.warning(f"framework_matrix_missing_{column}={state.rel(index_path)}::{capability}")
        if wrapper and implementation_surface_path(wrapper) is None:
            state.warning(f"framework_matrix_invalid_wrapper_boundary={state.rel(index_path)}::{capability}")
        if validation and not validation_probe_is_safe(validation):
            state.warning(f"framework_matrix_invalid_validation={state.rel(index_path)}::{capability}")
        if not missing_columns and wrapper and validation and implementation_surface_path(wrapper) is not None and validation_probe_is_safe(validation):
            valid_rows += 1
    return valid_rows


def validate_invariant_register_rows(state: ValidationState, index_path: Path, headers: list[str], rows: list[dict[str, str]]) -> int:
    if not headers_match(headers, ALGORITHMIC_INVARIANT_HEADERS):
        return 0
    valid_rows = 0
    seen_ids: set[str] = set()
    for row in rows:
        invariant_id = row_value(row, "Invariant ID")
        scope = row_value(row, "Scope")
        condition = row_value(row, "Required Condition")
        risk = row_value(row, "Violation Risk")
        probe = row_value(row, "Validation Probe")
        row_id = invariant_id or "missing"
        if not re.fullmatch(r"INV-\d{3}", invariant_id):
            state.warning(f"algorithmic_invariant_invalid_id={state.rel(index_path)}::{row_id}")
        elif invariant_id in seen_ids:
            state.warning(f"algorithmic_invariant_duplicate_id={state.rel(index_path)}::{invariant_id}")
        else:
            seen_ids.add(invariant_id)
        for column, value in [
            ("scope", scope),
            ("requiredcondition", condition),
            ("violationrisk", risk),
            ("validationprobe", probe),
        ]:
            if not cell_has_evidence(value):
                state.warning(f"algorithmic_invariant_missing_{column}={state.rel(index_path)}::{row_id}")
        if probe and not validation_probe_is_safe(probe):
            state.warning(f"algorithmic_invariant_invalid_validation_probe={state.rel(index_path)}::{row_id}")
        if (
            re.fullmatch(r"INV-\d{3}", invariant_id)
            and all(cell_has_evidence(value) for value in [scope, condition, risk, probe])
            and validation_probe_is_safe(probe)
        ):
            valid_rows += 1
    return valid_rows


def validate_framework_and_invariant_guidance(
    state: ValidationState,
    main_text: str,
    index_text: str,
    subplan_texts: list[str],
) -> None:
    planning_text = "\n".join([main_text, index_text, *subplan_texts]).lower()
    framework_terms = ("trl", "vllm", "peft", "langchain", "llamaindex", "django", "fastapi", "next.js", "react")
    if any(term in planning_text for term in framework_terms):
        framework_section = markdown_section(index_text, "### Framework Ownership Matrix")
        if not framework_section:
            state.warning("framework_ownership_matrix_missing=Planner-docs/Sub-Planing-Index.md")
        else:
            valid_rows = sum(
                validate_framework_matrix_rows(state, state.planner_docs / "Sub-Planing-Index.md", headers, rows)
                for headers, rows in markdown_tables(framework_section)
            )
            if valid_rows == 0:
                state.warning("framework_ownership_matrix_table_missing=Planner-docs/Sub-Planing-Index.md")

    invariant_terms = (
        r"\bgrpo\b",
        r"\brl\b",
        r"\bonline learning\b",
        r"\brollout group\b",
        r"\bpolicy fingerprint\b",
        r"\btrainer-step\b",
        r"\bstateful\b",
        r"\bdistributed\b",
    )
    if any(re.search(term, planning_text) for term in invariant_terms):
        invariant_section = markdown_section(index_text, "### Algorithmic Invariant Register")
        if not invariant_section:
            state.warning("algorithmic_invariant_register_missing=Planner-docs/Sub-Planing-Index.md")
        else:
            valid_rows = sum(
                validate_invariant_register_rows(state, state.planner_docs / "Sub-Planing-Index.md", headers, rows)
                for headers, rows in markdown_tables(invariant_section)
            )
            if valid_rows == 0:
                state.warning("algorithmic_invariant_register_table_missing=Planner-docs/Sub-Planing-Index.md")


def validate_index(state: ValidationState) -> tuple[set[str], dict[str, object]]:
    index_path = state.planner_docs / "Sub-Planing-Index.md"
    text = read_text(index_path, state)
    if text is None:
        state.metrics["index_reference_count"] = 0
        return set(), {}

    validate_artifact_frontmatter(text, index_path, state)
    validate_heading_order(text, INDEX_HEADINGS, index_path, state)
    manifest = parse_scope_manifest(text, index_path, state)
    refs = set()
    for match in INDEX_REF_RE.finditer(text):
        ref = match.group(0)
        if ref.startswith("./"):
            ref = ref[2:]
        if not ref.startswith("Planner-docs/"):
            ref = f"Planner-docs/{ref}"
        refs.add(ref)
    state.metrics["index_reference_count"] = len(refs)
    return refs, manifest


def validate_subplan_structure(
    state: ValidationState,
    phase: int | None,
    subphase: int | None,
    path: Path,
    repeated_bodies: dict[str, list[str]],
    repeated_sentences: dict[str, list[str]],
    normalized_sentences: dict[str, list[str]],
    active: bool,
    known_parent_signals: set[str],
) -> None:
    text = read_text(path, state)
    if text is None:
        return

    if active:
        validate_artifact_frontmatter(text, path, state)

    h1_match = H1_SUBPLAN_RE.search(text)
    if not h1_match:
        state.error(f"missing_or_invalid_h1={state.rel(path)}")
    else:
        h1_phase = int(h1_match.group(1))
        h1_subphase = int(h1_match.group(2))
        if phase is not None and h1_phase != phase:
            state.error(f"h1_phase_mismatch={state.rel(path)}::h1={h1_phase}::file={phase}")
        if subphase is not None and h1_subphase != subphase:
            state.error(f"h1_subphase_mismatch={state.rel(path)}::h1={h1_subphase}::file={subphase}")

    validate_heading_order(text, SUBPLAN_HEADINGS, path, state)

    headings = SECTION_RE.findall(text)
    for required in SUBPLAN_HEADINGS:
        count = headings.count(required)
        if count > 1:
            state.error(f"duplicate_heading={state.rel(path)}::{required}::{count}")
        body = section_body(text, required)
        if required in text and len(body) < 20:
            state.error(f"empty_or_too_short_section={state.rel(path)}::{required}")
        for pattern_name, pattern in PLACEHOLDER_PATTERNS:
            if pattern.search(body):
                state.warning(f"placeholder_text={state.rel(path)}::{required}::pattern={pattern_name}")

    for heading in ("## 3. Description", "## 7. Planned Work Breakdown"):
        body = normalized_body(section_body(text, heading))
        if len(body) >= 160:
            repeated_bodies[f"{heading}:{body}"].append(state.rel(path))

    for heading in (
        "## 3. Description",
        "## 6. Current Repository Evidence",
        "## 8. Acceptance Criteria",
        "## 11. Risks and Mitigations",
    ):
        add_repeated_sentence_candidates(state, path, section_body(text, heading), repeated_sentences)
        add_normalized_duplicate_candidates(state, path, section_body(text, heading), normalized_sentences)

    if active:
        validate_implementation_ready_subplan(state, path, text, known_parent_signals)


def validate_step2(state: ValidationState) -> None:
    main_phases = validate_step1(state)
    main_text = read_text(state.planner_docs / "Main-Planing.md", state) or ""
    validate_autopsy_optional(state)
    validate_optional_continuity_docs(state)
    index_refs, manifest = validate_index(state)
    index_path = state.planner_docs / "Sub-Planing-Index.md"
    index_text = read_text(index_path, state) or ""
    known_parent_signals = parent_signal_ids(main_text)
    folders = collect_phase_folders(state)
    subplans = collect_subplans(state)

    state.metrics["phase_folder_count"] = len(folders)
    state.metrics["subplan_count"] = len([item for item in subplans if item[1] is not None])
    mode = str(manifest.get("planning_mode", "")) if manifest else ""
    active_phases = set(manifest.get("active_phases", []) or [])
    deferred_phases = set(manifest.get("deferred_phases", []) or [])
    if not active_phases:
        active_phases = set(main_phases)
    if mode == "full":
        active_phases = set(main_phases)
        if deferred_phases:
            state.warning("full_mode_has_deferred_phases=Planner-docs/Sub-Planing-Index.md")
    state.metrics["planning_mode"] = mode or "legacy"
    state.metrics["active_phase_count"] = len(active_phases)
    state.metrics["deferred_phase_count"] = len(deferred_phases)

    main_phase_set = set(main_phases)
    manifest_phase_set = active_phases | deferred_phases
    if mode and main_phase_set:
        missing_manifest_phases = main_phase_set - manifest_phase_set
        for phase in sorted(missing_manifest_phases):
            state.warning(f"planning_scope_missing_main_phase=Faz-{phase}")
    unknown_manifest_phases = manifest_phase_set - main_phase_set
    for phase in sorted(unknown_manifest_phases):
        state.warning(f"planning_scope_phase_not_in_main_plan=Faz-{phase}")
    if active_phases & deferred_phases:
        overlap = ",".join(str(item) for item in sorted(active_phases & deferred_phases))
        state.warning(f"planning_scope_active_deferred_overlap={overlap}")

    if main_phases:
        for phase in sorted(active_phases):
            if phase not in folders:
                state.error(f"missing_phase_folder=Planner-docs/Faz-{phase}-Plans")
        for phase in sorted(folders):
            if phase not in main_phases:
                state.warning(f"extra_phase_folder_without_main_phase=Planner-docs/Faz-{phase}-Plans")
            if phase in deferred_phases:
                state.warning(f"deferred_phase_has_detailed_folder=Planner-docs/Faz-{phase}-Plans")

    actual_refs = {state.rel(path) for _, subphase, path in subplans if subphase is not None}
    active_actual_refs = {
        state.rel(path)
        for phase, subphase, path in subplans
        if subphase is not None and phase in active_phases
    }
    for ref in sorted(actual_refs - index_refs):
        state.error(f"unindexed_subplan={ref}")
    for ref in sorted(index_refs - actual_refs):
        state.error(f"missing_index_target={ref}")

    max_detailed = manifest.get("max_detailed_subplans") if manifest else None
    if isinstance(max_detailed, int) and len(active_actual_refs) > max_detailed:
        state.warning(f"planning_scope_exceeds_max_detailed_subplans={len(active_actual_refs)}>{max_detailed}")

    active_word_count = 0
    active_subplan_texts: list[str] = []
    for phase, subphase, path in subplans:
        if subphase is None or phase not in active_phases:
            continue
        text = read_text(path, state) or ""
        active_subplan_texts.append(text)
        active_word_count += len(re.findall(r"\S+", text))
    max_words = manifest.get("max_output_words") if manifest else None
    if isinstance(max_words, int) and active_word_count > max_words:
        state.warning(f"planning_scope_exceeds_max_output_words={active_word_count}>{max_words}")

    validate_deferred_cards(state, index_text, deferred_phases)
    validate_execution_waves(state, index_text, active_actual_refs)
    validate_parent_traceability(state, index_text, index_path, known_parent_signals, active_actual_refs)
    decision_ids = validate_decision_register(state, index_text, index_path)
    validate_decision_references(state, active_subplan_texts, decision_ids)
    validate_framework_and_invariant_guidance(state, main_text, index_text, active_subplan_texts)

    seen: set[tuple[int, int]] = set()
    per_phase: dict[int, list[int]] = defaultdict(list)
    repeated_bodies: dict[str, list[str]] = defaultdict(list)
    repeated_sentences: dict[str, list[str]] = defaultdict(list)
    normalized_sentences: dict[str, list[str]] = defaultdict(list)

    for phase, subphase, path in subplans:
        if phase is None or subphase is None:
            continue
        key = (phase, subphase)
        if key in seen:
            state.error(f"duplicate_subplan_number=Faz{phase}.{subphase}")
        seen.add(key)
        per_phase[phase].append(subphase)
        validate_subplan_structure(
            state,
            phase,
            subphase,
            path,
            repeated_bodies,
            repeated_sentences,
            normalized_sentences,
            phase in active_phases,
            known_parent_signals,
        )

    for phase, folder in sorted(folders.items()):
        numbers = sorted(per_phase.get(phase, []))
        if phase not in active_phases:
            continue
        if not numbers:
            state.error(f"phase_has_no_subplans={state.rel(folder)}")
            continue
        expected = list(range(1, max(numbers) + 1))
        if numbers != expected:
            state.error(f"subplan_numbering_gap=Faz{phase}::expected={expected}::actual={numbers}")

    for key, paths in sorted(repeated_bodies.items()):
        if len(paths) >= 3:
            heading = key.split(":", 1)[0]
            joined = ",".join(paths)
            state.warning(f"repeated_section_body={heading}::files={joined}")

    for sentence, paths in sorted(repeated_sentences.items()):
        if len(paths) >= REPEATED_SENTENCE_MIN_COUNT:
            preview = sentence[:120].replace("=", "-")
            joined = ",".join(paths[:10])
            state.warning(f"repeated_boilerplate_sentence=count:{len(paths)}::text={preview}::files={joined}")

    total_normalized = sum(len(paths) for paths in normalized_sentences.values())
    duplicate_normalized = sum(len(paths) - 1 for paths in normalized_sentences.values() if len(paths) > 1)
    ratio = (duplicate_normalized / total_normalized) if total_normalized else 0.0
    state.metrics["normalized_duplicate_ratio"] = f"{ratio:.2f}"
    if len(active_actual_refs) >= 3 and ratio > NORMALIZED_DUPLICATE_WARNING_RATIO:
        if state.strict:
            state.error(f"normalized_duplicate_ratio_too_high={ratio:.2f}")
        else:
            state.warning(f"normalized_duplicate_ratio_high={ratio:.2f}")
        if ratio > NORMALIZED_DUPLICATE_STRICT_FAILURE_RATIO:
            state.warning(f"normalized_duplicate_ratio_high_risk={ratio:.2f}")

    active_counts = [len(per_phase.get(phase, [])) for phase in sorted(active_phases) if len(per_phase.get(phase, [])) > 0]
    has_uniform_rationale = has_uniform_subplan_count_rationale(index_text)
    if len(active_counts) >= 3 and len(set(active_counts)) == 1 and not has_uniform_rationale:
        state.warning(f"uniform_subplan_count_anomaly=count:{active_counts[0]}::phases:{len(active_counts)}")


def validate_step3_preflight(state: ValidationState) -> None:
    validate_step2(state)
    audit_path = state.planner_docs / "Sub-Planing-Audit.md"
    audit_exists = state.file_exists(audit_path)
    state.metrics["audit_exists"] = "true" if audit_exists else "false"
    if state.mode == "all" and not audit_exists:
        state.error("missing_file=Planner-docs/Sub-Planing-Audit.md")
    if audit_exists:
        text = read_text(audit_path, state)
        if text is not None:
            validate_heading_order(text, AUDIT_HEADINGS, audit_path, state)


def extract_audit_status(text: str) -> str | None:
    status_pattern = re.compile(
        r"(?:overall audit status|audit status|final status|status|denetim durumu|nihai durum)"
        r"\s*[:：-]\s*(PASS_WITH_WARNINGS|BLOCKED|PASS)\b",
        re.IGNORECASE,
    )
    match = status_pattern.search(text)
    if match:
        return match.group(1).upper()

    for line in text.splitlines():
        stripped = line.strip(" -*`|:")
        if stripped in {"PASS", "PASS_WITH_WARNINGS", "BLOCKED"}:
            return stripped
    return None


def count_audit_severities(text: str) -> dict[str, int]:
    fix_section = markdown_section(text, "## 13. Priority Fix List")
    counts = {severity: 0 for severity in ("P0", "P1", "P2", "P3")}
    for _, severity in AUDIT_FIX_RE.findall(fix_section):
        counts[severity] += 1
    return counts


def parse_audit_findings(text: str, path: Path, state: ValidationState) -> list[dict[str, str]]:
    fix_section = markdown_section(text, "## 13. Priority Fix List")
    findings: list[dict[str, str]] = []
    for headers, rows in markdown_tables(fix_section):
        if not headers_match(headers, FINDING_HEADERS):
            continue
        for row in rows:
            finding_id = row_value(row, "Finding ID")
            severity = row_value(row, "Severity").upper()
            status = normalized_cell(row_value(row, "Status")) or "open"
            if not finding_id.startswith("AUDIT-FIX-"):
                continue
            if severity not in {"P0", "P1", "P2", "P3"}:
                state.error(f"invalid_finding_severity={state.rel(path)}::{finding_id}::{severity or 'missing'}")
            if status not in ALLOWED_FINDING_STATUSES:
                state.error(f"invalid_finding_status={state.rel(path)}::{finding_id}::{status or 'missing'}")
            findings.append(
                {
                    "id": finding_id,
                    "severity": severity,
                    "status": status,
                    "affected_files": row_value(row, "Affected Files"),
                }
            )
    if findings:
        return findings

    for finding_id, severity in AUDIT_FIX_RE.findall(fix_section):
        findings.append({"id": finding_id, "severity": severity, "status": "open", "affected_files": ""})
    return findings


def active_severity_counts(findings: list[dict[str, str]]) -> dict[str, int]:
    counts = {severity: 0 for severity in ("P0", "P1", "P2", "P3")}
    for finding in findings:
        severity = finding.get("severity", "")
        status = finding.get("status", "")
        if severity in counts and status in OPEN_FINDING_STATUSES:
            counts[severity] += 1
    return counts


def parse_readiness_rows(text: str, path: Path, state: ValidationState) -> list[dict[str, str]]:
    section = markdown_section(text, "## 12. Step 4 Readiness Assessment")
    for headers, rows in markdown_tables(section):
        if headers_match(headers, READINESS_HEADERS):
            return rows
    state.error(f"audit_readiness_table_missing={state.rel(path)}")
    return []


def validate_audit_section_depth(text: str, path: Path, state: ValidationState) -> None:
    for heading in AUDIT_HEADINGS:
        if heading == "# Sub-Planing Audit":
            continue
        body = markdown_section(text, heading)
        if len(body) < 20:
            state.error(f"empty_or_too_short_audit_section={state.rel(path)}::{heading}")


def validate_readiness_rows(
    rows: list[dict[str, str]],
    path: Path,
    state: ValidationState,
    findings: list[dict[str, str]],
) -> None:
    by_id = {finding.get("id", ""): finding for finding in findings}
    seen: dict[str, str] = {}
    ready_count = 0
    terminal_count = 0

    if not rows:
        state.metrics["execution_queue_state"] = "BLOCKED"
        return

    for row in rows:
        subplan = row_value(row, "Sub-Plan Path", "Sub-plan Path", "Subplan Path")
        status = row_value(row, "Status").upper()
        finding_ids = row_value(row, "Finding IDs", "Finding ID")
        dependency = normalized_cell(row_value(row, "Dependency State"))

        if status not in ALLOWED_READINESS_STATUSES:
            state.error(f"invalid_readiness_status={state.rel(path)}::{status or 'missing'}")
        if dependency not in ALLOWED_DEPENDENCY_STATES:
            state.error(f"invalid_dependency_state={state.rel(path)}::{dependency or 'missing'}")

        resolved, reason = safe_subplan_path(state, subplan)
        if reason == "unsafe":
            state.error(f"unsafe_subplan_path={state.rel(path)}::{subplan}")
            key = subplan
        elif reason == "missing":
            state.error(f"missing_readiness_subplan={subplan}")
            key = subplan
        else:
            key = state.rel(resolved) if resolved is not None else subplan

        previous = seen.get(key)
        if previous and previous != status:
            state.error(f"conflicting_readiness_status={key}::{previous},{status}")
        seen[key] = status

        if status in READY_READINESS_STATUSES:
            ready_count += 1
            if dependency not in {"satisfied", "independent"}:
                state.error(f"ready_row_has_blocked_dependency={key}::{dependency}")
        elif status in COMPLETED_READINESS_STATUSES:
            terminal_count += 1

        ids = [item.strip() for item in re.split(r"[,; ]+", finding_ids) if item.strip() and item.strip().lower() != "none"]
        if status == "READY_WITH_WARNINGS":
            for finding_id in ids:
                finding = by_id.get(finding_id)
                if finding and finding.get("status") in OPEN_FINDING_STATUSES and finding.get("severity") in {"P0", "P1"}:
                    state.error(f"ready_with_warnings_references_blocking_finding={key}::{finding_id}")

    if ready_count:
        state.metrics["execution_queue_state"] = "READY"
    elif terminal_count == len(rows):
        state.metrics["execution_queue_state"] = "NO_ACTION_REQUIRED"
    else:
        state.metrics["execution_queue_state"] = "BLOCKED"


def validate_audit_required(state: ValidationState, require_readiness: bool) -> None:
    audit_path = state.planner_docs / "Sub-Planing-Audit.md"
    text = read_text(audit_path, state)
    if text is None:
        state.metrics["audit_status"] = "missing"
        return

    validate_heading_order(text, AUDIT_HEADINGS, audit_path, state)
    validate_audit_section_depth(text, audit_path, state)

    status = extract_audit_status(text)
    state.metrics["audit_status"] = status or "unknown"
    if status is None:
        state.error("audit_status_missing=Planner-docs/Sub-Planing-Audit.md")
    elif status == "BLOCKED":
        state.error("step4_blocked_by_audit_status=BLOCKED")

    findings = parse_audit_findings(text, audit_path, state)
    severity_counts = active_severity_counts(findings)
    for severity, count in severity_counts.items():
        state.metrics[f"{severity.lower()}_findings"] = count
    if severity_counts["P0"] or severity_counts["P1"]:
        state.error(
            f"step4_blocked_by_high_severity_findings=P0:{severity_counts['P0']},P1:{severity_counts['P1']}"
        )
    if status == "PASS" and (severity_counts["P2"] or severity_counts["P3"]):
        state.error(f"audit_status_inconsistent_with_open_warnings=PASS::P2:{severity_counts['P2']},P3:{severity_counts['P3']}")
    if status == "PASS_WITH_WARNINGS" and (severity_counts["P2"] or severity_counts["P3"]):
        state.warning(
            f"step4_has_nonblocking_warnings=P2:{severity_counts['P2']},P3:{severity_counts['P3']}"
        )
    elif status == "PASS_WITH_WARNINGS" and not (severity_counts["P0"] or severity_counts["P1"]):
        state.warning("audit_status_has_no_open_warnings=PASS_WITH_WARNINGS")

    if require_readiness:
        rows = parse_readiness_rows(text, audit_path, state)
        validate_readiness_rows(rows, audit_path, state, findings)


def validate_step3_post_audit(state: ValidationState) -> None:
    validate_step3_preflight(state)
    validate_audit_required(state, require_readiness=False)


def validate_step4_readiness(state: ValidationState) -> None:
    validate_step3_preflight(state)
    validate_audit_required(state, require_readiness=True)


def scan_secrets(state: ValidationState) -> None:
    secret_findings = 0
    profile = "step3" if state.directory_exists("Planner-docs") else "intake"
    try:
        paths = state.regular_paths(profile)
    except (OSError, TypeError, ValueError) as exc:
        state.error(f"repository_secret_scan_failed={str(exc).split('=', 1)[0]}")
        state.metrics["secret_findings"] = 0
        return
    for relative in paths:
        path = state.root / relative
        text = read_text(path, state)
        if text is None:
            continue
        for name, offset in secret_match_locations(text):
            secret_findings += 1
            line = text.count("\n", 0, offset) + 1
            state.error(f"secret_pattern={name}::{state.rel(path)}:{line}")
    state.metrics["secret_findings"] = secret_findings


def finalize(state: ValidationState) -> int:
    if state.strict:
        for warning in state.warnings:
            if warning.startswith("legacy_ledger_schema=") and state.mode != "step4":
                continue
            if warning.startswith("legacy_ledger_schema_v2=") and state.mode != "step4":
                continue
            state.errors.append(f"strict_warning={warning}")

    state.metrics["warning_count"] = len(state.warnings)
    state.metrics["error_count"] = len(state.errors)

    status = "failed" if state.errors else "passed"
    print(f"planner_docs_validation={status}")
    print(f"validation_status={status}")
    print(f"mode={state.mode}")
    print(f"validation_mode={state.mode}")
    print(f"root={safe_log_text(state.root)}")
    for key in sorted(state.metrics):
        print(f"{key}={state.metrics[key]}")
    for warning in sorted(state.warnings):
        print(f"warning={safe_log_text(warning)}")
    for error in sorted(state.errors):
        print(f"error={safe_log_text(error)}")
    if any(error.startswith(("unknown_mode=", "read_error=", "non_utf8_file=")) for error in state.errors):
        return 2
    return 1 if state.errors else 0


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate CodexQB Planner-docs outputs.")
    parser.add_argument("--root", default=".", help="Project root containing Planner-docs/; default: current directory.")
    parser.add_argument(
        "--mode",
        choices=("step1", "autopsy", "step2", "step3-preflight", "step3", "step4", "all"),
        default="all",
        help="Validation scope.",
    )
    parser.add_argument("--strict", action="store_true", help="Treat quality warnings as failures.")
    return parser.parse_args(argv)


def run_validation(root: Path, mode: str, strict: bool = False) -> int:
    try:
        with open_repository_io(root) as repository:
            state = ValidationState(
                root=canonical_repository_root(repository),
                mode=mode,
                strict=strict,
                repository=repository,
            )

            if mode == "step1":
                validate_step1(state)
            elif mode == "autopsy":
                validate_step1(state)
                validate_autopsy_required(state)
                validate_optional_continuity_docs(state)
            elif mode == "step2":
                validate_step2(state)
            elif mode == "step3-preflight":
                validate_step3_preflight(state)
            elif mode == "step3":
                validate_step3_post_audit(state)
            elif mode == "all":
                validate_step3_post_audit(state)
            elif mode == "step4":
                validate_step4_readiness(state)
            else:
                state.error(f"unknown_mode={mode}")

            scan_secrets(state)
            return finalize(state)
    except (OSError, TypeError, ValueError) as exc:
        reason = str(exc).split("=", 1)[0].split(":", 1)[0]
        print("planner_docs_validation=failed")
        print("validation_status=failed")
        print(f"mode={mode}")
        print(f"error=repository_io_failed={safe_log_text(reason)}")
        return 2


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    return run_validation(Path(args.root), args.mode, args.strict)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
