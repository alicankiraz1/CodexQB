# CodexQB Subagent Playbook

Use subagents when they reduce context pollution, improve parallel evidence gathering, or separate implementation from review.

Do **not** use subagents for small, obvious, single-file planning tasks.

## Default Rule

The parent CodexQB agent owns the official artifact write.

Subagents may gather evidence, draft options, audit sections, or review changes. They should not write `Planner-docs/` artifacts directly unless the user explicitly asks for that behavior.

## Recommended Subagent Roles

### repo_explorer

Read-only. Maps repository structure, modules, ownership boundaries, tests, CI, docs, and key files. Returns file-path evidence.

### readiness_auditor

Read-only. Checks docs vs implementation, local vs live readiness, smoke vs production claims, and operational gaps.

### security_reviewer

Read-only by default. Checks secret safety, command execution risk, approval gates, insecure defaults, dependency risk, and external mutation boundaries.

### ontology_mapper

Read-only. Extracts domain vocabulary, entities, workflows, module boundaries, invariants, integrations, and open concept questions.

### structure_mapper

Read-only. Maps entrypoints, modules, tests, CI, persistence, deployment/runtime surfaces, and likely ownership boundaries for Step 1.5 comprehension.

### concept_trace_mapper

Read-only. Maps domain concepts or features to entrypoints, core implementation, state/data, tests, docs, and uncertainty using `TRACE-*` evidence.

### behavior_evidence_auditor

Read-only unless explicitly asked otherwise. Checks tests, smoke paths, runtime-only behavior claims, executable evidence, and missing validation probes.

### history_architecture_auditor

Read-only. Uses only evolutionary metadata exposed by named RepositoryIO/controller receipts together with safe doc, config, and source projections to identify churn, co-change signals, intended-vs-implemented architecture drift, and `ARC-*` candidates. If receipt evidence is absent, reports the evolutionary signal as unknown; it never runs Git history commands.

### phase_planner

Planning-only. Drafts sub-phase options for one phase or a small phase cluster. Parent consolidates final sub-plan files.

### implementation_slicer

Step 4 only. Turns a READY sub-plan into the smallest verified implementation slice.

### slice_implementer

Step 4 only. Fresh context for one active slice. Reports `DONE`, `DONE_WITH_CONCERNS`, `NEEDS_CONTEXT`, or `BLOCKED`, with changed files, validation evidence, and unresolved assumptions. Does not commit, push, open PRs, deploy, or mutate external systems unless the user explicitly opts in.

### spec_reviewer

Step 4 only. Independently checks the changed slice against the active sub-plan, acceptance criterion, audit row, parent acceptance signal, and implementation contract. Reports `spec_verdict: pass|fail`.

### verification_reviewer

Read-only where practical. Reviews diffs, tests, artifacts, and whether the acceptance criterion is actually met.

### quality_reviewer

Read-only where practical. Runs only after spec review passes. Checks maintainability, tests, integration risk, security-sensitive behavior, and ledger evidence. Reports `quality_verdict: pass|fail|with_fixes`.

## When to Spawn Subagents

Use subagents when:

- the repository is large or unfamiliar;
- Step 1.5 Autopsy has multiple independent evidence areas;
- Step 2 has many phases or very different domains;
- Step 3 has many sub-plans and needs separate coverage/readiness/security review;
- Step 4 needs implementation/review separation.
- Step 4 needs a fresh implementer, independent spec review, independent quality/security review, or final batch review.

Do not spawn subagents when:

- the task is small enough for one context window;
- results would be mostly duplicated;
- the user asked for a quick single-step output;
- subagent writes would create file conflicts.

## Safety Boundaries

- Subagents inherit and must obey sandbox, approval, secret, and file-boundary rules.
- Do not let multiple subagents write the same file.
- Only one writer should modify files for a Step 4 implementation slice unless the user explicitly requests parallel branches.
- Parent agent must consolidate subagent results and cite or summarize evidence before writing final artifacts.
- Reviews that fail require same-slice fixes and re-review before the parent marks a slice complete.
- Final Step 4 review should run after the selected batch or queue completes, before completion reporting.

## Required Result Format

Every subagent should return this structured shape:

```yaml
role:
question_ids_answered:
scope:
files_inspected:
claims:
  - claim:
    evidence:
    confidence:
contradictions:
open_questions:
recommended_parent_action:
should_block:
```

The parent agent owns final synthesis and official artifact writes.
