# CodexQB Workflow Quality Notes

Use these notes with the active planner prompt. They do not replace the planner
prompt; they clarify reliability practices observed from first real use.

## Read Before Reporting Counts

- Read the full active planner prompt before summarizing requirements.
- Do not report phase, sub-plan, or section counts from memory.
- Report section counts only after reading the prompt or running validation.
- Active Step 2 detailed sub-plan files require 13 top-level `##` sections after the H1. Deferred phases should remain roadmap cards in `Sub-Planing-Index.md` unless the user explicitly requests `full` planning.

## Step 1 Repo-Aware Intake

- Run a bounded read-only repository scan before asking the four Step 1 fields.
- Use `references/repo-aware-intake.md` to infer helpful defaults, but do not treat inferred values as final until the user confirms or edits them.
- Keep the intake conversational and sequential: one plain-text question at a time.
- If the repository is empty or evidence is weak, say so and fall back to concise generic questions.
- Do not let the pre-intake scan replace the full Step 1 inspection required by `First-Planner.md`.

## Step 1.5 Autopsy

- Run Step 1.5 only for existing or partially built projects with meaningful repo evidence.
- Use `references/Autopsy-Planner.md` and write only `Planner-docs/Autopsy.md`.
- Treat `Autopsy.md` as Step 2 feedback, not as a replacement for `Main-Planing.md`.
- Skip Autopsy for new or nearly empty repositories; do not create a speculative autopsy file.
- Step 2 must read `Autopsy.md` when it exists and must not block when it is absent.


## Vibecoding-First Planning

- Read `references/vibecoding-principles.md` before long planning or implementation handoffs.
- Prefer the next useful verified move over an over-specified speculative plan.
- Every phase/sub-plan should help identify small reversible slices, fast validation signals, explicit deferrals, and safety boundaries.
- Vibecoding does not relax validation, secret safety, approval gates, file boundaries, or secure coding expectations.

## Subagent Discipline

- Read `references/subagent-playbook.md` when repo size, phase count, audit surface, or Step 4 implementation complexity justifies subagents.
- Subagents are useful for read-only repo exploration, readiness/security review, ontology mapping, phase drafting, audit review, and Step 4 implementation/review separation.
- Parent CodexQB owns final artifact writes. Do not let multiple subagents write the same planning artifact.
- Do not spawn subagents for trivial single-file planning tasks.

## Planning Memory and Ontology

- Read `Planner-docs/Planing-Ledger.md` when it exists so replanning knows which plans were previously applied and what implementation summaries were recorded.
- Read `Planner-docs/Project-Ontology.md` when it exists so terminology, entities, workflows, boundaries, integrations, and invariants stay consistent.
- Treat ledger and ontology files as supporting evidence, not as absolute truth. Current repo state and user-confirmed intent win when they conflict.
- Step 4 should append concise implementation summaries to `Planing-Ledger.md` after verified slices or stop events.

## Assessment and Token/Context Budget

- Capture desired autonomy level, human review cadence, and token/usage budget when the user provides them.
- Use low/medium/high token/context risk bands unless the user provides a concrete baseline.
- Do not invent exact token spend or budget percentages.
- Long Goal handoffs should state outcome, unchanged boundaries, validation checkpoints, stop gates, token/context risk, and whether subagents are recommended.

## Use The Bundled Validator

Prefer the bundled validator over ad hoc validation snippets. When manually
validating from a CodexQB repository checkout, use:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step2 --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step3 --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step4 --strict
```

Resolve `<CODEXQB_SKILL_ROOT>` only through the active-skill contract in
`SKILL.md`. If that loader-supplied, controller-bound absolute root or the bundled validator is
unavailable, stop as `BLOCKED`; do not search the target repository or perform
manual/raw all-file validation.

The validator is read-only. It checks required sections, phase folders,
filename conventions, planning scope manifests, active/deferred phase
consistency, implementation-ready sub-plan signals, normalized duplicate
ratios, uniform quota anomalies, index references, duplicate numbering,
missing or unindexed files, and length-bounded secret patterns.

## Keep Goal Mode Output Concise

- Keep stdout concise during long Goal runs.
- Avoid dumping full generated files unless the user explicitly asks.
- Summarize counts, file paths, blockers, and validation status.
- Preserve detailed evidence inside the generated Markdown artifacts.

## Avoid Noisy Inline Generators

- Avoid very large inline generation scripts when normal file editing is
  practical.
- If a script is unavoidable for bulk document generation, keep it small,
  syntax-check it before use, and validate every generated file afterward.
- Do not rely on sampled reads alone; Step 2 requires all-file structure
  validation.

## Handle Untracked Planner Docs Correctly

`Planner-docs/` is often untracked during first use, so controller-captured Git
metadata alone does not prove the complete Planner-docs inventory.

Use the concrete launcher-backed `repository-io` inspect command and fixed
profile named by the active planner for complete Planner-docs inventory and
repository/worktree/VCS metadata evidence.

When comparing generated files, run only this fixed command:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller repository-io -- request-stdin
```

Send this non-executable request object through the host process stdin channel,
once for each exact path:

```json
{
  "schema": "codexqb.controller-argv/v1",
  "argv": ["--root", ".", "read-model", "--path", "<repository-relative-path>"]
}
```

Compare the receipt-bound hashes and safe model projections. Avoid raw Git or
filesystem comparison helpers. Never transport this JSON with echo, printf, a
pipe, redirection, a heredoc, command substitution, environment variables,
shell interpolation, or a temporary/repository file.

## Secret Scan Discipline

- Do not use one-character `sk-` prefix patterns; they can match normal
  filenames like `task-spec.yaml`.
- Use length-bounded token patterns such as `sk-[A-Za-z0-9_-]{20,}`.
- Do not print secret values if a secret-like pattern is detected.
- Do not run arbitrary repository-content search commands. Use the named
  repository I/O search profiles and bundled validator; if either is
  unavailable, stop as `BLOCKED` instead of using a raw fallback.

## Required Step Handoffs

- Step 1 must hand off Step 2 as text for Goal mode.
- Step 1.5 may create `Planner-docs/Autopsy.md` and optional `Planner-docs/Project-Ontology.md` before Step 2 for existing projects.
- Step 2 must read optional `Project-Ontology.md` and `Planing-Ledger.md` when present, then finish by handing off Step 3 as text for Goal mode.
- Step 3 must write only `Planner-docs/Sub-Planing-Audit.md`.
- Step 3 may hand off Step 4 only after `--mode step4 --strict` validation passes.
- Step 4 is implementation work in a new Goal run, not a planning-file generation step.

## Step 4 Token Discipline

- Do not load all phase sub-plans at once.
- Read `Sub-Planing-Audit.md` and `Sub-Planing-Index.md` first; read `Project-Ontology.md` and `Planing-Ledger.md` only as needed for the active slice.
- Build an ordered queue from READY and READY_WITH_WARNINGS sub-plans.
- Load only the active sub-plan and the repo files needed for the current slice.
- Continue to the next acceptance criterion or next queued sub-plan after each verified slice.
- Append a concise implementation summary to `Planner-docs/Planing-Ledger.md` after each verified slice or stop event when file writes are allowed in Step 4.
- Stop before implementation if audit contains P0/P1 findings.
- Stop during implementation on explicit stop gates such as failing tests, missing required files, approval/credential/live-environment blockers, unsafe external mutations, unrelated dirty worktree, or token/context pressure.
