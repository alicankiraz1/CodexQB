# Step 4 Implementation Handoff Prompt Template

This reference is not an auto-executed CodexQB planning step.

Use it only after Step 3 writes `Planner-docs/Sub-Planing-Audit.md` and the audit says Step 4 can begin. The full copy block lives in one canonical source:

```text
references/handoffs/run-step4.md
```

Do not duplicate the full Goal Run Contract in this file. When the user asks for Step 4 Goal mode text, read and return the exact canonical handoff from `references/handoffs/run-step4.md`.

If the audit status is `BLOCKED`, do not print the Step 4 handoff. Print the minimal unblock prompt from the audit instead.

If the audit status is `NO_ACTION_REQUIRED`, do not start implementation. Summarize that all in-scope sub-plans are COMPLETE, SUPERSEDED, or DEFERRED.

If the audit status is `PASS_WITH_WARNINGS` and any open P0/P1 finding exists, do not print the Step 4 handoff. Print a repair prompt targeting those P0/P1 findings first.

If the audit status is `PASS_WITH_WARNINGS` with only open or accepted P2/P3 findings, the canonical handoff may be printed, but state that the implementation run must keep those warnings visible.

Before printing the canonical handoff, run the bundled strict validator when available:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step4 --strict
```

## Operator Notes

- Keep each implementation slice small and reversible, but continue through the ordered queue after each verified slice when the canonical handoff allows it.
- For non-trivial slices, use this subagent pattern when available: explorer maps relevant files and risks; tester/verifier identifies validation path; implementer/worker makes the smallest change; reviewer/security reviews the diff and evidence.
- Only one writer should modify files per slice unless the user explicitly requests parallel branches.
- Do not batch unrelated sub-plans in one diff.
- If targeted validation fails and the source is unclear, stop before widening the edit.
- Do not load every sub-plan into context unless the active slice requires cross-plan repair.
- Prefer existing repo validation commands over invented commands.
- Report exact blocker strings and separate code-delivery status from external config or credential blockers.
- Keep `Planner-docs/Planing-Ledger.md` concise; it is a replanning memory artifact, not a transcript dump.
- Read `references/project-comprehension-methods.md` if the active slice depends on evidence confidence, CQ, TRACE, ARC, or HYP rows.
- Use `Planner-docs/Project-Ontology.md` to preserve vocabulary, entity, workflow, boundary, integration, and invariant consistency for the active slice.
- Use `Planner-docs/Project-Comprehension.md` to preserve evidence/confidence, CQ/TRACE/ARC links, and open hypothesis probes for the active slice.
- Use `references/probe-policy.md` before running local stateful or external/live probes.
- Do not commit, push, open a PR, deploy, or mutate external systems unless the user explicitly asks in the Step 4 run.
