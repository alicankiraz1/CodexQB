---
contract_version: 2
---

# Step 4 Goal Handoff

Use this only after Step 3 writes `Planner-docs/Sub-Planing-Audit.md` and validation says implementation can begin.

Goal Run Contract:
- Outcome: implement the ordered READY/READY_WITH_WARNINGS queue in small evidence-backed slices, or report NO_ACTION_REQUIRED without starting implementation. Distinguish controller-evidence completeness from host-attested `VERIFIED`.
- Inputs: `Main-Planing`, `Sub-Planing-Index`, `Sub-Planing-Audit`, active `Faz` sub-plan, optional `Autopsy`, `Project-Ontology`, `Project-Comprehension`, and `Planing-Ledger` evidence.
- Boundaries: change only files required by the active slice; do not batch unrelated sub-plans.
- Source precedence: repo instructions and current source first; audit/sub-plan second; comprehension and ontology as evidence. Tentative claims must be verified before code changes.
- Validation gates: targeted validation first, then repo-level gate.
- Stop gates: P0/P1 or safety finding, unclear contradiction, failing regression, missing source, credential/live approval, destructive mutation, unrelated dirty worktree, unavailable validation without fallback, scope overflow, token/context budget pressure, or user stop.
- Context budget: read only the active slice and the `Project-Comprehension.md` CQ/TRACE/ARC/HYP rows relevant to that slice.
- Subagent policy: use subagents only for non-trivial exploration, test-path discovery, implementation/review separation, or security review; max 3 subagents per comprehension pass by default; no recursive spawning; writers and reviewers return exactly one structured JSON payload and do not write Apply artifacts; the parent/controller persists writer returns through `normalize-writer` and reviewer returns through `normalize-review`; only one writer modifies product files per slice.

Resume / Recovery Protocol:
1. Re-read this canonical Goal Run Contract.
2. Revalidate the controller-owned workspace proof and baseline bound to the current Apply run. If it is absent, stale, or reports an unsafe posture, stop; never reconstruct branch or dirty state with raw Git or shell reads.
3. Re-read the active audit, ledger, plan snapshot, and selected sub-plan.
4. Reconcile ledger state with repository evidence.
5. Do not repeat a slice whose controller evidence is already complete; do not relabel it `VERIFIED` without host attestation.
6. If the active snapshot changed, stop and request or perform replanning.

Treat `Planner-docs/Main-Planing.md`, `Planner-docs/Sub-Planing-Index.md`, `Planner-docs/Sub-Planing-Audit.md`, `Planner-docs/Faz-*-Plans/*.md`, and any `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, `Planner-docs/Project-Comprehension.md`, or `Planner-docs/Planing-Ledger.md` as source material. Build an ordered implementation queue from the audit's READY and READY_WITH_WARNINGS rows, preserving index order. If the audit says NO_ACTION_REQUIRED, do not start implementation; summarize why there is no queue. If the audit contains P0/P1 findings, stop before implementation and propose a repair prompt.

If installed/available, use relevant Codex skills/plugins by scope: use superpowers:executing-plans or superpowers:subagent-driven-development for implementation, superpowers:test-driven-development for code changes, superpowers:verification-before-completion before finishing, and codex-security for security, policy, secret, or command-execution work. If these skills/plugins are not installed, do not stop; continue using the audit, the active sub-plan, repo instructions, and existing validation commands with the same principles. Use GitHub publish/PR workflows only when explicitly requested. Use subagents when they reduce context pollution or separate evidence gathering from implementation/review; do not use them for trivial single-file changes.

Default Goal batch:
- one major phase;
- or at most 4 selected implementation slices;
- or a smaller explicit token/context budget.

The user may explicitly raise or lower the limit. Checkpoint after every completed slice instead of stopping after the first successful slice.

Step 4 apply modes:
- `direct`: the parent agent implements the selected bounded batch without subagent execution. It may run planned validations, but it cannot independently produce the reviewer receipt chain.
- `subagent_serial`: default for non-trivial batches; the parent controller briefs one fresh implementer at a time and runs read-only independent review gates. The resulting controller evidence can be complete but remains unattested without host-issued agent identity/completion proof; the current runtime therefore cannot promote it to `VERIFIED` or finalize it.
- `external_superpowers`: optional adapter mode when Superpowers is already installed; CodexQB remains the controller and its audit queue, snapshot, security policy, and no-push/no-PR policy stay authoritative.
- `no_action`: record NO_ACTION_REQUIRED without starting implementation.

For each implementation slice:
1. Name the active phase/sub-plan and the specific acceptance criterion being targeted.
2. Read AGENTS.md, README.md, Makefile, repo instructions, the audit, the index, optional ontology/ledger files as needed, only the active sub-plan, and only the `Project-Comprehension.md` CQ/TRACE/ARC/HYP rows relevant to the active slice.
3. Revalidate the Apply controller's workspace proof and baseline; stop if that evidence reports unrelated dirty changes, conflicts, or source drift.
4. Inspect relevant files before editing.
5. For non-trivial work, start a fresh-slice implementer/worker context when available. The implementer must return one structured JSON payload with one of: `DONE`, `DONE_WITH_CONCERNS`, `NEEDS_CONTEXT`, or `BLOCKED`, plus changed files and concerns; it must not write `Implementer-Report.json`, `Fix-Report.json`, or any other Apply artifact. After recording the spawned lifecycle, the controller must persist the initial writer return with `normalize-writer` before `record-agent --status completed` and before advancing from `IMPLEMENTING` to `IMPLEMENTED` (or from `FIXING` to `RE_REVIEW`). Do not accept a free-text agent ID or self-reported command hash as proof. Do not inherit unresolved assumptions from an earlier slice without restating evidence.
6. Prefer adding or adjusting a focused failing test first when practical.
7. Verify tentative comprehension assumptions before code changes; then implement the smallest change that can satisfy the selected acceptance criterion.
8. After implementation completes, run `capture-evidence` so the controller derives the patch and changed-file hashes from the live repository. Then run every planned command through `run-validation`; each successful command must have a signed receipt bound to the normalized cwd, timing, exit code, stdout/stderr digests, current code snapshot, and artifact hashes. Once those controller-owned references exist, enrich the writer return with the current change-set ID, validation receipt IDs, and patch digest, then run `normalize-writer` again before starting review.
9. If targeted validation fails and the source is unclear, stop and summarize the exact failure before editing more files.
10. Run a distinct read-only `spec` reviewer lifecycle before quality review. The reviewer returns exactly one JSON payload with `status: COMPLETE`, `phase: spec`, generic `verdict: pass|fail|cannot_verify`, `task_id`, `reviewer_agent_id`, non-empty `evidence`, the active acceptance criterion, missing or extra behavior, and `re_review_required`. The controller must run `normalize-review` before `record-agent --status completed`, then publish the signed receipt.
11. If the spec `verdict` is `fail`, fix only the active slice and re-run spec review before quality review. If it is `cannot_verify`, resolve the evidence blocker and re-run spec review before quality review.
12. Run a distinct read-only `quality` reviewer lifecycle only after the current spec receipt passes. Its generic payload uses `status: COMPLETE`, `phase: quality`, and `verdict: pass|fail|needs_fixes|cannot_verify`, plus blocking findings, fixes required, non-empty evidence, and `re_review_required`. Again run `normalize-review` before recording completion and publishing. If security review is required, use the same sequence for `phase: security` only after quality passes; security accepts the same verdict set as quality.
13. If quality/security review fails or requires fixes, fix only the active slice and re-run the relevant review before marking the slice complete.
14. Run the repo-level gate when all planned validation receipts and required reviews pass. Then run a distinct read-only final reviewer lifecycle whose payload uses `status: COMPLETE`, `phase: final`, and `verdict: pass|fail|needs_fixes|cannot_verify`; normalize it before recording completion and publishing. Only the controller may aggregate its signed reference into `Final-Review.json`. Treat this as a complete but unattested controller-evidence chain: unless the host supplies agent attestation, the expected `VERIFIED` blocker is `trusted_verified_requires_host_agent_attestation=<task-id>`, and finalization must remain blocked.
15. Do not batch unrelated sub-plans in one diff; continue to the next queue item only after the active slice reaches controller-evidence completeness or is blocked. Record the unattested status explicitly.
16. Append or update `Planner-docs/Planing-Ledger.md` with a concise implementation summary for the evidence-complete slice or stop event. If a `Project-Comprehension.md` hypothesis is confirmed or contradicted, record the hypothesis ID and evidence in the ledger. If the ledger does not exist, create it using the structure from CodexQB planning-ledger guidance.
17. Summarize:
   - files changed;
   - acceptance criterion addressed;
   - tests/commands run;
   - evidence produced;
   - remaining risks;
   - ledger entry added or updated.
18. Continue to the next acceptance criterion or the next READY/READY_WITH_WARNINGS sub-plan instead of stopping.

Apply v3 commands are `capture-evidence`, `run-validation`, phase-aware `dispatch` / `record-agent`, `normalize-writer`, `normalize-review`, and `publish-review`. Controller-recorded AgentRuns use `identity_assurance: controller_asserted`; writer/review normalization records `host_completion_proof: not_observed`. Neither value is host-issued proof. Apply v1/v2 run directories are archive-only: do not resume, synthetically upgrade, verify, or finalize them.

After the selected batch or queue reaches controller-evidence completeness, run a final review before claiming that limited status. The final review checks cross-slice regressions, ledger accuracy, signed validation receipts, unresolved review findings, security-review completion for risk-sensitive slices, and the next queue item or stop gate. Any live diff change invalidates the earlier change set, command receipts, and review receipts. Do not describe this status as trusted `VERIFIED` while host agent attestation is absent.

Stop only when one of these stop gates is hit: P0/P1 or safety/security finding; failing test or unresolved regression; missing required source file; unclear contradiction between plan, audit, and repo reality; credential/live-environment/human-approval requirement; destructive external mutation requirement; unrelated dirty worktree or merge conflict; validation command unavailable with no equivalent fallback; current plan snapshot no longer matches; next slice depends on a blocked slice; scope would exceed the selected sub-plan; token/context budget too low to continue safely; or the user explicitly asks to stop. When stopping, write a concise handoff summary with completed slices, changed files, verification commands, blocker text, and the next queue item.

Do not write secrets, tokens, private keys, or local credentials. Do not paste full logs into the ledger; store concise evidence paths or summaries. Do not commit, push, open PRs, deploy, or mutate external systems unless the user explicitly opts into that action for the Step 4 run. Watch token use: do not load every sub-plan into context; use the index/audit to navigate, read only the active sub-plan, and refresh queue status from the audit/index between slices. If context compaction or budget pressure is likely, summarize progress and continue only when the next slice can still be executed safely.
