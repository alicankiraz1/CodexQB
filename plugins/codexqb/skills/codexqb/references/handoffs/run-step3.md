---
contract_version: 2
---

# Step 3 Goal Handoff

Use $codexqb. Run Step 3 according to `references/Third-Planner.md`.

Goal Run Contract:
- Outcome: audit every generated sub-plan and decide whether Step 4 can begin.
- Inputs: `Main-Planing`, `Sub-Planing-Index`, `Faz` plans, optional `Autopsy`, `Project-Ontology`, `Project-Comprehension`, and `Planing-Ledger` files.
- Boundaries: modify only `Planner-docs/Sub-Planing-Audit.md`.
- Source precedence: `Main-Planing` and validator findings first; support artifacts as evidence, with tentative comprehension claims audited before use.
- Validation gates: run the bundled Step 3 preflight and post-audit validators through the loader-supplied, controller-bound active skill root; missing active-path authority is `BLOCKED`.
- Stop gates: missing `Main-Planing`, missing `Sub-Planing-Index`, or no sub-plan files.
- Context budget: inspect all plan files structurally, then quote only concise evidence.
- Subagent policy: use subagents only for broad coverage/readiness/security review; parent writes the audit.

Resume / Recovery Protocol:
1. Re-read this canonical Goal Run Contract.
2. Invoke the fixed repository-io command below once for each following JSON
   request, sending the object directly through the host process API to the
   child process's stdin, then retain both receipts:

   ```bash
   python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller repository-io -- request-stdin
   ```

   ```json
   {"schema":"codexqb.controller-argv/v1","argv":["--root",".","inspect","--profile","step3"]}
   ```

   ```json
   {"schema":"codexqb.controller-argv/v1","argv":["--root",".","search","--profile","step3"]}
   ```

   Never use echo, printf, a pipe, redirection, a heredoc, command substitution,
   environment variables, shell interpolation, or a temporary/repository file
   to transport the request. Use only controller-owned workspace evidence
   already bound to the Goal run for branch/dirty-state posture; never fall back
   to raw Git or shell reads.
3. Re-read the active audit if present, ledger, plan snapshot, index, and all selected sub-plans.
4. Reconcile ledger state with repository evidence before deciding readiness.
5. Do not repeat a verified slice or mark completed work READY again.
6. If the active plan snapshot changed, stop and request or perform replanning.

Audit `Planner-docs/Main-Planing.md`, `Planner-docs/Sub-Planing-Index.md`, active detailed `Planner-docs/Faz-*-Plans/*.md` files, deferred roadmap cards, and any supporting `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, `Planner-docs/Project-Comprehension.md`, or `Planner-docs/Planing-Ledger.md`. Analyze main-phase active/deferred coverage, file naming, sequencing, required section structure, index consistency, content quality, scope drift, readiness realism, evidence quality, confidence calibration, trace coverage, architecture drift coverage, competency-question coverage, open-hypothesis probes, ontology consistency, planning-history continuity, security/governance, vibecoding slice quality, and Step 4 readiness. Do not fix any plan files; produce only `Planner-docs/Sub-Planing-Audit.md`. Do not stop until every active detailed sub-plan and every deferred roadmap card has been reviewed.
