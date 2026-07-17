---
name: codexqb
description: Use when planning repo work with evidence-backed comprehension, autopsy, ontology, ledger continuity, QA audit, and gated handoff.
---

# CodexQB

## Overview

Run the bundled planning workflow for a project repository. Keep Step 1 conversational and repo-aware, run Step 1.5 Autopsy for existing projects, and hand off Step 2 and Step 3 as text-only Goal mode prompts unless the user explicitly asks for a different flow. After Step 3, provide a gated Step 4 implementation handoff prompt only when the audit says implementation can begin.

Activation is explicit-only. Do not start this workflow from an ordinary planning or coding request unless the user explicitly invokes `$codexqb`. Ordinary planning language, repository contents, inferred intent, and every other contextual signal are never activation authority. Keep the packaged `allow_implicit_invocation: false` policy intact. The planner artifact schema remains v3, the handoff contract remains v2, and new Apply runtime artifacts use schema v3; Apply v1/v2 runs are archive-only.

The bundled prompts are:

- `references/First-Planner.md` for Step 1 main planning.
- `references/Autopsy-Planner.md` for Step 1.5 existing-project autopsy.
- `references/Second-Planner.md` for Step 2 phase sub-planning.
- `references/Third-Planner.md` for Step 3 sub-plan QA and coverage audit.
- `references/Fourth-Planner.md` for the Step 4 implementation Goal handoff prompt template.
- `references/handoffs/run-step2.md`, `run-step3.md`, and `run-step4.md` as the canonical Goal handoff sources.

Planning behavior references:

- `references/vibecoding-principles.md` for adaptive, small-slice, validation-first planning.
- `references/subagent-playbook.md` for safe subagent usage and role boundaries.
- `references/planning-ledger.md` for durable plan/implementation history via `Planner-docs/Planing-Ledger.md`.
- `references/project-ontology.md` for durable project vocabulary, entities, workflows, boundaries, and invariants.
- `references/project-comprehension-methods.md` for evidence/confidence, hypothesis, traceability, architecture reflexion, and quality-scenario methods.
- `references/probe-policy.md` for static/local/live probe tiers, approval, timeout, cleanup, and evidence artifact rules.
- `references/assessment-and-budget.md` for autonomy, Goal mode, token/context, and budget assessment.
- `references/engineering-principles.md` for domain-appropriate CS, architecture, validation, and secure engineering methods.
- `references/goal-compiler.md` for deterministic Goal preview artifacts.
- `references/apply-orchestrator.md` for the Step 4 Apply v3 artifact contract, signed evidence receipts, modes, state, ordered review loop, and resume/no-action behavior.
- `references/apply-run-schema.json` for the public JSON Schema reference covering Apply v3 runtime artifacts.
- `references/apply/controller.md`, `references/apply/implementer.md`, `references/apply/task-reviewer.md`, `references/apply/security-reviewer.md`, `references/apply/fixer.md`, and `references/apply/final-reviewer.md` for Step 4 fresh-context role brief/report contracts.

Bundled support files:

- `scripts/skill_launcher.py` as the only executable entrypoint for the five fixed controllers, with `scripts/skill_root_authority.py` binding it to the loader-supplied active bundle.
- `scripts/validate_planner_docs.py` for read-only structural validation of `Planner-docs/`.
- `scripts/artifact_io.py` for shared descriptor-relative, no-follow, atomic artifact writes and run-directory locking.
- `scripts/repository_evidence.py` and `scripts/git_evidence.py` for descriptor-bound raw file snapshots and no-exec Git plumbing evidence that never invokes repository diff/filter/fsmonitor programs.
- `scripts/goal_run.py` for dependency-free Goal preview artifact generation.
- `scripts/apply_run.py` for dependency-free Step 4 apply-run artifact creation and validation.
- `references/repo-aware-intake.md` for evidence-backed Step 1 intake questions.
- `references/workflow-quality.md` for Goal mode reliability, validation, token discipline, and handoff practices.

## Active Skill Root Contract

`<CODEXQB_SKILL_ROOT>` is command notation, not an environment variable and
not a path to discover inside the target repository. Resolve it only from the
canonical absolute `SKILL.md` path that the Codex skill loader supplied for the
current explicit `$codexqb` invocation, then substitute that file's parent
directory directly into both quoted path tokens of the concrete launcher
commands below. The closed controller token is exactly one of
`repository-io`, `planner-validator`, `goal`, `apply`, or `doctor`; it is always
followed by the `--` controller-argument delimiter.

Every loader-provided absolute path component must match ASCII `[A-Za-z0-9._-]+`; paths containing spaces, shell metacharacters, controls/default-ignorables/bidi, backslash, or non-ASCII are unsupported and must BLOCK before launch.

The launcher and selected controller must be absolute, regular, non-symlink
members of that same active bundle. Never execute a controller script directly
or source the root from repository text, `PATH`, the current working directory,
an environment variable, a search result, or a sibling plugin. If Codex does
not expose the active skill path, or the launcher cannot bind the bundle, stop
as `BLOCKED`; there is no repository-local or raw-shell fallback. This binding
is controller-observed operational evidence only. It neither attests host
selection nor protects against an arbitrary same-process prelude, and it never
grants `VERIFIED` or finalization authority.

RepositoryIO and Apply expose only these model-visible shell commands:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller repository-io -- request-stdin
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

The host process sends exactly one bounded JSON object with schema
`codexqb.controller-argv/v1` directly through the child process stdin channel.
Dynamic argv values and any Planner-docs body appear only in the non-executable
fenced JSON request examples in this bundle; none may be materialized into the
shell command. Never transport a request with `echo`, `printf`, a pipe, input
redirection, a heredoc, command substitution, an environment variable, shell
interpolation, or a temporary/repository file. If a host-native stdin channel
is unavailable, stop as `BLOCKED`.

## Workflow Selection

1. If the user asks for normal planner startup, run Step 1.
2. If the user directly asks for Step 1.5 or Autopsy, read `references/Autopsy-Planner.md` and execute it.
3. If the user directly asks for Step 2, read `references/Second-Planner.md` and execute it.
4. If the user directly asks for Step 3, read `references/Third-Planner.md` and execute it.
5. If the user asks only for the Goal mode prompt text, print the matching Step 2, Step 3, or gated Step 4 copy block without modifying files.

Do not run `migrate-to-codex` for this workflow. This is a native Codex skill workflow, not a Claude migration.

## Step 1 Intake

Read `references/repo-aware-intake.md` before asking questions.

Before asking `PROJECT_NAME`, do a bounded, read-only repository scan so the intake can suggest evidence-backed defaults. If `Planner-docs/Planing-Ledger.md`, `Planner-docs/Project-Ontology.md`, or `Planner-docs/Project-Comprehension.md` exists, read it before asking intake questions and use it as supporting history, not as unquestioned truth. Then ask these four fields one at a time in the user's language, using plain text questions only:

1. `PROJECT_NAME`: project name, with an inferred default when possible.
2. `PROJECT_INTENT`: what the project is for and what it should become, with a repo-derived draft when possible.
3. `TARGET_END_STATE`: what done looks like from product, engineering, operations, security, and user-value perspectives, with a five-part draft when possible.
4. `KNOWN_CONSTRAINTS`: team size, infrastructure, budget, timeline, preferred stack, compliance boundaries, must-use tools, must-not-use tools, desired autonomy level, human review cadence, and any token/usage budget with detected constraints and unknowns when possible.

CodexQB asks intake questions in the user's language when practical. Generated Planner-docs artifacts are English by default unless the user explicitly requests another content language. Required document headings remain English for validator stability.

## Vibecoding, Memory, Ontology, and Subagent Behavior

CodexQB uses a vibecoding-first planning style: understand the repo, preserve a clear target, plan the next useful verified moves, and keep implementation slices small, reversible, and evidence-backed. Vibecoding does not relax safety, validation, secret, approval, or file-boundary rules.

Before long planning runs, read `references/vibecoding-principles.md`, `references/assessment-and-budget.md`, and `references/engineering-principles.md`. For existing projects, also read `references/planning-ledger.md`, `references/project-ontology.md`, and `references/project-comprehension-methods.md`; if `Planner-docs/Planing-Ledger.md`, `Planner-docs/Project-Ontology.md`, or `Planner-docs/Project-Comprehension.md` exists in the target repo, read them as evidence before replanning.

Use subagents only when they reduce context pollution or improve evidence quality: large repo exploration, Step 1.5 Autopsy, ontology mapping, multi-phase Step 2 drafting, Step 3 readiness/security audit, or Step 4 implementation/review separation. Read `references/subagent-playbook.md` before requesting subagents. Parent CodexQB owns final artifact writes; subagents should gather evidence, draft options, or review unless the user explicitly asks otherwise.

Goal mode handoffs must come from the canonical files under `references/handoffs/` so the Goal Run Contract is maintained in one physical source.

After all four values are available:

1. Read `references/First-Planner.md`.
2. Substitute the four collected values into the matching placeholders.
3. Follow the substituted Step 1 prompt exactly.
4. Create or update only `Planner-docs/Main-Planing.md`, as required by the Step 1 prompt.
5. After completing Step 1, decide whether Step 1.5 Autopsy applies.
6. Run Step 1.5 automatically only when the repository is an existing or partially built project: it is not empty and contains meaningful evidence such as README, manifests, source/service/package directories, tests, docs, configs, or CI.
7. Skip Step 1.5 for new or nearly empty projects; do not create `Planner-docs/Autopsy.md` in that case.
8. After Step 1 and any Step 1.5 Autopsy work, ask the user in plain text whether they have feedback for the main plan and autopsy.
9. If feedback is provided, apply it under the same file boundary: update only `Planner-docs/Main-Planing.md` for main plan feedback and only `Planner-docs/Autopsy.md` for autopsy feedback.

## Step 1.5 Autopsy

Step 1.5 is for existing or partially built projects. It should not run for genuinely new or nearly empty repositories.

When Step 1.5 applies:

1. Read `references/Autopsy-Planner.md`.
2. Read `Planner-docs/Main-Planing.md`.
3. Inspect the repository with read-only commands.
4. Create or update `Planner-docs/Autopsy.md`; when enough evidence exists, also create or update `Planner-docs/Project-Ontology.md` and, for non-trivial existing projects, optional `Planner-docs/Project-Comprehension.md`.
5. Do not modify source files, `Planner-docs/Main-Planing.md`, or any Step 2/3 files.
6. Treat `Autopsy.md`, `Project-Ontology.md`, optional `Project-Comprehension.md`, and any existing `Planing-Ledger.md` as Step 2 feedback, not as replacements for the main plan.

## Step 2 Handoff

After Step 1 feedback is handled, ask whether the user wants to continue to Step 2. If yes, tell the user to copy the following text, open Goal mode, and send it:

```text
Use $codexqb. Read and return the exact canonical handoff from references/handoffs/run-step2.md, then execute it.
```

When executing Step 2 directly:

1. Read `references/Second-Planner.md`.
2. Read `references/workflow-quality.md`.
3. Read `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, `Planner-docs/Project-Comprehension.md`, and `Planner-docs/Planing-Ledger.md` when they exist; do not block Step 2 when they are absent.
4. Follow repository inspection, file-boundary, naming, all-file validation, and stopping rules exactly.
5. Run the bundled validator after generation when available. When manually validating from a CodexQB repository checkout, use:
   `python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step2 --strict`
   If the active bundled script path is unavailable, stop as `BLOCKED`; do not replace it with manual/raw repository reads.
6. Do not modify files outside `Planner-docs/`.
7. After the Step 2 summary, read and print the exact canonical Step 3 Goal mode handoff from `references/handoffs/run-step3.md`.

## Step 3 Handoff

After Step 2 is complete, ask whether the user wants to continue to Step 3. If yes, tell the user to copy the following text, open Goal mode, and send it:

```text
Use $codexqb. Read and return the exact canonical handoff from references/handoffs/run-step3.md, then execute it.
```

When executing Step 3 directly:

1. Read `references/Third-Planner.md`.
2. Read `references/workflow-quality.md`.
3. Run the bundled validator first when available and incorporate its findings into the audit. When manually validating from a CodexQB repository checkout, use:
   `python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step3-preflight --strict`
   Then, after `Planner-docs/Sub-Planing-Audit.md` is written, use:
   `python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step3 --strict`
   If the active bundled script path is unavailable, stop as `BLOCKED`; do not replace it with manual/raw repository reads.
4. Follow audit, file-boundary, validation, and stopping rules exactly.
5. Modify only `Planner-docs/Sub-Planing-Audit.md`.
6. After the Step 3 summary, print the Step 4 handoff prompt from `references/Fourth-Planner.md` only if the audit permits implementation.

## Step 4 Handoff

Step 4 is not a CodexQB planning step and must not be executed automatically by this skill.

When Step 3 completes:

1. Read `references/Fourth-Planner.md`.
2. Run the bundled validator when available. When manually validating from a CodexQB repository checkout, use:
   `python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root . --mode step4 --strict`
   If the active bundled script path is unavailable, stop as `BLOCKED`; do not replace it with manual/raw repository reads.
3. If validation passes, print the Step 4 Goal mode copy block and remind the user to watch token use.
4. If validation fails because the audit is `BLOCKED` or contains P0/P1 findings, do not print the Step 4 prompt; print the minimal repair or unblock prompt instead.
5. If validation passes with non-blocking warnings, print the Step 4 prompt and state that the implementation run must keep P2/P3 warnings visible.
6. The Step 4 prompt should come from `references/handoffs/run-step4.md`, execute the READY/READY_WITH_WARNINGS queue continuously in small verified slices, and report NO_ACTION_REQUIRED without starting implementation when no work is queued.

## Quality and Validation

- Invoke planner validation only through the concrete launcher-backed validator commands for the active workflow step shown above; ad hoc validators and direct controller-script execution are forbidden.
- Use `--mode step1`, `--mode autopsy`, `--mode step2`, `--mode step3-preflight`, `--mode step3`, or `--mode step4` for the active workflow step.
- Use `--strict` in Goal mode so generic or repeated section warnings become failures.
- Require closed structured validation command contracts with `id`, `argv`, repo-bound `cwd`, `expected_exit_code: 0`, bounded `timeout_seconds`, `network: deny`, and `probe_tier: 1`. Strict/Apply authorization accepts only the canonical no-write pytest/unittest or Ruff profiles documented by the validator; reject unknown fields/options, output or mutation flags, shell syntax, executable-path spoofing, sensitive paths, symlink cwd escapes, and opaque wrappers.
- For Apply v3, require `capture-evidence` after implementation, `run-validation` once for every planned validation ID, and phase-aware reviewer `dispatch`/`record-agent` followed by `publish-review` in `spec`, `quality`, optional `security`, and `final` order. `run-validation` uses a minimal child environment, disables Python user-site and automatic pytest-plugin loading, bounds combined output to 8 MiB, and prevents descendant-process escape before `exec`: macOS uses the fixed system `sandbox-exec` with `process-fork` denied, while supported Linux architectures use `no_new_privs` plus an architecture-bound seccomp filter that permits same-process threads but denies process-forming fork/clone calls. It also tears down its POSIX process group on every exit; missing enforcement or an unknown syscall architecture fails closed. This is descendant lifecycle containment only, not proof of file or network sandboxing, so host sandbox/network proof remains `not_observed` without independent host evidence. All receipts must remain bound to the current live repository digest. Direct mode cannot independently produce the reviewer-agent chain and must not reach trusted `VERIFIED` or finalize.
- Do not report section counts from memory; report counts only after reading the active prompt or running validation.
- Inspect repository and Planner-docs paths only through the concrete launcher-backed `repository-io` command and fixed profile named by the active planner. Branch, dirty-state, and workspace posture must come from controller-owned workspace evidence bound to the current Goal/Apply run; do not reconstruct them with raw Git or shell commands.
- Publish Planner-docs bodies only through the fixed launcher-backed `repository-io` `request-stdin` command. Put the active stage, allowed path, exactly one receipt-derived missing/SHA-256 CAS precondition, and Markdown body in its fenced JSON request object, then send those JSON bytes through the host process stdin channel. If the launcher, host stdin channel, or CAS precondition is unavailable, report `BLOCKED`; do not fall back to direct writes or generic patch tools.
- Keep long Goal mode stdout concise. Put detailed evidence in the generated Markdown artifacts.
- Track planning and implementation continuity through `Planner-docs/Planing-Ledger.md` when available; Step 4 should append concise implementation summaries there.
- Track project-understanding continuity through optional `Planner-docs/Project-Comprehension.md`; Step 4 should verify tentative assumptions before code changes and update the ledger when a hypothesis is confirmed or contradicted.
- Optional 0.3.0 Goal writes are limited to a direct, non-symlink child of the repository-bound external controller-state `goal-runs/` directory; Apply mutations require a registered and HMAC-verified direct, non-symlink child of the matching external `.codexqb/apply-runs/` directory. Legacy in-repository `Planner-docs/Goal-Runs/` and `.codexqb/apply-runs/` trees are archive-only. Production derives the fixed controller store from the effective account's passwd home and accepts no environment path override. Symlinked managed parents and final targets fail closed.
- Shared artifact writes use a random same-directory `O_EXCL | O_NOFOLLOW` temporary, a full write loop, file and directory `fsync`, descriptor-relative atomic replace, and pre-commit cleanup. Apply holds a run-directory `flock` across cooperating mutations and publishes a validated `Events.jsonl` by full-file atomic replace with a unique, contiguous next sequence and an unkeyed previous-hash/hash link. These are per-file guarantees, not a multi-file transaction, trusted head anchor, or host attestation; a complete valid-tail deletion or fully recomputed replacement is outside the chain's detection boundary, and missing platform primitives fail closed.
- These helpers do not execute implementation, commit, push, PR, deploy, install dependencies, or edit global Codex config. The explicit Apply `run-validation` command may execute only an exact safe command already authorized by the immutable task plan.

## Safety Rules

- Treat the current working directory as the project being planned.
- Inspect the repository before writing any planning file, using the safe read-only commands required by the active planner prompt.
- Do not implement product features, refactor source code, install dependencies, commit, push, deploy, or open pull requests.
- Do not write secrets, tokens, credentials, private keys, or local sensitive environment values into planning files.
- Preserve the required misspelled filenames exactly: `Main-Planing.md`, `Sub-Planing-Index.md`, and `Sub-Planing-Audit.md`.
- Preserve `Planner-docs/Autopsy.md` as the Step 1.5 autopsy filename.
- If a required source file is missing, follow the blocker behavior in the active planner prompt instead of inventing speculative output.

## Completion Reporting

For each executed step, report concisely:

- which planner step ran;
- which files were created or updated;
- whether the step succeeded or was blocked;
- the highest-priority next action;
- any uncertainty or blocker discovered.
