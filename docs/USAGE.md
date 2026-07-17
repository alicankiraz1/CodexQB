# Usage

CodexQB runs a vibecoding-first, repo-aware planning workflow with an optional Step 1.5 Autopsy and ontology pass for existing projects.

CodexQB is explicit-invocation only: `policy.allow_implicit_invocation` is `false`, so ordinary Codex requests do not start this workflow. Invoke `$codexqb` explicitly; no interface selection or implicit matching route is authorized by this contract.

Release contracts:

```text
plugin_version: 0.3.0
artifact_schema_version: 3
handoff_contract_version: 2
goal_run_schema_version: 1
apply_run_schema_version: 3
```


## Vibecoding, Subagents, and Durable Memory

CodexQB plans for coding agents, not for static slideware. Plans should identify the next useful verified moves, preserve room for discovery, and keep work in small reversible slices with fast validation signals. Vibecoding does not relax safety, secret handling, approval, validation, or file-boundary rules.

When the repo is large or ambiguous, CodexQB may ask Codex Goal mode to use bounded subagents for read-only repo exploration, readiness/security review, ontology mapping, phase drafting, Step 3 audit, or Step 4 implementation/review separation. Subagents should gather evidence or review; the parent CodexQB agent owns official artifact writes.

CodexQB may use these optional durable artifacts when they exist:

```text
Planner-docs/Project-Ontology.md
Planner-docs/Project-Comprehension.md
Planner-docs/Planing-Ledger.md
```

`Project-Ontology.md` helps future planning understand vocabulary, entities, workflows, boundaries, integrations, and invariants. `Project-Comprehension.md` records evidence confidence, comprehension questions, domain-to-code traces, architecture reflexion, quality scenarios, and open hypotheses. `Planing-Ledger.md` records planning runs, implementation summaries, current state snapshots, and replanning inputs so future CodexQB runs can understand what was planned and what was actually applied.

## Step 1: Main Plan

Open the project repository you want Codex to analyze and ask:

```text
Use $codexqb to create a main plan for this project.
```

CodexQB first performs a bounded read-only scan of the current repository. It may inspect files such as `README.md`, `AGENTS.md`, manifests, CI workflows, docs indexes, deployment files, tests, and top-level service directories.

Then it asks four intake questions, one at a time:

- `PROJECT_NAME`: the project name.
- `PROJECT_INTENT`: what the project is for and what it should become.
- `TARGET_END_STATE`: what done looks like across product, engineering, operations, security, and user value.
- `KNOWN_CONSTRAINTS`: team, infrastructure, budget, timeline, stack, compliance, must-use tools, must-not-use tools, desired autonomy, human review cadence, and any token/usage budget.

CodexQB asks intake questions in the user's language when practical. Generated Planner-docs artifacts are English by default unless the user explicitly requests another content language. Required document headings remain English for validator stability. If the user provides a weekly/monthly token or usage budget, CodexQB can estimate whether the planned Goal run is likely to be low, medium, or high relative usage; it should not invent exact token spend without a baseline.

Future language-mode work should add an explicit `PLANNER_DOC_LANGUAGE` or intake-level language setting. Until then, headings stay English and only body content should vary when the user requests another language.

For existing repositories, the questions should include repo-derived defaults or draft summaries. For example, CodexQB may say that the README and package manifests suggest a specific project name, then ask whether to use that name or a different official name. For empty or minimal repositories, CodexQB should clearly say repository evidence is limited and ask the concise generic version of each question.

After the answers are collected, CodexQB loads `First-Planner.md`, substitutes the values, inspects the repository, and creates or updates:

```text
Planner-docs/Main-Planing.md
```

Step 1 is allowed to modify only that file.

## Step 1.5: Existing Project Autopsy

When the target repository is an existing or partially built project, CodexQB runs `Autopsy-Planner.md` after Step 1.

Expected output:

```text
Planner-docs/Autopsy.md
Planner-docs/Project-Ontology.md   # optional when enough evidence exists
Planner-docs/Project-Comprehension.md  # optional for non-trivial existing projects
```

The Autopsy report analyzes project sections, feature inventory, placeholders/stubs/skeletons, technical debt, missing or broken integrations, test and CI gaps, security/governance issues, operational readiness, and alignment with `Planner-docs/Main-Planing.md`. The optional ontology captures domain vocabulary, entities, workflows, boundaries, integrations, invariants, and open concept questions. The optional comprehension artifact captures `CQ-*`, `TRACE-*`, `ARC-*`, evidence/confidence, QAW/ATAM-lite quality scenarios, and open validation probes.

Step 1.5 is skipped for empty or nearly empty repositories. In that case, `Autopsy.md` is not required and Step 2 should continue without it.

## Step 2: Phase Sub-Plans

After Step 1, CodexQB prints a text block for Goal mode. Copy it, open Goal mode, and send it.

The prompt is:

```text
Use $codexqb. Read and return the exact canonical handoff from references/handoffs/run-step2.md, then execute it.
```

Expected outputs:

```text
Planner-docs/Sub-Planing-Index.md
Planner-docs/Faz-<n>-Plans/Faz<n>.<m>-*.md
```

Step 2 is allowed to modify only files under `Planner-docs/`.

`Planner-docs/Main-Planing.md` remains the primary source of truth. `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, `Planner-docs/Project-Comprehension.md`, and `Planner-docs/Planing-Ledger.md`, when present, are supporting evidence that should influence sub-plan evidence, work breakdowns, acceptance criteria, risks, ontology consistency, traceability, confidence calibration, and replanning continuity.

Step 2 defaults to `wave` mode: it details only the active planning horizon from explicit user intent, `Main-Planing.md` Step 2 Preparation Notes, active ledger state, or the next useful CodexQB wave. Later phases stay visible as deferred roadmap cards in `Sub-Planing-Index.md`. `full` mode requires an explicit user request. `refresh` updates existing planning artifacts incrementally, and `repair` updates audit-selected files only.

`Sub-Planing-Index.md` includes a Planning Scope Manifest with `planning_mode`, `active_phases`, `deferred_phases`, `max_detailed_subplans`, `max_output_words`, `goal_token_risk`, and `review_checkpoint`. It also carries Execution Waves, Parent Acceptance Traceability, and a central Decision Register so repeated global blockers are not copied into every sub-plan.

Active detailed sub-plans keep the 13-section structure and add a machine-readable `### Implementation Contract` JSON block with implementation paths, structured validation commands, parent acceptance signal IDs, dependency graph labels, concrete outputs, risk metadata, and security review flags. Rewritten public planning artifacts use `artifact_schema_version: 3`, `generated_by: codexqb`, and `plugin_version: 0.3.0` frontmatter.

Strict validation commands use exactly `id`, `argv`, `cwd`, `expected_exit_code`, `timeout_seconds`, `network`, and `probe_tier`. `cwd` must be an existing, non-symlinked, non-sensitive directory inside the repository; expected exit is `0`, timeout is 1–3600 seconds, `network` is exactly `deny`, and `probe_tier` is exactly `1`. The canonical Python profiles use `python3 -B -m pytest -p no:cacheprovider ...` or `python3 -B -m unittest ...`; Ruff uses `ruff check --no-fix --no-cache ...`. Unknown envelope fields or tool options, output/mutation flags, response files, executable paths, and opaque make/package-manager/uv/cargo/go wrappers fail closed. Legacy `command` strings are compatibility-only outside strict mode and never authorize Apply. High or critical risk classes and domains such as `auth`, `authorization`, `credential`, `secret`, `external_provider`, `network`, `command_execution`, `deployment`, `migration`, `stateful_runtime`, `distributed_runtime`, `online_learning`, `reinforcement_learning`, `cache`, `resume`, `checkpoint`, `payment`, `personal_data`, or `algorithmic_invariant` require `security_review_required: true`.

At the end of Step 2, CodexQB should run the loader-bound bundled validator, summarize the result, and print the Step 3 Goal mode handoff block. No equivalent ad hoc validator is an authorized fallback, and sampled reads alone are insufficient for Step 2 structure checks.

After explicit `$codexqb` activation, validate through the loader-bound skill root:

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step2 --strict
```

If the active loader path or launcher is unavailable, report `BLOCKED`; do not fall back to a repository-relative, `PATH`-selected, sibling-plugin, or equivalent ad hoc validator.

## Step 3: Sub-Plan QA Audit

After Step 2, CodexQB prints another text block for Goal mode. Copy it, open Goal mode, and send it.

The prompt is:

```text
Use $codexqb. Read and return the exact canonical handoff from references/handoffs/run-step3.md, then execute it.
```

Expected output:

```text
Planner-docs/Sub-Planing-Audit.md
```

Step 3 is an audit step. It reports problems but does not fix the sub-plans.

Step 3 should run the bundled validator first and incorporate its findings into `Planner-docs/Sub-Planing-Audit.md`. After explicit `$codexqb` activation, use:

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step3-preflight --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step3 --strict
```

If the active loader path or launcher is unavailable, report `BLOCKED`; do not synthesize an alternate validator command.

If the validator exits nonzero because it found structural issues, Step 3 should still write the audit unless required source files are missing.

## Step 4: Gated Implementation Handoff

After Step 3, CodexQB may print a Step 4 Goal mode prompt. This prompt is for a separate implementation run; CodexQB itself does not implement product changes during Steps 1-3.

The canonical Step 4 handoff lives in `references/handoffs/run-step4.md`. When CodexQB prints a Step 4 prompt, it may include audit-derived queue details, but the structure must still follow that canonical handoff.

A manual Step 4 handoff request can use this shape:

```text
Use $codexqb. Read and return the exact canonical handoff from references/handoffs/run-step4.md, then execute it only if Planner-docs/Sub-Planing-Audit.md allows implementation.
```

The generated handoff should include the Goal Run Contract, the READY or READY_WITH_WARNINGS implementation queue or `NO_ACTION_REQUIRED`, source precedence, validation gates, stop gates, context-budget and subagent policy, and per-slice reporting requirements.

CodexQB should print the Step 4 prompt only when:

- `Planner-docs/Sub-Planing-Audit.md` exists;
- the audit status is `PASS`, or `PASS_WITH_WARNINGS` with no P0/P1 findings;
- the Step 4 validator passes.

After explicit `$codexqb` activation, check readiness through the loader-bound validator:

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step4 --strict
```

If the active loader path or launcher is unavailable, report `BLOCKED`; no repository-relative fallback is authorized.

If the audit is `BLOCKED` or contains P0/P1 findings, repair the planning package first. If only P2/P3 warnings remain, the implementation prompt may be used but the warnings should stay visible.

The implementation handoff tells Codex to use relevant skills/plugins or subagents by scope, execute the READY/READY_WITH_WARNINGS queue continuously in small reversible slices, test before or with code changes, report exact blockers, avoid secrets, update `Planner-docs/Planing-Ledger.md` with concise implementation summaries, and limit token use by reading the audit/index first and only the active sub-plan afterward.

Step 4 should not stop after the first successful slice. It should continue to the next acceptance criterion or next eligible sub-plan until the queue is complete or a stop gate is hit, such as a P0/P1 finding, failing test, missing source file, required credential/live approval, unsafe external mutation, unrelated dirty worktree, or token/context budget pressure.

Step 4 apply modes are `direct`, `subagent_serial`, `external_superpowers`, and `no_action`. `external_superpowers` requires an explicit availability check before dispatch; if the adapter is unavailable, reconcile the run to `subagent_serial` before implementation. Non-trivial slices should use a fresh-slice implementer when useful, followed by read-only independent spec review, quality review, security review when required, fix/re-review when needed, and final review for the selected batch or queue. Writers and reviewers return structured JSON instead of writing Apply artifacts directly; only the controller persists writer returns through `normalize-writer` and reviewer returns through `normalize-review`. A free-text agent ID is not evidence. The current controller can build a complete receipt chain, but it cannot turn its own lifecycle observations into host-issued identity or completion attestation. Commit, push, PR, deploy, and external mutation remain opt-in.

## Goal Preview and Apply Artifacts

CodexQB 0.3.0 includes dependency-free helpers for local preview and artifact validation. Goal preview, Apply preparation, and Apply validation do not execute implementation. The explicit Apply `run-validation` command does execute one exact safe validation command already authorized by the immutable task plan; it is not a general shell runner.

Compile a Goal preview:

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller goal -- --root /path/to/project --stage step2
```

`<CODEXQB_SKILL_ROOT>` is documentation notation for the absolute root derived by the Codex skill loader from the active `$codexqb` `SKILL.md`. It is not an environment variable and must not be discovered from the target repository, `PATH`, or a sibling plugin.

If that active-loader `SKILL.md`, its canonical root, or `skill_launcher.py` is unavailable, report `BLOCKED` for Goal, Apply, planner validation, and Doctor. Do not invoke a controller directly or substitute a repository-relative, environment-selected, `PATH`-selected, sibling-plugin, or equivalent ad hoc route.

Supported stages are `step15`, `step2`, `step3`, and `step4`. Output is written under the repository-bound external controller-state `goal-runs/<goal-run-id>/` directory as `Goal-Run.json`, `Goal-Prompt.md`, and `Goal-Result.json`. Production derives that state root from the effective account's passwd home and accepts no environment path override. `goal_spec_id` is deterministic for the same source snapshot, mode, objective, and active scope; `goal_run_id` is unique per invocation. `Goal-Run.json` records compiler version metadata, the template bundle digest (`template_bundle_digest`), `goal_policy_digest`, per-subplan `source_subplan_path` and `source_subplan_sha256`, and per-subplan implementation contract digest (`implementation_contract_digest`) values so generated prompts can be tied back to the exact local compiler, templates, source files, structured contracts, and approved policy envelope that produced them. It also records `stage_snapshot`, which treats stage inputs as immutable and expected outputs such as Step 3 audit files, Step 4 ledger updates, and Step 4 implementation paths as mutable resume outputs; Step 4 immutable sub-plan inputs are limited to the selected READY/READY_WITH_WARNINGS queue so deferred sub-plan edits do not break the active batch. Step 2 previews include `active_scope.planning_horizon`, which derives detected phases, active/deferred phases, parent acceptance signals, max detailed sub-plans, max output words, token-risk estimates, review checkpoint, framework ownership need, and algorithmic invariant need from `Main-Planing.md` before detailed sub-plans exist. Step 2/3 previews also include active sub-plan inventory, structured `implementation_contract` objects, contract-signal summaries, and `validation_command_ids` when present. Step 4 previews include READY/READY_WITH_WARNINGS audit queue entries plus each ready sub-plan's structured `implementation_contract`, `implementation_contract_digest`, contract-signal summary, `validation_command_ids`, and contract-derived `work_steps` for parent signals, implementation paths, validation commands, security review, dependency state, and outputs. `subagent_plan` records fresh-context role plans with model profiles, sandbox posture, and dispatch order; security-required queues include a `security_reviewer` role. `budget_contract` caps selected implementation tasks, subagent attempts, fix cycles, and advertised token ceilings; `token_usage` is `not_observed` unless the runtime supplies usage data.
If a stage prerequisite is missing or the bundled stage validator fails, `Goal-Result.json` is written with `status: blocked` and no `Goal-Prompt.md` execution prompt is produced. Rendering an existing `Goal-Run.json` validates schema, source snapshot, strict validation checkpoints, policy envelope, path policy, and secret hygiene before writing prompt text. Existing run directories are not overwritten unless `--replace` is explicit. `--resume` requires an explicit `--output-dir` for the run being continued.

Goal prepare and render writes are restricted to one direct, non-symlink child of the repository-bound external controller-state `goal-runs/` directory; render may update only that run's `Goal-Prompt.md`. Legacy in-repository `Planner-docs/Goal-Runs/` trees are archive-only. Traversal, a symlinked managed parent or run directory, and a symlink or special-file final target fail closed.

Create or validate an apply-run artifact directory:

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

The host sends one bounded `codexqb.controller-argv/v1` JSON object to that fixed process through stdin. Put `prepare`, `dispatch`, agent lifecycle records, transitions, normalization, evidence capture, validation, review publication, reconciliation, and validation arguments in the request object's `argv` array. Put agent/reviewer JSON returns there as data; never paste them into shell argv, `--report-json`, redirection, a heredoc, or a temporary command file. `references/apply-orchestrator.md` contains the canonical request objects and ordered lifecycle. Repeat `dispatch -> record spawned -> normalize-review -> record completed -> publish-review` for `quality`, required `security`, and `final`.

`recover-lock`, `reconcile`, and `finalize` are separate maintenance/fail-closed actions represented by their own stdin request objects, not a sequential continuation of the lifecycle. The current controller-only protocol cannot satisfy the host-attestation prerequisite, so every `finalize` request is expected to fail closed.

Output is written under the repository-bound external controller-state `.codexqb/apply-runs/<apply-run-id>/` directory as `Apply-Run.json`, `Progress.json`, `Events.jsonl`, optional `Writer-Lock.json`, per-task `AR-<apply-run-id>-T<nnn>/` brief/dispatch/agent-run/report/review/fix artifacts, `Final-Review.json`, and `Result.json`. `apply_spec_id` is deterministic for the selected mode, source snapshot, workspace baseline, and READY queue; `apply_policy_digest` binds the approved workspace, readiness, safety, budget, agent-profile, and external-adapter policy envelope; `apply_run_id` is unique per invocation. `prepare` runs strict Step 4 validation before writing action artifacts, records validator evidence in `Apply-Run.json`, and records a `workspace_baseline` with branch/base commit plus canonical no-exec Git plumbing evidence for HEAD/index state, staged changes, unstaged tracked content, untracked inventory, and a direct content manifest for the entire worktree except explicit CodexQB/runtime cache exclusions. That full inventory performs two no-follow, descriptor-relative traversals bound to one root and mount identity; its shared contract allows at most 100,000 paths, 64 MiB per file, 512 MiB read across both passes, and 60 seconds, with limit, identity, or nested-mount failures rejected rather than downgraded. This evidence capture does not provide a general filesystem sandbox. Historical status/diff-named hash fields carry the versioned canonical evidence digests, not porcelain or patch bytes. It then derives initial task briefs from Step 4 READY/READY_WITH_WARNINGS audit entries. Direct hashing means Git index visibility flags and ignore rules cannot hide a contract-external content mutation. Each queued task carries the active sub-plan's `source_subplan_path`, `source_subplan_sha256`, full structured `implementation_contract`, `implementation_contract_digest`, `task_contract_digest`, finding IDs, dependency state, exact planned `validation_commands`, `validation_command_ids`, and `security_review_required` flag into `Progress.json`, `Brief.md`, verified reports, and subagent dispatch prompts. `Apply-Run.json` and `Result.json` carry the same `budget_contract` and `token_usage`; the controller enforces the selected-task cap, per-role attempt cap, and fix-cycle cap while reporting token usage as `not_observed` unless runtime usage is available. Action modes reject non-Git workspaces by default; pass `--allow-non-git-unsafe` only when the user explicitly approves `workspace_mode: non_git_unsafe` with `user_approval: true`. Action modes also reject dirty or protected current Git worktrees by default; pass `--allow-unverified-git-worktree` only when the user explicitly approves `workspace_mode: unverified_current_worktree` with recorded `worktree_path`, `base_branch`, `working_branch`, and `dirty_state`. The default commit policy is `none`.

After implementation reaches `IMPLEMENTED`, run `capture-evidence`. The controller writes `Review-Package.patch` and a signed `Change-Set-<nn>.json` containing the live repository-state digest and before/after hashes for contract-bound changed files. Then run `run-validation` once for every planned validation ID. On supported POSIX hosts, each validation receives a minimal child environment and a separate process group; inherited proxy/Git/Python/pytest and arbitrary credential variables are removed, Python user-site and pytest plugin autoload are disabled, and combined output is capped at 8 MiB. Before the command executes, macOS denies process creation with the fixed system `sandbox-exec`, while supported Linux x86-64/ARM64 hosts install `no_new_privs` and an architecture-bound seccomp filter that allows same-process threads but denies process-forming fork/clone calls. The process group is killed on every exit as defense in depth. Missing enforcement and unknown Linux syscall architectures fail closed. This prevents `setsid`/double-fork descendants from escaping validation cleanup; it does not enforce file or network access. Each signed receipt binds the full planned command, normalized cwd, expected and actual exit status, start/finish time, stdout/stderr digests, relevant artifact hashes, run/registration/task/contract context, implementation generation, and live repository digest. The receipt records the declared network posture and explicitly records sandbox, approval, and network-enforcement proof as `not_observed` when the host supplies no independent proof; descendant containment does not prove network denial or a general host sandbox, and CodexQB never invents stronger isolation evidence.

Review evidence is phase-aware. For each phase, `dispatch` and both `record-agent` lifecycle calls use the same `--review-phase`. The read-only reviewer returns exactly one structured JSON payload; the controller must run `normalize-review` before `record-agent --status completed`, then may call `publish-review`. Publish `spec`, then `quality`, then `security` when required, and finally `final`. Every signed review receipt binds the controller-recorded AgentRun, normalized report, patch, code snapshot, and complete validation-receipt set. For each validation ID and review phase, the reference must point to the latest matching publish event; a newer failed command or review makes every older passing receipt stale. This freshness rule sees only the current local unkeyed event history: a coordinated `Progress.json` plus complete event-tail rollback requires host-bound freshness or an external monotonic anchor to detect, so it cannot authorize trusted verification. AgentRuns record `identity_assurance: controller_asserted`; the normalization event records `host_completion_proof: not_observed`. A receipt from another run/task, a modified or reused receipt, a stale repository digest, stale publish sequence, missing planned command, or wrong review order is rejected. `subagent_serial` can produce a complete but unattested chain; `direct` cannot produce that reviewer chain at all. Until a host-issued agent attestation contract is available, transition to `VERIFIED` fails with `trusted_verified_requires_host_agent_attestation=<task-id>` and `finalize` remains blocked.
Explicit Apply output directories must be direct, non-symlink children of the repository-bound external controller-state `.codexqb/apply-runs/` directory. Destructive `--replace` additionally requires a structurally valid schema-v3 `Apply-Run.json`, a matching full-manifest marker, and a run/root-inode-bound registry receipt under that directory's `.codexqb-run-registry/`. The receipt is authenticated with a private HMAC key stored at `<passwd-home>/.codex/codexqb-trust/apply-run-hmac-v1.key`; `<passwd-home>` is resolved from the effective UID through the passwd database. Production ignores `HOME`, `CODEXQB_TRUST_ROOT`, and `CODEXQB_CONTROLLER_STORE_ROOT`; tests use only a private injected home provider. The passwd-home ancestor chain must be root- or owner-controlled and not group/world-writable; only deny-only macOS ACL entries are tolerated on that ancestor/home chain. `.codex` must be owner-controlled, not group/world-writable, and have no granting ACL. `codexqb-trust`, `controller-state-v1`, repository identity, registry, and run directories must be owner-owned mode `0700` with no ACL; trust-state, binding, and key files must be owner-owned mode `0600`. The adjacent `apply-run-hmac-v1.state.json` binds the initialized key ID; if the key is deleted or replaced, CodexQB reports recovery-required instead of silently rotating it and splitting existing receipts across trust domains. Run initialization stays on the freshly created run descriptor, writes the marker near the end, and publishes the signed receipt last. Copied, partial, self-attested, or synthetically registered repository artifacts are insufficient. Apply schema-v1 and schema-v2 artifacts and legacy in-repository Apply trees are archive-only and cannot be validated, resumed, replaced, trusted-verified, or finalized; preserve/archive them and generate a new external v3 run. Repository roots, unmanaged directories, nested descendants, symlinked paths, mounts, changed root/parent/run identities, incomplete manifests, and synthetic manifests are rejected before deletion. Managed run creation requires directory-descriptor and no-follow filesystem primitives; replacement additionally requires atomic no-replace rename support. Unsupported hosts fail closed instead of falling back to path-based deletion. A restore conflict leaves the random `.codexqb-delete-*` quarantine intact; a stale receipt, missing trust key, or interrupted deletion can leave a preserved but intentionally unregistered run. These recovery-required states block later replacement or recreation until the operator inspects and handles the preserved content manually. The HMAC protects against repository-contained, copied, and synthesized artifacts; a malicious process with access to the same OS account and trust key is outside this boundary.

For schema-v3 runs, the same signed provenance is mandatory for `validate` and `--resume`; if final receipt publication fails, the partial directory is preserved but cannot be resumed or replaced. Schema-v1 or schema-v2 is not treated as proof of trusted legacy origin because repository data can be rewritten; both are rejected even when their schema-bound digest and IDs are internally consistent. If the trust key is lost or mismatched, restore both `apply-run-hmac-v1.key` and its matching state JSON from a trusted backup, keeping the trust directory owner-only and the files mode `0600`. If no backup exists, preserve and inspect/archive all affected runs and receipts before deliberately establishing a new trust domain. Removing or resetting key/state makes every old receipt permanently unverifiable; CodexQB never performs this reset automatically.

Normal Apply mutations accept only a registered and HMAC-verified direct, non-symlink child of the repository-bound external controller-state `.codexqb/apply-runs/` directory, and reject symlinked managed parents, run/task directories, and final targets. Goal and Apply share `scripts/artifact_io.py`: it creates a random same-directory temporary with `O_EXCL | O_NOFOLLOW`, completes short writes, `fsync`s the file, atomically replaces the destination relative to its opened directory, `fsync`s that directory, and removes an uncommitted temporary on failure. Apply serializes each cooperating run mutation with a run-directory `flock`. Under that lock, `Events.jsonl` is parsed for a complete, contiguous history and published by full-file atomic replace with one unique next sequence. Each record binds the previous event hash and its own canonical hash; partial trailing lines, malformed JSON, duplicate or reordered sequences, and broken hash links fail closed. A post-replace directory-`fsync` failure is reconciled against the exact intended bytes under the lock and retried; `event_log_commit_state_unknown` means inspect and validate the file, never blindly repeat the mutation. If validation reports a transition-event/`Progress.json` mismatch, archive the run and prepare a fresh one because automatic multi-file recovery is intentionally unsupported. This is logical append-only behavior with per-file atomicity, not a multi-file transaction. The unkeyed chain has no trusted external head anchor, so deletion of a complete valid tail or full replacement with a recomputed chain is not detectable by the chain alone; it provides an integrity link but is not independent host attestation. Every current unreleased schema-v3 event requires `event_chain_version: 1`; preserve pre-chain v3 development snapshots only as archives and prepare a fresh run. A host without the required descriptor, no-follow, locking, or replace primitives fails closed.

All persistent Goal/Apply JSON, JSONL, Markdown, and patch paths pass through the shared bounded secret policy. It checks semantic decoded JSON/JSONL and duplicate keys, renderer-visible Markdown/control forms, actor, summary, evidence, writer/reviewer payloads, metadata, and other untrusted fields before mutation; create-exclusive writes use the same gate. Writer agents return JSON and the controller persists it through `normalize-writer`; the current report hash and normalization event must match before writer state advances. Out-of-band same-account file changes cannot be intercepted at the OS boundary, so every consumed report also uses bounded no-follow reads and is rescanned. Baseline source bytes are scanned before base64 encoding and after decoding. Raw validation stdout/stderr is scanned before only digests can be published. Secret-shaped run suffixes and managed names fail before directory creation. Credential-shaped content for provider, authorization, URI, contextual credential, JWT, and private-key families causes a fixed-label failure without echoing the matched value; exact canonical placeholders remain valid. Persistent signed evidence is rejected rather than silently redacted, while console/error output is bounded, control-safe, single-line, and redacted.
For `subagent_serial`, send a `codexqb.controller-argv/v1` request through the fixed launcher whose `argv` begins with `dispatch` before implementation. It writes `Dispatch-Packet.json` with `spawn_tool: multi_agent_v1.spawn_agent`, `fork_context: false`, role profile, fresh brief hash, prompt hash, and the exact parent-to-subagent message. After the parent Codex controller calls the actual tool, send a second fixed-launcher request whose `argv` begins with `record-agent` and includes `--status spawned`. Implementer/fixer JSON returns go through a `normalize-writer` request before completion is recorded or state advances; the controller may normalize an enriched report again after live receipts exist. Reviewer lifecycle requests additionally require matching `--review-phase spec`, `quality`, `security`, or `final`; their read-only return must pass through `normalize-review` before completion. The helper does not call Codex tools or receive host-issued agent attestations. It records controller observations so resume, ordering, receipt publication, and re-dispatch are auditable without presenting those observations as trusted identity proof.
Apply validation rejects unsafe validation commands, path-traversal task IDs, non-Git action runs without explicit unsafe approval, dirty or protected current Git worktrees without explicit approval, no-action runs with queued tasks, recursive subagent depth, multiple writers, selected-task/attempt/fix-cycle budget overflow, policy-envelope drift, silent progress overwrite, eventless state jumps, stale writer locks, missing dispatch packets, missing spawned/completed agent lifecycle records, source sub-plan hash or contract drift, workspace baseline drift outside tracked contract paths or exact `state: proposed` untracked paths, agent profile drift, unchecked/unreconciled external Superpowers adapters, malformed or unnormalized review payloads, and completion claims without a signed current live change set, a receipt for every planned successful command, current file/artifact hashes, and ordered passing spec/quality/security-if-required/final review receipts. Any repository change invalidates receipts bound to the previous digest. Even when all controller evidence is complete, trusted verification additionally requires host agent attestation.
`make check` also runs `evals/run_apply_behavior_smoke.py`, which drives the held Apply controller's `prepare`, `dispatch`, `record-agent`, `transition`, `capture-evidence`, `run-validation`, `normalize-review`, `publish-review`, `validate`, `recover-lock`, and `finalize` actions through a test-only launcher harness in a disposable repository. It proves the controller protocol and its fail-closed unattested boundary, not live Codex model identity or host-issued completion attestation. The downstream Goal/Apply dry run has the same limitation and must not be cited as a real attested reviewer-agent run.
`Goal-Run.json` records `goal_run_schema_version: 1`; `Apply-Run.json` records `apply_run_schema_version: 3`. Apply schema-v1 and schema-v2 runs predate the live evidence receipt contract and are archive-only: runtime validation, resume, replacement, trusted verification, and finalization reject them. Preserve/archive them and prepare a new v3 run. The packaged Apply runtime schema reference is `plugins/codexqb/skills/codexqb/references/apply-run-schema.json`; runtime validation remains dependency-free in `scripts/apply_run.py`. The optional development/CI gate installs `requirements-ci.txt` and runs `make check-schema` with a real Draft 2020-12 engine. It validates each filename against its intended `$defs`; the root compatibility `anyOf` is deliberately not used as an acceptance discriminator. Cross-artifact and relational invariants remain runtime checks.

## Direct Step Invocation

You can invoke Step 2 or Step 3 directly:

```text
Use $codexqb to run Step 2 on the existing Planner-docs/Main-Planing.md.
```

```text
Use $codexqb to run Step 3 and audit the existing sub-plans.
```

CodexQB skips the Step 1 repo-aware intake when the requested step is explicit.

You can also invoke Step 1.5 directly when a main plan already exists:

```text
Use $codexqb to run Step 1.5 Autopsy for this existing project.
```

You can also ask for the Step 4 prompt text after a completed audit:

```text
Use $codexqb to print the Step 4 implementation handoff prompt if the audit allows it.
```

## Validator Output

The validator prints deterministic summary lines such as:

```text
planner_docs_validation=passed
validation_status=passed
mode=step2
validation_mode=step2
phase_folder_count=9
subplan_count=35
warning_count=0
error_count=0
```

It uses stable exit codes: `0` means validation passed, `1` means document validation failed, and `2` means invocation/configuration/I/O error. With `--strict`, missing semantic readiness signals, repeated or generic section warnings, unsafe validation commands, high-risk security-review bypasses, unsupported planning scope, and uniform quota anomalies are treated as failures except documented compatibility warnings. Validation command eligibility is shared with Goal/Apply helpers and is deliberately narrow: canonical no-bytecode/no-pytest-cache pytest, no-bytecode unittest, and no-fix/no-cache Ruff checks only. The parser validates the full envelope, tool-specific option grammar, canonical cwd, sensitive/output paths, and shell-free executable token; it does not treat a make target or package-manager script name as proof that an opaque recipe is read-only. Actual execution still requires the controller to enforce the declared no-network/sandbox posture. Secret scanning uses length-bounded token patterns so normal filenames such as `task-spec.yaml` are not flagged. In `--mode step4`, open P0/P1 audit findings block implementation readiness, open or accepted P2/P3 findings require `PASS_WITH_WARNINGS`, resolved/not_applicable P2/P3 findings may coexist with `PASS`, and `NO_ACTION_REQUIRED` is valid when all in-scope rows are COMPLETE, SUPERSEDED, or DEFERRED.

If `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, `Planner-docs/Project-Comprehension.md`, or `Planner-docs/Planing-Ledger.md` exists, the validator checks its required heading order and supported semantic fields during Step 2/3 validation. If these optional continuity docs do not exist, Step 2/3 validation continues without treating them as required. Use `--mode autopsy --strict` after Step 1.5 when `Autopsy.md` should be required.

The repository `make check` also runs the deterministic fixture corpus checker. The fixture corpus keeps static input repos and expected signals healthy; it does not measure live Codex behavior.

## Safety Expectations

CodexQB is not an implementation tool. It is designed to produce planning artifacts only.

If CodexQB finds missing source files or missing planner outputs, it should follow the blocker behavior in the active planner prompt instead of inventing speculative output.
