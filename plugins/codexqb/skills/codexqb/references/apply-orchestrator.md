# CodexQB Subagent Apply Orchestrator

The Apply Orchestrator defines a resumable Step 4 artifact protocol. It does not execute implementation by itself.

## Runtime Location

CodexQB stores Apply artifacts outside the target repository in a fixed, repository-identity-bound controller-state directory:

```text
<passwd-home>/.codex/codexqb-trust/controller-state-v1/<repository-identity>/.codexqb/apply-runs/<apply-run-id>/
  Apply-Run.json
  Progress.json
  Events.jsonl
  Writer-Lock.json
  AR-<apply-run-id>-T<nnn>/Brief.md
  AR-<apply-run-id>-T<nnn>/Dispatch-Packet.json
  AR-<apply-run-id>-T<nnn>/Agent-Run-<role>[-<review-phase>]-<nn>.json
  AR-<apply-run-id>-T<nnn>/Implementer-Report.json
  AR-<apply-run-id>-T<nnn>/Review-Package.patch
  AR-<apply-run-id>-T<nnn>/Change-Set-<nn>.json
  AR-<apply-run-id>-T<nnn>/Validation-Receipt-<validation-id>-<digest>.json
  AR-<apply-run-id>-T<nnn>/Review-Report-<phase>.json
  AR-<apply-run-id>-T<nnn>/Review-Receipt-<phase>-<digest>.json
  AR-<apply-run-id>-T<nnn>/Task-Review.json
  AR-<apply-run-id>-T<nnn>/Fix-Report.json
  Final-Review.json
  Result.json
```

Production derives the controller store from the effective account's passwd home and accepts no `HOME`, `CODEXQB_TRUST_ROOT`, or `CODEXQB_CONTROLLER_STORE_ROOT` path override. Tests may inject a private home provider. Legacy in-repository `.codexqb/apply-runs/` trees are archive-only and cannot be resumed, replaced, mutated, verified, or finalized.
Non-`no_action` runs derive initial task briefs from Step 4 READY or READY_WITH_WARNINGS entries in `Planner-docs/Sub-Planing-Audit.md` when available. The audit-derived source sub-plan path and hash are recorded in both `Progress.json` and `Brief.md`.
When present in the active sub-plan, the controller also copies the source sub-plan SHA-256, the full structured Implementation Contract, `implementation_contract_digest`, `task_contract_digest`, and fresh-context contract signals into each task: acceptance criteria, allowed/forbidden paths, parent signals, dependencies, framework ownership, algorithmic invariants, planned validation commands, `validation_command_ids`, outputs, risk/security requirements, and the security review flag. The same structured contract is included in `Brief.md`, verified reports, and subagent dispatch prompts so fresh agents can work from the task contract without inheriting parent chat history.
The launcher-backed Apply `prepare` operation must run strict Step 4 validation before writing action artifacts. `Apply-Run.json.step4_readiness` records validator status, a validator output hash, and the execution queue state used to accept READY tasks or `NO_ACTION_REQUIRED`.
Every Apply operation named in this section is invoked only through the exact
launcher command shown with each request below. Dynamic root, run, task, agent,
report, and body values exist only in the adjacent non-executable JSON data
object. The host process must pass exactly one bounded object directly to the
child process's stdin. Never materialize a request with echo, printf, a pipe,
redirection, a heredoc, command substitution, environment variables, shell
interpolation, or a temporary/repository file. If direct host-to-child stdin is
unavailable, stop as `BLOCKED`.

Use `prepare` for new runs; `init` remains a compatibility alias. Use `dispatch` before `subagent_serial` implementation to write a fresh-context `Dispatch-Packet.json` that can be converted into a Codex `multi_agent_v1.spawn_agent` call by the parent agent. After the parent calls the actual Codex tool, use `record-agent` to record the spawned agent ID and later the completed or failed result. Implementers and fixers return one structured JSON payload and write no Apply artifact; the controller must pass it to `normalize-writer` before recording completion or advancing writer state. Writer normalization rejects fields outside the public report schema. A `PENDING` report is the exact one-field placeholder; the first accepted controller-normalized writer report records task/agent identity and writer output, while later evidence-bound completion adds immutable contract, change-set, diff, and receipt digests. Reviewer dispatch and lifecycle calls must carry the matching `--review-phase spec`, `quality`, `security`, or `final`. Reviewers stay read-only and return exactly one structured JSON payload; the controller passes that payload to `normalize-review` before `record-agent --status completed`. Use `transition` for state changes so `Events.jsonl` remains the append-only transition truth. After implementation reaches `IMPLEMENTED`, use `capture-evidence`, then run `run-validation` for every planned validation ID and normalize the enriched writer report again so it binds the controller-issued receipt, change-set, contract, and patch digests. After the controller normalizes a reviewer return and records that lifecycle completed, use `publish-review` to issue its signed completion receipt. Use `recover-lock` only for expired writer locks to move an abandoned `IMPLEMENTING` task to `BLOCKED` or `NEEDS_CONTEXT`. Use `reconcile` for external adapter fallback before dispatch. `finalize` remains fail-closed until every task is VERIFIED, which the current controller-only evidence protocol cannot achieve without host-issued agent attestation. `Progress.json` is the current state snapshot.

The evidence and review portion of the public CLI is:

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["normalize-writer","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--role","implementer","--agent-id","<agent-id>","--report-json","{\"status\":\"DONE\",\"task_id\":\"<task-id>\",\"implementer_agent_id\":\"<agent-id>\",\"files_changed\":[\"src/example.py\"],\"concerns\":[]}","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["record-agent","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--role","implementer","--agent-id","<agent-id>","--status","completed","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["transition","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--to","IMPLEMENTED","--actor","<agent-id>"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["capture-evidence","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["run-validation","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--validation-id","VAL-01","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["dispatch","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--role","task_reviewer","--review-phase","spec","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["record-agent","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--role","task_reviewer","--review-phase","spec","--agent-id","<agent-id>","--status","spawned","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["normalize-review","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--review-phase","spec","--agent-id","<agent-id>","--report-json","{\"status\":\"COMPLETE\",\"phase\":\"spec\",\"verdict\":\"pass\",\"task_id\":\"<task-id>\",\"reviewer_agent_id\":\"<agent-id>\",\"evidence\":[\"reviewed current patch and receipts\"]}","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["record-agent","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--role","task_reviewer","--review-phase","spec","--agent-id","<agent-id>","--status","completed","--actor","controller"]}
```

```bash
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- request-stdin
```

```json
{"schema":"codexqb.controller-argv/v1","argv":["publish-review","--root","<project-root>","--run-dir","<run-dir>","--task-id","<task-id>","--review-phase","spec","--actor","controller"]}
```

Repeat the read-only reviewer lifecycle with `task_reviewer`/`quality`, then `security_reviewer`/`security` when required, and finally `final_reviewer`/`final`. The order is always `dispatch -> record spawned -> normalize-review -> record completed -> publish-review`. `publish-review` requires the matching controller-recorded completed lifecycle and normalized phase report; it cannot manufacture a host-issued reviewer identity or completion attestation.

`apply_spec_id` is deterministic for the selected mode, source snapshot, workspace baseline, and Step 4 READY queue. `apply_run_id` is unique per invocation. Explicit output directories must be direct, non-symlink children of the repository-bound external controller-state `.codexqb/apply-runs/` directory. To continue a schema-v3 run, pass `--resume` with the exact `--output-dir`. Apply schema-v1 and schema-v2 artifacts and legacy in-repository Apply trees are archive-only: they cannot be validated, resumed, replaced, trusted-verified, finalized, or migrated by synthesizing receipts. Preserve/archive them and create a new external v3 run. To intentionally regenerate a v3 run, pass `--replace`. Replacement requires a complete manifest digest, matching marker, run/root inode binding, and a registry receipt authenticated by the private HMAC key at `<passwd-home>/.codex/codexqb-trust/apply-run-hmac-v1.key`. Its adjacent trust-state record binds the initialized key ID: a missing or mismatched key is recovery-required and is never silently rotated. Initialization writes through the freshly created run descriptor and publishes that receipt only after all initial artifacts and the marker are durable. Copied, partial, self-attested, unsigned, and pre-registration runs fail closed on replacement. The replace guard binds the entry repository root descriptor, then rejects the repository root, unmanaged or nested directories, indirect targets, mounts, and changed root/parent/run identities before deletion. Managed run creation requires directory-descriptor and no-follow filesystem primitives; replacement additionally requires atomic no-replace rename support. Unsupported hosts fail closed instead of falling back to path-based deletion. Quarantine conflicts, stale registry receipts, missing trust keys, and interrupted deletion states block later replacement/recreation until manually inspected. The HMAC boundary does not claim protection from a process that can read the same OS account's trust key.

Normal Apply mutations open only a registered and HMAC-verified direct run child, then open its task directory and artifact names relative to retained descriptors. A symlinked managed parent, run/task directory, or final target fails closed. Shared `scripts/artifact_io.py` replacement uses a random same-directory `O_EXCL | O_NOFOLLOW` temporary, a full write loop, file `fsync`, descriptor-relative atomic replace, directory `fsync`, and cleanup before commit. The controller holds a run-directory `flock` across each cooperating mutation. `Events.jsonl` is parsed as a complete contiguous history and published by full-file atomic replace with the unique next sequence while that lock is held. Each event binds `previous_event_sha256` and a canonical `event_sha256`; partial trailing lines, malformed records, colliding or reordered sequences, and broken links fail closed. If directory `fsync` fails after replace, the controller reconciles exact intended bytes under the lock and retries; `event_log_commit_state_unknown` requires inspection and validation, not a blind mutation retry. A transition-event/`Progress.json` mismatch fails validation and has no automatic multi-file recovery; archive the run and prepare a fresh one. This preserves logical append-only behavior with per-file atomicity, not a multi-file transaction. The unkeyed chain has no trusted external head anchor and therefore does not detect deletion of a complete valid tail or whole-file replacement with a recomputed chain; it is an integrity link rather than independent host attestation. The current unreleased schema-v3 contract requires `event_chain_version: 1`, so pre-chain v3 development snapshots are archive-only and require a fresh run. Hosts without the required descriptor, no-follow, locking, or replace primitives fail closed.

Every persistent Apply JSON, JSONL, Markdown, and patch write also passes the shared bounded secret gate. It rejects duplicate JSON keys and scans decoded structured credential pairs, adjacent name/value fields, renderer-visible Markdown/control forms, actor, summary, evidence, payload, metadata, run names, and raw validation stdout/stderr before a mutation can publish partial state or a receipt. Implementer/fixer returns are untrusted JSON inputs: only the controller-owned `normalize-writer` path may persist them, and later validation rehashes the report and its normalization event. Out-of-band same-account file changes are outside OS-level interception, so every consumed artifact is read through a bounded no-follow gate and rescanned. Repository baseline bytes are checked before base64 encoding and after decoding. A finding rejects the artifact with detector labels only; exact canonical placeholders remain valid. Signed evidence is never silently rewritten, while CLI diagnostics are bounded and redacted through the same policy. The owner-only binary HMAC key in the external trust store is the sole intentional non-artifact exception.

Current schema-v3 runs must contain `apply_run_registration_id` and pass marker/receipt provenance verification for validate and resume as well as replace; changing the schema to v1/v2 and recomputing repository-contained IDs cannot downgrade them into a trusted legacy format. A final receipt-publish failure leaves a preserved, non-resumable partial run. For key recovery, restore the matching owner-only key and state record together from trusted backup. Without a backup, preserve and inspect/archive affected runs and receipts before creating a new trust domain; resetting key/state permanently invalidates old receipts and is never automatic.

## Schema Contract

New runs use `apply_run_schema_version: 3`. This Apply-specific bump does not change the planner `artifact_schema_version: 3` or `handoff_contract_version: 2` contracts.

`Apply-Run.json` is the immutable run envelope: schema versions, requested mode, current mode, spec/run IDs, `apply_policy_digest`, source snapshot, `workspace_baseline`, Step 4 readiness summary, workspace posture, `budget_contract`, `token_usage`, safety defaults, agent profiles, verification policy, and external adapter policy. The policy digest is recomputed during validation from the approved workspace, readiness, safety, budget, agent-profile, verification, and external-adapter envelope so self-consistent tampering is rejected. The baseline records branch/base commit, Git status and staged/unstaged diff hashes, untracked inventory hash, and a direct content manifest for the entire worktree except explicit CodexQB/runtime cache exclusions; this prevents `assume-unchanged`, `skip-worktree`, or Git ignore rules from hiding contract-external mutations. Non-Git runs use the same full file inventory. Workspace posture records `workspace_requested`, `workspace_detected`, `workspace_verified`, `workspace_mode`, `worktree_path`, `base_branch`, `working_branch`, `dirty_state`, and `user_approval`. `.codexqb/` runtime artifacts are excluded from these baseline hashes. `Progress.json` is mutable operational state: task list, task states, dispatch status, phase-aware agent runs, current change-set reference, validation-receipt references, review-receipt references, writer locks, verified task IDs, final-review requirement, fix-cycle count, and resume cursor. `Events.jsonl` is the append-only transition truth. Per-task directories use the exact task ID and contain the brief, dispatch packet, agent-run records, implementer report, controller patch/change set, validation receipts, phase reports/review receipts, task review, and fix report. `Final-Review.json` aggregates the signed per-task review references. `Result.json` records finalized task IDs, budget/token state, and the finalization event; the receipt artifacts and their `Progress.json` references remain the detailed verification provenance.

For a task to become `VERIFIED`, `capture-evidence` must first publish a signed controller-owned change set for the current implementation generation. It generates `Review-Package.patch` from the live repository and binds the patch digest, contract, baseline/current snapshot digests, and before/after hashes for every changed contract path. Verification re-reads and rehashes the live files and patch. A later content or patch change invalidates every command or review receipt bound to the previous repository-state digest.

`run-validation` must then succeed exactly once for every planned validation ID. Each command runs in a separate POSIX process group with a minimal allowlisted environment; inherited proxy, Git, Python, pytest, credential, and arbitrary parent variables are not forwarded, Python user-site and pytest plugin autoload are disabled, and combined stdout/stderr is capped at 8 MiB. Timeout or output overflow terminates and reaps the process group before any receipt can be published; a host without the required secure process-isolation primitive fails closed. Each signed command receipt binds the run registration, task and contract, implementation generation, change-set ID and repository-state digest, full planned command digest and argv, normalized cwd, expected/actual exit code, timeout/termination state, start and finish time, stdout/stderr/combined digests, and relevant artifact hashes. It also records the planned network posture and explicit host sandbox, approval, and network-enforcement proof status. Those host proof fields remain `not_observed` when CodexQB has no trusted host attestation; environment/process isolation does not prove network denial, and the receipt must not invent enforcement it did not observe.

Review evidence requires a phase-aware, controller-recorded AgentRun and normalized `Review-Report-<phase>.json` before `publish-review` can sign a receipt. The receipt binds that AgentRun, report, patch, code snapshot, and complete command-receipt set. The required order is `spec`, then `quality`, then `security` when the task requires it, and finally `final`. For each validation ID and review phase, the accepted reference must be the latest matching receipt-publish event; a newer failure invalidates every older passing receipt. This local latest-event rule does not detect coordinated rollback of both `Progress.json` and a complete valid event tail because the unkeyed chain has no external monotonic head; future trusted verification must bind freshness to host attestation or such an anchor. Missing, modified, stale, cross-run/cross-task, duplicate/reused, wrong-order, or non-passing receipts are rejected. AgentRuns carry `identity_assurance: controller_asserted`; the `review_report_normalized` event carries `host_completion_proof: not_observed`. These fields honestly describe controller observation and do not constitute host-issued attestation. Consequently, a complete controller evidence chain is complete/unattested: the current `VERIFIED` transition fails with `trusted_verified_requires_host_agent_attestation=<task-id>`, and `finalize` remains blocked. Free-text agent IDs or report verdicts are not substitutes for either the signed chain or host proof.

Implementation drift may include tracked unstaged files listed in the task contract and reported by the implementer/fixer. Untracked new files are accepted only for exact contract paths whose `implementation_paths` entry declares `state: proposed`; staged files and contract-external files remain blockers.

The default budget contract caps selected implementation tasks at 4, subagent attempts per role at 2, and fix cycles at 2. Token ceilings are recorded for planning discipline, but runtime token usage remains `not_observed` unless the controller receives real usage data. Validators reject artifacts that raise attempts or fix cycles above the recorded budget, exceed the selected-task cap, or claim partial unobserved token usage.

Action modes (`direct`, `subagent_serial`, and `external_superpowers`) must not prepare against a non-Git workspace by default. If a non-Git workspace is unavoidable, the caller must pass `--allow-non-git-unsafe`; `Apply-Run.json` then records `workspace_mode: non_git_unsafe` and `user_approval: true`. Without that explicit approval, prepare fails with `non_git_workspace_requires_explicit_approval`. `no_action` mode may record a non-Git workspace without this unsafe approval because it does not queue implementation tasks.

Action modes must also treat protected or dirty Git current worktrees as unverified. If `working_branch` is `main`, `master`, or `unknown`, or `dirty_state` is `dirty`, prepare fails unless the caller passes `--allow-unverified-git-worktree`; the resulting artifact records `workspace_mode: unverified_current_worktree` and `user_approval: true`. A future verified isolated worktree controller may use `workspace_mode: verified_isolated_worktree`.

The packaged public schema reference is `references/apply-run-schema.json`. Runtime validation remains dependency-free in `scripts/apply_run.py`; the schema file exists so users, reviewers, and generated package checks can inspect the artifact contract without reverse-engineering Python code.

## Modes

- `direct`: parent-only execution for a bounded selected batch. It may implement, capture the live change set, and run planned validation, but it cannot independently publish the reviewer receipt chain.
- `subagent_serial`: parent controller dispatches one fresh implementer at a time, then runs read-only independent reviews. It can build a complete controller-evidence chain, but that chain remains unattested until the host supplies identity/completion proof and therefore cannot currently reach `VERIFIED` or finalize.
- `external_superpowers`: optional adapter when Superpowers is already installed; CodexQB remains top-level controller. Availability must be checked before dispatch. If unavailable, run the launcher-backed Apply `reconcile` operation so the artifact mode becomes `subagent_serial` before implementation starts.
- `no_action`: record NO_ACTION_REQUIRED without starting implementation.

## State Machine

Allowed task states:

- `PREFLIGHT`
- `BRIEFED`
- `IMPLEMENTING`
- `IMPLEMENTED`
- `TASK_REVIEW`
- `SECURITY_REVIEW`
- `FIXING`
- `RE_REVIEW`
- `VERIFIED`
- `BLOCKED`
- `NEEDS_CONTEXT`

Each active slice must publish a passing spec receipt before quality, a passing quality receipt before security/final, and a passing security receipt when required before final. Failed review requires same-slice fix, a new change-set generation, re-running every planned validation, and fresh ordered review receipts. A passing final controller receipt completes the controller evidence chain but does not bypass the separate host-attestation gate for `VERIFIED`.
Existing apply-run directories are not overwritten by default. Use explicit resume/replace behavior when continuing or intentionally regenerating artifacts.

Transitions must follow:

```text
PREFLIGHT -> BRIEFED
BRIEFED -> IMPLEMENTING | BLOCKED | NEEDS_CONTEXT
IMPLEMENTING -> IMPLEMENTED | BLOCKED | NEEDS_CONTEXT
IMPLEMENTED -> TASK_REVIEW
TASK_REVIEW -> SECURITY_REVIEW | FIXING | VERIFIED
FIXING -> RE_REVIEW | BLOCKED | NEEDS_CONTEXT
RE_REVIEW -> SECURITY_REVIEW | VERIFIED | FIXING
SECURITY_REVIEW -> VERIFIED | FIXING | BLOCKED | NEEDS_CONTEXT
```

`IMPLEMENTING` acquires `Writer-Lock.json` atomically. Leaving `IMPLEMENTING` releases it. Expired writer locks are validation blockers until `recover-lock` records a recovery transition to `BLOCKED` or `NEEDS_CONTEXT`. Validation rejects state snapshots that are not backed by a contiguous transition event.

For `subagent_serial`, `BRIEFED -> IMPLEMENTING` additionally requires `Dispatch-Packet.json` plus a `record-agent --status spawned` event for the implementer. `IMPLEMENTING -> IMPLEMENTED` requires both a matching controller `normalize-writer` report binding and `record-agent --status completed` for that implementer attempt; `FIXING -> RE_REVIEW` requires the equivalent current fixer binding. Failed agent starts are recorded with `--status failed`; after that, the controller may prepare a new dispatch packet for the same task before implementation starts. Reviewer packets and agent records use `--review-phase spec|quality|security|final`; attempts are tracked per role and phase. A reviewer completion additionally requires a prior matching `normalize-review` event. The packet records `spawn_tool: multi_agent_v1.spawn_agent`, role, review phase when applicable, profile, sandbox, fresh brief hash, prompt hash, `fork_context: false`, and the exact message the parent Codex controller should pass to the subagent. The script prepares and validates these artifacts but does not call Codex tools or observe host-issued agent identity/completion proof itself.

## Role Templates and Model Profiles

Fresh-context role templates live under `references/apply/`:

- `controller.md`
- `implementer.md`
- `task-reviewer.md`
- `security-reviewer.md`
- `fixer.md`
- `final-reviewer.md`

`Apply-Run.json` includes role-level `agent_profiles` with stable model profiles instead of hardcoded model names: `fast`, `balanced`, `strong`, `security_strong`, and `inherit` when a user explicitly asks to inherit the active session. Reviewers default to read-only sandboxes; the implementer and fixer are the only default workspace-write roles.

## Review Result Shape

Each read-only reviewer returns exactly one structured JSON payload. The reviewer does not write the phase report; the controller persists the payload with `normalize-review`:

```json
{
  "status": "COMPLETE",
  "phase": "spec",
  "verdict": "pass",
  "task_id": "AR-apply-subagent_serial-<digest>-<invocation>-T001",
  "reviewer_agent_id": "reviewer-1",
  "evidence": ["reviewed the current patch and complete validation receipt set"]
}
```

All payloads require `status: COMPLETE`, a matching `phase`, `task_id`, `reviewer_agent_id`, non-empty `evidence`, and generic `verdict`. Spec accepts `pass`, `fail`, or `cannot_verify`; quality, security, and final accept `pass`, `fail`, `needs_fixes`, or `cannot_verify`. `security` is omitted only when the task contract marks it not required. The controller must run `normalize-review` before `record-agent --status completed`; that completed AgentRun captures the normalized report path and SHA-256. `publish-review` rehashes it, rejects post-completion substitution, checks the matching phase-aware AgentRun and all prior receipts, and writes `Review-Receipt-<phase>-<digest>.json`. `Task-Review.json` and `Final-Review.json` are controller aggregates of those signed references. This chain is evidence-complete but remains unattested when the host supplies no agent proof.

## Safety

- Commit policy defaults to `none`.
- Commit, push, PR, deploy, live probes, and destructive external mutation are opt-in only.
- Only one writer modifies files per slice unless the user explicitly requests separate branches or worktrees.
- Subagents are read-only by default except the selected fresh-slice implementer.
- Required or performed security review must have a distinct read-only `security_reviewer` return normalized before its controller-recorded completion and signed security review receipt; free-text identity fields cannot authorize verification.
- `subagent_serial` implementation must have a dispatch packet and spawned agent record before writer lock acquisition, then a controller-normalized current writer report plus a completed matching AgentRun before the task can move to `IMPLEMENTED` or `RE_REVIEW`.
- `Progress.json` is the authoritative operational state for resume.
- `Events.jsonl` is the logical append-only transition truth; under the run-directory `flock`, the complete chain-validated file is atomically replaced with one unique, contiguous next sequence whose previous-hash/hash link verifies.
- `Apply-Run.json.workspace_baseline` must match the current workspace baseline before resume; mismatches are blockers until the controller reconciles or starts a new run.
- JSON snapshots use random same-directory `O_EXCL | O_NOFOLLOW` temporaries, full writes, file/directory `fsync`, atomic replace, and pre-commit cleanup; this does not make a multi-file mutation transactional. Writer lock uses create-exclusive semantics and expired locks must be recovered with an explicit controller event.
- `no_action` runs must not contain queued tasks.
- Task IDs must use the controller-generated `AR-<apply-run-id>-T<nnn>` format and resolve inside the apply-run directory.
- `external_superpowers` runs must record adapter availability and metadata before dispatch; unavailable adapters must be reconciled to `subagent_serial`.
- Controller evidence completeness requires a current signed live change set, receipts for every planned successful validation command, current file/artifact hashes, controller-normalized read-only reviewer returns, controller-recorded AgentRuns, and passing signed spec/quality/security-if-required/final receipts in order. Trusted `VERIFIED` additionally requires host-issued agent attestation. The current runtime has no such host proof input and fails closed rather than promoting controller assertions.
