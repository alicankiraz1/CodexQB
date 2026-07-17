# CodexQB

[![validate](https://github.com/alicankiraz1/CodexQB/actions/workflows/validate.yml/badge.svg?branch=main)](https://github.com/alicankiraz1/CodexQB/actions/workflows/validate.yml)

**Vibecoding-first repo planning for Codex.** CodexQB turns a project repository into a durable planning package: main plan, existing-project autopsy, optional project comprehension, project ontology, planning ledger, phase sub-plans, QA audit, and a gated implementation handoff.

![CodexQB source-bound workflow and release validation](docs/assets/codexqb-workflow.png)

The diagram shows the current 0.3.0 flow: repo-aware intake, existing-project autopsy and comprehension, source-bound sub-plans, P0/P1-gated QA audit, digest-verified Goal/Apply runs, public privacy scanning, and dual-artifact release validation.

CodexQB is a Codex plugin that installs the `$codexqb` skill. It is built for software, AI, infrastructure, security, and automation projects where planning needs to be evidence-backed, reviewable, adaptive, and ready for small verified execution slices.

The unreleased 0.3.0 development line hardens CodexQB's Goal/Apply path from planning handoff through release evidence. Goal previews now bind every implementation contract to its source sub-plan path and SHA-256 hash, record stage-aware source snapshots, and separate expected mutable outputs from immutable planning inputs so normal Step 3/4 progress does not look like source drift. Apply runs carry the same source binding into task briefs, dispatch packets, reports, and results with contract digests, bounded budgets, honest token-usage reporting, and stricter validation around subagent attempts, fix cycles, writer locks, workspace drift, and review evidence.

Repository marketplace distribution remains the primary installation route. The release foundation adds capability-aware mount identity, a dependency-free doctor, split validation gates, a deterministic fixture corpus, and two unambiguous reproducible distributions: a marketplace-ready plugin-root ZIP and a full source ZIP. The feedback closeout includes sanitized live `subagent_serial` evidence for the earlier Apply lifecycle, but that evidence does not by itself prove the new schema-v3 receipt chain; a fresh live v3 E2E run is required before making that stronger claim. Final release tagging remains a separate clean-provenance gate.

Release contracts:

```text
plugin_version: 0.3.0
artifact_schema_version: 3
handoff_contract_version: 2
goal_run_schema_version: 1
apply_run_schema_version: 3
budget_schema_version: 1
```

0.3.0 hardening highlights:

- Source-bound Goal and Apply artifacts: `source_subplan_path`, `source_subplan_sha256`, `implementation_contract_digest`, `task_contract_digest`, validation command IDs, parent acceptance signal IDs, risk class, and risk domains are propagated through generated run artifacts.
- Stage-aware resume safety: Goal runs snapshot immutable planning inputs while allowing expected mutable outputs such as Step 3 audits, Step 4 ledger updates, and declared implementation paths.
- Bounded execution metadata: Goal and Apply artifacts include `budget_contract`; Apply validation enforces selected-task, per-role attempt, and fix-cycle limits while reporting runtime token usage as `not_observed` unless a real usage source is available.
- Receipt-bound Apply evidence: Apply schema v3 binds a controller-captured live change set, every planned validation command, and ordered spec, quality, optional security, and final controller-recorded reviewer lifecycles to the same run, task, contract, and repository-state digests; host attestation remains a separate fail-closed verification gate.
- Public release privacy checks: `make check-public-privacy` scans designated public release files and release evidence for local user paths, attachment paths, UUID-like attachment identifiers, and live Codex agent/thread IDs before release sharing.
- Sanitized live evidence: release evidence is redacted, reviewable, and labeled with its schema/protocol scope; raw local runtime logs stay out of public docs, and older lifecycle evidence is not presented as proof of the schema-v3 receipt chain.
- Capability-aware repository safety: Linux fdinfo, descriptor-bound `statx`, descriptor-bound `name_to_handle_at`, and Darwin `fstatfs` share one provider/assurance model. Filesystem device identity remains diagnostic-only; evidence and mutation paths fail closed without a descriptor-bound mount identity.
- Dependency-free diagnostics: `doctor.py` emits human-readable or stable JSON capability reports without raw mount identities, private paths, trust-key material, or environment secrets.
- Reproducible dual artifacts: plugin and source ZIPs have separate layouts, explicit names, schema-v3 manifests, canonical metadata, strict denylist enforcement in both producer and verifier, and extraction-time verification.
- Split portability gates: static, unit, platform, schema, behavior, package, and release checks have separate responsibilities; release provenance is not part of `check-fast` or normal push/pull-request validation.

## 0.3.0 Verification Snapshot

The release-foundation implementation was locally verified on 2026-07-15. This is evidence for the current unreleased work, not a claim that 0.3.0 has been tagged or published:

- `make test` passed 604 tests with 12 documented dependency/filesystem skips. The aggregate `make check` gate also passed its unit (162), platform (26), behavior (227), fixture/metric, and package (178) partitions.
- Darwin capability checks passed with descriptor-bound `fstatfs`. A real Linux container reconciled fdinfo and descriptor-bound `statx`, reported `name_to_handle_at` as expected-unsupported, and rejected a same-`st_dev` nested bind mount.
- The completed foundation run produced byte-identical A/B plugin artifacts and byte-identical A/B source artifacts, then verified their ZIPs, extracted roots, denylist policy, and an isolated repo-marketplace installation. The installed copy retained canonical `allow_implicit_invocation: false` metadata.
- Release-only gates remain open by design: `CHANGELOG.md` is still `Unreleased`, no final `v0.3.0` tag exists, and clean release provenance is therefore unavailable. The five-entry GitHub-hosted matrix has been defined but not yet observed remotely. A fresh live-host negative model invocation and host-attested schema-v3 end-to-end completion receipt also remain separate evidence gates.

See [CodexQB 0.3 Release Foundation](docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md) for the capability matrix, exact commands, artifact evidence, unsupported environments, and remaining trade-offs.

## Why CodexQB

- **Repo-aware intake:** CodexQB inspects the current repository before asking questions, then proposes evidence-backed defaults for project name, intent, target end state, constraints, autonomy/review cadence, and token/context budget assumptions.
- **Durable planning docs:** Output is written under `Planner-docs/` so long planning work, ontology, and implementation history survive context changes and can be reviewed like normal project documentation.
- **Project Autopsy + Ontology + Comprehension:** Existing projects get a focused `Autopsy.md` report and may get `Project-Ontology.md` plus `Project-Comprehension.md` to capture evidence confidence, CQ/TRACE/ARC links, architecture reflexion, quality scenarios, and open validation probes.
- **Adaptive phase decomposition:** The main plan can be expanded by active planning horizon in default `wave` mode, while later phases remain deferred roadmap cards unless the user explicitly requests `full` planning.
- **Implementation-ready planning gates:** Active sub-plans keep the 13-section human-readable structure and add a machine-readable implementation contract with repo-relative paths, exact validation commands, parent acceptance signal IDs, dependency labels, concrete outputs, and security review flags.
- **Structured command and risk contracts:** Strict Step 2 and Apply require a closed validation envelope containing `id`, `argv`, repo-bound `cwd`, `expected_exit_code: 0`, bounded `timeout_seconds`, `network: deny`, and `probe_tier: 1`. The shared parser accepts only narrow no-write pytest/unittest and Ruff profiles, rejects unknown fields/options, output or mutation flags, executable-path spoofing, sensitive paths, symlink cwd escapes, shell syntax, opaque make/package-manager wrappers, and high-risk work without security review. Legacy command strings remain informational compatibility data outside strict mode and cannot authorize Apply execution.
- **QA before implementation:** The audit step checks coverage, naming, ordering, section structure, readiness, ontology consistency, planning-history continuity, framework ownership, algorithmic invariants, security/governance, vibecoding slice quality, and implementation preparedness.
- **Deterministic Goal specs, unique Goal runs:** `scripts/goal_run.py` compiles stage-aware source snapshots, Step 2 planning horizons from `Main-Planing.md` before sub-plans exist, active sub-plan inventory, source-bound Implementation Contracts, implementation contract digests, validation command IDs, strict validation checkpoints, contract-derived Step 4 work steps, Step 4 READY queues, subagent role plans, compiler version metadata, template bundle digests, policy-envelope digests, budget metadata, and canonical handoffs into `Goal-Run.json`, `Goal-Prompt.md`, and `Goal-Result.json` without executing commands. `goal_spec_id` is stable for the same source/mode/objective/scope, while `goal_run_id` is unique per invocation. Missing stage prerequisites or failing bundled validator gates produce a blocked result instead of an execution prompt.
- **Gated execution handoff:** CodexQB does not implement product changes itself. It prints a separate Goal mode prompt only when the audit says implementation can begin, then guides that run through the READY queue in small evidence-backed slices and asks Step 4 to append concise implementation summaries to `Planing-Ledger.md`.
- **Artifact-based apply runs:** `scripts/apply_run.py` creates and validates `.codexqb/apply-runs/<apply-run-id>/` artifacts for `direct`, `subagent_serial`, `external_superpowers`, and `no_action` modes only after strict Step 4 validation passes. `apply_spec_id` is stable for the selected mode, source snapshot, workspace baseline, and READY queue; `apply_run_id` is unique per invocation. The immutable envelope records canonical no-exec Git plumbing evidence for HEAD, index, tracked worktree content, staged changes, unstaged changes, and untracked inventory, plus non-Git file inventory, `working_branch`, `base_branch`, `worktree_path`, and `dirty_state`, so resume validation can detect unrelated source/workspace drift while ignoring `.codexqb/` runtime artifacts. Historical schema field names that mention status or diff now carry these versioned canonical evidence digests rather than porcelain or patch bytes. During implementation and review, validation permits tracked unstaged drift that is listed in the active Implementation Contract and reported in verified implementer/fixer artifacts, and permits untracked new files only when the contract marks the exact path as `state: proposed`; staged or contract-external drift still blocks the run. Action modes reject non-Git workspaces by default unless the caller passes `--allow-non-git-unsafe`, and reject dirty or protected current Git worktrees unless the caller passes `--allow-unverified-git-worktree`; both approvals record `user_approval: true`. It derives task briefs from Step 4 READY audit entries and active sub-plan Implementation Contracts, carrying `source_subplan_sha256`, `implementation_contract_digest`, `task_contract_digest`, finding IDs, dependency state, exact planned validation commands, `validation_command_ids`, `security_review_required`, `budget_contract`, and `token_usage` metadata into `Progress.json`, `Brief.md`, reports, results, and subagent dispatch prompts. Apply schema v3 adds controller-owned `normalize-writer` persistence for implementer/fixer returns, `capture-evidence` for a signed live patch and changed-file manifest, `run-validation` for an exact planned command receipt, `normalize-review` for a read-only reviewer return, and `publish-review` for ordered phase receipts. These AgentRuns carry `identity_assurance: controller_asserted`, while normalization records `host_completion_proof: not_observed`; neither is host-issued identity or completion proof. `subagent_serial` can therefore build a complete but unattested command and ordered `spec -> quality -> security if required -> final` receipt chain bound to the same live repository digest. For each validation ID and review phase, only the latest published receipt event is current; a newer failure invalidates replay of an older passing reference. This local freshness check remains subject to the unkeyed/no-external-head rollback boundary documented below; trusted verification must not be enabled without host-bound freshness or an external monotonic anchor. Any changed file, patch, receipt, run/task context, freshness, or ordering mismatch blocks the chain. In the current runtime, absence of host-issued agent attestation additionally makes the `VERIFIED` transition fail closed with `trusted_verified_requires_host_agent_attestation=<task-id>`, so finalization remains blocked. `direct` cannot create even the independent reviewer chain. Commit, push, PR, deploy, and external mutation remain opt-in.


## Vibecoding-First Behavior

CodexQB is intentionally vibecoding-first: it keeps the target vision clear, reads the repository's real shape, avoids fake certainty, and plans the next useful verified moves instead of freezing unnecessary implementation detail too early. Generated plans should favor small reversible slices, fast validation signals, explicit deferrals, and human-review checkpoints. Vibecoding never relaxes safety, secret handling, approval, validation, or file-boundary rules.

When a project is large or ambiguous, CodexQB may recommend or explicitly request bounded subagents for read-only repo exploration, readiness/security review, ontology mapping, phase drafting, Step 3 audit, or Step 4 implementation/review separation. The parent CodexQB agent remains responsible for final artifact writes.

## Workflow

| Step | What CodexQB Does | Output |
| --- | --- | --- |
| 1. Repo Scan + Main Plan | Reads the repository, asks four enriched intake questions, and creates the master plan. | `Planner-docs/Main-Planing.md` |
| 1.5 Autopsy + Ontology + Comprehension | For existing projects, audits current project structure and may capture vocabulary, evidence confidence, concept-to-code traces, architecture reflexion, quality scenarios, and open hypotheses. | `Planner-docs/Autopsy.md`, optional `Planner-docs/Project-Ontology.md`, optional `Planner-docs/Project-Comprehension.md` |
| 2. Phase Sub-Plans | Expands the active planning horizon into implementation-ready sub-plans and keeps later phases as deferred roadmap cards unless `full` planning is explicit. | `Planner-docs/Sub-Planing-Index.md`, `Planner-docs/Faz-*-Plans/*.md` |
| 3. QA Audit | Audits coverage, structure, quality, readiness, and governance without repairing files. | `Planner-docs/Sub-Planing-Audit.md` |
| 4. Gated Handoff | Prints a copy-ready implementation Goal prompt when Step 3 passes and tracks implementation summaries through the optional ledger. | Text-only Goal mode prompt, optional `Planner-docs/Planing-Ledger.md` updates |

Step 1 runs in the current Codex thread. Steps 2, 3, and 4 are intentionally handed off as text-only Goal mode prompts so the user stays in control of long-running work. Canonical Goal handoffs live under `references/handoffs/` and include the Goal Run Contract, resume/recovery protocol, validation gates, stop gates, context budget, source-snapshot binding, and subagent policy.

CodexQB 0.3.0 also includes optional local preview helpers:

```bash
python3 plugins/codexqb/skills/codexqb/scripts/goal_run.py --root /path/to/project --stage step2
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py prepare --root /path/to/project --mode subagent_serial
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py dispatch --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role implementer --actor controller --evidence "fresh dispatch prepared"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py record-agent --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role implementer --agent-id <agent-id> --status spawned --actor controller --evidence "Codex subagent spawned"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py transition --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --to IMPLEMENTING --actor <agent-id> --evidence "brief accepted"
# The implementer now changes only contract-authorized files and returns its structured result to the controller.
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py normalize-writer --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role implementer --agent-id <agent-id> --report-json '{"status":"DONE","task_id":"<task-id>","implementer_agent_id":"<agent-id>","files_changed":["src/example.py"],"concerns":[]}' --actor controller
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py record-agent --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role implementer --agent-id <agent-id> --status completed --actor controller --summary "implementation completed"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py transition --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --to IMPLEMENTED --actor <agent-id> --evidence "implementation lifecycle completed"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py capture-evidence --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --actor controller --evidence "implementation complete"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py run-validation --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --validation-id VAL-01 --actor controller
# Repeat run-validation for every planned ID, then call normalize-writer again with the controller-bound receipt IDs, change-set ID, contract digests, and patch digest.
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py transition --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --to TASK_REVIEW --actor controller --evidence "controller evidence ready"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py dispatch --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role task_reviewer --review-phase spec --actor controller
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py record-agent --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role task_reviewer --review-phase spec --agent-id <reviewer-id> --status spawned --actor controller
# The read-only reviewer returns exactly one JSON payload; it does not write Review-Report-spec.json.
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py normalize-review --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --review-phase spec --agent-id <reviewer-id> --report-json '{"status":"COMPLETE","phase":"spec","verdict":"pass","task_id":"<task-id>","reviewer_agent_id":"<reviewer-id>","evidence":["reviewed current patch and receipts"]}' --actor controller
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py record-agent --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --role task_reviewer --review-phase spec --agent-id <reviewer-id> --status completed --actor controller
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py publish-review --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --review-phase spec --actor controller
```

The block above is one ordered excerpt through the first spec receipt, not a completion claim. Repeat the same read-only `dispatch -> record spawned -> normalize-review -> record completed -> publish-review` lifecycle for `quality`, required `security`, and `final`. Controller-only evidence remains unattested, so the current runtime intentionally rejects `VERIFIED` and `finalize` until a host-issued agent attestation contract exists.

These are separate maintenance or fail-closed checks, not the next steps in that excerpt:

```bash
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py recover-lock --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --task-id <task-id> --to NEEDS_CONTEXT --actor controller --evidence "writer lock expired"
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py reconcile --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id>
python3 plugins/codexqb/skills/codexqb/scripts/apply_run.py finalize --run-dir /path/to/project/.codexqb/apply-runs/<apply-run-id> --actor controller --evidence "host-attested tasks verified"
```

The `finalize` command above is documented for the contract boundary; with current controller-only evidence it is expected to fail closed.

Goal previews bind each structured implementation contract back to its source sub-plan path and SHA-256 hash, and they use stage-aware snapshots so expected Step 3/4 outputs do not falsely break resume while source drift still blocks. Apply artifacts carry the same source hash, implementation contract digest, task contract digest, bounded `budget_contract`, and honest `token_usage: not_observed` status through task briefs, dispatch packets, reports, and results.

Goal preview and Apply preparation helpers write deterministic spec records with unique run directories inside the target repository and do not execute implementation, commit, push, PR, deploy, dependency install, or global Codex configuration changes. The explicit Apply `run-validation` command is the exception for product validation: it executes only the selected safe command already present in the immutable plan, captures exit/timing and stdout/stderr digests, records normalized cwd and planned network posture, and reports host sandbox, approval, and network-enforcement proof as `not_observed` when the host supplies no proof. On supported POSIX hosts it launches a separate process group with a minimal allowlisted environment, strips inherited proxy/Git/Python/pytest and arbitrary credential variables, disables user-site and automatic pytest-plugin loading, and caps combined stdout/stderr at 8 MiB. Before `exec`, macOS applies the fixed system `sandbox-exec` profile with process creation denied; supported Linux x86-64/ARM64 hosts apply `no_new_privs` plus an architecture-bound seccomp filter that permits same-process threads but denies process-forming fork/clone calls. The process group is torn down on every exit as defense in depth, and missing enforcement or an unknown syscall architecture fails closed. This narrow mechanism prevents descendant lifecycle escape; it is not evidence of file or network sandboxing, and does not upgrade the receipt's `not_observed` host/network proof. Goal and Apply runs record `goal_policy_digest` / `apply_policy_digest` values so validation can recompute and reject tampered write, checkpoint, workspace, readiness, safety, budget, agent, and verification policy envelopes. Apply runs record a `workspace_baseline` in `Apply-Run.json` with branch/base commit, canonical no-exec Git staged/unstaged/status evidence digests, untracked inventory hash, and non-Git file inventory hash when applicable. Full-worktree evidence uses two descriptor- and root/mount-identity-bound traversals with no-follow reads; both passes share a 100,000-path, 64 MiB-per-file, 512 MiB aggregate-read, and 60-second deadline contract, and any limit, identity, or nested-mount violation fails closed. These are evidence-capture boundaries, not a general filesystem sandbox. The schema retains its historical hash field names, but current values bind the plumbing evidence manifest rather than invoking configurable Git diff/status drivers. Non-Git action runs require explicit `--allow-non-git-unsafe` approval. Dirty or protected current Git worktrees require explicit `--allow-unverified-git-worktree` approval.

Artifact writes fail closed at exact managed boundaries. Goal writes only to a direct, non-symlink child of `Planner-docs/Goal-Runs/`; Apply mutations only target a registered and HMAC-verified direct child of `.codexqb/apply-runs/`. Symlinked managed parents and final targets are rejected. The shared `scripts/artifact_io.py` writer uses a random same-directory temporary opened with `O_EXCL | O_NOFOLLOW`, a full write loop, file `fsync`, descriptor-relative atomic replace, directory `fsync`, and failure cleanup. Apply holds a run-directory `flock` while mutating state; `Events.jsonl` is validated and published by full-file atomic replace so sequence numbers remain unique and contiguous across cooperating processes. Every event carries `event_chain_version`, `previous_event_sha256`, and its own canonical `event_sha256`; validation rejects partial trailing lines, malformed records, reordered or colliding sequences, and broken hash links. If replace committed the intended bytes but the first directory `fsync` fails, the writer reconciles the exact file under the lock and retries that `fsync`; persistent ambiguity raises `event_log_commit_state_unknown`, which requires inspection and validation rather than a blind retry. Validation rejects a transition recorded without its matching `Progress.json` state; no automatic multi-file recovery exists, so archive that run and prepare a fresh one if this mismatch occurs. These remain per-file guarantees, not a multi-file transaction. Because the chain is unkeyed and has no trusted external head anchor, it cannot by itself detect removal of a complete valid tail or full-history replacement with a recomputed chain; it is an integrity link, not independent host attestation. This unreleased schema-v3 contract requires `event_chain_version: 1` on every event; earlier pre-chain v3 development runs are archive-only and must be replaced with a fresh run. Hosts without the required descriptor, no-follow, locking, or replace primitives fail closed.

The same bounded secret policy guards every persistent Goal/Apply JSON, JSONL, Markdown, and patch write, including create-exclusive artifacts. It checks semantic JSON/JSONL after decoding escapes, rejects duplicate keys, projects renderer-visible Markdown/control encodings, and scans actor, summary, evidence, report metadata, and controller payloads before mutation. Implementers and fixers return JSON to the controller; `normalize-writer` is the supported persistence path, and a matching normalization binding is required before the writer state can advance. Untrusted out-of-band file changes remain outside OS-level prevention but are bounded, no-follow, rescanned, and rejected when consumed. Repository baseline content is scanned before base64 encoding and after decoding. Validation stdout/stderr is scanned before only digests can enter an event or receipt. Secret-shaped run suffixes and managed directory names are rejected before directory creation. Detection covers common OpenAI, GitHub, Anthropic, Hugging Face, GitLab, Stripe, Google, AWS, Slack, JWT, private-key, authorization-header, URI-userinfo, and contextual credential forms while allowing exact canonical placeholders and ordinary filenames. Persistent artifacts fail closed instead of silently changing signed evidence; console diagnostics strip controls and use the same bounded redaction policy without printing matched values. The owner-only Apply trust key is an intentional binary trust-store exception outside the repository, not a run artifact.

`Goal-Run.json` uses `goal_run_schema_version: 1`; `Apply-Run.json` uses `apply_run_schema_version: 3`. Apply schema-v1 and schema-v2 artifacts predate the live evidence receipt contract: they are archive-only and are rejected by validation, resume, replacement, trusted verification, and finalization. Preserve/archive them and generate a new v3 run. The packaged Apply runtime schema reference is `plugins/codexqb/skills/codexqb/references/apply-run-schema.json`; runtime validation remains dependency-free in `scripts/apply_run.py`. CI and schema maintainers use the pinned development-only `make check-schema` gate to validate Draft 2020-12 meta-schema compliance and each artifact against its filename-mapped intended `$defs`. The root `anyOf` is a non-discriminating compatibility surface, not a security acceptance gate.

## Quick Start

CodexQB is configured for explicit invocation only. Package and installed-copy validation enforce `allow_implicit_invocation: false`; normal Codex requests are not intended to activate it. Confirm live host behavior with the fresh-thread negative and positive probes in the [Installation guide](docs/INSTALLATION.md), then start the workflow with `$codexqb` when you want to use it.

Add this repository as a Codex plugin marketplace:

```bash
codex plugin marketplace add alicankiraz1/CodexQB --ref main
codex plugin add codexqb@codexqb
```

If the repository is private, your Codex/GitHub environment must have access to `alicankiraz1/CodexQB`.

Start a new Codex thread in the project you want to plan, then ask:

```text
Use $codexqb to inspect this repo and plan this project.
```

CodexQB will inspect the repository briefly, then ask for:

- `PROJECT_NAME`
- `PROJECT_INTENT`
- `TARGET_END_STATE`
- `KNOWN_CONSTRAINTS`

CodexQB asks intake questions in the user's language when practical. Generated Planner-docs artifacts are English by default unless the user explicitly requests another content language. Required document headings remain English for validator stability. Intake should also surface desired autonomy, human review cadence, and any token/usage budget so CodexQB can describe rough Goal-mode cost/context risk without pretending to know exact spend.

Future language-mode work should add an explicit `PLANNER_DOC_LANGUAGE` or intake-level language setting. Until then, headings stay English and only body content should vary when the user requests another language.

For existing repositories, the questions include repo-derived suggestions. For empty or minimal repositories, CodexQB falls back to concise generic questions and marks repository evidence as limited.

## Generated Artifacts

CodexQB writes planning artifacts under the target project's `Planner-docs/` directory:

```text
Planner-docs/
  Main-Planing.md
  Autopsy.md
  Project-Ontology.md
  Project-Comprehension.md
  Planing-Ledger.md
  Sub-Planing-Index.md
  Sub-Planing-Audit.md
  Faz-0-Plans/
    Faz0.1-*.md
  Faz-1-Plans/
    Faz1.1-*.md
```

The `Planing` spelling is intentionally preserved because the bundled planner prompts and validators use these exact filenames.

Optional 0.3.0 runtime artifacts are written outside `Planner-docs/`:

```text
Planner-docs/
  Goal-Runs/<goal-run-id>/
    Goal-Run.json
    Goal-Prompt.md
    Goal-Result.json
.codexqb/
  apply-runs/<apply-run-id>/
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

`<goal-run-id>` and `<apply-run-id>` include invocation suffixes so repeated prepares do not collide. Apply task IDs use `AR-<apply-run-id>-T<nnn>` and resolve inside the apply-run directory. Apply `--output-dir` values must be direct, non-symlink children of `.codexqb/apply-runs/`. Use an explicit `--output-dir` plus `--resume` to continue an existing schema-v3 run. `--replace` regenerates only a recognized v3 run whose complete `Apply-Run.json` digest, matching `.codexqb-apply-run.json`, run/root inode binding, and out-of-run registry receipt all verify. The registry receipt is HMAC-authenticated by a private key outside the repository (default: `~/.codex/codexqb-trust/apply-run-hmac-v1.key`) and is published only after descriptor-relative initialization finishes; copied, partial, or self-attested repository artifacts are therefore insufficient. A companion trust-state record prevents a missing initialized key from being silently replaced: key loss or mismatch requires explicit recovery. Apply schema-v1 and schema-v2 artifacts are archive-only and cannot be validated, resumed, replaced, trusted-verified, or finalized; preserve/archive them and generate a new v3 run. The operation never authorizes deletion of the repository root or an arbitrary repo directory. Managed run creation requires directory-descriptor and no-follow filesystem primitives; replacement additionally requires atomic no-replace rename support. Unsupported hosts fail closed instead of falling back to path-based deletion. A restore conflict, stale registry receipt, missing trust key, or interrupted delete leaves an explicit recovery-required state and blocks later replacement or recreation until the preserved content is inspected and handled manually. The trust boundary includes processes running as the same OS account that can read the private trust key; the HMAC protects against repository-contained, copied, or synthesized artifacts, not a compromised user account.

Current schema-v3 runs must also pass this provenance check before validation or resume. Changing a run to schema-v1 or schema-v2, even while recomputing its schema-bound IDs and removing its marker/receipt, remains invalid and cannot downgrade it to legacy status; a receipt-publish failure leaves preserved but unusable artifacts rather than a resumable partial run. For trust-key recovery, restore the matching key and state record together from a trusted backup with owner-only permissions. If no backup exists, preserve and inspect/archive every affected run and receipt before establishing a new trust domain; resetting the key/state permanently prevents old receipts from authorizing replacement. CodexQB does not perform that reset automatically.
The public JSON Schema reference for Apply runtime artifacts is bundled at `plugins/codexqb/skills/codexqb/references/apply-run-schema.json`.

## Evidence-Based Project Comprehension

`Planner-docs/Project-Comprehension.md` is optional and intended for medium or large existing projects. It records question-driven comprehension, evidence registers, confidence, domain-to-code trace maps, intended-vs-implemented architecture relations, bounded history/hotspot signals, quality scenarios, and open hypotheses with next probes.

Allowed evidence types are `source`, `test`, `runtime`, `history`, `configuration`, `documentation`, and `user-confirmed`. Confidence values are `confirmed`, `probable`, `tentative`, and `contradicted`. Step 2 turns tentative claims into validation work; Step 3 audits evidence quality and trace coverage; Step 4 verifies relevant assumptions before code changes.

## Validator

The skill includes a read-only validator:

```bash
python3 plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py --root /path/to/project --mode autopsy --strict
python3 plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py --root /path/to/project --mode step2 --strict
python3 plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py --root /path/to/project --mode step3-preflight --strict
python3 plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py --root /path/to/project --mode step3 --strict
python3 plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py --root /path/to/project --mode step4 --strict
```

Validator modes:

| Mode | Purpose |
| --- | --- |
| `step1` | Validate `Main-Planing.md`. |
| `autopsy` | Require `Autopsy.md` and validate optional ontology/comprehension/ledger continuity docs. |
| `step2` | Validate index, phase folders, sub-plans, and optional continuity docs. |
| `step3-preflight` | Validate Step 2 artifacts before `Sub-Planing-Audit.md` exists. |
| `step3` | Require and validate `Sub-Planing-Audit.md` after Step 3 writes it. |
| `step4` | Enforce semantic readiness, finding status, NO_ACTION_REQUIRED, and Ledger v3 strict execution gates. |

These commands are for manual validation from a CodexQB repository checkout. When running through an installed plugin, CodexQB should use the bundled validator path exposed by the active skill; if that path is unavailable, it should perform equivalent all-file validation and report the fallback clearly.

The validator checks required sections, schema frontmatter, optional ontology/ledger/comprehension headings and content, planning scope manifests, active/deferred phase consistency, deferred roadmap cards, structured implementation contracts, safe validation command schemas, risk/security review consistency, execution waves, parent acceptance traceability, decision references, framework ownership matrices, algorithmic invariant registers, normalized duplicate ratios, uniform sub-plan count anomalies, phase folders, filename conventions, index references, duplicate numbering, unindexed files, length-bounded secret patterns, and Step 4 readiness. Open P0/P1 audit findings block the implementation handoff. Open or accepted P2/P3 findings require `PASS_WITH_WARNINGS`; resolved/not_applicable P2/P3 findings do not keep the audit in warning state forever.

Repository maintainers can run the dependency-free repo check with:

```bash
make check
```

`make check` aggregates the dependency-free static, unit, real-platform, behavior, and dual-package gates. The individual diagnostic targets are `check-static`, `check-unit`, `check-platform`, `check-behavior`, and `check-package`; `check-schema` intentionally uses the pinned development dependency in `requirements-ci.txt`, while `check-release` additionally requires clean release provenance. A tree that is not the exact root of a Git checkout must contain and verify `PACKAGE-MANIFEST.json` before Git discovery. Apply-run validation still requires a signed current change set and complete planned-command receipts, then controller-normalized read-only reviewer payloads and controller-recorded lifecycles published in `spec`, `quality`, optional `security`, and `final` order. Free-text reviewer IDs are not evidence, and the controller-built chain remains unattested until the host supplies identity and completion proof.

For the short platform-independent development loop, run:

```bash
make check-fast
```

Use `make test` when full legacy unittest discovery is specifically needed. `make check` duration is host-dependent and the full Apply regression suite can take tens of minutes. Do not impose a 45-second global timeout; use the focused gate while iterating, then allow the complete applicable gate to finish. A test that exceeds its own declared fixture timeout or stops making progress is a release blocker, not a warning to ignore.

Capability diagnostics are dependency-free:

```bash
python3 plugins/codexqb/skills/codexqb/scripts/doctor.py
python3 plugins/codexqb/skills/codexqb/scripts/doctor.py --json
```

Linux probes fdinfo `mnt_id`, descriptor-bound `statx`, and descriptor-bound `name_to_handle_at`; successful comparable providers must agree. macOS uses descriptor-bound `fstatfs`. `filesystem_fstat` is diagnostic-only and never authorizes evidence capture or mutation. `expected_unsupported` means no high-assurance provider is available on that runtime; `probe_failed` means an advertised provider or provider contract failed and is a gate failure. The compatibility error for blocked callers remains `secure_repository_mount_identity_unavailable`.

## Release Validation

Run these before sharing, committing, or pushing release changes:

```bash
make check
make check-public-privacy
git diff --check
```

The repository also includes GitHub Actions at `.github/workflows/validate.yml`, which runs validation on pushes and pull requests, then adds the pinned schema gate, public privacy scan, and a Gitless extracted-package smoke test.

`make check-public-privacy` is the repository-wide metadata-privacy gate: it detects local filesystem paths and machine/run identifiers in current public documentation and every regular blob reachable from public Git refs, while emitting only path/blob hashes and rule labels. Known text formats fail closed on invalid UTF-8; opaque binary formats use a byte-preserving scan for high-context path and run tokens, while context-free container UUIDs are not classified as local-machine identifiers. Credential and package-secret detection is a separate byte-safe package hygiene contract exercised by exporter, ZIP, extracted-root, and validation checks. This metadata gate does not replace a credential-oriented full-history scanner such as Gitleaks; that independent zero-finding proof remains a release-closure requirement.

Use an explicit artifact target instead of Finder or generic directory compression:

```bash
make export-plugin
make export-source
```

`make export-plugin` writes `codexqb-plugin-0.3.0.zip`; extraction places `.codex-plugin/plugin.json` and the invokable `skills/codexqb/SKILL.md` at the archive root and excludes repository tests, CI, release history, and maintenance docs. `make export-source` writes `CodexQB-source-0.3.0.zip`; extraction creates one `CodexQB/` source root containing repository source, tests, docs, and CI files. Both commands are strict-release exports and therefore require a clean exact Git root, a dated changelog heading, a matching `v0.3.0` tag at `HEAD`, and `origin/main` parity when that ref exists.

For non-release review artifacts use `make export-plugin-worktree` and `make export-source-worktree`. For a Gitless/copied source tree use `make export-source-package`. The legacy `export-sanitized`, `export-sanitized-worktree`, and `export-sanitized-source-package` Make targets remain compatibility aliases for source artifacts, but the ambiguous `CodexQB-sanitized.zip` filename is no longer generated by default and an existing copy may be stale historical evidence.

Schema-v3 manifests bind `artifact_type`, `layout_version`, plugin version, provenance status, file count, normalized modes, per-file hashes, and a content/tree digest. ZIP metadata and member order are canonical and stored without compressor-version variance. Raw preflight rejects ZIP64 and enforces at most 65,534 members, a 576 MiB archive, and an 8 MiB central directory before the standard-library parser runs; verification and extraction continue from one immutable opened snapshot. Producer and verifier apply the same portable denylist and reject Git/runtime metadata, cache/bytecode, macOS metadata, local secret paths, nested archives/polyglots, non-canonical names, traversal, symlinks, collisions, unsafe modes, size overruns, and manifest-external bytes. Exporter CLI failures use stable path-safe codes, and success reports `output=created` without printing the output path. Verify each ZIP before extraction and its actual artifact root afterwards:

```bash
python3 scripts/verify_package_manifest.py --zip <artifact.zip>
python3 scripts/verify_package_manifest.py --root <extracted-artifact-root> --strict-artifact
```

Strict extracted-root verification is descriptor-relative, no-follow, mount-aware, and rejects nested mounts, hardlinks, special files, unexpected empty directories, unsafe root or expected-directory modes, root/descendant swaps, and post-inventory changes. Canonical extraction normalizes generated inner directories to `0755` even under a restrictive umask; strict installed-copy verification also accepts the safe `0700` and `0750` forms produced by plugin managers under restrictive umasks, while still rejecting group- or world-writable directories. It therefore requires a high-assurance descriptor-bound mount provider and fails with the stable `secure_repository_mount_identity_unavailable` code when the host cannot supply one. The source verifier retains schema-v2 read compatibility for older source packages only when their ZIP container is canonical: no prefix/trailer bytes, global or member comments, extra fields, directory entries, or reordered members. New exports use schema v3. If extraction fails and cleanup cannot prove that the identity-pinned generated tree was removed, the helper returns `package_extract_cleanup_state_unknown` and deliberately leaves the recovery artifact for inspection. Manifest hashes prove consistency only, not publisher identity, signature, trusted timestamp, or host attestation. `make check-release` creates and verifies both strict artifacts in a temporary directory and never overwrites the historical repository-root ZIP.

The feedback closure status for the 0.3.0 Goal/Apply hardening pass is tracked in `docs/FEEDBACK-CLOSURE-AUDIT.md`, with requirement-by-requirement status in `docs/release-audits/0.3.0-feedback-closure.md` and sanitized live subagent smoke evidence in `docs/release-evidence/0.3.0-live-subagent-smoke.md`. Public release evidence is privacy-scanned by `make check-public-privacy`; raw local runtime artifacts are not published unless they are intentionally redacted and reviewable. The local metric gate `python3 evals/run_goal_apply_metric_checks.py` reports deterministic size estimates for static Step 4 handoff text, dynamic direct/subagent Goal prompts, direct Apply briefs, and subagent dispatch prompts. The downstream dry-run gate `python3 evals/run_downstream_goal_apply_dry_run.py` builds a disposable git project, validates Step 2, Step 3 preflight, Step 3, and Step 4, compiles Goal previews, and exercises the schema-v3 controller receipt protocol without calling live Codex tools; it is not proof of real multi-agent execution. Treat remaining release-audit items in the closure audit as blockers before moving `CHANGELOG.md` from `Unreleased` to a dated final release section.

## Safety Model

CodexQB is planning-first. Steps 1-3 should not:

- implement product features;
- refactor source code;
- install dependencies;
- run destructive commands;
- commit, push, deploy, or open pull requests;
- write secrets, tokens, credentials, private keys, or local sensitive environment values into planning files.

Generated plans should distinguish documentation readiness, local readiness, live readiness, production readiness, and operational evidence.

## Repository Layout

```text
.agents/plugins/marketplace.json
.github/workflows/validate.yml
Makefile
plugins/codexqb/
  .codex-plugin/plugin.json
  skills/codexqb/
    SKILL.md
    agents/openai.yaml
    scripts/validate_planner_docs.py
    scripts/safety_contracts.py
    scripts/goal_run.py
    scripts/apply_run.py
    scripts/repository_evidence.py
    scripts/mount_identity.py
    scripts/doctor.py
    references/
      First-Planner.md
      Autopsy-Planner.md
      Second-Planner.md
      Third-Planner.md
      Fourth-Planner.md
      handoffs/
        run-step2.md
        run-step3.md
        run-step4.md
      repo-aware-intake.md
      workflow-quality.md
      vibecoding-principles.md
      subagent-playbook.md
      planning-ledger.md
      project-ontology.md
      project-comprehension-methods.md
      probe-policy.md
      assessment-and-budget.md
      engineering-principles.md
      goal-compiler.md
      apply-orchestrator.md
      goal-specs/
docs/
  INSTALLATION.md
  MAINTAINING.md
  USAGE.md
  assets/codexqb-workflow.png
  revision/CODEXQB-0.3-RELEASE-FOUNDATION.md
evals/
  run_fixture_corpus_checks.py
scripts/
  check_public_privacy.py
  export_sanitized.py
  extract_verified_package.py
  package_policy.py
  run_test_suite.py
  validate.sh
  verify_package_manifest.py
tests/
  platform/
CHANGELOG.md
LICENSE
README.md
```

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Maintaining CodexQB](docs/MAINTAINING.md)
- [0.3 Release Foundation evidence](docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md)

## Contributing

Use GitHub issues for bugs, enhancements, and documentation requests. The issue templates ask for the CodexQB version, affected surface, validation evidence, and expected behavior so fixes can stay evidence-backed.

Before opening a pull request, run:

```bash
make test
make check
git diff --check
```

For release, packaging, or validation changes, also run:

```bash
make check-public-privacy
make check-release
```

`make check-release` creates both strict artifacts in a temporary directory, verifies and extracts them without `.git/`, and runs the bounded plugin/source validation there. It requires the exact release tag/changelog/clean-tree contract and does not leave or replace a repository-root ZIP.

Pull requests should keep the existing compatibility contracts intact: preserve explicit-only `$codexqb` invocation, keep `Planing` filenames unchanged, keep runtime validators dependency-free, avoid printing secret values, and do not weaken mount assurance, artifact producer/verifier parity, symlink/path boundaries, untracked-file scanning, or secret and nested-archive guards.

## Community Supporters

CodexQB's hardening has benefited from concrete public feedback and PR proposals. Thank you to:

- [@ozanturcan](https://github.com/ozanturcan) for detailed issue reports and acceptance criteria that strengthened Step 1 validation, Step 3/4 gate clarity, package fallback behavior, and prompt wording.
- [@hsnyvsh](https://github.com/hsnyvsh) for PR proposals that helped shape the Step 1 validator test coverage, Step 4 handoff documentation, and the `make test` developer loop.

## Public Plugin Directory Status

CodexQB currently uses repository marketplace distribution. Public directory or workspace sharing distribution can be revisited separately; this release focuses on repo-marketplace installation and local/team validation.

## License

MIT. See [LICENSE](LICENSE).
