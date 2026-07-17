# CodexQB Dynamic Goal Compiler

The Dynamic Goal Compiler turns CodexQB source contracts into a deterministic Goal spec and a unique Goal preview run before a user starts Goal mode.

It is not an executor. It does not run validation commands, edit global Codex configuration, install dependencies, sync plugin caches, commit, push, create pull requests, deploy, or mutate external systems.

## Inputs

- Target repository root.
- Goal stage: `step15`, `step2`, `step3`, or `step4`.
- Canonical handoff source when the stage has one.
- Stage goal spec under `references/goal-specs/`.
- Relevant existing `Planner-docs/` artifacts.
- Optional output directory that is one direct child of the repository-bound external controller-state `goal-runs/` directory.

## Outputs

The compiler writes a per-invocation run directory:

```text
<passwd-home>/.codex/codexqb-trust/controller-state-v1/<repository-identity>/goal-runs/<goal-run-id>/
  Goal-Run.json
  Goal-Prompt.md
  Goal-Result.json
```

`Goal-Run.json` records source snapshot hashes, deterministic `goal_spec_id`, invocation-specific `goal_run_id`, stage, handoff contract version, artifact schema version, output paths, pinned template hashes, compiler hash, `goal_policy_digest`, Step 2 `planning_horizon` metadata, active sub-plan inventories, source sub-plan paths and SHA-256 hashes, structured `implementation_contract` objects when present, `implementation_contract_digest`, `validation_command_ids`, contract-derived Step 4 work steps, strict validation checkpoints, `budget_contract`, `token_usage`, and safety policy. `Goal-Prompt.md` is the user-facing Goal prompt. `Goal-Result.json` is a preview result describing whether the prompt is ready or blocked and records `goal_run_sha256`, budget and token-usage state, plus `prompt_sha256` when a prompt is rendered.

`Goal-Prompt.md` must be rendered deterministically from a valid `Goal-Run.json`. Rendering must first validate schema version, secret hygiene, source snapshot integrity, current stage snapshot match, source-bound implementation contracts, strict checkpoint policy, the recomputed Goal policy envelope, allowed/forbidden path policy, and glob overlap.

`goal_spec_id` is stable for the same source snapshot, mode, objective, and active scope. `goal_run_id` includes an invocation suffix so repeated prepares create separate run directories unless the caller explicitly supplies the same `--output-dir`. Rendering must reject template bundle, compiler, source snapshot, or stored digest drift before writing output.

Goal prepare and render use the shared descriptor-relative `scripts/artifact_io.py` boundary. Each replacement is staged in a random same-directory file opened with `O_EXCL | O_NOFOLLOW`, completes a full write loop, `fsync`s the file, atomically replaces the final name, `fsync`s the directory, and cleans up an uncommitted temporary on failure. This is per-file atomicity, not a multi-file transaction.

Before any Goal JSON or Markdown is published, shared safe serialization rejects bounded secret-pattern findings without including the matched value in the error. The same gate decodes JSON semantics, rejects duplicate keys and structured credential contexts, projects renderer-visible Markdown/control forms, and checks managed names before directory creation. Existing Goal artifacts are reopened through bounded descriptor-relative no-follow reads and checked again. Persistent content is not silently redacted because that would change deterministic hashes; untrusted console diagnostics use the same policy's bounded, control-safe redaction path.

`prepare` must run the bundled validator for the selected stage prerequisite before writing an execution prompt. Missing prerequisites or validator failures write `Goal-Result.json` with `status: blocked` and remove/avoid `Goal-Prompt.md`.

Validation also rejects semantic drift in run controls: unsupported stage modes, blank objectives, empty work steps, unsafe validation checkpoints, recursive subagent depth, invalid context-token risk declarations, invalid budget limits, selected-task budget overflow, and dishonest token-usage state. These fields are execution safety controls, not display-only metadata.

Stage snapshots are stage-aware. Step 3 treats `Sub-Planing-Audit.md` as expected mutable output while keeping Step 2 source artifacts immutable. Step 4 treats `Planing-Ledger.md` and implementation paths declared by READY queue contracts as mutable repository outputs while keeping the Main Plan, index, audit, and selected source sub-plans immutable. Apply controller artifacts live outside the repository and are excluded by boundary rather than by a repository glob.

## Security Rules

- The output directory must be a direct, non-symlink child of the fixed, repository-bound external controller-state `goal-runs/` directory; no repo-local directory is approved.
- Default output is the external controller-state `goal-runs/<goal-run-id>/`; explicit output and resume use the same direct-child boundary. Production derives the store from the effective account's passwd home and accepts no environment path override.
- The external controller-store chain, `goal-runs`, the run directory, and final artifact targets are opened or inspected descriptor-relative without following symlinks; symlink and special-file targets fail closed.
- Legacy in-repository `Planner-docs/Goal-Runs/` trees are archive-only and cannot be resumed, replaced, or mutated.
- Source snapshots include hashes and relative paths only.
- Active scope must use portable repo-relative roots such as `"."`, not local absolute paths.
- Allowed and forbidden write patterns must be repo-relative. Absolute paths, traversal, unsafe wildcards, and overlapping allowed/forbidden patterns are blockers.
- Existing run directories must not be overwritten unless `--replace` is explicit. `--resume` requires an explicit output directory and validates the existing `Goal-Run.json` before rendering or reporting it.
- The compiler must never include secrets, environment values, local credentials, or full logs.
- The compiler must never execute validation commands from planner docs.
- Step 4 prompts must preserve no-commit/no-push/no-PR/no-deploy defaults unless the user explicitly opts in during the implementation run.

## Stage Behavior

- `step15`: prepare Step 1.5 Autopsy context for existing projects.
- `step2`: prepare adaptive wave/full/refresh/repair planning handoff with active sub-plan inventory, no-subplans `planning_horizon` derived from `Main-Planing.md`, contract-signal summaries, `validation_command_ids`, and structured `implementation_contract` objects when present.
- `step3`: prepare Step 3 preflight and audit handoff with active sub-plan inventory, contract-signal summaries, and structured `implementation_contract` objects when present.
- `step4`: prepare gated apply handoff with READY/READY_WITH_WARNINGS audit queue entries, contract-signal summaries, `validation_command_ids`, and structured `implementation_contract` objects. Work steps must be derived from parent signals, implementation paths, validation command IDs, dependency state, security review requirements, and expected outputs; actual implementation remains user-triggered.

If required stage inputs are missing, the compiler writes `Goal-Result.json` with `status: blocked` and blocker IDs. It must not write an execution `Goal-Prompt.md` for blocked prerequisites.
