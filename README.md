# CodexQB

[![validate](https://github.com/alicankiraz1/CodexQB/actions/workflows/validate.yml/badge.svg?branch=main)](https://github.com/alicankiraz1/CodexQB/actions/workflows/validate.yml)

**Evidence-backed, vibecoding-first project planning for Codex.**

CodexQB reads the repository before it plans. It turns the current project into a durable, reviewable planning package under `Planner-docs/`, then prepares small implementation handoffs that can be checked before code changes begin.

![CodexQB workflow](docs/assets/codexqb-workflow.png)

## What it gives you

- A repository-aware main plan instead of a generic task list.
- An existing-project autopsy, optional project comprehension, and project ontology.
- Phase plans with dependencies, validation commands, risks, and acceptance criteria.
- A QA audit and controlled Goal/Apply handoff for small, verifiable slices.
- A planning ledger that keeps decisions and implementation evidence durable across long Codex sessions.

CodexQB is useful for software, AI, infrastructure, security, and automation projects. It is planning-first: it does not silently turn a planning request into product-code changes.

## Quick start

Install from the repository marketplace:

```bash
codex plugin marketplace add alicankiraz1/CodexQB --ref main
codex plugin add codexqb@codexqb
```

Open a new Codex task in the project you want to plan and invoke the skill explicitly:

```text
Use $codexqb to inspect this repo and plan this project.
```

CodexQB is configured with `allow_implicit_invocation: false`. Normal Codex prompts should not activate it; only an explicit `$codexqb` request should start the workflow.

The intake covers four stable fields:

- `PROJECT_NAME`
- `PROJECT_INTENT`
- `TARGET_END_STATE`
- `KNOWN_CONSTRAINTS`

CodexQB asks intake questions in the user's language when practical. Generated Planner-docs artifacts are English by default unless the user explicitly requests another content language. Required document headings remain English for validator stability. A future `PLANNER_DOC_LANGUAGE` setting can make this choice explicit; it is not implemented yet.

For installation verification, upgrades, and fresh-task activation probes, see [Installation](docs/INSTALLATION.md).

## Workflow

| Step | Purpose | Main output |
| --- | --- | --- |
| 1. Understand | Inspect the repo, ask focused questions, and create the master plan. | `Planner-docs/Main-Planing.md` |
| 1.5 Diagnose | For existing projects, capture current-state gaps, vocabulary, architecture evidence, and open questions. | `Autopsy.md`, optional ontology/comprehension docs |
| 2. Decompose | Turn the active planning horizon into implementation-ready phase plans. | `Sub-Planing-Index.md`, `Faz-*-Plans/*.md` |
| 3. Audit | Check coverage, dependencies, risks, structure, and readiness. | `Sub-Planing-Audit.md` |
| 4. Hand off | Produce bounded Goal/Apply work contracts and record progress. | Goal prompt, optional `Planing-Ledger.md` updates |

Later phases can stay as deferred roadmap cards while CodexQB plans the next useful slice in detail. Bounded subagent exploration and review may be recommended for large projects, but the parent agent remains responsible for final planning artifacts.

## Generated planning package

```text
Planner-docs/
  Main-Planing.md
  Autopsy.md
  Project-Ontology.md
  Project-Comprehension.md
  Sub-Planing-Index.md
  Sub-Planing-Audit.md
  Planing-Ledger.md
  Faz-0-Plans/
  Faz-1-Plans/
```

The historical `Planing` spelling is intentional because validators and prompt contracts use these exact filenames.

Goal and Apply runtime state is stored outside the target repository in an owner-only, repository-bound controller directory under the effective account's passwd home. Production does not trust `HOME` or repository-provided path overrides. Legacy in-repository Goal/Apply run directories are archive-only.

## Safety boundaries

CodexQB keeps the following rules explicit:

- Repository evidence flows through the bounded `RepositoryIO v1` interface.
- Repository reads are no-follow, identity-checked, mount-aware, size-bounded, and fail closed.
- Planner writes are allowlisted, compare-and-swap guarded, atomically published, and never include secrets.
- Goal/Apply controllers are launched only from the active `$codexqb` skill root resolved by the Codex loader.
- Commit, push, pull request, deployment, destructive commands, and external mutations require explicit user approval.
- Local controller receipts and HMACs do not claim host or agent attestation.

Without an independent trusted host/agent attestation API, `VERIFIED` and every finalization path intentionally remain unavailable. The stable fail-closed code is `trusted_verified_requires_host_agent_attestation`.

## 0.3.0 status

`0.3.0` is still unreleased. The current line strengthens repository I/O, portable skill launching, source-bound Goal/Apply contracts, privacy scanning, deterministic packaging, and validation evidence.

Release remains blocked until all closure gates are complete:

- The history-privacy baseline still contains 70 hash-only records from reachable historical blobs. It is a migration inventory, not an accepted release baseline.
- `make check-release` must stay blocked until the separately approved history rewrite and a fresh zero-finding history scan are complete.
- A fresh schema-v3 live end-to-end run, installed-copy parity, activation evidence, and final release provenance are still required.
- No history force-push, tag push, or GitHub Release is implied or authorized by normal development work.

The earlier sanitized live smoke is reviewable at [0.3.0 live subagent smoke](docs/release-evidence/0.3.0-live-subagent-smoke.md). It does not prove the full current receipt chain.

## Validation

Fast local feedback:

```bash
make check-fast
```

Full development gates:

```bash
make check-unit
make check-schema
make check-behavior
make check-package
make check-public-privacy
make check
```

The full Goal/Apply regression suite can take tens of minutes. Release and package details live in [Maintaining CodexQB](docs/MAINTAINING.md); day-to-day validator and controller examples live in [Usage](docs/USAGE.md).

<details>
<summary>Maintainer contract notes</summary>

Current public contract versions:

```text
plugin_version: 0.3.0
artifact_schema_version: 3
handoff_contract_version: 2
goal_run_schema_version: 1
apply_run_schema_version: 3
budget_schema_version: 1
```

Goal artifacts bind the source path and hash, compiler version, template bundle digest, implementation contract digest, validation command IDs, and bounded budget. The fixture corpus checks these contracts across representative project shapes.

Operational commands use the loader-derived absolute `"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"`; `<CODEXQB_SKILL_ROOT>` is documentation notation, not an environment variable. Apply accepts a bounded `codexqb.controller-argv/v1` request through stdin via `--controller apply -- request-stdin`.

The Apply lifecycle is `prepare` → `dispatch` → `record` → `normalize-writer` → `capture-evidence` → `run-validation` → `normalize-review` → `publish-review` → `finalize`. It binds `validation_command_ids`, uses strict Step 4 validation, and persists an `Events.jsonl` chain governed by the bundled `apply-run-schema.json`. Agent identity remains `controller_asserted`; `finalize` cannot bypass `trusted_verified_requires_host_agent_attestation`.

Event recovery is deliberately conservative. `event_log_commit_state_unknown` requires inspection, never a blind retry. The unkeyed event chain is not a trusted external head anchor. Older pre-chain v3 runs are archive-only; use a fresh run after recovery.

Detailed controller, filesystem, receipt, packaging, and recovery contracts are maintained in [Usage](docs/USAGE.md), [Maintaining CodexQB](docs/MAINTAINING.md), and the bundled skill references.

</details>

## Documentation

- [Installation](docs/INSTALLATION.md)
- [Usage](docs/USAGE.md)
- [Maintaining CodexQB](docs/MAINTAINING.md)
- [0.3 release foundation](docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md)
- [Feedback closure audit](docs/FEEDBACK-CLOSURE-AUDIT.md)

## Contributing

Use GitHub issues for bugs, enhancements, and documentation requests. Before opening a pull request, run the relevant focused tests and then the full applicable gates. Preserve explicit-only `$codexqb` activation, exact `Planing` filenames, dependency-free runtime validation, privacy-safe diagnostics, and fail-closed security boundaries.

## Community supporters

Thanks to [@ozanturcan](https://github.com/ozanturcan) and [@hsnyvsh](https://github.com/hsnyvsh) for detailed public feedback and PR proposals that improved validation, handoff clarity, package behavior, and test coverage.

## License

MIT. See [LICENSE](LICENSE).
