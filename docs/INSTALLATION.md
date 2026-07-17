# Installation

CodexQB is distributed as a Codex plugin repository with a repo-local marketplace manifest.

Current package contracts:

```text
plugin_version: 0.3.0
artifact_schema_version: 3
handoff_contract_version: 2
goal_run_schema_version: 1
apply_run_schema_version: 3
```

## Requirements

- Codex with plugin support.
- GitHub access to `alicankiraz1/CodexQB`.
- A new Codex thread after installation so the `$codexqb` skill is loaded into context.

If this repository is private, installation only works for users and workspaces that can access the repository.

## Install From The Repository Marketplace

Run these commands in Codex:

```bash
codex plugin marketplace add alicankiraz1/CodexQB --ref main
codex plugin add codexqb@codexqb
```

Then start a new Codex thread and run the negative activation probe without naming the skill:

```text
Summarize this project's README without using any plugin or skill.
```

CodexQB must remain idle: it must not start its intake, create `Planner-docs/`, or present CodexQB handoffs. Start a second new thread and test explicit activation:

```text
Use $codexqb to plan this project.
```

CodexQB is configured with `allow_implicit_invocation: false`. It should remain idle for ordinary Codex requests and run only after the user explicitly invokes `$codexqb` (or selects the CodexQB skill in the interface).

## Install From A Local Clone

Clone the repository:

```bash
git clone git@github.com:alicankiraz1/CodexQB.git
cd CodexQB
```

Add the local marketplace root:

```bash
codex plugin marketplace add .
codex plugin add codexqb@codexqb
```

Start a new Codex thread before testing. Run the ordinary README-summary negative probe first, then use a separate new thread for the explicit `$codexqb` probe so one loaded skill context is not cited as proof of the other.

## Distribution Artifacts

CodexQB publishes two different ZIP layouts. They are deliberately not interchangeable:

| Artifact | Extracted root | Intended use |
| --- | --- | --- |
| `codexqb-plugin-<version>.zip` | `.codex-plugin/`, `skills/`, `PACKAGE-MANIFEST.json` | Plugin payload for a marketplace publisher, cache, or air-gapped local-marketplace assembly |
| `CodexQB-source-<version>.zip` | `CodexQB/` | Reviewable source, tests, docs, CI, and maintenance tooling, excluding the two checkout-only validation controllers |

The Codex CLI installs plugins from a configured marketplace snapshot; `codex plugin add` does not accept a ZIP path directly. The repository marketplace commands above are therefore the canonical end-user installation path. If a plugin ZIP is used for offline assembly, verify it before extraction, place the extracted plugin root at the path referenced by a local marketplace's `.agents/plugins/marketplace.json`, add that marketplace, and then install `codexqb@<marketplace-name>`.

Before trusting either artifact, verify both the ZIP envelope and the extracted artifact root:

```bash
python3 scripts/verify_package_manifest.py --zip <artifact.zip>
python3 scripts/verify_package_manifest.py --root <extracted-artifact-root> --strict-artifact
```

For the source artifact, `<extracted-artifact-root>` is the extracted `CodexQB/` directory. For the plugin artifact, it is the directory that directly contains `.codex-plugin/`. ZIP verification rejects ZIP64, more than 65,534 members, archives over 576 MiB, and central directories over 8 MiB before parser allocation; verification and extraction share one immutable opened package snapshot. Strict root verification requires a high-assurance descriptor-bound mount provider and rejects nested mounts, hardlinks, special files, unexpected empty directories, unsafe root or expected-directory modes, path swaps, and post-inventory changes. The helper normalizes generated inner directories to `0755`; an installed copy made under a restrictive umask may instead use safe `0700` or `0750` directories, which strict verification accepts without accepting group- or world-writable modes. On a host without that capability it fails closed with `secure_repository_mount_identity_unavailable`; run doctor and move verification to a declared-supported host rather than weakening the gate. If the extraction helper cannot prove cleanup after a failure, it returns `package_extract_cleanup_state_unknown` and preserves the recovery artifact for manual inspection. Do not infer freshness from an older file named `CodexQB-sanitized.zip`; 0.3.0 no longer generates that ambiguous name by default.

## Verify Installation

In a fresh task in a project repository, first ask without naming CodexQB:

```text
Summarize this project's README without using any plugin or skill.
```

Confirm that no CodexQB intake or `Planner-docs/` workflow starts. Then open a separate fresh task and ask:

```text
Use $codexqb to create a main plan for this project.
```

Expected behavior:

1. Without explicit `$codexqb` invocation or UI selection, CodexQB remains idle.
2. After explicit invocation, CodexQB performs a bounded read-only scan of the current repository.
3. It asks for `PROJECT_NAME`, ideally with a repo-derived default.
4. It asks for `PROJECT_INTENT`, ideally with a repo-derived draft.
5. It asks for `TARGET_END_STATE`, ideally across product, engineering, operations, security, and user value.
6. It asks for `KNOWN_CONSTRAINTS`, including detected stack, infra, validation, security, autonomy level, review cadence, budget/context assumptions, and unknown constraints.
7. It uses the confirmed values to create or update `Planner-docs/Main-Planing.md`.
8. For existing or partially built repositories, it may create or update `Planner-docs/Autopsy.md` as Step 1.5.
9. When enough evidence exists, it may create or update `Planner-docs/Project-Ontology.md`.
10. For non-trivial existing projects, it may create or update `Planner-docs/Project-Comprehension.md` with evidence confidence, CQ/TRACE/ARC links, architecture reflexion, quality scenarios, and open validation probes.
11. Later Goal-mode implementation handoffs may update `Planner-docs/Planing-Ledger.md` with concise verified-slice summaries and confirmed/contradicted hypothesis evidence.

## Update An Existing Local Install

After pulling repository changes or switching to a newer local clone, refresh the plugin and start a new Codex thread:

```bash
codex plugin add codexqb@codexqb
```

If Codex reports stale marketplace metadata, refresh marketplaces first:

```bash
codex plugin marketplace upgrade
codex plugin add codexqb@codexqb
```

For a manually maintained global skill copy, sync and verify parity from the repository root:

```bash
rsync -a --delete --exclude '__pycache__/' --exclude '*.pyc' plugins/codexqb/skills/codexqb/ "$HOME/.codex/skills/codexqb/"
diff -ru -x __pycache__ plugins/codexqb/skills/codexqb "$HOME/.codex/skills/codexqb"
```

## Compatibility Notes

| Earlier surface | 0.3.0 behavior |
| --- | --- |
| `make export-sanitized` | Compatibility alias for the strict source artifact |
| `make export-sanitized-worktree` | Compatibility alias for the worktree source artifact |
| `make export-sanitized-source-package` | Compatibility alias for the Gitless/filesystem source artifact |
| Package manifest schema v2 | Read-compatible only for legacy source ZIPs with the canonical no-prefix/trailer, no-comment, no-extra-field, no-directory-entry, canonical-member-order container; all new plugin/source exports use schema v3 |
| `secure_repository_mount_identity_unavailable` | Stable caller-facing error retained; provider-specific safe codes are reported by doctor only |
| Extracted-root verification without mount assurance | Non-strict legacy inspection remains available, but `--strict-artifact` now fails closed; use doctor and verify on supported Linux/macOS |
| Apply schema v1/v2 | Archive-only; create a new schema-v3 run rather than migrating or resuming in place |

CodexQB 0.3.0 keeps older planner artifacts readable outside strict execution gates. Legacy `Planing-Ledger.md` v1 and v2 files pass non-strict validation with compatibility warnings, but strict Step 4 execution requires Ledger v3 migration before implementation starts. New strict planner artifacts must use the closed validation command envelope (`id`, `argv`, repo-bound `cwd`, expected exit `0`, bounded timeout, `network: deny`, Tier 1), source-bound implementation contracts, explicit risk metadata, and the Apply `budget_contract` schema. Legacy command strings remain non-executable compatibility data.

New Apply runs use `apply_run_schema_version: 3`. Apply schema-v1 and schema-v2 run directories predate the signed live change-set, complete command-receipt, and ordered reviewer-receipt contract; preserve them as archive-only evidence and prepare a new v3 run instead of attempting validation, resume, replacement, trusted verification, finalization, or in-place migration. A v3 evidence chain uses `capture-evidence`, `run-validation`, and phase-aware reviewer `dispatch`/`record-agent` followed by `publish-review` in spec, quality, optional security, and final order. Direct mode cannot independently produce that reviewer-agent chain. `subagent_serial` can build the complete but unattested chain, but in the current runtime trusted `VERIFIED` and `finalize` remain blocked until a host-issued agent attestation contract is available.

Extracted source packages have no self-validation authority and case-insensitively omit the checkout-only `scripts/validate.sh` and `scripts/run_extracted_validation.py` entrypoints. From the exact selected checkout, run `python3 -I -S -B scripts/run_extracted_validation.py --expected-head <externally-asserted-full-HEAD> --zip <source.zip> --root <extracted-root> --profile static`. The launcher pair-binds that HEAD, checkout/root identity, held controller bundle, archive, manifest, and extracted inventory; materializes controller bytes into a private fsynced snapshot; and treats the target only as descriptor-bound data for static policy. Its unsigned diagnostic explicitly reports `controller_observed_explicit_source_selection`, `host_attested=false`, `verified=false`, and `finalization_allowed=false`. It is not publisher authentication, host attestation, Goal/Apply authority, Step 4 readiness, or release finalization. Dynamic extracted tests remain deferred until the PR4 host-native sandbox. A plugin payload likewise omits repository-level validation tooling and is verified through its manifest plus the local-marketplace installation smoke.

Package export CLI failures emit stable path-safe error codes. A successful export reports `output=created` instead of echoing the destination path; treat the requested destination supplied by the caller as the location to inspect.

The old fixture checker command remains available as a compatibility wrapper:

```bash
python3 evals/run_fixture_checks.py
```

The canonical command is:

```bash
python3 evals/run_fixture_corpus_checks.py
```

Both should return the same exit code.

## Troubleshooting

If `$codexqb` is not recognized:

- start a new Codex thread;
- confirm the plugin is installed;
- reinstall with `codex plugin add codexqb@codexqb`;
- confirm the repository or local clone is accessible;
- if installed from a private repository, confirm Codex has GitHub access to that repository.

If Goal preparation, repository evidence capture, packaging, or Apply reports `secure_repository_mount_identity_unavailable`, run the dependency-free capability doctor:

```bash
python3 -I -S -B plugins/codexqb/skills/codexqb/scripts/doctor.py
python3 -I -S -B plugins/codexqb/skills/codexqb/scripts/doctor.py --json
```

`status=expected_unsupported` means the runtime offers no usable descriptor-bound mount provider; move the operation to a supported Linux or macOS host. `status=probe_failed` means an advertised provider failed or comparable providers disagreed; treat that as a blocker and repair the host/runtime before retrying. The report never includes raw mount IDs, repository/home paths, credentials, or environment values.

If Step 2, Step 3, or the gated Step 4 implementation handoff does not run automatically, that is expected. CodexQB prints text-only Goal mode prompts so you can explicitly launch long-running decomposition, audit, or implementation runs. Step 1.5 Autopsy is local to the initial planning thread and runs only when the repository has meaningful existing-project evidence.
