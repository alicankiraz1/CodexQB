# Maintaining CodexQB

This document covers validation and release maintenance for CodexQB.

Current release contracts:

```text
plugin_version: 0.3.0
artifact_schema_version: 3
handoff_contract_version: 2
goal_run_schema_version: 1
apply_run_schema_version: 3
```

## Dependency-Free Repo Check

Run the default repository validation before every release:

```bash
make check
```

`make check` aggregates `check-static`, `check-unit`, `check-platform`, `check-behavior`, and `check-package`. It covers repository/content hygiene, dependency-free unit contracts, the real host capability probe, Goal/Apply behavior, fixture and prompt-size checks, and both plugin/source package contracts. Release provenance and the development-only JSON Schema dependency remain separate so a normal edit loop is not blocked by a missing release tag or optional package.

CI and schema maintainers must additionally validate the public Apply schema with a real Draft 2020-12 engine:

```bash
python3 -m pip install --requirement requirements-ci.txt
make check-schema
```

This development/CI-only gate checks the schema meta-contract and validates artifacts by their filename-mapped intended `$defs` definition. The schema's root `anyOf` remains a non-discriminating compatibility surface and must not be used as the security or CI acceptance gate. Runtime validation in `apply_run.py` remains dependency-free. Structural JSON Schema checks complement, but do not replace, runtime relational checks such as budget relationships and cross-artifact provenance.

The required package set includes `plugins/codexqb/skills/codexqb/scripts/artifact_io.py`, `controller_store.py`, and `mount_identity.py`. Keep their contracts aligned across code, tests, and public docs: Goal writes only below one direct, non-symlink external controller-state `goal-runs/<run>/`; Apply mutations require a registered and HMAC-verified direct child of the matching external `.codexqb/apply-runs/<run>/`; legacy in-repository Goal/Apply trees are archive-only; managed-parent and final-target symlinks fail closed. Production derives the fixed store from the effective UID's passwd home and accepts no environment path override; tests inject a private home provider. The passwd-home ancestor chain may accept only restrictive deny-only macOS ACLs. `.codex` is owner-controlled and not group/world-writable; `codexqb-trust` and every state/run directory below it are owner-owned mode `0700` with no ACL, while state/binding/key files are mode `0600`. Before evidence capture, package publication, or mutation, the repository descriptor must have at least `mount_unique_descriptor_bound` assurance. Linux can obtain that assurance from fdinfo `mnt_id`, descriptor-bound `statx`, or descriptor-bound `name_to_handle_at`; Darwin uses descriptor-bound `fstatfs`. Comparable successful providers must agree. `fstat().st_dev` remains diagnostic-only and cannot authorize an operation. Missing capability, provider disagreement, root replacement, or a nested mount fails closed under the stable caller error `secure_repository_mount_identity_unavailable` or the existing operation-specific identity error.

Secure replacement still uses a random same-directory `O_EXCL | O_NOFOLLOW` temporary, a full write loop, file and directory `fsync`, descriptor-relative atomic replace, and cleanup before commit. Apply uses a run-directory `flock` to serialize cooperating mutations, and rewrites the complete validated `Events.jsonl` atomically while allocating a unique, contiguous sequence under that lock. Every event must bind the previous event SHA-256 and its own canonical SHA-256; partial trailing lines, malformed records, colliding or reordered sequences, and broken hash links fail closed. When post-replace directory `fsync` first fails, the append path may return success only after observing the exact intended file under the lock and completing a retry; persistent or unreadable ambiguity raises `event_log_commit_state_unknown`, and callers must inspect and validate instead of blindly retrying. Validation rejects a transition-event/`Progress.json` mismatch; there is no automatic multi-file recovery, so archive the affected run and prepare a fresh run. Test and document these as per-file integrity guarantees, not a multi-file transaction or independent host attestation. The unkeyed chain has no trusted external head anchor, so complete valid-tail deletion and a full recomputed replacement remain outside its detection boundary.

Apply runtime artifacts use schema v3 while the planner artifact schema remains v3 and the handoff contract remains v2. Apply schema-v1 and schema-v2 runs are archive-only and must not be validated, resumed, replaced, trusted-verified, finalized, or migrated by synthesizing missing receipts. The current unreleased v3 contract also requires `event_chain_version: 1`; pre-chain v3 development snapshots are archive-only and must not be resumed or appended. Prepare a new v3 run instead.

`make check` duration is host-dependent and the full Apply regression suite can take tens of minutes. Do not wrap the complete gate in a 45-second timeout. Validator CLI smoke tests retain their focused per-fixture timeout, and a test that exceeds its declared timeout or stops making progress is a release blocker. Portability CI runs Ubuntu on Python 3.12, 3.13, and 3.14 plus macOS on Python 3.13 and 3.14; behavior/package jobs remain separately diagnosable, and strict release provenance runs only for tags or an explicit manual request.

Keep the language contract stable: required Planner-docs headings stay English for validator stability, while body content may use another language only when the user explicitly asks. If a future release adds language selection, document and test a `PLANNER_DOC_LANGUAGE` or equivalent intake-level setting before changing prompt behavior.

If a real key is exposed in chat, logs, docs, examples, or commits, treat it as compromised and rotate it outside the repository before release. Validation output must identify only the file, line, and pattern name; it must not print the matched secret value.

When run inside an exact Git checkout root, `make check` uses `git ls-files` for tracked-file secret hygiene and `git archive` for archive hygiene. A tree that is not the exact Git root must contain `PACKAGE-MANIFEST.json`; missing-manifest package copies fail closed. The validator verifies that manifest against the exact packaged file set and SHA-256 digests, ignoring only known regenerated runtime-cache files while still rejecting symlinks or special files inside those caches, then falls back to clearly labeled filesystem checks: package secret hygiene and package path hygiene. The package fallback is useful for validating shared archives, but it does not claim tracked-file or `git archive` coverage.

Use separate validation tiers when diagnosing portability or release blockers:

```bash
make check-fast
make check-static
make check-unit
make check-platform
make check-behavior
make check-package
make check-schema
make check-release
```

`check-fast` is intentionally short: static hygiene plus the bounded safety/artifact/mount/doctor unit subset. It does not run the live platform harness, package generation, behavior smokes, schema dependency, or release provenance. `check-platform` runs doctor in human and JSON forms plus the host harness; `PLATFORM_POLICY=required` demands a usable high-assurance provider, while the default `auto` accepts an honestly reported unsupported runtime and still fails an advertised-provider error. The declared-supported Ubuntu and macOS CI matrix always sets `PLATFORM_POLICY=required`, so an `expected_unsupported` result cannot silently pass those jobs. `check-behavior` runs the Apply lifecycle, downstream Goal/Apply dry run, prompt-size metrics, and fixture corpus. `check-package` creates/verifies/extracts both worktree artifacts. `check-release` first attempts both strict exports, so dirty state, an Unreleased changelog, a missing/misaligned tag, or origin mismatch stops before the long gates; only then does it run the aggregate, privacy, schema, and extracted-artifact checks.

Use `make export-plugin` and `make export-source` for strict-release artifacts. The plugin ZIP extracts directly to a plugin root (`.codex-plugin/`, `skills/`, manifest); the source ZIP extracts to one `CodexQB/` root containing source, tests, docs, and CI except for the two checkout-only validation controllers. `export-plugin-worktree` and `export-source-worktree` produce explicitly non-release review snapshots; `export-source-package` is the Gitless/filesystem source mode. The old `export-sanitized*` targets remain source-artifact aliases, but the ambiguous historical filename is not generated.

All new exports use manifest schema v3 and bind artifact type, layout, version, provenance status, normalized modes, file hashes, and a tree/content digest. Source schema-v2 packages remain verifier-readable for migration only when the legacy container is canonical: no prefix/trailer bytes, global or member comments, extra fields, directory entries, or member reordering. ZIP member order and stored metadata are canonical so two exports from unchanged input are byte-identical. Raw preflight rejects ZIP64, more than 65,534 members, archives over 576 MiB, and central directories over 8 MiB before parser allocation. Verification and extraction retain one immutable opened package snapshot after that preflight. Producer and verifier share one portable denylist and reject Git/runtime metadata, secret/local paths, caches, bytecode, AppleDouble/macOS metadata, nested ZIPs and polyglot envelopes, unexpected plugin skills/auto-activation surfaces, non-canonical/Windows-ambiguous names, traversal, symlinks, hardlinks, duplicates and case/Unicode collisions, unsafe modes, size overruns, manifest-external bytes, unexpected empty directories, unsafe root or expected-directory modes, nested mounts, root/descendant swaps, and post-inventory changes. The exporter keeps the verified and `fsync`ed temporary inode open through atomic publication, reopens and verifies the destination, rechecks mutable provenance, and restores an identity-pinned backup on failure. Its CLI reports stable path-safe failure codes and `output=created` on success without exposing the destination path. The extraction helper verifies before writing, requires parent-mount assurance before creating its private sibling, writes no-follow through descriptors, normalizes generated inner directories to `0755` independent of umask, publishes with no-replace semantics, reopens the published output relative to the parent, and rolls back only the identity-pinned generated tree on failure. Strict verification additionally accepts safe `0700` and `0750` directory modes used by plugin managers under restrictive umasks but never accepts group- or world-writable directories. If cleanup cannot prove removal of that generated tree, it returns `package_extract_cleanup_state_unknown` and leaves the recovery artifact in place for inspection rather than deleting an uncertain path. Run `scripts/verify_package_manifest.py --zip <package>` before extraction and `--root <extracted-root> --strict-artifact` afterwards. Strict extracted-root verification requires high mount assurance and retains `secure_repository_mount_identity_unavailable` as its fail-closed compatibility code. The manifest is an unkeyed consistency record, not a publisher signature, trusted timestamp, or host attestation.

`make check-public-privacy` runs `scripts/check_public_privacy.py` over public release-facing docs and evidence. It rejects local user paths, attachment paths, UUID-like attachment identifiers, and live Codex agent/thread IDs. Keep raw live runtime logs outside public docs unless they are intentionally redacted and independently reviewable.

Extracted source artifacts deliberately omit the checkout-only `scripts/validate.sh` and `scripts/run_extracted_validation.py` controllers under portable case-folding. Use the selected checkout's `scripts/run_extracted_validation.py --expected-head <externally-asserted-full-HEAD> --zip <source.zip> --root <extracted-root> --profile static`. The launcher binds the exact HEAD, selected root identity/path hash, held controller bundle, archive, manifest, and extracted path/mode/size inventory. Controller modules run only from a private, fsynced, content-revalidated snapshot; the extracted target remains data-only input to the static policy scanner. The resulting unsigned diagnostic is explicitly non-attested and cannot produce `VERIFIED`, Step 4 readiness, or finalization. Dynamic package/unit/behavior execution is deferred to PR4 host-native isolation. Use `make export-source-package` rather than an unmanifested directory copy.

## Optional Codex Validator Checks

The Codex skill/plugin validator scripts may require PyYAML in the active Python environment. Use them when available, but do not make them the only release gate.

```bash
CODEX_SKILL_VALIDATOR="${CODEX_SKILL_VALIDATOR:-$HOME/.codex/skills/.system/skill-creator/scripts/quick_validate.py}"
CODEX_PLUGIN_VALIDATOR="${CODEX_PLUGIN_VALIDATOR:-$HOME/.codex/skills/.system/plugin-creator/scripts/validate_plugin.py}"

python3 "$CODEX_SKILL_VALIDATOR" plugins/codexqb/skills/codexqb
python3 "$CODEX_PLUGIN_VALIDATOR" plugins/codexqb
```

To validate an optional local global skill copy:

```bash
CODEXQB_GLOBAL_SKILL="${CODEXQB_GLOBAL_SKILL:-$HOME/.codex/skills/codexqb}"
python3 "$CODEX_SKILL_VALIDATOR" "$CODEXQB_GLOBAL_SKILL"
```

## Validate Planner Docs

The skill ships a read-only validator for generated `Planner-docs/` outputs. Even checkout maintenance uses the reviewed absolute skill root derived from the active, explicitly invoked `$codexqb` loader's canonical `SKILL.md` and the sole executable launcher entrypoint. `<CODEXQB_SKILL_ROOT>` is documentation notation for that root, not an environment variable or a path selected from the target repository, `PATH`, or a sibling plugin.

If that active-loader `SKILL.md`, its canonical root, or `skill_launcher.py` is unavailable, Goal, Apply, planner validation, and Doctor report `BLOCKED`; no direct controller, repository-relative, environment-selected, `PATH`-selected, sibling-plugin, or equivalent ad hoc substitute is authorized.

```text
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step1
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode autopsy --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step2 --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step3-preflight --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step3 --strict
python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller planner-validator -- --root /path/to/project --mode step4 --strict
```

Mode contract:

- `step3-preflight` validates Step 2 artifacts before `Sub-Planing-Audit.md` exists.
- `step3` requires `Planner-docs/Sub-Planing-Audit.md` and validates post-audit structure.
- `step4` enforces semantic readiness rows, finding status consistency, NO_ACTION_REQUIRED, and strict Ledger v3 execution gates.
- Exit codes are stable: `0` passed, `1` document validation failed, `2` invocation/configuration/I/O error.
- Output includes `validation_status=...`, `validation_mode=...`, `error_count=...`, and `warning_count=...`.

Installed-plugin validation uses the same loader-bound launcher contract. If the active loader path or launcher is unavailable, stop with `BLOCKED`; do not substitute an equivalent ad hoc validator.

When changing the validator, test at least:

- a valid Step 2 fixture;
- a missing-section fixture;
- a normal filename containing `sk-` such as `task-spec.yaml`;
- a fake long secret token that should be detected;
- roadmap table extraction with historical phase references such as `Faz 0B-10` or `Phase 11`;
- optional `Autopsy.md`, `Project-Ontology.md`, and `Planing-Ledger.md` validation when present, and no failure when they are absent;
- optional `Project-Comprehension.md` validation when present, including evidence types, confidence values, architecture statuses, trace anchors, and open hypothesis probes;
- fenced code block heading false positives and duplicate real headings;
- Ledger v3 headings with split planning/execution status and split planning/implementation evidence, while v2 and legacy v1 ledgers remain accepted outside strict Step 4 execution with compatibility warnings;
- Step 2 Planning Scope Manifest validation, including active/deferred phase consistency and `wave` vs explicit `full` planning behavior;
- semantic Step 2 gates for implementation paths, exact validation commands, behavioral acceptance criteria, parent acceptance signals, dependency labels, concrete outputs, and domain-specific risks;
- shared 0.3.0 command safety gates for closed seven-field validation envelopes, root-bound non-symlink cwd checks, deny-only network and Tier-1 probes, canonical no-write pytest/unittest/Ruff profiles, unknown option/field rejection, shell-metacharacter and executable-spoof rejection, sensitive/output path rejection, full planned/evidence envelope binding, risk/security review consistency, and meaningful framework/invariant rows;
- Goal compiler artifacts from `scripts/goal_run.py`, including deterministic spec IDs, unique invocation run IDs, project-specific active sub-plan and READY queue collectors, compiler version metadata, template bundle digests, implementation contract digests, direct non-symlink external controller-state `goal-runs/<run>/` output boundaries, legacy in-repository archive-only rejection, parent/final-target symlink rejection, explicit-output resume behavior, bundled-validator stage prerequisite blockers, render-time validation, unsafe glob/path overlap rejection, source snapshot digest integrity, and no silent overwrite;
- Goal-run artifacts from `scripts/goal_run.py`, including no-subplans Step 2 `planning_horizon` collection from `Main-Planing.md`, active/deferred phase recommendations, parent acceptance signals, planning budget estimates, framework/invariant requirement flags, structured contract summaries, `implementation_contract_digest`, `validation_command_ids`, and contract-derived Step 4 work steps for parent signals, implementation paths, validation IDs, security review, dependency state, and outputs;
- Apply-run artifacts from `scripts/apply_run.py`, including deterministic apply spec IDs, unique invocation run IDs, strict Step 4 validator gating before prepare writes action artifacts, audit-derived task briefs, Step 4 readiness summaries, registered/HMAC-verified direct-run mutation boundaries, parent/task/final-target symlink rejection, run-directory `flock` serialization, full-file atomic Events replacement with unique contiguous sequences and a canonical previous-hash/hash chain, `workspace_baseline` hashes for branch/base commit and canonical no-exec Git plumbing evidence covering HEAD/index state, staged changes, unstaged tracked content, untracked inventory, and non-Git file inventory when applicable (historical status/diff field names carry versioned canonical evidence digests), descriptor/root-and-mount-bound two-pass full-worktree inventory with a shared 100,000-path, 64 MiB-per-file, 512 MiB aggregate-read, and 60-second deadline contract whose limit/identity/mount failures fail closed, required posture fields (`worktree_path`, `base_branch`, `working_branch`, `dirty_state`), default blocking for non-Git action runs unless `--allow-non-git-unsafe` records `workspace_mode: non_git_unsafe` and `user_approval: true`, default blocking for dirty/protected current Git worktrees unless `--allow-unverified-git-worktree` records explicit approval, `no_action` mode, default `commit_policy: none`, unsafe command rejection, no-action queue rejection, task ID traversal rejection, transition/reconcile CLI event log enforcement, writer-lock consistency, workspace baseline drift detection, external Superpowers readiness/reconcile validation, agent profile drift detection, `validation_command_ids` in tasks and briefs, controller-signed `capture-evidence` live change sets with changed-file hashes, complete `run-validation` receipts for every planned command, phase-aware `dispatch`/`record-agent`, signed `publish-review` receipts in spec/quality/security-if-required/final order, latest-published-event enforcement per validation ID and review phase, receipt tamper/context/reuse/staleness rejection, diff invalidation, direct-mode trusted-verification refusal, no silent progress overwrite, and fail-closed finalization;
- normalized duplicate ratio and uniform sub-plan count anomaly checks;
- Step 4 readiness gating for missing audit, headings-only audit, `BLOCKED`, `PASS`, `PASS_WITH_WARNINGS`, NO_ACTION_REQUIRED, unsafe readiness paths, duplicate conflicting rows, and prose such as `no P0/P1 findings`.

Run the tracked validator test suite:

```bash
python3 -m unittest discover -s tests -v
```

## Validate Skill Prompt Content

The test suite also checks that the Step 1 repo-aware intake contract remains wired into the skill:

```bash
python3 -m unittest discover -s tests -v
```

When changing Step 1 behavior, verify that:

- `SKILL.md` references `references/repo-aware-intake.md`;
- the intake reference still asks only the four stable fields;
- `SKILL.md` references `references/Autopsy-Planner.md` for Step 1.5;
- `Second-Planner.md` reads `Planner-docs/Autopsy.md`, `Planner-docs/Project-Ontology.md`, and `Planner-docs/Planing-Ledger.md` as optional supporting sources;
- Step 1.5, Step 2, Step 3, and Step 4 references mention `Planner-docs/Project-Comprehension.md` and `references/project-comprehension-methods.md`;
- `First-Planner.md` still accepts the same four required placeholders;
- `SKILL.md` references vibecoding, subagent, planning ledger, project ontology, assessment/budget, and engineering-principles guidance;
- prompts do not contain `rg -n "sk-` scans that could print secret-bearing lines.

## Goal Mode and Replanning Memory Checks

When changing Goal handoff behavior, verify that Step 2, Step 3, and Step 4 prompts define:

- the desired outcome;
- unchanged file boundaries;
- validation checkpoints;
- stop gates;
- token/context risk guidance;
- subagent usage rules;
- ledger update expectations for Step 4.
- comprehension evidence expectations, especially that tentative claims must be verified before implementation.

When changing replanning behavior, verify that `Planing-Ledger.md`, `Project-Ontology.md`, and `Project-Comprehension.md` are read as supporting evidence and never treated as stronger than current repository state or explicit user intent.

## Fixture Corpus Checks

CodexQB includes lightweight deterministic fixture corpus checks. They do not run live `codex exec`; they keep the fixture repos and expected signals stable for future live skill evals.

```bash
python3 evals/run_fixture_corpus_checks.py
```

`make check` runs this command. `python3 evals/run_fixture_checks.py` remains as a compatibility wrapper and should return the same exit code. Optional live skill evals may be added later with `codex exec --json` and structured rubric output, but they must not become required for dependency-free CI until the runtime is stable in CI.

CodexQB also tracks deterministic Goal/Apply prompt-size estimates:

```bash
python3 evals/run_goal_apply_metric_checks.py
```

This emits approximate token counts for the static Step 4 handoff, dynamic direct and `subagent_serial` Goal prompts, direct Apply briefs, and subagent dispatch messages. These estimates are for regression tracking only; they are not exact model billing. Goal and Apply artifacts include a structured `budget_contract`; runtime token usage stays `not_observed` unless an actual runtime usage source is available.

CodexQB also keeps a repeatable downstream artifact dry run:

```bash
python3 evals/run_downstream_goal_apply_dry_run.py
```

This builds a disposable git-backed project with small source and test files, runs strict Step 2, Step 3 preflight, Step 3, and Step 4 validation, compiles Goal previews, prepares a `subagent_serial` Apply run, captures the live change set, executes planned validations, and exercises the ordered review-receipt protocol. It does not call live Codex tools or prove real multi-agent model execution; a live E2E run is required for that claim.

## Optional Local Skill Copy Parity

If you maintain a local global skill copy, sync without generated Python caches and compare it with the repo-bundled skill:

```bash
CODEXQB_GLOBAL_SKILL="${CODEXQB_GLOBAL_SKILL:-$HOME/.codex/skills/codexqb}"
rsync -a --delete --exclude '__pycache__/' --exclude '*.pyc' plugins/codexqb/skills/codexqb/ "$CODEXQB_GLOBAL_SKILL/"
diff -ru -x __pycache__ plugins/codexqb/skills/codexqb "$CODEXQB_GLOBAL_SKILL"
```

This is a local-only workflow check. It is not required for CI or repository marketplace releases.

## Check For Stale Invocation Names

CodexQB should use `$codexqb` as the skill invocation name and must retain `policy.allow_implicit_invocation: false`; ordinary Codex requests must not activate the workflow. The default release check includes this scan:

```bash
make check
```

No public-facing stale references should remain.

## Reproducible Distribution Export

Do not create release zips with Finder or generic directory compression, because ignored files such as `.git/`, `__pycache__/`, `.env`, `artifacts/`, `logs/`, or `tmp/` can be included.

Build the two explicit strict-release artifacts:

```bash
make export-plugin
make export-source
```

These write `codexqb-plugin-<version>.zip` and `CodexQB-source-<version>.zip` only after the strict Git/changelog/tag contract passes. Use the `*-worktree` targets only for explicit non-release review snapshots, or `make export-source-package` for an explicit Gitless/filesystem source artifact. The legacy `export-sanitized*` names are compatibility aliases for source exports; they do not recreate `CodexQB-sanitized.zip`. Verify generated ZIPs before extraction and the exact plugin/source roots after extraction. Never infer release truth from a filename alone: a historical repository-root ZIP may be stale evidence, and only freshly passing strict artifacts whose manifests report release provenance are release-eligible.

The default `make check` gate validates tracked archive contents in Git checkouts and fails if forbidden tracked paths such as `.git/`, `__pycache__/`, `.env`, `artifacts/`, `logs/`, `tmp/`, `__MACOSX/`, `.pyc`, `.pem`, `.key`, or `.local` files would be included. An extracted package does not run `make check` itself; the trusted outer controller applies equivalent source-owned checks to its held root. The repository gate also runs the apply-run behavior smoke so the public `prepare`/`transition`/`capture-evidence`/`run-validation`/phase-aware `dispatch` and `record-agent`/`publish-review`/`validate`/`finalize` lifecycle is exercised through subprocesses before release. Keep an explicit negative test proving direct mode cannot independently issue reviewer receipts, reach trusted `VERIFIED`, or finalize.

## Release Flow

1. Update `plugins/codexqb/.codex-plugin/plugin.json`.
2. Update `plugins/codexqb/skills/codexqb/SKILL.md` and references as needed.
3. Update `plugins/codexqb/skills/codexqb/references/repo-aware-intake.md` if Step 1 intake behavior changes.
4. Update `plugins/codexqb/skills/codexqb/references/Autopsy-Planner.md` if Step 1.5 autopsy behavior changes.
5. Update `plugins/codexqb/skills/codexqb/references/vibecoding-principles.md`, `subagent-playbook.md`, `planning-ledger.md`, `project-ontology.md`, `assessment-and-budget.md`, or `engineering-principles.md` when planning behavior changes.
6. Update `plugins/codexqb/skills/codexqb/references/Fourth-Planner.md` if implementation handoff behavior changes.
7. Update `plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py` if planner structure or readiness gates change.
8. Update `plugins/codexqb/skills/codexqb/scripts/goal_run.py`, `apply_run.py`, or `references/apply-run-schema.json` if Goal preview or Step 4 apply artifacts change.
9. Run the applicable split gates and `make check`; keep the changelog under `Unreleased` during development.
10. Optionally run the Codex skill/plugin validator scripts if their Python dependencies are available.
11. Optionally sync and compare the local global skill copy for manual testing only when the active task permits global cache changes.
12. When release authority is explicit, date the changelog, commit the exact reviewed tree, push `main`, create the matching `v<version>` tag at that commit, and ensure `origin/main` resolves to the same commit.
13. Run `make check-release` from that exact clean tagged checkout and preserve both verified artifact digests as release evidence.
14. Reinstall the plugin in Codex:

   ```bash
   codex plugin add codexqb@codexqb
   ```

15. If Codex reports stale marketplace metadata, refresh the marketplace and retry:

   ```bash
   codex plugin marketplace upgrade
   codex plugin add codexqb@codexqb
   ```

16. Start a new Codex thread before testing.

## Public Directory Status

CodexQB currently uses repository marketplace distribution. Public directory or workspace sharing distribution can be revisited separately; this release focuses on repo-marketplace installation and local/team validation.

## Contribution Guidelines

- Keep the skill concise.
- Keep long planner prompts in `references/`.
- Preserve the `Planner-docs/*Planing*` filenames required by the bundled prompts.
- Do not add MCP servers, apps, hooks, or assets unless the plugin manifest and validator are updated accordingly.
- Do not put secrets or environment-specific credentials into docs, planner prompts, or examples.
