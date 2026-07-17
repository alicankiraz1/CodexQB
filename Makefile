SHELL := /bin/bash
PYTHON ?= python3
NO_BYTECODE = PYTHONDONTWRITEBYTECODE=1
PLATFORM_POLICY ?= auto

.PHONY: check check-fast check-static check-unit check-platform check-schema check-behavior check-package check-public-privacy check-release test export-plugin export-source export-plugin-worktree export-source-worktree export-source-package export-sanitized export-sanitized-worktree export-sanitized-source-package

# The default gate remains dependency-free. Draft 2020-12 schema parity is a
# development/release gate because it intentionally uses requirements-ci.txt.
check: check-static check-unit check-platform check-behavior check-package

check-fast: check-static
	$(NO_BYTECODE) $(PYTHON) scripts/run_test_suite.py fast

check-static:
	$(NO_BYTECODE) bash scripts/validate.sh static
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	PYTHONPYCACHEPREFIX="$$tmpdir/pycache" $(PYTHON) -m compileall -q plugins scripts evals tests
	@if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then git diff --check; fi

check-unit:
	$(NO_BYTECODE) $(PYTHON) scripts/run_test_suite.py unit

check-platform:
	$(NO_BYTECODE) $(PYTHON) scripts/run_test_suite.py platform
	@set -euo pipefail; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(NO_BYTECODE) $(PYTHON) plugins/codexqb/skills/codexqb/scripts/doctor.py --json > "$$tmpdir/doctor.json"; \
	$(NO_BYTECODE) $(PYTHON) plugins/codexqb/skills/codexqb/scripts/doctor.py; \
	probe_output="$$( $(NO_BYTECODE) $(PYTHON) tests/platform/run_mount_identity_probe.py )"; \
	echo "$$probe_output"; \
	if [[ "$(PLATFORM_POLICY)" == "required" && "$$probe_output" != *"status=ready "* ]]; then \
		echo "required_platform_capability_unavailable"; \
		exit 1; \
	elif [[ "$(PLATFORM_POLICY)" != "required" && "$(PLATFORM_POLICY)" != "auto" ]]; then \
		echo "unknown_platform_policy=$(PLATFORM_POLICY)"; \
		exit 2; \
	fi

check-schema:
	$(NO_BYTECODE) $(PYTHON) scripts/validate_apply_schema.py
	$(NO_BYTECODE) $(PYTHON) -m unittest -v tests.test_apply_schema

check-behavior:
	$(NO_BYTECODE) bash scripts/validate.sh behavior

check-package:
	$(NO_BYTECODE) bash scripts/validate.sh package

check-public-privacy:
	$(NO_BYTECODE) $(PYTHON) scripts/check_public_privacy.py --root . --scope all

# Keep release-only provenance out of check/check-fast. The strict export runs
# first so an Unreleased changelog or missing tag fails before the long gates.
check-release:
	@set -euo pipefail; \
	tmpdir="$$(mktemp -d)"; \
	trap 'rm -rf "$$tmpdir"' EXIT; \
	$(NO_BYTECODE) $(PYTHON) scripts/check_public_privacy.py --root . --scope all --require-empty-baseline; \
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type plugin --provenance-mode strict-release --output "$$tmpdir/codexqb-plugin-release.zip"; \
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type source --provenance-mode strict-release --output "$$tmpdir/CodexQB-source-release.zip"; \
	$(MAKE) check; \
	$(MAKE) check-public-privacy; \
	$(MAKE) check-schema; \
	$(NO_BYTECODE) $(PYTHON) scripts/verify_package_manifest.py --zip "$$tmpdir/codexqb-plugin-release.zip"; \
	$(NO_BYTECODE) $(PYTHON) scripts/verify_package_manifest.py --zip "$$tmpdir/CodexQB-source-release.zip"; \
	$(NO_BYTECODE) $(PYTHON) scripts/extract_verified_package.py --zip "$$tmpdir/codexqb-plugin-release.zip" --output "$$tmpdir/plugin" --artifact-type plugin; \
	$(NO_BYTECODE) $(PYTHON) scripts/extract_verified_package.py --zip "$$tmpdir/CodexQB-source-release.zip" --output "$$tmpdir/source" --artifact-type source; \
	$(NO_BYTECODE) $(PYTHON) scripts/verify_package_manifest.py --root "$$tmpdir/plugin" --strict-artifact --expected-artifact-type plugin; \
	test -f "$$tmpdir/plugin/.codex-plugin/plugin.json"; \
	$(NO_BYTECODE) $(PYTHON) scripts/verify_package_manifest.py --root "$$tmpdir/source/CodexQB" --strict-artifact --expected-artifact-type source; \
	cd "$$tmpdir/source/CodexQB" && CODEXQB_VALIDATE_SKIP_UNITTESTS=1 CODEXQB_VALIDATE_SKIP_BEHAVIOR_SMOKE=1 bash scripts/validate.sh

# Legacy full discovery remains available for maintainers. Gate-aware CI uses
# the explicit targets above so schema/package/platform behavior cannot drift.
test:
	$(NO_BYTECODE) $(PYTHON) -m unittest discover -s tests -v

export-plugin:
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type plugin --provenance-mode strict-release

export-source:
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type source --provenance-mode strict-release

export-plugin-worktree:
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type plugin --provenance-mode worktree

export-source-worktree:
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type source --provenance-mode worktree

export-source-package:
	$(NO_BYTECODE) $(PYTHON) scripts/export_sanitized.py --root . --artifact-type source --provenance-mode filesystem

# Compatibility aliases keep the old target names without recreating the
# ambiguous legacy artifact filename.
export-sanitized: export-source

export-sanitized-worktree: export-source-worktree

export-sanitized-source-package: export-source-package
