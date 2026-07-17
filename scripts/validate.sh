#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PROFILE="${1:-all}"
case "$PROFILE" in
  all|static|fast|unit|platform|behavior|package)
    ;;
  *)
    echo "unknown_validation_profile=$PROFILE"
    exit 2
    ;;
esac

export PYTHONDONTWRITEBYTECODE=1
unset PYTHONPATH PYTHONHOME
export PYTHONNOUSERSITE=1

# Bootstrap the held accidental-mutation guard before any checkout-owned
# validation/controller Python process is executed.
TMPDIR_VALIDATE="$(mktemp -d)"
TRUST_GUARD_HELD="$TMPDIR_VALIDATE/controller_test_support.py"
TRUST_GUARD_BASELINE="$TMPDIR_VALIDATE/real-trust-baseline.json"
TRUST_GUARD_READY=0

cleanup_validate() {
  local validation_status=$?
  local trust_status=0
  trap - EXIT
  set +e
  if [[ "$TRUST_GUARD_READY" == "1" ]]; then
    python3 -I -S -B "$TRUST_GUARD_HELD" verify --baseline "$TRUST_GUARD_BASELINE"
    trust_status=$?
    if [[ "$trust_status" != "0" ]]; then
      echo "real_controller_trust_guard=changed" >&2
    fi
  fi
  rm -rf "$TMPDIR_VALIDATE"
  if [[ "$trust_status" != "0" ]]; then
    exit "$trust_status"
  fi
  if [[ "$validation_status" != "0" ]]; then
    exit "$validation_status"
  fi
  exit 0
}
trap cleanup_validate EXIT

# Hold one guard copy so ordinary checkout edits cannot make the before/after
# algorithms drift. This detects accidental test mutation only; it is not
# same-UID tamper resistance, host authority, or attestation. The commitment
# contains hashes and metadata only, never trust-store paths or secret bytes.
cp tests/controller_test_support.py "$TRUST_GUARD_HELD"
chmod 0600 "$TRUST_GUARD_HELD"
python3 -I -S -B "$TRUST_GUARD_HELD" capture --output "$TRUST_GUARD_BASELINE"
TRUST_GUARD_READY=1

# Establish the checkout-owned static-policy trust anchor as the first
# repository validation process after the held guard is active. Extracted
# artifacts do not contain this script.
python3 -I -S -B scripts/check_repository_io_policy.py --root . --layout repository-plugin

# Keep the no-exec Git evidence implementation and its regression suite wired
# into the source validation surface. The unit partition executes the test;
# these existence checks also make an incomplete checkout fail closed before
# repository validation begins.
GIT_EVIDENCE_IMPLEMENTATION="plugins/codexqb/skills/codexqb/scripts/git_evidence.py"
GIT_EVIDENCE_TEST="tests/test_git_evidence.py"
test -f "$GIT_EVIDENCE_IMPLEMENTATION"
test -f "$GIT_EVIDENCE_TEST"

python3 -I -S -B \
  plugins/codexqb/skills/codexqb/scripts/repository_validation.py \
  --root . \
  --contract full \
  --workspace-mode git

if [[ "$PROFILE" == "all" || "$PROFILE" == "package" ]]; then
PLUGIN_PACKAGE="$TMPDIR_VALIDATE/codexqb-plugin-worktree.zip"
SOURCE_PACKAGE="$TMPDIR_VALIDATE/CodexQB-source-worktree.zip"
PACKAGE_PROVENANCE_MODE="worktree"
python3 -I -S -B scripts/export_sanitized.py --root . --artifact-type plugin --provenance-mode "$PACKAGE_PROVENANCE_MODE" --output "$PLUGIN_PACKAGE" >/dev/null
python3 -I -S -B scripts/export_sanitized.py --root . --artifact-type source --provenance-mode "$PACKAGE_PROVENANCE_MODE" --output "$SOURCE_PACKAGE" >/dev/null
python3 -I -S -B scripts/verify_package_manifest.py --zip "$PLUGIN_PACKAGE"
python3 -I -S -B scripts/verify_package_manifest.py --zip "$SOURCE_PACKAGE"
python3 -I -S -B scripts/extract_verified_package.py \
  --zip "$PLUGIN_PACKAGE" \
  --output "$TMPDIR_VALIDATE/plugin-extracted" \
  --artifact-type plugin
python3 -I -S -B scripts/extract_verified_package.py \
  --zip "$SOURCE_PACKAGE" \
  --output "$TMPDIR_VALIDATE/source-extracted" \
  --artifact-type source
python3 -I -S -B scripts/verify_package_manifest.py \
  --root "$TMPDIR_VALIDATE/plugin-extracted" \
  --strict-artifact \
  --expected-artifact-type plugin
python3 -I -S -B scripts/verify_package_manifest.py \
  --root "$TMPDIR_VALIDATE/source-extracted/CodexQB" \
  --strict-artifact \
  --expected-artifact-type source
test -f "$TMPDIR_VALIDATE/plugin-extracted/.codex-plugin/plugin.json"
test -f "$TMPDIR_VALIDATE/plugin-extracted/skills/codexqb/SKILL.md"
test ! -e "$TMPDIR_VALIDATE/plugin-extracted/tests"
test ! -e "$TMPDIR_VALIDATE/source-extracted/CodexQB/.git"
# Always use the source-owned checker and compare the extracted runtime bytes
# to that trusted source. Package-controlled self-checkers are never executed.
python3 -I -S -B scripts/check_repository_io_policy.py --root "$TMPDIR_VALIDATE/plugin-extracted" --layout extracted-plugin
python3 -I -S -B scripts/check_repository_io_policy.py --root "$TMPDIR_VALIDATE/source-extracted/CodexQB" --layout repository-plugin
CODEXQB_PACKAGE_ZIPS="$PLUGIN_PACKAGE:$SOURCE_PACKAGE" python3 -I -S -B - <<'PY'
import hashlib
import os
import re
import sys
import zipfile
from pathlib import Path

safety_dir = Path("plugins/codexqb/skills/codexqb/scripts").resolve()
sys.path.insert(0, safety_dir.as_posix())
from safety_contracts import (  # noqa: E402
    package_secret_match_locations,
    package_secret_path_match_locations,
)

bad = re.compile(
    r"(^|/)(\.git|\.codexqb|__pycache__|\.env|artifacts|logs|tmp|__MACOSX)(/|$)"
    r"|\.pyc$|\.pem$|\.key$|\.local($|\.)"
)
findings: list[tuple[str, str, int]] = []
for archive_name in os.environ["CODEXQB_PACKAGE_ZIPS"].split(":"):
    archive_path = Path(archive_name)
    with zipfile.ZipFile(archive_path) as archive:
        names = set(archive.namelist())
        expected_manifest = (
            "PACKAGE-MANIFEST.json"
            if archive_path.name.startswith("codexqb-plugin-")
            else "CodexQB/PACKAGE-MANIFEST.json"
        )
        if expected_manifest not in names:
            expected_path_sha256 = hashlib.sha256(
                expected_manifest.encode("utf-8")
            ).hexdigest()
            findings.append(("missing_package_manifest", expected_path_sha256, 0))
        for info in archive.infolist():
            name = info.filename
            path_sha256 = hashlib.sha256(name.encode("utf-8", errors="surrogateescape")).hexdigest()
            for rule, offset in package_secret_path_match_locations(name):
                findings.append((f"package_path_{rule}", path_sha256, offset))
            if bad.search(name):
                findings.append(("blocked_path", path_sha256, 0))
                continue
            if info.is_dir():
                continue
            data = archive.read(info)
            for rule, offset in package_secret_match_locations(data, Path(name).suffix):
                findings.append((rule, path_sha256, offset))

if findings:
    print("sanitized_zip_hygiene_failed")
    for index, (rule, path_sha256, offset) in enumerate(findings, start=1):
        print(
            f"zip_hygiene_finding=index-{index}:"
            f"path_sha256:{path_sha256}:offset:{offset}:rule:{rule}"
        )
    sys.exit(1)
print("sanitized_zip_hygiene=passed")
PY
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" != "1" ]]; then
  python3 -I -S -B scripts/run_test_suite.py package
fi
fi

if [[ "$PROFILE" == "fast" ]]; then
  python3 -I -S -B scripts/run_test_suite.py fast
elif [[ "$PROFILE" == "all" || "$PROFILE" == "unit" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" == "1" ]]; then
  echo "unit_tests_skipped=1"
else
  python3 -I -S -B scripts/run_test_suite.py unit
fi
fi

if [[ "$PROFILE" == "all" || "$PROFILE" == "platform" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" != "1" ]]; then
  python3 -I -S -B scripts/run_test_suite.py platform
fi
fi

if [[ "$PROFILE" == "all" || "$PROFILE" == "behavior" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_BEHAVIOR_SMOKE:-0}" == "1" ]]; then
  echo "behavior_smokes_skipped=1"
else
  # evals/run_apply_behavior_smoke.py prints apply_behavior_smoke=passed on success.
  python3 -I -S -B evals/run_apply_behavior_smoke.py
  # evals/run_downstream_goal_apply_dry_run.py prints downstream_goal_apply_dry_run=passed on success.
  python3 -I -S -B evals/run_downstream_goal_apply_dry_run.py
  python3 -I -S -B scripts/run_test_suite.py behavior
fi
# evals/run_goal_apply_metric_checks.py prints goal_apply_metric_checks=passed on success.
python3 -I -S -B evals/run_goal_apply_metric_checks.py
python3 -I -S -B evals/run_fixture_corpus_checks.py
fi
