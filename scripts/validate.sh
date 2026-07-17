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
HAS_PACKAGE_MANIFEST=0
if [[ -f "PACKAGE-MANIFEST.json" ]]; then
  # A Gitless extracted source package is authenticated by its manifest before
  # Git discovery. Package validation must not require a Git executable.
  python3 scripts/verify_package_manifest.py --root . --strict-artifact --expected-artifact-type source
  HAS_PACKAGE_MANIFEST=1
fi

TRUSTED_GIT=""
if [[ "$HAS_PACKAGE_MANIFEST" != "1" ]]; then
  TRUSTED_GIT="$(PATH=/bin:/usr/bin command -v git || true)"
  if [[ -z "$TRUSTED_GIT" ]]; then
    echo "trusted_git_executable_unavailable"
    exit 1
  fi
fi
export CODEXQB_TRUSTED_GIT="$TRUSTED_GIT"
GIT_TOP_LEVEL=""
if [[ -n "$TRUSTED_GIT" ]]; then
  GIT_TOP_LEVEL="$("$TRUSTED_GIT" rev-parse --show-toplevel 2>/dev/null || true)"
fi
IS_EXACT_GIT_ROOT=0
if [[ -n "$GIT_TOP_LEVEL" && "$(cd "$GIT_TOP_LEVEL" && pwd -P)" == "$(pwd -P)" ]]; then
  IS_EXACT_GIT_ROOT=1
fi
if [[ "$HAS_PACKAGE_MANIFEST" != "1" && "$IS_EXACT_GIT_ROOT" != "1" ]]; then
  echo "package_manifest_missing_for_gitless_tree"
  exit 1
fi
TMPDIR_VALIDATE="$(mktemp -d)"
trap 'rm -rf "$TMPDIR_VALIDATE"' EXIT
export CODEXQB_TRUST_ROOT="$TMPDIR_VALIDATE/codexqb-trust"
mkdir -m 700 "$CODEXQB_TRUST_ROOT"

if [[ "$PROFILE" == "all" || "$PROFILE" == "static" || "$PROFILE" == "fast" ]]; then
python3 -m json.tool .agents/plugins/marketplace.json >/dev/null
python3 -m json.tool plugins/codexqb/.codex-plugin/plugin.json >/dev/null

required_files=(
  ".agents/plugins/marketplace.json"
  "plugins/codexqb/.codex-plugin/plugin.json"
  "plugins/codexqb/skills/codexqb/SKILL.md"
  "plugins/codexqb/skills/codexqb/agents/openai.yaml"
  "plugins/codexqb/skills/codexqb/scripts/safety_contracts.py"
  "plugins/codexqb/skills/codexqb/scripts/artifact_io.py"
  "plugins/codexqb/skills/codexqb/scripts/evidence_contracts.py"
  "plugins/codexqb/skills/codexqb/scripts/repository_evidence.py"
  "plugins/codexqb/skills/codexqb/scripts/git_evidence.py"
  "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"
  "plugins/codexqb/skills/codexqb/scripts/goal_run.py"
  "plugins/codexqb/skills/codexqb/scripts/apply_run.py"
  "plugins/codexqb/skills/codexqb/scripts/mount_identity.py"
  "plugins/codexqb/skills/codexqb/scripts/doctor.py"
  "plugins/codexqb/skills/codexqb/references/First-Planner.md"
  "plugins/codexqb/skills/codexqb/references/Autopsy-Planner.md"
  "plugins/codexqb/skills/codexqb/references/Second-Planner.md"
  "plugins/codexqb/skills/codexqb/references/Third-Planner.md"
  "plugins/codexqb/skills/codexqb/references/Fourth-Planner.md"
  "plugins/codexqb/skills/codexqb/references/goal-compiler.md"
  "plugins/codexqb/skills/codexqb/references/apply-orchestrator.md"
  "plugins/codexqb/skills/codexqb/references/apply-run-schema.json"
  "plugins/codexqb/skills/codexqb/references/apply/controller.md"
  "plugins/codexqb/skills/codexqb/references/apply/implementer.md"
  "plugins/codexqb/skills/codexqb/references/apply/task-reviewer.md"
  "plugins/codexqb/skills/codexqb/references/apply/security-reviewer.md"
  "plugins/codexqb/skills/codexqb/references/apply/fixer.md"
  "plugins/codexqb/skills/codexqb/references/apply/final-reviewer.md"
  "plugins/codexqb/skills/codexqb/references/goal-specs/step15.md"
  "plugins/codexqb/skills/codexqb/references/goal-specs/step2.md"
  "plugins/codexqb/skills/codexqb/references/goal-specs/step3.md"
  "plugins/codexqb/skills/codexqb/references/goal-specs/step4.md"
  "plugins/codexqb/skills/codexqb/references/handoffs/run-step2.md"
  "plugins/codexqb/skills/codexqb/references/handoffs/run-step3.md"
  "plugins/codexqb/skills/codexqb/references/handoffs/run-step4.md"
  "plugins/codexqb/skills/codexqb/references/repo-aware-intake.md"
  "plugins/codexqb/skills/codexqb/references/workflow-quality.md"
  "plugins/codexqb/skills/codexqb/references/vibecoding-principles.md"
  "plugins/codexqb/skills/codexqb/references/subagent-playbook.md"
  "plugins/codexqb/skills/codexqb/references/planning-ledger.md"
  "plugins/codexqb/skills/codexqb/references/project-ontology.md"
  "plugins/codexqb/skills/codexqb/references/project-comprehension-methods.md"
  "plugins/codexqb/skills/codexqb/references/probe-policy.md"
  "plugins/codexqb/skills/codexqb/references/assessment-and-budget.md"
  "plugins/codexqb/skills/codexqb/references/engineering-principles.md"
  "evals/run_apply_behavior_smoke.py"
  "evals/run_downstream_goal_apply_dry_run.py"
  "evals/run_goal_apply_metric_checks.py"
  "evals/run_fixture_corpus_checks.py"
  "evals/run_fixture_checks.py"
  "requirements-ci.txt"
  "scripts/export_sanitized.py"
  "scripts/extract_verified_package.py"
  "scripts/package_policy.py"
  "scripts/validate_openai_yaml.py"
  "scripts/verify_package_manifest.py"
  "scripts/validate_apply_schema.py"
  "scripts/run_test_suite.py"
  "tests/test_package_manifest.py"
  "tests/test_package_extraction.py"
  "tests/test_apply_schema.py"
  "tests/test_apply_inventory.py"
  "tests/test_evidence_contracts.py"
  "tests/test_repository_evidence.py"
  "tests/test_git_evidence.py"
  "tests/test_mount_identity.py"
  "tests/test_doctor.py"
  "tests/test_suite_partition.py"
  "tests/platform/run_mount_identity_probe.py"
  "README.md"
  "CHANGELOG.md"
  "docs/INSTALLATION.md"
  "docs/USAGE.md"
  "docs/MAINTAINING.md"
  "docs/FEEDBACK-CLOSURE-AUDIT.md"
  "docs/release-audits/0.3.0-feedback-closure.md"
  "LICENSE"
)

for path in "${required_files[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "missing_required_file=$path"
    exit 1
  fi
done

python3 scripts/validate_openai_yaml.py

python3 - <<'PY'
import hashlib
from pathlib import Path
import sys

needles = ("project-" + "planner", "Project " + "Planner", "$" + "project-" + "planner")
ignored_parts = {
    ".git",
    "__MACOSX",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "artifacts",
    "build",
    "dist",
    "logs",
    "tmp",
}
blocked_suffixes = {".key", ".pem", ".pyc", ".zip"}
findings: list[str] = []
for path in Path(".").rglob("*"):
    if not path.is_file():
        continue
    if ignored_parts.intersection(path.parts):
        continue
    if path.suffix in blocked_suffixes:
        continue
    if path.name == ".DS_Store" or path.name.startswith(".env"):
        continue
    if path.name.endswith(".local") or ".local." in path.name:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for needle in needles:
        if needle in text:
            findings.append(hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest())
            break

if findings:
    print("stale_invocation_references_found")
    for index, path_sha256 in enumerate(findings, start=1):
        print(
            f"stale_invocation_finding=index-{index}:"
            f"path_sha256:{path_sha256}:rule:stale_invocation_text"
        )
    sys.exit(1)
PY

python3 - <<'PY'
import hashlib
from pathlib import Path
import os
import subprocess
import sys

safety_dir = Path("plugins/codexqb/skills/codexqb/scripts").resolve()
sys.path.insert(0, safety_dir.as_posix())
from safety_contracts import (  # noqa: E402
    package_secret_match_locations,
    package_secret_path_match_locations,
)

GIT = os.environ["CODEXQB_TRUSTED_GIT"]

def in_git_checkout() -> bool:
    if not GIT:
        return False
    return subprocess.run(
        [GIT, "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def package_paths() -> list[Path]:
    ignored_parts = {
        ".git",
        "__MACOSX",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "artifacts",
        "build",
        "dist",
        "logs",
        "tmp",
    }
    paths: list[Path] = []
    for path in Path(".").rglob("*"):
        if not path.is_file():
            continue
        if ignored_parts.intersection(path.parts):
            continue
        if path.name == ".DS_Store":
            continue
        paths.append(path)
    return paths


if in_git_checkout():
    tracked = subprocess.run([GIT, "ls-files", "-z"], check=True, capture_output=True).stdout
    paths = [Path(item.decode("utf-8")) for item in tracked.split(b"\0") if item]
    failure_label = "tracked_secret_hygiene_failed"
else:
    paths = package_paths()
    failure_label = "package_secret_hygiene_failed"
    print("package_secret_hygiene_mode=filesystem")

# Shared provider labels include openrouter_api_key. Canonical environment
# references and redaction placeholders are handled by the shared policy.

findings: list[tuple[str, int, str]] = []
for path in paths:
    path_sha256 = hashlib.sha256(path.as_posix().encode("utf-8")).hexdigest()
    for name, offset in package_secret_path_match_locations(path.as_posix()):
        findings.append((path_sha256, offset, f"package_path_{name}"))
    try:
        data = path.read_bytes()
    except OSError:
        findings.append((path_sha256, 0, "package_payload_unreadable"))
        continue

    for name, offset in package_secret_match_locations(data, path.suffix):
        findings.append((path_sha256, offset, name))

if findings:
    print(failure_label)
    for index, (path_sha256, offset, rule) in enumerate(findings, start=1):
        print(
            f"secret_hygiene_finding=index-{index}:"
            f"path_sha256:{path_sha256}:offset:{offset}:rule:{rule}"
        )
    sys.exit(1)
PY

python3 - <<'PY'
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile

GIT = os.environ["CODEXQB_TRUSTED_GIT"]

bad = re.compile(
    r"(^|/)(\.git|__pycache__|\.env|artifacts|logs|tmp|__MACOSX)(/|$)"
    r"|\.pyc$|\.pem$|\.key$|\.local($|\.)"
)

def in_git_checkout() -> bool:
    if not GIT:
        return False
    return subprocess.run(
        [GIT, "rev-parse", "--is-inside-work-tree"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    ).returncode == 0


def package_offenders() -> list[str]:
    ignored_parts = {
        ".git",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "build",
        "dist",
    }
    offenders: list[str] = []
    for path in Path(".").rglob("*"):
        if not path.is_file():
            continue
        if ignored_parts.intersection(path.parts):
            continue
        rel = path.as_posix()
        if bad.search(rel):
            offenders.append(rel)
    return offenders


if in_git_checkout():
    archive = subprocess.run([GIT, "archive", "--format=tar", "HEAD"], check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tar:
        offenders = [member.name for member in tar.getmembers() if bad.search(member.name)]
    failure_label = "archive_hygiene_failed"
else:
    offenders = package_offenders()
    failure_label = "package_hygiene_failed"
    print("package_hygiene_mode=filesystem")

if offenders:
    print(failure_label)
    for index, offender in enumerate(offenders, start=1):
        path_sha256 = hashlib.sha256(offender.encode("utf-8")).hexdigest()
        print(f"archive_hygiene_finding=index-{index}:path_sha256:{path_sha256}:rule:blocked_path")
    sys.exit(1)
PY
fi

if [[ "$PROFILE" == "all" || "$PROFILE" == "package" ]]; then
PLUGIN_PACKAGE="$TMPDIR_VALIDATE/codexqb-plugin-worktree.zip"
SOURCE_PACKAGE="$TMPDIR_VALIDATE/CodexQB-source-worktree.zip"
if [[ "$IS_EXACT_GIT_ROOT" == "1" ]]; then
  PACKAGE_PROVENANCE_MODE="worktree"
else
  PACKAGE_PROVENANCE_MODE="filesystem"
fi
python3 scripts/export_sanitized.py --root . --artifact-type plugin --provenance-mode "$PACKAGE_PROVENANCE_MODE" --output "$PLUGIN_PACKAGE" >/dev/null
python3 scripts/export_sanitized.py --root . --artifact-type source --provenance-mode "$PACKAGE_PROVENANCE_MODE" --output "$SOURCE_PACKAGE" >/dev/null
python3 scripts/verify_package_manifest.py --zip "$PLUGIN_PACKAGE"
python3 scripts/verify_package_manifest.py --zip "$SOURCE_PACKAGE"
python3 scripts/extract_verified_package.py \
  --zip "$PLUGIN_PACKAGE" \
  --output "$TMPDIR_VALIDATE/plugin-extracted" \
  --artifact-type plugin
python3 scripts/extract_verified_package.py \
  --zip "$SOURCE_PACKAGE" \
  --output "$TMPDIR_VALIDATE/source-extracted" \
  --artifact-type source
python3 scripts/verify_package_manifest.py \
  --root "$TMPDIR_VALIDATE/plugin-extracted" \
  --strict-artifact \
  --expected-artifact-type plugin
python3 scripts/verify_package_manifest.py \
  --root "$TMPDIR_VALIDATE/source-extracted/CodexQB" \
  --strict-artifact \
  --expected-artifact-type source
test -f "$TMPDIR_VALIDATE/plugin-extracted/.codex-plugin/plugin.json"
test -f "$TMPDIR_VALIDATE/plugin-extracted/skills/codexqb/SKILL.md"
test ! -e "$TMPDIR_VALIDATE/plugin-extracted/tests"
test ! -e "$TMPDIR_VALIDATE/source-extracted/CodexQB/.git"
CODEXQB_PACKAGE_ZIPS="$PLUGIN_PACKAGE:$SOURCE_PACKAGE" python3 - <<'PY'
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
findings: list[tuple[str, int, str]] = []
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
            findings.append(
                (
                    hashlib.sha256(expected_manifest.encode("utf-8")).hexdigest(),
                    0,
                    "missing_package_manifest",
                )
            )
        for info in archive.infolist():
            name = info.filename
            path_sha256 = hashlib.sha256(name.encode("utf-8")).hexdigest()
            for rule, offset in package_secret_path_match_locations(name):
                findings.append((path_sha256, offset, f"package_path_{rule}"))
            if bad.search(name):
                findings.append((path_sha256, 0, "blocked_path"))
                continue
            if info.is_dir():
                continue
            data = archive.read(info)
            for rule, offset in package_secret_match_locations(data, Path(name).suffix):
                findings.append((path_sha256, offset, rule))

if findings:
    print("sanitized_zip_hygiene_failed")
    for index, (path_sha256, offset, rule) in enumerate(findings, start=1):
        print(
            f"zip_hygiene_finding=index-{index}:"
            f"path_sha256:{path_sha256}:offset:{offset}:rule:{rule}"
        )
    sys.exit(1)
print("sanitized_zip_hygiene=passed")
PY
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" != "1" ]]; then
  python3 scripts/run_test_suite.py package
fi
fi

if [[ "$PROFILE" == "fast" ]]; then
  python3 scripts/run_test_suite.py fast
elif [[ "$PROFILE" == "all" || "$PROFILE" == "unit" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" == "1" ]]; then
  echo "unit_tests_skipped=1"
else
  python3 scripts/run_test_suite.py unit
fi
fi

if [[ "$PROFILE" == "all" || "$PROFILE" == "platform" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_UNITTESTS:-0}" != "1" && "$HAS_PACKAGE_MANIFEST" != "1" ]]; then
  python3 scripts/run_test_suite.py platform
fi
fi

if [[ "$PROFILE" == "all" || "$PROFILE" == "behavior" ]]; then
if [[ "${CODEXQB_VALIDATE_SKIP_BEHAVIOR_SMOKE:-0}" == "1" ]]; then
  echo "behavior_smokes_skipped=1"
else
  # evals/run_apply_behavior_smoke.py prints apply_behavior_smoke=passed on success.
  python3 evals/run_apply_behavior_smoke.py
  # evals/run_downstream_goal_apply_dry_run.py prints downstream_goal_apply_dry_run=passed on success.
  python3 evals/run_downstream_goal_apply_dry_run.py
  python3 scripts/run_test_suite.py behavior
fi
# evals/run_goal_apply_metric_checks.py prints goal_apply_metric_checks=passed on success.
python3 evals/run_goal_apply_metric_checks.py
python3 evals/run_fixture_corpus_checks.py
fi
