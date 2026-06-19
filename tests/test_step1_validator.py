from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"


@dataclass
class ValidatorResult:
    returncode: int
    stdout: str
    stderr: str


def load_validator_module():
    spec = importlib.util.spec_from_file_location("codexqb_step1_validator", VALIDATOR)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load validator module from {VALIDATOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VALIDATOR_MODULE = load_validator_module()
STEP1_HEADINGS = VALIDATOR_MODULE.STEP1_HEADINGS


def run_validator(root: Path, mode: str, strict: bool = False) -> ValidatorResult:
    stdout = io.StringIO()
    stderr = io.StringIO()
    with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
        try:
            code = VALIDATOR_MODULE.run_validation(root, mode, strict)
        except SystemExit as exc:
            code = int(exc.code or 0) if isinstance(exc.code, int) else 1
    return ValidatorResult(code, stdout.getvalue(), stderr.getvalue())


def run_validator_cli(root: Path, mode: str) -> ValidatorResult:
    completed = subprocess.run(
        [sys.executable, str(VALIDATOR), "--root", str(root), "--mode", mode],
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    return ValidatorResult(completed.returncode, completed.stdout, completed.stderr)


def section_body(heading: str) -> str:
    clean = heading.lstrip("# ").strip()
    return f"{clean} section includes enough detail for a deterministic step1 validator fixture."


def write_main_plan(docs: Path, headings: list[str] | None = None, include_phase_table: bool = True) -> None:
    lines: list[str] = []
    for heading in headings or STEP1_HEADINGS:
        lines += [heading, "", section_body(heading), ""]
        if heading == "## 6. Phase-Based Master Roadmap" and include_phase_table:
            lines += [
                "| Phase | Phase name | Goal | Approximate maturity | Main acceptance signals |",
                "|---|---|---|---|---|",
                "| 1 | Foundation | Stabilize the planning contract. | M2 | Validator passes. |",
                "| 2 | Execution | Prepare implementation slices. | M3 | Tests pass. |",
                "",
            ]
    (docs / "Main-Planing.md").write_text("\n".join(lines), encoding="utf-8")


class Step1ValidatorTests(unittest.TestCase):
    def test_step1_valid_main_plan_reports_phase_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)

            result = run_validator(Path(temp_dir), "step1", strict=True)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_phase_count=2", result.stdout)
            self.assertIn("mode=step1", result.stdout)

    def test_step1_missing_heading_reports_expected_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            headings = [heading for heading in STEP1_HEADINGS if heading != "## 2. Project Vision"]
            write_main_plan(docs, headings=headings)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("missing_heading=Planner-docs/Main-Planing.md::## 2. Project Vision", result.stdout)

    def test_step1_heading_order_error_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            headings = STEP1_HEADINGS.copy()
            headings[2], headings[3] = headings[3], headings[2]
            write_main_plan(docs, headings=headings)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("heading_out_of_order=Planner-docs/Main-Planing.md", result.stdout)

    def test_step1_without_roadmap_phases_reports_expected_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs, include_phase_table=False)

            result = run_validator(Path(temp_dir), "step1")

            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("main_plan_has_no_detected_phases=Planner-docs/Main-Planing.md", result.stdout)

    def test_cli_step1_success_smoke(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            docs = Path(temp_dir) / "Planner-docs"
            docs.mkdir()
            write_main_plan(docs)

            result = run_validator_cli(Path(temp_dir), "step1")

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("planner_docs_validation=passed", result.stdout)
            self.assertIn("main_phase_count=2", result.stdout)


if __name__ == "__main__":
    unittest.main()
