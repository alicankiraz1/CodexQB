#!/usr/bin/env python3
"""Run the dependency-free CodexQB test groups without ambient discovery drift."""

from __future__ import annotations

import argparse
from collections.abc import Iterable
from pathlib import Path
import sys
import unittest


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = REPO_ROOT / "tests"
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

FAST_BASELINE_STEMS = (
    "test_safety_contracts",
    "test_validate_planner_docs",
    "test_artifact_io",
    "test_evidence_contracts",
)

PRIMARY_SUITE_STEMS = {
    "unit": {
        *FAST_BASELINE_STEMS,
        "test_git_evidence",
        "test_suite_partition",
    },
    "platform": {
        "test_repository_evidence",
    },
    "schema": {
        "test_apply_schema",
    },
    "behavior": {
        "test_goal_run",
        "test_apply_inventory",
        "test_apply_run",
    },
    "package": {
        "test_export_sanitized",
        "test_package_manifest",
        "test_package_privacy",
        # This module contains the extracted-package integration contract in
        # addition to content assertions, so it belongs to the package gate.
        "test_skill_content",
    },
}


def discover_test_stems() -> set[str]:
    return {path.stem for path in TEST_ROOT.glob("test_*.py") if path.is_file()}


def _dynamic_suite(stem: str) -> str | None:
    """Classify bounded extension modules whose names encode their gate."""

    if stem.endswith("_platform"):
        return "platform"
    if stem.startswith("test_mount_identity") or stem.startswith("test_doctor"):
        return "unit"
    if stem.startswith("test_package_") or stem.startswith("test_artifact_package"):
        return "package"
    return None


def primary_suite_stems() -> dict[str, tuple[str, ...]]:
    suites = {name: set(stems) for name, stems in PRIMARY_SUITE_STEMS.items()}
    explicitly_classified = set().union(*suites.values())
    for stem in discover_test_stems() - explicitly_classified:
        suite = _dynamic_suite(stem)
        if suite is not None:
            suites[suite].add(stem)
    return {name: tuple(sorted(stems)) for name, stems in suites.items()}


def suite_stems(name: str) -> tuple[str, ...]:
    primary = primary_suite_stems()
    if name == "fast":
        optional_capability_units = tuple(
            stem
            for stem in primary["unit"]
            if stem.startswith("test_mount_identity") or stem.startswith("test_doctor")
        )
        return tuple(dict.fromkeys((*FAST_BASELINE_STEMS, *optional_capability_units)))
    if name == "all":
        return tuple(sorted(set().union(*primary.values())))
    return primary[name]


def module_names(stems: Iterable[str]) -> tuple[str, ...]:
    return tuple(f"tests.{stem}" for stem in stems)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "suite",
        choices=("fast", "unit", "platform", "schema", "behavior", "package", "all"),
    )
    parser.add_argument("--list", action="store_true", help="Print modules without running them.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    modules = module_names(suite_stems(args.suite))
    if args.list:
        print("\n".join(modules))
        return 0
    if not modules:
        print(f"test_suite_empty={args.suite}")
        return 1
    loader = unittest.defaultTestLoader
    selected = loader.loadTestsFromNames(modules)
    result = unittest.TextTestRunner(verbosity=2).run(selected)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
