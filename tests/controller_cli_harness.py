#!/usr/bin/env python3
"""Invoke one controller with a private test-only passwd-home provider."""

from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path
import sys


HARNESS_DIR = Path(__file__).resolve().parent
SUPPORT_SOURCE = HARNESS_DIR / "controller_test_support.py"
HELD_RUNTIME_SUPPORT_SOURCE = HARNESS_DIR / "held_runtime_test_support.py"


def load_test_support():
    if SUPPORT_SOURCE.resolve(strict=True).parent != HARNESS_DIR:
        raise RuntimeError("test_controller_support_identity_invalid")
    spec = importlib.util.spec_from_file_location(
        "codexqb_controller_test_support",
        SUPPORT_SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("test_controller_support_load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


TEST_SUPPORT = load_test_support()
REPO_ROOT = TEST_SUPPORT.REPO_ROOT
validate_test_home = TEST_SUPPORT.validate_test_home
CONTROLLER_SCRIPT_DIR = (REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts").resolve()


def load_held_runtime_test_support():
    if HELD_RUNTIME_SUPPORT_SOURCE.resolve(strict=True).parent != HARNESS_DIR:
        raise RuntimeError("test_held_runtime_support_identity_invalid")
    spec = importlib.util.spec_from_file_location(
        "codexqb_held_runtime_test_support",
        HELD_RUNTIME_SUPPORT_SOURCE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("test_held_runtime_support_load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


HELD_RUNTIME_TEST_SUPPORT = load_held_runtime_test_support()


CONTROLLERS = {
    "doctor": REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/doctor.py",
    "goal": REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/goal_run.py",
    "apply": REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/apply_run.py",
    "planner-validator": (
        REPO_ROOT
        / "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"
    ),
    "repository-io": (
        REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/repository_io.py"
    ),
}
STATEFUL_CONTROLLERS = frozenset({"apply", "goal"})


def load_controller_store(test_home: Path):
    source = CONTROLLER_SCRIPT_DIR / "controller_store.py"
    if source.resolve(strict=True).parent != CONTROLLER_SCRIPT_DIR:
        raise RuntimeError("test_controller_store_source_identity_invalid")
    if CONTROLLER_SCRIPT_DIR.as_posix() not in sys.path:
        sys.path.insert(0, CONTROLLER_SCRIPT_DIR.as_posix())
    if "controller_store" in sys.modules:
        raise RuntimeError("test_controller_store_preloaded")
    spec = importlib.util.spec_from_file_location("controller_store", source)
    if spec is None or spec.loader is None:
        raise RuntimeError("test_controller_store_load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    original_provider = module.controller_home_directory
    module.controller_home_directory = lambda: test_home
    return module, original_provider


def load_controller(kind: str):
    source = CONTROLLERS[kind]
    if source.resolve(strict=True).parent != CONTROLLER_SCRIPT_DIR:
        raise RuntimeError("test_controller_source_identity_invalid")
    module_kind = kind.replace("-", "_")
    spec = importlib.util.spec_from_file_location(
        f"codexqb_test_{module_kind}_controller", source
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("test_controller_load_failed")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller", required=True, choices=sorted(CONTROLLERS))
    parser.add_argument("--test-home")
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    arguments = list(args.arguments)
    if arguments[:1] == ["--"]:
        arguments = arguments[1:]
    if not arguments:
        raise ValueError("test_controller_arguments_required")
    if args.controller in STATEFUL_CONTROLLERS:
        if args.test_home is None:
            raise ValueError("test_controller_home_required")
        test_home = validate_test_home(Path(args.test_home))
        controller_store, original_provider = load_controller_store(test_home)
        try:
            with HELD_RUNTIME_TEST_SUPPORT.held_runtime_test_provider():
                controller = load_controller(args.controller)
                return int(controller.main(arguments))
        finally:
            controller_store.controller_home_directory = original_provider
    if args.test_home is not None:
        raise ValueError("test_controller_home_not_applicable")
    with HELD_RUNTIME_TEST_SUPPORT.held_runtime_test_provider():
        controller = load_controller(args.controller)
        return int(controller.main(arguments))


if __name__ == "__main__":
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.flags.optimize == 0
    ):
        raise SystemExit("test_controller_harness_requires_python_-I_-S_-B")
    raise SystemExit(main())
