from __future__ import annotations

from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path
import sys
from types import ModuleType


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb"
SCRIPT_ROOT = SKILL_ROOT / "scripts"
HELD_RUNTIME_CONTEXT_NAME = "_codexqb_held_runtime_context_v1"
RUNTIME_SOURCE_NAMES = frozenset(
    {
        "apply_run.py",
        "artifact_io.py",
        "controller_store.py",
        "doctor.py",
        "evidence_contracts.py",
        "execution_controller.py",
        "git_evidence.py",
        "goal_run.py",
        "mount_identity.py",
        "repository_evidence.py",
        "repository_io.py",
        "safety_contracts.py",
        "validate_planner_docs.py",
    }
)
GOAL_RESOURCE_NAMES = frozenset(
    {
        "references/Autopsy-Planner.md",
        "references/Fourth-Planner.md",
        "references/Second-Planner.md",
        "references/Third-Planner.md",
        "references/goal-specs/step15.md",
        "references/goal-specs/step2.md",
        "references/goal-specs/step3.md",
        "references/goal-specs/step4.md",
        "references/handoffs/run-step2.md",
        "references/handoffs/run-step3.md",
        "references/handoffs/run-step4.md",
    }
)


def test_runtime_sources() -> dict[str, bytes]:
    return {
        name: (SCRIPT_ROOT / name).read_bytes()
        for name in sorted(RUNTIME_SOURCE_NAMES)
    }


def test_goal_resources() -> dict[str, bytes]:
    return {
        name: (SKILL_ROOT / name).read_bytes()
        for name in sorted(GOAL_RESOURCE_NAMES)
    }


@contextmanager
def held_runtime_test_provider(
    *,
    runtime_sources: Mapping[str, bytes] | None = None,
    goal_resources: Mapping[str, bytes] | None = None,
) -> Iterator[ModuleType]:
    """Install the private provider only for in-memory controller unit tests."""

    if HELD_RUNTIME_CONTEXT_NAME in sys.modules:
        raise AssertionError("held_runtime_test_provider_preseeded")
    runtime = tuple(
        sorted(
            (test_runtime_sources() if runtime_sources is None else runtime_sources).items()
        )
    )
    resources = tuple(
        sorted(
            (test_goal_resources() if goal_resources is None else goal_resources).items()
        )
    )
    module = ModuleType(HELD_RUNTIME_CONTEXT_NAME)
    module.__file__ = "<test-only-held-runtime-context>"
    module.__package__ = ""
    module.schema_version = 1
    module.assurance = "controller_observed_loader_path_unattested"
    module.host_attested = False
    module.verified = False
    module.finalization_authority = False
    module.runtime_sources = runtime
    module.goal_resources = resources
    sys.modules[HELD_RUNTIME_CONTEXT_NAME] = module
    try:
        yield module
    finally:
        unchanged = sys.modules.get(HELD_RUNTIME_CONTEXT_NAME) is module
        sys.modules.pop(HELD_RUNTIME_CONTEXT_NAME, None)
        if not unchanged:
            raise AssertionError("held_runtime_test_provider_identity_changed")
