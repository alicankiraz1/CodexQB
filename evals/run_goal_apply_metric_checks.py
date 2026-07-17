#!/usr/bin/env python3
"""Collect deterministic Goal/Apply prompt-size metrics.

These checks estimate prompt size from local artifacts only. They do not call
Codex, spawn subagents, or claim exact model token billing.
"""

from __future__ import annotations

import hashlib
import json
import math
import subprocess
import sys
import tempfile
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
STEP4_HANDOFF = REPO_ROOT / "plugins/codexqb/skills/codexqb/references/handoffs/run-step4.md"

if REPO_ROOT.as_posix() not in sys.path:
    sys.path.insert(0, REPO_ROOT.as_posix())

from tests.controller_test_support import (  # noqa: E402
    assert_real_trust_store_unchanged,
    controller_cli_command,
    temporary_controller_home,
)
from tests.test_validate_planner_docs import write_audit, write_valid_step2_fixture  # noqa: E402


_CONTROLLER_TEST_HOME: Path | None = None
_SAFE_FAILURE_CODES = frozenset(
    {
        "apply_command_repository_root_mismatch",
        "command_failed",
        "controller_test_home_not_initialized",
        "unhandled_exception",
    }
)


def fail(message: str) -> None:
    candidate = message.partition("=")[0]
    code = candidate if candidate in _SAFE_FAILURE_CODES else "unspecified"
    detail_sha256 = hashlib.sha256(message.encode("utf-8", errors="replace")).hexdigest()
    print(f"goal_apply_metric_checks_failed_code={code.lower()}")
    print(f"goal_apply_metric_checks_failed_detail_sha256={detail_sha256}")
    raise SystemExit(1)


def approx_tokens(text: str) -> int:
    # Deterministic dependency-free estimate. This is not model billing.
    return max(1, math.ceil(len(text) / 4))


def metric(name: str, text: str) -> dict[str, int | str]:
    return {
        "name": name,
        "bytes": len(text.encode("utf-8")),
        "chars": len(text),
        "words": len(text.split()),
        "estimated_tokens": approx_tokens(text),
    }


def run_command(args: list[str], *, cwd: Path) -> str:
    completed = subprocess.run(
        args,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        timeout=30,
    )
    if completed.returncode != 0:
        fail(f"command_failed={' '.join(args)} stdout={completed.stdout.strip()} stderr={completed.stderr.strip()}")
    return completed.stdout


def parse_key(output: str, key: str) -> str:
    prefix = f"{key}="
    for line in output.splitlines():
        if line.startswith(prefix):
            return line.split("=", 1)[1]
    fail(f"missing_output_key={key}")
    raise AssertionError("unreachable")


def apply_controller_command(root: Path, args: list[str]) -> list[str]:
    if _CONTROLLER_TEST_HOME is None:
        fail("controller_test_home_not_initialized")
    rooted = list(args)
    root_positions = [index for index, value in enumerate(rooted) if value == "--root"]
    if not root_positions:
        rooted.extend(["--root", root.as_posix()])
    elif (
        len(root_positions) != 1
        or root_positions[0] + 1 >= len(rooted)
        or Path(rooted[root_positions[0] + 1]).resolve() != root.resolve()
    ):
        fail("apply_command_repository_root_mismatch")
    return controller_cli_command("apply", _CONTROLLER_TEST_HOME, rooted)


def write_fixture(root: Path) -> None:
    docs = write_valid_step2_fixture(root)
    write_audit(docs, "PASS")


def compile_goal_prompt(root: Path, mode: str, suffix: str) -> str:
    if _CONTROLLER_TEST_HOME is None:
        fail("controller_test_home_not_initialized")
    output = run_command(
        controller_cli_command(
            "goal",
            _CONTROLLER_TEST_HOME,
            [
            "prepare",
            "--root",
            root.as_posix(),
            "--stage",
            "step4",
            "--mode",
            mode,
            "--run-id-suffix",
            suffix,
            ],
        ),
        cwd=root,
    )
    out_dir = Path(parse_key(output, "output_dir"))
    prompt_path = out_dir / "Goal-Prompt.md"
    if not prompt_path.is_file():
        fail(f"missing_goal_prompt={mode}")
    prompt = prompt_path.read_text(encoding="utf-8")
    if "Planner-docs/Faz-1-Plans/Faz1.1-local-contract.md" not in prompt:
        fail(f"dynamic_prompt_missing_ready_subplan={mode}")
    if mode not in prompt:
        fail(f"dynamic_prompt_missing_mode={mode}")
    return prompt


def prepare_apply_run(root: Path, mode: str, suffix: str) -> Path:
    output = run_command(
        apply_controller_command(
            root,
            [
            "prepare",
            "--root",
            root.as_posix(),
            "--mode",
            mode,
            "--run-id-suffix",
            suffix,
            "--allow-non-git-unsafe",
            ],
        ),
        cwd=root,
    )
    return Path(parse_key(output, "run_dir"))


def first_task(run_dir: Path) -> tuple[str, Path]:
    progress = json.loads((run_dir / "Progress.json").read_text(encoding="utf-8"))
    tasks = progress.get("tasks")
    if not isinstance(tasks, list) or not tasks:
        fail(f"missing_apply_task={run_dir}")
    task = tasks[0]
    if not isinstance(task, dict) or not isinstance(task.get("task_id"), str):
        fail(f"invalid_apply_task={run_dir}")
    task_id = str(task["task_id"])
    return task_id, run_dir / task_id


def subagent_dispatch_message(root: Path, run_dir: Path, task_id: str) -> str:
    output = run_command(
        apply_controller_command(
            root,
            [
            "dispatch",
            "--run-dir",
            run_dir.as_posix(),
            "--task-id",
            task_id,
            "--role",
            "implementer",
            "--actor",
            "metric-controller",
            "--evidence",
            "metric collection generated dispatch packet",
            ],
        ),
        cwd=root,
    )
    packet_path = Path(parse_key(output, "packet_path"))
    packet = json.loads(packet_path.read_text(encoding="utf-8"))
    message = packet.get("spawn_request", {}).get("message")
    if not isinstance(message, str):
        fail("dispatch_packet_missing_message")
    if "Use only this fresh task context" not in message:
        fail("dispatch_message_not_fresh_context")
    if "Structured Implementation Contract" not in message:
        fail("dispatch_message_missing_structured_contract")
    return message


def main() -> int:
    global _CONTROLLER_TEST_HOME
    with (
        assert_real_trust_store_unchanged(),
        tempfile.TemporaryDirectory() as temp_dir,
        temporary_controller_home() as controller_home,
    ):
        root = Path(temp_dir)
        _CONTROLLER_TEST_HOME = Path(controller_home)
        write_fixture(root)

        static_handoff = STEP4_HANDOFF.read_text(encoding="utf-8")
        direct_prompt = compile_goal_prompt(root, "direct", "metrics-direct")
        subagent_prompt = compile_goal_prompt(root, "subagent_serial", "metrics-subagent")

        direct_run_dir = prepare_apply_run(root, "direct", "metrics-direct")
        direct_task_id, direct_task_dir = first_task(direct_run_dir)
        direct_brief = (direct_task_dir / "Brief.md").read_text(encoding="utf-8")
        if direct_task_id not in direct_brief:
            fail("direct_brief_missing_task_id")

        subagent_run_dir = prepare_apply_run(root, "subagent_serial", "metrics-subagent")
        subagent_task_id, _subagent_task_dir = first_task(subagent_run_dir)
        dispatch_message = subagent_dispatch_message(root, subagent_run_dir, subagent_task_id)

        metrics = [
            metric("static_step4_handoff", static_handoff),
            metric("dynamic_step4_goal_direct", direct_prompt),
            metric("dynamic_step4_goal_subagent_serial", subagent_prompt),
            metric("apply_direct_brief", direct_brief),
            metric("apply_subagent_dispatch_message", dispatch_message),
        ]

    for item in metrics:
        if int(item["estimated_tokens"]) <= 0:
            fail(f"invalid_estimated_tokens={item['name']}")
        print(
            "metric="
            f"{item['name']} bytes={item['bytes']} words={item['words']} estimated_tokens={item['estimated_tokens']}"
        )
    print("goal_apply_metric_checks=passed")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception as exc:
        fail(f"unhandled_exception={type(exc).__name__}:{exc}")
