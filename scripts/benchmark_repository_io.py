#!/usr/bin/env python3
"""Measure the repository I/O facade against its descriptor-bound primitive.

The default fixture is the release acceptance shape: 4,096 regular files and
64 MiB of repository content.  Baseline and candidate measurements run in
fresh child processes so peak RSS is comparable.  The primitive is used only
as an in-process performance reference; protected planner consumers remain
required to use ``RepositoryIO`` by the static policy gate.
"""

from __future__ import annotations

import argparse
import gc
import json
import os
from pathlib import Path
import resource
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_SCRIPTS = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts"
if str(SKILL_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SKILL_SCRIPTS))

from repository_evidence import (  # noqa: E402
    open_repository_root_anchor,
    snapshot_repository_inventory_from_anchor,
)
from repository_io import (  # noqa: E402
    DEFAULT_MAX_FILE_BYTES,
    DEFAULT_MAX_PATHS,
    DEFAULT_MAX_TOTAL_BYTES,
    DEFAULT_TIMEOUT_SECONDS,
    _controller_inventory as controller_inventory,
    _controller_read_bytes as controller_read_bytes,
    open_repository_io,
)


BENCHMARK_SCHEMA = "codexqb.repository-io-performance/v1"
DEFAULT_FILES = DEFAULT_MAX_PATHS
DEFAULT_TOTAL_BYTES = DEFAULT_MAX_TOTAL_BYTES
WALL_REGRESSION_FRACTION = 0.20
WALL_REGRESSION_FLOOR_SECONDS = 1.0
RSS_REGRESSION_FRACTION = 0.25
RSS_REGRESSION_FLOOR_BYTES = 64 * 1024 * 1024


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    # Darwin reports bytes; Linux and the other supported CI hosts report KiB.
    return value if sys.platform == "darwin" else value * 1024


def _fixture_paths(file_count: int) -> tuple[str, ...]:
    width = max(4, len(str(file_count - 1)))
    return tuple(f"fixture-{index:0{width}d}.txt" for index in range(file_count))


def _create_fixture(root: Path, file_count: int, total_bytes: int) -> tuple[str, ...]:
    if file_count <= 0 or total_bytes < file_count:
        raise ValueError("benchmark_fixture_shape_invalid")
    root.chmod(0o700)
    paths = _fixture_paths(file_count)
    quotient, remainder = divmod(total_bytes, file_count)
    if quotient > DEFAULT_MAX_FILE_BYTES:
        raise ValueError("benchmark_fixture_file_budget_exceeded")
    block = b"repository-io-benchmark\n"
    for index, relative in enumerate(paths):
        size = quotient + (1 if index < remainder else 0)
        payload = (block * ((size + len(block) - 1) // len(block)))[:size]
        descriptor = os.open(
            root / relative,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
        )
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("benchmark_fixture_short_write")
                view = view[written:]
        finally:
            os.close(descriptor)
    return paths


def _worker(mode: str, root: Path, file_count: int, total_bytes: int) -> dict[str, Any]:
    paths = _fixture_paths(file_count)
    started = time.perf_counter()
    if mode == "baseline":
        with open_repository_root_anchor(root) as anchor:
            snapshot = snapshot_repository_inventory_from_anchor(
                anchor,
                max_bytes=DEFAULT_MAX_FILE_BYTES,
                max_total_bytes=total_bytes * 2,
                max_paths=file_count,
                timeout_seconds=max(DEFAULT_TIMEOUT_SECONDS, 120.0),
            )
        observed_bytes = sum(int(item.get("size") or 0) for item in snapshot)
        observed_paths = len(snapshot)
        del snapshot
    elif mode == "candidate":
        with open_repository_io(root) as repository:
            snapshot = controller_inventory(repository, "intake")
            observed_bytes = sum(int(item.get("size") or 0) for item in snapshot)
            observed_paths = len(snapshot)
            try:
                controller_read_bytes(repository, paths[0])
            except ValueError as exc:
                total_budget_enforced = str(exc) == "repository_io_total_bytes_exceeded"
            else:
                total_budget_enforced = False
            if not total_budget_enforced:
                raise ValueError("benchmark_total_read_budget_not_enforced")
        del snapshot
    else:
        raise ValueError("benchmark_worker_mode_invalid")
    wall_seconds = time.perf_counter() - started
    gc.collect()
    if observed_paths != file_count or observed_bytes != total_bytes:
        raise ValueError("benchmark_fixture_observation_mismatch")
    result = {
        "mode": mode,
        "paths": observed_paths,
        "bytes": observed_bytes,
        "wall_seconds": wall_seconds,
        "peak_rss_bytes": _rss_bytes(),
    }
    if mode == "candidate":
        result["total_read_budget_enforced"] = total_budget_enforced
    return result


def _run_worker(mode: str, root: Path, file_count: int, total_bytes: int) -> dict[str, Any]:
    completed = subprocess.run(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--worker",
            mode,
            "--fixture-root",
            str(root),
            "--files",
            str(file_count),
            "--total-bytes",
            str(total_bytes),
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=max(180.0, DEFAULT_TIMEOUT_SECONDS * 4),
    )
    if completed.returncode != 0:
        reason = completed.stderr.strip().splitlines()[-1:] or ["unknown"]
        raise ValueError(f"benchmark_worker_failed={mode}:{reason[0][:160]}")
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError(f"benchmark_worker_output_invalid={mode}") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"benchmark_worker_output_invalid={mode}")
    return payload


def _acceptance(baseline: dict[str, Any], candidate: dict[str, Any]) -> dict[str, Any]:
    baseline_wall = float(baseline["wall_seconds"])
    baseline_rss = int(baseline["peak_rss_bytes"])
    wall_limit = baseline_wall + max(
        baseline_wall * WALL_REGRESSION_FRACTION,
        WALL_REGRESSION_FLOOR_SECONDS,
    )
    rss_limit = baseline_rss + max(
        int(baseline_rss * RSS_REGRESSION_FRACTION),
        RSS_REGRESSION_FLOOR_BYTES,
    )
    return {
        "wall_limit_seconds": wall_limit,
        "rss_limit_bytes": rss_limit,
        "wall_pass": float(candidate["wall_seconds"]) <= wall_limit,
        "rss_pass": int(candidate["peak_rss_bytes"]) <= rss_limit,
    }


def benchmark(file_count: int, total_bytes: int, *, samples: int) -> dict[str, Any]:
    if samples <= 0 or samples > 5:
        raise ValueError("benchmark_sample_count_invalid")
    with tempfile.TemporaryDirectory(prefix="codexqb-repository-io-benchmark-") as temp_dir:
        root = Path(temp_dir)
        _create_fixture(root, file_count, total_bytes)
        # Warm metadata/content caches symmetrically, then alternate order so
        # neither side receives a systematic filesystem-cache advantage.
        _run_worker("baseline", root, file_count, total_bytes)
        _run_worker("candidate", root, file_count, total_bytes)
        baselines: list[dict[str, Any]] = []
        candidates: list[dict[str, Any]] = []
        for index in range(samples):
            order = ("baseline", "candidate") if index % 2 == 0 else ("candidate", "baseline")
            for mode in order:
                measured = _run_worker(mode, root, file_count, total_bytes)
                (baselines if mode == "baseline" else candidates).append(measured)
    baseline = {
        **baselines[0],
        "wall_seconds": statistics.median(float(item["wall_seconds"]) for item in baselines),
        "peak_rss_bytes": int(
            statistics.median(int(item["peak_rss_bytes"]) for item in baselines)
        ),
    }
    candidate = {
        **candidates[0],
        "wall_seconds": statistics.median(float(item["wall_seconds"]) for item in candidates),
        "peak_rss_bytes": int(
            statistics.median(int(item["peak_rss_bytes"]) for item in candidates)
        ),
    }
    acceptance = _acceptance(baseline, candidate)
    return {
        "schema": BENCHMARK_SCHEMA,
        "fixture": {"paths": file_count, "bytes": total_bytes},
        "samples": samples,
        "baseline": baseline,
        "candidate": candidate,
        "acceptance": acceptance,
        "passed": bool(acceptance["wall_pass"] and acceptance["rss_pass"]),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--files", type=int, default=DEFAULT_FILES)
    parser.add_argument("--total-bytes", type=int, default=DEFAULT_TOTAL_BYTES)
    parser.add_argument("--samples", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--worker", choices=("baseline", "candidate"), help=argparse.SUPPRESS)
    parser.add_argument("--fixture-root", type=Path, help=argparse.SUPPRESS)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if args.worker is not None:
        if args.fixture_root is None:
            raise ValueError("benchmark_fixture_root_required")
        result = _worker(args.worker, args.fixture_root, args.files, args.total_bytes)
    else:
        result = benchmark(args.files, args.total_bytes, samples=args.samples)
    rendered = json.dumps(result, sort_keys=True, separators=(",", ":"))
    print(rendered if args.json else json.dumps(result, sort_keys=True, indent=2))
    return 0 if bool(result.get("passed", True)) else 1


if __name__ == "__main__":
    raise SystemExit(main())
