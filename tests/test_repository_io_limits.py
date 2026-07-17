from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_IO_PATH = (
    REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/repository_io.py"
)
BENCHMARK_PATH = REPO_ROOT / "scripts/benchmark_repository_io.py"


def load_repository_io_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_repository_io_limits",
        REPOSITORY_IO_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load repository_io from {REPOSITORY_IO_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REPOSITORY_IO = load_repository_io_module()


class RepositoryIOLimitTests(unittest.TestCase):
    def test_internal_controller_listing_is_private_while_public_listing_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(4):
                (root / f"file-{index}.txt").write_text("safe\n", encoding="utf-8")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                max_paths=16,
                model_max_matches=2,
            )

            with REPOSITORY_IO.open_repository_io(root, policy=policy) as repository:
                internal = REPOSITORY_IO._controller_regular_paths(repository, "intake")
                model = repository.list_paths("intake")

                self.assertEqual(
                    internal,
                    tuple(f"file-{index}.txt" for index in range(4)),
                )
                self.assertEqual(len(model.paths), 2)
                self.assertTrue(model.receipt.truncated)
                with self.assertRaises(TypeError):
                    repository.list_paths("intake", audience="internal")

    def write_bytes(self, root: Path, relative: str, data: bytes) -> None:
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        target.chmod(0o600)

    def test_release_shape_benchmark_enforces_wall_rss_and_total_read_limits(self) -> None:
        completed = subprocess.run(
            [sys.executable, str(BENCHMARK_PATH), "--json"],
            text=True,
            capture_output=True,
            check=False,
            timeout=180,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        receipt = json.loads(completed.stdout)
        self.assertEqual(
            receipt["fixture"],
            {
                "paths": REPOSITORY_IO.DEFAULT_MAX_PATHS,
                "bytes": REPOSITORY_IO.DEFAULT_MAX_TOTAL_BYTES,
            },
        )
        self.assertEqual(receipt["schema"], "codexqb.repository-io-performance/v1")
        self.assertTrue(receipt["candidate"]["total_read_budget_enforced"])
        self.assertLessEqual(
            receipt["candidate"]["wall_seconds"],
            receipt["acceptance"]["wall_limit_seconds"],
        )
        self.assertLessEqual(
            receipt["candidate"]["peak_rss_bytes"],
            receipt["acceptance"]["rss_limit_bytes"],
        )
        baseline_wall = receipt["baseline"]["wall_seconds"]
        self.assertEqual(
            receipt["acceptance"]["wall_limit_seconds"],
            baseline_wall + max(baseline_wall * 0.20, 1.0),
        )
        baseline_rss = receipt["baseline"]["peak_rss_bytes"]
        self.assertEqual(
            receipt["acceptance"]["rss_limit_bytes"],
            baseline_rss + max(int(baseline_rss * 0.25), 64 * 1024 * 1024),
        )

    def test_model_projection_accounts_exact_one_mib_session_budget(self) -> None:
        block = b"x" * REPOSITORY_IO.DEFAULT_MODEL_MAX_FILE_BYTES
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(5):
                self.write_bytes(root, f"model-{index}.md", block)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                rendered_receipts = []
                for index in range(4):
                    evidence = repository.read_text(
                        f"model-{index}.md",
                        audience="model",
                    )
                    self.assertEqual(len((evidence.text or "").encode("utf-8")), len(block))
                    rendered_receipts.append(evidence.receipt)
                self.assertEqual(
                    sum(receipt.bytes_rendered for receipt in rendered_receipts),
                    REPOSITORY_IO.DEFAULT_MODEL_MAX_TOTAL_BYTES,
                )
                with self.assertRaisesRegex(ValueError, "repository_io_model_bytes_exceeded"):
                    repository.read_text("model-4.md", audience="model")

    def test_list_and_search_enforce_512_records_one_mib_and_4096_characters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(REPOSITORY_IO.DEFAULT_MODEL_MAX_MATCHES + 1):
                self.write_bytes(
                    root,
                    f"record-{index:04d}.md",
                    b"architecture\n",
                )
            with REPOSITORY_IO.open_repository_io(root) as repository:
                listing = repository.list_paths("intake")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                result = repository.search("intake")
            self.assertEqual(
                len(listing.paths),
                REPOSITORY_IO.DEFAULT_MODEL_MAX_MATCHES,
            )
            self.assertTrue(listing.receipt.truncated)
            self.assertEqual(listing.receipt.reason, "record_budget")
            self.assertLessEqual(
                listing.receipt.bytes_rendered + result.receipt.bytes_rendered,
                REPOSITORY_IO.DEFAULT_MODEL_MAX_TOTAL_BYTES,
            )
            self.assertEqual(
                len(result.records),
                REPOSITORY_IO.DEFAULT_MODEL_MAX_MATCHES,
            )
            self.assertEqual(result.receipt.match_count, REPOSITORY_IO.DEFAULT_MODEL_MAX_MATCHES)
            self.assertTrue(result.receipt.truncated)
            self.assertEqual(result.receipt.reason, "match_budget")
            self.assertTrue(
                all(
                    len(
                        json.dumps(
                            record,
                            sort_keys=True,
                            separators=(",", ":"),
                            ensure_ascii=False,
                        )
                    )
                    <= REPOSITORY_IO.DEFAULT_MODEL_MAX_RECORD_CHARACTERS
                    for record in result.records
                )
            )

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(REPOSITORY_IO.DEFAULT_MODEL_MAX_MATCHES):
                self.write_bytes(root, f"record-{index:04d}.md", b"architecture\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                exact_listing = repository.list_paths("intake")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                exact_search = repository.search("intake")
            self.assertFalse(exact_listing.receipt.truncated)
            self.assertFalse(exact_search.receipt.truncated)
            self.assertEqual(exact_search.receipt.path_count, 512)
            self.assertEqual(exact_search.receipt.bytes_scanned, 512 * len(b"architecture\n"))

    def test_model_record_budget_is_session_wide_and_cached_outputs_are_debited(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_bytes(root, "a.md", b"architecture\n")
            self.write_bytes(root, "b.md", b"architecture\n")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                name="test-model/v1",
                max_paths=4,
                model_max_matches=2,
                model_max_total_bytes=4096,
            )
            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                first = repository.list_paths("intake")
                self.assertEqual(len(first.paths), 2)
                second = repository.list_paths("intake")
                self.assertEqual(second.paths, ())
                self.assertTrue(second.receipt.truncated)
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_model_record_budget_exceeded",
                ):
                    repository.read_many(["a.md"], audience="model")
                search = repository.search("intake")
                self.assertEqual(search.records, ())
                self.assertTrue(search.receipt.truncated)

    def test_listing_byte_and_combined_file_directory_record_budgets_truncate(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(4):
                self.write_bytes(root, f"directory-{index}/value.md", b"safe\n")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                name="test-list/v1",
                max_paths=16,
                model_max_matches=5,
                model_max_total_bytes=180,
                model_max_record_characters=128,
            )
            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                listing = repository.list_paths("intake")
            self.assertLessEqual(len(listing.paths) + len(listing.directories), 5)
            self.assertLessEqual(listing.receipt.bytes_rendered, 180)
            self.assertTrue(listing.receipt.truncated)
            self.assertIn(listing.receipt.reason, {"record_budget", "model_byte_budget"})

    def test_read_many_input_iteration_and_model_expansion_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_bytes(root, "README.md", b"safe\n")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                name="test-input/v1",
                max_paths=2,
                model_max_matches=2,
            )

            def duplicate_flood():
                yield "README.md"
                yield "README.md"
                yield "README.md"
                raise AssertionError("iterator consumed beyond fail-closed bound")

            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_path_budget_exceeded"):
                    repository.read_many(duplicate_flood())

        expansion = "\ufdfa" * 20_000
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_bytes(root, "expansion.md", expansion.encode("utf-8"))
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_model_file_too_large"):
                    repository.read_text("expansion.md", audience="model")

    def test_policy_rejects_nonfinite_boolean_timeout_and_unsafe_name(self) -> None:
        for timeout in (True, False, float("nan"), float("inf"), float("-inf"), 0, -1):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(ValueError, "repository_io_policy_timeout_invalid"):
                    REPOSITORY_IO.RepositoryIOPolicy(timeout_seconds=timeout)
        fixture = "sk-" + "P" * 40
        with self.assertRaisesRegex(ValueError, "repository_io_policy_name_invalid"):
            REPOSITORY_IO.RepositoryIOPolicy(name=fixture)

    def test_listing_bounds_raw_scandir_before_sorting_and_revalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for index in range(3):
                self.write_bytes(root, f"value-{index}.md", b"safe\n")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                name="test-scan/v1",
                max_paths=2,
                model_max_matches=2,
            )
            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_path_budget_exceeded"):
                    repository.list_paths("intake")

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_bytes(root, "a.md", b"safe\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                repository.list_paths("intake")
                self.write_bytes(root, "b.md", b"safe\n")
                with self.assertRaisesRegex(ValueError, "repository_io_inventory_changed"):
                    repository.list_paths("intake")


if __name__ == "__main__":
    unittest.main()
