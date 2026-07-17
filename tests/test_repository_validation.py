from __future__ import annotations

import os
import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
VALIDATOR = (
    REPO_ROOT
    / "plugins/codexqb/skills/codexqb/scripts/repository_validation.py"
)
PACKAGE_POLICY_PATH = REPO_ROOT / "scripts/package_policy.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"module_load_failed={name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


VALIDATION_MODULE = load_module("codexqb_repository_validation_test", VALIDATOR)
PACKAGE_POLICY = load_module("codexqb_package_policy_validation_test", PACKAGE_POLICY_PATH)


class RepositoryValidationTests(unittest.TestCase):
    def run_validator(self, root: Path) -> subprocess.CompletedProcess[str]:
        (root / "PACKAGE-MANIFEST.json").write_text("{}\n", encoding="utf-8")
        return subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                VALIDATOR.as_posix(),
                "--root",
                ".",
                "--contract",
                "hygiene",
                "--workspace-mode",
                "external-package",
            ],
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
        )

    def test_safe_repository_passes_through_common_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text("safe repository\n", encoding="utf-8")
            (root / "asset.bin").write_bytes(b"\x89PNG\x00safe")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "repository_validation=passed\n")
            self.assertEqual(result.stderr, "")

    def test_stale_secret_and_blocked_path_findings_are_hash_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            stale = root / "stale-canary.txt"
            stale.write_text("invoke project-" + "planner now\n", encoding="utf-8")
            secret = root / "secret-canary.txt"
            secret_value = "sk-proj-" + "A" * 40
            secret.write_text(secret_value + "\n", encoding="utf-8")
            blocked = root / ".env"
            blocked.write_text("SAFE_PLACEHOLDER=1\n", encoding="utf-8")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("stale_invocation_references_found", result.stdout)
            self.assertIn("repository_secret_hygiene_failed", result.stdout)
            self.assertIn("package_hygiene_failed", result.stdout)
            for raw in (stale.name, secret.name, blocked.name, secret_value):
                self.assertNotIn(raw, result.stdout)
                self.assertNotIn(raw, result.stderr)
            self.assertNotIn(temp_dir, result.stdout)
            self.assertNotIn(temp_dir, result.stderr)

    def test_linked_repository_entry_fails_closed_without_victim_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            victim = Path(outside_dir) / "victim.txt"
            victim_value = "outside-victim-canary"
            victim.write_text(victim_value, encoding="utf-8")
            os.symlink(victim, root / "linked.txt")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("repository_validation=failed", result.stdout)
            self.assertNotIn(victim.name, result.stdout)
            self.assertNotIn(victim_value, result.stdout + result.stderr)
            self.assertNotIn(outside_dir, result.stdout + result.stderr)

    def test_hardlinked_repository_entry_fails_closed_without_victim_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            victim = Path(outside_dir) / "hardlink-victim.txt"
            victim_value = "outside-hardlink-victim-canary"
            victim.write_text(victim_value, encoding="utf-8")
            os.link(victim, root / "repository-entry.txt")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("repository_validation=failed", result.stdout)
            self.assertNotIn(victim.name, result.stdout + result.stderr)
            self.assertNotIn(victim_value, result.stdout + result.stderr)
            self.assertNotIn(outside_dir, result.stdout + result.stderr)

    def test_validator_integration_rejects_nested_mount_before_content_scan(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "PACKAGE-MANIFEST.json").write_text("{}\n", encoding="utf-8")
            nested = root / "nested-mount-canary"
            nested.mkdir()
            (nested / "victim.txt").write_text(
                "nested-mount-content-canary\n",
                encoding="utf-8",
            )
            repository_io_module = sys.modules[
                VALIDATION_MODULE.open_repository_io.__module__
            ]
            original = repository_io_module.require_same_repository_mount

            def reject_nested_mount(anchor, child_fd, relative_path):
                if relative_path == nested.name:
                    raise ValueError("repository_nested_mount_rejected")
                return original(anchor, child_fd, relative_path)

            with VALIDATION_MODULE.open_repository_io(root) as repository, mock.patch.object(
                repository_io_module,
                "require_same_repository_mount",
                side_effect=reject_nested_mount,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_inventory_mount_escape",
                ):
                    VALIDATION_MODULE.validate_repository(
                        repository,
                        require_shape=False,
                        workspace_mode="external-package",
                    )

    def test_noncanonical_root_argument_is_rejected_before_open(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    VALIDATOR.as_posix(),
                    "--root",
                    temp_dir,
                    "--contract",
                    "hygiene",
                    "--workspace-mode",
                    "external-package",
                ],
                cwd=temp_dir,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2)
            self.assertIn("repository_root_requires_exact_dot", result.stdout)
            self.assertNotIn(temp_dir, result.stdout + result.stderr)

    def test_git_workspace_mode_rejects_gitless_copy_nested_in_parent_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            subprocess.run(
                ["git", "init", "-q"],
                cwd=parent,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            nested = parent / "copied-source"
            nested.mkdir()
            (nested / "README.md").write_text("copied source\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    VALIDATOR.as_posix(),
                    "--root",
                    ".",
                    "--contract",
                    "hygiene",
                    "--workspace-mode",
                    "git",
                ],
                cwd=nested,
                text=True,
                capture_output=True,
                check=False,
                timeout=10,
            )

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "repository_validation=failed",
                    "error=repository_validation_git_root_required",
                ],
            )
            self.assertEqual(result.stderr, "")

    def test_blocked_directories_are_visible_but_not_descended(self) -> None:
        for directory in (
            ".codexqb",
            ".ENV.DEV",
            "artifacts",
            "logs",
            "tmp",
            "__pycache__",
            "__MACOSX",
        ):
            with self.subTest(directory=directory), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                blocked = root / directory
                blocked.mkdir()
                os.symlink("/outside", blocked / "not-descended")

                result = self.run_validator(root)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("package_hygiene_failed", result.stdout)
                self.assertNotIn(directory, result.stdout + result.stderr)

    def test_source_denied_path_vectors_match_package_policy(self) -> None:
        denied = {
            *(f"{part}/payload.txt" for part in PACKAGE_POLICY.COMMON_DENIED_PARTS),
            *(f"payload{suffix}" for suffix in PACKAGE_POLICY.COMMON_DENIED_SUFFIXES),
            ".env",
            ".env.production",
            ".ENV.DEV",
            "nested/.envrc",
            "settings.local",
            "settings.local.json",
            ".DS_Store",
            "._resource",
        }
        for relative in sorted(denied):
            with self.subTest(relative=relative):
                self.assertIsNotNone(
                    PACKAGE_POLICY.denied_path_reason(relative, "source")
                )
                self.assertTrue(VALIDATION_MODULE._path_denied(relative))
        for relative in ("README.md", "docs/example.json", "src/localization.py"):
            with self.subTest(relative=relative):
                self.assertIsNone(
                    PACKAGE_POLICY.denied_path_reason(relative, "source")
                )
                self.assertFalse(VALIDATION_MODULE._path_denied(relative))

    def test_denied_file_vectors_fail_repository_validation(self) -> None:
        for relative in (
            ".env.production",
            ".ENV.DEV",
            "nested/.envrc",
            "payload.tmp",
            "payload.zip",
            "._resource",
            ".DS_Store",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("safe\n", encoding="utf-8")

                result = self.run_validator(root)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("package_hygiene_failed", result.stdout)
                self.assertNotIn(target.name, result.stdout + result.stderr)

    def test_allowed_vendor_tree_is_scanned_for_secret_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            secret = root / "vendor/source/token.txt"
            secret.parent.mkdir(parents=True)
            secret_value = "sk-proj-" + "V" * 40
            secret.write_text(secret_value + "\n", encoding="utf-8")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("repository_secret_hygiene_failed", result.stdout)
            self.assertNotIn(secret_value, result.stdout + result.stderr)
            self.assertNotIn("vendor", result.stdout + result.stderr)

    def test_byte_safe_scanner_rejects_invalid_utf8_and_suffixless_binary(self) -> None:
        secret_value = "sk-proj-" + "B" * 40
        non_ascii_value = "密碼值" * 16
        structural_value = "V" * 40
        cases = (
            (
                "invalid-utf8-prefix.txt",
                b"\xff\xfe" + secret_value.encode("ascii") + b"\x80",
            ),
            (
                "suffixless",
                b"\x00\xff" + secret_value.encode("ascii") + b"\x00",
            ),
            (
                "suffixless-non-ascii",
                ("password=" + non_ascii_value).encode("utf-8"),
            ),
            (
                "suffixless-structural",
                ("failure=('password','" + structural_value + "')").encode("utf-8"),
            ),
        )
        for name, payload in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                (root / name).write_bytes(payload)

                result = self.run_validator(root)

                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn("repository_secret_hygiene_failed", result.stdout)
                self.assertIn("path_sha256:", result.stdout)
                for value in (secret_value, non_ascii_value, structural_value):
                    self.assertNotIn(value, result.stdout + result.stderr)
                self.assertNotIn(name, result.stdout + result.stderr)
                self.assertNotIn(temp_dir, result.stdout + result.stderr)

    def test_secret_shaped_filename_is_hash_only_and_fails_closed(self) -> None:
        secret_name = "sk-proj-" + "P" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / secret_name).write_text("safe payload\n", encoding="utf-8")

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
            self.assertIn("repository_secret_hygiene_failed", result.stdout)
            self.assertIn("path_sha256:", result.stdout)
            self.assertNotIn(secret_name, result.stdout + result.stderr)
            self.assertNotIn(temp_dir, result.stdout + result.stderr)

    def test_finding_overflow_fails_with_constant_bounded_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            # The primitive scanner intentionally caps one payload at 256
            # matches plus a sentinel.  Multiple files exercise the global
            # validator cap without relying on unbounded primitive output.
            for file_index in range(5):
                payload = root / f"many-{file_index}.txt"
                payload.write_text(
                    "\n".join(
                        f"sk-proj-{file_index:02d}{index:04d}-" + "X" * 32
                        for index in range(300)
                    ),
                    encoding="utf-8",
                )

            result = self.run_validator(root)

            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "repository_validation=failed",
                    "error=repository_validation_finding_limit_exceeded",
                ],
            )
            self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
