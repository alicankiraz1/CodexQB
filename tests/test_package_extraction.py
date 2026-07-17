from __future__ import annotations

import errno
import importlib.util
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.controller_test_support import assert_real_trust_store_unchanged
from tests.test_export_sanitized import (
    EXPORT_MODULE,
    VALID_PLUGIN_SKILL,
    valid_empty_zip64,
    write_minimal_codexqb_tree,
)
from tests.test_package_manifest import (
    append_manifest_bound_file,
    create_plugin_package,
    rewrite_manifest_bound_file,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
EXTRACTOR = REPO_ROOT / "scripts/extract_verified_package.py"


def load_extractor_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_extract_verified_package_tests",
        EXTRACTOR,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load package extractor from {EXTRACTOR}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXTRACT_MODULE = load_extractor_module()
MOUNT_MODULE = sys.modules["mount_identity"]
VERIFY_MODULE = sys.modules["verify_package_manifest"]


def create_source_package(base: Path) -> Path:
    root = base / "source"
    root.mkdir()
    write_minimal_codexqb_tree(root)
    executable = root / "scripts/evidence_probe.py"
    executable.parent.mkdir()
    executable.write_text("#!/usr/bin/env python3\nprint('ok')\n", encoding="utf-8")
    executable.chmod(0o755)
    output = base / "CodexQB-source-0.3.0.zip"
    EXPORT_MODULE.create_zip(root, output, source_package=True)
    return output


def assert_manifest_modes(test: unittest.TestCase, root: Path) -> None:
    manifest_path = root / "PACKAGE-MANIFEST.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    test.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o644)
    for item in manifest["files"]:
        relative_path = item["path"]
        expected_mode = int(item["mode"], 8)
        actual_mode = stat.S_IMODE((root / relative_path).stat().st_mode)
        test.assertEqual(actual_mode, expected_mode, relative_path)


class PackageExtractionTests(unittest.TestCase):
    def assert_no_extraction_residue(self, parent: Path, output_name: str) -> None:
        self.assertFalse((parent / output_name).exists())
        self.assertEqual(list(parent.glob(f".{output_name}.extract-*")), [])

    def test_extractor_rejects_secret_bearing_verified_manifest_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            forged = base / "forged-secret.zip"
            fixture = b"\xff" + ("sk-" + "D" * 40).encode("ascii")
            rewrite_manifest_bound_file(
                package,
                forged,
                artifact_type="source",
                relative_path="README.md",
                data=fixture,
            )
            output = base / "unpacked"

            with self.assertRaisesRegex(
                ValueError,
                "^package_zip_secret_content_rejected$",
            ):
                EXTRACT_MODULE.extract_verified_package(forged, output, "source")

            self.assertFalse(output.exists())
            self.assert_no_extraction_residue(base, output.name)

    def test_extractor_rejects_suffixless_structural_secret_before_publish(self) -> None:
        secret = "V" * 40
        fixtures = (
            (
                "opaque-pair",
                ("failure=('password','" + secret + "')\n").encode("utf-8"),
            ),
            (
                "opaque-wide-block",
                b"\x81" * 61
                + b"\xff\xfe"
                + ("name: password\nvalue: " + secret + "\n").encode(
                    "utf-16-le"
                ),
            ),
            (
                "credential-structural.html",
                (
                    "<table><tr><td>password</td><td>"
                    + secret
                    + "</td></tr></table>\n"
                ).encode("utf-8"),
            ),
        )
        for relative_path, data in fixtures:
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                package = create_source_package(base)
                forged = base / "forged-structural-secret.zip"
                append_manifest_bound_file(
                    package,
                    forged,
                    artifact_type="source",
                    relative_path=relative_path,
                    data=data,
                )
                output = base / "unpacked"

                with self.assertRaisesRegex(
                    ValueError,
                    "^package_zip_secret_content_rejected$",
                ) as caught:
                    EXTRACT_MODULE.extract_verified_package(forged, output, "source")

                self.assertNotIn(secret, str(caught.exception))
                self.assertFalse(output.exists())
                self.assert_no_extraction_residue(base, output.name)

    def test_valid_plugin_and_source_artifacts_restore_modes_and_verify_strictly(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _plugin_source, plugin_package = create_plugin_package(base)
            source_package = create_source_package(base)

            cases = (
                ("plugin", plugin_package, base / "plugin-unpacked"),
                ("source", source_package, base / "source-unpacked"),
            )
            for artifact_type, package, output in cases:
                with self.subTest(artifact_type=artifact_type):
                    artifact_root = EXTRACT_MODULE.extract_verified_package(
                        package,
                        output,
                        artifact_type,
                    )
                    expected_root = output if artifact_type == "plugin" else output / "CodexQB"
                    self.assertEqual(artifact_root, expected_root.resolve())
                    self.assertEqual(
                        EXTRACT_MODULE.verify_directory(
                            artifact_root,
                            strict_artifact=True,
                            expected_artifact_type=artifact_type,
                        ),
                        [],
                    )
                    assert_manifest_modes(self, artifact_root)

            executable = base / "source-unpacked/CodexQB/scripts/evidence_probe.py"
            self.assertEqual(stat.S_IMODE(executable.stat().st_mode), 0o755)

    def test_extraction_normalizes_directory_modes_under_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _plugin_source, plugin_package = create_plugin_package(base)
            source_package = create_source_package(base)

            previous_umask = os.umask(0o077)
            try:
                plugin_root = EXTRACT_MODULE.extract_verified_package(
                    plugin_package,
                    base / "plugin-restrictive-umask",
                    "plugin",
                )
                source_root = EXTRACT_MODULE.extract_verified_package(
                    source_package,
                    base / "source-restrictive-umask",
                    "source",
                )
            finally:
                os.umask(previous_umask)

            self.assertEqual(stat.S_IMODE(plugin_root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(source_root.stat().st_mode), 0o755)
            self.assertEqual(
                stat.S_IMODE((base / "source-restrictive-umask").stat().st_mode),
                0o700,
            )
            for artifact_root in (plugin_root, source_root):
                for path in artifact_root.rglob("*"):
                    if path.is_dir():
                        self.assertEqual(
                            stat.S_IMODE(path.stat().st_mode),
                            0o755,
                            path.relative_to(artifact_root).as_posix(),
                        )

    def test_extracted_active_skill_script_runs_by_absolute_path_from_foreign_repository(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix=".codexqb-extracted-launcher-",
            dir=REPO_ROOT.parent,
        ) as temp_dir:
            base = Path(temp_dir)
            base.chmod(0o700)
            source = base / "plugin-source"
            source.mkdir()
            write_minimal_codexqb_tree(source)
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                source / "plugins/codexqb",
                dirs_exist_ok=True,
            )
            package = base / "codexqb-plugin-0.3.0.zip"
            EXPORT_MODULE.create_zip(
                source,
                package,
                source_package=True,
                artifact_type="plugin",
            )
            plugin_root = EXTRACT_MODULE.extract_verified_package(
                package,
                base / "plugin-unpacked",
                "plugin",
            )
            skill_root = (plugin_root / "skills/codexqb").resolve(strict=True)
            skill_md = (skill_root / "SKILL.md").resolve(strict=True)
            launcher = (skill_root / "scripts/skill_launcher.py").resolve(strict=True)
            self.assertTrue(launcher.is_file())
            self.assertFalse(launcher.is_symlink())

            foreign_root = base / "foreign-target"
            foreign_root.mkdir()
            (foreign_root / "README.md").write_text("architecture boundary\n", encoding="utf-8")
            self.assertFalse((foreign_root / "repository_io.py").exists())
            self.assertFalse((foreign_root / "plugins").exists())

            with assert_real_trust_store_unchanged():
                result = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        launcher.as_posix(),
                        "--active-skill-md",
                        skill_md.as_posix(),
                        "--controller",
                        "repository-io",
                        "--",
                        "--root",
                        ".",
                        "inspect",
                        "--profile",
                        "intake",
                    ],
                    cwd=foreign_root,
                    env={**os.environ, "PWD": foreign_root.resolve(strict=True).as_posix()},
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["profile"], "intake")
            self.assertIn("README.md", payload["paths"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO creation is unavailable")
    def test_fifo_input_is_rejected_promptly_with_sanitized_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            fifo = base / "secret-package-input"
            os.mkfifo(fifo)
            output = base / "unpacked"

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXTRACTOR),
                    "--zip",
                    str(fifo),
                    "--output",
                    str(output),
                    "--artifact-type",
                    "source",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=5,
            )

            self.assertEqual(result.returncode, 1)
            self.assertEqual(
                result.stdout.strip(),
                "package_extract_failed=package_extract_input_not_regular",
            )
            self.assertEqual(result.stderr, "")
            self.assertNotIn(str(base), result.stdout + result.stderr)
            self.assertRegex(
                result.stdout.strip(),
                re.compile(r"\Apackage_extract_failed=[a-z][a-z0-9_]*\Z"),
            )
            self.assert_no_extraction_residue(base, output.name)

    def test_success_output_never_echoes_untrusted_plugin_output_basename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _plugin_source, package = create_plugin_package(base)
            secret_shaped = "sk-proj-" + "D" * 24
            output_name = f"plugin-output-\x1b[31m{secret_shaped}\x1b[0m"
            output = base / output_name

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXTRACTOR),
                    "--zip",
                    str(package),
                    "--output",
                    str(output),
                    "--artifact-type",
                    "plugin",
                ],
                check=False,
                text=True,
                capture_output=True,
                timeout=10,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(
                result.stdout.splitlines(),
                [
                    "package_extract_verification=passed",
                    "artifact_type=plugin",
                    "artifact_root=.",
                ],
            )
            self.assertEqual(result.stderr, "")
            self.assertNotIn(output_name, result.stdout + result.stderr)
            self.assertNotIn(secret_shaped, result.stdout + result.stderr)
            self.assertNotIn("\x1b", result.stdout + result.stderr)
            self.assertTrue(output.is_dir())

    def test_injected_write_failure_leaves_no_residue_and_retry_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "retry-unpacked"

            with mock.patch.object(
                EXTRACT_MODULE.os,
                "write",
                side_effect=OSError(errno.ENOSPC, "sensitive-path-must-not-persist"),
            ):
                with self.assertRaises(OSError) as raised:
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assertEqual(raised.exception.errno, errno.ENOSPC)
            self.assert_no_extraction_residue(base, output.name)

            artifact_root = EXTRACT_MODULE.extract_verified_package(
                package,
                output,
                "source",
            )
            self.assertEqual(artifact_root, (output / "CodexQB").resolve())
            self.assertEqual(
                EXTRACT_MODULE.verify_directory(
                    artifact_root,
                    strict_artifact=True,
                    expected_artifact_type="source",
                ),
                [],
            )

    def test_low_mount_assurance_fails_before_any_member_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "low-assurance-unpacked"
            low_assurance = MOUNT_MODULE.MountResolution(
                selected_provider=MOUNT_MODULE.FILESYSTEM_FSTAT_PROVIDER,
                identity=MOUNT_MODULE.MountIdentity("filesystem", (1,)),
                assurance=MOUNT_MODULE.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
                providers=(),
                failure_code=None,
            )

            with (
                mock.patch.object(
                    EXTRACT_MODULE,
                    "resolve_mount_identity",
                    return_value=low_assurance,
                ),
                mock.patch.object(EXTRACT_MODULE, "_write_member_at") as write_member,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_repository_mount_identity_unavailable",
                ):
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            write_member.assert_not_called()
            self.assert_no_extraction_residue(base, output.name)

    def test_zip64_preflight_fails_before_private_directory_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = base / "zip64.zip"
            package.write_bytes(valid_empty_zip64())
            output = base / "zip64-unpacked"

            with (
                mock.patch.object(
                    VERIFY_MODULE.zipfile,
                    "ZipFile",
                    side_effect=AssertionError("ZipFile constructor must not run"),
                ) as constructor,
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_create_private_sibling",
                ) as create_private,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "^package_zip_zip64_rejected$",
                ):
                    EXTRACT_MODULE.extract_verified_package(
                        package,
                        output,
                        "source",
                    )

            constructor.assert_not_called()
            create_private.assert_not_called()
            self.assert_no_extraction_residue(base, output.name)

    def test_verification_and_extraction_share_one_immutable_package_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _plugin_source, package = create_plugin_package(base)
            swapped_package = base / "swapped-after-verification.zip"
            original_skill = VALID_PLUGIN_SKILL.encode("utf-8")
            swapped_skill = (
                VALID_PLUGIN_SKILL + "\nPost-verification swapped payload.\n"
            ).encode("utf-8")
            rewrite_manifest_bound_file(
                package,
                swapped_package,
                artifact_type="plugin",
                relative_path="skills/codexqb/SKILL.md",
                data=swapped_skill,
            )
            swapped_bytes = swapped_package.read_bytes()
            output = base / "immutable-snapshot-unpacked"
            real_verify = EXTRACT_MODULE.verify_zip
            verification_calls = 0

            def verify_then_mutate_original(source, **kwargs):
                nonlocal verification_calls
                verification_calls += 1
                errors = real_verify(source, **kwargs)
                self.assertEqual(errors, [])
                package.write_bytes(swapped_bytes)
                return errors

            with mock.patch.object(
                EXTRACT_MODULE,
                "verify_zip",
                side_effect=verify_then_mutate_original,
            ):
                artifact_root = EXTRACT_MODULE.extract_verified_package(
                    package,
                    output,
                    "plugin",
                )

            self.assertEqual(verification_calls, 1)
            self.assertEqual(package.read_bytes(), swapped_bytes)
            self.assertEqual(
                (artifact_root / "skills/codexqb/SKILL.md").read_bytes(),
                original_skill,
            )
            self.assertEqual(
                EXTRACT_MODULE.verify_directory(
                    artifact_root,
                    strict_artifact=True,
                    expected_artifact_type="plugin",
                ),
                [],
            )

    def test_late_published_artifact_mutation_cannot_return_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _plugin_source, package = create_plugin_package(base)
            output = base / "late-published-mutation"
            real_open_published = EXTRACT_MODULE._open_published_artifact
            open_calls = 0

            def open_then_mutate(*args, **kwargs):
                nonlocal open_calls
                descriptors = real_open_published(*args, **kwargs)
                open_calls += 1
                if open_calls == 2:
                    (output / "skills/codexqb/SKILL.md").write_text(
                        "attacker-controlled late payload\n",
                        encoding="utf-8",
                    )
                return descriptors

            with mock.patch.object(
                EXTRACT_MODULE,
                "_open_published_artifact",
                side_effect=open_then_mutate,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_file_digest_mismatch",
                ):
                    EXTRACT_MODULE.extract_verified_package(
                        package,
                        output,
                        "plugin",
                    )

            self.assertEqual(open_calls, 2)
            self.assert_no_extraction_residue(base, output.name)

    def test_strict_verifier_maps_descendant_mount_mismatch_to_stable_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "nested-mount-unpacked"
            artifact_root = EXTRACT_MODULE.extract_verified_package(
                package,
                output,
                "source",
            )
            observed_paths: list[str] = []

            def mismatch_descendant(_resolution, _descriptor, relative_path):
                observed_paths.append(relative_path)
                if relative_path == "plugins":
                    raise ValueError("repository_nested_mount_rejected=plugins")
                return None

            with mock.patch.object(
                VERIFY_MODULE,
                "require_same_mount",
                side_effect=mismatch_descendant,
            ):
                errors = VERIFY_MODULE.verify_directory(
                    artifact_root,
                    strict_artifact=True,
                    expected_artifact_type="source",
                )

            self.assertIn(".", observed_paths)
            self.assertIn("plugins", observed_paths)
            self.assertIn("package_directory_nested_mount_rejected", errors)
            rendered_errors = "\n".join(errors)
            self.assertNotIn("repository_nested_mount_rejected", rendered_errors)
            self.assertNotIn("=plugins", rendered_errors)

    def test_atomic_publish_race_preserves_racer_output_without_private_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "raced-output"
            sentinel = "racer-owned-output\n"
            real_publish = EXTRACT_MODULE._atomic_rename_no_replace

            def publish_after_racer(
                source: str,
                destination: str,
                *,
                parent_descriptor: int,
            ) -> None:
                self.assertEqual(destination, output.name)
                output.mkdir()
                (output / "owner.txt").write_text(sentinel, encoding="utf-8")
                real_publish(
                    source,
                    destination,
                    parent_descriptor=parent_descriptor,
                )

            with mock.patch.object(
                EXTRACT_MODULE,
                "_atomic_rename_no_replace",
                side_effect=publish_after_racer,
            ):
                with self.assertRaises(OSError) as raised:
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assertEqual(raised.exception.errno, errno.EEXIST)
            self.assertEqual(
                (output / "owner.txt").read_text(encoding="utf-8"),
                sentinel,
            )
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                ["owner.txt"],
            )
            self.assertEqual(list(base.glob(f".{output.name}.extract-*")), [])

    def test_published_output_mount_mismatch_is_rejected_and_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "published-mount-mismatch"
            real_open_directory = EXTRACT_MODULE._open_directory_at

            def reject_published_output(parent_descriptor, name, **kwargs):
                if name == output.name and kwargs.get("root_resolution") is not None:
                    raise ValueError("package_extract_nested_mount_rejected")
                return real_open_directory(parent_descriptor, name, **kwargs)

            with mock.patch.object(
                EXTRACT_MODULE,
                "_open_directory_at",
                side_effect=reject_published_output,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_extract_nested_mount_rejected",
                ):
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assert_no_extraction_residue(base, output.name)

    def test_post_publish_parent_mount_change_is_rejected_and_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            parent = base / "destination-parent"
            parent.mkdir()
            package = create_source_package(base)
            output = parent / "parent-mount-change"
            real_publish = EXTRACT_MODULE._atomic_rename_no_replace
            real_parent_check = EXTRACT_MODULE._require_directory_path_mount
            published = False

            def publish_then_mark(source, destination, *, parent_descriptor):
                nonlocal published
                real_publish(
                    source,
                    destination,
                    parent_descriptor=parent_descriptor,
                )
                published = True

            def reject_changed_parent(path, expected, root_resolution):
                if published:
                    raise ValueError("package_extract_parent_mount_changed")
                return real_parent_check(path, expected, root_resolution)

            with (
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_atomic_rename_no_replace",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_require_directory_path_mount",
                    side_effect=reject_changed_parent,
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_extract_parent_mount_changed",
                ):
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assert_no_extraction_residue(parent, output.name)

    def test_failed_post_publish_cleanup_reports_unknown_recovery_state(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _source, package = create_plugin_package(base)
            output = base / "cleanup-state-unknown"
            real_publish = EXTRACT_MODULE._atomic_rename_no_replace
            real_parent_check = EXTRACT_MODULE._require_directory_path_mount
            published = False

            def publish_then_mark(source, destination, *, parent_descriptor):
                nonlocal published
                real_publish(
                    source,
                    destination,
                    parent_descriptor=parent_descriptor,
                )
                published = True

            def fail_after_publish(path, expected, root_resolution):
                if published:
                    raise ValueError("package_extract_injected_post_publish_failure")
                return real_parent_check(path, expected, root_resolution)

            with (
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_atomic_rename_no_replace",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_require_directory_path_mount",
                    side_effect=fail_after_publish,
                ),
                mock.patch.object(
                    EXTRACT_MODULE,
                    "_remove_generated_root",
                    side_effect=ValueError("package_extract_nested_mount_rejected"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^package_extract_cleanup_state_unknown$",
                ) as caught:
                    EXTRACT_MODULE.extract_verified_package(package, output, "plugin")

            primary_error = caught.exception.__cause__
            self.assertIsInstance(primary_error, ValueError)
            self.assertEqual(
                str(primary_error),
                "package_extract_injected_post_publish_failure",
            )
            self.assertIsInstance(primary_error.__cause__, ValueError)
            self.assertEqual(
                str(primary_error.__cause__),
                "package_extract_nested_mount_rejected",
            )
            self.assertTrue(output.exists())

    def test_source_artifact_root_swap_is_rejected_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            package = create_source_package(base)
            output = base / "root-swap-unpacked"

            def swap_artifact_root(root: Path, **_kwargs) -> list[str]:
                displaced = root.with_name("CodexQB-displaced")
                root.rename(displaced)
                root.mkdir()
                return []

            with mock.patch.object(
                EXTRACT_MODULE,
                "verify_directory",
                side_effect=swap_artifact_root,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_extract_artifact_root_changed",
                ):
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assert_no_extraction_residue(base, output.name)

    def test_output_parent_path_swap_is_rejected_before_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            parent = base / "destination-parent"
            parent.mkdir()
            package = create_source_package(base)
            output = parent / "parent-swap-unpacked"
            displaced_parent = base / "destination-parent-displaced"

            def swap_parent_path(_root: Path, **_kwargs) -> list[str]:
                parent.rename(displaced_parent)
                parent.mkdir()
                return []

            with mock.patch.object(
                EXTRACT_MODULE,
                "verify_directory",
                side_effect=swap_parent_path,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_extract_parent_changed",
                ):
                    EXTRACT_MODULE.extract_verified_package(package, output, "source")

            self.assert_no_extraction_residue(parent, output.name)
            self.assertFalse(any(displaced_parent.glob(f".{output.name}.extract-*")))


if __name__ == "__main__":
    unittest.main()
