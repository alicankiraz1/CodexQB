from __future__ import annotations

import errno
import importlib.util
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
EXPORTER = REPO_ROOT / "scripts/export_sanitized.py"


def load_export_module():
    spec = importlib.util.spec_from_file_location("codexqb_export_sanitized", EXPORTER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load export_sanitized from {EXPORTER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXPORT_MODULE = load_export_module()
MOUNT_MODULE = sys.modules["mount_identity"]
VALID_PLUGIN_SKILL = """---
name: codexqb
description: Canonical CodexQB package fixture.
---

# CodexQB fixture
"""
VALID_PLUGIN_ACTIVATION = """interface:
  display_name: "CodexQB"
  short_description: "Vibecoding evidence fixture"
  default_prompt: "Use $codexqb for the fixture."
policy:
  allow_implicit_invocation: false
"""


def valid_empty_zip64() -> bytes:
    zip64_eocd = struct.pack(
        "<IQHHIIQQQQ",
        0x06064B50,
        44,
        45,
        45,
        0,
        0,
        0,
        0,
        0,
        0,
    )
    locator = struct.pack("<IIQI", 0x07064B50, 0, 0, 1)
    eocd = struct.pack(
        "<IHHHHIIH",
        0x06054B50,
        0,
        0,
        0xFFFF,
        0xFFFF,
        0xFFFFFFFF,
        0xFFFFFFFF,
        0,
    )
    payload = zip64_eocd + locator + eocd
    if not zipfile.is_zipfile(io.BytesIO(payload)):
        raise AssertionError("ZIP64 fixture must be a valid ZIP archive")
    return payload


def valid_zip_polyglot() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("payload.txt", b"nested payload\n")
    payload = b"#!/bin/sh\nexit 0\n" + buffer.getvalue()
    if not zipfile.is_zipfile(io.BytesIO(payload)):
        raise AssertionError("polyglot fixture must be a valid ZIP archive")
    return payload


def git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, text=True, capture_output=True)


def git_commit_all(root: Path, message: str = "fixture") -> None:
    git(root, "add", ".")
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=CodexQB Export Test",
            "-c",
            "user.email=codexqb-export@example.invalid",
            "commit",
            "-m",
            message,
        ],
        cwd=root,
        check=True,
        text=True,
        capture_output=True,
    )


def write_minimal_codexqb_tree(root: Path) -> None:
    (root / "plugins/codexqb/.codex-plugin").mkdir(parents=True)
    (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
        json.dumps({"version": "0.3.0"}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (root / "CHANGELOG.md").write_text("# Changelog\n\n## Unreleased\n\n- 0.3.0 fixture.\n", encoding="utf-8")
    (root / "README.md").write_text("# Fixture\n", encoding="utf-8")


def write_released_changelog(root: Path, version: str = "0.3.0") -> None:
    (root / "CHANGELOG.md").write_text(
        f"# Changelog\n\n## {version} - 2026-07-14\n\n- Release fixture.\n",
        encoding="utf-8",
    )


def tag_release(root: Path, version: str = "0.3.0") -> None:
    git(root, "tag", f"v{version}")


def archive_names(output: Path) -> set[str]:
    with zipfile.ZipFile(output) as archive:
        return set(archive.namelist())


def archive_name_list(output: Path) -> list[str]:
    with zipfile.ZipFile(output) as archive:
        return archive.namelist()


def package_manifest(output: Path, artifact_type: str = "source") -> dict[str, object]:
    member = (
        "PACKAGE-MANIFEST.json"
        if artifact_type == "plugin"
        else "CodexQB/PACKAGE-MANIFEST.json"
    )
    with zipfile.ZipFile(output) as archive:
        return json.loads(archive.read(member).decode("utf-8"))


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ExportSanitizedTests(unittest.TestCase):
    def test_release_export_writes_manifest_from_clean_tracked_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            output = root / "CodexQB-sanitized.zip"

            count = EXPORT_MODULE.create_zip(root, output)

            self.assertEqual(count, 3)
            names = archive_names(output)
            self.assertIn("CodexQB/README.md", names)
            self.assertIn("CodexQB/PACKAGE-MANIFEST.json", names)
            manifest = package_manifest(output)
            self.assertEqual(manifest["package_schema_version"], 3)
            self.assertEqual(manifest["artifact_type"], "source")
            self.assertEqual(manifest["layout_version"], 1)
            self.assertEqual(manifest["content_sha256"], manifest["tree_sha256"])
            self.assertEqual(manifest["plugin_version"], "0.3.0")
            self.assertEqual(manifest["file_count"], 3)
            self.assertEqual(manifest["working_tree_clean"], True)
            self.assertEqual(manifest["tracked_only"], True)
            self.assertEqual(manifest["include_untracked"], False)
            self.assertEqual(manifest["changelog_mentions_plugin_version"], True)
            self.assertEqual(manifest["export_mode"], "strict_release")
            self.assertEqual(manifest["git_provenance_available"], True)
            self.assertEqual(manifest["changelog_release_state"], "released")
            self.assertEqual(manifest["release_tag"], "v0.3.0")
            self.assertEqual(manifest["release_tag_commit"], manifest["git_commit"])
            self.assertEqual(manifest["release_tag_matches_head"], True)
            self.assertIsInstance(manifest["tree_sha256"], str)

    def test_release_export_replaces_existing_package_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            (root / "PACKAGE-MANIFEST.json").write_text('{"stale": true}\n', encoding="utf-8")
            git_commit_all(root)
            tag_release(root)
            output = root / "CodexQB-sanitized.zip"

            count = EXPORT_MODULE.create_zip(root, output)

            names = archive_name_list(output)
            self.assertEqual(count, 3)
            self.assertEqual(names.count("CodexQB/PACKAGE-MANIFEST.json"), 1)
            manifest = package_manifest(output)
            self.assertNotIn("stale", manifest)
            self.assertFalse(any(item["path"] == "PACKAGE-MANIFEST.json" for item in manifest["files"]))

    def test_release_export_rejects_dirty_worktree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            (root / "notes.txt").write_text("local draft\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "working_tree_dirty"):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_worktree_evidence_never_executes_configured_clean_filter(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "checkout"
            root.mkdir()
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            (root / ".gitattributes").write_text(
                "README.md diff=probe filter=probe\n",
                encoding="utf-8",
            )
            git_commit_all(root)
            tag_release(root)

            markers: list[Path] = []

            def marker_program(name: str) -> Path:
                marker = base / f"{name}-ran"
                program = base / name
                program.write_text(
                    "#!/bin/sh\n"
                    f"touch '{marker.as_posix()}'\n"
                    "cat\n",
                    encoding="utf-8",
                )
                program.chmod(0o755)
                markers.append(marker)
                return program

            clean_filter = marker_program("clean-filter")
            process_filter = marker_program("process-filter")
            diff_command = marker_program("diff-command")
            textconv = marker_program("textconv")
            external_diff = marker_program("external-diff")
            fsmonitor = marker_program("fsmonitor")
            git(root, "config", "filter.probe.clean", clean_filter.as_posix())
            git(root, "config", "filter.probe.process", process_filter.as_posix())
            git(root, "config", "filter.probe.required", "true")
            git(root, "config", "diff.probe.command", diff_command.as_posix())
            git(root, "config", "diff.probe.textconv", textconv.as_posix())
            git(root, "config", "diff.external", external_diff.as_posix())
            git(root, "config", "core.fsmonitor", fsmonitor.as_posix())

            transient = root / "CodexQB-sanitized.zip"
            transient.write_bytes(b"temporary package")
            self.assertEqual(
                EXPORT_MODULE.git_status_excluding(root, [transient.name]),
                "",
            )
            self.assertFalse(any(marker.exists() for marker in markers))

            (root / "README.md").write_text("# Changed\n", encoding="utf-8")
            self.assertEqual(EXPORT_MODULE.git_status(root), "dirty")
            self.assertFalse(any(marker.exists() for marker in markers))

    def test_git_output_limit_fails_closed_before_export(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            output = root / "CodexQB-sanitized.zip"
            index_arguments = [
                "ls-files",
                "--stage",
                "-v",
                "-z",
                "--cached",
                "--full-name",
                "--",
            ]
            real_git_command = EXPORT_MODULE.git_command

            for output_descriptor in (1, 2):
                with self.subTest(output_descriptor=output_descriptor):
                    def command_with_oversized_index(args):
                        if args == index_arguments:
                            return [
                                sys.executable,
                                "-c",
                                (
                                    "import os; "
                                    f"os.write({output_descriptor}, b'x' * 65536)"
                                ),
                            ]
                        return real_git_command(args)

                    with mock.patch.object(
                        EXPORT_MODULE,
                        "MAX_GIT_COMMAND_OUTPUT_BYTES",
                        1024,
                    ), mock.patch.object(
                        EXPORT_MODULE,
                        "git_command",
                        side_effect=command_with_oversized_index,
                    ):
                        self.assertIsNone(
                            EXPORT_MODULE.run_git_bytes(root, index_arguments)
                        )
                        if output_descriptor == 1:
                            with self.assertRaisesRegex(
                                ValueError,
                                "git_index_inventory_required_for_output_safety",
                            ):
                                EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "posix", "process-group cleanup requires POSIX")
    def test_git_helper_reaps_process_group_when_interrupted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            child_pid_path = root / "child.pid"
            command = [
                sys.executable,
                "-c",
                (
                    "import pathlib, subprocess, sys, time; "
                    "child = subprocess.Popen([sys.executable, '-c', "
                    "'import time; time.sleep(60)']); "
                    "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
                    "time.sleep(60)"
                ),
                str(child_pid_path),
            ]

            def interrupt_after_child_starts(*_args, **_kwargs):
                deadline = time.monotonic() + 5
                while not child_pid_path.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(child_pid_path.exists())
                raise KeyboardInterrupt

            with mock.patch.object(
                EXPORT_MODULE,
                "git_command",
                return_value=command,
            ), mock.patch.object(
                EXPORT_MODULE.selectors.DefaultSelector,
                "select",
                side_effect=interrupt_after_child_starts,
            ):
                with self.assertRaises(KeyboardInterrupt):
                    EXPORT_MODULE.run_git_bytes(root, ["rev-parse", "HEAD"])

            child_pid = int(child_pid_path.read_text(encoding="utf-8"))
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.kill(child_pid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.01)
            else:
                try:
                    os.kill(child_pid, 9)
                except ProcessLookupError:
                    pass
                self.fail("interrupted Git child process survived cleanup")

    def test_strict_export_rejects_repository_root_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            replacement = base / "replacement"
            held = base / "held-source"
            root.mkdir()
            replacement.mkdir()
            for checkout, readme in (
                (root, "# ORIGINAL\n"),
                (replacement, "# REPLACEMENT\n"),
            ):
                git(checkout, "init")
                write_minimal_codexqb_tree(checkout)
                write_released_changelog(checkout)
                (checkout / "README.md").write_text(readme, encoding="utf-8")
                git_commit_all(checkout)
                tag_release(checkout)
            output = base / "CodexQB-sanitized.zip"
            real_popen = EXPORT_MODULE.subprocess.Popen
            swapped = False

            def swap_root_before_first_git(*args, **kwargs):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    root.rename(held)
                    replacement.rename(root)
                return real_popen(*args, **kwargs)

            with mock.patch.object(
                EXPORT_MODULE.subprocess,
                "Popen",
                side_effect=swap_root_before_first_git,
            ):
                with self.assertRaisesRegex(ValueError, "repository_root_identity_changed"):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertTrue(swapped)
            self.assertFalse(output.exists())

    def test_payload_reads_stay_bound_to_root_during_transient_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            replacement = base / "replacement"
            held = base / "held-source"
            displaced = base / "displaced-replacement"
            root.mkdir()
            replacement.mkdir()
            for checkout, readme in (
                (root, "# ORIGINAL\n"),
                (replacement, "# REPLACEMENT\n"),
            ):
                write_minimal_codexqb_tree(checkout)
                (checkout / "README.md").write_text(readme, encoding="utf-8")
            output = base / "CodexQB-source-package.zip"
            repository_evidence = sys.modules["repository_evidence"]
            real_open = repository_evidence.os.open
            swapped = False

            def swap_only_while_opening_readme(
                path,
                flags,
                mode=0o777,
                *,
                dir_fd=None,
            ):
                nonlocal swapped
                if not swapped and path == "README.md" and dir_fd is not None:
                    swapped = True
                    root.rename(held)
                    replacement.rename(root)
                    try:
                        return real_open(path, flags, mode, dir_fd=dir_fd)
                    finally:
                        root.rename(displaced)
                        held.rename(root)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                repository_evidence.os,
                "open",
                side_effect=swap_only_while_opening_readme,
            ):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(swapped)
            with zipfile.ZipFile(output) as archive:
                self.assertEqual(archive.read("CodexQB/README.md"), b"# ORIGINAL\n")

    def test_source_package_rejects_nested_mount_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "CodexQB-source-package.zip"

            with mock.patch.object(
                EXPORT_MODULE,
                "require_same_repository_mount",
                side_effect=ValueError("repository_nested_mount_rejected=plugins"),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_nested_mount_rejected=plugins",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertFalse(output.exists())

    def test_source_package_rejects_single_file_mount_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "CodexQB-source-package.zip"
            repository_evidence = sys.modules["repository_evidence"]
            real_mount_identity = repository_evidence._descriptor_mount_identity

            def simulated_file_mount(file_descriptor):
                metadata = os.fstat(file_descriptor)
                if stat.S_ISREG(metadata.st_mode):
                    return ("simulated_single_file_mount", 2)
                return real_mount_identity(file_descriptor)

            with mock.patch.object(
                repository_evidence,
                "_descriptor_mount_identity",
                side_effect=simulated_file_mount,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_nested_mount_rejected=",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertFalse(output.exists())

    def test_root_replacement_during_publish_fails_and_rolls_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            replacement = base / "replacement"
            held = base / "held-source"
            root.mkdir()
            replacement.mkdir()
            write_minimal_codexqb_tree(root)
            write_minimal_codexqb_tree(replacement)
            output = root / "CodexQB-source-package.zip"
            attacker_payload = b"attacker-visible-output\n"
            (replacement / output.name).write_bytes(attacker_payload)
            real_replace = EXPORT_MODULE.os.replace
            swapped = False

            def swap_root_during_first_replace(
                source,
                destination,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                nonlocal swapped
                if not swapped:
                    swapped = True
                    root.rename(held)
                    replacement.rename(root)
                return real_replace(
                    source,
                    destination,
                    src_dir_fd=src_dir_fd,
                    dst_dir_fd=dst_dir_fd,
                )

            with mock.patch.object(
                EXPORT_MODULE.os,
                "replace",
                side_effect=swap_root_during_first_replace,
            ):
                with self.assertRaisesRegex(ValueError, "repository_root_identity_changed"):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(swapped)
            self.assertEqual((root / output.name).read_bytes(), attacker_payload)
            self.assertFalse((held / output.name).exists())

    def test_strict_export_rejects_git_index_trust_flags(self) -> None:
        for flag in ["--assume-unchanged", "--skip-worktree"]:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                git(root, "init")
                write_minimal_codexqb_tree(root)
                write_released_changelog(root)
                git_commit_all(root)
                tag_release(root)
                git(root, "update-index", flag, "README.md")
                (root / "README.md").write_text("# Hidden worktree change\n", encoding="utf-8")
                status = subprocess.run(
                    ["git", "status", "--porcelain=v1"],
                    cwd=root,
                    check=True,
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(status.stdout, "")
                output = root / "CodexQB-sanitized.zip"

                with self.assertRaisesRegex(ValueError, "git_index_trust_flags_present"):
                    EXPORT_MODULE.create_zip(root, output)

                self.assertFalse(output.exists())

    def test_strict_export_ignores_git_replacement_objects(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root, "release A")
            tag_release(root)
            release_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            original_readme = (root / "README.md").read_bytes()
            (root / "README.md").write_text("# Replacement commit B\n", encoding="utf-8")
            git_commit_all(root, "replacement B")
            replacement_commit = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                text=True,
                capture_output=True,
            ).stdout.strip()
            git(root, "replace", release_commit, replacement_commit)
            git(root, "reset", "--hard", release_commit)
            status = subprocess.run(
                ["git", "status", "--porcelain=v1"],
                cwd=root,
                check=True,
                text=True,
                capture_output=True,
            )
            self.assertEqual(status.stdout, "")
            self.assertNotEqual((root / "README.md").read_bytes(), original_readme)
            output = root / "CodexQB-sanitized.zip"

            with self.assertRaisesRegex(
                ValueError,
                "working_tree_dirty|strict_index_not_release_commit",
            ):
                EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_ignores_inherited_git_repository_routing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "actual"
            root.mkdir()
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root, "actual release A")
            tag_release(root)
            alternate = base / "alternate"
            subprocess.run(
                ["git", "clone", str(root), str(alternate)],
                check=True,
                text=True,
                capture_output=True,
            )
            changed = "# Alternate commit B\n"
            (alternate / "README.md").write_text(changed, encoding="utf-8")
            git_commit_all(alternate, "alternate B")
            git(alternate, "tag", "-f", "v0.3.0")
            (root / "README.md").write_text(changed, encoding="utf-8")
            output = base / "routed.zip"

            with mock.patch.dict(
                os.environ,
                {
                    "GIT_DIR": str(alternate / ".git"),
                    "GIT_WORK_TREE": str(root),
                },
                clear=False,
            ):
                with self.assertRaisesRegex(ValueError, "working_tree_dirty"):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_ignores_inherited_alternate_index(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "actual"
            root.mkdir()
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            clean_index = base / "clean-index"
            clean_index.write_bytes((root / ".git/index").read_bytes())
            original = (root / "README.md").read_bytes()
            (root / "README.md").write_text("# Staged alternate index bytes\n", encoding="utf-8")
            git(root, "add", "README.md")
            (root / "README.md").write_bytes(original)
            output = base / "alternate-index.zip"

            with mock.patch.dict(
                os.environ,
                {"GIT_INDEX_FILE": str(clean_index)},
                clear=False,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "working_tree_dirty|strict_index_not_release_commit",
                ):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_hashes_sanitizer_excluded_tracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            excluded = root / "archive.zip"
            excluded.write_bytes(b"tracked release archive\n")
            git_commit_all(root)
            tag_release(root)
            excluded.write_bytes(b"hidden modified archive\n")
            output = root / "CodexQB-sanitized.zip"

            with mock.patch.object(EXPORT_MODULE, "git_status", return_value=""):
                with self.assertRaisesRegex(ValueError, "strict_worktree_not_release_commit"):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_output_cannot_overwrite_tracked_source_or_git_metadata(self) -> None:
        for source_package in [False, True]:
            with self.subTest(source_package=source_package), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                git(root, "init")
                write_minimal_codexqb_tree(root)
                write_released_changelog(root)
                git_commit_all(root)
                tag_release(root)
                readme = root / "README.md"
                original_readme = readme.read_bytes()

                with self.assertRaisesRegex(
                    ValueError,
                    "output_collides_with_tracked_source",
                ):
                    EXPORT_MODULE.create_zip(root, readme, source_package=source_package)

                self.assertEqual(readme.read_bytes(), original_readme)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            git_config = root / ".git/config"
            original_config = git_config.read_bytes()

            with self.assertRaisesRegex(ValueError, "output_inside_git_metadata"):
                EXPORT_MODULE.create_zip(root, git_config)

            self.assertEqual(git_config.read_bytes(), original_config)
            subprocess.run(
                ["git", "status", "--porcelain=v1"],
                cwd=root,
                check=True,
                text=True,
                capture_output=True,
            )

    def test_output_collision_uses_portable_casefolded_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            tracked = root / "Release.ZIP"
            tracked.write_bytes(b"tracked source bytes\n")
            git_commit_all(root)
            tag_release(root)
            original = tracked.read_bytes()

            with self.assertRaisesRegex(ValueError, "output_collides_with_tracked_source"):
                EXPORT_MODULE.create_zip(root, root / "release.zip")

            self.assertEqual(tracked.read_bytes(), original)

    def test_output_collision_handles_alternate_case_repo_root_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            tracked = root / "Release.ZIP"
            tracked.write_bytes(b"tracked source bytes\n")
            git_commit_all(root)
            tag_release(root)
            alias_root = root.parent / root.name.swapcase()
            if alias_root == root or not alias_root.exists() or not os.path.samefile(root, alias_root):
                self.skipTest("case-insensitive filesystem required")
            original = tracked.read_bytes()

            with self.assertRaisesRegex(ValueError, "output_collides_with_tracked_source"):
                EXPORT_MODULE.create_zip(root, alias_root / "release.zip")

            self.assertEqual(tracked.read_bytes(), original)

    def test_git_metadata_guard_uses_directory_identity_for_case_aliases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            upper_git = root / ".GIT"
            if not upper_git.exists():
                self.skipTest("case-insensitive filesystem required")
            git(root, "branch", "release.zip")
            branch_ref = upper_git / "refs/heads/release.zip"
            original = branch_ref.read_bytes()

            with self.assertRaisesRegex(ValueError, "output_inside_git_metadata"):
                EXPORT_MODULE.create_zip(root, branch_ref)

            self.assertEqual(branch_ref.read_bytes(), original)
            subprocess.run(
                ["git", "show-ref", "--verify", "refs/heads/release.zip"],
                cwd=root,
                check=True,
                text=True,
                capture_output=True,
            )

    def test_blocked_suffixes_are_case_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_minimal_codexqb_tree(root)
            (root / "archive.ZIP").write_bytes(b"not package input\n")
            (root / "private.PEM").write_bytes(b"synthetic blocked input\n")
            output = root / "CodexQB-source-package.zip"

            EXPORT_MODULE.create_zip(root, output, source_package=True)

            names = archive_names(output)
            self.assertNotIn("CodexQB/archive.ZIP", names)
            self.assertNotIn("CodexQB/private.PEM", names)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink support required")
    def test_output_parent_ancestor_swap_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            write_minimal_codexqb_tree(root)
            safe = base / "safe"
            original_parent = safe / "b"
            original_parent.mkdir(parents=True)
            outside = base / "outside"
            outside_parent = outside / "b"
            outside_parent.mkdir(parents=True)
            output = original_parent / "out.zip"
            canonical_parent = original_parent.resolve()
            real_open = EXPORT_MODULE.os.open
            fired = False

            def swap_ancestor(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal fired
                if not fired and dir_fd is None and Path(path) == canonical_parent:
                    fired = True
                    safe.rename(base / "safe-original")
                    safe.symlink_to(outside, target_is_directory=True)
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(EXPORT_MODULE.os, "open", side_effect=swap_ancestor):
                with self.assertRaisesRegex(ValueError, "output_parent_changed_during_export"):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(fired)
            self.assertFalse(outside_parent.joinpath("out.zip").exists())
            self.assertFalse((base / "safe-original/b/out.zip").exists())

    def test_source_package_marks_hidden_git_status_as_not_clean(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            git(root, "update-index", "--assume-unchanged", "README.md")
            (root / "README.md").write_text("# Hidden source-package bytes\n", encoding="utf-8")
            output = root / "CodexQB-source-package.zip"

            EXPORT_MODULE.create_zip(root, output, source_package=True)

            manifest = package_manifest(output)
            self.assertEqual(manifest["release_claim"], False)
            self.assertEqual(manifest["working_tree_clean"], False)

    def test_strict_export_binds_payload_bytes_and_mode_to_release_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            output = root / "CodexQB-sanitized.zip"
            (root / "README.md").write_text("# Unreported bytes\n", encoding="utf-8")

            with mock.patch.object(EXPORT_MODULE, "git_status", return_value=""):
                with self.assertRaisesRegex(ValueError, "strict_payload_not_release_commit"):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            git(root, "config", "core.filemode", "false")
            readme = root / "README.md"
            readme.chmod(0o755)
            output = root / "CodexQB-sanitized.zip"

            with mock.patch.object(EXPORT_MODULE, "git_status", return_value=""):
                with self.assertRaisesRegex(
                    ValueError,
                    "strict_payload_mode_not_release_commit",
                ):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_rejects_index_not_at_release_commit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            (root / "README.md").write_text("# Staged after tag\n", encoding="utf-8")
            git(root, "add", "README.md")
            output = root / "CodexQB-sanitized.zip"

            with mock.patch.object(EXPORT_MODULE, "git_status", return_value=""):
                with self.assertRaisesRegex(ValueError, "strict_index_not_release_commit"):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_git_index_inventory_parser_is_nul_safe_and_fail_closed(self) -> None:
        oid = b"a" * 40
        unusual_path = "dir/tab\tnewline\nname.txt"
        valid = b"H 100644 " + oid + b" 0\t" + os.fsencode(unusual_path) + b"\0"
        inventory, errors = EXPORT_MODULE.parse_git_index_inventory(valid)
        self.assertEqual(errors, [])
        self.assertEqual(inventory[unusual_path], ("H", "100644", "a" * 40))

        malformed_samples = [
            valid[:-1],
            b"H 100644 " + oid + b" 1\tREADME.md\0",
            valid + valid,
            b"H bad-header\tREADME.md\0",
        ]
        for sample in malformed_samples:
            with self.subTest(sample=sample[:32]):
                _inventory, sample_errors = EXPORT_MODULE.parse_git_index_inventory(sample)
                self.assertIn("git_index_inventory_malformed", sample_errors)

        for tag in [b"h", b"S", b"s"]:
            with self.subTest(tag=tag):
                _inventory, flag_errors = EXPORT_MODULE.parse_git_index_inventory(
                    tag + b" 100644 " + oid + b" 0\tREADME.md\0"
                )
                self.assertIn("git_index_trust_flags_present", flag_errors)

        two_records = (
            b"H 100644 " + oid + b" 0\tone.txt\0"
            b"H 100644 " + oid + b" 0\ttwo.txt\0"
        )
        with mock.patch.object(EXPORT_MODULE, "MAX_MANIFEST_FILES", 1):
            _inventory, limit_errors = EXPORT_MODULE.parse_git_index_inventory(
                two_records
            )
        self.assertIn("git_index_inventory_limit_exceeded", limit_errors)

    def test_strict_export_rejects_non_git_source(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_minimal_codexqb_tree(root)
            output = root / "CodexQB-sanitized.zip"

            with self.assertRaisesRegex(
                ValueError,
                "^git_metadata_required_for_strict_export$",
            ):
                EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_rejects_source_nested_inside_parent_git_checkout(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            git(parent, "init")
            root = parent / "extracted-copy"
            write_minimal_codexqb_tree(root)

            with self.assertRaisesRegex(
                ValueError,
                "^git_metadata_required_for_strict_export$",
            ):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_strict_export_fails_closed_when_git_status_or_head_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)

            with mock.patch.object(EXPORT_MODULE, "git_status", return_value=None):
                with self.assertRaisesRegex(ValueError, "git_status_unavailable"):
                    EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")
            with mock.patch.object(EXPORT_MODULE, "git_commit", return_value=None):
                with self.assertRaisesRegex(ValueError, "git_head_unavailable"):
                    EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_strict_export_rechecks_manifest_provenance_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)
            output = root / "CodexQB-sanitized.zip"
            real_status = EXPORT_MODULE.git_status
            calls = 0

            def status_disappears(candidate_root):
                nonlocal calls
                calls += 1
                return real_status(candidate_root) if calls == 1 else None

            with mock.patch.object(EXPORT_MODULE, "git_status", side_effect=status_disappears):
                with self.assertRaisesRegex(
                    ValueError,
                    "strict_release_manifest_provenance_incomplete=working_tree_clean",
                ):
                    EXPORT_MODULE.create_zip(root, output)

            self.assertFalse(output.exists())

    def test_strict_export_fails_if_origin_main_ref_status_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)
            tag_release(root)

            with mock.patch.object(
                EXPORT_MODULE,
                "origin_main_provenance",
                return_value=("unavailable", None),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "origin_main_ref_status_unavailable",
                ):
                    EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_source_package_export_is_explicit_and_never_claims_tracked_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_minimal_codexqb_tree(root)
            output = root / "CodexQB-source-package.zip"

            count = EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertEqual(count, 3)
            manifest = package_manifest(output)
            self.assertEqual(manifest["export_mode"], "source_package")
            self.assertEqual(manifest["git_provenance_available"], False)
            self.assertEqual(manifest["tracked_only"], False)
            self.assertEqual(manifest["include_untracked"], True)
            self.assertEqual(manifest["working_tree_clean"], None)
            self.assertEqual(manifest["changelog_release_state"], "unreleased")
            self.assertEqual(manifest["release_tag"], "v0.3.0")
            self.assertEqual(manifest["release_tag_commit"], "unknown")
            self.assertEqual(manifest["release_tag_matches_head"], None)

    def test_filesystem_export_remains_available_without_a_git_executable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "source.zip"

            with mock.patch.object(
                EXPORT_MODULE,
                "trusted_git_executable",
                side_effect=ValueError("trusted_git_executable_unavailable"),
            ):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            manifest = package_manifest(output)
            self.assertEqual(manifest["export_mode"], "source_package")
            self.assertEqual(manifest["git_provenance_available"], False)
            self.assertEqual(manifest["git_commit"], "unknown")

    def test_package_creation_enforces_the_non_destructive_mount_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "source.zip"
            low_assurance = MOUNT_MODULE.MountResolution(
                selected_provider=MOUNT_MODULE.FILESYSTEM_FSTAT_PROVIDER,
                identity=MOUNT_MODULE.MountIdentity("filesystem", (1,)),
                assurance=MOUNT_MODULE.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
                providers=(),
                failure_code=None,
            )
            real_require = EXPORT_MODULE.require_mount_assurance
            observed_operations: list[str] = []

            def force_low_assurance(_resolution, operation):
                observed_operations.append(operation)
                return real_require(low_assurance, operation)

            with mock.patch.object(
                EXPORT_MODULE,
                "require_mount_assurance",
                side_effect=force_low_assurance,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_repository_mount_identity_unavailable",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertEqual(
                observed_operations,
                [MOUNT_MODULE.NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION],
            )
            self.assertFalse(output.exists())

    def test_output_parent_mount_assurance_is_required_before_temp_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "source.zip"
            low_assurance = MOUNT_MODULE.MountResolution(
                selected_provider=MOUNT_MODULE.FILESYSTEM_FSTAT_PROVIDER,
                identity=MOUNT_MODULE.MountIdentity("filesystem", (1,)),
                assurance=MOUNT_MODULE.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
                providers=(),
                failure_code=None,
            )

            with (
                mock.patch.object(
                    EXPORT_MODULE,
                    "resolve_mount_identity",
                    return_value=low_assurance,
                ),
                mock.patch.object(
                    EXPORT_MODULE,
                    "create_secure_package_temp",
                ) as create_temp,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "secure_repository_mount_identity_unavailable",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            create_temp.assert_not_called()
            self.assertFalse(output.exists())

    def test_post_publish_output_parent_mount_change_is_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "source.zip"
            real_replace = EXPORT_MODULE.os.replace
            real_parent_check = EXPORT_MODULE.require_output_parent_identity
            published = False

            def publish_then_mark(source, destination, *args, **kwargs):
                nonlocal published
                result = real_replace(source, destination, *args, **kwargs)
                if destination == output.name:
                    published = True
                return result

            def reject_changed_parent(*args, **kwargs):
                if published:
                    raise ValueError("package_output_nested_mount_rejected")
                return real_parent_check(*args, **kwargs)

            with (
                mock.patch.object(
                    EXPORT_MODULE.os,
                    "replace",
                    side_effect=publish_then_mark,
                ),
                mock.patch.object(
                    EXPORT_MODULE,
                    "require_output_parent_identity",
                    side_effect=reject_changed_parent,
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "package_output_nested_mount_rejected",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertFalse(output.exists())
            self.assertEqual(list(base.glob(f".{output.name}.*.tmp")), [])
            self.assertEqual(list(base.glob(f".{output.name}.*.backup")), [])

    def test_final_output_path_substitution_cannot_return_success(self) -> None:
        for existing_bytes in (None, b"preexisting package bytes"):
            with self.subTest(existing=existing_bytes is not None), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                write_minimal_codexqb_tree(root)
                output = base / "source.zip"
                poison = b"attacker-controlled final path"
                if existing_bytes is not None:
                    output.write_bytes(existing_bytes)
                real_parent_check = EXPORT_MODULE.require_output_parent_identity
                parent_checks = 0

                def substitute_before_final_parent_check(*args, **kwargs):
                    nonlocal parent_checks
                    parent_checks += 1
                    if parent_checks == 5:
                        output.unlink()
                        output.write_bytes(poison)
                    return real_parent_check(*args, **kwargs)

                with mock.patch.object(
                    EXPORT_MODULE,
                    "require_output_parent_identity",
                    side_effect=substitute_before_final_parent_check,
                ):
                    with self.assertRaisesRegex(
                        RuntimeError,
                        "^package_publish_rollback_failed$",
                    ):
                        EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertEqual(parent_checks, 5)
                self.assertEqual(output.read_bytes(), poison)
                self.assertEqual(list(base.glob(f".{output.name}.*.tmp")), [])
                backups = list(base.glob(f".{output.name}.*.backup"))
                if existing_bytes is None:
                    self.assertEqual(backups, [])
                else:
                    self.assertEqual(len(backups), 1)
                    self.assertEqual(backups[0].read_bytes(), existing_bytes)

    def test_final_output_parent_mount_failure_rolls_back_before_commit(self) -> None:
        for existing_bytes in (None, b"preexisting package bytes"):
            with self.subTest(existing=existing_bytes is not None), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                write_minimal_codexqb_tree(root)
                output = base / "source.zip"
                if existing_bytes is not None:
                    output.write_bytes(existing_bytes)
                real_parent_check = EXPORT_MODULE.require_output_parent_identity
                parent_checks = 0

                def reject_final_parent_mount(*args, **kwargs):
                    nonlocal parent_checks
                    parent_checks += 1
                    if parent_checks == 5:
                        raise ValueError("package_output_nested_mount_rejected")
                    return real_parent_check(*args, **kwargs)

                with mock.patch.object(
                    EXPORT_MODULE,
                    "require_output_parent_identity",
                    side_effect=reject_final_parent_mount,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "^package_output_nested_mount_rejected$",
                    ):
                        EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertEqual(parent_checks, 5)
                if existing_bytes is None:
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(output.read_bytes(), existing_bytes)
                self.assertEqual(list(base.glob(f".{output.name}.*.tmp")), [])
                self.assertEqual(list(base.glob(f".{output.name}.*.backup")), [])

    def test_plugin_and_source_artifacts_have_distinct_reproducible_layouts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
                json.dumps(
                    {
                        "name": "codexqb",
                        "version": "0.3.0",
                        "skills": "./skills/",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            skill = root / "plugins/codexqb/skills/codexqb/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(VALID_PLUGIN_SKILL, encoding="utf-8")
            activation = root / "plugins/codexqb/skills/codexqb/agents/openai.yaml"
            activation.parent.mkdir()
            activation.write_text(VALID_PLUGIN_ACTIVATION, encoding="utf-8")
            (root / ".github").mkdir()
            (root / ".github/workflow.yml").write_text("name: fixture\n", encoding="utf-8")
            (root / "tests").mkdir()
            (root / "tests/test_fixture.py").write_text("pass\n", encoding="utf-8")
            (root / "._README.md").write_bytes(b"appledouble source metadata")
            (root / ".cache").mkdir()
            (root / ".cache/runtime.bin").write_bytes(b"cache metadata")
            (root / ".env").mkdir()
            (root / ".env/credentials.txt").write_text("local only\n", encoding="utf-8")
            (root / "scratch.tmp").write_bytes(b"temporary metadata")
            plugin_appledouble = root / "plugins/codexqb/._plugin.json"
            plugin_appledouble.write_bytes(b"appledouble plugin metadata")
            plugin_environment = root / "plugins/codexqb/.env/credentials.txt"
            plugin_environment.parent.mkdir()
            plugin_environment.write_text("local only\n", encoding="utf-8")

            plugin_a = base / "plugin-a.zip"
            plugin_b = base / "plugin-b.zip"
            source_a = base / "source-a.zip"
            source_b = base / "source-b.zip"
            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "946684800"}):
                EXPORT_MODULE.create_zip(
                    root,
                    plugin_a,
                    source_package=True,
                    artifact_type="plugin",
                )
                EXPORT_MODULE.create_zip(
                    root,
                    plugin_b,
                    source_package=True,
                    artifact_type="plugin",
                )
                EXPORT_MODULE.create_zip(root, source_a, source_package=True)
                EXPORT_MODULE.create_zip(root, source_b, source_package=True)

            self.assertEqual(file_sha256(plugin_a), file_sha256(plugin_b))
            self.assertEqual(file_sha256(source_a), file_sha256(source_b))
            plugin_names = archive_names(plugin_a)
            self.assertIn(".codex-plugin/plugin.json", plugin_names)
            self.assertIn("skills/codexqb/SKILL.md", plugin_names)
            self.assertIn("PACKAGE-MANIFEST.json", plugin_names)
            self.assertNotIn("README.md", plugin_names)
            self.assertNotIn("._plugin.json", plugin_names)
            self.assertNotIn(".env/credentials.txt", plugin_names)
            self.assertFalse(any(name.startswith(".github/") for name in plugin_names))
            self.assertFalse(any(name.startswith("tests/") for name in plugin_names))
            source_names = archive_names(source_a)
            self.assertIn("CodexQB/README.md", source_names)
            self.assertNotIn("CodexQB/._README.md", source_names)
            self.assertNotIn("CodexQB/.cache/runtime.bin", source_names)
            self.assertNotIn("CodexQB/.env/credentials.txt", source_names)
            self.assertNotIn("CodexQB/scratch.tmp", source_names)
            self.assertNotIn("CodexQB/plugins/codexqb/._plugin.json", source_names)
            self.assertNotIn(
                "CodexQB/plugins/codexqb/.env/credentials.txt",
                source_names,
            )
            self.assertIn(
                "CodexQB/plugins/codexqb/.codex-plugin/plugin.json",
                source_names,
            )
            plugin_manifest = package_manifest(plugin_a, "plugin")
            self.assertEqual(plugin_manifest["artifact_type"], "plugin")
            self.assertEqual(plugin_manifest["plugin_version"], "0.3.0")
            self.assertEqual(
                plugin_manifest["content_sha256"],
                plugin_manifest["tree_sha256"],
            )

    def test_nested_zip_and_polyglot_payloads_are_rejected_without_zip_suffix(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            payloads = {
                "local-header": b"PK\x03\x04payload",
                "zip64": valid_empty_zip64(),
                "shell-polyglot": valid_zip_polyglot(),
            }
            for label, payload in payloads.items():
                with self.subTest(label=label):
                    (root / "disguised.bin").write_bytes(payload)
                    output = base / f"{label}.zip"
                    with self.assertRaisesRegex(
                        ValueError,
                        "package_nested_zip_rejected",
                    ):
                        EXPORT_MODULE.create_zip(
                            root,
                            output,
                            source_package=True,
                        )
                    self.assertFalse(output.exists())

    def test_plugin_artifact_requires_the_invokable_codexqb_skill(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
                json.dumps(
                    {
                        "name": "codexqb",
                        "version": "0.3.0",
                        "skills": "./skills/",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            junk = root / "plugins/codexqb/skills/junk.txt"
            junk.parent.mkdir(parents=True)
            junk.write_text("not invokable\n", encoding="utf-8")
            output = base / "plugin.zip"

            with self.assertRaisesRegex(ValueError, "package_plugin_skills_missing"):
                EXPORT_MODULE.create_zip(
                    root,
                    output,
                    source_package=True,
                    artifact_type="plugin",
                )

            self.assertFalse(output.exists())

    def test_plugin_artifact_omits_additional_skill_and_auto_activation_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
                json.dumps(
                    {
                        "name": "codexqb",
                        "version": "0.3.0",
                        "skills": "./skills/",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            skill = root / "plugins/codexqb/skills/codexqb/SKILL.md"
            skill.parent.mkdir(parents=True)
            skill.write_text(VALID_PLUGIN_SKILL, encoding="utf-8")
            activation = root / "plugins/codexqb/skills/codexqb/agents/openai.yaml"
            activation.parent.mkdir()
            activation.write_text(VALID_PLUGIN_ACTIVATION, encoding="utf-8")
            evil_skill = root / "plugins/codexqb/skills/evil/SKILL.md"
            evil_skill.parent.mkdir(parents=True)
            evil_skill.write_text(VALID_PLUGIN_SKILL, encoding="utf-8")
            hook = root / "plugins/codexqb/hooks/preflight.json"
            hook.parent.mkdir(parents=True)
            hook.write_text("{}\n", encoding="utf-8")
            (root / "plugins/codexqb/.mcp.json").write_text("{}\n", encoding="utf-8")
            output = base / "plugin.zip"

            EXPORT_MODULE.create_zip(
                root,
                output,
                source_package=True,
                artifact_type="plugin",
            )

            names = archive_names(output)
            self.assertIn("skills/codexqb/SKILL.md", names)
            self.assertNotIn("skills/evil/SKILL.md", names)
            self.assertNotIn("hooks/preflight.json", names)
            self.assertNotIn(".mcp.json", names)

    def test_plugin_artifact_rejects_invalid_skill_and_implicit_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
                json.dumps(
                    {
                        "name": "codexqb",
                        "version": "0.3.0",
                        "skills": "./skills/",
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            skill = root / "plugins/codexqb/skills/codexqb/SKILL.md"
            skill.parent.mkdir(parents=True)
            activation = root / "plugins/codexqb/skills/codexqb/agents/openai.yaml"
            activation.parent.mkdir()
            output = base / "plugin.zip"

            skill.write_text("not frontmatter\n", encoding="utf-8")
            activation.write_text(VALID_PLUGIN_ACTIVATION, encoding="utf-8")
            with self.assertRaisesRegex(
                ValueError,
                "package_plugin_skill_frontmatter_invalid",
            ):
                EXPORT_MODULE.create_zip(
                    root,
                    output,
                    source_package=True,
                    artifact_type="plugin",
                )

            skill.write_text(VALID_PLUGIN_SKILL, encoding="utf-8")
            activation.write_text(
                VALID_PLUGIN_ACTIVATION.replace(
                    "allow_implicit_invocation: false",
                    "allow_implicit_invocation: true",
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "package_plugin_implicit_invocation_not_disabled",
            ):
                EXPORT_MODULE.create_zip(
                    root,
                    output,
                    source_package=True,
                    artifact_type="plugin",
                )

            self.assertFalse(output.exists())

    def test_source_date_epoch_must_be_canonical_non_negative_integer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)

            with mock.patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "../secret"}):
                with self.assertRaisesRegex(ValueError, "source_date_epoch_invalid"):
                    EXPORT_MODULE.create_zip(
                        root,
                        base / "source.zip",
                        source_package=True,
                    )

    def test_default_artifact_filenames_are_versioned_and_mode_explicit(self) -> None:
        self.assertEqual(
            EXPORT_MODULE.default_artifact_filename(
                "plugin",
                "0.3.0",
                "strict_release",
            ),
            "codexqb-plugin-0.3.0.zip",
        )
        self.assertEqual(
            EXPORT_MODULE.default_artifact_filename(
                "source",
                "0.3.0",
                "strict_release",
            ),
            "CodexQB-source-0.3.0.zip",
        )
        self.assertEqual(
            EXPORT_MODULE.default_artifact_filename(
                "source",
                "0.3.0",
                "worktree",
            ),
            "CodexQB-source-0.3.0-worktree.zip",
        )

    @unittest.skipIf(os.name == "nt", "POSIX filename semantics required")
    def test_export_rejects_nonportable_manifest_path_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "bad\\name.txt").write_text("not portable\n", encoding="utf-8")
            output = base / "package.zip"

            with self.assertRaisesRegex(ValueError, "package_manifest_preflight_failed"):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertFalse(output.exists())

    @unittest.skipIf(os.name == "nt", "POSIX filename semantics required")
    def test_export_rejects_windows_ambiguous_dot_suffixed_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            ambiguous = root / ".git./config"
            ambiguous.parent.mkdir()
            ambiguous.write_text("not portable\n", encoding="utf-8")
            output = base / "package.zip"

            with self.assertRaisesRegex(ValueError, "package_manifest_preflight_failed"):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertFalse(output.exists())

    def test_export_limits_file_count_and_total_payload_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)

            with mock.patch.object(EXPORT_MODULE, "MAX_MANIFEST_FILES", 2):
                with self.assertRaisesRegex(ValueError, "package_file_count_limit_exceeded"):
                    EXPORT_MODULE.create_zip(root, base / "count.zip", source_package=True)
            with mock.patch.object(EXPORT_MODULE, "MAX_EXPORT_PAYLOAD_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "package_payload_size_limit_exceeded"):
                    EXPORT_MODULE.create_zip(root, base / "bytes.zip", source_package=True)
            with mock.patch.object(EXPORT_MODULE, "MAX_EXPORT_FILE_BYTES", 1):
                with self.assertRaisesRegex(ValueError, "package_file_size_limit_exceeded"):
                    EXPORT_MODULE.create_zip(root, base / "file-bytes.zip", source_package=True)
            with mock.patch.object(EXPORT_MODULE, "SOURCE_WALK_TIMEOUT_SECONDS", 1e-9):
                with self.assertRaisesRegex(ValueError, "package_source_walk_deadline_exceeded"):
                    EXPORT_MODULE.create_zip(root, base / "deadline.zip", source_package=True)

            self.assertFalse((base / "count.zip").exists())
            self.assertFalse((base / "bytes.zip").exists())
            self.assertFalse((base / "file-bytes.zip").exists())
            self.assertFalse((base / "deadline.zip").exists())

    def test_failed_final_package_verification_preserves_existing_output(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            output.write_bytes(b"existing package bytes")

            with mock.patch.object(EXPORT_MODULE, "verify_zip", return_value=["forced_failure"]):
                with self.assertRaisesRegex(ValueError, "package_verification_failed"):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertEqual(output.read_bytes(), b"existing package bytes")
            self.assertEqual(list(base.glob(".package.zip.*.tmp")), [])

    def test_successful_export_replaces_existing_output_without_backup_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            output.write_bytes(b"historical package bytes")

            EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertEqual(EXPORT_MODULE.verify_zip(output), [])
            self.assertEqual(list(base.glob(".package.zip.*.tmp")), [])
            self.assertEqual(list(base.glob(".package.zip.*.backup")), [])

    def test_temp_path_is_mount_revalidated_before_atomic_publish(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            descriptor_names: dict[int, str] = {}
            mount_checked_names: list[str] = []
            real_create_temp = EXPORT_MODULE.create_secure_package_temp
            real_open_output = EXPORT_MODULE.open_output_descriptor_at
            real_require_mount = EXPORT_MODULE.require_package_output_mount

            def record_temp(parent_descriptor, output_name):
                name, descriptor = real_create_temp(parent_descriptor, output_name)
                descriptor_names[descriptor] = name
                return name, descriptor

            def record_open(parent_descriptor, name):
                descriptor = real_open_output(parent_descriptor, name)
                descriptor_names[descriptor] = name
                return descriptor

            def record_mount_check(resolution, descriptor):
                name = descriptor_names.get(descriptor)
                if name is not None:
                    mount_checked_names.append(name)
                return real_require_mount(resolution, descriptor)

            with (
                mock.patch.object(
                    EXPORT_MODULE,
                    "create_secure_package_temp",
                    side_effect=record_temp,
                ),
                mock.patch.object(
                    EXPORT_MODULE,
                    "open_output_descriptor_at",
                    side_effect=record_open,
                ),
                mock.patch.object(
                    EXPORT_MODULE,
                    "require_package_output_mount",
                    side_effect=record_mount_check,
                ),
            ):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            temp_mount_checks = [
                name
                for name in mount_checked_names
                if name.startswith(f".{output.name}.") and name.endswith(".tmp")
            ]
            self.assertGreaterEqual(len(temp_mount_checks), 2)

    def test_backup_path_is_mount_revalidated_before_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            output.write_bytes(b"preexisting package bytes")
            descriptor_names: dict[int, str] = {}
            mount_checked_names: list[str] = []
            real_open_output = EXPORT_MODULE.open_output_descriptor_at
            real_require_mount = EXPORT_MODULE.require_package_output_mount

            def record_open(parent_descriptor, name):
                descriptor = real_open_output(parent_descriptor, name)
                descriptor_names[descriptor] = name
                return descriptor

            def record_mount_check(resolution, descriptor):
                name = descriptor_names.get(descriptor)
                if name is not None:
                    mount_checked_names.append(name)
                return real_require_mount(resolution, descriptor)

            with (
                mock.patch.object(
                    EXPORT_MODULE,
                    "open_output_descriptor_at",
                    side_effect=record_open,
                ),
                mock.patch.object(
                    EXPORT_MODULE,
                    "require_package_output_mount",
                    side_effect=record_mount_check,
                ),
            ):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            backup_mount_checks = [
                name
                for name in mount_checked_names
                if name.startswith(f".{output.name}.") and name.endswith(".backup")
            ]
            self.assertGreaterEqual(len(backup_mount_checks), 2)

    def test_backup_cleanup_ebusy_has_stable_error_and_preserves_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            original = b"preexisting package bytes"
            output.write_bytes(original)
            real_unlink = EXPORT_MODULE.os.unlink

            def reject_backup_unlink(path, *args, **kwargs):
                if isinstance(path, str) and path.endswith(".backup"):
                    raise OSError(errno.EBUSY, "simulated backup mountpoint")
                return real_unlink(path, *args, **kwargs)

            with mock.patch.object(
                EXPORT_MODULE.os,
                "unlink",
                side_effect=reject_backup_unlink,
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "^package_backup_cleanup_state_unknown$",
                ):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertEqual(EXPORT_MODULE.verify_zip(output), [])
            backups = list(base.glob(f".{output.name}.*.backup"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)

    def test_temp_cleanup_ebusy_preserves_primary_error_with_stable_cause(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            original = b"preexisting package bytes"
            output.write_bytes(original)
            real_unlink = EXPORT_MODULE.os.unlink

            def reject_temp_unlink(path, *args, **kwargs):
                if isinstance(path, str) and path.endswith(".tmp"):
                    raise OSError(errno.EBUSY, "simulated temp mountpoint")
                return real_unlink(path, *args, **kwargs)

            with (
                mock.patch.object(
                    EXPORT_MODULE,
                    "verify_zip",
                    return_value=["forced_failure"],
                ),
                mock.patch.object(
                    EXPORT_MODULE.os,
                    "unlink",
                    side_effect=reject_temp_unlink,
                ),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "^package_verification_failed=forced_failure$",
                ) as caught:
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            cleanup_error = caught.exception.__cause__
            self.assertIsInstance(cleanup_error, RuntimeError)
            self.assertEqual(str(cleanup_error), "package_temp_cleanup_state_unknown")
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(list(base.glob(f".{output.name}.*.backup")), [])

    def test_cli_failure_does_not_echo_secret_paths_or_tracebacks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            project_prefix = "proj-"
            secret_marker = "sk-" + project_prefix + "DO_NOT_ECHO_1234567890"
            output = base / f"missing-{secret_marker}-\x1b[31m" / "package.zip"

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--root",
                    str(root),
                    "--output",
                    str(output),
                    "--provenance-mode",
                    "filesystem",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            combined = result.stdout + result.stderr
            self.assertEqual(result.returncode, 1)
            self.assertIn("sanitized_export=failed", result.stdout)
            self.assertIn("error_code=output_parent_unavailable", result.stdout)
            self.assertNotIn(secret_marker, combined)
            self.assertNotIn(str(root), combined)
            self.assertNotIn("Traceback", combined)
            self.assertNotIn("\x1b", combined)

    def test_temp_name_swap_fails_and_rolls_back_output(self) -> None:
        for existing_bytes in (None, b"preexisting package bytes"):
            with self.subTest(existing=existing_bytes is not None), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                write_minimal_codexqb_tree(root)
                output = base / "package.zip"
                if existing_bytes is not None:
                    output.write_bytes(existing_bytes)
                real_replace = EXPORT_MODULE.os.replace
                poison = b"attacker-controlled replacement"
                replace_calls = 0

                def swap_temp_before_replace(
                    source,
                    destination,
                    *,
                    src_dir_fd=None,
                    dst_dir_fd=None,
                ):
                    nonlocal replace_calls
                    replace_calls += 1
                    if replace_calls > 1:
                        return real_replace(
                            source,
                            destination,
                            src_dir_fd=src_dir_fd,
                            dst_dir_fd=dst_dir_fd,
                        )
                    os.unlink(source, dir_fd=src_dir_fd)
                    descriptor = os.open(
                        source,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=src_dir_fd,
                    )
                    try:
                        os.write(descriptor, poison)
                    finally:
                        os.close(descriptor)
                    return real_replace(
                        source,
                        destination,
                        src_dir_fd=src_dir_fd,
                        dst_dir_fd=dst_dir_fd,
                    )

                with mock.patch.object(
                    EXPORT_MODULE.os,
                    "replace",
                    side_effect=swap_temp_before_replace,
                ):
                    with self.assertRaisesRegex(ValueError, "package_publish_identity_mismatch"):
                        EXPORT_MODULE.create_zip(root, output, source_package=True)

                if existing_bytes is None:
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(output.read_bytes(), existing_bytes)
                self.assertEqual(list(base.glob(".package.zip.*.tmp")), [])
                self.assertEqual(list(base.glob(".package.zip.*.backup")), [])

    def test_failed_output_restore_preserves_recovery_backup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            original = b"recoverable original package"
            poison = b"poisoned publication"
            output.write_bytes(original)
            real_replace = EXPORT_MODULE.os.replace
            replace_calls = 0

            def poison_then_fail_restore(
                source,
                destination,
                *,
                src_dir_fd=None,
                dst_dir_fd=None,
            ):
                nonlocal replace_calls
                replace_calls += 1
                if replace_calls == 1:
                    os.unlink(source, dir_fd=src_dir_fd)
                    descriptor = os.open(
                        source,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                        0o600,
                        dir_fd=src_dir_fd,
                    )
                    try:
                        os.write(descriptor, poison)
                    finally:
                        os.close(descriptor)
                    return real_replace(
                        source,
                        destination,
                        src_dir_fd=src_dir_fd,
                        dst_dir_fd=dst_dir_fd,
                    )
                raise OSError("forced restore failure")

            with mock.patch.object(
                EXPORT_MODULE.os,
                "replace",
                side_effect=poison_then_fail_restore,
            ):
                with self.assertRaisesRegex(RuntimeError, "package_publish_rollback_failed"):
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

            backups = list(base.glob(".package.zip.*.backup"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(backups[0].read_bytes(), original)
            self.assertEqual(output.read_bytes(), poison)

    def test_strict_export_rechecks_mutable_git_evidence_after_temp_verification(self) -> None:
        for mutation, expected_error in (
            ("tag", "git_release_tag_changed_during_export"),
            ("head", "git_head_changed_during_export"),
            ("index", "git_index_changed_during_export"),
        ):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                git(root, "init")
                write_minimal_codexqb_tree(root)
                write_released_changelog(root)
                git_commit_all(root)
                tag_release(root)
                output = base / "package.zip"
                real_verify = EXPORT_MODULE.verify_zip
                verify_calls = 0

                def verify_then_mutate(package):
                    nonlocal verify_calls
                    errors = real_verify(package)
                    verify_calls += 1
                    if verify_calls == 1:
                        if mutation == "tag":
                            git(root, "tag", "-d", "v0.3.0")
                        elif mutation == "head":
                            subprocess.run(
                                [
                                    "git",
                                    "-c",
                                    "user.name=CodexQB Export Test",
                                    "-c",
                                    "user.email=codexqb-export@example.invalid",
                                    "commit",
                                    "--allow-empty",
                                    "-m",
                                    "late head mutation",
                                ],
                                cwd=root,
                                check=True,
                                text=True,
                                capture_output=True,
                            )
                        else:
                            readme = root / "README.md"
                            original = readme.read_bytes()
                            readme.write_text("# Late index mutation\n", encoding="utf-8")
                            git(root, "add", "README.md")
                            readme.write_bytes(original)
                    return errors

                with mock.patch.object(
                    EXPORT_MODULE,
                    "verify_zip",
                    side_effect=verify_then_mutate,
                ):
                    with self.assertRaisesRegex(ValueError, expected_error):
                        EXPORT_MODULE.create_zip(root, output)

                self.assertFalse(output.exists())

    def test_manifest_release_metadata_comes_from_scanned_payloads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            real_manifest_builder = EXPORT_MODULE.package_manifest

            def mutate_sources_then_build(*args, **kwargs):
                (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
                    json.dumps({"version": "9.9.9"}) + "\n",
                    encoding="utf-8",
                )
                write_released_changelog(root, "9.9.9")
                return real_manifest_builder(*args, **kwargs)

            with mock.patch.object(
                EXPORT_MODULE,
                "package_manifest",
                side_effect=mutate_sources_then_build,
            ):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            manifest = package_manifest(output)
            self.assertEqual(manifest["plugin_version"], "0.3.0")
            self.assertEqual(manifest["changelog_release_state"], "unreleased")
            self.assertTrue(all(item["mode"] in {"0644", "0755"} for item in manifest["files"]))
            with zipfile.ZipFile(output) as archive:
                packaged_plugin = json.loads(
                    archive.read("CodexQB/plugins/codexqb/.codex-plugin/plugin.json")
                )
            self.assertEqual(packaged_plugin["version"], "0.3.0")

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink support required")
    def test_output_symlink_cannot_overwrite_external_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside = Path(outside_dir) / "outside.txt"
            outside.write_bytes(b"must remain unchanged")
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            (root / ".gitignore").write_text("out.zip\n", encoding="utf-8")
            git_commit_all(root)
            tag_release(root)
            output = root / "out.zip"
            output.symlink_to(outside)

            with self.assertRaisesRegex(ValueError, "output_target_symlink_rejected"):
                EXPORT_MODULE.create_zip(root, output)

            self.assertTrue(output.is_symlink())
            self.assertEqual(outside.read_bytes(), b"must remain unchanged")

    def test_output_directory_is_rejected_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            output.mkdir()

            with self.assertRaisesRegex(ValueError, "output_target_non_regular_rejected"):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(output.is_dir())

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_output_fifo_is_rejected_without_opening_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            output = base / "package.zip"
            os.mkfifo(output)

            with self.assertRaisesRegex(ValueError, "output_target_non_regular_rejected"):
                EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(stat.S_ISFIFO(os.lstat(output).st_mode))

    def test_export_uses_portable_manifest_order_and_preserves_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            write_minimal_codexqb_tree(root)
            (root / "apply").mkdir()
            (root / "apply/controller.md").write_text("controller\n", encoding="utf-8")
            (root / "apply-orchestrator.md").write_text("orchestrator\n", encoding="utf-8")
            executable = root / "run.sh"
            executable.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
            output = root / "CodexQB-source-package.zip"

            EXPORT_MODULE.create_zip(root, output, source_package=True)

            manifest = package_manifest(output)
            paths = [item["path"] for item in manifest["files"]]
            self.assertEqual(paths, sorted(paths))
            with zipfile.ZipFile(output) as archive:
                script_mode = archive.getinfo("CodexQB/run.sh").external_attr >> 16
                readme_mode = archive.getinfo("CodexQB/README.md").external_attr >> 16
                manifest_mode = archive.getinfo("CodexQB/PACKAGE-MANIFEST.json").external_attr >> 16
            self.assertTrue(stat.S_ISREG(script_mode))
            self.assertEqual(stat.S_IMODE(script_mode), 0o755)
            self.assertEqual(stat.S_IMODE(readme_mode), 0o644)
            self.assertEqual(stat.S_IMODE(manifest_mode), 0o644)

    def test_strict_export_rejects_unreleased_changelog_heading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            tag_release(root)

            with self.assertRaisesRegex(ValueError, "changelog_version_unreleased=0.3.0"):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_strict_export_rejects_invalid_calendar_date_in_release_heading(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            (root / "CHANGELOG.md").write_text(
                "# Changelog\n\n## 0.3.0 - 2026-99-99\n\n- Invalid date.\n",
                encoding="utf-8",
            )
            git_commit_all(root)
            tag_release(root)

            with self.assertRaisesRegex(ValueError, "changelog_version_unreleased=0.3.0"):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_strict_export_rejects_missing_release_tag(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root)

            with self.assertRaisesRegex(ValueError, "release_tag_missing=v0.3.0"):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_strict_export_rejects_release_tag_not_at_head(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            git_commit_all(root, "release")
            tag_release(root)
            (root / "README.md").write_text("# Fixture\n\nPost-tag change.\n", encoding="utf-8")
            git_commit_all(root, "post-tag")

            with self.assertRaisesRegex(ValueError, "release_tag_head_mismatch=v0.3.0"):
                EXPORT_MODULE.create_zip(root, root / "CodexQB-sanitized.zip")

    def test_include_untracked_scans_secret_content(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            (root / "notes.txt").write_text("leaked sk-" + "A" * 40 + "\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "^secret_like_content$"):
                EXPORT_MODULE.create_zip(
                    root,
                    root / "CodexQB-sanitized.zip",
                    include_untracked=True,
                    allow_dirty=True,
                    allow_head_mismatch=True,
                )

    def test_export_rejects_invalid_utf8_text_and_binary_secret_without_replacing_output(self) -> None:
        utf32_fixture = "sk-" + "U" * 40
        non_ascii_assignment = "password=" + "密碼值" * 16
        fixtures = (
            ("invalid.py", b"print('safe')\n\xff"),
            ("payload.bin", b"\xff" + ("sk-" + "B" * 40).encode("ascii")),
            ("payload-utf32.bin", utf32_fixture.encode("utf-32-le")),
            ("payload-utf8", non_ascii_assignment.encode("utf-8")),
            ("payload-utf16", non_ascii_assignment.encode("utf-16-be")),
            ("payload-opaque", b"password=" + b"\xff" * 40),
            (
                "opaque-wide-block",
                b"\x81" * 61
                + b"\xff\xfe"
                + (
                    "name: password\nvalue: this-is-a-real-long-password-value\n"
                ).encode("utf-16-le"),
            ),
        )
        for name, data in fixtures:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                write_minimal_codexqb_tree(root)
                (root / name).write_bytes(data)
                output = root.parent / f"{name}.zip"
                original = b"existing-output"
                output.write_bytes(original)

                with self.assertRaisesRegex(ValueError, "^secret_like_content$") as caught:
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertEqual(output.read_bytes(), original)
                self.assertNotIn(utf32_fixture, str(caught.exception))
                self.assertNotIn(non_ascii_assignment, str(caught.exception))

    def test_source_export_rejects_semantic_credential_assignments_without_disclosure(self) -> None:
        fixture = "this-is-a-real-long-password-value"
        joined_fixture = "sk-" + "J" * 40
        neutral_join_tail = "N" * 40
        neutral_join_fixture = "sk-" + neutral_join_tail
        assignment = "PASSWORD=" + fixture
        variants = (
            ("settings.py", "PASSWORD = " + repr(fixture) + "\n"),
            ("settings-bytes.py", "PASSWORD = " + repr(fixture.encode("utf-8")) + "\n"),
            (
                "settings-bytes-concat.py",
                "PASSWORD = "
                + repr("this-is-a-real-".encode("utf-8"))
                + " + "
                + repr("long-password-value".encode("utf-8"))
                + "\n",
            ),
            ("settings.json", json.dumps({"password": fixture}) + "\n"),
            ("default.py", "def f(password=" + repr(fixture) + "):\n    pass\n"),
            ("comment.py", "# " + assignment + "\n"),
            (
                "docstring.py",
                "def fixture():\n    \"\"\"" + assignment + "\"\"\"\n",
            ),
            ("comment.sh", "# " + assignment + "\n"),
            ("note.json", json.dumps({"note": assignment}) + "\n"),
            (
                "constant-join.py",
                "API_KEY = ''.join(("
                + repr("sk-")
                + ", "
                + repr("J" * 40)
                + "))\n",
            ),
            (
                "neutral-join.py",
                "message = ''.join(("
                + repr("sk-")
                + ", "
                + repr(neutral_join_tail)
                + "))\n",
            ),
            (
                "argument-join.py",
                "print(''.join(("
                + repr("sk-")
                + ", "
                + repr(neutral_join_tail)
                + ")))\n",
            ),
            (
                "neutral-bytes-join.py",
                "message = b''.join(("
                + repr(b"sk-")
                + ", "
                + repr(neutral_join_tail.encode())
                + "))\n",
            ),
            (
                "argument-bytes-join.py",
                "print(b''.join(("
                + repr(b"sk-")
                + ", "
                + repr(neutral_join_tail.encode())
                + ")))\n",
            ),
            (
                "credential-pair.md",
                "release failure: password, '" + fixture + "'\n",
            ),
            (
                "credential-table.md",
                "| Field | Value |\n| --- | --- |\n| password | " + fixture + " |\n",
            ),
            (
                "credential-failure.txt",
                "failure=('password', {'value': '" + fixture + "'})\n",
            ),
            (
                "credential-record.yaml",
                "- name: AWS_SECRET_ACCESS_KEY\n  value: " + fixture + "\n",
            ),
            ("opaque-pair", "failure=('password','" + fixture + "')\n"),
            (
                "opaque-record",
                json.dumps({"name": "password", "value": fixture}) + "\n",
            ),
            ("opaque-block", "name: password\nvalue: " + fixture + "\n"),
            ("opaque-table", "| password | " + fixture + " |\n"),
            (
                "credential-concat.txt",
                "failure=('password', '" + fixture + "' + '')\n",
            ),
            (
                "credential-concat-terminator",
                "failure=('password', ('$PASSWORD' + '') and '"
                + fixture
                + "')\n",
            ),
            (
                "credential-fstring.txt",
                "failure=('password', f'" + fixture + "' + '')\n",
            ),
            (
                "credential-concat-boundary.txt",
                "failure=('password', '$PASSWORD'"
                + (" " * 4084)
                + "+ '"
                + fixture
                + "')\n",
            ),
            (
                "credential-rendered.md",
                "| Field | Value |\n| --- | --- |\n| pass&#119;ord | "
                + fixture
                + " |\n",
            ),
            ("credential-rendered-direct.md", "**password**=" + fixture + "\n"),
            ("credential-rendered.rst", "``password``=" + fixture + "\n"),
            ("credential-rendered.html", "<b>password</b>=" + fixture + "\n"),
            ("credential-rendered.xml", "<label>password</label>=" + fixture + "\n"),
            ("credential-rendered.txt", "pass&#119;ord=" + fixture + "\n"),
            (
                "credential-structural.html",
                "<table><tr><td>password</td><td>"
                + fixture
                + "</td></tr></table>\n",
            ),
            (
                "credential-structural.xml",
                "<record><name>password</name><value>"
                + fixture
                + "</value></record>\n",
            ),
        )
        for name, text in variants:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                write_minimal_codexqb_tree(root)
                (root / name).write_text(text, encoding="utf-8")
                output = base / "package.zip"

                with self.assertRaisesRegex(ValueError, "^secret_like_content$") as caught:
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertNotIn(fixture, str(caught.exception))
                self.assertNotIn(joined_fixture, str(caught.exception))
                self.assertNotIn(neutral_join_fixture, str(caught.exception))
                self.assertFalse(output.exists())

    def test_source_export_rejects_secret_file_and_directory_names_before_manifest(self) -> None:
        fixture = "sk-" + "P" * 40
        variants = (f"{fixture}.txt", f"safe/{fixture}/payload.txt")
        for relative in variants:
            with self.subTest(path_hash=hashlib.sha256(relative.encode()).hexdigest()), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                write_minimal_codexqb_tree(root)
                payload = root / relative
                payload.parent.mkdir(parents=True, exist_ok=True)
                payload.write_text("safe file body\n", encoding="utf-8")
                output = base / "package.zip"

                with self.assertRaisesRegex(ValueError, "^secret_like_path$") as caught:
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertNotIn(fixture, str(caught.exception))
                self.assertFalse(output.exists())

    def test_source_export_accepts_bytes_credential_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            (root / "settings.py").write_text(
                "PASSWORD = " + repr(b"${PASSWORD}") + "\n",
                encoding="utf-8",
            )
            (root / "credential-placeholder.txt").write_text(
                "failure=('password', '${' + 'PASSWORD}')\n",
                encoding="utf-8",
            )
            output = base / "package.zip"

            EXPORT_MODULE.create_zip(root, output, source_package=True)

            self.assertTrue(output.is_file())

    def test_source_export_rejects_secret_shaped_git_branch_before_temp_write(self) -> None:
        generic_value = "branch-credential-value"
        variants = (
            ("provider", "sk-" + "B" * 40),
            ("generic", "PASSWORD=" + generic_value),
        )
        for label, fixture in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                root = base / "source"
                root.mkdir()
                git(root, "init")
                write_minimal_codexqb_tree(root)
                git_commit_all(root)
                git(root, "checkout", "-q", "-b", fixture)
                output = base / "package.zip"

                with self.assertRaisesRegex(ValueError, "^secret_like_manifest$") as caught:
                    EXPORT_MODULE.create_zip(root, output, source_package=True)

                self.assertNotIn(fixture, str(caught.exception))
                self.assertFalse(output.exists())

    def test_cli_secret_content_failure_never_discloses_secret_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "source"
            root.mkdir()
            write_minimal_codexqb_tree(root)
            fixture = "sk-" + "R" * 40
            (root / f"{fixture}.txt").write_text(fixture + "\n", encoding="utf-8")

            result = subprocess.run(
                [
                    sys.executable,
                    str(EXPORTER),
                    "--root",
                    str(root),
                    "--output",
                    str(base / "package.zip"),
                    "--provenance-mode",
                    "filesystem",
                ],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )

            combined = result.stdout + result.stderr
            self.assertEqual(result.returncode, 1)
            self.assertIn("error_code=secret_like_path", result.stdout)
            self.assertNotIn(fixture, combined)
            self.assertNotIn("Traceback", combined)
    def test_package_export_scans_binary_secret_across_eight_mib_window(self) -> None:
        """The byte-safe overlap catches a token split at the 8 MiB boundary."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            secret = b"sk-" + b"proj-" + b"C" * 40
            boundary = 8 * 1024 * 1024
            # Start the token four bytes before the core boundary and keep a
            # non-word byte on either side so the credential boundary itself,
            # not an unrelated regex boundary, is what the overlap exercises.
            payload = b"\xff" * (boundary - 4) + secret + b"\x80"
            (root / "payload").write_bytes(payload)

            with self.assertRaisesRegex(
                ValueError,
                "^secret_like_content$",
            ) as raised:
                EXPORT_MODULE.create_zip(
                    root,
                    root / "CodexQB-sanitized.zip",
                    include_untracked=True,
                    allow_dirty=True,
                    allow_head_mismatch=True,
                )
            self.assertNotIn(secret.decode("ascii"), str(raised.exception))

    def test_tracked_suffixless_structural_record_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            secret = "V" * 40
            (root / "Dispatch-Packet").write_text(
                json.dumps({"name": "password", "value": secret}) + "\n",
                encoding="utf-8",
            )
            git_commit_all(root)
            output = root / "CodexQB-sanitized.zip"

            with self.assertRaisesRegex(
                ValueError,
                "^secret_like_content$",
            ) as caught:
                EXPORT_MODULE.create_zip(
                    root,
                    output,
                    allow_dirty=True,
                    allow_head_mismatch=True,
                )

            self.assertNotIn(secret, str(caught.exception))
            self.assertFalse(output.exists())

    def test_worktree_export_can_include_scanned_untracked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            (root / "notes.txt").write_text("local draft without secrets\n", encoding="utf-8")
            output = root / "CodexQB-sanitized.zip"

            count = EXPORT_MODULE.create_zip(
                root,
                output,
                include_untracked=True,
                allow_dirty=True,
                allow_head_mismatch=True,
            )

            self.assertEqual(count, 4)
            self.assertIn("CodexQB/notes.txt", archive_names(output))
            manifest = package_manifest(output)
            self.assertEqual(manifest["export_mode"], "worktree")
            self.assertEqual(manifest["git_provenance_available"], True)
            self.assertEqual(manifest["tracked_only"], False)
            self.assertEqual(manifest["include_untracked"], True)
            self.assertEqual(manifest["working_tree_clean"], False)

    def test_worktree_export_fails_if_untracked_inventory_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            git_commit_all(root)
            real_run_git_paths = EXPORT_MODULE.run_git_paths
            matching_calls = 0

            def fail_untracked(candidate_root, args):
                nonlocal matching_calls
                if args == ["ls-files", "-z", "--others", "--exclude-standard"]:
                    matching_calls += 1
                    if matching_calls == 2:
                        return None
                return real_run_git_paths(candidate_root, args)

            with mock.patch.object(EXPORT_MODULE, "run_git_paths", side_effect=fail_untracked):
                with self.assertRaisesRegex(
                    ValueError,
                    "^git_untracked_file_inventory_unavailable$",
                ):
                    EXPORT_MODULE.create_zip(
                        root,
                        root / "CodexQB-sanitized.zip",
                        include_untracked=True,
                        allow_dirty=True,
                        allow_head_mismatch=True,
                    )

    def test_nul_delimited_inventory_preserves_newlines_before_portable_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init")
            write_minimal_codexqb_tree(root)
            tracked_name = "tracked-line\nbreak.txt"
            untracked_name = "untracked-line\nbreak.txt"
            (root / tracked_name).write_text("tracked safe content\n", encoding="utf-8")
            git_commit_all(root)
            (root / untracked_name).write_text("untracked safe content\n", encoding="utf-8")
            output = root / "CodexQB-worktree.zip"

            index_inventory, index_errors = EXPORT_MODULE.git_index_inventory(root)
            self.assertEqual(index_errors, [])
            self.assertIn(tracked_name, index_inventory)
            self.assertIn(
                untracked_name,
                EXPORT_MODULE.run_git_paths(
                    root,
                    ["ls-files", "-z", "--others", "--exclude-standard"],
                ),
            )
            with self.assertRaisesRegex(ValueError, "package_manifest_preflight_failed"):
                EXPORT_MODULE.create_zip(
                    root,
                    output,
                    include_untracked=True,
                    allow_dirty=True,
                    allow_head_mismatch=True,
                )
            self.assertFalse(output.exists())

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink support required")
    def test_export_rejects_symlink_candidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside = Path(outside_dir) / "outside.txt"
            outside.write_text("outside secret\n", encoding="utf-8")
            git(root, "init")
            write_minimal_codexqb_tree(root)
            write_released_changelog(root)
            (root / "external-link.txt").symlink_to(outside)
            git_commit_all(root)
            tag_release(root)

            with self.assertRaisesRegex(ValueError, "symlink_rejected=external-link.txt"):
                EXPORT_MODULE.create_zip(
                    root,
                    root / "CodexQB-sanitized.zip",
                    allow_dirty=True,
                    allow_head_mismatch=True,
                )


if __name__ == "__main__":
    unittest.main()
