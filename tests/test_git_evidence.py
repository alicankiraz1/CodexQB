from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_DIR = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts"
GIT_EVIDENCE_PATH = SCRIPTS_DIR / "git_evidence.py"


def load_git_evidence_module():
    sys.path.insert(0, str(SCRIPTS_DIR))
    try:
        spec = importlib.util.spec_from_file_location("codexqb_git_evidence", GIT_EVIDENCE_PATH)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"could not load git_evidence from {GIT_EVIDENCE_PATH}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(SCRIPTS_DIR))


GIT_EVIDENCE = load_git_evidence_module()
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()


class GitEvidenceTests(unittest.TestCase):
    def test_metadata_tree_enumeration_stops_at_budget_before_materializing_all_names(self) -> None:
        class SyntheticScandir:
            def __init__(self, counter: list[int]) -> None:
                self.counter = counter

            def __enter__(self):
                def entries():
                    for index in range(250_000):
                        self.counter[0] += 1
                        yield SimpleNamespace(name=f"entry-{index}")

                return entries()

            def __exit__(self, *_args):
                return False

        with tempfile.TemporaryDirectory() as source_dir, tempfile.TemporaryDirectory() as target_dir:
            source_fd = os.open(source_dir, os.O_RDONLY | os.O_DIRECTORY)
            target_fd = os.open(target_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                for operation, expected in (
                    (
                        lambda: GIT_EVIDENCE._snapshot_refs_tree(mock.Mock(), source_fd),
                        "git_evidence_refs_limit_exceeded",
                    ),
                    (
                        lambda: GIT_EVIDENCE._copy_objects_tree(
                            mock.Mock(),
                            source_fd,
                            target_fd,
                        ),
                        "git_evidence_objects_path_limit",
                    ),
                ):
                    counter = [0]
                    with self.subTest(expected=expected), mock.patch.object(
                        GIT_EVIDENCE,
                        "MAX_GIT_METADATA_TREE_PATHS",
                        8,
                    ), mock.patch.object(
                        GIT_EVIDENCE.os,
                        "scandir",
                        side_effect=lambda _fd: SyntheticScandir(counter),
                    ):
                        with self.assertRaisesRegex(ValueError, expected):
                            operation()
                    self.assertEqual(counter[0], 9)
            finally:
                os.close(target_fd)
                os.close(source_fd)

    def test_exclusion_iterable_is_bounded_before_full_materialization(self) -> None:
        counter = [0]

        def paths():
            for index in range(250_000):
                counter[0] += 1
                yield f"path-{index}"

        with mock.patch.object(GIT_EVIDENCE, "MAX_GIT_EXCLUSION_PATHS", 8):
            with self.assertRaisesRegex(
                ValueError,
                "git_evidence_exclusion_limit_exceeded",
            ):
                GIT_EVIDENCE._normalize_exclusions(paths())
        self.assertEqual(counter[0], 9)

    def git(self, root: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return subprocess.run(
            ["git", *arguments],
            cwd=root,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def init_repo(self, root: Path, *, attributes: bool = False) -> Path:
        self.git(root, "init", "-q")
        tracked = root / "tracked.txt"
        tracked.write_text("before\n", encoding="utf-8")
        if attributes:
            (root / ".gitattributes").write_text(
                "*.txt diff=probe filter=probe\n",
                encoding="utf-8",
            )
        self.git(root, "add", ".")
        self.git(
            root,
            "-c",
            "user.name=CodexQB Test",
            "-c",
            "user.email=codexqb-test@example.invalid",
            "commit",
            "-qm",
            "fixture",
        )
        return tracked

    def marker_program(self, root: Path, name: str) -> tuple[Path, Path]:
        marker = root / f"{name}.ran"
        program = root / f"{name}.sh"
        program.write_text(f"#!/bin/sh\ntouch '{marker.as_posix()}'\nexit 0\n", encoding="utf-8")
        program.chmod(0o755)
        return program, marker

    def init_linked_worktree(self, base: Path) -> tuple[Path, Path, Path]:
        main = base / "main"
        main.mkdir()
        self.init_repo(main)
        worktree = base / "linked"
        self.git(
            main,
            "worktree",
            "add",
            "-q",
            "-b",
            "linked-test",
            worktree.as_posix(),
            "HEAD",
        )
        marker_text = (worktree / ".git").read_text(encoding="utf-8")
        self.assertTrue(marker_text.startswith("gitdir: "))
        git_dir = Path(marker_text.removeprefix("gitdir: ").strip())
        return main, worktree, git_dir

    def test_clean_staged_unstaged_and_untracked_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            tracked = self.init_repo(root)

            clean = GIT_EVIDENCE.capture_git_workspace_evidence(root)
            self.assertTrue(clean["is_git"])
            self.assertEqual(clean["tracked_paths"], ["tracked.txt"])
            self.assertEqual(clean["staged_diff_sha256"], EMPTY_SHA256)
            self.assertEqual(clean["unstaged_diff_sha256"], EMPTY_SHA256)
            self.assertEqual(clean["untracked_paths_sha256"], EMPTY_SHA256)
            self.assertEqual(clean["untracked_entries_sha256"], EMPTY_SHA256)
            self.assertEqual(clean["status_sha256"], EMPTY_SHA256)

            tracked.write_text("staged\n", encoding="utf-8")
            self.git(root, "add", "tracked.txt")
            staged = GIT_EVIDENCE.capture_git_workspace_evidence(root)
            self.assertEqual([item["path"] for item in staged["staged_changes"]], ["tracked.txt"])
            self.assertNotEqual(staged["staged_diff_sha256"], EMPTY_SHA256)
            self.assertEqual(staged["unstaged_diff_sha256"], EMPTY_SHA256)

            tracked.write_text("unstaged\n", encoding="utf-8")
            (root / "new file.txt").write_text("untracked\n", encoding="utf-8")
            dirty = GIT_EVIDENCE.capture_git_workspace_evidence(root)
            self.assertEqual([item["path"] for item in dirty["unstaged_changes"]], ["tracked.txt"])
            self.assertEqual(dirty["untracked_paths"], ["new file.txt"])
            self.assertEqual([item["path"] for item in dirty["untracked_entries"]], ["new file.txt"])
            self.assertNotEqual(dirty["unstaged_diff_sha256"], EMPTY_SHA256)
            self.assertNotEqual(dirty["untracked_paths_sha256"], EMPTY_SHA256)
            self.assertNotEqual(dirty["untracked_entries_sha256"], EMPTY_SHA256)
            self.assertNotEqual(dirty["status_sha256"], EMPTY_SHA256)

    def test_gitless_nested_directory_does_not_inherit_parent_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            self.init_repo(parent)
            nested = parent / "copied-source"
            nested.mkdir()
            (nested / "README.md").write_text("copied source\n", encoding="utf-8")

            evidence = GIT_EVIDENCE.capture_git_workspace_evidence(nested)

            self.assertFalse(evidence["is_git"])
            self.assertEqual(evidence["tracked_paths"], [])

    def test_linked_worktree_gitdir_chain_is_nofollow_and_backlink_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _main, worktree, git_dir = self.init_linked_worktree(base)
            alias = base / "gitdir-alias"
            alias.symlink_to(git_dir, target_is_directory=True)
            (worktree / ".git").write_text(
                f"gitdir: {alias.as_posix()}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "git_evidence_metadata_path_invalid",
            ):
                GIT_EVIDENCE.capture_git_workspace_evidence(worktree)

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _main, worktree, git_dir = self.init_linked_worktree(base)
            (git_dir / "gitdir").write_text(
                f"{(base / 'forged' / '.git').as_posix()}\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "git_evidence_worktree_backlink_invalid",
            ):
                GIT_EVIDENCE.capture_git_workspace_evidence(worktree)

    def test_linked_worktree_gitdir_cross_mount_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _main, worktree, git_dir = self.init_linked_worktree(base)
            git_dir_identity = (git_dir.stat().st_dev, git_dir.stat().st_ino)
            original = GIT_EVIDENCE.require_same_repository_mount

            def reject_git_dir(anchor, descriptor, relative_path):
                metadata = os.fstat(descriptor)
                if (metadata.st_dev, metadata.st_ino) == git_dir_identity:
                    raise ValueError("synthetic_cross_mount")
                return original(anchor, descriptor, relative_path)

            with mock.patch.object(
                GIT_EVIDENCE,
                "require_same_repository_mount",
                side_effect=reject_git_dir,
            ), self.assertRaisesRegex(
                ValueError,
                "git_evidence_metadata_untrusted",
            ):
                GIT_EVIDENCE.capture_git_workspace_evidence(worktree)

    def test_repository_config_include_and_object_alternates_are_rejected_pre_git(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            external = root / "external-config"
            external.write_text("[core]\n\texcludesFile = /outside\n", encoding="utf-8")
            with (root / ".git/config").open("a", encoding="utf-8") as stream:
                stream.write(f"[include]\n\tpath = {external.as_posix()}\n")
            with mock.patch.object(GIT_EVIDENCE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_unsafe_repository_config",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(root)
            popen.assert_not_called()

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            alternates = root / ".git/objects/info/alternates"
            alternates.write_text("/outside/objects\n", encoding="utf-8")
            with mock.patch.object(GIT_EVIDENCE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_forbidden_metadata_present",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(root)
            popen.assert_not_called()

    def test_git_subprocess_reads_private_snapshot_and_detects_gitdir_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _main, worktree, git_dir = self.init_linked_worktree(base)
            detached = base / "detached-gitdir"
            real_popen = subprocess.Popen
            invocation: dict[str, object] = {}

            def swap_restore_before_child(*args, **kwargs):
                if not invocation:
                    invocation.update(kwargs)
                    git_dir.rename(detached)
                    detached.rename(git_dir)
                return real_popen(*args, **kwargs)

            with mock.patch.object(
                GIT_EVIDENCE.subprocess,
                "Popen",
                side_effect=swap_restore_before_child,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_metadata_path_changed|git_evidence_metadata_changed",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(worktree)

            environment = invocation["env"]
            self.assertIsInstance(environment, dict)
            runtime_git_dir = str(environment["GIT_DIR"])
            self.assertNotEqual(runtime_git_dir, git_dir.as_posix())
            self.assertTrue(str(environment["GIT_OBJECT_DIRECTORY"]).startswith(runtime_git_dir))

    @unittest.skipUnless(
        sys.platform == "darwin" or sys.platform.startswith("linux"),
        "Darwin/Linux Git metadata ACL probe",
    )
    def test_git_metadata_extended_acl_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            marker = root / ".git"
            if sys.platform == "darwin":
                tool = shutil.which("chmod", path=os.defpath)
                command = [
                    tool or "",
                    "+a",
                    "everyone allow read,write,append,delete,list,search",
                    marker.as_posix(),
                ]
                cleanup = [tool or "", "-N", marker.as_posix()]
            else:
                tool = shutil.which("setfacl", path=os.defpath)
                command = [
                    tool or "",
                    "-m",
                    f"u:{os.geteuid()}:r-x,m::r-x",
                    marker.as_posix(),
                ]
                cleanup = [tool or "", "-b", marker.as_posix()]
            if not command[0]:
                self.skipTest("ACL mutation tool unavailable")
            result = subprocess.run(command, capture_output=True, text=True, check=False)
            if result.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_metadata_untrusted",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(root)
            finally:
                subprocess.run(cleanup, capture_output=True, check=False)

    def test_tracked_and_untracked_content_share_one_descriptor_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            untracked = root / "local.txt"
            untracked.write_text("first\n", encoding="utf-8")
            runtime = root / ".runtime"
            runtime.mkdir()
            (runtime / "excluded.bin").write_bytes(b"x" * 1024)
            self.git(root, "add", ".runtime/excluded.bin")
            self.git(
                root,
                "-c",
                "user.name=CodexQB Test",
                "-c",
                "user.email=codexqb-test@example.invalid",
                "commit",
                "-qm",
                "tracked exclusion",
            )

            def exclude_runtime(path: str) -> bool:
                return path.startswith(".runtime/")

            real_snapshot = GIT_EVIDENCE.snapshot_git_paths_from_anchor
            calls: list[list[str]] = []

            def recording_snapshot(anchor, paths, **kwargs):
                selected = list(paths)
                calls.append(selected)
                return real_snapshot(anchor, selected, **kwargs)

            with mock.patch.object(
                GIT_EVIDENCE,
                "snapshot_git_paths_from_anchor",
                side_effect=recording_snapshot,
            ):
                first = GIT_EVIDENCE.capture_git_workspace_evidence(
                    root,
                    exclude_untracked=exclude_runtime,
                    exclude_tracked=exclude_runtime,
                )

            self.assertEqual(calls, [["local.txt", "tracked.txt"]])
            self.assertEqual(first["untracked_paths"], ["local.txt"])
            self.assertEqual(
                [entry["path"] for entry in first["worktree_entries"]],
                ["tracked.txt"],
            )
            first_entry = first["untracked_entries"][0]
            self.assertEqual(first_entry["kind"], "regular")
            self.assertEqual(first_entry["git_mode"], "100644")
            first_digest = first["untracked_entries_sha256"]

            untracked.write_text("second\n", encoding="utf-8")
            content_changed = GIT_EVIDENCE.capture_git_workspace_evidence(
                root,
                exclude_untracked=exclude_runtime,
                exclude_tracked=exclude_runtime,
            )
            self.assertNotEqual(content_changed["untracked_entries_sha256"], first_digest)

            untracked.chmod(0o755)
            mode_changed = GIT_EVIDENCE.capture_git_workspace_evidence(
                root,
                exclude_untracked=exclude_runtime,
                exclude_tracked=exclude_runtime,
            )
            self.assertEqual(mode_changed["untracked_entries"][0]["git_mode"], "100755")
            self.assertNotEqual(
                mode_changed["untracked_entries_sha256"],
                content_changed["untracked_entries_sha256"],
            )

            untracked.unlink()
            untracked.symlink_to("tracked.txt")
            kind_changed = GIT_EVIDENCE.capture_git_workspace_evidence(
                root,
                exclude_untracked=exclude_runtime,
                exclude_tracked=exclude_runtime,
            )
            self.assertEqual(kind_changed["untracked_entries"][0]["kind"], "symlink")
            self.assertNotEqual(
                kind_changed["untracked_entries_sha256"],
                mode_changed["untracked_entries_sha256"],
            )

    def test_unborn_detached_and_sha256_repositories_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            unborn_root = Path(temp_dir) / "unborn"
            unborn_root.mkdir()
            self.git(unborn_root, "init", "-q")
            (unborn_root / "first.txt").write_text("first\n", encoding="utf-8")
            self.git(unborn_root, "add", "first.txt")

            unborn = GIT_EVIDENCE.capture_git_workspace_evidence(unborn_root)
            self.assertEqual(unborn["head"], "unknown")
            self.assertEqual(unborn["staged_changes"][0]["state"], "add")
            self.assertEqual(unborn["unstaged_diff_sha256"], EMPTY_SHA256)

            self.git(
                unborn_root,
                "-c",
                "user.name=CodexQB Test",
                "-c",
                "user.email=codexqb-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            self.git(unborn_root, "checkout", "--detach", "-q")
            detached = GIT_EVIDENCE.capture_git_workspace_evidence(unborn_root)
            self.assertEqual(detached["branch"], "unknown")
            self.assertRegex(str(detached["head"]), r"^[0-9a-f]{40}$")

        with tempfile.TemporaryDirectory() as temp_dir:
            sha256_root = Path(temp_dir)
            initialized = subprocess.run(
                ["git", "init", "-q", "--object-format=sha256"],
                cwd=sha256_root,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if initialized.returncode != 0:
                self.skipTest("installed Git does not support SHA-256 repositories")
            (sha256_root / "tracked.txt").write_text("sha256\n", encoding="utf-8")
            self.git(sha256_root, "add", "tracked.txt")
            self.git(
                sha256_root,
                "-c",
                "user.name=CodexQB Test",
                "-c",
                "user.email=codexqb-test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            )
            evidence = GIT_EVIDENCE.capture_git_workspace_evidence(sha256_root)
            self.assertEqual(evidence["object_format"], "sha256")
            self.assertRegex(str(evidence["head"]), r"^[0-9a-f]{64}$")
            self.assertEqual(evidence["status_sha256"], EMPTY_SHA256)

    def test_repository_controlled_executables_are_never_invoked(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            tracked = self.init_repo(root, attributes=True)
            external, external_marker = self.marker_program(root, "external-diff")
            textconv, textconv_marker = self.marker_program(root, "textconv")
            clean, clean_marker = self.marker_program(root, "clean-filter")
            fsmonitor, fsmonitor_marker = self.marker_program(root, "fsmonitor")
            inherited, inherited_marker = self.marker_program(root, "inherited-external-diff")
            fake_git, fake_git_marker = self.marker_program(root, "fake-git")
            fake_bin = root / "fake-bin"
            fake_bin.mkdir()
            (fake_bin / "git").symlink_to(fake_git)
            self.git(root, "config", "diff.external", external.as_posix())
            self.git(root, "config", "diff.probe.textconv", textconv.as_posix())
            self.git(root, "config", "filter.probe.clean", clean.as_posix())
            self.git(root, "config", "core.fsmonitor", fsmonitor.as_posix())
            tracked.write_text("after\n", encoding="utf-8")

            previous = os.environ.get("GIT_EXTERNAL_DIFF")
            previous_path = os.environ.get("PATH")
            os.environ["GIT_EXTERNAL_DIFF"] = inherited.as_posix()
            os.environ["PATH"] = f"{fake_bin}{os.pathsep}{previous_path or ''}"
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_unsafe_repository_config",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(root)
            finally:
                if previous is None:
                    os.environ.pop("GIT_EXTERNAL_DIFF", None)
                else:
                    os.environ["GIT_EXTERNAL_DIFF"] = previous
                if previous_path is None:
                    os.environ.pop("PATH", None)
                else:
                    os.environ["PATH"] = previous_path

            for marker in (
                external_marker,
                textconv_marker,
                clean_marker,
                fsmonitor_marker,
                inherited_marker,
                fake_git_marker,
            ):
                self.assertFalse(marker.exists(), marker.name)

    def test_repository_root_replacement_is_detected_while_git_uses_open_anchor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            root = parent / "root"
            replacement = parent / "replacement"
            original_after_swap = parent / "original-after-swap"
            root.mkdir()
            replacement.mkdir()
            self.init_repo(root)
            replacement_tracked = self.init_repo(replacement)
            replacement_tracked.write_text("attacker replacement\n", encoding="utf-8")

            real_popen = subprocess.Popen
            invocation: dict[str, object] = {}

            def swap_before_child_chdir(*args, **kwargs):
                if not invocation:
                    invocation.update(kwargs)
                    root.rename(original_after_swap)
                    replacement.rename(root)
                return real_popen(*args, **kwargs)

            with mock.patch.object(
                GIT_EVIDENCE.subprocess,
                "Popen",
                side_effect=swap_before_child_chdir,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_root_identity_changed",
                ):
                    GIT_EVIDENCE.capture_git_workspace_evidence(root)

            self.assertIsNone(invocation["cwd"])
            self.assertTrue(invocation["pass_fds"])
            self.assertIsNotNone(invocation["preexec_fn"])
            self.assertEqual((root / "tracked.txt").read_text(encoding="utf-8"), "attacker replacement\n")
            self.assertEqual(
                (original_after_swap / "tracked.txt").read_text(encoding="utf-8"),
                "before\n",
            )

    def test_environment_and_command_allowlist_are_fail_closed(self) -> None:
        environment = GIT_EVIDENCE.git_subprocess_environment(
            {
                "PATH": "/usr/bin",
                "GIT_DIR": "/tmp/attacker",
                "git_external_diff": "/tmp/attacker-diff",
                "LD_PRELOAD": "/tmp/attacker.so",
                "LD_LIBRARY_PATH": "/tmp/attacker-lib",
                "DYLD_INSERT_LIBRARIES": "/tmp/attacker.dylib",
                "DYLD_LIBRARY_PATH": "/tmp/attacker-lib",
                "PYTHONPATH": "/tmp/attacker-python",
                "PYTHONHOME": "/tmp/attacker-python-home",
                "BASH_ENV": "/tmp/attacker-bash-env",
                "ENV": "/tmp/attacker-shell-env",
                "PERL5OPT": "-M/tmp/attacker",
                "RUBYOPT": "-r/tmp/attacker",
                "NODE_OPTIONS": "--require=/tmp/attacker",
                "HOME": "/tmp/attacker-home",
                "XDG_CONFIG_HOME": "/tmp/attacker-xdg",
                "LANG": "tr_TR.UTF-8",
                "PWD": "/tmp/replaced-root",
                "OLDPWD": "/tmp/old-root",
            }
        )
        self.assertEqual(
            environment,
            {
                "GIT_ATTR_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_OPTIONAL_LOCKS": "0",
                "GIT_TERMINAL_PROMPT": "0",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": os.defpath,
            },
        )
        with self.assertRaisesRegex(ValueError, "git_evidence_command_not_allowed"):
            GIT_EVIDENCE.git_command(["diff", "--binary"])

    def test_user_and_environment_git_config_do_not_reach_child(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repo"
            root.mkdir()
            self.init_repo(root)
            untracked = root / "must-remain-visible.txt"
            untracked.write_text("visible\n", encoding="utf-8")

            attacker_home = base / "attacker-home"
            attacker_xdg = base / "attacker-xdg"
            attacker_home.mkdir()
            (attacker_xdg / "git").mkdir(parents=True)
            excludes = base / "attacker-excludes"
            excludes.write_text("*\n", encoding="utf-8")
            attacker_config = base / "attacker-config"
            payload = f"[core]\n\texcludesFile = {excludes.as_posix()}\n"
            attacker_config.write_text(payload, encoding="utf-8")
            (attacker_home / ".gitconfig").write_text(payload, encoding="utf-8")
            (attacker_xdg / "git/config").write_text(payload, encoding="utf-8")

            injected = {
                "HOME": attacker_home.as_posix(),
                "XDG_CONFIG_HOME": attacker_xdg.as_posix(),
                "GIT_CONFIG_GLOBAL": attacker_config.as_posix(),
                "GIT_CONFIG_NOSYSTEM": "0",
            }
            previous = {key: os.environ.get(key) for key in injected}
            os.environ.update(injected)
            try:
                evidence = GIT_EVIDENCE.capture_git_workspace_evidence(root)
            finally:
                for key, value in previous.items():
                    if value is None:
                        os.environ.pop(key, None)
                    else:
                        os.environ[key] = value

            self.assertIn(untracked.name, evidence["untracked_paths"])

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux loader regression")
    def test_linux_ld_preload_cannot_reach_trusted_git_child(self) -> None:
        compiler = shutil.which("cc", path=os.defpath)
        if compiler is None:
            self.skipTest("system C compiler unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repo"
            root.mkdir()
            self.init_repo(root)
            marker = Path(temp_dir) / "preload-constructor-ran"
            source = Path(temp_dir) / "preload.c"
            library = Path(temp_dir) / "preload.so"
            source.write_text(
                "#include <stdio.h>\n"
                "__attribute__((constructor)) static void mark(void) {\n"
                f"  FILE *stream = fopen({json.dumps(marker.as_posix())}, \"w\");\n"
                "  if (stream != NULL) { fputs(\"ran\", stream); fclose(stream); }\n"
                "}\n",
                encoding="utf-8",
            )
            subprocess.run(
                [compiler, "-shared", "-fPIC", "-o", library.as_posix(), source.as_posix()],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            control_environment = os.environ.copy()
            control_environment["LD_PRELOAD"] = library.as_posix()
            subprocess.run(
                [GIT_EVIDENCE.trusted_git_executable(), "--version"],
                check=True,
                env=control_environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertTrue(marker.is_file(), "LD_PRELOAD positive control did not run")
            marker.unlink()

            previous = os.environ.get("LD_PRELOAD")
            os.environ["LD_PRELOAD"] = library.as_posix()
            try:
                evidence = GIT_EVIDENCE.capture_git_workspace_evidence(root)
            finally:
                if previous is None:
                    os.environ.pop("LD_PRELOAD", None)
                else:
                    os.environ["LD_PRELOAD"] = previous

            self.assertTrue(evidence["is_git"])
            self.assertFalse(marker.exists())

    @unittest.skipUnless(sys.platform == "darwin", "Darwin loader regression")
    def test_darwin_dyld_variables_are_not_preserved(self) -> None:
        environment = GIT_EVIDENCE.git_subprocess_environment(
            {
                "DYLD_INSERT_LIBRARIES": "/tmp/attacker.dylib",
                "DYLD_LIBRARY_PATH": "/tmp/attacker-lib",
                "DYLD_FRAMEWORK_PATH": "/tmp/attacker-frameworks",
                "DYLD_PRINT_LIBRARIES": "1",
            }
        )
        self.assertFalse(any(key.startswith("DYLD_") for key in environment))

    def test_git_command_output_is_bounded_before_buffering(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            noisy_git = root / "noisy-git"
            noisy_git.write_text(
                "#!/bin/sh\n/usr/bin/yes A | /usr/bin/head -c 10000\n",
                encoding="utf-8",
            )
            noisy_git.chmod(0o755)
            with mock.patch.object(
                GIT_EVIDENCE,
                "trusted_git_executable",
                return_value=noisy_git.as_posix(),
            ), mock.patch.object(
                GIT_EVIDENCE,
                "MAX_GIT_COMMAND_OUTPUT_BYTES",
                1024,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_output_limit_exceeded=bounded_probe",
                ):
                    GIT_EVIDENCE.run_git_bytes(
                        root,
                        ("rev-parse", "--show-object-format"),
                        operation="bounded_probe",
                    )

    def test_preexec_git_runner_rejects_multithreaded_parent_before_popen(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            with mock.patch.object(
                GIT_EVIDENCE.threading,
                "active_count",
                return_value=2,
            ), mock.patch.object(GIT_EVIDENCE.subprocess, "Popen") as popen:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_preexec_requires_single_thread",
                ):
                    GIT_EVIDENCE.run_git_bytes(
                        root,
                        ("rev-parse", "--show-object-format"),
                        operation="thread_guard",
                    )
                popen.assert_not_called()

    def test_all_post_popen_setup_failures_kill_reap_and_close_pipes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.init_repo(root)
            incomplete = mock.Mock()
            incomplete.pid = 4242
            incomplete.stdout = None
            incomplete.stderr = mock.Mock()
            incomplete.wait.return_value = 0

            with mock.patch.object(
                GIT_EVIDENCE.subprocess,
                "Popen",
                return_value=incomplete,
            ), mock.patch.object(
                GIT_EVIDENCE,
                "_terminate_git_process_group",
            ) as terminate:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_command_unavailable=incomplete_pipe",
                ):
                    GIT_EVIDENCE.run_git_bytes(
                        root,
                        ("rev-parse", "--show-object-format"),
                        operation="incomplete_pipe",
                    )
            terminate.assert_called_once_with(incomplete)
            incomplete.wait.assert_called_once_with(timeout=5)
            incomplete.stderr.close.assert_called_once_with()

            selector_failure = mock.Mock()
            selector_failure.pid = 4343
            selector_failure.stdout = mock.Mock()
            selector_failure.stderr = mock.Mock()
            selector_failure.wait.return_value = 0

            with mock.patch.object(
                GIT_EVIDENCE.subprocess,
                "Popen",
                return_value=selector_failure,
            ), mock.patch.object(
                GIT_EVIDENCE.selectors,
                "DefaultSelector",
                side_effect=OSError("selector unavailable"),
            ), mock.patch.object(
                GIT_EVIDENCE,
                "_terminate_git_process_group",
            ) as terminate:
                with self.assertRaisesRegex(
                    ValueError,
                    "git_evidence_command_unavailable=selector_setup",
                ):
                    GIT_EVIDENCE.run_git_bytes(
                        root,
                        ("rev-parse", "--show-object-format"),
                        operation="selector_setup",
                    )
            terminate.assert_called_once_with(selector_failure)
            selector_failure.wait.assert_called_once_with(timeout=5)
            selector_failure.stdout.close.assert_called_once_with()
            selector_failure.stderr.close.assert_called_once_with()

            interrupted = mock.Mock()
            interrupted.pid = 4444
            interrupted.stdout = mock.Mock()
            interrupted.stderr = mock.Mock()
            interrupted.wait.return_value = 0

            real_monotonic = GIT_EVIDENCE.time.monotonic
            child_started = False

            def start_interrupted_child(*_args, **_kwargs):
                nonlocal child_started
                child_started = True
                return interrupted

            def interrupt_after_child_start():
                if child_started:
                    raise KeyboardInterrupt
                return real_monotonic()

            with mock.patch.object(
                GIT_EVIDENCE.subprocess,
                "Popen",
                side_effect=start_interrupted_child,
            ), mock.patch.object(
                GIT_EVIDENCE.time,
                "monotonic",
                side_effect=interrupt_after_child_start,
            ), mock.patch.object(
                GIT_EVIDENCE,
                "_terminate_git_process_group",
            ) as terminate:
                with self.assertRaises(KeyboardInterrupt):
                    GIT_EVIDENCE.run_git_bytes(
                        root,
                        ("rev-parse", "--show-object-format"),
                        operation="post_popen_interrupt",
                    )
            terminate.assert_called_once_with(interrupted)
            interrupted.wait.assert_called_once_with(timeout=5)
            interrupted.stdout.close.assert_called_once_with()
            interrupted.stderr.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
