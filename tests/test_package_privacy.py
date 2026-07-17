from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
PRIVACY_SCRIPT = REPO_ROOT / "scripts/check_public_privacy.py"


def load_privacy_module():
    spec = importlib.util.spec_from_file_location("codexqb_public_privacy_tests", PRIVACY_SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load public privacy checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


PRIVACY = load_privacy_module()


def git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )
    return result.stdout.strip()


def commit_all(root: Path, message: str) -> None:
    git(root, "add", ".")
    subprocess.run(
        [
            "git",
            "-c",
            "user.name=CodexQB Privacy Test",
            "-c",
            "user.email=privacy@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-m",
            message,
        ],
        cwd=root,
        text=True,
        capture_output=True,
        check=True,
    )


def run_checker(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(PRIVACY_SCRIPT), "--root", str(root), *args],
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )


class PackagePrivacyTests(unittest.TestCase):
    def test_history_scope_includes_runtime_cache_artifacts(self) -> None:
        self.assertTrue(
            PRIVACY.history_path_is_in_scope("plugins/codexqb/skills/codexqb/SKILL.md")
        )
        self.assertTrue(PRIVACY.history_path_is_in_scope("build/__pycache__/state.pyc"))
        self.assertTrue(PRIVACY.history_path_is_in_scope(".DS_Store"))

    def test_history_scans_runtime_cache_blob_content_without_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            first = root / "build/__pycache__/state.pyc"
            first.parent.mkdir(parents=True)
            first.write_bytes(b"\x00\xff" + ("/" + "Users/example/private").encode("ascii"))
            second = root / ".DS_Store"
            second.write_bytes(b"\x00\xff" + ("/" + "home/example/private").encode("ascii"))
            commit_all(root, "runtime cache privacy fixture")

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            rules = {item["rule"] for item in payload["findings"]}
            self.assertIn("mac_user_path", rules)
            self.assertIn("linux_home_path", rules)
            self.assertGreaterEqual(payload["history_counts"]["blobs"], 2)
            self.assertNotIn("/" + "Users/example/private", result.stdout + result.stderr)
            self.assertNotIn("/" + "home/example/private", result.stdout + result.stderr)

    def test_unrelated_local_feature_ref_does_not_expand_public_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "public head")
            public_branch = git(root, "branch", "--show-current")
            git(root, "checkout", "-q", "-b", "local-only")
            (root / "README.md").write_text("path: /Us" + "ers/local/private\n", encoding="utf-8")
            commit_all(root, "local-only metadata")
            git(root, "checkout", "-q", public_branch)

            result = run_checker(root, "--scope", "history", "--format", "json")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_public_ref_names_and_symbolic_head_fail_closed_without_disclosure(self) -> None:
        token = "sk-" + "R" * 40
        local_path = "leak-/" + "Users/example/private"
        cases = (
            ("tag-local-path", lambda root: git(root, "tag", local_path), local_path),
            ("tag-token", lambda root: git(root, "tag", token), token),
            (
                "remote-branch-local-path",
                lambda root: git(
                    root,
                    "update-ref",
                    f"refs/remotes/origin/{local_path}",
                    "HEAD",
                ),
                local_path,
            ),
            (
                "remote-branch-ending-head",
                lambda root: git(
                    root,
                    "update-ref",
                    f"refs/remotes/origin/{local_path}/HEAD",
                    "HEAD",
                ),
                local_path,
            ),
            ("head-branch-token", lambda root: git(root, "checkout", "-q", "-b", token), token),
        )
        for label, mutate, fixture in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                git(root, "init", "-q")
                (root / "README.md").write_text("safe\n", encoding="utf-8")
                commit_all(root, "safe ref baseline")
                mutate(root)

                result = run_checker(root, "--scope", "history", "--format", "json")

                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["errors"], ["history_scan_ref_metadata_rejected"])
                self.assertEqual(payload["findings"], [])
                self.assertNotIn(fixture, result.stdout + result.stderr)

    def test_clean_public_ref_names_remain_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "safe ref baseline")
            git(root, "tag", "v0.1.0")
            git(root, "update-ref", "refs/remotes/origin/main", "HEAD")

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(json.loads(result.stdout)["findings"], [])

    def test_history_scan_finds_removed_metadata_without_disclosing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            fixture = "/" + "Users/example/private"
            (root / "README.md").write_text(f"path: {fixture}\n", encoding="utf-8")
            commit_all(root, "historical fixture")
            (root / "README.md").write_text("# Safe current README\n", encoding="utf-8")
            commit_all(root, "redacted current state")

            failed = run_checker(root, "--scope", "history", "--format", "json")
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(fixture, failed.stdout + failed.stderr)
            payload = json.loads(failed.stdout)
            self.assertTrue(payload["history_applicable"])
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in payload["findings"]))
            baseline = [
                {
                    "blob_sha256": item["blob_sha256"],
                    "path_sha256": item["path_sha256"],
                    "rule": item["rule"],
                }
                for item in payload["findings"]
            ]
            baseline_path = root / "docs/history-privacy-baseline.json"
            baseline_path.parent.mkdir(parents=True)
            baseline_path.write_text(json.dumps(baseline), encoding="utf-8")

            allowed = run_checker(root, "--scope", "history", "--format", "json")
            self.assertEqual(allowed.returncode, 0, allowed.stdout + allowed.stderr)
            allowed_payload = json.loads(allowed.stdout)
            self.assertEqual(allowed_payload["baseline_matches"], len(baseline))
            self.assertEqual(allowed_payload["findings"], [])

    def test_gitless_history_scopes_fail_closed_and_current_ignores_history_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "README.md").write_text("# Safe\n", encoding="utf-8")
            baseline = root / "docs/history-privacy-baseline.json"
            baseline.parent.mkdir(parents=True)
            baseline.write_text("not-json\n", encoding="utf-8")

            current = run_checker(root, "--scope", "current", "--format", "json")
            self.assertEqual(current.returncode, 0, current.stdout + current.stderr)
            current_payload = json.loads(current.stdout)
            self.assertFalse(current_payload["history_applicable"])
            self.assertEqual(current_payload["baseline_count"], 0)

            baseline.write_text("[]\n", encoding="utf-8")
            for scope in ("history", "all"):
                with self.subTest(scope=scope):
                    result = run_checker(root, "--scope", scope, "--format", "json")
                    self.assertNotEqual(result.returncode, 0)
                    payload = json.loads(result.stdout)
                    self.assertEqual(
                        payload["errors"],
                        ["history_scan_git_repository_required"],
                    )
                    self.assertFalse(payload["history_applicable"])

    def test_current_scan_never_follows_public_file_symlinks_or_swap_races(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repo"
            root.mkdir()
            outside = base / "outside"
            fixture = "/" + "Users/example/private"
            outside.write_text(fixture, encoding="utf-8")
            readme = root / "README.md"
            readme.symlink_to(outside)
            with self.assertRaisesRegex(PRIVACY.PrivacyScanError, "current_scan_file_unavailable") as symlink_error:
                PRIVACY.current_findings(root)
            self.assertNotIn(fixture, str(symlink_error.exception))

            readme.unlink()
            readme.write_text("safe\n", encoding="utf-8")
            real_reader = PRIVACY.read_regular_files_from_anchor

            def swap_then_read(anchor, relatives, **kwargs):
                readme.unlink()
                readme.symlink_to(outside)
                return real_reader(anchor, relatives, **kwargs)

            with mock.patch.object(
                PRIVACY,
                "read_regular_files_from_anchor",
                side_effect=swap_then_read,
            ):
                with self.assertRaisesRegex(PRIVACY.PrivacyScanError, "current_scan_file_unavailable") as race_error:
                    PRIVACY.current_findings(root)
            self.assertNotIn(fixture, str(race_error.exception))

    def test_current_scan_hashes_secret_and_control_bearing_filenames(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public_dir = root / "docs/release-evidence"
            public_dir.mkdir(parents=True)
            fixture = "sk-" + "S" * 40
            filename = fixture + "-\x1b.txt"
            path = public_dir / filename
            path.write_text("local path: /Us" + "ers/example/private\n", encoding="utf-8")

            result = run_checker(root, "--scope", "current", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            rendered = result.stdout + result.stderr
            self.assertNotIn(fixture, rendered)
            self.assertNotIn("\x1b", rendered)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["scanner_contract"], "public_metadata_privacy_v1")
            self.assertTrue(
                any(item["rule"] == "openai_api_key" for item in payload["findings"])
            )
            self.assertEqual(
                payload["findings"][0]["path_sha256"],
                hashlib.sha256(
                    f"docs/release-evidence/{filename}".encode("utf-8")
                ).hexdigest(),
            )
            self.assertNotIn("path", payload["findings"][0])

    def test_current_scan_finds_safe_body_in_unsafe_public_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            relative = "docs/release-evidence/leak-/" + "Users/example/private.txt"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_text("safe body\n", encoding="utf-8")

            result = run_checker(root, "--scope", "current", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in payload["findings"]))
            self.assertTrue(all(item["line"] == 0 for item in payload["findings"]))
            self.assertNotIn(relative, result.stdout + result.stderr)

    def test_current_scan_has_fixed_path_and_deadline_budgets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            public_dir = root / "docs/release-evidence"
            public_dir.mkdir(parents=True)
            (public_dir / "one.txt").write_text("safe\n", encoding="utf-8")
            (public_dir / "two.txt").write_text("safe\n", encoding="utf-8")

            with mock.patch.object(PRIVACY, "MAX_CURRENT_PATHS", 1):
                with self.assertRaisesRegex(
                    PRIVACY.PrivacyScanError,
                    "current_scan_path_limit_exceeded",
                ):
                    PRIVACY.current_findings(root)

            with mock.patch.object(PRIVACY.time, "monotonic", side_effect=(0.0, 61.0)):
                with self.assertRaisesRegex(
                    PRIVACY.PrivacyScanError,
                    "current_scan_deadline_exceeded",
                ):
                    PRIVACY.current_findings(root)

    def test_history_scope_fails_closed_for_shallow_clone(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            origin = base / "origin"
            origin.mkdir()
            git(origin, "init", "-q")
            (origin / "README.md").write_text("first\n", encoding="utf-8")
            commit_all(origin, "first")
            (origin / "README.md").write_text("second\n", encoding="utf-8")
            commit_all(origin, "second")
            clone = base / "clone"
            subprocess.run(
                ["git", "clone", "-q", "--depth", "1", origin.as_uri(), str(clone)],
                check=True,
            )

            result = run_checker(clone, "--scope", "history", "--format", "json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("history_scan_shallow_repository", result.stdout)

    def test_history_scope_fails_closed_for_missing_reachable_object(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "reachable blob")
            blob_oid = git(root, "rev-parse", "HEAD:README.md")
            loose_object = root / ".git/objects" / blob_oid[:2] / blob_oid[2:]
            self.assertTrue(loose_object.is_file())
            loose_object.unlink()

            result = run_checker(root, "--scope", "history", "--format", "json")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("history_scan_missing_object", result.stdout)

    @unittest.skipIf(os.name != "posix", "byte filenames require POSIX paths")
    def test_history_scope_fails_closed_for_invalid_utf8_path_without_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            blob_oid = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=root,
                input=b"safe fixture\n",
                capture_output=True,
                check=True,
            ).stdout.strip()
            tree_oid = subprocess.run(
                ["git", "mktree", "-z"],
                cwd=root,
                input=b"100644 blob " + blob_oid + b"\t\xff-private.md\0",
                capture_output=True,
                check=True,
            ).stdout.strip()
            commit_oid = subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Privacy Test",
                    "-c",
                    "user.email=privacy@example.invalid",
                    "commit-tree",
                    tree_oid.decode("ascii"),
                    "-m",
                    "invalid path fixture",
                ],
                cwd=root,
                capture_output=True,
                check=True,
            ).stdout.decode("ascii").strip()
            git(root, "update-ref", "HEAD", commit_oid)

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertEqual(payload["errors"], ["history_scan_path_invalid_utf8"])
            rendered = result.stdout + result.stderr
            self.assertNotIn("private.md", rendered)
            self.assertNotIn("safe fixture", rendered)

    def test_history_scope_finds_removed_private_metadata_anywhere_in_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            skill = root / "plugins/codexqb/skills/codexqb/SKILL.md"
            skill.parent.mkdir(parents=True)
            fixture = "/Us" + "ers/example/private"
            skill.write_text(f"local evidence: {fixture}\n", encoding="utf-8")
            commit_all(root, "private plugin metadata")
            skill.write_text("# Safe skill\n", encoding="utf-8")
            commit_all(root, "redacted plugin metadata")

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            self.assertNotIn(fixture, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in payload["findings"]))

    def test_history_scope_scans_tree_entry_paths_without_disclosing_them(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            relative = "fixtures/" + "Users/example/evidence.txt"
            path = root / relative
            path.parent.mkdir(parents=True)
            path.write_text("safe body\n", encoding="utf-8")
            commit_all(root, "private tree path fixture")

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in payload["findings"]))
            self.assertNotIn(relative, result.stdout + result.stderr)

    def test_history_scans_commit_and_annotated_tag_messages_without_disclosure(self) -> None:
        for label in ("commit", "tag"):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                git(root, "init", "-q")
                (root / "README.md").write_text("safe\n", encoding="utf-8")
                fixture = "private /" + "Users/example/private"
                if label == "commit":
                    commit_all(root, fixture)
                else:
                    commit_all(root, "safe commit")
                    git(
                        root,
                        "-c",
                        "user.name=CodexQB Privacy Test",
                        "-c",
                        "user.email=privacy@example.invalid",
                        "tag",
                        "-a",
                        "v0.1.0",
                        "-m",
                        fixture,
                    )

                result = run_checker(root, "--scope", "history", "--format", "json")

                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                self.assertTrue(
                    any(item["rule"] == "mac_user_path" for item in payload["findings"])
                )
                self.assertNotIn(fixture, result.stdout + result.stderr)

    def test_history_rejects_active_grafts_and_raw_parent_walk_cannot_hide_history(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            fixture = "/" + "Users/example/private"
            (root / "README.md").write_text(fixture + "\n", encoding="utf-8")
            commit_all(root, "private first commit")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "safe second commit")
            grafts = root / git(root, "rev-parse", "--git-path", "info/grafts")
            grafts.parent.mkdir(parents=True, exist_ok=True)
            grafts.write_text(git(root, "rev-parse", "HEAD") + "\n", encoding="ascii")

            rejected = run_checker(root, "--scope", "history", "--format", "json")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(
                json.loads(rejected.stdout)["errors"],
                ["history_scan_grafts_present"],
            )
            self.assertNotIn(fixture, rejected.stdout + rejected.stderr)

            with mock.patch.object(PRIVACY, "_reject_active_git_grafts", return_value=None):
                findings, _counters, applicable = PRIVACY.history_findings(root)
            self.assertTrue(applicable)
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in findings))

    def test_history_scans_gitlink_and_credential_shaped_tree_paths(self) -> None:
        cases = (
            ("gitlink", "modules/leak-/" + "Users/example/private"),
            ("credential", "fixtures/" + "sk-" + "T" * 40),
        )
        for label, relative in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                git(root, "init", "-q")
                (root / "README.md").write_text("safe\n", encoding="utf-8")
                commit_all(root, "safe baseline")
                if label == "gitlink":
                    subprocess.run(
                        [
                            "git",
                            "update-index",
                            "--add",
                            "--cacheinfo",
                            "160000",
                            git(root, "rev-parse", "HEAD"),
                            relative,
                        ],
                        cwd=root,
                        capture_output=True,
                        check=True,
                    )
                    subprocess.run(
                        [
                            "git",
                            "-c",
                            "user.name=CodexQB Privacy Test",
                            "-c",
                            "user.email=privacy@example.invalid",
                            "-c",
                            "commit.gpgsign=false",
                            "commit",
                            "-m",
                            "gitlink path fixture",
                        ],
                        cwd=root,
                        capture_output=True,
                        check=True,
                    )
                else:
                    path = root / relative
                    path.parent.mkdir(parents=True)
                    path.write_text("safe body\n", encoding="utf-8")
                    commit_all(root, "credential-shaped path fixture")

                result = run_checker(root, "--scope", "history", "--format", "json")

                self.assertNotEqual(result.returncode, 0)
                payload = json.loads(result.stdout)
                expected_rule = "mac_user_path" if label == "gitlink" else "openai_api_key"
                self.assertTrue(
                    any(item["rule"] == expected_rule for item in payload["findings"])
                )
                self.assertNotIn(relative, result.stdout + result.stderr)

    def test_history_finding_and_commit_parent_fanout_limits_fail_before_growth(self) -> None:
        records: set[tuple[str, str, str]] = set()
        with mock.patch.object(PRIVACY, "MAX_HISTORY_FINDINGS", 1):
            PRIVACY._add_history_records(
                records,
                content_sha256="a" * 64,
                path_sha256="b" * 64,
                rules={"mac_user_path"},
            )
            with self.assertRaisesRegex(
                PRIVACY.PrivacyScanError,
                "history_scan_finding_limit_exceeded",
            ):
                PRIVACY._add_history_records(
                    records,
                    content_sha256="c" * 64,
                    path_sha256="d" * 64,
                    rules={"linux_home_path"},
                )
        self.assertEqual(len(records), 1)

        parent = b"parent " + b"b" * 40 + b"\n"
        commit = b"tree " + b"a" * 40 + b"\n" + parent * 3 + b"\nmessage\n"
        with mock.patch.object(PRIVACY, "MAX_COMMIT_PARENT_HEADERS", 2):
            with self.assertRaisesRegex(
                PRIVACY.PrivacyScanError,
                "history_scan_commit_parent_limit_exceeded",
            ):
                PRIVACY._commit_parent_oids(commit, PRIVACY.time.monotonic() + 1)

    def test_history_deadline_covers_content_scanning_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "deadline fixture")
            real_monotonic = PRIVACY.time.monotonic
            real_scan_bytes = PRIVACY.scan_bytes
            offset = [0.0]

            def monotonic() -> float:
                return real_monotonic() + offset[0]

            def expire_after_scan(data, relative, **kwargs):
                result = real_scan_bytes(data, relative, **kwargs)
                if relative not in {
                    "repository-ref-name.txt",
                    "repository-tree-path.txt",
                }:
                    offset[0] = PRIVACY.HISTORY_DEADLINE_SECONDS + 1.0
                return result

            with (
                mock.patch.object(PRIVACY.time, "monotonic", side_effect=monotonic),
                mock.patch.object(PRIVACY, "scan_bytes", side_effect=expire_after_scan) as scanner,
            ):
                with self.assertRaisesRegex(
                    PRIVACY.PrivacyScanError,
                    "history_scan_deadline_exceeded",
                ):
                    PRIVACY.history_findings(root)
            self.assertGreaterEqual(scanner.call_count, 2)

    def test_history_deadline_covers_final_finding_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir).resolve()
            git(root, "init", "-q")
            (root / "README.md").write_text("safe\n", encoding="utf-8")
            commit_all(root, "materialization deadline fixture")
            real_monotonic = PRIVACY.time.monotonic
            real_materialize = PRIVACY._materialize_history_findings
            offset = [0.0]

            def monotonic() -> float:
                return real_monotonic() + offset[0]

            def expire_after_materialize(records):
                result = real_materialize(records)
                offset[0] = PRIVACY.HISTORY_DEADLINE_SECONDS + 1.0
                return result

            with (
                mock.patch.object(PRIVACY.time, "monotonic", side_effect=monotonic),
                mock.patch.object(
                    PRIVACY,
                    "_materialize_history_findings",
                    side_effect=expire_after_materialize,
                ),
            ):
                with self.assertRaisesRegex(
                    PRIVACY.PrivacyScanError,
                    "history_scan_deadline_exceeded",
                ):
                    PRIVACY.history_findings(root)

    @unittest.skipIf(os.name != "posix", "Git symlink blobs require POSIX semantics")
    def test_history_scans_symlink_blob_targets_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            fixture = "/" + "Users/example/private"
            (root / "evidence-link").symlink_to(fixture)
            commit_all(root, "symlink metadata fixture")

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertTrue(any(item["rule"] == "mac_user_path" for item in payload["findings"]))
            self.assertGreater(payload["history_counts"]["blobs"], 0)
            self.assertNotIn(fixture, result.stdout + result.stderr)

    @unittest.skipIf(os.name != "posix", "raw Git symlink fixtures require POSIX")
    def test_history_invalid_utf8_symlink_blob_fails_closed_without_disclosure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            blob_oid = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=root,
                input=b"\xff-private-target",
                capture_output=True,
                check=True,
            ).stdout.strip()
            tree_oid = subprocess.run(
                ["git", "mktree", "-z"],
                cwd=root,
                input=b"120000 blob " + blob_oid + b"\tevidence-link\0",
                capture_output=True,
                check=True,
            ).stdout.strip()
            commit_oid = subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Privacy Test",
                    "-c",
                    "user.email=privacy@example.invalid",
                    "commit-tree",
                    tree_oid.decode("ascii"),
                    "-m",
                    "invalid symlink target fixture",
                ],
                cwd=root,
                capture_output=True,
                check=True,
            ).stdout.decode("ascii").strip()
            git(root, "update-ref", "HEAD", commit_oid)

            result = run_checker(root, "--scope", "history", "--format", "json")

            self.assertNotEqual(result.returncode, 0)
            payload = json.loads(result.stdout)
            self.assertTrue(
                any(item["rule"] == "public_text_invalid_utf8" for item in payload["findings"])
            )
            self.assertNotIn("private-target", result.stdout + result.stderr)

    def test_history_git_evidence_failure_is_not_reported_as_not_applicable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, (
            mock.patch.object(PRIVACY, "_exact_git_root", return_value=False)
        ), mock.patch.object(
            PRIVACY,
            "capture_git_workspace_evidence",
            side_effect=OSError("private backend detail"),
        ):
            with self.assertRaisesRegex(
                PRIVACY.PrivacyScanError,
                "history_scan_git_evidence_unavailable",
            ) as caught:
                PRIVACY.history_findings(Path(temp_dir))
            self.assertNotIn("private backend detail", str(caught.exception))

    def test_metadata_scanner_is_suffix_aware_and_binary_byte_safe(self) -> None:
        invalid = b"\x89PNG\r\n\x1a\n\xffclean"
        self.assertEqual(PRIVACY.scan_bytes(invalid, "docs/assets/workflow.png"), [])
        workflow = REPO_ROOT / "docs/assets/codexqb-workflow.png"
        self.assertEqual(
            PRIVACY.scan_bytes(workflow.read_bytes(), workflow.relative_to(REPO_ROOT).as_posix()),
            [],
        )
        self.assertEqual(
            PRIVACY.scan_bytes(invalid, "docs/release-evidence/report.md"),
            [("public_text_invalid_utf8", 0)],
        )
        marker = ("/" + "Users/example/private").encode("ascii")
        findings = PRIVACY.scan_bytes(b"\x00\xff" + marker + b"\x00", "artifact.bin")
        self.assertTrue(any(rule == "mac_user_path" for rule, _line in findings))
        run_identifier = "019e" + "a" * 28
        run_findings = PRIVACY.scan_bytes(run_identifier.encode("ascii"), "artifact.bin")
        self.assertTrue(any(rule == "codex_live_agent_id" for rule, _line in run_findings))
        container_uuid = "12345678-" + "1234-1234-1234-123456789abc"
        self.assertEqual(PRIVACY.scan_bytes(container_uuid.encode("ascii"), "artifact.bin"), [])
        self.assertIn(
            ("local_uuid", 1),
            PRIVACY.scan_bytes((container_uuid + "\n").encode("ascii"), "report.md"),
        )

    def test_history_binary_blob_does_not_require_utf8_but_still_scans_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git(root, "init", "-q")
            asset = root / "docs/assets/workflow.png"
            asset.parent.mkdir(parents=True)
            asset.write_bytes(b"\x89PNG\r\n\x1a\n\xffclean")
            commit_all(root, "binary asset")

            clean = run_checker(root, "--scope", "history", "--format", "json")
            self.assertEqual(clean.returncode, 0, clean.stdout + clean.stderr)

            marker = ("/" + "Users/example/private").encode("ascii")
            asset.write_bytes(b"\x89PNG\r\n\x1a\n\xff" + marker)
            commit_all(root, "binary metadata fixture")
            failed = run_checker(root, "--scope", "history", "--format", "json")
            self.assertNotEqual(failed.returncode, 0)
            self.assertNotIn(marker.decode("ascii"), failed.stdout + failed.stderr)
            self.assertTrue(
                any(item["rule"] == "mac_user_path" for item in json.loads(failed.stdout)["findings"])
            )
