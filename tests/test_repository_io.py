from __future__ import annotations

import ast
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest import mock

from tests.controller_test_support import (
    assert_real_trust_store_unchanged,
    controller_cli_command,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_IO_PATH = (
    REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/repository_io.py"
)


def load_repository_io_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_repository_io",
        REPOSITORY_IO_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load repository_io from {REPOSITORY_IO_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


REPOSITORY_IO = load_repository_io_module()
ARTIFACT_IO = sys.modules[REPOSITORY_IO.atomic_write_bytes_at.__module__]
REPOSITORY_EVIDENCE = sys.modules[REPOSITORY_IO.open_repository_cwd_anchor.__module__]


class RepositoryIOTests(unittest.TestCase):
    def write_file(self, root: Path, relative: str, text: str = "safe\n") -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        path.chmod(0o644)
        return path

    def test_receipt_dictionary_literal_has_no_duplicate_fields(self) -> None:
        tree = ast.parse(REPOSITORY_IO_PATH.read_text(encoding="utf-8"))
        receipt_class = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "RepositoryIOReceipt"
        )
        as_dict = next(
            node
            for node in receipt_class.body
            if isinstance(node, ast.FunctionDef) and node.name == "as_dict"
        )
        literal = next(
            node.value
            for node in as_dict.body
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Dict)
        )
        keys = [
            key.value
            for key in literal.keys
            if isinstance(key, ast.Constant) and isinstance(key.value, str)
        ]
        self.assertEqual(len(keys), len(set(keys)), keys)
        self.assertEqual(keys.count("bytes_scanned"), 1)

    def test_public_facade_exposes_only_contract_methods_and_closes_lifetime(self) -> None:
        allowed = {
            "list_paths",
            "read_many",
            "read_text",
            "search",
            "write_planner_text",
        }
        forbidden = {
            "anchor",
            "root",
            "policy",
            "receipts",
            "read_bytes",
            "path_kind",
            "snapshot_paths",
            "internal_paths",
            "internal_directories",
            "revalidate_listing",
            "inventory",
        }
        self.assertEqual(
            {name for name in dir(REPOSITORY_IO.RepositoryIO) if not name.startswith("_")},
            allowed,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                self.assertFalse(any(hasattr(repository, name) for name in forbidden))
                self.assertTrue(repository.read_text("README.md").exists)
            with self.assertRaisesRegex(ValueError, "repository_io_session_closed"):
                repository.read_text("README.md")

    def test_reads_are_anchored_and_reject_parent_final_and_hardlink_indirection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            external = base / "external"
            external.mkdir()
            self.write_file(external, "victim.md", "outside\n")

            parent_link_root = base / "parent-link"
            parent_link_root.mkdir()
            (parent_link_root / "Planner-docs").symlink_to(external, target_is_directory=True)
            with REPOSITORY_IO.open_repository_io(parent_link_root) as repository:
                with self.assertRaisesRegex(ValueError, "repository_path_parent_identity_changed"):
                    repository.read_text("Planner-docs/victim.md")

            final_link_root = base / "final-link"
            (final_link_root / "Planner-docs").mkdir(parents=True)
            (final_link_root / "Planner-docs/Main-Planing.md").symlink_to(external / "victim.md")
            with REPOSITORY_IO.open_repository_io(final_link_root) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_regular_file_required"):
                    repository.read_text("Planner-docs/Main-Planing.md")

    def test_csf_84f60038c99e3b782876a719_symlink_read_poc_is_fail_closed(self) -> None:
        """Regression for PP-READ-002: ordinary path reads follow the PoC link."""

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            outside = self.write_file(base, "outside/evidence.md", "SYMLINK_READ_CANARY\n")
            root = base / "repository"
            (root / "Planner-docs").mkdir(parents=True)
            linked = root / "Planner-docs/Main-Planing.md"
            linked.symlink_to(outside)
            # Preserve the original finding semantics: an unguarded read would
            # cross the repository boundary and disclose the outside bytes.
            self.assertEqual(linked.read_text(encoding="utf-8"), "SYMLINK_READ_CANARY\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaises(ValueError) as raised:
                    repository.read_text("Planner-docs/Main-Planing.md")
            self.assertNotIn("SYMLINK_READ_CANARY", str(raised.exception))

            hardlink_root = base / "hardlink"
            target = self.write_file(hardlink_root, "Planner-docs/Main-Planing.md")
            os.link(target, hardlink_root / "Planner-docs/alias.md")
            with REPOSITORY_IO.open_repository_io(hardlink_root) as repository:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_read_identity_changed",
                ):
                    repository.read_text("Planner-docs/Main-Planing.md")

    def test_special_file_is_rejected_without_opening_it(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("FIFO support unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "Planner-docs").mkdir()
            os.mkfifo(root / "Planner-docs/pipe.md")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_regular_file_required"):
                    repository.read_text("Planner-docs/pipe.md")

    def test_model_projection_normalizes_semantic_encoding_and_never_returns_secret(self) -> None:
        fixture = "sk-" + "Q" * 40
        entity = "".join(f"&#{ord(character)};" for character in fixture)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(
                root,
                "Planner-docs/Main-Planing.md",
                f"safe\ncredential={entity[:30]}\u202e{entity[30:]}\n",
            )
            with REPOSITORY_IO.open_repository_io(root) as repository:
                evidence = repository.read_text(
                    "Planner-docs/Main-Planing.md",
                    audience="model",
                )
                serialized = json.dumps(
                    {"text": evidence.text, "receipt": evidence.receipt.as_dict()},
                    sort_keys=True,
                )
                self.assertNotIn(fixture, serialized)
                self.assertNotIn("&#", evidence.text or "")
                self.assertFalse(REPOSITORY_IO.secret_findings(evidence.text or ""))

    def test_model_projection_fail_closes_semantically_split_credentials(self) -> None:
        credential = "sk-" + "R" * 40
        variants = {
            "invisible": "sk-\u200b" + "R" * 40,
            "control": "sk-\x1f" + "R" * 40,
            "terminal_escape": "sk-\x1b[31m" + "R" * 40,
            "textual_escape": "sk-" + "\\u0052" * 40,
            "html_entity": "".join(f"&#{ord(character)};" for character in credential),
        }
        for name, payload in variants.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_file(root, "Planner-docs/Main-Planing.md", payload + "\n")
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    evidence = repository.read_text(
                        "Planner-docs/Main-Planing.md",
                        audience="model",
                    )
                self.assertEqual(
                    evidence.text,
                    "<redacted:unsafe-repository-evidence>\n",
                )
                self.assertNotIn("sk-", evidence.text or "")
                self.assertNotIn("R" * 8, evidence.text or "")

        with mock.patch.object(
            REPOSITORY_IO,
            "secret_findings",
            side_effect=RuntimeError("scanner unavailable"),
        ):
            projected, redacted = REPOSITORY_IO._model_projection(b"otherwise safe")
        self.assertTrue(redacted)
        self.assertEqual(projected, "<redacted:unsafe-repository-evidence>\n")

        with mock.patch.object(
            REPOSITORY_IO,
            "secret_findings",
            side_effect=[[], RuntimeError("residual scanner unavailable")],
        ):
            projected, redacted = REPOSITORY_IO._model_projection(b"otherwise safe")
        self.assertTrue(redacted)
        self.assertEqual(projected, "<redacted:unsafe-repository-evidence>\n")

    def test_invalid_utf8_fails_internal_and_is_constant_redaction_for_model(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "Planner-docs/Main-Planing.md"
            target.parent.mkdir(parents=True)
            target.write_bytes(b"safe\xffbody")
            target.chmod(0o644)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "repository_io_non_utf8_text"):
                    repository.read_text("Planner-docs/Main-Planing.md")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                evidence = repository.read_text(
                    "Planner-docs/Main-Planing.md",
                    audience="model",
                )
                self.assertEqual(evidence.text, "<redacted:non-utf8-repository-evidence>\n")

    def test_named_profiles_and_search_emit_metadata_not_matching_lines(self) -> None:
        marker = "unique architecture sentence that must not be copied"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md", marker + "\n")
            self.write_file(root, "Planner-docs/Main-Planing.md", "Phase roadmap validation\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                listing = repository.list_paths("step2")
                result = repository.search("intake")
                self.assertIn("Planner-docs/Main-Planing.md", listing.paths)
                self.assertTrue(any(record["signal"] == "architecture" for record in result.records))
                self.assertNotIn(marker, json.dumps(result.records))
                with self.assertRaisesRegex(ValueError, "repository_io_profile_invalid"):
                    repository.search("arbitrary")

    def test_active_source_controller_harness_runs_from_foreign_repository(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            foreign_root = Path(temp_dir) / "foreign-target"
            foreign_root.mkdir()
            self.write_file(foreign_root, "README.md", "architecture boundary\n")
            self.assertFalse((foreign_root / "repository_io.py").exists())
            script = REPOSITORY_IO_PATH.resolve(strict=True)
            self.assertTrue(script.is_file())
            self.assertFalse(script.is_symlink())

            with assert_real_trust_store_unchanged():
                result = subprocess.run(
                    controller_cli_command(
                        "repository-io",
                        None,
                        [
                            "--root",
                            ".",
                            "inspect",
                            "--profile",
                            "intake",
                        ],
                    ),
                    cwd=foreign_root,
                    env={**os.environ, "PWD": foreign_root.resolve(strict=True).as_posix()},
                    text=True,
                    capture_output=True,
                    timeout=10,
                    check=False,
                )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            self.assertIn("README.md", payload["paths"])
            self.assertEqual(payload["profile"], "intake")
            self.assertEqual(payload["receipt"]["policy"], "planner-evidence/v1")

    def test_stdin_request_keeps_repository_paths_out_of_shell_text(self) -> None:
        hostile_names = (
            "$(touch SHELL_MARKER).md",
            "`touch SHELL_MARKER`.md",
            "semi;touch SHELL_MARKER;.md",
            "single'touch SHELL_MARKER'.md",
            'double"touch SHELL_MARKER".md',
            "space touch SHELL_MARKER.md",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for name in hostile_names:
                self.write_file(root, f"docs/{name}", "architecture boundary\n")
            marker = root / "SHELL_MARKER"
            for name in hostile_names:
                relative = f"docs/{name}"
                request = json.dumps(
                    {
                        "schema": "codexqb.controller-argv/v1",
                        "argv": ["--root", ".", "read-model", "--path", relative],
                    },
                    sort_keys=True,
                )
                with self.subTest(name=name), assert_real_trust_store_unchanged():
                    completed = subprocess.run(
                        controller_cli_command(
                            "repository-io", None, ["request-stdin"]
                        ),
                        cwd=root,
                        env={**os.environ, "PWD": root.resolve().as_posix()},
                        input=request,
                        text=True,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertIn("architecture boundary", completed.stdout)
                self.assertFalse(marker.exists())
                self.assertNotIn(request, completed.stdout)
                self.assertNotIn(request, completed.stderr)

    def test_stdin_request_binds_write_body_and_rejects_unsafe_envelopes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            request = json.dumps(
                {
                    "schema": "codexqb.controller-argv/v1",
                    "argv": [
                        "--root",
                        ".",
                        "write-planner",
                        "--stage",
                        "step1",
                        "--path",
                        "Planner-docs/Main-Planing.md",
                        "--expected-missing",
                    ],
                    "body": "# Safe plan\n",
                },
                sort_keys=True,
            )
            completed = subprocess.run(
                controller_cli_command("repository-io", None, ["request-stdin"]),
                cwd=root,
                env={**os.environ, "PWD": root.resolve().as_posix()},
                input=request,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                (root / "Planner-docs/Main-Planing.md").read_text(encoding="utf-8"),
                "# Safe plan\n",
            )

            for invalid in (
                '{"schema":"codexqb.controller-argv/v1","schema":"duplicate","argv":[]}',
                json.dumps(
                    {
                        "schema": "codexqb.controller-argv/v1",
                        "argv": ["request-stdin"],
                    }
                ),
                json.dumps(
                    {
                        "schema": "codexqb.controller-argv/v1",
                        "argv": ["--root", ".", "inspect", "--profile", "intake"],
                        "body": "not allowed",
                    }
                ),
            ):
                with self.subTest(invalid=invalid[:32]):
                    rejected = subprocess.run(
                        controller_cli_command(
                            "repository-io", None, ["request-stdin"]
                        ),
                        cwd=root,
                        env={**os.environ, "PWD": root.resolve().as_posix()},
                        input=invalid,
                        text=True,
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    self.assertEqual(rejected.returncode, 1)
                    self.assertEqual(rejected.stdout, "")
                    self.assertEqual(
                        rejected.stderr,
                        "repository_io_failed=repository_io_operation_failed\n",
                    )
                    self.assertNotIn(invalid, rejected.stderr)

    def test_real_regular_file_listing_uses_canonical_seven_field_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "README.md", "architecture\n")
            expected = target.stat()
            with REPOSITORY_IO.open_repository_io(root) as repository:
                listing = repository.list_paths("intake")
                metadata_listing = REPOSITORY_IO._controller_engine(
                    repository
                )._internal_listing("intake")

            self.assertIn("README.md", listing.paths)
            entry = next(
                item for item in metadata_listing if item["path"] == "README.md"
            )
            identity = entry["identity"]
            self.assertEqual(len(identity), 7)
            self.assertEqual(
                identity,
                (
                    expected.st_dev,
                    expected.st_ino,
                    expected.st_mode,
                    expected.st_nlink,
                    expected.st_size,
                    expected.st_mtime_ns,
                    expected.st_ctime_ns,
                ),
            )

    def test_owner_controlled_root_proof_binds_mode_and_root_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir(mode=0o700)
            self.write_file(root, "bundle.py")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                self.assertIsNone(
                    REPOSITORY_IO._controller_require_owner_controlled_root(
                        repository
                    )
                )
                proof = REPOSITORY_IO._controller_root_proof(repository)
                self.assertRegex(proof.repository_identity_sha256, r"[0-9a-f]{64}")
                inventory = REPOSITORY_IO._controller_complete_inventory(repository)
                root_records = [
                    item
                    for item in inventory
                    if item.get("path") == "." and item.get("kind") == "root"
                ]
                self.assertEqual(len(root_records), 1)
                self.assertEqual(len(root_records[0]["identity"]), 9)
                transient = root / ".transient"
                transient.write_bytes(b"temporary")
                transient.unlink()
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_owner_controlled_root_failed",
                ):
                    REPOSITORY_IO._controller_require_owner_controlled_root(
                        repository
                    )
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_owner_controlled_root_failed",
                ):
                    REPOSITORY_IO._controller_root_proof(repository)
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_owner_controlled_root_failed|repository_io_complete_inventory_changed",
                ):
                    REPOSITORY_IO._controller_complete_inventory(repository)

    def test_root_proof_identity_is_stable_across_safe_root_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir(mode=0o700)
            self.write_file(root, "README.md", "stable repository\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                before = REPOSITORY_IO._controller_root_proof(repository)

            transient = root / ".transient"
            transient.write_bytes(b"temporary")
            transient.unlink()

            with REPOSITORY_IO.open_repository_io(root) as repository:
                after = REPOSITORY_IO._controller_root_proof(repository)

            self.assertEqual(
                after.repository_identity_sha256,
                before.repository_identity_sha256,
            )
            self.assertEqual(after.root_device, before.root_device)
            self.assertEqual(after.root_inode, before.root_inode)

    def test_engine_root_identity_never_resolves_through_namespace_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            root = base / "repository"
            held = base / "held"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            self.write_file(root, "README.md", "anchored\n")
            self.write_file(outside, "README.md", "outside\n")
            real_resolve = Path.resolve
            resolve_calls = 0

            def resolve_through_temporary_alias(candidate: Path, strict: bool = False) -> Path:
                nonlocal resolve_calls
                if candidate != root:
                    return real_resolve(candidate, strict=strict)
                resolve_calls += 1
                root.rename(held)
                root.symlink_to(outside, target_is_directory=True)
                try:
                    return real_resolve(candidate, strict=strict)
                finally:
                    root.unlink()
                    held.rename(root)

            with mock.patch.object(
                Path,
                "resolve",
                new=resolve_through_temporary_alias,
            ):
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    proof = REPOSITORY_IO._controller_root_proof(repository)
                    bound_root = REPOSITORY_IO._controller_engine(repository).root

            self.assertEqual(bound_root, root)
            self.assertEqual(proof.root_inode, root.stat().st_ino)
            self.assertEqual(resolve_calls, 0)

    def test_missing_receipt_revalidates_anchor_after_final_missing_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            root = base / "repository"
            held = base / "held"
            replacement = base / "replacement"
            root.mkdir()
            replacement.mkdir()
            swapped = False
            exits = 0
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    engine = REPOSITORY_IO._controller_engine(repository)
                    original_parent_descriptor = engine._parent_descriptor

                    @contextmanager
                    def swap_after_second_missing_parent(path: str):
                        nonlocal exits, swapped
                        with original_parent_descriptor(path) as opened:
                            yield opened
                        exits += 1
                        if exits == 2:
                            root.rename(held)
                            replacement.rename(root)
                            swapped = True

                    with mock.patch.object(
                        engine,
                        "_parent_descriptor",
                        new=swap_after_second_missing_parent,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_root_identity_changed",
                        ):
                            repository.read_text(
                                "missing/child.md",
                                required=False,
                            )
                self.assertTrue(swapped)
                self.assertEqual(exits, 2)
            finally:
                if swapped:
                    root.rename(replacement)
                    held.rename(root)

            root.chmod(0o777)
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_owner_controlled_root_failed",
                    ):
                        REPOSITORY_IO._controller_require_owner_controlled_root(
                            repository
                        )
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_owner_controlled_root_failed",
                    ):
                        REPOSITORY_IO._controller_root_proof(repository)
            finally:
                root.chmod(0o700)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_root_proof_rejects_acl_inserted_between_authority_snapshots(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            root.mkdir()
            self.write_file(root, "README.md", "safe\n")
            acl_applied = False
            calls = 0
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    engine = REPOSITORY_IO._controller_engine(repository)
                    original_identity = engine._owner_controlled_root_identity

                    def insert_acl_after_first_snapshot():
                        nonlocal acl_applied, calls
                        calls += 1
                        identity = original_identity()
                        if calls == 1:
                            applied = subprocess.run(
                                [
                                    chmod,
                                    "+a",
                                    "everyone allow read,write,append,delete,list,search",
                                    root.as_posix(),
                                ],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            if applied.returncode != 0:
                                raise unittest.SkipTest(
                                    "extended ACL creation unavailable"
                                )
                            acl_applied = True
                        return identity

                    receipts_before = len(engine.receipts)
                    with mock.patch.object(
                        engine,
                        "_owner_controlled_root_identity",
                        side_effect=insert_acl_after_first_snapshot,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_owner_controlled_root_failed",
                        ):
                            REPOSITORY_IO._controller_root_proof(repository)
                    self.assertEqual(len(engine.receipts), receipts_before)
                self.assertTrue(acl_applied)
                self.assertEqual(calls, 2)
            finally:
                subprocess.run(
                    [chmod, "-N", root.as_posix()],
                    capture_output=True,
                    check=False,
                )

    def test_missing_receipt_revalidates_nested_parent_after_final_lookup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            docs = root / "docs"
            replacement = root / "docs-replacement"
            held = root / "docs-held"
            docs.mkdir(parents=True)
            replacement.mkdir()
            real_stat = REPOSITORY_IO.os.stat
            misses = 0
            swapped = False

            def swap_parent_on_second_final_miss(path, *args, **kwargs):
                nonlocal misses, swapped
                try:
                    return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == "missing.md" and kwargs.get("dir_fd") is not None:
                        misses += 1
                        if misses == 2:
                            docs.rename(held)
                            replacement.rename(docs)
                            swapped = True
                    raise

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO.os,
                        "stat",
                        side_effect=swap_parent_on_second_final_miss,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_path_parent_identity_changed",
                        ):
                            repository.read_text(
                                "docs/missing.md",
                                required=False,
                            )
                self.assertTrue(swapped)
                self.assertEqual(misses, 2)
            finally:
                if swapped:
                    docs.rename(replacement)
                    held.rename(docs)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_missing_receipt_rejects_nested_parent_acl_after_final_lookup(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            docs = root / "docs"
            docs.mkdir(parents=True)
            real_stat = REPOSITORY_IO.os.stat
            misses = 0
            acl_applied = False

            def add_parent_acl_on_second_final_miss(path, *args, **kwargs):
                nonlocal misses, acl_applied
                try:
                    return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == "missing.md" and kwargs.get("dir_fd") is not None:
                        misses += 1
                        if misses == 2:
                            applied = subprocess.run(
                                [
                                    chmod,
                                    "+a",
                                    "everyone allow read,write,append,delete,list,search",
                                    docs.as_posix(),
                                ],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            if applied.returncode != 0:
                                raise unittest.SkipTest(
                                    "extended ACL creation unavailable"
                                )
                            acl_applied = True
                    raise

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO.os,
                        "stat",
                        side_effect=add_parent_acl_on_second_final_miss,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_parent_acl_rejected",
                        ):
                            repository.read_text(
                                "docs/missing.md",
                                required=False,
                            )
                self.assertTrue(acl_applied)
                self.assertEqual(misses, 2)
            finally:
                subprocess.run(
                    [chmod, "-N", docs.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_missing_intermediate_parent_rechecks_repository_root_acl(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            root.mkdir()
            real_stat = REPOSITORY_IO.os.stat
            misses = 0
            acl_applied = False

            def add_root_acl_on_second_parent_miss(path, *args, **kwargs):
                nonlocal misses, acl_applied
                try:
                    return real_stat(path, *args, **kwargs)
                except FileNotFoundError:
                    if path == "missing" and kwargs.get("dir_fd") is not None:
                        misses += 1
                        if misses == 2:
                            applied = subprocess.run(
                                [
                                    chmod,
                                    "+a",
                                    "everyone allow read,write,append,delete,list,search",
                                    root.as_posix(),
                                ],
                                capture_output=True,
                                text=True,
                                check=False,
                            )
                            if applied.returncode != 0:
                                raise unittest.SkipTest(
                                    "extended ACL creation unavailable"
                                )
                            acl_applied = True
                    raise

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO.os,
                        "stat",
                        side_effect=add_root_acl_on_second_parent_miss,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_owner_controlled_root_failed",
                        ):
                            repository.read_text(
                                "missing/child.md",
                                required=False,
                            )
                self.assertTrue(acl_applied)
                self.assertEqual(misses, 2)
            finally:
                subprocess.run(
                    [chmod, "-N", root.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_repository_reads_and_root_proof_reject_extended_acl(self) -> None:
        chmod = shutil.which("chmod")
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "root"
            root.mkdir(mode=0o700)
            target = self.write_file(root, "bundle.py")
            for protected in (root, target):
                with self.subTest(protected=protected):
                    result = subprocess.run(
                        [
                            chmod,
                            "+a",
                            "everyone allow read,write,append,delete",
                            str(protected),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.skipTest("extended ACL creation unavailable")
                    try:
                        with REPOSITORY_IO.open_repository_io(root) as repository:
                            if protected == root:
                                with self.assertRaisesRegex(
                                    ValueError,
                                    "repository_io_owner_controlled_root_failed",
                                ):
                                    REPOSITORY_IO._controller_require_owner_controlled_root(
                                        repository
                                    )
                                with self.assertRaisesRegex(
                                    ValueError,
                                    "repository_io_owner_controlled_root_failed",
                                ):
                                    REPOSITORY_IO._controller_root_proof(repository)
                            else:
                                with self.assertRaisesRegex(
                                    ValueError,
                                    "repository_io_target_acl_rejected",
                                ):
                                    REPOSITORY_IO._controller_read_bytes(
                                        repository,
                                        "bundle.py",
                                    )
                    finally:
                        subprocess.run(
                            [chmod, "-N", str(protected)],
                            capture_output=True,
                            check=False,
                        )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_listing_and_search_reject_acl_on_root_parent_or_final_file(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        for protected_kind in ("root", "parent", "file"):
            with self.subTest(protected_kind=protected_kind), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir) / "root"
                root.mkdir(mode=0o700)
                parent = root / "docs"
                parent.mkdir(mode=0o700)
                target = self.write_file(parent, "README.md", "architecture boundary\n")
                protected = {"root": root, "parent": parent, "file": target}[protected_kind]
                applied = subprocess.run(
                    [
                        chmod,
                        "+a",
                        "everyone allow read,write,append,delete",
                        protected.as_posix(),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if applied.returncode != 0:
                    self.skipTest("extended ACL creation unavailable")
                try:
                    for operation in ("list", "search"):
                        with self.subTest(operation=operation):
                            with REPOSITORY_IO.open_repository_io(root) as repository:
                                with self.assertRaisesRegex(
                                    ValueError,
                                    "repository_io_(?:inventory_root_untrusted|inventory_parent_changed|inventory_file_acl_rejected)",
                                ):
                                    if operation == "list":
                                        repository.list_paths("intake")
                                    else:
                                        repository.search("intake")
                finally:
                    subprocess.run(
                        [chmod, "-N", protected.as_posix()],
                        capture_output=True,
                        check=False,
                    )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_controller_inventory_rejects_acl_on_root_parent_or_final_file(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        for protected_kind in ("root", "parent", "file"):
            with self.subTest(protected_kind=protected_kind), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir) / "root"
                root.mkdir(mode=0o700)
                parent = root / "docs"
                parent.mkdir(mode=0o700)
                target = self.write_file(parent, "README.md", "architecture boundary\n")
                protected = {"root": root, "parent": parent, "file": target}[protected_kind]
                applied = subprocess.run(
                    [
                        chmod,
                        "+a",
                        "everyone allow read,write,append,delete",
                        protected.as_posix(),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if applied.returncode != 0:
                    self.skipTest("extended ACL creation unavailable")
                try:
                    with REPOSITORY_IO.open_repository_io(root) as repository:
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_inventory_failed",
                        ):
                            REPOSITORY_IO._controller_inventory(repository)
                finally:
                    subprocess.run(
                        [chmod, "-N", protected.as_posix()],
                        capture_output=True,
                        check=False,
                    )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_controller_workspace_proof_rejects_tracked_file_acl(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        git = shutil.which("git", path=os.defpath)
        if chmod is None or git is None:
            self.skipTest("chmod or git unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            root.mkdir(mode=0o700)
            tracked = self.write_file(root, "tracked.txt", "tracked\n")
            for arguments in (
                ("init", "-q"),
                ("config", "user.email", "codexqb-tests@example.invalid"),
                ("config", "user.name", "CodexQB Tests"),
                ("add", "tracked.txt"),
                ("commit", "-q", "-m", "fixture"),
            ):
                completed = subprocess.run(
                    [git, *arguments],
                    cwd=root,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            applied = subprocess.run(
                [
                    chmod,
                    "+a",
                    "everyone allow read,write,append,delete",
                    tracked.as_posix(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if applied.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_workspace_proof_failed",
                    ):
                        REPOSITORY_IO._controller_workspace_proof(repository)
            finally:
                subprocess.run(
                    [chmod, "-N", tracked.as_posix()],
                    capture_output=True,
                    check=False,
                )

    def test_darwin_acl_null_result_without_enoent_fails_closed(self) -> None:
        libc = mock.Mock()
        libc.acl_get_fd_np = mock.Mock(return_value=None)
        libc.acl_free = mock.Mock(return_value=0)
        with mock.patch.object(REPOSITORY_IO.sys, "platform", "darwin"), mock.patch.object(
            REPOSITORY_IO.os,
            "listxattr",
            return_value=[],
            create=True,
        ), mock.patch.object(REPOSITORY_IO.ctypes, "CDLL", return_value=libc), mock.patch.object(
            REPOSITORY_IO.ctypes,
            "get_errno",
            return_value=0,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "repository_io_acl_probe_failed",
            ):
                REPOSITORY_IO._descriptor_has_acl(0)

    def test_linux_opath_symlink_acl_probe_handles_ebadf_without_weakening_regular_files(self) -> None:
        symlink_metadata = mock.Mock(st_mode=REPOSITORY_IO.stat.S_IFLNK | 0o777)
        regular_metadata = mock.Mock(st_mode=REPOSITORY_IO.stat.S_IFREG | 0o644)
        failure = OSError(REPOSITORY_IO.errno.EBADF, "O_PATH descriptor")
        with mock.patch.object(
            REPOSITORY_IO.sys,
            "platform",
            "linux",
        ), mock.patch.object(
            REPOSITORY_IO.os,
            "listxattr",
            side_effect=failure,
            create=True,
        ), mock.patch.object(
            REPOSITORY_IO.os,
            "fstat",
            return_value=symlink_metadata,
        ):
            self.assertFalse(REPOSITORY_IO._descriptor_has_acl(41))

        with mock.patch.object(
            REPOSITORY_IO.sys,
            "platform",
            "linux",
        ), mock.patch.object(
            REPOSITORY_IO.os,
            "listxattr",
            side_effect=failure,
            create=True,
        ), mock.patch.object(
            REPOSITORY_IO.os,
            "fstat",
            return_value=regular_metadata,
        ):
            with self.assertRaisesRegex(
                ValueError,
                "repository_io_acl_probe_failed",
            ):
                REPOSITORY_IO._descriptor_has_acl(42)

    def test_acl_xattr_registry_covers_posix_nfs_cifs_and_nt_descriptors(self) -> None:
        names = (
            "system.posix_acl_access",
            "system.nfs4_acl",
            "system.richacl",
            "system.cifs_acl",
            "security.NTACL",
            b"security.NTACL",
            "com.apple.system.Security",
            "security.NT_SECURITY_DESCRIPTOR",
        )
        for name in names:
            with self.subTest(name=name), mock.patch.object(
                REPOSITORY_IO.os,
                "listxattr",
                return_value=[name],
                create=True,
            ):
                self.assertTrue(REPOSITORY_IO._descriptor_has_acl(0))

    def test_authority_rejects_network_fuse_and_unverified_overlay_filesystems(self) -> None:
        rejected = (
            "nfs",
            "nfs4",
            "cifs",
            "smb3",
            "9p",
            "fuse",
            "fuse.sshfs",
            "davfs",
            "overlay",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            for filesystem_type in rejected:
                with self.subTest(filesystem_type=filesystem_type), mock.patch.object(
                    REPOSITORY_IO,
                    "_authority_filesystem_type_from_resolution",
                    return_value=filesystem_type,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_filesystem_not_local",
                    ):
                        with REPOSITORY_IO.open_repository_io(Path(temp_dir)):
                            self.fail("nonlocal filesystem gained repository authority")

    def test_darwin_authority_requires_descriptor_observed_local_flag(self) -> None:
        resolution = mock.Mock()
        resolution.identity = mock.Mock(
            namespace="darwin_fstatfs",
            parts=(1, 2, 3, b"apfs", 0, b"/mount", b"/device"),
        )
        with mock.patch.object(REPOSITORY_IO.sys, "platform", "darwin"):
            with self.assertRaisesRegex(
                ValueError,
                "repository_io_filesystem_locality_unavailable",
            ):
                REPOSITORY_IO._authority_filesystem_type_from_resolution(resolution)
            resolution.identity.parts = (
                1,
                2,
                3,
                b"apfs",
                REPOSITORY_IO._DARWIN_MNT_LOCAL,
                b"/mount",
                b"/device",
            )
            self.assertEqual(
                REPOSITORY_IO._authority_filesystem_type_from_resolution(resolution),
                "apfs",
            )

    def test_linux_mountinfo_rejects_idmapped_local_filesystem(self) -> None:
        safe = b"42 31 8:1 / /repo rw,nosuid - ext4 /dev/sda1 rw\n"
        self.assertEqual(REPOSITORY_IO._mountinfo_filesystem_type(safe, 42), "ext4")
        for payload in (
            b"42 31 8:1 / /repo rw,nosuid idmapped - ext4 /dev/sda1 rw\n",
            b"42 31 8:1 / /repo rw,idmapped=1000 - ext4 /dev/sda1 rw\n",
            b"42 31 8:1 / /repo rw - ext4 /dev/sda1 rw,idmapped\n",
        ):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                ValueError,
                "repository_io_filesystem_idmapped",
            ):
                REPOSITORY_IO._mountinfo_filesystem_type(payload, 42)

    def test_validation_inventory_exposes_blocked_roots_prunes_git_and_revalidates(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            git = root / ".git"
            git.mkdir()
            os.symlink("/outside", git / "ignored-link")
            artifacts = root / "artifacts"
            artifacts.mkdir()
            self.write_file(root, "artifacts/not-descended.txt")
            self.write_file(root, "README.md")

            with REPOSITORY_IO.open_repository_io(root) as repository:
                inventory = REPOSITORY_IO._controller_validation_inventory(repository)
                paths = {str(item["path"]) for item in inventory}
                self.assertIn(".", paths)
                self.assertIn("artifacts", paths)
                self.assertIn("README.md", paths)
                self.assertNotIn("artifacts/not-descended.txt", paths)
                self.assertFalse(any(path == ".git" or path.startswith(".git/") for path in paths))

                self.write_file(root, "late.txt")
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_validation_inventory_changed|repository_io_owner_controlled_root_failed",
                ):
                    REPOSITORY_IO._controller_validation_inventory(repository)

    def test_validation_inventory_rejects_hardlink_and_nested_mount(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            victim = Path(outside_dir) / "victim.txt"
            victim.write_text("safe\n", encoding="utf-8")
            os.link(victim, root / "hardlinked.txt")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_inventory_untrusted_regular",
                ):
                    REPOSITORY_IO._controller_validation_inventory(repository)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "nested").mkdir()
            with REPOSITORY_IO.open_repository_io(root) as repository, mock.patch.object(
                REPOSITORY_IO,
                "require_same_repository_mount",
                side_effect=ValueError("repository_nested_mount_rejected"),
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_inventory_mount_escape",
                ):
                    REPOSITORY_IO._controller_validation_inventory(repository)

    def test_validation_inventory_binds_reads_against_swap_restore(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "evidence.txt", "original\n")
            original_metadata = target.stat()
            saved = root / "saved-original"
            with REPOSITORY_IO.open_repository_io(root) as repository:
                REPOSITORY_IO._controller_validation_inventory(repository)
                target.rename(saved)
                target.write_text("replaced\n", encoding="utf-8")
                target.chmod(0o644)
                os.utime(
                    target,
                    ns=(original_metadata.st_atime_ns, original_metadata.st_mtime_ns),
                )
                try:
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_file_identity_changed|repository_io_bound_identity_changed|repository_io_batch_identity_changed",
                    ):
                        REPOSITORY_IO._controller_read_bytes(
                            repository,
                            "evidence.txt",
                            required=True,
                        )
                finally:
                    target.unlink()
                    saved.rename(target)
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_validation_inventory_changed|repository_io_owner_controlled_root_failed",
                ):
                    REPOSITORY_IO._controller_validation_inventory(repository)

    def test_path_budget_counts_unique_paths_across_listing_and_reads(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md", "architecture\n")
            self.write_file(root, "AGENTS.md", "validation\n")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                max_paths=2,
                model_max_matches=2,
            )
            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                listing = repository.list_paths("intake")
                self.assertEqual(len(listing.paths), 2)
                self.assertTrue(repository.read_text("README.md").exists)
                self.assertTrue(repository.read_text("AGENTS.md").exists)
                with self.assertRaisesRegex(ValueError, "repository_io_path_budget_exceeded"):
                    REPOSITORY_IO._controller_engine(repository).path_kind("missing.md")

    def test_search_redacts_binary_evidence_instead_of_decoding_or_skipping_unsafely(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md", "architecture\n")
            (root / "image.bin").write_bytes(b"\xff\x00secret-like-binary")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                result = repository.search("intake")
            self.assertTrue(any(record["path"] == "README.md" for record in result.records))
            self.assertFalse(any(record["path"] == "image.bin" for record in result.records))

    def test_csf_2a0161737ddd8f9795805ece_secret_line_discovery_never_returns_lines(self) -> None:
        """Regression for PP-SECRET-005: discovery emits metadata, never raw matches."""

        fixture = "sk-" + "S" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            source = self.write_file(
                root,
                "README.md",
                f"architecture credential {fixture}\n",
            )
            # The raw source retains the original PoC condition: a line-based
            # grep/rg discovery would print the credential-bearing line.
            self.assertIn(fixture, source.read_text(encoding="utf-8"))
            with REPOSITORY_IO.open_repository_io(root) as repository:
                result = repository.search("intake")
            rendered = json.dumps(
                {
                    "records": result.records,
                    "receipt": result.receipt.as_dict(),
                },
                sort_keys=True,
            )
            self.assertNotIn(fixture, rendered)
            self.assertTrue(result.records)
            self.assertTrue(
                all(
                    set(record)
                    == {"path", "signal", "occurrence_count", "first_line"}
                    for record in result.records
                )
            )
            completed = subprocess.run(
                controller_cli_command(
                    "repository-io",
                    None,
                    [
                        "--root",
                        ".",
                        "search",
                        "--profile",
                        "intake",
                    ],
                ),
                cwd=root,
                env={**os.environ, "PWD": os.fspath(root.resolve())},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(fixture, completed.stdout + completed.stderr)

    def test_write_is_stage_allowlisted_cas_atomic_and_receipted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = "# Main Planing\n\nsafe body\n"
            second = "# Main Planing\n\nupdated safe body\n"
            with REPOSITORY_IO.open_repository_io(root) as repository:
                receipt = repository.write_planner_text(
                    "step1",
                    "Planner-docs/Main-Planing.md",
                    first,
                    "missing",
                )
                self.assertEqual(receipt.state, "committed")
                self.assertEqual(receipt.sha256, hashlib.sha256(first.encode()).hexdigest())

            target = root / "Planner-docs/Main-Planing.md"
            first_digest = hashlib.sha256(first.encode()).hexdigest()
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "planner_write_cas_mismatch"):
                    repository.write_planner_text(
                        "step1",
                        "Planner-docs/Main-Planing.md",
                        second,
                        "0" * 64,
                    )
                self.assertEqual(target.read_text(encoding="utf-8"), first)
                repository.write_planner_text(
                    "step1",
                    "Planner-docs/Main-Planing.md",
                    second,
                    first_digest,
                )
            self.assertEqual(target.read_text(encoding="utf-8"), second)
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)

    def test_write_present_cas_does_not_create_missing_parent_and_detects_concurrent_writer(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "planner_write_cas_mismatch"):
                    repository.write_planner_text(
                        "step1",
                        "Planner-docs/Main-Planing.md",
                        "safe\n",
                        "0" * 64,
                    )
            self.assertFalse((root / "Planner-docs").exists())

            self.write_file(root, "Planner-docs/Main-Planing.md", "before\n")
            target = root / "Planner-docs/Main-Planing.md"
            expected = hashlib.sha256(b"before\n").hexdigest()
            original = REPOSITORY_IO.atomic_write_bytes_at

            def concurrent_writer(*args, **kwargs):
                target.write_text("concurrent\n", encoding="utf-8")
                return original(*args, **kwargs)

            with REPOSITORY_IO.open_repository_io(root) as repository:
                with mock.patch.object(
                    REPOSITORY_IO,
                    "atomic_write_bytes_at",
                    side_effect=concurrent_writer,
                ):
                    with self.assertRaisesRegex(ValueError, "planner_write_cas_mismatch"):
                        repository.write_planner_text(
                            "step1",
                            "Planner-docs/Main-Planing.md",
                            "replacement\n",
                            expected,
                        )
            self.assertEqual(target.read_text(encoding="utf-8"), "concurrent\n")

    def test_write_rejects_non_allowlisted_receipt_secret_and_symlink_targets(self) -> None:
        fixture = "sk-" + "Z" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "victim.md", "preserve\n")
            (root / "Planner-docs").mkdir()
            (root / "Planner-docs/Main-Planing.md").symlink_to(root / "victim.md")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(ValueError, "planner_write_validator_owned_target"):
                    repository.write_planner_text(
                        "step1",
                        "Planner-docs/Step4-Readiness-Receipt.json",
                        "safe\n",
                        "missing",
                    )
                cases = (
                    lambda: repository.write_planner_text(
                        "step1", "README.md", "safe\n", "missing"
                    ),
                    lambda: repository.write_planner_text(
                        "step1",
                        "Planner-docs/Main-Planing.md",
                        fixture,
                        "missing",
                    ),
                    lambda: repository.write_planner_text(
                        "step1",
                        "Planner-docs/Main-Planing.md",
                        "safe\n",
                        "missing",
                    ),
                )
                for operation in cases:
                    try:
                        operation()
                    except ValueError as exc:
                        self.assertNotIn(fixture, str(exc))
                    else:
                        self.fail("unsafe planner write was accepted")
            self.assertEqual((root / "victim.md").read_text(encoding="utf-8"), "preserve\n")

    def test_csf_b1ff37f7abcd03a58db1e2e8_symlink_write_poc_is_fail_closed(self) -> None:
        """Regression for PP-WRITE-003: facade publication cannot follow a link."""

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "repository"
            (root / "Planner-docs").mkdir(parents=True)
            victim = self.write_file(Path(temp_dir), "outside-victim.md", "preserve\n")
            linked = root / "Planner-docs/Main-Planing.md"
            linked.symlink_to(victim)
            # Demonstrate the original unsafe write primitive on a disposable
            # fixture, then restore the canary before exercising the facade.
            linked.write_text("POC_FOLLOWED_LINK\n", encoding="utf-8")
            self.assertEqual(victim.read_text(encoding="utf-8"), "POC_FOLLOWED_LINK\n")
            victim.write_text("preserve\n", encoding="utf-8")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaises(ValueError):
                    repository.write_planner_text(
                        "step1",
                        "Planner-docs/Main-Planing.md",
                        "replacement\n",
                        "missing",
                    )
            self.assertEqual(victim.read_text(encoding="utf-8"), "preserve\n")

    def test_write_maps_ambiguous_io_failure_and_does_not_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with mock.patch.object(
                    REPOSITORY_IO,
                    "atomic_write_bytes_at",
                    side_effect=OSError("simulated fsync ambiguity"),
                ) as writer:
                    with self.assertRaisesRegex(ValueError, "artifact_commit_state_unknown"):
                        repository.write_planner_text(
                            "step1",
                            "Planner-docs/Main-Planing.md",
                            "safe\n",
                            "missing",
                        )
                    self.assertEqual(writer.call_count, 1)

    def test_custom_policy_name_and_budgets_are_bound_to_receipts(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md", "x" * 80)
            self.write_file(root, "a" * 40 + ".md", "safe")
            policy = REPOSITORY_IO.RepositoryIOPolicy(
                name="test-policy/v9",
                max_file_bytes=100,
                max_total_bytes=128,
                max_paths=3,
                timeout_seconds=5,
                model_max_file_bytes=100,
                model_max_total_bytes=128,
                model_max_matches=1,
                model_max_record_characters=32,
            )
            with REPOSITORY_IO.open_repository_io(root, policy) as repository:
                listing = repository.list_paths("intake")
                self.assertEqual(listing.receipt.bytes_scanned, 0)
                self.assertEqual(len(listing.paths) + len(listing.directories), 1)
                self.assertTrue(listing.receipt.truncated)
                self.assertEqual(listing.receipt.reason, "record_budget")
                evidence = repository.read_text("README.md")
                self.assertEqual(evidence.receipt.policy, "test-policy/v9")
                with self.assertRaisesRegex(ValueError, "repository_io_total_bytes_exceeded"):
                    repository.read_text("README.md")

    def test_cli_redacts_token_like_filename_from_all_output(self) -> None:
        fixture = "sk-" + "N" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, fixture + ".md", "safe architecture\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                listing = repository.list_paths("intake")
                search = repository.search("intake")
                rendered = json.dumps(
                    {
                        "paths": listing.paths,
                        "receipt": listing.receipt.as_dict(),
                        "records": search.records,
                        "search_receipt": search.receipt.as_dict(),
                    },
                    sort_keys=True,
                )
                self.assertNotIn(fixture, rendered)
            completed = subprocess.run(
                controller_cli_command(
                    "repository-io",
                    None,
                    [
                        "--root",
                        ".",
                        "inspect",
                        "--profile",
                        "intake",
                    ],
                ),
                cwd=root,
                env={**os.environ, "PWD": os.fspath(root.resolve())},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertNotIn(fixture, completed.stdout)
            self.assertNotIn(fixture, completed.stderr)
            self.assertIn("<redacted-path:", completed.stdout)

    def test_cli_rejects_every_noncanonical_root_grammar_before_open(self) -> None:
        cases = (
            ["inspect", "--profile", "intake"],
            ["--root", "/tmp", "inspect", "--profile", "intake"],
            ["--root", "..", "inspect", "--profile", "intake"],
            ["--root", "./", "inspect", "--profile", "intake"],
            ["--root=.", "inspect", "--profile", "intake"],
            ["--root", ".", "inspect", "--profile", "intake", "--root", "."],
        )
        for argv in cases:
            with self.subTest(argv=argv):
                stderr = io.StringIO()
                with (
                    mock.patch.object(
                        REPOSITORY_IO,
                        "_open_cli_repository_io_from_cwd",
                    ) as opener,
                    mock.patch.object(REPOSITORY_IO.sys, "stderr", stderr),
                ):
                    self.assertEqual(REPOSITORY_IO.main(list(argv)), 1)
                opener.assert_not_called()
                self.assertEqual(
                    stderr.getvalue(),
                    "repository_io_failed=repository_io_operation_failed\n",
                )

    def test_cli_rejects_logical_symlink_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repository"
            root.mkdir()
            self.write_file(root, "README.md", "architecture\n")
            logical = base / "logical-repository"
            logical.symlink_to(root, target_is_directory=True)
            completed = subprocess.run(
                controller_cli_command(
                    "repository-io",
                    None,
                    [
                        "--root",
                        ".",
                        "inspect",
                        "--profile",
                        "intake",
                    ],
                ),
                cwd=logical,
                env={**os.environ, "PWD": os.fspath(logical)},
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(completed.returncode, 1)
            self.assertEqual(completed.stdout, "")
            self.assertEqual(
                completed.stderr,
                "repository_io_failed=repository_io_operation_failed\n",
            )

    def test_cli_cwd_binding_rejects_bind_time_rename_and_swap(self) -> None:
        for swap in (False, True):
            with self.subTest(swap=swap), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                root = base / "repository"
                held = base / "held"
                replacement = base / "replacement"
                root.mkdir()
                if swap:
                    replacement.mkdir()
                previous_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
                renamed = False
                try:
                    os.chdir(root)
                    physical_root = Path(os.getcwd())
                    real_getcwd = os.getcwd
                    calls = 0

                    def rename_after_capture() -> str:
                        nonlocal calls, renamed
                        value = real_getcwd()
                        calls += 1
                        if calls == 1:
                            physical_root.rename(held)
                            if swap:
                                replacement.rename(physical_root)
                            renamed = True
                        return value

                    with (
                        mock.patch.dict(os.environ, {"PWD": os.fspath(physical_root)}),
                        mock.patch.object(
                            REPOSITORY_EVIDENCE.os,
                            "getcwd",
                            side_effect=rename_after_capture,
                        ),
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_cli_cwd_binding_failed",
                        ):
                            with REPOSITORY_EVIDENCE.open_repository_cwd_anchor():
                                self.fail("renamed CWD was accepted")
                finally:
                    os.fchdir(previous_fd)
                    os.close(previous_fd)
                    if renamed:
                        if swap and physical_root.exists():
                            physical_root.rename(replacement)
                        if held.exists():
                            held.rename(physical_root)

    def test_cli_bound_repository_rejects_post_bind_root_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            root = base / "repository"
            held = base / "held"
            replacement = base / "replacement"
            root.mkdir()
            replacement.mkdir()
            self.write_file(root, "README.md", "architecture original\n")
            self.write_file(replacement, "README.md", "architecture replacement\n")
            previous_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            swapped = False
            try:
                os.chdir(root)
                physical_root = Path(os.getcwd())
                with mock.patch.dict(os.environ, {"PWD": os.fspath(physical_root)}):
                    with REPOSITORY_IO._open_cli_repository_io_from_cwd() as repository:
                        physical_root.rename(held)
                        replacement.rename(physical_root)
                        swapped = True
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_(?:root_identity_changed|io_inventory_regular_identity_changed)",
                        ):
                            repository.list_paths("intake")
            finally:
                os.fchdir(previous_fd)
                os.close(previous_fd)
                if swapped:
                    physical_root.rename(replacement)
                    held.rename(physical_root)

    def test_search_binds_listed_identity_and_rejects_swap_read_restore_aba(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "README.md", "architecture original\n")
            replacement = self.write_file(root, "replacement.md", "architecture replacement\n")
            held = root / "held.md"
            original_reader = REPOSITORY_IO.read_regular_files_from_anchor

            def swap_read_restore(*args, **kwargs):
                target.rename(held)
                replacement.rename(target)
                try:
                    return original_reader(*args, **kwargs)
                finally:
                    target.rename(replacement)
                    held.rename(target)

            with REPOSITORY_IO.open_repository_io(root) as repository:
                repository.list_paths("intake")
                with mock.patch.object(
                    REPOSITORY_IO,
                    "read_regular_files_from_anchor",
                    side_effect=swap_read_restore,
                ):
                    with self.assertRaisesRegex(ValueError, "repository_io_read_identity_changed"):
                        repository.search("intake")

    def test_single_read_binds_precheck_identity_to_opened_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "README.md", "architecture original\n")
            replacement = self.write_file(
                root,
                "replacement.md",
                "architecture replacement\n",
            )
            held = root / "held.md"
            original_reader = REPOSITORY_IO.read_regular_files_from_anchor
            observed_expected_identities: list[object] = []

            def swap_read_restore(*args, **kwargs):
                observed_expected_identities.append(kwargs.get("expected_identities"))
                target.rename(held)
                replacement.rename(target)
                try:
                    return original_reader(*args, **kwargs)
                finally:
                    target.rename(replacement)
                    held.rename(target)

            with REPOSITORY_IO.open_repository_io(root) as repository:
                with mock.patch.object(
                    REPOSITORY_IO,
                    "read_regular_files_from_anchor",
                    side_effect=swap_read_restore,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_io_read_identity_changed",
                    ):
                        repository.read_text("README.md")

            self.assertEqual(len(observed_expected_identities), 1)
            self.assertIsInstance(observed_expected_identities[0], dict)
            self.assertIn("README.md", observed_expected_identities[0])

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_single_read_checks_acl_on_actual_payload_descriptor(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "README.md", "architecture original\n")
            original_reader = REPOSITORY_IO.read_regular_files_from_anchor
            real_open = REPOSITORY_EVIDENCE.os.open
            inner_errors: list[str] = []
            observed_validator: list[object] = []
            acl_applied = False

            def read_with_acl_inserted_after_precheck(*args, **kwargs):
                nonlocal acl_applied
                observed_validator.append(kwargs.get("descriptor_authority_validator"))

                def insert_acl_before_payload_open(path, flags, *open_args, **open_kwargs):
                    nonlocal acl_applied
                    if path == "README.md" and not acl_applied:
                        applied = subprocess.run(
                            [
                                chmod,
                                "+a",
                                "everyone allow read,write,append,delete",
                                target.as_posix(),
                            ],
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        if applied.returncode != 0:
                            raise unittest.SkipTest("extended ACL creation unavailable")
                        acl_applied = True
                    return real_open(path, flags, *open_args, **open_kwargs)

                with mock.patch.object(
                    REPOSITORY_EVIDENCE.os,
                    "open",
                    side_effect=insert_acl_before_payload_open,
                ):
                    try:
                        return original_reader(*args, **kwargs)
                    except ValueError as exc:
                        inner_errors.append(str(exc))
                        raise

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "read_regular_files_from_anchor",
                        side_effect=read_with_acl_inserted_after_precheck,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_read_identity_changed",
                        ):
                            repository.read_text("README.md")
                self.assertTrue(acl_applied)
                self.assertEqual(len(observed_validator), 1)
                self.assertTrue(callable(observed_validator[0]))
                self.assertEqual(
                    inner_errors,
                    ["repository_evidence_descriptor_authority_rejected"],
                )
            finally:
                subprocess.run(
                    [chmod, "-N", target.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_single_read_rejects_transient_repository_root_acl(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, "README.md", "architecture original\n")
            original_reader = REPOSITORY_IO.read_regular_files_from_anchor
            inner_errors: list[str] = []
            acl_applied = False

            def read_while_root_has_acl(*args, **kwargs):
                nonlocal acl_applied
                applied = subprocess.run(
                    [
                        chmod,
                        "+a",
                        "everyone allow read,write,append,delete,list,search",
                        root.as_posix(),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if applied.returncode != 0:
                    raise unittest.SkipTest("extended ACL creation unavailable")
                acl_applied = True
                try:
                    return original_reader(*args, **kwargs)
                except ValueError as exc:
                    inner_errors.append(str(exc))
                    raise
                finally:
                    subprocess.run(
                        [chmod, "-N", root.as_posix()],
                        capture_output=True,
                        check=False,
                    )

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "read_regular_files_from_anchor",
                        side_effect=read_while_root_has_acl,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_read_identity_changed",
                        ):
                            repository.read_text("README.md")
                self.assertTrue(acl_applied)
                self.assertEqual(
                    inner_errors,
                    ["repository_evidence_descriptor_authority_rejected"],
                )
            finally:
                subprocess.run(
                    [chmod, "-N", root.as_posix()],
                    capture_output=True,
                    check=False,
                )

    def test_read_many_and_snapshot_reject_mid_batch_mixed_generation(self) -> None:
        for operation in ("read_many", "snapshot_paths"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                self.write_file(root, "a.md", "old-a\n")
                second = self.write_file(root, "b.md", "old-b\n")
                original_reader = REPOSITORY_IO.read_regular_files_from_anchor
                calls = 0

                def mutate_after_first(*args, **kwargs):
                    nonlocal calls
                    result = original_reader(*args, **kwargs)
                    calls += 1
                    if calls == 1:
                        second.write_text("new-b\n", encoding="utf-8")
                    return result

                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "read_regular_files_from_anchor",
                        side_effect=mutate_after_first,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "repository_io_batch_identity_changed|repository_io_read_identity_changed",
                        ):
                            if operation == "read_many":
                                repository.read_many(["a.md", "b.md"])
                            else:
                                REPOSITORY_IO._controller_engine(repository).snapshot_paths(
                                    ["a.md", "b.md"]
                                )

    def test_write_native_cas_preserves_concurrent_missing_present_and_truncated_targets(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = root / "Planner-docs/Main-Planing.md"
            target.parent.mkdir()
            real_noreplace = ARTIFACT_IO._rename_noreplace

            def concurrent_create(directory_fd: int, temporary: str, name: str) -> None:
                target.write_text("concurrent missing\n", encoding="utf-8")
                real_noreplace(directory_fd, temporary, name)

            with REPOSITORY_IO.open_repository_io(root) as repository:
                with mock.patch.object(
                    ARTIFACT_IO,
                    "_rename_noreplace",
                    side_effect=concurrent_create,
                ):
                    with self.assertRaisesRegex(ValueError, "planner_write_cas_mismatch"):
                        repository.write_planner_text(
                            "step1",
                            "Planner-docs/Main-Planing.md",
                            "planner\n",
                            "missing",
                        )
            self.assertEqual(target.read_text(encoding="utf-8"), "concurrent missing\n")

            for mutation in ("replace", "truncate"):
                with self.subTest(mutation=mutation):
                    target.write_text("expected\n", encoding="utf-8")
                    expected = hashlib.sha256(b"expected\n").hexdigest()
                    real_exchange = ARTIFACT_IO._rename_exchange
                    calls = 0

                    def concurrent_change(directory_fd: int, temporary: str, name: str) -> None:
                        nonlocal calls
                        calls += 1
                        if calls == 1:
                            if mutation == "replace":
                                attacker = target.with_name("attacker.md")
                                attacker.write_text("concurrent present\n", encoding="utf-8")
                                os.replace(attacker, target)
                            else:
                                target.write_text("concurrent present\n", encoding="utf-8")
                        real_exchange(directory_fd, temporary, name)

                    with REPOSITORY_IO.open_repository_io(root) as repository:
                        with mock.patch.object(
                            ARTIFACT_IO,
                            "_rename_exchange",
                            side_effect=concurrent_change,
                        ):
                            with self.assertRaisesRegex(ValueError, "planner_write_cas_mismatch"):
                                repository.write_planner_text(
                                    "step1",
                                    "Planner-docs/Main-Planing.md",
                                    "planner\n",
                                    expected,
                                )
                    self.assertEqual(target.read_text(encoding="utf-8"), "concurrent present\n")

    def test_write_post_publish_content_and_ancestor_races_are_unknown(self) -> None:
        for race in ("content", "ancestor"):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                target = self.write_file(root, "Planner-docs/Main-Planing.md", "before\n")
                expected = hashlib.sha256(b"before\n").hexdigest()
                original_writer = REPOSITORY_IO.atomic_write_bytes_at

                def post_publish(*args, **kwargs):
                    published = original_writer(*args, **kwargs)
                    if race == "content":
                        target.write_text("post publish race\n", encoding="utf-8")
                    else:
                        detached = root / "detached-planner-docs"
                        target.parent.rename(detached)
                        target.parent.mkdir()
                    return published

                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "atomic_write_bytes_at",
                        side_effect=post_publish,
                    ) as writer:
                        with self.assertRaisesRegex(ValueError, "artifact_commit_state_unknown"):
                            repository.write_planner_text(
                                "step1",
                                "Planner-docs/Main-Planing.md",
                                "after\n",
                                expected,
                            )
                    self.assertEqual(writer.call_count, 1)

    def test_write_exchange_rollback_and_fsync_ambiguity_are_unknown_without_retry(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(root, "Planner-docs/Main-Planing.md", "expected\n")
            expected = hashlib.sha256(b"expected\n").hexdigest()
            real_exchange = ARTIFACT_IO._rename_exchange
            calls = 0

            def ambiguous_exchange(directory_fd: int, temporary: str, name: str) -> None:
                nonlocal calls
                calls += 1
                if calls == 1:
                    target.write_text("concurrent\n", encoding="utf-8")
                    real_exchange(directory_fd, temporary, name)
                    return
                raise OSError("synthetic rollback failure")

            with REPOSITORY_IO.open_repository_io(root) as repository:
                with mock.patch.object(
                    ARTIFACT_IO,
                    "_rename_exchange",
                    side_effect=ambiguous_exchange,
                ) as exchange:
                    with self.assertRaisesRegex(ValueError, "artifact_commit_state_unknown"):
                        repository.write_planner_text(
                            "step1",
                            "Planner-docs/Main-Planing.md",
                            "planner\n",
                            expected,
                        )
                self.assertEqual(exchange.call_count, 2)

        for failing_call in (1, 2):
            with self.subTest(fsync_call=failing_call), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                (root / "Planner-docs").mkdir()
                real_fsync = os.fsync
                calls = 0

                def fail_selected(descriptor: int) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == failing_call:
                        raise OSError("synthetic fsync failure")
                    real_fsync(descriptor)

                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(ARTIFACT_IO.os, "fsync", side_effect=fail_selected):
                        with self.assertRaisesRegex(ValueError, "artifact_commit_state_unknown"):
                            repository.write_planner_text(
                                "step1",
                                "Planner-docs/Main-Planing.md",
                                "planner\n",
                                "missing",
                            )

    def test_write_created_hierarchy_is_exact_mode_fsynced_and_failure_is_unknown(self) -> None:
        relative = "Planner-docs/Faz-1-Plans/Faz1.1-safe.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            previous = os.umask(0o777)
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    real_fsync = os.fsync
                    observed: list[int] = []

                    def observe(descriptor: int) -> None:
                        observed.append(descriptor)
                        real_fsync(descriptor)

                    with mock.patch.object(REPOSITORY_IO.os, "fsync", side_effect=observe):
                        repository.write_planner_text("step2", relative, "safe\n", "missing")
                self.assertGreaterEqual(len(observed), 6)
            finally:
                os.umask(previous)
            self.assertEqual((root / "Planner-docs").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / "Planner-docs/Faz-1-Plans").stat().st_mode & 0o777, 0o700)
            self.assertEqual((root / relative).stat().st_mode & 0o777, 0o600)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                real_fsync = os.fsync
                calls = 0

                def fail_root(descriptor: int) -> None:
                    nonlocal calls
                    calls += 1
                    if calls == 2:
                        raise OSError("synthetic parent fsync failure")
                    real_fsync(descriptor)

                with mock.patch.object(REPOSITORY_IO.os, "fsync", side_effect=fail_root):
                    with self.assertRaisesRegex(ValueError, "artifact_commit_state_unknown"):
                        repository.write_planner_text("step2", relative, "safe\n", "missing")

    def test_write_rejects_group_writable_and_acl_controlled_parent_directories(self) -> None:
        relative = "Planner-docs/Main-Planing.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "Planner-docs"
            parent.mkdir()
            parent.chmod(0o770)
            with REPOSITORY_IO.open_repository_io(root) as repository:
                with self.assertRaisesRegex(
                    ValueError,
                    "planner_write_parent_not_owner_controlled",
                ):
                    repository.write_planner_text("step1", relative, "safe\n", "missing")
            self.assertFalse((root / relative).exists())

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "Planner-docs"
            parent.mkdir(mode=0o700)
            if sys.platform == "darwin":
                command = [
                    shutil.which("chmod", path=os.defpath) or "",
                    "+a",
                    "everyone allow read,write,append,delete,list,search",
                    parent.as_posix(),
                ]
                cleanup = [command[0], "-N", parent.as_posix()]
            elif sys.platform.startswith("linux"):
                setfacl = shutil.which("setfacl", path=os.defpath)
                command = [
                    setfacl or "",
                    "-m",
                    f"u:{os.geteuid()}:rwx",
                    parent.as_posix(),
                ]
                cleanup = [setfacl or "", "-b", parent.as_posix()]
            else:
                self.skipTest("ACL mutation regression requires Darwin or Linux")
            if not command[0]:
                self.skipTest("ACL mutation tool unavailable")
            applied = subprocess.run(command, capture_output=True, text=True, check=False)
            if applied.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "planner_write_parent_not_owner_controlled",
                    ):
                        repository.write_planner_text(
                            "step1",
                            relative,
                            "safe\n",
                            "missing",
                        )
                self.assertFalse((root / relative).exists())
            finally:
                subprocess.run(cleanup, capture_output=True, check=False)

    def test_write_rejects_untrusted_repository_root_before_mutation(self) -> None:
        relative = "Planner-docs/Main-Planing.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            root.chmod(0o777)
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "planner_write_parent_not_owner_controlled",
                    ):
                        repository.write_planner_text(
                            "step1",
                            relative,
                            "safe\n",
                            "missing",
                        )
                self.assertFalse((root / "Planner-docs").exists())
            finally:
                root.chmod(0o700)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_write_rejects_repository_root_acl_before_mutation(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        relative = "Planner-docs/Main-Planing.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            applied = subprocess.run(
                [
                    chmod,
                    "+a",
                    "everyone allow read,write,append,delete,list,search",
                    root.as_posix(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if applied.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "planner_write_parent_not_owner_controlled",
                    ):
                        repository.write_planner_text(
                            "step1",
                            relative,
                            "safe\n",
                            "missing",
                        )
                self.assertFalse((root / "Planner-docs").exists())
            finally:
                subprocess.run(
                    [chmod, "-N", root.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_write_rejects_transient_root_acl_inside_parent_creation(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        relative = "Planner-docs/Main-Planing.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            original_open_or_create = REPOSITORY_IO.open_or_create_child_directory
            acl_applied = False

            def open_or_create_while_root_has_acl(*args, **kwargs):
                nonlocal acl_applied
                if not acl_applied:
                    applied = subprocess.run(
                        [
                            chmod,
                            "+a",
                            "everyone allow read,write,append,delete,list,search",
                            root.as_posix(),
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if applied.returncode != 0:
                        raise unittest.SkipTest("extended ACL creation unavailable")
                    acl_applied = True
                try:
                    return original_open_or_create(*args, **kwargs)
                finally:
                    subprocess.run(
                        [chmod, "-N", root.as_posix()],
                        capture_output=True,
                        check=False,
                    )

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "open_or_create_child_directory",
                        side_effect=open_or_create_while_root_has_acl,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "planner_write_parent_not_owner_controlled",
                        ):
                            repository.write_planner_text(
                                "step1",
                                relative,
                                "safe\n",
                                "missing",
                            )
                self.assertTrue(acl_applied)
                self.assertFalse((root / "Planner-docs").exists())
            finally:
                subprocess.run(
                    [chmod, "-N", root.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_write_rejects_existing_target_acl_without_replacement(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(
                root,
                "Planner-docs/Main-Planing.md",
                "expected\n",
            )
            expected = hashlib.sha256(b"expected\n").hexdigest()
            applied = subprocess.run(
                [
                    chmod,
                    "+a",
                    "everyone allow read,write,append,delete",
                    target.as_posix(),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if applied.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with self.assertRaisesRegex(
                        ValueError,
                        "planner_write_target_not_owner_controlled",
                    ):
                        repository.write_planner_text(
                            "step1",
                            "Planner-docs/Main-Planing.md",
                            "replacement\n",
                            expected,
                        )
                self.assertEqual(target.read_text(encoding="utf-8"), "expected\n")
            finally:
                subprocess.run(
                    [chmod, "-N", target.as_posix()],
                    capture_output=True,
                    check=False,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_write_rejects_acl_inserted_during_cas_without_replacement(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(
                root,
                "Planner-docs/Main-Planing.md",
                "expected\n",
            )
            expected = hashlib.sha256(b"expected\n").hexdigest()
            original_writer = REPOSITORY_IO.atomic_write_bytes_at
            acl_applied = False

            def insert_acl_before_atomic_cas(*args, **kwargs):
                nonlocal acl_applied
                applied = subprocess.run(
                    [
                        chmod,
                        "+a",
                        "everyone allow read,write,append,delete",
                        target.as_posix(),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if applied.returncode != 0:
                    raise unittest.SkipTest("extended ACL creation unavailable")
                acl_applied = True
                return original_writer(*args, **kwargs)

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        REPOSITORY_IO,
                        "atomic_write_bytes_at",
                        side_effect=insert_acl_before_atomic_cas,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "planner_write_cas_mismatch",
                        ):
                            repository.write_planner_text(
                                "step1",
                                "Planner-docs/Main-Planing.md",
                                "replacement\n",
                                expected,
                            )
                self.assertTrue(acl_applied)
                self.assertEqual(target.read_text(encoding="utf-8"), "expected\n")
            finally:
                if target.exists():
                    subprocess.run(
                        [chmod, "-N", target.as_posix()],
                        capture_output=True,
                        check=False,
                    )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_write_rolls_back_acl_inserted_at_exchange_boundary(self) -> None:
        chmod = shutil.which("chmod", path=os.defpath)
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_file(
                root,
                "Planner-docs/Main-Planing.md",
                "expected\n",
            )
            expected = hashlib.sha256(b"expected\n").hexdigest()
            real_exchange = ARTIFACT_IO._rename_exchange
            acl_applied = False

            def insert_acl_then_exchange(directory_fd: int, temporary: str, name: str) -> None:
                nonlocal acl_applied
                applied = subprocess.run(
                    [
                        chmod,
                        "+a",
                        "everyone allow read,write,append,delete",
                        target.as_posix(),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if applied.returncode != 0:
                    raise unittest.SkipTest("extended ACL creation unavailable")
                acl_applied = True
                real_exchange(directory_fd, temporary, name)

            try:
                with REPOSITORY_IO.open_repository_io(root) as repository:
                    with mock.patch.object(
                        ARTIFACT_IO,
                        "_rename_exchange",
                        side_effect=insert_acl_then_exchange,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "planner_write_cas_mismatch|artifact_commit_state_unknown",
                        ):
                            repository.write_planner_text(
                                "step1",
                                "Planner-docs/Main-Planing.md",
                                "replacement\n",
                                expected,
                            )
                self.assertTrue(acl_applied)
                self.assertEqual(target.read_text(encoding="utf-8"), "expected\n")
            finally:
                if target.exists():
                    subprocess.run(
                        [chmod, "-N", target.as_posix()],
                        capture_output=True,
                        check=False,
                    )

    def test_tracebacks_do_not_retain_secret_shaped_path_causes(self) -> None:
        fixture = "sk-" + "R" * 40
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_file(root, fixture, "not a directory\n")
            with REPOSITORY_IO.open_repository_io(root) as repository:
                try:
                    repository.read_text(f"{fixture}/child.md")
                except ValueError:
                    rendered = traceback.format_exc()
                else:
                    self.fail("secret-shaped non-directory parent was accepted")
            self.assertNotIn(fixture, rendered)


if __name__ == "__main__":
    unittest.main()
