from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_EVIDENCE_PATH = (
    REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/repository_evidence.py"
)


def load_repository_evidence_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_repository_evidence",
        REPOSITORY_EVIDENCE_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load repository_evidence from {REPOSITORY_EVIDENCE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EVIDENCE = load_repository_evidence_module()


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class RepositoryEvidenceTests(unittest.TestCase):
    def write_owned_file(self, root: Path, relative: str, content: bytes, mode: int = 0o644) -> Path:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        path.chmod(mode)
        return path

    def bindings(self) -> dict[str, object]:
        return {
            "apply_run_id": "apply-direct-test",
            "task_id": "AR-apply-direct-test-T001",
            "apply_run_registration_id": "a" * 64,
            "contract_digest": "b" * 64,
            "generation": 1,
            "review_package_sha256": "c" * 64,
        }

    def test_normalize_repo_relative_path_is_strict_and_cross_platform_deterministic(self) -> None:
        self.assertEqual(EVIDENCE.normalize_repo_relative_path("src/example.py"), "src/example.py")
        self.assertEqual(EVIDENCE.normalize_repo_relative_path(r"src\example.py"), "src/example.py")

        invalid = (
            "",
            ".",
            "..",
            "../escape",
            "src/../escape",
            "./src/example.py",
            "src//example.py",
            "/absolute",
            r"\absolute",
            r"C:\outside.txt",
            " src/example.py",
            "src/example.py ",
            "src/\x00example.py",
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaisesRegex(ValueError, "invalid_repository_relative_path"):
                    EVIDENCE.normalize_repo_relative_path(value)

        for value in (True, 1, b"src/example.py", Path("src/example.py"), None):
            with self.subTest(type=type(value).__name__):
                with self.assertRaisesRegex(TypeError, "repository_path_must_be_string"):
                    EVIDENCE.normalize_repo_relative_path(value)

    def test_snapshot_is_explicit_sorted_and_supports_missing_and_0644_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "zeta.txt", b"zeta\n", 0o644)
            self.write_owned_file(root, "nested/alpha.txt", b"alpha\n", 0o644)
            entries_before = sorted(path.relative_to(root).as_posix() for path in root.rglob("*"))

            snapshot = EVIDENCE.snapshot_allowed_paths(
                root,
                ["zeta.txt", "missing/child.txt", "nested/alpha.txt", "zeta.txt"],
            )

            self.assertEqual(
                [item["path"] for item in snapshot],
                ["missing/child.txt", "nested/alpha.txt", "zeta.txt"],
            )
            self.assertEqual(
                snapshot[0],
                {"path": "missing/child.txt", "state": "missing", "sha256": None, "size": None},
            )
            self.assertEqual(snapshot[1]["sha256"], sha256(b"alpha\n"))
            self.assertEqual(snapshot[1]["size"], len(b"alpha\n"))
            self.assertEqual(snapshot[2]["sha256"], sha256(b"zeta\n"))
            self.assertEqual(
                sorted(path.relative_to(root).as_posix() for path in root.rglob("*")),
                entries_before,
            )

    def test_git_snapshot_hashes_raw_regular_and_symlink_bytes_without_following(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            executable = self.write_owned_file(root, "bin/tool", b"#!/bin/sh\nexit 0\n", 0o755)
            link = root / "tool-link"
            link.symlink_to("bin/tool")

            snapshot = EVIDENCE.snapshot_git_paths(
                root,
                ["tool-link", "missing.txt", "bin/tool"],
                object_format="sha1",
            )
            by_path = {item["path"]: item for item in snapshot}

            executable_bytes = executable.read_bytes()
            expected_regular_oid = hashlib.sha1(
                f"blob {len(executable_bytes)}\0".encode("ascii") + executable_bytes
            ).hexdigest()
            target_bytes = b"bin/tool"
            expected_link_oid = hashlib.sha1(
                f"blob {len(target_bytes)}\0".encode("ascii") + target_bytes
            ).hexdigest()
            self.assertEqual(by_path["bin/tool"]["kind"], "regular")
            self.assertEqual(by_path["bin/tool"]["git_mode"], "100755")
            self.assertEqual(by_path["bin/tool"]["git_blob_oid"], expected_regular_oid)
            self.assertEqual(by_path["tool-link"]["kind"], "symlink")
            self.assertEqual(by_path["tool-link"]["git_mode"], "120000")
            self.assertEqual(by_path["tool-link"]["git_blob_oid"], expected_link_oid)
            self.assertEqual(by_path["tool-link"]["sha256"], sha256(target_bytes))
            self.assertEqual(by_path["missing.txt"]["kind"], "missing")

            with self.assertRaisesRegex(ValueError, "unsupported_git_object_format"):
                EVIDENCE.snapshot_git_paths(root, ["bin/tool"], object_format="md5")

    def test_repository_snapshot_enforces_path_and_total_byte_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "one.txt", b"1234")
            self.write_owned_file(root, "two.txt", b"5678")

            with self.assertRaisesRegex(ValueError, "repository_evidence_path_count_exceeded"):
                EVIDENCE.snapshot_git_paths(
                    root,
                    ["one.txt", "two.txt"],
                    object_format="sha1",
                    max_paths=1,
                )
            with self.assertRaisesRegex(ValueError, "repository_evidence_total_bytes_exceeded"):
                EVIDENCE.snapshot_git_paths(
                    root,
                    ["one.txt", "two.txt"],
                    object_format="sha1",
                    max_total_bytes=7,
                )

            bytes_read = 0
            real_read = os.read

            def counting_read(file_fd: int, size: int) -> bytes:
                nonlocal bytes_read
                encoded = real_read(file_fd, size)
                bytes_read += len(encoded)
                return encoded

            with mock.patch.object(EVIDENCE.os, "read", side_effect=counting_read):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_total_bytes_exceeded",
                ):
                    EVIDENCE.snapshot_git_paths(
                        root,
                        ["one.txt"],
                        object_format="sha1",
                        max_total_bytes=7,
                    )
            self.assertEqual(bytes_read, 4)
            self.assertEqual(
                EVIDENCE.snapshot_git_paths(
                    root,
                    ["one.txt"],
                    object_format="sha1",
                    max_total_bytes=8,
                )[0]["size"],
                4,
            )

            consumed: list[int] = []

            def excessive_paths():
                for position in range(1_000):
                    consumed.append(position)
                    yield "one.txt"

            with self.assertRaisesRegex(ValueError, "repository_evidence_path_count_exceeded"):
                EVIDENCE.snapshot_git_paths(
                    root,
                    excessive_paths(),
                    object_format="sha1",
                    max_paths=2,
                )
            self.assertEqual(consumed, [0, 1, 2])

    def test_repository_snapshot_deadline_covers_both_capture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "one.txt", b"1234")

            with mock.patch.object(
                EVIDENCE.time,
                "monotonic",
                side_effect=[0.0, 0.5, 2.0],
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_deadline_exceeded",
                ):
                    EVIDENCE.snapshot_allowed_paths(
                        root,
                        ["one.txt"],
                        timeout_seconds=1.0,
                    )

    def test_full_inventory_is_descriptor_bound_and_preserves_explicit_exclusions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            tracked = self.write_owned_file(root, "src/value.txt", b"before\n", 0o644)
            link = root / "value-link"
            link.symlink_to("src/value.txt")
            excluded = root / ".runtime"
            excluded.mkdir()
            (excluded / "oversized.bin").write_bytes(b"x" * 128)

            before = EVIDENCE.snapshot_repository_inventory(
                root,
                exclude=lambda path: path == ".runtime" or path.startswith(".runtime/"),
                max_bytes=32,
            )
            by_path = {entry["path"]: entry for entry in before}

            self.assertEqual(set(by_path), {"src", "src/value.txt", "value-link"})
            self.assertEqual(by_path["src"]["kind"], "directory")
            self.assertEqual(by_path["src/value.txt"]["kind"], "regular")
            self.assertEqual(by_path["src/value.txt"]["sha256"], sha256(b"before\n"))
            self.assertEqual(by_path["value-link"]["kind"], "symlink")
            self.assertNotIn(".runtime", by_path)

            tracked.write_bytes(b"after\n")
            tracked.chmod(0o755)
            link.unlink()
            link.symlink_to("other.txt")
            after = EVIDENCE.snapshot_repository_inventory(
                root,
                exclude=lambda path: path == ".runtime" or path.startswith(".runtime/"),
                max_bytes=32,
            )
            after_by_path = {entry["path"]: entry for entry in after}
            self.assertNotEqual(
                by_path["src/value.txt"]["fingerprint_sha256"],
                after_by_path["src/value.txt"]["fingerprint_sha256"],
            )
            self.assertNotEqual(
                by_path["value-link"]["fingerprint_sha256"],
                after_by_path["value-link"]["fingerprint_sha256"],
            )

    def test_full_inventory_enforces_per_file_shared_total_and_path_limits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "one.txt", b"1234")
            self.write_owned_file(root, "two.txt", b"5678")

            with self.assertRaisesRegex(ValueError, "repository_evidence_file_too_large"):
                EVIDENCE.snapshot_repository_inventory(root, max_bytes=3)
            with self.assertRaisesRegex(ValueError, "repository_evidence_total_bytes_exceeded"):
                EVIDENCE.snapshot_repository_inventory(root, max_total_bytes=15)
            with self.assertRaisesRegex(ValueError, "repository_evidence_path_count_exceeded"):
                EVIDENCE.snapshot_repository_inventory(root, max_paths=1)

            bytes_read = 0
            real_read = os.read

            def counting_read(file_fd: int, size: int) -> bytes:
                nonlocal bytes_read
                value = real_read(file_fd, size)
                bytes_read += len(value)
                return value

            with mock.patch.object(EVIDENCE.os, "read", side_effect=counting_read):
                with self.assertRaisesRegex(ValueError, "repository_evidence_total_bytes_exceeded"):
                    EVIDENCE.snapshot_repository_inventory(
                        root,
                        exclude=lambda path: path == "two.txt",
                        max_total_bytes=7,
                    )
            self.assertEqual(bytes_read, 4)

    def test_full_inventory_stops_scandir_before_buffering_past_path_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for position in range(10):
                self.write_owned_file(root, f"file-{position}.txt", b"x")
            real_scandir = EVIDENCE.os.scandir
            consumed = 0

            class CountingScandir:
                def __init__(self, directory_fd: int) -> None:
                    self.iterator = real_scandir(directory_fd)

                def __enter__(self):
                    return self

                def __exit__(self, *_args) -> None:
                    self.iterator.close()

                def __iter__(self):
                    return self

                def __next__(self):
                    nonlocal consumed
                    entry = next(self.iterator)
                    consumed += 1
                    return entry

            with mock.patch.object(
                EVIDENCE.os,
                "scandir",
                side_effect=CountingScandir,
            ):
                with self.assertRaisesRegex(ValueError, "repository_evidence_path_count_exceeded"):
                    EVIDENCE.snapshot_repository_inventory(root, max_paths=2)
            self.assertEqual(consumed, 3)

    def test_full_inventory_rejects_root_replacement_and_symlink_parent_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            parent = Path(temp_dir)
            root = parent / "root"
            root.mkdir()
            nested = root / "nested"
            nested.mkdir()
            self.write_owned_file(root, "nested/value.txt", b"inside\n")
            outside = Path(outside_dir)
            self.write_owned_file(outside, "secret.txt", b"outside\n")

            real_capture = EVIDENCE._capture_repository_inventory_pass
            calls = 0

            def swap_parent_after_first(*args, **kwargs):
                nonlocal calls
                result = real_capture(*args, **kwargs)
                calls += 1
                if calls == 1:
                    nested.rename(root / "nested-original")
                    nested.symlink_to(outside, target_is_directory=True)
                return result

            with mock.patch.object(
                EVIDENCE,
                "_capture_repository_inventory_pass",
                side_effect=swap_parent_after_first,
            ):
                with self.assertRaisesRegex(ValueError, "repository_inventory_changed_during_capture"):
                    EVIDENCE.snapshot_repository_inventory(root)

            nested.unlink()
            (root / "nested-original").rename(nested)
            moved = parent / "moved-root"
            replacement = parent / "root-replacement"
            replacement.mkdir()
            calls = 0

            def replace_root_after_first(*args, **kwargs):
                nonlocal calls
                result = real_capture(*args, **kwargs)
                calls += 1
                if calls == 1:
                    root.rename(moved)
                    replacement.rename(root)
                return result

            with mock.patch.object(
                EVIDENCE,
                "_capture_repository_inventory_pass",
                side_effect=replace_root_after_first,
            ):
                with self.assertRaisesRegex(ValueError, "repository_root_identity_changed"):
                    EVIDENCE.snapshot_repository_inventory(root)

    def test_full_inventory_rejects_same_device_nested_mount_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            nested = root / "nested"
            nested.mkdir()
            self.write_owned_file(root, "nested/external.txt", b"must not be read\n")

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                nested_metadata = os.stat(nested, follow_symlinks=False)
                real_mount_identity = EVIDENCE._descriptor_mount_identity

                def simulated_bind_mount(file_fd: int):
                    metadata = os.fstat(file_fd)
                    if metadata.st_ino == nested_metadata.st_ino:
                        return ("simulated_nested_mount", 2)
                    return real_mount_identity(file_fd)

                with mock.patch.object(
                    EVIDENCE,
                    "_descriptor_mount_identity",
                    side_effect=simulated_bind_mount,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=nested",
                    ):
                        EVIDENCE.snapshot_repository_inventory_from_anchor(anchor)

    def test_root_anchor_fails_closed_for_low_or_unavailable_mount_assurance(self) -> None:
        mount = EVIDENCE._mount_identity
        low_identity = mount.MountIdentity("filesystem_device", (7,))
        low_provider = mount.MountProviderResult(
            provider=mount.FILESYSTEM_FSTAT_PROVIDER,
            supported=True,
            identity=low_identity,
            assurance=mount.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
            failure_code=None,
        )
        low_resolution = mount.MountResolution(
            selected_provider=mount.FILESYSTEM_FSTAT_PROVIDER,
            identity=low_identity,
            assurance=mount.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
            providers=(low_provider,),
            failure_code=mount.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        )
        unavailable_provider = mount.MountProviderResult(
            provider=mount.LINUX_STATX_PROVIDER,
            supported=False,
            identity=None,
            assurance=mount.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_statx_syscall_unavailable",
        )
        unavailable_resolution = mount.MountResolution(
            selected_provider=None,
            identity=None,
            assurance=mount.MountAssurance.UNAVAILABLE,
            providers=(unavailable_provider,),
            failure_code=mount.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            for candidate in (low_resolution, unavailable_resolution):
                with self.subTest(assurance=candidate.assurance.value), mock.patch.object(
                    mount,
                    "resolve_mount_identity",
                    return_value=candidate,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "^secure_repository_mount_identity_unavailable$",
                    ):
                        with EVIDENCE.open_repository_root_anchor(Path(temp_dir)):
                            self.fail("low-assurance repository anchor was opened")

    def test_root_resolution_reconciles_then_revalidation_prefers_selected_provider(self) -> None:
        mount = EVIDENCE._mount_identity
        real_resolver = mount.resolve_mount_identity
        with tempfile.TemporaryDirectory() as temp_dir, mock.patch.object(
            mount,
            "resolve_mount_identity",
            wraps=real_resolver,
        ) as resolver:
            with EVIDENCE.open_repository_root_anchor(Path(temp_dir)) as anchor:
                self.assertIsInstance(anchor.mount_identity, tuple)
                self.assertIn(
                    anchor.mount_resolution.assurance,
                    (
                        mount.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
                        mount.MountAssurance.MOUNT_RECONCILED,
                    ),
                )
                first = resolver.call_args_list[0]
                self.assertIs(first.kwargs.get("reconcile"), True)
                resolver.reset_mock()

                EVIDENCE.revalidate_repository_root_anchor(anchor)

                self.assertTrue(resolver.called)
                last = resolver.call_args_list[-1]
                self.assertIs(last.kwargs.get("reconcile"), False)
                self.assertEqual(
                    last.kwargs.get("preferred_provider"),
                    anchor.mount_resolution.selected_provider,
                )

    def test_root_provider_identity_change_keeps_stable_external_error(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            with EVIDENCE.open_repository_root_anchor(Path(temp_dir)) as anchor:
                with mock.patch.object(
                    EVIDENCE,
                    "_descriptor_mount_identity",
                    return_value=("changed_mount_identity", 99),
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "^repository_root_mount_identity_changed$",
                    ):
                        EVIDENCE.revalidate_repository_root_anchor(anchor)

    def test_final_file_and_symlink_mounts_are_rejected_before_content_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            regular = self.write_owned_file(root, "mounted-file.txt", b"external bytes\n")
            link = root / "mounted-link"
            link.symlink_to("mounted-file.txt")
            regular_identity = os.stat(regular, follow_symlinks=False)
            link_identity = os.stat(link, follow_symlinks=False)

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                real_mount_identity = EVIDENCE._descriptor_mount_identity

                def simulated_file_mount(file_fd: int):
                    metadata = os.fstat(file_fd)
                    if metadata.st_ino == regular_identity.st_ino:
                        return ("simulated_file_mount", 2)
                    return real_mount_identity(file_fd)

                with mock.patch.object(
                    EVIDENCE,
                    "_descriptor_mount_identity",
                    side_effect=simulated_file_mount,
                ), mock.patch.object(EVIDENCE.os, "read") as read:
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=mounted-file.txt",
                    ):
                        EVIDENCE.snapshot_repository_inventory_from_anchor(
                            anchor,
                            exclude=lambda path: path == "mounted-link",
                        )
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=mounted-file.txt",
                    ):
                        EVIDENCE.snapshot_git_paths_from_anchor(
                            anchor,
                            ["mounted-file.txt"],
                            object_format="sha1",
                        )
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=mounted-file.txt",
                    ):
                        EVIDENCE.read_regular_files_from_anchor(
                            anchor,
                            ["mounted-file.txt"],
                        )
                    read.assert_not_called()

                def simulated_symlink_mount(file_fd: int):
                    metadata = os.fstat(file_fd)
                    if metadata.st_ino == link_identity.st_ino:
                        return ("simulated_symlink_mount", 3)
                    return real_mount_identity(file_fd)

                with mock.patch.object(
                    EVIDENCE,
                    "_descriptor_mount_identity",
                    side_effect=simulated_symlink_mount,
                ), mock.patch.object(EVIDENCE.os, "readlink") as readlink:
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=mounted-link",
                    ):
                        EVIDENCE.snapshot_repository_inventory_from_anchor(
                            anchor,
                            exclude=lambda path: path == "mounted-file.txt",
                        )
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_nested_mount_rejected=mounted-link",
                    ):
                        EVIDENCE.snapshot_git_paths_from_anchor(
                            anchor,
                            ["mounted-link"],
                            object_format="sha1",
                        )
                    readlink.assert_not_called()

    def test_regular_read_descriptor_authority_validator_observes_actual_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_owned_file(root, "evidence.txt", b"safe evidence\n")
            target_identity = os.stat(target, follow_symlinks=False)
            observed: list[tuple[str, int, int]] = []

            def accept(descriptor: int, path: str) -> bool:
                metadata = os.fstat(descriptor)
                observed.append((path, metadata.st_dev, metadata.st_ino))
                return True

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                payloads = EVIDENCE.read_regular_files_from_anchor(
                    anchor,
                    ["evidence.txt"],
                    descriptor_authority_validator=accept,
                )
                self.assertEqual(payloads[0].data, b"safe evidence\n")
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_descriptor_authority_rejected",
                ):
                    EVIDENCE.read_regular_files_from_anchor(
                        anchor,
                        ["evidence.txt"],
                        descriptor_authority_validator=lambda _fd, _path: False,
                    )

            self.assertEqual(
                observed,
                [
                    (".", os.stat(root, follow_symlinks=False).st_dev, os.stat(root, follow_symlinks=False).st_ino),
                    ("evidence.txt", target_identity.st_dev, target_identity.st_ino),
                    ("evidence.txt", target_identity.st_dev, target_identity.st_ino),
                    (".", os.stat(root, follow_symlinks=False).st_dev, os.stat(root, follow_symlinks=False).st_ino),
                ],
            )

    def test_regular_read_rejects_root_descriptor_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "evidence.txt", b"safe evidence\n")
            root_identity = os.stat(root, follow_symlinks=False)
            observed: list[tuple[int, int]] = []

            def reject_root(descriptor: int, path: str) -> bool:
                metadata = os.fstat(descriptor)
                if path == ".":
                    observed.append((metadata.st_dev, metadata.st_ino))
                    return False
                return True

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_descriptor_authority_rejected",
                ):
                    EVIDENCE.read_regular_files_from_anchor(
                        anchor,
                        ["evidence.txt"],
                        descriptor_authority_validator=reject_root,
                    )

            self.assertEqual(
                observed,
                [(root_identity.st_dev, root_identity.st_ino)],
            )

    def test_inventory_and_snapshot_authority_use_root_parent_and_file_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "nested"
            parent.mkdir()
            target = self.write_owned_file(root, "nested/evidence.txt", b"safe evidence\n")
            identities = {
                ".": os.stat(root, follow_symlinks=False),
                "nested": os.stat(parent, follow_symlinks=False),
                "nested/evidence.txt": os.stat(target, follow_symlinks=False),
            }

            for operation in ("inventory", "snapshot"):
                with self.subTest(operation=operation):
                    observed: set[tuple[str, int, int]] = set()

                    def accept(descriptor: int, path: str) -> bool:
                        metadata = os.fstat(descriptor)
                        observed.add((path, metadata.st_dev, metadata.st_ino))
                        return True

                    with EVIDENCE.open_repository_root_anchor(root) as anchor:
                        if operation == "inventory":
                            EVIDENCE.snapshot_repository_inventory_from_anchor(
                                anchor,
                                descriptor_authority_validator=accept,
                            )
                        else:
                            EVIDENCE.snapshot_git_paths_from_anchor(
                                anchor,
                                ["nested/evidence.txt"],
                                object_format="sha1",
                                descriptor_authority_validator=accept,
                            )

                    for path, metadata in identities.items():
                        self.assertIn(
                            (path, metadata.st_dev, metadata.st_ino),
                            observed,
                        )

    def test_snapshot_parent_authority_is_revalidated_after_use(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            parent = root / "nested"
            parent.mkdir()
            self.write_owned_file(root, "nested/evidence.txt", b"safe evidence\n")
            parent_identity = os.stat(parent, follow_symlinks=False)
            parent_calls: dict[tuple[int, str], int] = {}

            def reject_second_parent_observation(descriptor: int, path: str) -> bool:
                metadata = os.fstat(descriptor)
                if (
                    path == "nested"
                    and metadata.st_dev == parent_identity.st_dev
                    and metadata.st_ino == parent_identity.st_ino
                ):
                    key = (descriptor, path)
                    parent_calls[key] = parent_calls.get(key, 0) + 1
                    return parent_calls[key] == 1
                return True

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                budget = EVIDENCE._SnapshotBudget(
                    remaining_bytes=1024,
                    remaining_path_reads=1,
                    deadline=EVIDENCE.time.monotonic() + 5,
                )
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_descriptor_authority_rejected",
                ):
                    EVIDENCE._snapshot_one(
                        anchor.path,
                        anchor.fd,
                        anchor.metadata,
                        anchor.mount_identity,
                        anchor.mount_resolution.selected_provider,
                        anchor.component_fds,
                        anchor.component_metadata,
                        "nested/evidence.txt",
                        1024,
                        budget,
                        "sha1",
                        reject_second_parent_observation,
                    )

            self.assertEqual(max(parent_calls.values(), default=0), 2)

    def test_git_symlink_authority_validator_observes_actual_fd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "target.txt", b"safe evidence\n")
            link = root / "target-link"
            link.symlink_to("target.txt")
            link_identity = os.stat(link, follow_symlinks=False)
            observed: list[tuple[int, int]] = []

            def reject_symlink(descriptor: int, path: str) -> bool:
                metadata = os.fstat(descriptor)
                if path == "target-link":
                    observed.append((metadata.st_dev, metadata.st_ino))
                    return False
                return True

            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_evidence_descriptor_authority_rejected",
                ):
                    EVIDENCE.snapshot_git_paths_from_anchor(
                        anchor,
                        ["target-link"],
                        object_format="sha1",
                        descriptor_authority_validator=reject_symlink,
                    )

            self.assertEqual(
                observed,
                [(link_identity.st_dev, link_identity.st_ino)],
            )

    def test_change_manifest_classifies_add_modify_delete_and_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            modified = self.write_owned_file(root, "modified.txt", b"before\n")
            deleted = self.write_owned_file(root, "deleted.txt", b"deleted\n")
            self.write_owned_file(root, "unchanged.txt", b"same\n")
            allowed = ["unchanged.txt", "added.txt", "modified.txt", "deleted.txt"]
            before = EVIDENCE.snapshot_allowed_paths(root, allowed)

            self.write_owned_file(root, "added.txt", b"added\n")
            modified.write_bytes(b"after content\n")
            modified.chmod(0o644)
            deleted.unlink()
            after = EVIDENCE.snapshot_allowed_paths(root, allowed)
            manifest = EVIDENCE.build_change_manifest(before, after)

            by_path = {item["path"]: item for item in manifest}
            self.assertEqual([item["path"] for item in manifest], sorted(allowed))
            self.assertEqual(by_path["added.txt"]["state"], "add")
            self.assertIsNone(by_path["added.txt"]["before_sha256"])
            self.assertEqual(by_path["added.txt"]["after_sha256"], sha256(b"added\n"))
            self.assertEqual(by_path["added.txt"]["size"], len(b"added\n"))
            self.assertEqual(by_path["modified.txt"]["state"], "modify")
            self.assertEqual(by_path["modified.txt"]["before_sha256"], sha256(b"before\n"))
            self.assertEqual(by_path["modified.txt"]["after_sha256"], sha256(b"after content\n"))
            self.assertEqual(by_path["deleted.txt"]["state"], "delete")
            self.assertEqual(by_path["deleted.txt"]["before_sha256"], sha256(b"deleted\n"))
            self.assertIsNone(by_path["deleted.txt"]["after_sha256"])
            self.assertEqual(by_path["deleted.txt"]["size"], 0)
            self.assertEqual(by_path["unchanged.txt"]["state"], "unchanged")
            self.assertEqual(
                [item["path"] for item in EVIDENCE.changed_file_manifest(manifest)],
                ["added.txt", "deleted.txt", "modified.txt"],
            )
            self.assertRegex(EVIDENCE.changed_file_digest(manifest), r"^[a-f0-9]{64}$")

    def test_snapshot_manifest_and_digests_are_order_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            first = self.write_owned_file(root, "b.txt", b"before\n")
            self.write_owned_file(root, "a.txt", b"same\n")
            before = EVIDENCE.snapshot_allowed_paths(root, ["b.txt", "a.txt"])
            first.write_bytes(b"after\n")
            first.chmod(0o644)
            after = EVIDENCE.snapshot_allowed_paths(root, ["a.txt", "b.txt"])

            manifest = EVIDENCE.build_change_manifest(before, after)
            reversed_manifest = list(reversed(manifest))
            self.assertEqual(
                EVIDENCE.build_change_manifest(list(reversed(before)), list(reversed(after))),
                manifest,
            )
            self.assertEqual(EVIDENCE.baseline_digest(before), EVIDENCE.baseline_digest(list(reversed(before))))
            self.assertEqual(
                EVIDENCE.repository_snapshot_digest(after),
                EVIDENCE.repository_snapshot_digest(list(reversed(after))),
            )
            self.assertEqual(
                EVIDENCE.changed_file_digest(manifest),
                EVIDENCE.changed_file_digest(reversed_manifest),
            )

    def test_content_drift_changes_repository_state_digest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_owned_file(root, "src/value.py", b"VALUE = 0\n")
            baseline = EVIDENCE.snapshot_allowed_paths(root, ["src/value.py"])

            target.write_bytes(b"VALUE = 1\n")
            target.chmod(0o644)
            first = EVIDENCE.capture_repository_evidence(
                root,
                ["src/value.py"],
                baseline,
                **self.bindings(),
            )
            target.write_bytes(b"VALUE = 2\n")
            target.chmod(0o644)
            second = EVIDENCE.capture_repository_evidence(
                root,
                ["src/value.py"],
                baseline,
                **self.bindings(),
            )

            self.assertNotEqual(first["current_snapshot_digest"], second["current_snapshot_digest"])
            self.assertNotEqual(first["changed_files_digest"], second["changed_files_digest"])
            self.assertNotEqual(first["repository_state_digest"], second["repository_state_digest"])
            self.assertEqual(first["baseline_digest"], second["baseline_digest"])

    def test_snapshot_rejects_content_drift_between_capture_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            target = self.write_owned_file(root, "value.txt", b"first\n")
            real_snapshot_one = EVIDENCE._snapshot_one
            call_count = 0

            def mutate_after_first_snapshot(*args, **kwargs):
                nonlocal call_count
                result = real_snapshot_one(*args, **kwargs)
                call_count += 1
                if call_count == 1:
                    target.write_bytes(b"second\n")
                    target.chmod(0o644)
                return result

            with mock.patch.object(EVIDENCE, "_snapshot_one", side_effect=mutate_after_first_snapshot):
                with self.assertRaisesRegex(ValueError, "repository_snapshot_changed_during_capture"):
                    EVIDENCE.snapshot_allowed_paths(root, ["value.txt"])

    def test_repository_state_digest_binds_context_generation_and_review_patch(self) -> None:
        common = {
            **self.bindings(),
            "repository_baseline_digest": "d" * 64,
            "current_snapshot_digest": "e" * 64,
            "changed_files_digest": "f" * 64,
        }
        original = EVIDENCE.repository_state_digest(**common)
        variants = [
            {**common, "apply_run_id": "apply-other"},
            {**common, "task_id": "AR-other-T001"},
            {**common, "apply_run_registration_id": "0" * 64},
            {**common, "contract_digest": "1" * 64},
            {**common, "generation": 2},
            {**common, "review_package_sha256": "2" * 64},
            {**common, "repository_baseline_digest": "3" * 64},
            {**common, "current_snapshot_digest": "4" * 64},
            {**common, "changed_files_digest": "5" * 64},
        ]
        for variant in variants:
            with self.subTest(changed=[key for key in variant if variant[key] != common.get(key)]):
                self.assertNotEqual(EVIDENCE.repository_state_digest(**variant), original)

        with self.assertRaisesRegex(ValueError, "generation_must_be_nonnegative_integer"):
            EVIDENCE.repository_state_digest(**{**common, "generation": True})

    def test_snapshot_rejects_symlink_parent_and_final_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside = Path(outside_dir)
            victim = self.write_owned_file(outside, "victim.txt", b"outside secret\n", 0o600)
            (root / "parent-link").symlink_to(outside, target_is_directory=True)
            (root / "final-link").symlink_to(victim)

            with self.assertRaisesRegex(ValueError, "repository_path_parent_must_be_real_directory"):
                EVIDENCE.snapshot_allowed_paths(root, ["parent-link/victim.txt"])
            with self.assertRaisesRegex(
                ValueError,
                "repository_evidence_target_must_be_owner_controlled_regular_file",
            ):
                EVIDENCE.snapshot_allowed_paths(root, ["final-link"])

    def test_snapshot_rejects_fifo_without_blocking(self) -> None:
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo is unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            os.mkfifo(root / "evidence.fifo", 0o600)

            with self.assertRaisesRegex(
                ValueError,
                "repository_evidence_target_must_be_owner_controlled_regular_file",
            ):
                EVIDENCE.snapshot_allowed_paths(root, ["evidence.fifo"])

    def test_snapshot_rejects_group_writable_and_hard_linked_files(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            group_writable = self.write_owned_file(root, "group-writable.txt", b"unsafe\n", 0o664)
            original = self.write_owned_file(root, "original.txt", b"linked\n", 0o600)
            os.link(original, root / "second-link.txt")

            for path in (group_writable.name, original.name, "second-link.txt"):
                with self.subTest(path=path):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_evidence_target_must_be_owner_controlled_regular_file",
                    ):
                        EVIDENCE.snapshot_allowed_paths(root, [path])

    def test_snapshot_rejects_symlink_repository_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            real_root = parent / "real"
            real_root.mkdir()
            root_link = parent / "root-link"
            root_link.symlink_to(real_root, target_is_directory=True)

            with self.assertRaisesRegex(ValueError, "repository_root_must_be_real_directory"):
                EVIDENCE.snapshot_allowed_paths(root_link, ["missing.txt"])

    def test_root_anchor_rejects_symlinked_parent_and_ancestor_components(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            outside = base / "outside"
            (outside / "nested" / "repository").mkdir(parents=True)
            (outside / "repository").mkdir()

            cases = (
                ("parent-link", ("repository",)),
                ("ancestor-link", ("nested", "repository")),
            )
            for link_name, suffix in cases:
                with self.subTest(link_name=link_name):
                    link = base / link_name
                    link.symlink_to(outside, target_is_directory=True)
                    root = link.joinpath(*suffix)
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_root_must_be_real_directory",
                    ):
                        with EVIDENCE.open_repository_root_anchor(root):
                            self.fail("symlinked repository ancestor was accepted")

    def test_root_anchor_rejects_ancestor_swap_during_component_walk(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            trusted = base / "trusted"
            root = trusted / "project" / "repository"
            root.mkdir(parents=True)
            held = base / "trusted-held"
            replacement = base / "trusted-replacement"
            (replacement / "project" / "repository").mkdir(parents=True)
            original_identity = os.stat(root, follow_symlinks=False)
            real_open = EVIDENCE.os.open
            swapped = False

            def swap_ancestor_after_root_open(path, flags, *args, **kwargs):
                nonlocal swapped
                descriptor = real_open(path, flags, *args, **kwargs)
                opened = os.fstat(descriptor)
                if (
                    not swapped
                    and opened.st_dev == original_identity.st_dev
                    and opened.st_ino == original_identity.st_ino
                ):
                    trusted.rename(held)
                    replacement.rename(trusted)
                    swapped = True
                return descriptor

            try:
                with mock.patch.object(
                    EVIDENCE.os,
                    "open",
                    side_effect=swap_ancestor_after_root_open,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_root_must_be_real_directory",
                    ):
                        with EVIDENCE.open_repository_root_anchor(root):
                            self.fail("repository ancestor swap was accepted")
            finally:
                if swapped:
                    trusted.rename(replacement)
                    held.rename(trusted)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin platform alias")
    def test_root_anchor_accepts_canonical_darwin_var_alias(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            if not os.fspath(root).startswith("/var/"):
                self.skipTest("temporary directory is not exposed through /var")
            with EVIDENCE.open_repository_root_anchor(root) as anchor:
                self.assertEqual(
                    anchor.path,
                    Path("/private") / root.relative_to("/"),
                )
                self.assertEqual(
                    (anchor.metadata.st_dev, anchor.metadata.st_ino),
                    (root.stat().st_dev, root.stat().st_ino),
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin platform alias")
    def test_cwd_anchor_binds_darwin_var_pwd_to_physical_private_var(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            if not os.fspath(root).startswith("/var/"):
                self.skipTest("temporary directory is not exposed through /var")
            previous_fd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.chdir(root)
                with mock.patch.dict(os.environ, {"PWD": os.fspath(root)}):
                    with EVIDENCE.open_repository_cwd_anchor() as anchor:
                        self.assertEqual(
                            anchor.path,
                            Path("/private") / root.relative_to("/"),
                        )
                        self.assertEqual(
                            (anchor.metadata.st_dev, anchor.metadata.st_ino),
                            (root.stat().st_dev, root.stat().st_ino),
                        )
            finally:
                os.fchdir(previous_fd)
                os.close(previous_fd)

    def test_root_anchor_promotes_closed_stdio_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            script = """
import os
from pathlib import Path
import sys

sys.path.insert(0, sys.argv[1])
from repository_evidence import open_repository_root_anchor

try:
    os.close(0)
except OSError:
    pass
with open_repository_root_anchor(Path(sys.argv[2])) as anchor:
    if anchor.fd < 3:
        raise SystemExit(f"unsafe root fd: {anchor.fd}")
    if os.fstat(anchor.fd).st_ino != anchor.metadata.st_ino:
        raise SystemExit("root identity mismatch")
"""
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    script,
                    REPOSITORY_EVIDENCE_PATH.parent.as_posix(),
                    temp_dir,
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))

    def test_limits_and_container_types_reject_bool_and_string_tricks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "large.txt", b"12345", 0o600)

            with self.assertRaisesRegex(TypeError, "allowed_paths_must_be_iterable"):
                EVIDENCE.snapshot_allowed_paths(root, "large.txt")
            with self.assertRaisesRegex(TypeError, "allowed_paths_must_be_iterable"):
                EVIDENCE.snapshot_allowed_paths(root, {"large.txt": True})
            with self.assertRaisesRegex(TypeError, "repository_path_must_be_string"):
                EVIDENCE.snapshot_allowed_paths(root, [True])
            with self.assertRaisesRegex(TypeError, "max_bytes_must_be_positive_integer"):
                EVIDENCE.snapshot_allowed_paths(root, ["large.txt"], max_bytes=True)
            for timeout in (True, 0, float("inf"), float("nan")):
                with self.subTest(timeout=timeout):
                    with self.assertRaisesRegex(
                        TypeError,
                        "timeout_seconds_must_be_positive_number",
                    ):
                        EVIDENCE.snapshot_allowed_paths(
                            root,
                            ["large.txt"],
                            timeout_seconds=timeout,
                        )
            with self.assertRaisesRegex(ValueError, "repository_evidence_file_too_large"):
                EVIDENCE.snapshot_allowed_paths(root, ["large.txt"], max_bytes=4)

            valid = EVIDENCE.snapshot_allowed_paths(root, ["large.txt"])
            tampered = [{**valid[0], "size": True}]
            with self.assertRaisesRegex(ValueError, "invalid_repository_snapshot_entry"):
                EVIDENCE.baseline_digest(tampered)

    def test_capture_rejects_baseline_from_a_different_allowed_path_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            self.write_owned_file(root, "first.txt", b"first\n")
            baseline = EVIDENCE.snapshot_allowed_paths(root, ["first.txt"])

            with self.assertRaisesRegex(ValueError, "repository_baseline_allowed_path_mismatch"):
                EVIDENCE.capture_repository_evidence(
                    root,
                    ["first.txt", "second.txt"],
                    baseline,
                    **self.bindings(),
                )


if __name__ == "__main__":
    unittest.main()
