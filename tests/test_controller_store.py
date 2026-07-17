from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import getpass
import importlib.util
import json
import errno
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_STORE = (
    REPO_ROOT
    / "plugins/codexqb/skills/codexqb/scripts/controller_store.py"
)


def load_controller_store_module():
    script_dir = str(CONTROLLER_STORE.parent)
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    spec = importlib.util.spec_from_file_location(
        "codexqb_controller_store_tests",
        CONTROLLER_STORE,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could_not_load_controller_store")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STORE = load_controller_store_module()
SAFE_TEST_HOME_PARENT = Path(
    STORE.pwd.getpwuid(STORE.controller_effective_uid()).pw_dir
).resolve()


def temporary_safe_home() -> tempfile.TemporaryDirectory[str]:
    return tempfile.TemporaryDirectory(
        prefix=".codexqb-test-home-",
        dir=SAFE_TEST_HOME_PARENT,
    )


class ControllerStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.home_directory = temporary_safe_home()
        self.home_path = Path(self.home_directory.name).resolve()
        os.chmod(self.home_path, 0o700)
        self.home_provider = mock.patch.object(
            STORE,
            "controller_home_directory",
            return_value=self.home_path,
        )
        self.home_provider.start()

    def tearDown(self) -> None:
        self.home_provider.stop()
        self.home_directory.cleanup()

    def repository(self, parent: Path, name: str = "repository") -> Path:
        root = parent / name
        root.mkdir()
        (root / "README.md").write_text("evidence\n", encoding="utf-8")
        return root

    def open_state(self, root: Path) -> Path:
        with STORE.open_repository_state(root, create=True) as (_descriptor, path):
            return path

    def test_repository_identity_consumer_rejects_group_writable_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            root.chmod(0o777)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "repository_io_owner_controlled_root_failed",
                ):
                    STORE.repository_identity(root)
            finally:
                root.chmod(0o700)

    def test_repository_identity_consumer_survives_safe_root_generation(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            identity_before = STORE.repository_identity(root)
            state_before = self.open_state(root)

            transient = root / ".transient"
            transient.write_bytes(b"temporary")
            transient.unlink()

            identity_after = STORE.repository_identity(root)
            state_after = self.open_state(root)
            self.assertEqual(identity_after, identity_before)
            self.assertEqual(state_after, state_before)

    def test_binding_is_hash_keyed_private_and_contains_no_raw_path(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            state = self.open_state(root)
            binding = state / STORE.REPOSITORY_BINDING_NAME
            payload_text = binding.read_text(encoding="utf-8")
            payload = json.loads(payload_text)

            self.assertFalse(state.resolve().is_relative_to(root.resolve()))
            self.assertEqual(state.name, STORE.repository_identity(root))
            self.assertNotIn(str(root), payload_text)
            self.assertEqual(
                set(payload),
                {
                    "binding_version",
                    "mount_assurance",
                    "mount_provider",
                    "repository_device",
                    "repository_identity",
                    "repository_inode",
                },
            )
            self.assertEqual(state.stat().st_mode & 0o777, 0o700)
            self.assertEqual(binding.stat().st_mode & 0o777, 0o600)
            self.assertEqual(binding.stat().st_nlink, 1)

    def test_foreign_binding_replay_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir)
            first = self.repository(parent, "first")
            second = self.repository(parent, "second")
            first_state = self.open_state(first)
            second_state = self.open_state(second)
            first_binding = first_state / STORE.REPOSITORY_BINDING_NAME
            second_binding = second_state / STORE.REPOSITORY_BINDING_NAME
            second_binding.write_bytes(first_binding.read_bytes())
            second_binding.chmod(0o600)

            with self.assertRaisesRegex(
                ValueError,
                "controller_repository_binding_mismatch",
            ):
                with STORE.open_repository_state(second, create=False):
                    self.fail("foreign binding replay was accepted")

    def test_relaxed_state_permissions_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            state = self.open_state(root)
            state.chmod(0o755)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_store_directory_not_private",
                ):
                    with STORE.open_repository_state(root, create=False):
                        self.fail("shared controller state was accepted")
            finally:
                state.chmod(0o700)

    def test_hardlinked_binding_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            state = self.open_state(root)
            binding = state / STORE.REPOSITORY_BINDING_NAME
            link = Path(temp_dir) / "binding-hardlink"
            os.link(binding, link)
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_repository_binding_invalid",
                ):
                    with STORE.open_repository_state(root, create=False):
                        self.fail("hardlinked binding was accepted")
            finally:
                link.unlink()

    def test_concurrent_first_open_publishes_one_valid_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))

            def open_once(_index: int) -> str:
                with STORE.open_repository_state(root, create=True) as (_fd, path):
                    return path.name

            with ThreadPoolExecutor(max_workers=8) as pool:
                identities = list(pool.map(open_once, range(24)))

            self.assertEqual(set(identities), {STORE.repository_identity(root)})
            state = STORE.controller_state_root(root)
            binding = state / STORE.REPOSITORY_BINDING_NAME
            self.assertEqual(binding.stat().st_nlink, 1)
            self.assertEqual(binding.stat().st_mode & 0o777, 0o600)

    def test_existing_unbound_identity_is_never_adopted(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            identity = STORE.repository_identity(root)
            with STORE.open_controller_store(create=True) as (_store_fd, store_path):
                state = store_path / identity
                state.mkdir(mode=0o700)
                payload = state / "goal-runs"
                payload.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                ValueError,
                "controller_repository_enrollment_recovery_required",
            ):
                with STORE.open_repository_state(root, create=True):
                    self.fail("preseeded repository state was adopted")
            self.assertFalse((state / STORE.REPOSITORY_BINDING_NAME).exists())
            self.assertTrue(payload.is_dir())

    def test_empty_orphan_identity_requires_recovery(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            identity = STORE.repository_identity(root)
            with STORE.open_controller_store(create=True) as (_store_fd, store_path):
                state = store_path / identity
                state.mkdir(mode=0o700)
            with self.assertRaisesRegex(
                ValueError,
                "controller_repository_enrollment_recovery_required",
            ):
                with STORE.open_repository_state(root, create=True):
                    self.fail("orphan repository identity was adopted")
            self.assertEqual(list(state.iterdir()), [])

    def test_environment_and_fake_home_do_not_redirect_production_store(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            hostile = root / "attacker-state"
            hostile.mkdir(mode=0o700)
            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(hostile),
                    "CODEXQB_CONTROLLER_STORE_ROOT": str(hostile),
                    "CODEXQB_TRUST_ROOT": str(hostile),
                },
            ):
                state = self.open_state(root)
            self.assertTrue(state.is_relative_to(self.home_path))
            self.assertFalse(state.is_relative_to(hostile))

    def test_store_inside_repository_is_rejected_by_descriptor_identity(self) -> None:
        with temporary_safe_home() as temp_dir:
            root = self.repository(Path(temp_dir).resolve())
            embedded_home = root / "home"
            embedded_home.mkdir(mode=0o700)
            with mock.patch.object(
                STORE,
                "controller_home_directory",
                return_value=embedded_home,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_store_must_be_outside_repository",
                ):
                    with STORE.open_repository_state(root, create=True):
                        self.fail("repository-contained controller store was accepted")

    def test_symlinked_home_component_is_rejected(self) -> None:
        with temporary_safe_home() as temp_dir:
            parent = Path(temp_dir).resolve()
            real_home = parent / "real-home"
            real_home.mkdir(mode=0o700)
            linked_home = parent / "linked-home"
            linked_home.symlink_to(real_home, target_is_directory=True)
            with mock.patch.object(
                STORE,
                "controller_home_directory",
                return_value=linked_home,
            ):
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_store_home_chain_invalid",
                ):
                    with STORE.open_controller_store(create=True):
                        self.fail("symlinked fixed-home component was accepted")

    @unittest.skipUnless(sys.platform == "darwin", "Darwin passwd-home ACL regression")
    def test_live_passwd_home_deny_only_acl_is_accepted(self) -> None:
        home = Path(
            STORE.pwd.getpwuid(STORE.controller_effective_uid()).pw_dir
        )
        opened = STORE._open_absolute_home_chain(home)
        try:
            self.assertEqual(
                (os.fstat(opened[-1]).st_dev, os.fstat(opened[-1]).st_ino),
                (home.stat().st_dev, home.stat().st_ino),
            )
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL regression")
    def test_home_acl_granting_access_is_rejected(self) -> None:
        chmod = shutil.which("chmod")
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            home = Path(temp_dir).resolve()
            home.chmod(0o700)
            result = subprocess.run(
                [chmod, "+a", f"user:{getpass.getuser()} allow write", str(home)],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with mock.patch.object(
                    STORE,
                    "controller_home_directory",
                    return_value=home,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "controller_store_home_chain_not_private",
                    ):
                        with STORE.open_controller_store(create=True):
                            self.fail("access-granting home ACL was accepted")
            finally:
                subprocess.run(
                    [chmod, "-N", str(home)],
                    check=False,
                    capture_output=True,
                )

    @unittest.skipUnless(sys.platform == "darwin", "Darwin final trust ACL regression")
    def test_final_trust_directory_rejects_even_deny_only_acl(self) -> None:
        chmod = shutil.which("chmod")
        if chmod is None:
            self.skipTest("chmod unavailable")
        with STORE.open_controller_store(create=True) as (_fd, store_path):
            trust = store_path.parent
        result = subprocess.run(
            [chmod, "+a", "group:everyone deny delete", str(trust)],
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.skipTest("extended ACL creation unavailable")
        try:
            with self.assertRaisesRegex(
                ValueError,
                "controller_store_directory_identity_changed|controller_store_acl_rejected",
            ):
                with STORE.open_controller_store(create=False):
                    self.fail("deny-only ACL on final trust root was accepted")
        finally:
            subprocess.run(
                [chmod, "-N", str(trust)],
                check=False,
                capture_output=True,
            )

    def test_default_store_accepts_read_only_shared_codex_parent_only(self) -> None:
        with temporary_safe_home() as temp_dir:
            home = Path(temp_dir) / "home"
            home.mkdir(mode=0o700)
            home = home.resolve()
            codex = home / ".codex"
            codex.mkdir(mode=0o755)
            configured = codex / "codexqb-trust" / STORE.CONTROLLER_STORE_DIR_NAME
            with mock.patch.object(
                STORE,
                "controller_home_directory",
                return_value=home,
            ):
                with STORE.open_controller_store(create=True) as (_fd, opened):
                    self.assertEqual(opened, configured)
            self.assertEqual((codex / "codexqb-trust").stat().st_mode & 0o777, 0o700)
            self.assertEqual(configured.stat().st_mode & 0o777, 0o700)

            for unsafe_mode in (0o775, 0o777):
                codex.chmod(unsafe_mode)
                try:
                    with mock.patch.object(
                        STORE,
                        "controller_home_directory",
                        return_value=home,
                    ):
                        with self.assertRaisesRegex(
                            ValueError,
                            "controller_store_directory_not_private",
                        ):
                            with STORE.open_controller_store(create=False):
                                self.fail("writable .codex parent was accepted")
                finally:
                    codex.chmod(0o755)

    def test_acl_query_errors_fail_closed_but_unsupported_xattrs_are_explicit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            descriptor = os.open(temp_dir, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    STORE.os,
                    "listxattr",
                    side_effect=OSError(errno.EIO, "synthetic ACL query failure"),
                    create=True,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "controller_store_acl_probe_failed",
                    ):
                        STORE._descriptor_has_acl(descriptor)
                with mock.patch.object(
                    STORE.os,
                    "listxattr",
                    side_effect=OSError(errno.ENOTSUP, "xattrs unsupported"),
                    create=True,
                ), mock.patch.object(STORE.sys, "platform", "linux"):
                    with self.assertRaisesRegex(
                        ValueError,
                        "controller_store_acl_probe_failed",
                    ):
                        STORE._descriptor_has_acl(descriptor)
                for acl_name in (
                    "system.nfs4_acl",
                    "system.richacl",
                    "system.cifs_acl",
                    "security.NTACL",
                    b"system.posix_acl_access",
                ):
                    with self.subTest(acl_name=acl_name), mock.patch.object(
                        STORE.os,
                        "listxattr",
                        return_value=[acl_name],
                        create=True,
                    ):
                        self.assertTrue(STORE._descriptor_has_acl(descriptor))
            finally:
                os.close(descriptor)

    def test_controller_mount_resolution_rejects_nonlocal_authority(self) -> None:
        resolution = mock.Mock()
        with mock.patch.object(
            STORE,
            "resolve_mount_identity",
            return_value=resolution,
        ), mock.patch.object(
            STORE,
            "require_mount_assurance",
        ), mock.patch.object(
            STORE,
            "_require_local_authority_mount_resolution",
            side_effect=ValueError("repository_io_filesystem_not_local"),
        ):
            with self.assertRaisesRegex(
                ValueError,
                "repository_io_filesystem_not_local",
            ):
                STORE.controller_resolve_mount_identity(7, reconcile=True)

    def test_darwin_null_acl_with_zero_errno_is_ambiguous_and_fails_closed(self) -> None:
        class FakeFunction:
            def __init__(self, result):
                self.result = result
                self.argtypes = None
                self.restype = None

            def __call__(self, *_args):
                return self.result

        fake_libc = type(
            "FakeLibc",
            (),
            {
                "acl_get_fd_np": FakeFunction(None),
                "acl_free": FakeFunction(0),
            },
        )()
        with mock.patch.object(STORE.sys, "platform", "darwin"), mock.patch.object(
            STORE.os, "listxattr", return_value=[], create=True
        ), mock.patch.object(STORE.ctypes, "CDLL", return_value=fake_libc), mock.patch.object(
            STORE.ctypes, "get_errno", return_value=0
        ), mock.patch.object(STORE.ctypes, "set_errno"):
            with self.assertRaisesRegex(ValueError, "controller_store_acl_probe_failed"):
                STORE._descriptor_has_acl(0)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support unavailable")
    def test_tree_regular_to_fifo_swap_is_nonblocking_and_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            root.chmod(0o700)
            victim = root / "victim.json"
            victim.write_text("{}\n", encoding="utf-8")
            victim.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            real_open = os.open
            swapped = False

            def swap_then_open(path, flags, *args, **kwargs):
                nonlocal swapped
                if path == "victim.json" and kwargs.get("dir_fd") == directory_fd and not swapped:
                    self.assertTrue(flags & getattr(os, "O_NONBLOCK", 0))
                    os.unlink(path, dir_fd=directory_fd)
                    os.mkfifo(path, 0o600, dir_fd=directory_fd)
                    swapped = True
                return real_open(path, flags, *args, **kwargs)

            try:
                with mock.patch.object(STORE.os, "open", side_effect=swap_then_open):
                    self.assertFalse(STORE.controller_tree_is_private(directory_fd))
                self.assertTrue(swapped)
            finally:
                os.close(directory_fd)

    def test_tree_depth_is_bounded_before_python_recursion_or_label_growth(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            root.chmod(0o700)
            root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            opened = [root_fd]
            try:
                current = root_fd
                for index in range(40):
                    name = f"d{index:02d}"
                    os.mkdir(name, 0o700, dir_fd=current)
                    child = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=current,
                    )
                    opened.append(child)
                    current = child
                self.assertFalse(
                    STORE.controller_tree_is_private(
                        root_fd,
                        max_entries=128,
                        max_depth=32,
                    )
                )
            finally:
                for descriptor in reversed(opened):
                    os.close(descriptor)

    def test_same_size_in_place_binding_rewrite_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            state = self.open_state(root)
            binding = state / STORE.REPOSITORY_BINDING_NAME
            binding_metadata = binding.stat()
            original_read = os.read
            mutated = False

            def mutate_after_read(descriptor: int, amount: int) -> bytes:
                nonlocal mutated
                data = original_read(descriptor, amount)
                metadata = os.fstat(descriptor)
                if metadata.st_ino == binding_metadata.st_ino and data and not mutated:
                    raw = binding.read_bytes()
                    marker = b'"repository_identity":"'
                    offset = raw.index(marker) + len(marker)
                    replacement = b"0" if raw[offset : offset + 1] != b"0" else b"1"
                    rewritten = raw[:offset] + replacement + raw[offset + 1 :]
                    self.assertEqual(len(rewritten), len(raw))
                    writer = os.open(binding, os.O_WRONLY | os.O_TRUNC)
                    try:
                        os.write(writer, rewritten)
                        os.fsync(writer)
                    finally:
                        os.close(writer)
                    mutated = True
                return data

            with mock.patch.object(STORE.os, "read", side_effect=mutate_after_read):
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_repository_binding_changed",
                ):
                    with STORE.open_repository_state(root, create=False):
                        self.fail("same-size binding rewrite was accepted")
            self.assertTrue(mutated)

    def test_repository_swap_during_state_open_cannot_bind_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            parent = Path(temp_dir).resolve()
            root = self.repository(parent, "repository")
            replacement = self.repository(parent, "replacement")
            held = parent / "held"
            original = STORE._open_child_directory
            swapped = False

            def swap_before_state_open(parent_fd, name, **kwargs):
                nonlocal swapped
                if re.fullmatch(r"[a-f0-9]{64}", name) and not swapped:
                    root.rename(held)
                    replacement.rename(root)
                    swapped = True
                return original(parent_fd, name, **kwargs)

            try:
                with mock.patch.object(
                    STORE,
                    "_open_child_directory",
                    side_effect=swap_before_state_open,
                ):
                    with self.assertRaisesRegex(
                        ValueError,
                        "repository_root_identity_changed|controller_repository_root_identity_changed|repository_io_root_proof_failed",
                    ):
                        with STORE.open_repository_state(root, create=True):
                            self.fail("replacement repository was bound")
            finally:
                if swapped:
                    root.rename(replacement)
                    held.rename(root)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_extended_acl_is_rejected(self) -> None:
        chmod = shutil.which("chmod")
        if chmod is None:
            self.skipTest("chmod unavailable")
        with tempfile.TemporaryDirectory() as temp_dir:
            root = self.repository(Path(temp_dir))
            state = self.open_state(root)
            result = subprocess.run(
                [chmod, "+a", f"user:{getpass.getuser()} allow read", str(state)],
                text=True,
                capture_output=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                with self.assertRaisesRegex(
                    ValueError,
                    "controller_store_directory_identity_changed|controller_store_acl_rejected",
                ):
                    with STORE.open_repository_state(root, create=False):
                        self.fail("extended ACL was accepted")
            finally:
                subprocess.run(
                    [chmod, "-N", str(state)],
                    check=False,
                    capture_output=True,
                )

    def test_controller_store_exposes_no_repository_path_recovery_map(self) -> None:
        self.assertFalse(hasattr(STORE, "register_active_run"))
        self.assertFalse(hasattr(STORE, "active_repository_root"))
        self.assertFalse(hasattr(STORE, "_ACTIVE_RUN_ROOTS"))


if __name__ == "__main__":
    unittest.main()
