from __future__ import annotations

import ctypes
import errno
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
MOUNT_IDENTITY_PATH = (
    REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/mount_identity.py"
)


def load_mount_identity_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_mount_identity_tests",
        MOUNT_IDENTITY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load mount_identity from {MOUNT_IDENTITY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MOUNT = load_mount_identity_module()


def supported_result(provider: str, value: int):
    return MOUNT.MountProviderResult(
        provider=provider,
        supported=True,
        identity=MOUNT.MountIdentity("linux_mount_id", (value,)),
        assurance=MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
        failure_code=None,
    )


def unavailable_result(provider: str, code: str = "mount_provider_platform_unsupported"):
    return MOUNT.MountProviderResult(
        provider=provider,
        supported=False,
        identity=None,
        assurance=MOUNT.MountAssurance.UNAVAILABLE,
        failure_code=code,
    )


class MountIdentityProviderTests(unittest.TestCase):
    def test_assurance_order_and_operation_policy_are_explicit(self) -> None:
        self.assertLess(
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.UNAVAILABLE],
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.FILESYSTEM_IDENTITY_ONLY],
        )
        self.assertLess(
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.FILESYSTEM_IDENTITY_ONLY],
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND],
        )
        self.assertLess(
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND],
            MOUNT.ASSURANCE_RANK[MOUNT.MountAssurance.MOUNT_RECONCILED],
        )
        self.assertEqual(
            set(MOUNT.OPERATION_MINIMUM_ASSURANCE),
            {
                MOUNT.READ_ONLY_EVIDENCE,
                MOUNT.NON_DESTRUCTIVE_ARTIFACT_CREATION,
                MOUNT.APPLY_RUN_MUTATION,
                MOUNT.RUN_REPLACE_QUARANTINE_DELETE,
            },
        )
        self.assertTrue(
            all(
                value is MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND
                for value in MOUNT.OPERATION_MINIMUM_ASSURANCE.values()
            )
        )

    def test_provider_result_contract_rejects_inconsistent_and_unsafe_diagnostics(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid_failed_mount_provider_result"):
            MOUNT.MountProviderResult(
                provider="provider",
                supported=True,
                identity=None,
                assurance=MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
                failure_code=None,
            )
        supported_failure = MOUNT.MountProviderResult(
            provider="provider",
            supported=True,
            identity=None,
            assurance=MOUNT.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_permission_denied",
        )
        self.assertTrue(supported_failure.supported)
        self.assertIsNone(supported_failure.identity)
        with self.assertRaisesRegex(ValueError, "unsafe_mount_diagnostic"):
            MOUNT.MountProviderResult(
                provider="provider",
                supported=False,
                identity=None,
                assurance=MOUNT.MountAssurance.UNAVAILABLE,
                failure_code="mount_provider_failed",
                diagnostics=("path=/" + "Users/example/private",),
            )

    def test_fdinfo_provider_accepts_one_bounded_positive_mount_id(self) -> None:
        result = MOUNT.probe_linux_fdinfo(
            7,
            reader=lambda fd: b"pos:\t0\nflags:\t0100000\nmnt_id:\t4242\nino:\t1\n",
            platform="linux",
        )
        self.assertTrue(result.supported)
        self.assertEqual(result.provider, MOUNT.LINUX_FDINFO_PROVIDER)
        self.assertEqual(result.identity, MOUNT.MountIdentity("linux_mount_id", (4242,)))
        self.assertEqual(result.assurance, MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND)

    def test_fdinfo_provider_classifies_missing_malformed_duplicate_and_oversized(self) -> None:
        cases = (
            (b"pos:\t0\n", "mount_provider_fdinfo_mnt_id_missing"),
            (b"mnt_id:\tbad\n", "mount_provider_fdinfo_mnt_id_malformed"),
            (b"mnt_id:\t1\nmnt_id:\t1\n", "mount_provider_fdinfo_mnt_id_duplicate"),
            (b"x" * (MOUNT.MAX_FDINFO_BYTES + 1), "mount_provider_fdinfo_oversized"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                result = MOUNT.probe_linux_fdinfo(
                    8,
                    reader=lambda fd, payload=payload: payload,
                    platform="linux",
                )
                self.assertTrue(result.supported)
                self.assertEqual(result.failure_code, expected)

    def test_fdinfo_provider_reports_unavailable_without_path_or_exception_text(self) -> None:
        def denied(_fd: int) -> bytes:
            raise PermissionError(errno.EACCES, "/private/repository")

        result = MOUNT.probe_linux_fdinfo(9, reader=denied, platform="linux")
        self.assertTrue(result.supported)
        self.assertEqual(result.failure_code, "mount_provider_fdinfo_unavailable")
        encoded = json.dumps(MOUNT.safe_provider_result_report(result), sort_keys=True)
        self.assertNotIn("private", encoded)
        self.assertNotIn("repository", encoded)
        self.assertIn("errno=eacces", encoded)

        def broken(_fd: int) -> bytes:
            raise RuntimeError("secret=/" + "Users/example/private")

        runtime_failure = MOUNT.probe_linux_fdinfo(
            9,
            reader=broken,
            platform="linux",
        )
        self.assertTrue(runtime_failure.supported)
        self.assertEqual(
            runtime_failure.failure_code,
            "mount_provider_backend_failed",
        )
        runtime_report = json.dumps(
            MOUNT.safe_provider_result_report(runtime_failure),
            sort_keys=True,
        )
        self.assertNotIn("secret", runtime_report)
        self.assertNotIn("Users", runtime_report)

    def test_statx_structure_matches_linux_uapi_mount_id_offset(self) -> None:
        self.assertEqual(ctypes.sizeof(MOUNT._LinuxStatx), 256)
        self.assertEqual(MOUNT._LinuxStatx.stx_mnt_id.offset, 144)

    def test_statx_provider_uses_empty_path_flag_mask_and_validates_result_mask(self) -> None:
        observed: dict[str, object] = {}

        def backend(fd, path, flags, mask, payload):
            observed.update(fd=fd, path=path, flags=flags, mask=mask)
            payload.stx_mask = MOUNT.STATX_MNT_ID
            payload.stx_mnt_id = 77
            return 0

        result = MOUNT.probe_linux_statx(10, backend=backend, platform="linux")
        self.assertTrue(result.supported)
        self.assertEqual(result.identity, MOUNT.MountIdentity("linux_mount_id", (77,)))
        self.assertEqual(
            observed,
            {"fd": 10, "path": b"", "flags": MOUNT.AT_EMPTY_PATH, "mask": MOUNT.STATX_MNT_ID},
        )

        def missing_mask(_fd, _path, _flags, _mask, payload):
            payload.stx_mnt_id = 77
            return 0

        missing = MOUNT.probe_linux_statx(10, backend=missing_mask, platform="linux")
        self.assertEqual(missing.failure_code, "mount_provider_statx_mnt_id_missing")

    def test_statx_provider_distinguishes_syscall_request_and_permission_failures(self) -> None:
        cases = (
            (errno.ENOSYS, "mount_provider_statx_syscall_unavailable", False),
            (errno.EINVAL, "mount_provider_statx_request_unsupported", False),
            (errno.EPERM, "mount_provider_statx_permission_denied", True),
        )
        for number, expected, supported in cases:
            with self.subTest(number=number):
                def backend(_fd, _path, _flags, _mask, _payload, number=number):
                    ctypes.set_errno(number)
                    return -1

                result = MOUNT.probe_linux_statx(11, backend=backend, platform="linux")
                self.assertEqual(result.failure_code, expected)
                self.assertEqual(result.supported, supported)

    def test_statx_provider_rejects_success_without_positive_mount_id(self) -> None:
        def backend(_fd, _path, _flags, _mask, payload):
            payload.stx_mask = MOUNT.STATX_MNT_ID
            payload.stx_mnt_id = 0
            return 0

        result = MOUNT.probe_linux_statx(12, backend=backend, platform="linux")
        self.assertTrue(result.supported)
        self.assertEqual(result.failure_code, "mount_provider_statx_mnt_id_malformed")

    def test_name_to_handle_provider_accepts_success_and_eoverflow_mount_ids(self) -> None:
        observed: list[tuple[bytes, int, int]] = []

        def success(_fd, path, handle, mount_id, flags):
            observed.append((path, handle.handle_bytes, flags))
            mount_id.value = 91
            return 0

        direct = MOUNT.probe_linux_name_to_handle_at(13, backend=success, platform="linux")
        self.assertTrue(direct.supported)
        self.assertEqual(direct.identity, MOUNT.MountIdentity("linux_mount_id", (91,)))

        def overflow(_fd, path, handle, mount_id, flags):
            observed.append((path, handle.handle_bytes, flags))
            handle.handle_bytes = 32
            mount_id.value = 92
            ctypes.set_errno(errno.EOVERFLOW)
            return -1

        sized = MOUNT.probe_linux_name_to_handle_at(13, backend=overflow, platform="linux")
        self.assertTrue(sized.supported)
        self.assertEqual(sized.identity, MOUNT.MountIdentity("linux_mount_id", (92,)))
        self.assertEqual(observed, [(b"", 0, MOUNT.AT_EMPTY_PATH), (b"", 0, MOUNT.AT_EMPTY_PATH)])

    def test_name_to_handle_provider_rejects_eoverflow_without_usable_mount_id(self) -> None:
        def overflow(_fd, _path, _handle, _mount_id, _flags):
            ctypes.set_errno(errno.EOVERFLOW)
            return -1

        result = MOUNT.probe_linux_name_to_handle_at(14, backend=overflow, platform="linux")
        self.assertEqual(result.failure_code, "mount_provider_name_to_handle_mnt_id_malformed")

    def test_name_to_handle_provider_classifies_filesystem_permission_and_request_failures(self) -> None:
        cases = (
            (errno.EOPNOTSUPP, "mount_provider_name_to_handle_filesystem_unsupported", False),
            (errno.EPERM, "mount_provider_name_to_handle_permission_denied", True),
            (errno.EINVAL, "mount_provider_name_to_handle_request_unsupported", False),
        )
        for number, expected, supported in cases:
            with self.subTest(number=number):
                def backend(_fd, _path, _handle, _mount_id, _flags, number=number):
                    ctypes.set_errno(number)
                    return -1

                result = MOUNT.probe_linux_name_to_handle_at(
                    15,
                    backend=backend,
                    platform="linux",
                )
                self.assertEqual(result.failure_code, expected)
                self.assertEqual(result.supported, supported)

    def test_darwin_fstatfs_provider_builds_opaque_identity(self) -> None:
        def backend(fd, payload):
            self.assertEqual(fd, 16)
            payload.f_fsid.value[0] = 10
            payload.f_fsid.value[1] = 20
            payload.f_type = 30
            payload.f_flags = MOUNT.DARWIN_MNT_LOCAL
            payload.f_fstypename = b"apfs"
            payload.f_mntonname = b"/" + b"Users/example/private"
            payload.f_mntfromname = b"/dev/disk-test"
            return 0

        result = MOUNT.probe_darwin_fstatfs(16, backend=backend, platform="darwin")
        self.assertTrue(result.supported)
        self.assertEqual(result.identity.namespace, "darwin_fstatfs")
        self.assertEqual(result.identity.parts[4], MOUNT.DARWIN_MNT_LOCAL)
        report = json.dumps(MOUNT.safe_provider_result_report(result), sort_keys=True)
        self.assertNotIn("Users", report)
        self.assertNotIn("disk-test", report)

    def test_darwin_fstatfs_provider_classifies_failure_and_empty_response(self) -> None:
        def failed(_fd, _payload):
            ctypes.set_errno(errno.EIO)
            return -1

        result = MOUNT.probe_darwin_fstatfs(17, backend=failed, platform="darwin")
        self.assertTrue(result.supported)
        self.assertEqual(result.failure_code, "mount_provider_fstatfs_call_failed")
        empty = MOUNT.probe_darwin_fstatfs(
            17,
            backend=lambda _fd, _payload: 0,
            platform="darwin",
        )
        self.assertTrue(empty.supported)
        self.assertEqual(empty.failure_code, "mount_provider_fstatfs_response_invalid")

    def test_platform_mismatch_is_explicit_not_supported(self) -> None:
        linux = MOUNT.probe_linux_fdinfo(1, reader=lambda _fd: b"mnt_id:\t1\n", platform="darwin")
        darwin = MOUNT.probe_darwin_fstatfs(1, backend=lambda _fd, _payload: 0, platform="linux")
        self.assertEqual(linux.failure_code, "mount_provider_platform_unsupported")
        self.assertEqual(darwin.failure_code, "mount_provider_platform_unsupported")

    def test_filesystem_fstat_is_explicitly_low_assurance(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            fd = os.open(temp_dir, os.O_RDONLY)
            try:
                result = MOUNT.probe_filesystem_fstat(fd)
            finally:
                os.close(fd)
        self.assertTrue(result.supported)
        self.assertEqual(result.assurance, MOUNT.MountAssurance.FILESYSTEM_IDENTITY_ONLY)


class MountIdentityResolverTests(unittest.TestCase):
    def provider(self, name: str, result):
        def call(_fd: int):
            return result
        call.provider_name = name
        return call

    def test_resolver_reconciles_agreeing_high_assurance_providers(self) -> None:
        first = self.provider("first", supported_result("first", 100))
        second = self.provider("second", supported_result("second", 100))
        resolution = MOUNT.resolve_mount_identity(3, providers=(first, second), reconcile=True)
        self.assertEqual(resolution.selected_provider, "first")
        self.assertEqual(resolution.assurance, MOUNT.MountAssurance.MOUNT_RECONCILED)
        self.assertEqual(resolution.identity, MOUNT.MountIdentity("linux_mount_id", (100,)))

    def test_resolver_fails_closed_on_provider_conflict(self) -> None:
        first = self.provider("first", supported_result("first", 100))
        second = self.provider("second", supported_result("second", 101))
        resolution = MOUNT.resolve_mount_identity(3, providers=(first, second), reconcile=True)
        self.assertIsNone(resolution.identity)
        self.assertEqual(resolution.assurance, MOUNT.MountAssurance.UNAVAILABLE)
        self.assertEqual(resolution.failure_code, "mount_identity_provider_conflict")
        with self.assertRaisesRegex(
            MOUNT.MountIdentityError,
            MOUNT.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        ):
            MOUNT.require_mount_assurance(resolution, MOUNT.APPLY_RUN_MUTATION)

    def test_non_reconciled_resolver_stops_at_first_high_provider(self) -> None:
        calls: list[str] = []

        def first(_fd):
            calls.append("first")
            return supported_result("first", 100)

        def second(_fd):
            calls.append("second")
            return supported_result("second", 101)

        resolution = MOUNT.resolve_mount_identity(3, providers=(first, second), reconcile=False)
        self.assertEqual(calls, ["first"])
        self.assertEqual(resolution.assurance, MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND)

    def test_resolver_reports_low_assurance_without_silent_upgrade(self) -> None:
        low = MOUNT.MountProviderResult(
            provider="low",
            supported=True,
            identity=MOUNT.MountIdentity("filesystem_device", (1,)),
            assurance=MOUNT.MountAssurance.FILESYSTEM_IDENTITY_ONLY,
            failure_code=None,
        )
        resolution = MOUNT.resolve_mount_identity(
            3,
            providers=(self.provider("high", unavailable_result("high")), self.provider("low", low)),
        )
        self.assertEqual(resolution.assurance, MOUNT.MountAssurance.FILESYSTEM_IDENTITY_ONLY)
        self.assertEqual(resolution.failure_code, MOUNT.SECURE_MOUNT_IDENTITY_UNAVAILABLE)
        for operation in MOUNT.OPERATION_MINIMUM_ASSURANCE:
            with self.subTest(operation=operation):
                with self.assertRaisesRegex(
                    MOUNT.MountIdentityError,
                    MOUNT.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
                ):
                    MOUNT.require_mount_assurance(resolution, operation)

    def test_all_unavailable_and_provider_exception_are_safe(self) -> None:
        unavailable = MOUNT.resolve_mount_identity(
            3,
            providers=(self.provider("first", unavailable_result("first")),),
        )
        self.assertEqual(unavailable.failure_code, MOUNT.SECURE_MOUNT_IDENTITY_UNAVAILABLE)

        def broken(_fd):
            raise RuntimeError("secret=/" + "Users/example/private")

        broken.provider_name = "broken"
        resolution = MOUNT.resolve_mount_identity(3, providers=(broken,))
        report = json.dumps(MOUNT.safe_resolution_report(resolution), sort_keys=True)
        self.assertNotIn("secret", report)
        self.assertNotIn("Users", report)
        self.assertIn("provider_exception", report)

    def test_supported_probe_failure_is_not_selected_or_downgraded_to_unsupported(self) -> None:
        failed = MOUNT.MountProviderResult(
            provider="advertised",
            supported=True,
            identity=None,
            assurance=MOUNT.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_runtime_failed",
        )
        resolution = MOUNT.resolve_mount_identity(
            3,
            providers=(self.provider("advertised", failed),),
        )
        self.assertIsNone(resolution.selected_provider)
        self.assertIsNone(resolution.identity)
        self.assertEqual(resolution.failure_code, "mount_identity_provider_probe_failed")
        report = MOUNT.safe_resolution_report(resolution)
        self.assertEqual(report["providers"][0]["supported"], True)
        self.assertEqual(
            report["providers"][0]["failure_code"],
            "mount_provider_runtime_failed",
        )

    def test_require_same_mount_accepts_equal_and_rejects_different_identity(self) -> None:
        root_provider = self.provider("same", supported_result("same", 500))
        root = MOUNT.resolve_mount_identity(3, providers=(root_provider,), reconcile=False)
        child = MOUNT.require_same_mount(root, 4, "nested", providers=(root_provider,))
        self.assertEqual(child.identity, root.identity)

        different = self.provider("different", supported_result("different", 501))
        with self.assertRaisesRegex(ValueError, "repository_nested_mount_rejected=nested"):
            MOUNT.require_same_mount(root, 4, "nested", providers=(different,))

    def test_require_same_mount_rejects_unsafe_error_path(self) -> None:
        provider = self.provider("same", supported_result("same", 500))
        root = MOUNT.resolve_mount_identity(3, providers=(provider,), reconcile=False)
        for path in ("/absolute", "../escape", "nested\\escape", "nested\nsecret"):
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "invalid_repository_relative_path"):
                    MOUNT.require_same_mount(root, 4, path, providers=(provider,))

    def test_safe_resolution_report_never_serializes_identity_parts(self) -> None:
        raw = MOUNT.MountProviderResult(
            provider="private_provider",
            supported=True,
            identity=MOUNT.MountIdentity(
                "darwin_fstatfs",
                (1, 2, b"/" + b"Users/example/private", b"token-value"),
            ),
            assurance=MOUNT.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
            failure_code=None,
        )
        resolution = MOUNT.resolve_mount_identity(
            3,
            providers=(self.provider("private_provider", raw),),
            reconcile=False,
        )
        encoded = json.dumps(MOUNT.safe_resolution_report(resolution), sort_keys=True)
        self.assertNotIn("Users", encoded)
        self.assertNotIn("token-value", encoded)
        self.assertIn('"identity_present": true', encoded)

    def test_unknown_operation_and_invalid_descriptor_fail_stably(self) -> None:
        resolution = MOUNT.resolve_mount_identity(-1)
        self.assertEqual(resolution.failure_code, MOUNT.SECURE_MOUNT_IDENTITY_UNAVAILABLE)
        with self.assertRaisesRegex(ValueError, "unknown_mount_operation"):
            MOUNT.require_mount_assurance(resolution, "unknown")


if __name__ == "__main__":
    unittest.main()
