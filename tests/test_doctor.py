from __future__ import annotations

import importlib.util
import io
import json
import os
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
DOCTOR_PATH = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/doctor.py"
MOUNT_IDENTITY_PATH = (
    REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/mount_identity.py"
)
PLATFORM_PROBE_PATH = REPO_ROOT / "tests/platform/run_mount_identity_probe.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


DOCTOR = load_module("codexqb_doctor_tests", DOCTOR_PATH)
MOUNT_IDENTITY = load_module("codexqb_mount_identity_doctor_tests", MOUNT_IDENTITY_PATH)
PLATFORM_PROBE = load_module("codexqb_platform_probe_tests", PLATFORM_PROBE_PATH)


def provider(
    name: str,
    *,
    supported: bool,
    identity: object | None,
    assurance: str,
    failure_code: str | None = None,
    diagnostics: object | None = None,
):
    return SimpleNamespace(
        provider=name,
        supported=supported,
        identity=identity,
        assurance=assurance,
        failure_code=failure_code,
        diagnostics=diagnostics,
    )


def resolution(
    providers,
    *,
    selected_provider: str | None,
    identity: object | None,
    assurance: str,
    failure_code: str | None = None,
):
    return SimpleNamespace(
        selected_provider=selected_provider,
        identity=identity,
        assurance=assurance,
        providers=tuple(providers),
        failure_code=failure_code,
    )


class DoctorReportTests(unittest.TestCase):
    def ready_resolution(self):
        return resolution(
            (
                provider(
                    "linux_fdinfo",
                    supported=True,
                    identity=("linux_mount_id", 42),
                    assurance="mount_unique_descriptor_bound",
                    diagnostics={"raw": "/" + "Users/alice/private/repository"},
                ),
                provider(
                    "linux_statx_mnt_id",
                    supported=False,
                    identity=None,
                    assurance="unavailable",
                    failure_code="mount_provider_statx_symbol_unavailable",
                ),
            ),
            selected_provider="linux_fdinfo",
            identity=("linux_mount_id", 42),
            assurance="mount_unique_descriptor_bound",
        )

    def test_ready_json_is_deterministic_and_matches_golden_contract(self) -> None:
        report = DOCTOR.build_report(
            self.ready_resolution(),
            platform_name="linux",
            python_version=(3, 12),
        )
        expected = {
            "error_code": None,
            "mount_identity": {
                "providers": [
                    {
                        "assurance": "mount_unique_descriptor_bound",
                        "failure_code": None,
                        "provider": "linux_fdinfo",
                        "status": "available",
                        "supported": True,
                    },
                    {
                        "assurance": "unavailable",
                        "failure_code": "mount_provider_statx_symbol_unavailable",
                        "provider": "linux_statx_mnt_id",
                        "status": "expected_unsupported",
                        "supported": False,
                    },
                ],
                "failure_code": None,
                "selected_assurance": "mount_unique_descriptor_bound",
                "selected_provider": "linux_fdinfo",
            },
            "operations": {
                "blocked": [],
                "supported": list(DOCTOR.OPERATIONS),
            },
            "remediation": "No action required.",
            "runtime": {
                "os_family": "linux",
                "python": {"major": 3, "minor": 12},
            },
            "schema": "codexqb.doctor.capability-report",
            "status": "ready",
            "version": 1,
        }
        self.assertEqual(report, expected)
        self.assertEqual(
            DOCTOR.render_json(report),
            json.dumps(expected, indent=2, sort_keys=True, ensure_ascii=True),
        )
        self.assertEqual(DOCTOR.render_json(report), DOCTOR.render_json(report))

    def test_report_never_serializes_identity_diagnostics_paths_or_secret_values(self) -> None:
        secret = "fixture-token-value-never-print"
        hostile = resolution(
            (
                provider(
                    "/" + "Users/alice/private/provider",
                    supported=True,
                    identity={"trust_key": secret},
                    assurance="filesystem_identity_only",
                    failure_code=secret,
                    diagnostics={
                        "repository": "/" + "Users/alice/private/repository",
                        "trust_key": secret,
                    },
                ),
            ),
            selected_provider="/" + "Users/alice/private/provider",
            identity={"trust_key": secret},
            assurance="filesystem_identity_only",
            failure_code=secret,
        )
        report = DOCTOR.build_report(
            hostile,
            platform_name="darwin",
            python_version=(3, 14),
        )
        rendered = DOCTOR.render_json(report) + DOCTOR.render_human(report)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("/" + "Users/alice", rendered)
        self.assertNotIn("trust_key", rendered)
        self.assertNotIn('\n    "identity":', rendered)
        self.assertNotIn('"diagnostics"', rendered)
        self.assertEqual(
            report["mount_identity"]["providers"][0]["provider"],
            "unknown_provider",
        )

    def test_unavailable_capability_is_stable_expected_unsupported(self) -> None:
        unavailable = resolution(
            (
                provider(
                    "linux_fdinfo",
                    supported=False,
                    identity=None,
                    assurance="unavailable",
                    failure_code="mount_provider_fdinfo_unavailable",
                    diagnostics=("errno=enoent",),
                ),
                provider(
                    "filesystem_fstat",
                    supported=True,
                    identity=("filesystem", 7),
                    assurance="filesystem_identity_only",
                ),
            ),
            selected_provider="filesystem_fstat",
            identity=("filesystem", 7),
            assurance="filesystem_identity_only",
        )
        report = DOCTOR.build_report(
            unavailable,
            platform_name="linux",
            python_version=(3, 13),
        )
        self.assertEqual(report["status"], "expected_unsupported")
        self.assertEqual(report["error_code"], DOCTOR.EXTERNAL_MOUNT_ERROR)
        self.assertEqual(report["operations"]["supported"], [])
        self.assertEqual(report["operations"]["blocked"], list(DOCTOR.OPERATIONS))
        self.assertEqual(PLATFORM_PROBE.evaluate_report(report), (True, "expected_unsupported"))

    def test_advertised_high_assurance_provider_failure_is_not_hidden(self) -> None:
        failed = resolution(
            (
                provider(
                    "darwin_fstatfs",
                    supported=True,
                    identity=None,
                    assurance="unavailable",
                ),
            ),
            selected_provider=None,
            identity=None,
            assurance="unavailable",
        )
        report = DOCTOR.build_report(
            failed,
            platform_name="darwin",
            python_version=(3, 14),
        )
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(
            PLATFORM_PROBE.evaluate_report(report),
            (False, "advertised_provider_probe_failed"),
        )

    def test_real_provider_permission_failure_forces_probe_failed(self) -> None:
        failed_provider = MOUNT_IDENTITY.MountProviderResult(
            provider=MOUNT_IDENTITY.LINUX_STATX_PROVIDER,
            supported=False,
            identity=None,
            assurance=MOUNT_IDENTITY.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_statx_permission_denied",
            diagnostics=("errno=eperm",),
        )
        failed_resolution = MOUNT_IDENTITY.MountResolution(
            selected_provider=None,
            identity=None,
            assurance=MOUNT_IDENTITY.MountAssurance.UNAVAILABLE,
            providers=(failed_provider,),
            failure_code=MOUNT_IDENTITY.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        )
        report = DOCTOR.build_report(
            failed_resolution,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(
            report["mount_identity"]["providers"][0]["failure_code"],
            "mount_provider_statx_permission_denied",
        )
        self.assertNotIn("eperm", DOCTOR.render_json(report))

    def test_real_provider_request_unsupported_is_expected(self) -> None:
        unsupported_provider = MOUNT_IDENTITY.MountProviderResult(
            provider=MOUNT_IDENTITY.LINUX_STATX_PROVIDER,
            supported=False,
            identity=None,
            assurance=MOUNT_IDENTITY.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_statx_request_unsupported",
        )
        unsupported_resolution = MOUNT_IDENTITY.MountResolution(
            selected_provider=None,
            identity=None,
            assurance=MOUNT_IDENTITY.MountAssurance.UNAVAILABLE,
            providers=(unsupported_provider,),
            failure_code=MOUNT_IDENTITY.SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        )
        report = DOCTOR.build_report(
            unsupported_resolution,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertEqual(report["status"], "expected_unsupported")

    def test_malformed_provider_forces_failure_even_when_another_provider_succeeds(self) -> None:
        malformed = MOUNT_IDENTITY.MountProviderResult(
            provider=MOUNT_IDENTITY.LINUX_FDINFO_PROVIDER,
            supported=False,
            identity=None,
            assurance=MOUNT_IDENTITY.MountAssurance.UNAVAILABLE,
            failure_code="mount_provider_fdinfo_mnt_id_malformed",
        )
        identity = MOUNT_IDENTITY.MountIdentity("linux_mount_id", (42,))
        succeeded = MOUNT_IDENTITY.MountProviderResult(
            provider=MOUNT_IDENTITY.LINUX_STATX_PROVIDER,
            supported=True,
            identity=identity,
            assurance=MOUNT_IDENTITY.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
            failure_code=None,
        )
        mixed_resolution = MOUNT_IDENTITY.MountResolution(
            selected_provider=MOUNT_IDENTITY.LINUX_STATX_PROVIDER,
            identity=identity,
            assurance=MOUNT_IDENTITY.MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
            providers=(malformed, succeeded),
            failure_code=None,
        )
        report = DOCTOR.build_report(
            mixed_resolution,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(report["operations"]["supported"], [])

    def test_provider_conflict_forces_probe_failed(self) -> None:
        conflicted = resolution(
            (),
            selected_provider=None,
            identity=None,
            assurance="unavailable",
            failure_code="mount_identity_provider_conflict",
        )
        report = DOCTOR.build_report(
            conflicted,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(
            report["mount_identity"]["failure_code"],
            "mount_identity_provider_conflict",
        )

    def test_identity_from_provider_marked_unsupported_cannot_make_report_ready(self) -> None:
        contradictory = resolution(
            (
                provider(
                    "linux_statx_mnt_id",
                    supported=False,
                    identity=("linux_mount_id", 42),
                    assurance="mount_unique_descriptor_bound",
                ),
            ),
            selected_provider="linux_statx_mnt_id",
            identity=("linux_mount_id", 42),
            assurance="mount_unique_descriptor_bound",
        )
        report = DOCTOR.build_report(
            contradictory,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertNotEqual(report["status"], "ready")
        self.assertEqual(report["operations"]["supported"], [])

    def test_provider_order_is_preserved(self) -> None:
        ordered = resolution(
            (
                provider(
                    "linux_fdinfo",
                    supported=False,
                    identity=None,
                    assurance="unavailable",
                    failure_code="mount_provider_fdinfo_mnt_id_missing",
                ),
                provider(
                    "linux_statx_mnt_id",
                    supported=False,
                    identity=None,
                    assurance="unavailable",
                    failure_code="mount_provider_statx_symbol_unavailable",
                ),
                provider(
                    "linux_name_to_handle_at",
                    supported=False,
                    identity=None,
                    assurance="unavailable",
                    failure_code="mount_provider_name_to_handle_symbol_unavailable",
                ),
                provider(
                    "filesystem_fstat",
                    supported=True,
                    identity=("filesystem", 7),
                    assurance="filesystem_identity_only",
                ),
            ),
            selected_provider="filesystem_fstat",
            identity=("filesystem", 7),
            assurance="filesystem_identity_only",
        )
        report = DOCTOR.build_report(ordered, platform_name="linux", python_version=(3, 12))
        self.assertEqual(
            [item["provider"] for item in report["mount_identity"]["providers"]],
            [
                "linux_fdinfo",
                "linux_statx_mnt_id",
                "linux_name_to_handle_at",
                "filesystem_fstat",
            ],
        )


class DoctorCliTests(unittest.TestCase):
    def test_live_probe_uses_descriptor_and_reconcile_mode(self) -> None:
        calls: list[tuple[int, bool]] = []

        def resolve_mount_identity(file_descriptor: int, *, reconcile: bool):
            calls.append((file_descriptor, reconcile))
            os.fstat(file_descriptor)
            return DoctorReportTests().ready_resolution()

        fake_module = SimpleNamespace(resolve_mount_identity=resolve_mount_identity)
        report = DOCTOR.build_live_report(
            mount_identity_module=fake_module,
            platform_name="linux",
            python_version=(3, 12),
        )
        self.assertEqual(report["status"], "ready")
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0][1])
        with self.assertRaises(OSError):
            os.fstat(calls[0][0])

    def test_probe_exception_returns_stable_report_without_traceback_or_exception_text(self) -> None:
        secret = "secret-exception-value"

        def fail(_fd: int, *, reconcile: bool):
            raise RuntimeError(secret)

        report = DOCTOR.build_live_report(
            mount_identity_module=SimpleNamespace(resolve_mount_identity=fail),
            platform_name="linux",
            python_version=(3, 12),
        )
        rendered = DOCTOR.render_json(report)
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(report["error_code"], DOCTOR.EXTERNAL_MOUNT_ERROR)
        self.assertNotIn(secret, rendered)
        self.assertNotIn("Traceback", rendered)

    def test_missing_mount_module_has_stable_error_and_exit_behavior(self) -> None:
        with mock.patch.object(
            DOCTOR,
            "_load_mount_identity_module",
            side_effect=ImportError("private import location"),
        ):
            report = DOCTOR.build_live_report(
                platform_name="darwin",
                python_version=(3, 14),
            )
        self.assertEqual(report["status"], "probe_failed")
        self.assertEqual(report["error_code"], DOCTOR.EXTERNAL_MOUNT_ERROR)
        self.assertNotIn("private import location", DOCTOR.render_json(report))
        with mock.patch.object(DOCTOR, "build_live_report", return_value=report):
            self.assertEqual(
                DOCTOR.main(["--json"], stdout=io.StringIO(), stderr=io.StringIO()),
                1,
            )

    def test_json_and_human_cli_are_path_safe(self) -> None:
        ready = DOCTOR.build_report(
            DoctorReportTests().ready_resolution(),
            platform_name="linux",
            python_version=(3, 12),
        )
        for arguments in ([], ["--json"]):
            with self.subTest(arguments=arguments):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch.object(DOCTOR, "build_live_report", return_value=ready):
                    exit_code = DOCTOR.main(arguments, stdout=stdout, stderr=stderr)
                self.assertEqual(exit_code, 0)
                self.assertEqual(stderr.getvalue(), "")
                self.assertNotIn(os.fspath(Path.home()), stdout.getvalue())
                self.assertNotIn(os.fspath(Path.cwd()), stdout.getvalue())
                self.assertNotIn('\n    "identity":', stdout.getvalue())

    def test_unknown_argument_is_not_echoed(self) -> None:
        secret_argument = "--token=fixture-secret-never-print"
        stdout = io.StringIO()
        stderr = io.StringIO()
        exit_code = DOCTOR.main([secret_argument], stdout=stdout, stderr=stderr)
        self.assertEqual(exit_code, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(stderr.getvalue(), "codexqb-doctor: error: unsupported_argument\n")
        self.assertNotIn(secret_argument, stderr.getvalue())

    def test_probe_failed_cli_returns_one_but_expected_unsupported_returns_zero(self) -> None:
        failed = DOCTOR.build_report(
            DOCTOR._error_resolution("mount_identity_resolver", supported=True),
            platform_name="linux",
            python_version=(3, 12),
            probe_error_code="mount_identity_probe_failed",
        )
        unsupported = DOCTOR.build_report(
            resolution(
                (
                    provider(
                        "linux_fdinfo_mnt_id",
                        supported=False,
                        identity=None,
                        assurance="unavailable",
                        failure_code="mount_provider_platform_unsupported",
                    ),
                ),
                selected_provider=None,
                identity=None,
                assurance="unavailable",
                failure_code=DOCTOR.EXTERNAL_MOUNT_ERROR,
            ),
            platform_name="other",
            python_version=(3, 12),
        )
        for report, expected in ((failed, 1), (unsupported, 0)):
            with self.subTest(status=report["status"]):
                with mock.patch.object(DOCTOR, "build_live_report", return_value=report):
                    self.assertEqual(
                        DOCTOR.main([], stdout=io.StringIO(), stderr=io.StringIO()),
                        expected,
                    )


if __name__ == "__main__":
    unittest.main()
