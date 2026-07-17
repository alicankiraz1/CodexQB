from __future__ import annotations

import ast
import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_CONTROLLER_PATHS = {
    "scripts/issue_trusted_source_authority.py",
    "scripts/run_extracted_validation.py",
    "scripts/validate.sh",
}
FORBIDDEN_FOLDED = {value.casefold() for value in FORBIDDEN_CONTROLLER_PATHS}
RUN_EXTRACTED_VALIDATION_PATH = REPO_ROOT / "scripts/run_extracted_validation.py"


def load_run_extracted_validation_module():
    name = "codexqb_run_extracted_validation_output_tests"
    spec = importlib.util.spec_from_file_location(name, RUN_EXTRACTED_VALIDATION_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("run_extracted_validation_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUN_EXTRACTED_VALIDATION = load_run_extracted_validation_module()


class TrustedComponentOutputTests(unittest.TestCase):
    @staticmethod
    def synthetic_secret(marker: str) -> str:
        label = "".join(chr(value) for value in (112, 97, 115, 115, 119, 111, 114, 100, 61))
        return label + marker * 40

    def run_component(
        self,
        code: str,
        *,
        failure_code: str = "synthetic_component_failed",
        output_limit: int | None = None,
    ) -> tuple[dict[str, object] | None, BaseException | None, bytes, bytes]:
        stdout = bytearray()
        stderr = bytearray()

        def capture(descriptor: int, data: bytes) -> None:
            target = stdout if descriptor == 1 else stderr
            target.extend(data)

        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryFile(
            mode="w+b"
        ) as held:
            root = Path(temp_dir)
            root_descriptor = os.open(
                root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            controller_temp = root / "controller"
            controller_temp.mkdir(mode=0o700)
            previous_stream = RUN_EXTRACTED_VALIDATION._HELD_CODE_STREAM
            RUN_EXTRACTED_VALIDATION._HELD_CODE_STREAM = held
            patches = [
                mock.patch.object(
                    RUN_EXTRACTED_VALIDATION,
                    "_forward_output",
                    side_effect=capture,
                )
            ]
            if output_limit is not None:
                patches.append(
                    mock.patch.object(
                        RUN_EXTRACTED_VALIDATION,
                        "_MAX_COMPONENT_OUTPUT_BYTES",
                        output_limit,
                    )
                )
            record: dict[str, object] | None = None
            raised: BaseException | None = None
            try:
                for patcher in patches:
                    patcher.start()
                try:
                    record = RUN_EXTRACTED_VALIDATION._run_trusted_component(
                        root_descriptor,
                        (
                            Path(sys.executable).resolve(strict=True).as_posix(),
                            "-I",
                            "-S",
                            "-B",
                            "-c",
                            code,
                        ),
                        RUN_EXTRACTED_VALIDATION._component_environment(
                            controller_temp
                        ),
                        failure_code=failure_code,
                    )
                except BaseException as exc:  # assertion inspects exact safe error
                    raised = exc
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
                RUN_EXTRACTED_VALIDATION._HELD_CODE_STREAM = previous_stream
                os.close(root_descriptor)
        return record, raised, bytes(stdout), bytes(stderr)

    def test_component_output_forwards_only_allowlisted_status_and_hashes(self) -> None:
        secret = self.synthetic_secret("S")
        private_path = "fixture-sensitive-location"
        status = (
            "repository_io_policy=passed external_attestation=false "
            "layout_bound=true layout=repository-plugin"
        )
        record, raised, stdout, stderr = self.run_component(
            "import sys\n"
            f"sys.stdout.write({status + chr(10)!r})\n"
            f"sys.stdout.write({secret + chr(10)!r})\n"
            f"sys.stdout.write({private_path + chr(10)!r})\n"
            f"sys.stderr.write({secret + chr(10)!r})\n"
        )

        self.assertIsNone(raised)
        self.assertIsNotNone(record)
        combined = stdout + stderr
        self.assertIn((status + "\n").encode("ascii"), stdout)
        self.assertNotIn(secret.encode("ascii"), combined)
        self.assertNotIn(private_path.encode("ascii"), combined)
        for field in (
            b"trusted_component_argv_sha256=",
            b"trusted_component_stdout_sha256=",
            b"trusted_component_stderr_sha256=",
        ):
            self.assertIn(field, stdout)

    def test_component_status_allowlist_covers_package_success_protocols(self) -> None:
        expected = (
            b"sanitized_export=created",
            b"artifact_type=source",
            b"export_mode=filesystem",
            b"file_count=42",
            b"output=created",
            b"package_manifest_verification=passed",
            b"package_extract_verification=passed",
            b"artifact_root=CodexQB",
            b"real_controller_trust_guard=unchanged",
            b"repository_io_policy=passed external_attestation=false "
            b"layout_bound=true layout=extracted-plugin",
        )
        payload = b"\n".join(
            (*expected, b"unknown_status=private-value", b"/private/target/path")
        ) + b"\n"

        self.assertEqual(
            RUN_EXTRACTED_VALIDATION._safe_component_status_lines(payload),
            expected,
        )

    def test_component_output_suppresses_non_utf8_and_secret_on_both_streams(self) -> None:
        secret = self.synthetic_secret("N").encode("ascii")
        code = (
            "import os\n"
            f"os.write(1, {bytes([255, 254]) + secret!r})\n"
            f"os.write(2, {bytes([128, 129]) + secret!r})\n"
        )
        record, raised, stdout, stderr = self.run_component(code)

        self.assertIsNone(raised)
        self.assertIsNotNone(record)
        combined = stdout + stderr
        self.assertNotIn(secret, combined)
        self.assertNotIn(bytes([255, 254, 128, 129]), combined)
        self.assertIn(b"trusted_component_stdout_sha256=", stdout)
        self.assertIn(b"trusted_component_stderr_sha256=", stdout)

    def test_component_output_limit_fails_without_forwarding_partial_content(self) -> None:
        secret = self.synthetic_secret("O").encode("ascii")
        code = "import os\nos.write(1, " + repr(secret * 64) + ")\n"
        record, raised, stdout, stderr = self.run_component(
            code,
            output_limit=512,
        )

        self.assertIsNone(record)
        self.assertIsInstance(raised, RUN_EXTRACTED_VALIDATION.AdmissionError)
        self.assertEqual(str(raised), "trusted_component_output_limit_exceeded")
        self.assertNotIn(secret, stdout + stderr)

    def test_failed_component_emits_hashes_but_no_raw_or_spoofed_pass(self) -> None:
        secret = self.synthetic_secret("F")
        spoofed = "package_manifest_verification=passed"
        record, raised, stdout, stderr = self.run_component(
            "import sys\n"
            f"sys.stdout.write({spoofed + chr(10)!r})\n"
            f"sys.stdout.write({secret + chr(10)!r})\n"
            f"sys.stderr.write({secret + chr(10)!r})\n"
            "raise SystemExit(7)\n",
            failure_code="synthetic_component_failed",
        )

        self.assertIsNone(record)
        self.assertIsInstance(raised, RUN_EXTRACTED_VALIDATION.AdmissionError)
        self.assertEqual(str(raised), "synthetic_component_failed")
        combined = stdout + stderr
        self.assertNotIn(secret.encode("ascii"), combined)
        self.assertNotIn(spoofed.encode("ascii"), combined)
        self.assertIn(b"trusted_component_stdout_sha256=", stdout)
        self.assertIn(b"trusted_component_stderr_sha256=", stdout)


class ExternalPackageValidationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._fixture = tempfile.TemporaryDirectory()
        fixture = Path(cls._fixture.name)
        cls.ready_marker = fixture / "held-checker-ready"
        cls.target_runtime_marker = fixture / "target-runtime-executed"
        cls.selected_root = fixture / "selected" / "CodexQB"
        cls.selected_root.parent.mkdir(mode=0o700)
        shutil.copytree(
            REPO_ROOT,
            cls.selected_root,
            ignore=shutil.ignore_patterns(
                ".git",
                "__pycache__",
                "*.pyc",
                ".DS_Store",
            ),
        )
        policy = (
            cls.selected_root
            / "plugins/codexqb/skills/codexqb/scripts/repository_io_policy.py"
        )
        policy_text = policy.read_text(encoding="utf-8").replace(
            "from __future__ import annotations\n",
            "from __future__ import annotations\n"
            "from pathlib import Path as _FixtureTargetRuntimeMarker\n"
            "if 'codexqb-held-controller-' not in __file__:\n"
            f"    _FixtureTargetRuntimeMarker({str(cls.target_runtime_marker)!r}).write_text('executed', encoding='utf-8')\n",
            1,
        )
        policy_tree = ast.parse(policy_text)

        def assignment(name: str) -> ast.Assign | ast.AnnAssign:
            matches = [
                node
                for node in ast.walk(policy_tree)
                if (
                    isinstance(node, ast.Assign)
                    and any(
                        isinstance(target, ast.Name) and target.id == name
                        for target in node.targets
                    )
                )
                or (
                    isinstance(node, ast.AnnAssign)
                    and isinstance(node.target, ast.Name)
                    and node.target.id == name
                )
            ]
            if len(matches) != 1:
                raise AssertionError(f"fixture assignment missing: {name}")
            return matches[0]

        surface_node = assignment("_APPROVED_MODEL_SURFACE_SHA256")
        surface_value = ast.literal_eval(surface_node.value)
        skill_root = cls.selected_root / "plugins/codexqb/skills/codexqb"
        surface_hashes = {
            relative: hashlib.sha256((skill_root / relative).read_bytes()).hexdigest()
            for relative in surface_value
        }
        metadata_hash = hashlib.sha256(
            (
                cls.selected_root
                / "plugins/codexqb/.codex-plugin/plugin.json"
            ).read_bytes()
        ).hexdigest()
        replacements = []
        for node, value in (
            (
                surface_node,
                "_APPROVED_MODEL_SURFACE_SHA256: dict[str, str] = "
                + repr(surface_hashes),
            ),
            (
                assignment("_APPROVED_PLUGIN_METADATA_SHA256"),
                "_APPROVED_PLUGIN_METADATA_SHA256 = " + repr(metadata_hash),
            ),
        ):
            replacements.append((node.lineno - 1, node.end_lineno, value))
        policy_lines = policy_text.splitlines(keepends=True)
        for start, end, value in sorted(replacements, reverse=True):
            policy_lines[start:end] = [value + "\n"]
        policy.write_text("".join(policy_lines), encoding="utf-8")

        checker = cls.selected_root / "scripts/check_repository_io_policy.py"
        checker_text = checker.read_text(encoding="utf-8")
        runtime_directory = skill_root / "scripts"
        checker_tree = ast.parse(checker_text)
        registry_nodes = [
            node
            for node in ast.walk(checker_tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name)
                and target.id == "_REVIEWED_SOURCE_SHA256"
                for target in node.targets
            )
        ]
        if len(registry_nodes) != 1:
            raise AssertionError("fixture checker registry missing")
        registry_node = registry_nodes[0]
        registry = ast.literal_eval(registry_node.value)
        current_registry = {
            name: hashlib.sha256((runtime_directory / name).read_bytes()).hexdigest()
            for name in registry
        }
        checker_lines = checker_text.splitlines(keepends=True)
        checker_lines[registry_node.lineno - 1 : registry_node.end_lineno] = [
            f"_REVIEWED_SOURCE_SHA256 = {current_registry!r}\n"
        ]
        checker_text = "".join(checker_lines)
        checker_text = checker_text.replace(
            "def main(argv: list[str] | None = None) -> int:\n",
            "def main(argv: list[str] | None = None) -> int:\n"
            "    from pathlib import Path as _FixtureReadyPath\n"
            "    import time as _fixture_time\n"
            f"    _FixtureReadyPath({str(cls.ready_marker)!r}).write_text('ready', encoding='utf-8')\n"
            "    _fixture_time.sleep(0.8)\n",
            1,
        )
        checker.write_text(checker_text, encoding="utf-8")
        checker.chmod(0o644)
        commands = (
            ("git", "init", "-q"),
            ("git", "config", "user.email", "codexqb-tests@example.invalid"),
            ("git", "config", "user.name", "CodexQB Tests"),
            ("git", "add", "-A"),
            ("git", "commit", "-qm", "external diagnostic fixture"),
        )
        for command in commands:
            completed = subprocess.run(
                command,
                cwd=cls.selected_root,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            if completed.returncode != 0:
                raise AssertionError(completed.stdout + completed.stderr)
        cls.expected_head = subprocess.check_output(
            ("git", "rev-parse", "--verify", "HEAD"),
            cwd=cls.selected_root,
            text=True,
        ).strip()
        cls.launcher = cls.selected_root / "scripts/run_extracted_validation.py"
        cls.archive = fixture / "CodexQB-source-worktree.zip"
        export = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(cls.selected_root / "scripts/export_sanitized.py"),
                "--root",
                ".",
                "--artifact-type",
                "source",
                "--provenance-mode",
                "worktree",
                "--output",
                str(cls.archive),
            ],
            cwd=cls.selected_root,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        if export.returncode != 0:
            raise AssertionError(export.stdout + export.stderr)
        extracted = fixture / "base"
        extract = subprocess.run(
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                str(cls.selected_root / "scripts/extract_verified_package.py"),
                "--zip",
                str(cls.archive),
                "--output",
                str(extracted),
                "--artifact-type",
                "source",
            ],
            cwd=cls.selected_root,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )
        if extract.returncode != 0:
            raise AssertionError(extract.stdout + extract.stderr)
        cls.base_root = extracted / "CodexQB"

    @classmethod
    def tearDownClass(cls) -> None:
        cls._fixture.cleanup()

    def setUp(self) -> None:
        self.ready_marker.unlink(missing_ok=True)
        self.target_runtime_marker.unlink(missing_ok=True)

    def fresh_target(self):
        context = tempfile.TemporaryDirectory()
        target = Path(context.name) / "CodexQB"
        shutil.copytree(self.base_root, target)
        return context, target

    def outer_command(
        self,
        target: Path,
        *,
        expected_head: str | None = None,
    ) -> list[str]:
        return [
            sys.executable,
            "-I",
            "-S",
            "-B",
            str(self.launcher),
            "--expected-head",
            expected_head or self.expected_head,
            "--zip",
            str(self.archive),
            "--root",
            str(target),
            "--profile",
            "static",
            "--skip-unit-tests",
            "--skip-behavior-smoke",
        ]

    def run_outer(
        self,
        target: Path,
        *,
        expected_head: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.outer_command(target, expected_head=expected_head),
            cwd=self.selected_root,
            text=True,
            capture_output=True,
            timeout=90,
            check=False,
        )

    def install_import_marker(
        self,
        target: Path,
        relative: str,
        marker: Path,
    ) -> None:
        path = target / relative
        path.write_text(
            "from pathlib import Path as _TargetMarkerPath\n"
            f"_TargetMarkerPath({str(marker)!r}).write_text('executed')\n"
            + path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        path.chmod(0o644)

    def test_source_zip_and_root_omit_casefold_controller_aliases(self) -> None:
        with zipfile.ZipFile(self.archive) as archive:
            relative_names = {
                name.removeprefix("CodexQB/").casefold()
                for name in archive.namelist()
                if name.startswith("CodexQB/") and not name.endswith("/")
            }
        self.assertTrue(FORBIDDEN_FOLDED.isdisjoint(relative_names))
        extracted_names = {
            path.relative_to(self.base_root).as_posix().casefold()
            for path in self.base_root.rglob("*")
            if path.is_file()
        }
        self.assertTrue(FORBIDDEN_FOLDED.isdisjoint(extracted_names))

    def test_casefold_controller_reinjection_is_rejected_by_zip_and_root(self) -> None:
        for relative in sorted(FORBIDDEN_CONTROLLER_PATHS):
            alias = "Scripts/" + Path(relative).name.upper()
            with self.subTest(relative=relative, surface="zip"):
                crafted = (
                    Path(self._fixture.name)
                    / f"casefold-{Path(relative).stem}.zip"
                )
                shutil.copy2(self.archive, crafted)
                with zipfile.ZipFile(crafted, "a") as archive:
                    archive.writestr(f"CodexQB/{alias}", b"exit 0\n")
                verified = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        str(
                            self.selected_root
                            / "scripts/verify_package_manifest.py"
                        ),
                        "--zip",
                        str(crafted),
                    ],
                    cwd=self.selected_root,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertNotEqual(verified.returncode, 0)
                self.assertIn("package_zip_denied_path", verified.stdout)

            context, target = self.fresh_target()
            try:
                with self.subTest(relative=relative, surface="root"):
                    injected = target / alias
                    injected.parent.mkdir(parents=True, exist_ok=True)
                    injected.write_text("exit 0\n", encoding="utf-8")
                    verified_root = subprocess.run(
                        [
                            sys.executable,
                            "-I",
                            "-S",
                            "-B",
                            str(
                                self.selected_root
                                / "scripts/verify_package_manifest.py"
                            ),
                            "--root",
                            str(target),
                            "--strict-artifact",
                            "--expected-artifact-type",
                            "source",
                        ],
                        cwd=self.selected_root,
                        text=True,
                        capture_output=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertNotEqual(verified_root.returncode, 0)
                    self.assertIn(
                        "package_directory_denied_path",
                        verified_root.stdout,
                    )
            finally:
                context.cleanup()

    def test_pair_bound_target_runtime_is_data_only_at_policy_stage(self) -> None:
        result = self.run_outer(self.base_root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue(self.ready_marker.exists(), result.stdout + result.stderr)
        self.assertFalse(
            self.target_runtime_marker.exists(), result.stdout + result.stderr
        )
        self.assertIn("repository_io_policy=passed", result.stdout)
        self.assertIn("target_code_executed=false", result.stdout)

    def test_tampered_target_checker_is_rejected_without_import(self) -> None:
        context, target = self.fresh_target()
        try:
            marker = Path(context.name) / "target-code-executed"
            self.install_import_marker(
                target,
                "scripts/check_repository_io_policy.py",
                marker,
            )
            result = self.run_outer(target)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("error=extracted_size_mismatch", result.stdout)
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
            self.assertNotIn("extracted_package_admission=passed", result.stdout)
        finally:
            context.cleanup()

    def test_wrong_external_head_fails_before_target_import(self) -> None:
        context, target = self.fresh_target()
        try:
            marker = Path(context.name) / "target-code-executed"
            self.install_import_marker(
                target,
                "scripts/check_repository_io_policy.py",
                marker,
            )
            result = self.run_outer(target, expected_head="0" * 40)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "selected_checkout_head_or_workspace_mismatch",
                result.stdout,
            )
            self.assertFalse(marker.exists(), result.stdout + result.stderr)
        finally:
            context.cleanup()

    def test_valid_static_diagnostic_is_explicitly_non_attested(self) -> None:
        result = self.run_outer(self.base_root)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("extracted_package_admission=passed", result.stdout)
        self.assertIn("external_pair_diagnostic_schema_version=1", result.stdout)
        self.assertIn(
            "source_selection_assurance=controller_observed_explicit_source_selection",
            result.stdout,
        )
        self.assertIn("execution_scope=static_policy_and_pair_parity_only", result.stdout)
        self.assertIn("target_code_executed=false", result.stdout)
        self.assertIn("host_attested=false", result.stdout)
        self.assertIn("verified=false", result.stdout)
        self.assertIn("finalization_allowed=false", result.stdout)
        self.assertIn(
            f"selected_checkout_expected_head={self.expected_head}",
            result.stdout,
        )
        for field in (
            "archive_sha256",
            "manifest_sha256",
            "inventory_sha256",
            "selected_checkout_identity_sha256",
            "selected_checkout_path_sha256",
            "selected_controller_bundle_sha256",
            "trusted_bundle_sha256",
            "trusted_source_sha256",
            "trusted_workspace_sha256",
            "root_identity_sha256",
            "pair_digest",
            "validation_components_sha256",
            "external_pair_diagnostic_sha256",
        ):
            self.assertRegex(result.stdout, rf"(?m)^{field}=[0-9a-f]{{64}}$")
        self.assertNotIn("authority=true", result.stdout)
        self.assertNotIn("host_attested=true", result.stdout)
        self.assertNotIn("verified=true", result.stdout)

    def test_selected_checker_swap_restore_cannot_execute_lexical_replacement(self) -> None:
        marker = Path(self._fixture.name) / "aba-malicious-checker-executed"
        marker.unlink(missing_ok=True)
        checker = self.selected_root / "scripts/check_repository_io_policy.py"
        backup = checker.with_name("check_repository_io_policy.py.aba-original")
        process = subprocess.Popen(
            self.outer_command(self.base_root),
            cwd=self.selected_root,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 30
        while not self.ready_marker.exists() and process.poll() is None:
            if time.monotonic() >= deadline:
                process.kill()
                self.fail("held checker did not reach the controlled ABA window")
            time.sleep(0.02)
        try:
            os.replace(checker, backup)
            checker.write_text(
                "#!/usr/bin/env python3\n"
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            checker.chmod(0o644)
            time.sleep(0.15)
        finally:
            checker.unlink(missing_ok=True)
            if backup.exists():
                os.replace(backup, checker)
        stdout, stderr = process.communicate(timeout=90)
        self.assertEqual(process.returncode, 0, stdout + stderr)
        self.assertFalse(marker.exists(), stdout + stderr)
        self.assertIn("extracted_package_admission=passed", stdout)


if __name__ == "__main__":
    unittest.main()
