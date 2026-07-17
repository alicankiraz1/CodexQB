from __future__ import annotations

from dataclasses import replace
import importlib.util
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from types import ModuleType
from unittest import mock

from tests.held_runtime_test_support import (
    HELD_RUNTIME_CONTEXT_NAME,
    held_runtime_test_provider,
    test_goal_resources,
    test_runtime_sources,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts"
EXECUTION_CONTROLLER = SCRIPT_ROOT / "execution_controller.py"


def load_execution_controller():
    if str(SCRIPT_ROOT) not in sys.path:
        sys.path.insert(0, str(SCRIPT_ROOT))
    spec = importlib.util.spec_from_file_location(
        "codexqb_execution_controller_bundle_tests", EXECUTION_CONTROLLER
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could_not_load_execution_controller")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


EXECUTION = load_execution_controller()


class PlannerValidatorBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        super().setUp()
        self._provider = held_runtime_test_provider()
        self._provider.__enter__()

    def tearDown(self) -> None:
        self._provider.__exit__(None, None, None)
        super().tearDown()

    def test_capture_is_hardcoded_deterministic_and_path_free(self) -> None:
        first = EXECUTION.capture_planner_validator_bundle()
        second = EXECUTION.capture_planner_validator_bundle()
        self.assertEqual(first.bundle_sha256, second.bundle_sha256)
        self.assertEqual(first.source_sha256, second.source_sha256)
        self.assertEqual(
            {name for name, _digest in first.source_sha256},
            set(EXECUTION._VALIDATOR_BUNDLE_NAMES),
        )
        evidence = EXECUTION.planner_validator_bundle_evidence(first)
        rendered = json.dumps(evidence, sort_keys=True)
        self.assertNotIn(str(SCRIPT_ROOT), rendered)
        self.assertEqual(
            list(inspect.signature(EXECUTION.capture_planner_validator_bundle).parameters),
            [],
        )
        self.assertNotIn(
            "validator_path",
            inspect.signature(EXECUTION.run_goal_planner_validator).parameters,
        )
        with self.assertRaises(TypeError):
            EXECUTION.capture_planner_validator_bundle(Path("arbitrary"))

    def test_capture_requires_held_launcher_provider(self) -> None:
        provider_name = "_codexqb_held_runtime_context_v1"
        previous = sys.modules.pop(provider_name, None)
        try:
            with self.assertRaisesRegex(ValueError, "held_runtime_context_required"):
                EXECUTION.capture_planner_validator_bundle()
        finally:
            if previous is not None:
                sys.modules[provider_name] = previous

    def test_validator_bootstrap_installs_exact_unattested_held_context(self) -> None:
        probe = b"""
import json
import sys
from pathlib import Path
from types import ModuleType
name = "_codexqb_held_runtime_context_v1"
context = sys.modules[name]
state = ModuleType.__getattribute__(context, "__dict__")
runtime = state["runtime_sources"]
script_dir = Path(__file__).resolve().parent
if str(script_dir) not in sys.path:
    sys.path.insert(0, str(script_dir))
try:
    import unheld_probe
except ModuleNotFoundError:
    late_import = "blocked"
else:
    late_import = "loaded"
print(json.dumps({
    "assurance": state["assurance"],
    "context_identity": sys.modules[name] is context,
    "context_name": state["__name__"],
    "false_authority": [
        state["host_attested"],
        state["verified"],
        state["finalization_authority"],
    ],
    "first_process_flags": [
        sys.flags.isolated,
        sys.flags.no_site,
        sys.flags.dont_write_bytecode,
        sys.flags.optimize,
    ],
    "goal_resources_exact_empty_tuple": type(state["goal_resources"]) is tuple and not state["goal_resources"],
    "held_file": state["__file__"],
    "held_package": state["__package__"],
    "late_bundle_external_import": late_import,
    "main_file": __file__,
    "main_origin_parent_is_dir": script_dir.is_dir(),
    "runtime_exact_types": type(runtime) is tuple and all(
        type(item) is tuple and len(item) == 2 and type(item[0]) is str and type(item[1]) is bytes
        for item in runtime
    ),
    "runtime_names": [item[0] for item in runtime],
    "schema_version": state["schema_version"],
    "unclaimed_hash_fields": "runtime_sha256" not in state and "goal_sha256" not in state,
}, sort_keys=True))
"""
        payloads = {
            name: (probe if name == "validate_planner_docs.py" else b"# held\n")
            for name in EXECUTION._VALIDATOR_BUNDLE_NAMES
        }
        envelope = EXECUTION._validator_bundle_payload(payloads)
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "unheld_probe.py").write_text(
                "raise RuntimeError('bundle_external_source_executed')\n",
                encoding="utf-8",
            )
            with tempfile.TemporaryFile(mode="w+b") as held_bundle:
                held_bundle.write(envelope)
                held_bundle.flush()
                held_bundle.seek(0)
                descriptor = held_bundle.fileno()
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        "-c",
                        EXECUTION._HELD_VALIDATOR_BOOTSTRAP,
                        str(descriptor),
                    ],
                    text=True,
                    capture_output=True,
                    check=False,
                    cwd=root,
                    env=EXECUTION._sanitised_environment(root),
                    pass_fds=(descriptor,),
                )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stderr, "")
        evidence = json.loads(completed.stdout)
        self.assertEqual(
            evidence,
            {
                "assurance": "controller_observed_loader_path_unattested",
                "context_identity": True,
                "context_name": "_codexqb_held_runtime_context_v1",
                "false_authority": [False, False, False],
                "first_process_flags": [1, 1, 1, 0],
                "goal_resources_exact_empty_tuple": True,
                "held_file": "<controller-held-validator-bundle>",
                "held_package": "",
                "late_bundle_external_import": "blocked",
                "main_file": "/dev/null/__codexqb_held__/validate_planner_docs.py",
                "main_origin_parent_is_dir": False,
                "runtime_exact_types": True,
                "runtime_names": sorted(EXECUTION._VALIDATOR_BUNDLE_NAMES),
                "schema_version": 1,
                "unclaimed_hash_fields": True,
            },
        )

    def test_execution_uses_captured_bytes_not_later_path_contents(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repository"
            root.mkdir(mode=0o700)
            marker = base / "path-source-executed"
            captured = EXECUTION.capture_planner_validator_bundle()
            malicious_runtime = test_runtime_sources()
            malicious_runtime["validate_planner_docs.py"] = (
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('executed')\n"
            ).encode("utf-8")
            self._provider.__exit__(None, None, None)
            try:
                with held_runtime_test_provider(runtime_sources=malicious_runtime):
                    code, output = EXECUTION.run_goal_planner_validator(
                        root=root,
                        mode="step1",
                        strict=True,
                        bundle=captured,
                    )
            finally:
                self._provider = held_runtime_test_provider()
                self._provider.__enter__()
            self.assertNotEqual(code, 0)
            self.assertIn("missing_file=Planner-docs/Main-Planing.md", output)
            self.assertFalse(marker.exists())

    def test_capture_rejects_mutable_incomplete_or_oversize_provider(self) -> None:
        valid_runtime = test_runtime_sources()
        valid_resources = test_goal_resources()
        self._provider.__exit__(None, None, None)
        try:
            mutable = ModuleType(HELD_RUNTIME_CONTEXT_NAME)
            mutable.schema_version = 1
            mutable.assurance = "controller_observed_loader_path_unattested"
            mutable.host_attested = False
            mutable.verified = False
            mutable.finalization_authority = False
            mutable.runtime_sources = valid_runtime
            mutable.goal_resources = tuple(sorted(valid_resources.items()))
            sys.modules[HELD_RUNTIME_CONTEXT_NAME] = mutable
            with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                EXECUTION.capture_planner_validator_bundle()
            sys.modules.pop(HELD_RUNTIME_CONTEXT_NAME, None)

            with held_runtime_test_provider() as fingerprint_tampered:
                changed = dict(fingerprint_tampered.runtime_sources)
                changed["validate_planner_docs.py"] = b"MALICIOUS_VALIDATOR"
                fingerprint_tampered.runtime_sources = tuple(sorted(changed.items()))
                with mock.patch.object(
                    EXECUTION,
                    "_validator_bundle_payload",
                    wraps=EXECUTION._validator_bundle_payload,
                ) as payload_builder:
                    with self.assertRaisesRegex(
                        ValueError,
                        "held_runtime_context_invalid",
                    ):
                        EXECUTION.capture_planner_validator_bundle()
                    payload_builder.assert_not_called()

            incomplete = dict(valid_runtime)
            incomplete.pop("validate_planner_docs.py")
            with held_runtime_test_provider(runtime_sources=incomplete):
                with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                    EXECUTION.capture_planner_validator_bundle()

            oversize = dict(valid_runtime)
            oversize["validate_planner_docs.py"] = b"x" * (
                EXECUTION.MAX_VALIDATOR_SOURCE_BYTES + 1
            )
            with held_runtime_test_provider(runtime_sources=oversize):
                with self.assertRaisesRegex(
                    ValueError,
                    "planner_validator_bundle_source_too_large",
                ):
                    EXECUTION.capture_planner_validator_bundle()
        finally:
            sys.modules.pop(HELD_RUNTIME_CONTEXT_NAME, None)
            self._provider = held_runtime_test_provider()
            self._provider.__enter__()

    def test_forged_module_is_rejected_before_bundle_or_child_side_effect(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "forged-validator-executed"
            valid_runtime = test_runtime_sources()
            valid_resources = test_goal_resources()
            forged = ModuleType(HELD_RUNTIME_CONTEXT_NAME)
            forged.schema_version = 1
            forged.assurance = "controller_observed_loader_path_unattested"
            forged.host_attested = False
            forged.verified = False
            forged.finalization_authority = False
            valid_runtime["validate_planner_docs.py"] = (
                b"from pathlib import Path\n"
                + f"Path({os.fspath(marker)!r}).write_text('executed')\n".encode("utf-8")
            )
            forged.runtime_sources = tuple(sorted(valid_runtime.items()))
            forged.goal_resources = tuple(sorted(valid_resources.items()))

            self._provider.__exit__(None, None, None)
            sys.modules[HELD_RUNTIME_CONTEXT_NAME] = forged
            try:
                with mock.patch.object(
                    EXECUTION,
                    "_validator_bundle_payload",
                    wraps=EXECUTION._validator_bundle_payload,
                ) as payload_builder:
                    with self.assertRaisesRegex(
                        ValueError,
                        "held_runtime_context_invalid",
                    ):
                        EXECUTION.capture_planner_validator_bundle()
                    payload_builder.assert_not_called()
                self.assertFalse(marker.exists())
            finally:
                sys.modules.pop(HELD_RUNTIME_CONTEXT_NAME, None)
                self._provider = held_runtime_test_provider()
                self._provider.__enter__()

    def test_provider_scalar_comparison_cannot_run_attacker_eq(self) -> None:
        marker = {"executed": False}

        class AttackerControlledScalar:
            def __eq__(self, other: object) -> bool:
                del other
                marker["executed"] = True
                return True

        provider = sys.modules[HELD_RUNTIME_CONTEXT_NAME]
        original = provider.schema_version
        provider.schema_version = AttackerControlledScalar()
        try:
            with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                EXECUTION.capture_planner_validator_bundle()
        finally:
            provider.schema_version = original
        self.assertFalse(marker["executed"])

    def test_self_consistent_forged_bundle_is_rejected_before_child_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repository"
            root.mkdir(mode=0o700)
            marker = base / "forged-validator-executed"
            runtime = test_runtime_sources()
            payloads = {
                name: runtime[name]
                for name in EXECUTION._VALIDATOR_BUNDLE_NAMES
            }
            payloads["validate_planner_docs.py"] = (
                b"from pathlib import Path\n"
                + f"Path({os.fspath(marker)!r}).write_text('executed')\n".encode("utf-8")
                + b"print('forged-validator-ran')\n"
            )
            envelope = EXECUTION._validator_bundle_payload(payloads)
            forged = EXECUTION.PlannerValidatorBundle(
                schema=EXECUTION.PLANNER_VALIDATOR_BUNDLE_SCHEMA,
                bundle_sha256=EXECUTION.hashlib.sha256(envelope).hexdigest(),
                source_sha256=tuple(
                    (
                        name,
                        EXECUTION.hashlib.sha256(payloads[name]).hexdigest(),
                    )
                    for name in sorted(payloads)
                ),
                _envelope=envelope,
            )
            with mock.patch.object(EXECUTION.subprocess, "run") as child_run:
                with self.assertRaisesRegex(
                    ValueError,
                    "planner_validator_bundle_tampered",
                ):
                    EXECUTION.run_goal_planner_validator(
                        root=root,
                        mode="step1",
                        strict=True,
                        bundle=forged,
                    )
                child_run.assert_not_called()
            self.assertFalse(marker.exists())

    def test_validator_pin_inventory_matches_all_seven_exact_sources(self) -> None:
        expected = dict(EXECUTION._VALIDATOR_SOURCE_SHA256)
        runtime = dict(sys.modules[HELD_RUNTIME_CONTEXT_NAME].runtime_sources)
        self.assertEqual(tuple(expected), tuple(sorted(EXECUTION._VALIDATOR_BUNDLE_NAMES)))
        self.assertEqual(len(expected), 7)
        self.assertEqual(
            expected,
            {name: EXECUTION.hashlib.sha256(runtime[name]).hexdigest() for name in expected},
        )

    def test_goal_run_pin_matches_exact_current_source(self) -> None:
        goal_run_source = (SCRIPT_ROOT / "goal_run.py").read_bytes()
        self.assertEqual(
            EXECUTION.GOAL_RUN_SOURCE_SHA256,
            EXECUTION.hashlib.sha256(goal_run_source).hexdigest(),
        )

    def test_goal_resource_reader_is_exact_pinned_and_path_closed(self) -> None:
        expected = dict(EXECUTION.GOAL_RESOURCE_SOURCE_SHA256)
        resources = dict(sys.modules[HELD_RUNTIME_CONTEXT_NAME].goal_resources)
        pin_names = tuple(path for path, _digest in EXECUTION.GOAL_RESOURCE_SOURCE_SHA256)
        self.assertIs(type(EXECUTION.GOAL_RESOURCE_SOURCE_SHA256), tuple)
        self.assertEqual(pin_names, tuple(sorted(pin_names)))
        self.assertEqual(len(pin_names), len(set(pin_names)))
        for item in EXECUTION.GOAL_RESOURCE_SOURCE_SHA256:
            self.assertIs(type(item), tuple)
            self.assertEqual(len(item), 2)
            self.assertIs(type(item[0]), str)
            self.assertIs(type(item[1]), str)
        self.assertEqual(set(expected), set(EXECUTION._HELD_GOAL_RESOURCE_NAMES))
        self.assertEqual(
            expected,
            {
                name: EXECUTION.hashlib.sha256(resources[name]).hexdigest()
                for name in expected
            },
        )
        for path, payload in resources.items():
            with self.subTest(path=path):
                self.assertEqual(EXECUTION.read_goal_held_bytes(path), payload)
        self.assertEqual(
            EXECUTION.read_goal_held_bytes("scripts/goal_run.py"),
            (SCRIPT_ROOT / "goal_run.py").read_bytes(),
        )
        for invalid in (
            "../SKILL.md",
            "references/extra.md",
            "scripts/execution_controller.py",
            Path("references/Autopsy-Planner.md"),
        ):
            with self.subTest(invalid=invalid), self.assertRaisesRegex(
                ValueError,
                "untrusted_skill_resource_path",
            ):
                EXECUTION.read_goal_held_bytes(invalid)

    def test_goal_resource_reader_validates_unselected_goal_and_resource_bytes(self) -> None:
        provider = sys.modules[HELD_RUNTIME_CONTEXT_NAME]
        original_runtime = provider.runtime_sources
        original_resources = provider.goal_resources
        current_goal = dict(original_runtime)["goal_run.py"]
        try:
            with mock.patch.object(
                EXECUTION,
                "GOAL_RUN_SOURCE_SHA256",
                EXECUTION.hashlib.sha256(current_goal).hexdigest(),
            ):
                resources = dict(original_resources)
                resources["references/Autopsy-Planner.md"] = b"TAMPERED_REFERENCE"
                provider.goal_resources = tuple(sorted(resources.items()))
                with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                    EXECUTION.read_goal_held_bytes("scripts/goal_run.py")

                provider.goal_resources = original_resources
                runtime = dict(original_runtime)
                runtime["goal_run.py"] = b"TAMPERED_GOAL_SOURCE"
                provider.runtime_sources = tuple(sorted(runtime.items()))
                with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                    EXECUTION.read_goal_held_bytes("references/Fourth-Planner.md")
        finally:
            provider.runtime_sources = original_runtime
            provider.goal_resources = original_resources

    def test_goal_resource_reader_rejects_malformed_held_source_tuples(self) -> None:
        provider = sys.modules[HELD_RUNTIME_CONTEXT_NAME]
        original_runtime = provider.runtime_sources
        original_resources = provider.goal_resources
        runtime = list(original_runtime)
        resources = list(original_resources)

        class TupleSubclass(tuple):
            pass

        class BytesSubclass(bytes):
            pass

        cases = (
            ("runtime_missing", tuple(runtime[:-1]), original_resources),
            ("runtime_extra", tuple(runtime + [("unexpected.py", b"x")]), original_resources),
            ("runtime_reordered", tuple(reversed(runtime)), original_resources),
            ("runtime_duplicate", tuple(runtime[:-1] + [runtime[0]]), original_resources),
            ("runtime_list", list(runtime), original_resources),
            ("runtime_tuple_subclass", TupleSubclass(runtime), original_resources),
            ("runtime_item_list", tuple([list(runtime[0]), *runtime[1:]]), original_resources),
            ("runtime_item_tuple_subclass", tuple([TupleSubclass(runtime[0]), *runtime[1:]]), original_resources),
            ("runtime_name_subclass", tuple([(type("S", (str,), {})(runtime[0][0]), runtime[0][1]), *runtime[1:]]), original_resources),
            ("runtime_payload_bytearray", tuple([(runtime[0][0], bytearray(runtime[0][1])), *runtime[1:]]), original_resources),
            ("runtime_payload_bytes_subclass", tuple([(runtime[0][0], BytesSubclass(runtime[0][1])), *runtime[1:]]), original_resources),
            ("resource_missing", original_runtime, tuple(resources[:-1])),
            ("resource_extra", original_runtime, tuple(resources + [("references/extra.md", b"x")])),
            ("resource_reordered", original_runtime, tuple(reversed(resources))),
            ("resource_duplicate", original_runtime, tuple(resources[:-1] + [resources[0]])),
            ("resource_list", original_runtime, list(resources)),
            ("resource_tuple_subclass", original_runtime, TupleSubclass(resources)),
            ("resource_item_list", original_runtime, tuple([list(resources[0]), *resources[1:]])),
            ("resource_item_tuple_subclass", original_runtime, tuple([TupleSubclass(resources[0]), *resources[1:]])),
            ("resource_name_subclass", original_runtime, tuple([(type("S", (str,), {})(resources[0][0]), resources[0][1]), *resources[1:]])),
            ("resource_payload_bytearray", original_runtime, tuple([(resources[0][0], bytearray(resources[0][1])), *resources[1:]])),
            ("resource_payload_bytes_subclass", original_runtime, tuple([(resources[0][0], BytesSubclass(resources[0][1])), *resources[1:]])),
        )
        try:
            for label, candidate_runtime, candidate_resources in cases:
                with self.subTest(case=label):
                    provider.runtime_sources = candidate_runtime
                    provider.goal_resources = candidate_resources
                    with self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                        EXECUTION._held_runtime_context_maps()
        finally:
            provider.runtime_sources = original_runtime
            provider.goal_resources = original_resources

    def test_goal_resource_reader_enforces_source_and_bundle_byte_budgets(self) -> None:
        provider = sys.modules[HELD_RUNTIME_CONTEXT_NAME]
        original_runtime = provider.runtime_sources
        original_resources = provider.goal_resources
        current_goal = dict(original_runtime)["goal_run.py"]
        try:
            oversized_runtime = dict(original_runtime)
            oversized_goal = b"x" * (
                EXECUTION._MAX_HELD_GOAL_SOURCE_BYTES + 1
            )
            oversized_runtime["goal_run.py"] = oversized_goal
            provider.runtime_sources = tuple(sorted(oversized_runtime.items()))
            with mock.patch.object(
                EXECUTION,
                "GOAL_RUN_SOURCE_SHA256",
                EXECUTION.hashlib.sha256(oversized_goal).hexdigest(),
            ), self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                EXECUTION.read_goal_held_bytes("scripts/goal_run.py")

            provider.runtime_sources = original_runtime
            oversized_resources = dict(original_resources)
            oversized_resources["references/Autopsy-Planner.md"] = b"x" * (
                EXECUTION._MAX_HELD_GOAL_SOURCE_BYTES + 1
            )
            oversized_resource_pins = tuple(
                (path, EXECUTION.hashlib.sha256(payload).hexdigest())
                for path, payload in sorted(oversized_resources.items())
            )
            self.assertLessEqual(
                sum(len(payload) for payload in oversized_resources.values()),
                EXECUTION._MAX_HELD_GOAL_RESOURCE_BUNDLE_BYTES,
            )
            provider.goal_resources = tuple(sorted(oversized_resources.items()))
            with mock.patch.object(
                EXECUTION,
                "GOAL_RUN_SOURCE_SHA256",
                EXECUTION.hashlib.sha256(current_goal).hexdigest(),
            ), mock.patch.object(
                EXECUTION,
                "GOAL_RESOURCE_SOURCE_SHA256",
                oversized_resource_pins,
            ), self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                EXECUTION.read_goal_held_bytes("references/Fourth-Planner.md")

            bundle_payload_size = (
                EXECUTION._MAX_HELD_GOAL_RESOURCE_BUNDLE_BYTES
                // len(original_resources)
                + 1
            )
            aggregate_resources = {
                path: bytes([index % 251 + 1]) * bundle_payload_size
                for index, (path, _payload) in enumerate(original_resources)
            }
            self.assertTrue(
                all(
                    len(payload) <= EXECUTION._MAX_HELD_GOAL_SOURCE_BYTES
                    for payload in aggregate_resources.values()
                )
            )
            self.assertGreater(
                sum(len(payload) for payload in aggregate_resources.values()),
                EXECUTION._MAX_HELD_GOAL_RESOURCE_BUNDLE_BYTES,
            )
            aggregate_pins = tuple(
                (path, EXECUTION.hashlib.sha256(payload).hexdigest())
                for path, payload in sorted(aggregate_resources.items())
            )
            provider.goal_resources = tuple(sorted(aggregate_resources.items()))
            with mock.patch.object(
                EXECUTION,
                "GOAL_RUN_SOURCE_SHA256",
                EXECUTION.hashlib.sha256(current_goal).hexdigest(),
            ), mock.patch.object(
                EXECUTION,
                "GOAL_RESOURCE_SOURCE_SHA256",
                aggregate_pins,
            ), self.assertRaisesRegex(ValueError, "held_runtime_context_invalid"):
                EXECUTION.read_goal_held_bytes("references/Fourth-Planner.md")
        finally:
            provider.runtime_sources = original_runtime
            provider.goal_resources = original_resources

    def test_isolated_child_ignores_python_startup_and_rejects_tampered_capture(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "repository"
            root.mkdir(mode=0o700)
            hostile = base / "hostile"
            hostile.mkdir(mode=0o700)
            marker = base / "sitecustomize-executed"
            (hostile / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            captured = EXECUTION.capture_planner_validator_bundle()
            with mock.patch.dict(os.environ, {"PYTHONPATH": str(hostile)}):
                code, _output = EXECUTION.run_goal_planner_validator(
                    root=root,
                    mode="step1",
                    bundle=captured,
                )
            self.assertNotEqual(code, 0)
            self.assertFalse(marker.exists())

            tampered = replace(captured, _envelope=captured._envelope + b" ")
            with self.assertRaisesRegex(ValueError, "planner_validator_bundle_tampered"):
                EXECUTION.run_goal_planner_validator(
                    root=root,
                    mode="step1",
                    bundle=tampered,
                )
            lying_sources = replace(
                captured,
                source_sha256=(("validate_planner_docs.py", "0" * 64),),
            )
            with self.assertRaisesRegex(ValueError, "planner_validator_bundle_tampered"):
                EXECUTION.planner_validator_bundle_evidence(lying_sources)


if __name__ == "__main__":
    unittest.main()
