from __future__ import annotations

import ast
import importlib.util
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import ModuleType

from tests.held_runtime_test_support import (
    HELD_RUNTIME_CONTEXT_NAME,
    test_goal_resources,
    test_runtime_sources,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb"
LAUNCHER = SKILL_ROOT / "scripts/skill_launcher.py"
BLOCKED_PREFIX = "codexqb_skill_launcher=blocked reason="
CONTROLLER_BASENAMES = (
    "apply_run.py",
    "doctor.py",
    "goal_run.py",
    "repository_io.py",
    "validate_planner_docs.py",
)
DIRECT_CONTROLLER_BLOCK = (
    "codexqb_controller=unsupported reason=launcher_admission_required\n"
)
UNSAFE_PATH_COMPONENTS = (
    ("space", " "),
    ("dollar", "$"),
    ("backtick", "`"),
    ("double_quote", '"'),
    ("single_quote", "'"),
    ("backslash", "\\"),
    ("semicolon", ";"),
    ("control_c0", "\x01"),
    ("control_del", "\x7f"),
    ("default_ignorable", "\u200b"),
    ("bidi", "\u202e"),
    ("non_ascii", "é"),
)


def load_launcher_module():
    spec = importlib.util.spec_from_file_location(
        "codexqb_skill_launcher_tests",
        LAUNCHER,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("skill launcher test import unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class SkillLauncherTests(unittest.TestCase):
    maxDiff = 4096

    def copy_skill(self, base: Path, relative: str = "installed/codexqb") -> Path:
        target = base / relative
        shutil.copytree(
            SKILL_ROOT,
            target,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        return target

    def run_launcher(
        self,
        *,
        launcher: Path = LAUNCHER,
        skill_root: Path = SKILL_ROOT,
        controller: str = "doctor",
        controller_argv: tuple[str, ...] = ("--json",),
        cwd: Path,
        environment: dict[str, str] | None = None,
        isolated: bool = True,
        launcher_argument: str | None = None,
        active_skill_argument: str | None = None,
        extra_prefix: tuple[str, ...] = (),
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PWD"] = os.fspath(cwd)
        if environment:
            env.update(environment)
        command = [sys.executable]
        if isolated:
            command.extend(("-I", "-S", "-B"))
        command.extend(extra_prefix)
        command.extend(
            (
                launcher_argument or os.fspath(launcher),
                "--active-skill-md",
                active_skill_argument or os.fspath(skill_root / "SKILL.md"),
                "--controller",
                controller,
                "--",
                *controller_argv,
            )
        )
        return subprocess.run(
            command,
            cwd=cwd,
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
        )

    def assert_blocked(self, result: subprocess.CompletedProcess[str]) -> None:
        self.assertEqual(result.returncode, 2, result)
        self.assertEqual(result.stdout, "")
        self.assertRegex(
            result.stderr,
            rf"^{BLOCKED_PREFIX}[A-Za-z0-9_-]+\n$",
        )

    def test_shell_safe_path_predicate_accepts_source_and_rejects_unsafe_components(self) -> None:
        launcher_module = load_launcher_module()
        self.assertTrue(
            launcher_module._shell_safe_absolute_path(
                os.fspath(SKILL_ROOT / "SKILL.md"),
                expected_basename="SKILL.md",
            )
        )
        self.assertTrue(
            launcher_module._lexical_launcher_path_is_valid(
                os.fspath(LAUNCHER),
                os.fspath(LAUNCHER),
            )
        )
        for label, character in UNSAFE_PATH_COMPONENTS:
            unsafe_component = f"unsafe{character}component"
            with self.subTest(category=label, path_kind="loader"):
                self.assertFalse(
                    launcher_module._shell_safe_absolute_path(
                        f"/safe/{unsafe_component}/codexqb/SKILL.md",
                        expected_basename="SKILL.md",
                    )
                )
            unsafe_launcher = (
                f"/safe/{unsafe_component}/codexqb/scripts/skill_launcher.py"
            )
            with self.subTest(category=label, path_kind="launcher"):
                self.assertFalse(
                    launcher_module._lexical_launcher_path_is_valid(
                        unsafe_launcher,
                        unsafe_launcher,
                    )
                )

    def test_reviewed_source_pins_match_current_skill_bytes(self) -> None:
        launcher_module = load_launcher_module()
        runtime_sources = test_runtime_sources()
        goal_resources = test_goal_resources()

        authority_source = (
            SKILL_ROOT / "scripts/skill_root_authority.py"
        ).read_bytes()
        self.assertEqual(
            launcher_module._AUTHORITY_SOURCE_SHA256,
            hashlib.sha256(authority_source).hexdigest(),
        )
        self.assertEqual(
            set(launcher_module._REVIEWED_RUNTIME_SHA256),
            set(runtime_sources),
        )
        for basename, source in runtime_sources.items():
            with self.subTest(runtime=basename):
                self.assertEqual(
                    launcher_module._REVIEWED_RUNTIME_SHA256[basename],
                    hashlib.sha256(source).hexdigest(),
                )

        reviewed_resources = dict(
            launcher_module._REVIEWED_GOAL_RESOURCE_SHA256
        )
        self.assertEqual(set(reviewed_resources), set(goal_resources))
        for relative_path, source in goal_resources.items():
            with self.subTest(goal_resource=relative_path):
                self.assertEqual(
                    reviewed_resources[relative_path],
                    hashlib.sha256(source).hexdigest(),
                )

    def test_source_launcher_executes_held_controller_from_foreign_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            foreign = Path(temp_dir).resolve() / "foreign-repository"
            foreign.mkdir()
            result = self.run_launcher(cwd=foreign)

        self.assertIn(result.returncode, (0, 1), result)
        report = json.loads(result.stdout)
        self.assertEqual(report["schema"], "codexqb.doctor.capability-report")
        self.assertEqual(result.stderr, "")

    def test_source_and_extracted_repository_io_run_from_foreign_cwd(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            foreign = base / "foreign-target-repository"
            foreign.mkdir()
            (foreign / "README.md").write_text("# Foreign target\n", encoding="utf-8")
            extracted = self.copy_skill(base, "extracted/codexqb")

            copies = (
                ("source", SKILL_ROOT),
                ("extracted", extracted),
            )
            for label, skill_root in copies:
                with self.subTest(copy=label):
                    result = self.run_launcher(
                        launcher=skill_root / "scripts/skill_launcher.py",
                        skill_root=skill_root,
                        controller="repository-io",
                        controller_argv=(
                            "--root",
                            ".",
                            "inspect",
                            "--profile",
                            "intake",
                        ),
                        cwd=foreign,
                    )
                    self.assertEqual(result.returncode, 0, result)
                    self.assertEqual(result.stderr, "")
                    payload = json.loads(result.stdout)
                    self.assertEqual(payload["profile"], "intake")
                    self.assertIn("README.md", payload["paths"])
                    self.assertEqual(payload["receipt"]["operation"], "list")
                    self.assertEqual(payload["receipt"]["state"], "complete")

    def test_executor_uses_exact_absolute_file_argv_and_no_real_local_path(self) -> None:
        launcher_module = load_launcher_module()
        source = (
            b"import json, sys\n"
            b"print(json.dumps({'argv': sys.argv, 'file': __file__, 'path': list(sys.path)}))\n"
        )
        controller_path = "/absolute/held/scripts/fixture.py"
        output = io.StringIO()
        with redirect_stdout(output):
            result = launcher_module._execute_held_controller(
                source=source,
                runtime_bundle={"fixture.py": source},
                goal_resource_bundle={},
                controller_path=controller_path,
                scripts_directory="/absolute/held/scripts",
                controller_argv=["alpha", "beta"],
            )

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["argv"], [controller_path, "alpha", "beta"])
        self.assertEqual(payload["file"], controller_path)
        self.assertNotIn("/absolute/held/scripts", payload["path"])

    def test_executor_provider_is_immutable_unattested_and_removed(self) -> None:
        launcher_module = load_launcher_module()
        source = (
            b"import gc, json, sys\n"
            b"context = sys.modules['_codexqb_held_runtime_context_v1']\n"
            b"failures = []\n"
            b"try:\n"
            b"    context.runtime_sources[0] = ('fixture.py', b'changed')\n"
            b"except TypeError:\n"
            b"    failures.append('tuple')\n"
            b"try:\n"
            b"    context.runtime_sources = {'fixture.py': b'changed'}\n"
            b"except AttributeError:\n"
            b"    failures.append('module')\n"
            b"finder = next(item for item in sys.meta_path if type(item).__name__ == '_HeldRuntimeFinder')\n"
            b"try:\n"
            b"    finder._sources = (('fixture.py', b'changed'),)\n"
            b"except AttributeError:\n"
            b"    failures.append('finder')\n"
            b"print(json.dumps({\n"
            b"    'failures': failures,\n"
            b"    'runtime_proxy': type(context.runtime_sources).__name__,\n"
            b"    'goal_proxy': type(context.goal_resources).__name__,\n"
            b"    'runtime_item_type': type(context.runtime_sources[0]).__name__,\n"
            b"    'gc_dict_backing': any(isinstance(item, dict) for item in gc.get_referents(context.runtime_sources)),\n"
            b"    'self_hash_fields_absent': not hasattr(context, 'runtime_sha256') and not hasattr(context, 'goal_sha256'),\n"
            b"    'host_attested': context.host_attested,\n"
            b"    'verified': context.verified,\n"
            b"    'finalization_authority': context.finalization_authority,\n"
            b"}))\n"
        )
        output = io.StringIO()
        with redirect_stdout(output):
            result = launcher_module._execute_held_controller(
                source=source,
                runtime_bundle={"fixture.py": source},
                goal_resource_bundle={"references/fixture.md": b"original"},
                controller_path="/held/scripts/fixture.py",
                scripts_directory="/held/scripts",
                controller_argv=[],
            )

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["failures"], ["tuple", "module", "finder"])
        self.assertEqual(payload["runtime_proxy"], tuple.__name__)
        self.assertEqual(payload["goal_proxy"], tuple.__name__)
        self.assertEqual(payload["runtime_item_type"], tuple.__name__)
        self.assertFalse(payload["gc_dict_backing"])
        self.assertTrue(payload["self_hash_fields_absent"])
        self.assertFalse(payload["host_attested"])
        self.assertFalse(payload["verified"])
        self.assertFalse(payload["finalization_authority"])
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_executor_rejects_preseeded_or_replaced_provider_without_residue(self) -> None:
        launcher_module = load_launcher_module()
        marker = {"executed": False}
        source = b"MARKER['executed'] = True\n"
        preseeded = ModuleType(HELD_RUNTIME_CONTEXT_NAME)
        sys.modules[HELD_RUNTIME_CONTEXT_NAME] = preseeded
        try:
            with self.assertRaises(launcher_module._LauncherBlocked):
                launcher_module._execute_held_controller(
                    source=source,
                    runtime_bundle={"fixture.py": source},
                    goal_resource_bundle={},
                    controller_path="/held/scripts/fixture.py",
                    scripts_directory="/held/scripts",
                    controller_argv=[],
                )
        finally:
            self.assertIs(sys.modules.pop(HELD_RUNTIME_CONTEXT_NAME, None), preseeded)
        self.assertFalse(marker["executed"])

        replacing_source = (
            b"import sys, types\n"
            b"sys.modules['_codexqb_held_runtime_context_v1'] = types.ModuleType('replacement')\n"
        )
        with self.assertRaises(launcher_module._LauncherBlocked):
            launcher_module._execute_held_controller(
                source=replacing_source,
                runtime_bundle={"fixture.py": replacing_source},
                goal_resource_bundle={},
                controller_path="/held/scripts/fixture.py",
                scripts_directory="/held/scripts",
                controller_argv=[],
            )
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_goal_rejects_provider_attribute_replacement_before_resource_use(self) -> None:
        launcher_module = load_launcher_module()
        runtime_sources = test_runtime_sources()
        goal_resources = test_goal_resources()
        reference = "references/Autopsy-Planner.md"
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "forged-resource-consumed"
            source = (
                b"import goal_run, sys\n"
                b"from pathlib import Path\n"
                b"from types import ModuleType\n"
                b"context = sys.modules['_codexqb_held_runtime_context_v1']\n"
                b"resources = dict(context.goal_resources)\n"
                + f"resources[{reference!r}] = b'MALICIOUS_REFERENCE'\n".encode("utf-8")
                + b"ModuleType.__setattr__(context, 'goal_resources', tuple(sorted(resources.items())))\n"
                + b"try:\n"
                + f"    payload = goal_run.read_skill_bytes({reference!r})\n".encode("utf-8")
                + b"except ValueError:\n"
                + b"    pass\n"
                + b"else:\n"
                + f"    Path({os.fspath(marker)!r}).write_bytes(payload)\n".encode("utf-8")
            )
            local_names = {
                name.removesuffix(".py") for name in runtime_sources
            }
            previous_modules = {
                name: sys.modules.pop(name)
                for name in local_names
                if name in sys.modules
            }
            try:
                with self.assertRaises(launcher_module._LauncherBlocked):
                    launcher_module._execute_held_controller(
                        source=source,
                        runtime_bundle=runtime_sources,
                        goal_resource_bundle=goal_resources,
                        controller_path="/held/scripts/probe.py",
                        scripts_directory="/held/scripts",
                        controller_argv=[],
                    )
            finally:
                for name, module in previous_modules.items():
                    sys.modules[name] = module
            self.assertFalse(marker.exists())
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_finder_base_attribute_replacement_fails_before_module_execution(self) -> None:
        launcher_module = load_launcher_module()
        victim_name = "held_runtime_victim_fixture"
        legitimate_victim = b"VALUE = 'reviewed'\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "forged-held-module-executed"
            malicious_victim = (
                b"from pathlib import Path\n"
                + f"Path({os.fspath(marker)!r}).write_text('executed')\n".encode("utf-8")
            )
            source = (
                b"import sys\n"
                b"finder = next(item for item in sys.meta_path if type(item).__name__ == '_HeldRuntimeFinder')\n"
                b"sources = dict(finder._sources)\n"
                + f"sources[{victim_name + '.py'!r}] = {malicious_victim!r}\n".encode("utf-8")
                + b"object.__setattr__(finder, '_sources', tuple(sorted(sources.items())))\n"
                + b"try:\n"
                + f"    __import__({victim_name!r})\n".encode("utf-8")
                + b"except ImportError:\n"
                + b"    pass\n"
            )
            self.assertNotIn(victim_name, sys.modules)
            with self.assertRaises(launcher_module._LauncherBlocked):
                launcher_module._execute_held_controller(
                    source=source,
                    runtime_bundle={
                        "fixture.py": source,
                        f"{victim_name}.py": legitimate_victim,
                    },
                    goal_resource_bundle={},
                    controller_path="/held/scripts/fixture.py",
                    scripts_directory="/held/scripts",
                    controller_argv=[],
                )
            self.assertFalse(marker.exists())
            self.assertNotIn(victim_name, sys.modules)
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_launcher_final_state_check_cannot_run_attacker_eq(self) -> None:
        launcher_module = load_launcher_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            marker = Path(temp_dir) / "attacker-eq-executed"
            source = (
                b"import sys\n"
                b"from pathlib import Path\n"
                b"from types import ModuleType\n"
                b"context = sys.modules['_codexqb_held_runtime_context_v1']\n"
                b"class AttackerControlledScalar:\n"
                b"    def __eq__(self, other):\n"
                + f"        Path({os.fspath(marker)!r}).write_text('executed')\n".encode("utf-8")
                + b"        return True\n"
                + b"ModuleType.__setattr__(context, 'schema_version', AttackerControlledScalar())\n"
            )
            with self.assertRaises(launcher_module._LauncherBlocked):
                launcher_module._execute_held_controller(
                    source=source,
                    runtime_bundle={"fixture.py": source},
                    goal_resource_bundle={},
                    controller_path="/held/scripts/fixture.py",
                    scripts_directory="/held/scripts",
                    controller_argv=[],
                )
            self.assertFalse(marker.exists())
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_goal_reference_uses_held_bytes_after_atomic_skill_root_swap(self) -> None:
        launcher_module = load_launcher_module()
        runtime_sources = test_runtime_sources()
        goal_resources = test_goal_resources()
        reference = "references/Autopsy-Planner.md"
        original_digest = hashlib.sha256(goal_resources[reference]).hexdigest()
        source = (
            b"import goal_run, hashlib, json, sys\n"
            + f"payload = goal_run.read_skill_bytes({reference!r})\n".encode("utf-8")
            + b"print(json.dumps({'sha256': hashlib.sha256(payload).hexdigest(), 'malicious': b'MALICIOUS_REFERENCE' in payload}))\n"
        )
        local_names = {
            name.removesuffix(".py") for name in runtime_sources
        }
        previous_modules = {
            name: sys.modules.pop(name)
            for name in local_names
            if name in sys.modules
        }
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                active = base / "active-codexqb"
                old = base / "held-old-codexqb"
                replacement = base / "replacement-codexqb"
                (active / "scripts").mkdir(parents=True)
                (replacement / "scripts").mkdir(parents=True)
                malicious = replacement / reference
                malicious.parent.mkdir(parents=True)
                malicious.write_bytes(b"MALICIOUS_REFERENCE")
                active.rename(old)
                replacement.rename(active)
                output = io.StringIO()
                with redirect_stdout(output):
                    result = launcher_module._execute_held_controller(
                        source=source,
                        runtime_bundle=runtime_sources,
                        goal_resource_bundle=goal_resources,
                        controller_path=os.fspath(active / "scripts/probe.py"),
                        scripts_directory=os.fspath(active / "scripts"),
                        controller_argv=[],
                    )
        finally:
            for name, module in previous_modules.items():
                sys.modules[name] = module

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["sha256"], original_digest)
        self.assertFalse(payload["malicious"])
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_validator_capture_and_execution_use_held_bytes_after_scripts_swap(self) -> None:
        launcher_module = load_launcher_module()
        runtime_sources = test_runtime_sources()
        goal_resources = test_goal_resources()
        expected_digest = hashlib.sha256(
            runtime_sources["validate_planner_docs.py"]
        ).hexdigest()
        local_names = {
            name.removesuffix(".py") for name in runtime_sources
        }
        previous_modules = {
            name: sys.modules.pop(name)
            for name in local_names
            if name in sys.modules
        }
        try:
            with tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                active_scripts = base / "active/scripts"
                replacement_scripts = base / "replacement/scripts"
                active_scripts.mkdir(parents=True)
                replacement_scripts.mkdir(parents=True)
                repository = base / "repository"
                repository.mkdir()
                marker = base / "malicious-validator-executed"
                (replacement_scripts / "validate_planner_docs.py").write_text(
                    "from pathlib import Path\n"
                    f"Path({os.fspath(marker)!r}).write_text('executed')\n",
                    encoding="utf-8",
                )
                active_scripts.rename(base / "held-old-scripts")
                replacement_scripts.rename(active_scripts)
                source = (
                    b"import execution_controller, json\n"
                    b"bundle = execution_controller.capture_planner_validator_bundle()\n"
                    + f"code, output = execution_controller.run_goal_planner_validator(root=__import__('pathlib').Path({os.fspath(repository)!r}), mode='step1', strict=True, bundle=bundle)\n".encode("utf-8")
                    + b"print(json.dumps({'sources': dict(bundle.source_sha256), 'code': code, 'output': output}))\n"
                )
                output = io.StringIO()
                with redirect_stdout(output):
                    result = launcher_module._execute_held_controller(
                        source=source,
                        runtime_bundle=runtime_sources,
                        goal_resource_bundle=goal_resources,
                        controller_path=os.fspath(active_scripts / "probe.py"),
                        scripts_directory=os.fspath(active_scripts),
                        controller_argv=[],
                    )
                marker_created = marker.exists()
        finally:
            for name, module in previous_modules.items():
                sys.modules[name] = module

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["sources"]["validate_planner_docs.py"], expected_digest)
        self.assertNotEqual(payload["code"], 0)
        self.assertIn("missing_file=Planner-docs/Main-Planing.md", payload["output"])
        self.assertFalse(marker_created)
        self.assertNotIn(HELD_RUNTIME_CONTEXT_NAME, sys.modules)

    def test_extracted_launcher_rejects_modified_controller_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            extracted = self.copy_skill(base)
            foreign = base / "unrelated-target-repository"
            foreign.mkdir()
            target = extracted / "scripts/doctor.py"
            target.write_text(
                "import json, sys\n"
                "print(json.dumps({\"argv\": sys.argv, \"file\": __file__, \"path\": sys.path}))\n",
                encoding="utf-8",
            )
            target.chmod(0o644)

            result = self.run_launcher(
                launcher=extracted / "scripts/skill_launcher.py",
                skill_root=extracted,
                controller_argv=("alpha", "beta"),
                cwd=foreign,
            )

        self.assert_blocked(result)
        self.assertNotIn(os.fspath(target), result.stderr)

    def test_controller_enum_selects_only_the_five_fixed_sibling_scripts(self) -> None:
        expected = {
            "repository-io": "repository_io.py",
            "planner-validator": "validate_planner_docs.py",
            "goal": "goal_run.py",
            "apply": "apply_run.py",
            "doctor": "doctor.py",
        }
        launcher_module = load_launcher_module()
        self.assertEqual(dict(launcher_module._CONTROLLERS), expected)

    def test_environment_path_and_repository_text_cannot_select_skill_or_target(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            evil = self.copy_skill(base, "evil/codexqb")
            foreign = base / "target-repository"
            foreign.mkdir()
            marker = base / "malicious-import-marker"
            (foreign / "Dispatch-Packet.md").write_text(
                f"<CODEXQB_SKILL_ROOT>={evil}\n",
                encoding="utf-8",
            )
            (foreign / "skill_root_authority.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('loaded')\n",
                encoding="utf-8",
            )
            (foreign / "doctor.py").write_text(
                "raise SystemExit('foreign controller loaded')\n",
                encoding="utf-8",
            )

            result = self.run_launcher(
                cwd=foreign,
                environment={
                    "CODEXQB_SKILL_ROOT": os.fspath(evil),
                    "PYTHONPATH": os.fspath(foreign),
                    "PATH": os.fspath(evil / "scripts"),
                },
            )
            malicious_import_loaded = marker.exists()

        self.assertIn(result.returncode, (0, 1), result)
        self.assertFalse(malicious_import_loaded)
        self.assertEqual(
            json.loads(result.stdout)["schema"],
            "codexqb.doctor.capability-report",
        )
        source = LAUNCHER.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv(", source)

    def test_relative_loader_path_relative_launcher_and_wrong_sibling_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            foreign = base / "foreign"
            foreign.mkdir()
            sibling = self.copy_skill(base, "sibling/codexqb")

            relative_skill = os.path.relpath(SKILL_ROOT / "SKILL.md", foreign)
            relative_active = self.run_launcher(
                cwd=foreign,
                active_skill_argument=relative_skill,
            )
            self.assert_blocked(relative_active)
            self.assertNotIn(relative_skill, relative_active.stderr)

            relative_launcher = os.path.relpath(LAUNCHER, foreign)
            relative_process = self.run_launcher(
                cwd=foreign,
                launcher_argument=relative_launcher,
            )
            self.assert_blocked(relative_process)
            self.assertNotIn(relative_launcher, relative_process.stderr)

            wrong_sibling = self.run_launcher(
                cwd=foreign,
                active_skill_argument=os.fspath(sibling / "SKILL.md"),
            )
            self.assert_blocked(wrong_sibling)
            self.assertNotIn(os.fspath(sibling), wrong_sibling.stderr)

            relative_copy = self.copy_skill(base, "relative/codexqb")
            marker = base / "relative-authority-imported"
            (relative_copy / "scripts/skill_root_authority.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('loaded')\n",
                encoding="utf-8",
            )
            relative_copy_launcher = os.path.relpath(
                relative_copy / "scripts/skill_launcher.py",
                foreign,
            )
            rejected_before_import = self.run_launcher(
                skill_root=relative_copy,
                cwd=foreign,
                launcher_argument=relative_copy_launcher,
            )
            self.assert_blocked(rejected_before_import)
            self.assertFalse(marker.exists())

    def test_unsafe_active_skill_components_reject_before_authority_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            copied = self.copy_skill(base, "safe-copy/codexqb")
            marker = base / "unsafe-active-authority-imported"
            (copied / "scripts/skill_root_authority.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('loaded')\n",
                encoding="utf-8",
            )

            for label, character in UNSAFE_PATH_COMPONENTS:
                unsafe_component = f"unsafe{character}component"
                with self.subTest(category=label):
                    result = self.run_launcher(
                        launcher=copied / "scripts/skill_launcher.py",
                        skill_root=copied,
                        active_skill_argument=(
                            f"/safe/{unsafe_component}/codexqb/SKILL.md"
                        ),
                        cwd=base,
                    )
                    self.assertEqual(result.returncode, 2, label)
                    self.assertEqual(result.stdout, "", label)
                    self.assertEqual(
                        result.stderr,
                        BLOCKED_PREFIX + "active_skill_path_rejected\n",
                        label,
                    )
                    self.assertFalse(marker.exists(), label)

    def test_unsafe_launcher_components_reject_before_authority_import(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            for label, character in UNSAFE_PATH_COMPONENTS:
                with self.subTest(category=label):
                    unsafe_parent = base / f"unsafe{character}component"
                    copied = self.copy_skill(unsafe_parent, "codexqb")
                    marker = base / f"unsafe-launcher-authority-imported-{label}"
                    (copied / "scripts/skill_root_authority.py").write_text(
                        f"open({os.fspath(marker)!r}, 'w').write('loaded')\n",
                        encoding="utf-8",
                    )
                    result = self.run_launcher(
                        launcher=copied / "scripts/skill_launcher.py",
                        skill_root=copied,
                        cwd=base,
                    )
                    self.assertEqual(result.returncode, 2, label)
                    self.assertEqual(result.stdout, "", label)
                    self.assertEqual(
                        result.stderr,
                        BLOCKED_PREFIX + "launcher_path_rejected\n",
                        label,
                    )
                    self.assertFalse(marker.exists(), label)

    def test_symlinked_loader_launcher_and_controller_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()

            loader_copy = self.copy_skill(base, "loader/codexqb")
            real_skill_md = loader_copy / "SKILL.real.md"
            (loader_copy / "SKILL.md").rename(real_skill_md)
            (loader_copy / "SKILL.md").symlink_to(real_skill_md.name)
            loader_result = self.run_launcher(
                launcher=loader_copy / "scripts/skill_launcher.py",
                skill_root=loader_copy,
                cwd=base,
            )
            self.assert_blocked(loader_result)

            launcher_copy = self.copy_skill(base, "launcher/codexqb")
            launcher = launcher_copy / "scripts/skill_launcher.py"
            real_launcher = launcher.with_name("skill_launcher.real.py")
            launcher.rename(real_launcher)
            launcher.symlink_to(real_launcher.name)
            launcher_result = self.run_launcher(
                launcher=launcher,
                skill_root=launcher_copy,
                cwd=base,
            )
            self.assert_blocked(launcher_result)

            target_copy = self.copy_skill(base, "target/codexqb")
            target = target_copy / "scripts/doctor.py"
            real_target = target.with_name("doctor.real.py")
            target.rename(real_target)
            target.symlink_to(real_target.name)
            target_result = self.run_launcher(
                launcher=target_copy / "scripts/skill_launcher.py",
                skill_root=target_copy,
                cwd=base,
            )
            self.assert_blocked(target_result)

    def test_target_mode_and_hardlink_controls_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()

            mode_copy = self.copy_skill(base, "mode/codexqb")
            (mode_copy / "scripts/doctor.py").chmod(0o664)
            mode_result = self.run_launcher(
                launcher=mode_copy / "scripts/skill_launcher.py",
                skill_root=mode_copy,
                cwd=base,
            )
            self.assert_blocked(mode_result)

            link_copy = self.copy_skill(base, "link/codexqb")
            target = link_copy / "scripts/doctor.py"
            os.link(target, target.with_name("doctor.peer.py"))
            link_result = self.run_launcher(
                launcher=link_copy / "scripts/skill_launcher.py",
                skill_root=link_copy,
                cwd=base,
            )
            self.assert_blocked(link_result)

    def test_modified_runtime_dependency_is_rejected_without_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            modified = self.copy_skill(base, "modified-runtime/codexqb")
            marker = base / "modified-runtime-executed"
            (modified / "scripts/repository_evidence.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('executed')\n",
                encoding="utf-8",
            )
            result = self.run_launcher(
                launcher=modified / "scripts/skill_launcher.py",
                skill_root=modified,
                cwd=base,
            )
            marker_created = marker.exists()

        self.assert_blocked(result)
        self.assertFalse(marker_created)
        self.assertNotIn(os.fspath(modified), result.stderr)

    def test_held_finder_ignores_atomic_scripts_directory_replacement(self) -> None:
        launcher_module = load_launcher_module()
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            lexical_scripts = base / "active/scripts"
            lexical_scripts.mkdir(parents=True)
            replacement_scripts = base / "replacement/scripts"
            replacement_scripts.mkdir(parents=True)
            marker = base / "replacement-peer-executed"
            (replacement_scripts / "repository_evidence.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('executed')\n",
                encoding="utf-8",
            )
            (replacement_scripts / "fcntl.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('shadowed-stdlib')\n",
                encoding="utf-8",
            )
            held_dependency = (
                b"from pathlib import Path\n"
                b"import sys\n"
                b"SCRIPT_DIR = Path(__file__).resolve().parent\n"
                b"if str(SCRIPT_DIR) not in sys.path:\n"
                b"    sys.path.insert(0, str(SCRIPT_DIR))\n"
                b"import fcntl\n"
                b"ORIGIN = 'held-descriptor-bytes'\n"
                b"FCNTL_ORIGIN = getattr(fcntl, '__file__', '')\n"
            )
            held_target = (
                b"import json, repository_evidence, sys\n"
                b"print(json.dumps({'origin': repository_evidence.ORIGIN, "
                b"'fcntl': repository_evidence.FCNTL_ORIGIN, 'path': list(sys.path)}))\n"
            )

            lexical_scripts.rename(base / "held-old-scripts")
            replacement_scripts.rename(lexical_scripts)
            output = io.StringIO()
            preserved_modules = {
                name: sys.modules.pop(name)
                for name in ("fcntl", "repository_evidence")
                if name in sys.modules
            }
            try:
                with redirect_stdout(output):
                    result = launcher_module._execute_held_controller(
                        source=held_target,
                        runtime_bundle={
                            "doctor.py": held_target,
                            "repository_evidence.py": held_dependency,
                        },
                        goal_resource_bundle={},
                        controller_path=os.fspath(lexical_scripts / "doctor.py"),
                        scripts_directory=os.fspath(lexical_scripts),
                        controller_argv=[],
                    )
            finally:
                for name in ("fcntl", "repository_evidence"):
                    sys.modules.pop(name, None)
                sys.modules.update(preserved_modules)
            marker_created = marker.exists()

        self.assertEqual(result, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["origin"], "held-descriptor-bytes")
        self.assertNotIn(os.fspath(lexical_scripts), payload["fcntl"])
        self.assertNotIn(os.fspath(lexical_scripts), payload["path"])
        self.assertFalse(marker_created)

    def test_fixed_enum_and_exact_cli_shape_reject_target_path_options(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            cwd = Path(temp_dir).resolve()
            invalid_enum = self.run_launcher(
                cwd=cwd,
                controller="/tmp/doctor.py",
            )
            self.assert_blocked(invalid_enum)

            command = [
                sys.executable,
                "-I",
                "-S",
                "-B",
                os.fspath(LAUNCHER),
                "--active-skill-md",
                os.fspath(SKILL_ROOT / "SKILL.md"),
                "--controller",
                "doctor",
                "--target",
                "/tmp/doctor.py",
                "--",
            ]
            unexpected_option = subprocess.run(
                command,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            self.assert_blocked(unexpected_option)
            self.assertNotIn("/tmp/doctor.py", unexpected_option.stderr)

    def test_missing_first_process_flags_fail_before_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            marker = base / "shadowed-hashlib-imported"
            (base / "hashlib.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('executed')\n",
                encoding="utf-8",
            )
            env = os.environ.copy()
            env.pop("PYTHONDONTWRITEBYTECODE", None)
            env["PYTHONPATH"] = os.fspath(base)
            result = subprocess.run(
                [
                    sys.executable,
                    "-S",
                    os.fspath(LAUNCHER),
                    "--active-skill-md",
                    "/not/a/real/SKILL.md",
                    "--controller",
                    "doctor",
                    "--",
                ],
                cwd=base,
                env=env,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )

        self.assert_blocked(result)
        self.assertEqual(
            result.stderr,
            BLOCKED_PREFIX + "requires_python_-I_-S_-B_first_process\n",
        )
        self.assertNotIn("/not/a/real", result.stderr)
        self.assertFalse(marker.exists())

    def test_runpy_prelude_and_preseeded_authority_cannot_launch_controller(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            marker = base / "preseeded-authority-executed"
            code = (
                "import runpy,sys,types\n"
                "fake=types.ModuleType('skill_root_authority')\n"
                f"fake.open_skill_root_authority=lambda **kwargs: open({os.fspath(marker)!r},'w')\n"
                "sys.modules['skill_root_authority']=fake\n"
                f"sys.argv={[os.fspath(LAUNCHER), '--active-skill-md', os.fspath(SKILL_ROOT / 'SKILL.md'), '--controller', 'doctor', '--', '--json']!r}\n"
                f"runpy.run_path({os.fspath(LAUNCHER)!r},run_name='__main__')\n"
            )
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B", "-c", code],
                cwd=base,
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            marker_created = marker.exists()

        self.assert_blocked(result)
        self.assertFalse(marker_created)
        self.assertEqual(
            result.stderr,
            BLOCKED_PREFIX + "requires_python_-I_-S_-B_first_process\n",
        )

    def test_authority_import_failure_is_content_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            broken = self.copy_skill(base, "broken/codexqb")
            (broken / "scripts/skill_root_authority.py").write_text(
                "this is not valid python !!!\n",
                encoding="utf-8",
            )
            result = self.run_launcher(
                launcher=broken / "scripts/skill_launcher.py",
                skill_root=broken,
                cwd=base,
            )

        self.assert_blocked(result)
        self.assertEqual(
            result.stderr,
            BLOCKED_PREFIX + "authority_import_rejected\n",
        )
        self.assertNotIn(os.fspath(broken), result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_unreviewed_peer_authority_cannot_execute_before_binding(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            replaced = self.copy_skill(base, "replaced-authority/codexqb")
            marker = base / "unreviewed-authority-executed"
            (replaced / "scripts/skill_root_authority.py").write_text(
                f"open({os.fspath(marker)!r}, 'w').write('executed')\n",
                encoding="utf-8",
            )
            result = self.run_launcher(
                launcher=replaced / "scripts/skill_launcher.py",
                skill_root=replaced,
                cwd=base,
            )
            marker_created = marker.exists()

        self.assert_blocked(result)
        self.assertFalse(marker_created)
        self.assertNotIn(os.fspath(replaced), result.stderr)

    def test_direct_controller_first_process_blocks_before_sibling_imports(self) -> None:
        for basename in CONTROLLER_BASENAMES:
            with self.subTest(controller=basename), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                controller = base / basename
                shutil.copyfile(SKILL_ROOT / "scripts" / basename, controller)
                controller.chmod(0o644)

                result = subprocess.run(
                    (
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        os.fspath(controller),
                        "--help",
                    ),
                    cwd=base,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                self.assertEqual(result.returncode, 2, result)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, DIRECT_CONTROLLER_BLOCK)

    def test_missing_isolation_flag_blocks_before_shadowed_types_import(self) -> None:
        for basename in CONTROLLER_BASENAMES:
            with self.subTest(controller=basename), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                controller = base / basename
                marker = base / "shadowed-types-imported"
                shutil.copyfile(SKILL_ROOT / "scripts" / basename, controller)
                controller.chmod(0o644)
                (base / "types.py").write_text(
                    f"open({os.fspath(marker)!r}, 'w').write('executed')\n"
                    "class ModuleType: pass\n",
                    encoding="utf-8",
                )

                result = subprocess.run(
                    (
                        sys.executable,
                        "-S",
                        "-B",
                        os.fspath(controller),
                        "--help",
                    ),
                    cwd=base,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                self.assertEqual(result.returncode, 2, result)
                self.assertEqual(result.stdout, "")
                self.assertIn(
                    "requires_python_-I_-S_-B_first_process",
                    result.stderr,
                )
                self.assertFalse(marker.exists(), basename)

    def test_malformed_held_provider_shapes_block_before_sibling_imports(self) -> None:
        provider_name = "_codexqb_held_runtime_context_v1"
        malformed_setups = (
            "context = object()",
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = True",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b'x'),)",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = [('doctor.py', b'x')]",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('other.py', b'x'),)",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = True",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b'x'),)",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'wrong_assurance'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b'x'),)",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = ()",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b''),)",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b'x'),)",
                    "context.runtime_sha256 = '0' * 64",
                )
            ),
            "\n".join(
                (
                    "context = ModuleType(provider_name)",
                    "context.schema_version = 1",
                    "context.assurance = 'controller_observed_loader_path_unattested'",
                    "context.host_attested = False",
                    "context.verified = False",
                    "context.finalization_authority = False",
                    "context.runtime_sources = (('doctor.py', b'x'), ('apply_run.py', b'y'))",
                )
            ),
        )
        for case_number, provider_setup in enumerate(malformed_setups, start=1):
            with self.subTest(case=case_number), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                controller = base / "doctor.py"
                shutil.copyfile(SKILL_ROOT / "scripts/doctor.py", controller)
                controller.chmod(0o644)
                prelude = "\n".join(
                    (
                        "import runpy, sys",
                        "from types import ModuleType",
                        f"provider_name = {provider_name!r}",
                        provider_setup,
                        "sys.modules[provider_name] = context",
                        f"sys.argv = [{os.fspath(controller)!r}, '--json']",
                        f"runpy.run_path({os.fspath(controller)!r}, run_name='__main__')",
                    )
                )
                result = subprocess.run(
                    (sys.executable, "-I", "-S", "-B", "-c", prelude),
                    cwd=base,
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                )

                self.assertEqual(result.returncode, 2, result)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, DIRECT_CONTROLLER_BLOCK)

    def test_controller_admission_helpers_have_one_identical_early_ast_shape(self) -> None:
        helper_shapes: dict[str, str] = {}
        expected_basename_by_path: dict[str, str] = {}
        for basename in CONTROLLER_BASENAMES:
            path = SKILL_ROOT / "scripts" / basename
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=os.fspath(path))
            helpers = [
                node
                for node in tree.body
                if isinstance(node, ast.FunctionDef)
                and node.name == "_launcher_admission_is_valid"
            ]
            self.assertEqual(len(helpers), 1, basename)
            helper = helpers[0]
            helper_shapes[basename] = ast.dump(helper, include_attributes=False)
            calls = [
                node
                for node in ast.walk(tree)
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_launcher_admission_is_valid"
            ]
            self.assertEqual(len(calls), 1, basename)
            self.assertEqual(len(calls[0].args), 1, basename)
            self.assertFalse(calls[0].keywords, basename)
            expected_basename_by_path[basename] = ast.literal_eval(calls[0].args[0])
            later_imports = [
                node
                for node in tree.body
                if isinstance(node, (ast.Import, ast.ImportFrom))
                and node.lineno > helper.lineno
            ]
            self.assertTrue(later_imports, basename)
            self.assertLess(calls[0].lineno, min(node.lineno for node in later_imports))

        self.assertEqual(len(set(helper_shapes.values())), 1)
        self.assertEqual(
            expected_basename_by_path,
            {basename: basename for basename in CONTROLLER_BASENAMES},
        )

    def test_same_process_forged_shape_is_explicitly_unattested_residual(self) -> None:
        # Python already running arbitrary code can synthesize this local shape.
        # Admission closes ordinary direct-first-process execution; it is not a
        # host-issued invocation token and must never be described as attestation.
        provider_name = "_codexqb_held_runtime_context_v1"
        controller = SKILL_ROOT / "scripts/doctor.py"
        prelude = "\n".join(
            (
                "import runpy, sys",
                "from types import ModuleType",
                f"provider_name = {provider_name!r}",
                "context = ModuleType(provider_name)",
                "context.schema_version = 1",
                "context.assurance = 'controller_observed_loader_path_unattested'",
                "context.host_attested = False",
                "context.verified = False",
                "context.finalization_authority = False",
                "context.runtime_sources = (('doctor.py', b'forged-unattested'),)",
                "sys.modules[provider_name] = context",
                f"sys.argv = [{os.fspath(controller)!r}, '--json']",
                f"runpy.run_path({os.fspath(controller)!r}, run_name='__main__')",
            )
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            result = subprocess.run(
                (sys.executable, "-I", "-S", "-B", "-c", prelude),
                cwd=Path(temp_dir).resolve(),
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

        self.assertIn(result.returncode, (0, 1), result)
        self.assertEqual(result.stderr, "")
        self.assertEqual(
            json.loads(result.stdout)["schema"],
            "codexqb.doctor.capability-report",
        )

    def test_self_consistent_wrong_copy_is_explicitly_unattested(self) -> None:
        launcher_module = load_launcher_module()
        self.assertEqual(
            launcher_module.launcher_receipt(),
            {
                "schema_version": 1,
                "assurance": "controller_observed_loader_path_unattested",
                "host_attested": False,
                "verified": False,
                "finalization_authority": False,
            },
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            wrong_copy = self.copy_skill(base, "self-consistent-wrong/codexqb")
            result = self.run_launcher(
                launcher=wrong_copy / "scripts/skill_launcher.py",
                skill_root=wrong_copy,
                cwd=base,
            )

        # Without a host token the copied launcher and copied SKILL.md form the
        # same controller-observed layout and are intentionally accepted only
        # under the unattested receipt above.
        self.assertIn(result.returncode, (0, 1), result)
        self.assertEqual(
            json.loads(result.stdout)["schema"],
            "codexqb.doctor.capability-report",
        )


if __name__ == "__main__":
    unittest.main()
