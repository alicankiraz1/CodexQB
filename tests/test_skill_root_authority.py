from __future__ import annotations

import ast
import hashlib
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb"
SCRIPTS_ROOT = SKILL_ROOT / "scripts"
AUTHORITY_PATH = SCRIPTS_ROOT / "skill_root_authority.py"
MOUNT_IDENTITY_PATH = SCRIPTS_ROOT / "mount_identity.py"
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


def load_authority_module():
    scripts_text = os.fspath(SCRIPTS_ROOT)
    if scripts_text not in sys.path:
        sys.path.insert(0, scripts_text)
    spec = importlib.util.spec_from_file_location(
        "codexqb_skill_root_authority",
        AUTHORITY_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load skill root authority from {AUTHORITY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


AUTHORITY = load_authority_module()


class SkillRootAuthorityTests(unittest.TestCase):
    def make_layout(self, base: Path, relative: str = "skills/codexqb") -> tuple[Path, Path]:
        skill_root = base / relative
        scripts_root = skill_root / "scripts"
        scripts_root.mkdir(parents=True)
        skill_path = skill_root / "SKILL.md"
        script_path = scripts_root / "goal_run.py"
        skill_path.write_text("---\nname: codexqb\n---\n", encoding="utf-8")
        script_path.write_text("# isolated launcher fixture\n", encoding="utf-8")
        mount_path = scripts_root / "mount_identity.py"
        shutil.copyfile(MOUNT_IDENTITY_PATH, mount_path)
        skill_root.chmod(0o755)
        scripts_root.chmod(0o755)
        skill_path.chmod(0o644)
        script_path.chmod(0o644)
        mount_path.chmod(0o644)
        return skill_path, script_path

    def open_binding(self, skill_path: Path, script_path: Path):
        return AUTHORITY.open_skill_root_authority(
            loader_skill_md_path=os.fspath(skill_path),
            executing_script_path=os.fspath(script_path),
            expected_script_basename=script_path.name,
        )

    def make_runtime_layout(self, base: Path) -> tuple[Path, Path]:
        skill_path, script_path = self.make_layout(base)
        scripts_root = skill_path.parent / "scripts"
        for basename in AUTHORITY.REVIEWED_SCRIPT_BASENAMES:
            source = SCRIPTS_ROOT / basename
            self.assertTrue(source.is_file(), basename)
            destination = scripts_root / basename
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
        return skill_path, scripts_root / "goal_run.py"

    def make_skill_resource_layout(self, base: Path) -> tuple[Path, Path]:
        skill_path, script_path = self.make_layout(base)
        skill_root = skill_path.parent
        for relative_path in AUTHORITY.GOAL_REFERENCE_PATHS:
            source = SKILL_ROOT / relative_path
            destination = skill_root / relative_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
        for directory in (
            skill_root / "references",
            skill_root / "references/goal-specs",
            skill_root / "references/handoffs",
        ):
            directory.chmod(0o755)
        return skill_path, script_path

    def test_valid_source_layout_returns_content_free_unattested_receipt(self) -> None:
        with AUTHORITY.open_skill_root_authority(
            loader_skill_md_path=os.fspath(SKILL_ROOT / "SKILL.md"),
            executing_script_path=os.fspath(AUTHORITY_PATH),
            expected_script_basename="skill_root_authority.py",
        ) as binding:
            self.assertEqual(binding.skill_root, SKILL_ROOT)
            self.assertEqual(binding.scripts_directory, SCRIPTS_ROOT)
            self.assertGreaterEqual(binding.skill_root_fd, 0)
            self.assertGreaterEqual(binding.scripts_fd, 0)
            self.assertGreaterEqual(binding.skill_markdown_fd, 0)
            self.assertGreaterEqual(binding.executing_script_fd, 0)
            binding.revalidate()
            receipt = binding.receipt()

        self.assertEqual(
            receipt,
            {
                "schema_version": 1,
                "assurance": "controller_observed_loader_path_unattested",
                "host_attested": False,
                "binding": "held_descriptor_skill_layout",
            },
        )
        serialized = json.dumps(receipt, sort_keys=True)
        for forbidden in ("sha256", "content", "device", "inode", "uid", os.fspath(SKILL_ROOT)):
            self.assertNotIn(forbidden, serialized)

    def test_mount_identity_pin_matches_exact_current_source(self) -> None:
        self.assertEqual(
            AUTHORITY.MOUNT_IDENTITY_SOURCE_SHA256,
            hashlib.sha256(MOUNT_IDENTITY_PATH.read_bytes()).hexdigest(),
        )

    def test_valid_extracted_layout_is_not_repository_relative(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            # macOS exposes TemporaryDirectory through /var, which is itself a
            # symlink.  A loader-supplied canonical lexical path uses /private.
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base, "package/skills/codexqb")

            with self.open_binding(skill_path, script_path) as binding:
                self.assertEqual(binding.skill_root, skill_path.parent)
                binding.revalidate()

    def test_relative_dotdot_and_wrong_basename_inputs_fail_closed(self) -> None:
        valid_skill = os.fspath(SKILL_ROOT / "SKILL.md")
        valid_script = os.fspath(AUTHORITY_PATH)
        invalid_cases = (
            ("plugins/codexqb/SKILL.md", valid_script, "skill_root_authority.py"),
            (valid_skill, "plugins/codexqb/scripts/skill_root_authority.py", "skill_root_authority.py"),
            (valid_skill.replace("/SKILL.md", "/scripts/../SKILL.md"), valid_script, "skill_root_authority.py"),
            (valid_skill, valid_script, "goal_run.py"),
            (valid_skill.replace("SKILL.md", "OTHER.md"), valid_script, "skill_root_authority.py"),
        )
        for case_number, (skill_path, script_path, expected) in enumerate(invalid_cases, start=1):
            with self.subTest(case_number=case_number):
                with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                    with AUTHORITY.open_skill_root_authority(
                        loader_skill_md_path=skill_path,
                        executing_script_path=script_path,
                        expected_script_basename=expected,
                    ):
                        self.fail("invalid binding unexpectedly opened")

    def test_shell_unsafe_loader_and_executing_components_reject_before_open(self) -> None:
        safe_skill = "/safe/codexqb/SKILL.md"
        safe_script = "/safe/codexqb/scripts/goal_run.py"
        for label, character in UNSAFE_PATH_COMPONENTS:
            unsafe_component = f"unsafe{character}component"
            cases = (
                (
                    "loader",
                    f"/safe/{unsafe_component}/codexqb/SKILL.md",
                    safe_script,
                    "skill_root_authority_loader_skill_path_component_invalid",
                ),
                (
                    "executing",
                    safe_skill,
                    f"/safe/{unsafe_component}/codexqb/scripts/goal_run.py",
                    "skill_root_authority_executing_script_path_component_invalid",
                ),
            )
            for path_kind, skill_path, script_path, expected_error in cases:
                with self.subTest(category=label, path_kind=path_kind):
                    with mock.patch.object(
                        AUTHORITY.os,
                        "open",
                        side_effect=AssertionError("filesystem open reached"),
                    ) as open_mock:
                        with self.assertRaisesRegex(ValueError, expected_error):
                            with AUTHORITY.open_skill_root_authority(
                                loader_skill_md_path=skill_path,
                                executing_script_path=script_path,
                                expected_script_basename="goal_run.py",
                            ):
                                self.fail("unsafe lexical component unexpectedly opened")
                    open_mock.assert_not_called()

    def test_parent_and_final_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            real_skill, real_script = self.make_layout(base, "real/skills/codexqb")

            linked_parent = base / "linked"
            linked_parent.symlink_to(base / "real", target_is_directory=True)
            linked_skill = linked_parent / "skills/codexqb/SKILL.md"
            linked_script = linked_parent / "skills/codexqb/scripts/goal_run.py"
            with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                with self.open_binding(linked_skill, linked_script):
                    self.fail("parent symlink unexpectedly opened")

            alternate_skill = real_skill.with_name("SKILL.real.md")
            real_skill.rename(alternate_skill)
            real_skill.symlink_to(alternate_skill.name)
            with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                with self.open_binding(real_skill, real_script):
                    self.fail("final SKILL.md symlink unexpectedly opened")

            real_skill.unlink()
            alternate_skill.rename(real_skill)
            alternate_script = real_script.with_name("goal_run.real.py")
            real_script.rename(alternate_script)
            real_script.symlink_to(alternate_script.name)
            with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                with self.open_binding(real_skill, real_script):
                    self.fail("final script symlink unexpectedly opened")

    def test_loader_and_executing_script_must_share_the_same_lexical_skill_root(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            first_skill, _first_script = self.make_layout(base, "skills/codexqb")
            _second_skill, second_script = self.make_layout(base, "skills/sibling")

            with self.assertRaisesRegex(ValueError, "skill_root_authority_layout_mismatch"):
                with self.open_binding(first_skill, second_script):
                    self.fail("foreign sibling script unexpectedly opened")

            # Without a host-issued invocation token a self-consistent sibling
            # is observable only as another unattested layout.  The primitive
            # must be honest about that limit rather than elevating it.
            second_skill = second_script.parent.parent / "SKILL.md"
            with self.open_binding(second_skill, second_script) as binding:
                self.assertEqual(
                    binding.receipt()["assurance"],
                    "controller_observed_loader_path_unattested",
                )
                self.assertFalse(binding.receipt()["host_attested"])

    def test_environment_path_and_repository_text_are_not_authority_sources(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            trusted_skill, trusted_script = self.make_layout(base, "trusted/skills/codexqb")
            evil_skill, _evil_script = self.make_layout(base, "evil/skills/codexqb")
            repository = base / "target-repository"
            repository.mkdir()
            (repository / "Dispatch-Packet.md").write_text(
                f"<CODEXQB_SKILL_ROOT>={evil_skill.parent}\n",
                encoding="utf-8",
            )
            previous_cwd = Path.cwd()
            try:
                os.chdir(repository)
                with mock.patch.dict(
                    os.environ,
                    {
                        "CODEXQB_SKILL_ROOT": os.fspath(evil_skill.parent),
                        "PATH": os.fspath(evil_skill.parent / "scripts"),
                    },
                    clear=False,
                ):
                    with self.open_binding(trusted_skill, trusted_script) as binding:
                        self.assertEqual(binding.skill_root, trusted_skill.parent)
            finally:
                os.chdir(previous_cwd)

        source = AUTHORITY_PATH.read_text(encoding="utf-8")
        self.assertNotIn("os.environ", source)
        self.assertNotIn("getenv(", source)
        self.assertNotIn("from mount_identity import", source)

    def test_target_repo_pythonpath_and_sys_modules_cannot_supply_mount_policy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base, "trusted/skills/codexqb")
            attacker = base / "target-repository"
            attacker.mkdir()
            (attacker / "mount_identity.py").write_text(
                "def require_same_mount(*args, **kwargs): return None\n",
                encoding="utf-8",
            )
            fake = types.ModuleType("mount_identity")
            fake.READ_ONLY_EVIDENCE = "attacker_policy"
            previous_path = list(sys.path)
            try:
                sys.path.insert(0, os.fspath(attacker))
                with mock.patch.dict(sys.modules, {"mount_identity": fake}):
                    with self.open_binding(skill_path, script_path) as binding:
                        binding.revalidate()
                        self.assertNotEqual(
                            binding._mount_module.READ_ONLY_EVIDENCE,
                            fake.READ_ONLY_EVIDENCE,
                        )
            finally:
                sys.path[:] = previous_path

    def test_acl_and_owner_controlled_mode_failures_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base)

            with mock.patch.object(AUTHORITY, "_descriptor_has_acl", return_value=True):
                with self.assertRaisesRegex(ValueError, "skill_root_authority_.*acl_rejected"):
                    with self.open_binding(skill_path, script_path):
                        self.fail("ACL-controlled layout unexpectedly opened")

            script_path.chmod(0o664)
            with self.assertRaisesRegex(ValueError, "skill_root_authority_owner_control_rejected"):
                with self.open_binding(skill_path, script_path):
                    self.fail("group-writable script unexpectedly opened")

            script_path.chmod(0o644)
            skill_path.parent.chmod(0o775)
            with self.assertRaisesRegex(ValueError, "skill_root_authority_owner_control_rejected"):
                with self.open_binding(skill_path, script_path):
                    self.fail("group-writable skill root unexpectedly opened")

            skill_path.parent.chmod(0o755)
            hardlink = script_path.with_name("goal_run.hardlink.py")
            os.link(script_path, hardlink)
            with self.assertRaisesRegex(ValueError, "skill_root_authority_owner_control_rejected"):
                with self.open_binding(skill_path, script_path):
                    self.fail("hardlinked script unexpectedly opened")

    def test_world_writable_ancestor_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            unsafe = base / "world-writable"
            unsafe.mkdir()
            unsafe.chmod(0o777)
            skill_path, script_path = self.make_layout(unsafe)

            with self.assertRaisesRegex(
                ValueError,
                "skill_root_authority_ancestor_owner_control_rejected",
            ):
                with self.open_binding(skill_path, script_path):
                    self.fail("world-writable ancestor unexpectedly opened")

    def test_unrelated_child_churn_does_not_change_ancestor_identity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base)
            with self.open_binding(skill_path, script_path) as binding:
                unrelated = base / "unrelated-child"
                unrelated.mkdir()
                unrelated.rmdir()
                binding.revalidate()

    def test_authorized_launch_targets_are_read_only_from_held_scripts_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base)
            doctor = script_path.with_name("doctor.py")
            doctor.write_bytes(b"# held doctor target\n")
            doctor.chmod(0o644)

            with self.open_binding(skill_path, script_path) as binding:
                self.assertEqual(binding.read_script_bytes("doctor.py"), doctor.read_bytes())
                self.assertEqual(
                    binding.read_script_bytes("goal_run.py"),
                    script_path.read_bytes(),
                )
                for rejected in (
                    "../goal_run.py",
                    "skill_launcher.py",
                    "/absolute/doctor.py",
                    ["doctor.py"],
                ):
                    with self.subTest(rejected=rejected):
                        with self.assertRaisesRegex(
                            ValueError,
                            "skill_root_authority_launch_target_rejected",
                        ):
                            binding.read_script_bytes(rejected)

    def test_runtime_bundle_is_exact_immutable_and_descriptor_bound(self) -> None:
        source_inventory = frozenset(path.name for path in SCRIPTS_ROOT.glob("*.py"))
        self.assertEqual(source_inventory, AUTHORITY.REVIEWED_SCRIPT_BASENAMES)
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_runtime_layout(base)

            with self.open_binding(skill_path, script_path) as binding:
                bundle = binding.read_runtime_bundle()
                self.assertEqual(
                    frozenset(bundle),
                    AUTHORITY.RUNTIME_BUNDLE_BASENAMES,
                )
                for basename, payload in bundle.items():
                    self.assertEqual(payload, (SCRIPTS_ROOT / basename).read_bytes())
                with self.assertRaises(TypeError):
                    bundle["artifact_io.py"] = b"attacker"  # type: ignore[index]
                with self.assertRaises(TypeError):
                    binding.read_runtime_bundle("artifact_io.py")  # type: ignore[call-arg]
                with self.assertRaisesRegex(
                    ValueError,
                    "skill_root_authority_launch_target_rejected",
                ):
                    binding.read_script_bytes("artifact_io.py")

    def test_runtime_bundle_matches_transitive_local_import_closure(self) -> None:
        local_modules = {
            path.stem for path in SCRIPTS_ROOT.glob("*.py") if path.is_file()
        }
        pending = {
            basename.removesuffix(".py")
            for basename in AUTHORITY.AUTHORIZED_LAUNCH_TARGET_BASENAMES
        }
        closure: set[str] = set()
        while pending:
            module_name = pending.pop()
            if module_name in closure:
                continue
            closure.add(module_name)
            tree = ast.parse(
                (SCRIPTS_ROOT / f"{module_name}.py").read_text(encoding="utf-8")
            )
            for node in ast.walk(tree):
                imported: list[str] = []
                if isinstance(node, ast.Import):
                    imported = [alias.name.split(".", 1)[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    imported = [node.module.split(".", 1)[0]]
                pending.update(
                    name for name in imported if name in local_modules and name not in closure
                )
            if module_name == "doctor":
                # doctor intentionally loads this capability dynamically.
                pending.add("mount_identity")
        self.assertEqual(
            {f"{module_name}.py" for module_name in closure},
            AUTHORITY.RUNTIME_BUNDLE_BASENAMES,
        )

    def test_runtime_bundle_rejects_dependency_symlink_hardlink_mode_and_acl(self) -> None:
        cases = ("symlink", "hardlink", "mode", "acl")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                skill_path, script_path = self.make_runtime_layout(base)
                dependency = skill_path.parent / "scripts/artifact_io.py"
                patcher = None
                if case == "symlink":
                    displaced = dependency.with_suffix(".real")
                    dependency.rename(displaced)
                    dependency.symlink_to(displaced.name)
                elif case == "hardlink":
                    os.link(dependency, dependency.with_name("artifact_io.alias"))
                elif case == "mode":
                    dependency.chmod(0o664)
                else:
                    identity = (dependency.stat().st_dev, dependency.stat().st_ino)
                    real_acl_probe = AUTHORITY._descriptor_has_acl

                    def dependency_acl(descriptor: int) -> bool:
                        metadata = os.fstat(descriptor)
                        if (metadata.st_dev, metadata.st_ino) == identity:
                            return True
                        return real_acl_probe(descriptor)

                    patcher = mock.patch.object(
                        AUTHORITY,
                        "_descriptor_has_acl",
                        side_effect=dependency_acl,
                    )

                context = patcher if patcher is not None else mock.patch.object(
                    AUTHORITY,
                    "_MAX_LAUNCH_TARGET_BYTES",
                    AUTHORITY._MAX_LAUNCH_TARGET_BYTES,
                )
                with context:
                    with self.open_binding(skill_path, script_path) as binding:
                        with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                            binding.read_runtime_bundle()

    def test_runtime_bundle_rejects_dependency_mount_mismatch_and_toctou(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_runtime_layout(base)
            with self.open_binding(skill_path, script_path) as binding:
                real_same_mount = binding._mount_module.require_same_mount

                def reject_runtime_mount(root, descriptor, label, **kwargs):
                    if str(label).startswith("scripts/runtime_module_"):
                        raise ValueError(f"repository_nested_mount_rejected={label}")
                    return real_same_mount(root, descriptor, label, **kwargs)

                with mock.patch.object(
                    binding._mount_module,
                    "require_same_mount",
                    side_effect=reject_runtime_mount,
                ):
                    with self.assertRaisesRegex(ValueError, "skill_root_authority_mount_mismatch"):
                        binding.read_runtime_bundle()

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_runtime_layout(base)
            dependency = skill_path.parent / "scripts/artifact_io.py"
            real_read = AUTHORITY._read_held_regular_bytes
            replaced = False

            def replace_after_read(entry, *, max_bytes):
                nonlocal replaced
                payload = real_read(entry, max_bytes=max_bytes)
                if entry.name == "artifact_io.py" and not replaced:
                    replaced = True
                    displaced = dependency.with_suffix(".displaced")
                    dependency.rename(displaced)
                    dependency.write_bytes(b"# attacker replacement\n")
                    dependency.chmod(0o644)
                return payload

            with self.open_binding(skill_path, script_path) as binding:
                with mock.patch.object(
                    AUTHORITY,
                    "_read_held_regular_bytes",
                    side_effect=replace_after_read,
                ):
                    with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                        binding.read_runtime_bundle()
            self.assertTrue(replaced)

    def test_runtime_bundle_ignores_malicious_same_name_cwd_and_rejects_inventory_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_runtime_layout(base)
            attacker = base / "target-repository"
            attacker.mkdir()
            malicious = b"raise RuntimeError('attacker module loaded')\n"
            (attacker / "artifact_io.py").write_bytes(malicious)
            previous_cwd = Path.cwd()
            previous_path = list(sys.path)
            try:
                os.chdir(attacker)
                sys.path.insert(0, os.fspath(attacker))
                with self.open_binding(skill_path, script_path) as binding:
                    bundle = binding.read_runtime_bundle()
                    self.assertNotEqual(bundle["artifact_io.py"], malicious)
                    self.assertEqual(
                        bundle["artifact_io.py"],
                        (SCRIPTS_ROOT / "artifact_io.py").read_bytes(),
                    )
            finally:
                sys.path[:] = previous_path
                os.chdir(previous_cwd)

        for drift in ("missing", "extra"):
            with self.subTest(drift=drift), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                skill_path, script_path = self.make_runtime_layout(base)
                scripts_root = skill_path.parent / "scripts"
                if drift == "missing":
                    (scripts_root / "evidence_contracts.py").unlink()
                else:
                    (scripts_root / "unreviewed_runtime.py").write_text(
                        "# unreviewed\n",
                        encoding="utf-8",
                    )
                with self.open_binding(skill_path, script_path) as binding:
                    with self.assertRaisesRegex(
                        ValueError,
                        "skill_root_authority_runtime_inventory_invalid",
                    ):
                        binding.read_runtime_bundle()

    def test_skill_resource_bundle_matches_goal_stage_contract_and_is_immutable(self) -> None:
        goal_tree = ast.parse((SCRIPTS_ROOT / "goal_run.py").read_text(encoding="utf-8"))
        stage_assignments = [
            node
            for node in goal_tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "STAGE_REFERENCES"
                for target in node.targets
            )
        ]
        self.assertEqual(len(stage_assignments), 1)
        stage_references = ast.literal_eval(stage_assignments[0].value)
        expected = frozenset(
            relative_path
            for paths in stage_references.values()
            for relative_path in paths
        )
        self.assertEqual(expected, AUTHORITY.GOAL_REFERENCE_PATHS)

        with AUTHORITY.open_skill_root_authority(
            loader_skill_md_path=os.fspath(SKILL_ROOT / "SKILL.md"),
            executing_script_path=os.fspath(AUTHORITY_PATH),
            expected_script_basename="skill_root_authority.py",
        ) as binding:
            bundle = binding.read_skill_resource_bundle()
            self.assertEqual(frozenset(bundle), AUTHORITY.GOAL_REFERENCE_PATHS)
            for relative_path, payload in bundle.items():
                self.assertEqual(payload, (SKILL_ROOT / relative_path).read_bytes())
            with self.assertRaises(TypeError):
                bundle["references/Autopsy-Planner.md"] = b"attacker"  # type: ignore[index]
            with self.assertRaises(TypeError):
                binding.read_skill_resource_bundle("references/Autopsy-Planner.md")  # type: ignore[call-arg]

    def test_skill_resource_bundle_rejects_symlink_hardlink_mode_acl_and_mount(self) -> None:
        cases = ("symlink", "hardlink", "mode", "acl", "mount")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir).resolve()
                skill_path, script_path = self.make_skill_resource_layout(base)
                target = skill_path.parent / "references/Autopsy-Planner.md"
                patcher = None
                if case == "symlink":
                    displaced = target.with_suffix(".real")
                    target.rename(displaced)
                    target.symlink_to(displaced.name)
                elif case == "hardlink":
                    os.link(target, target.with_name("Autopsy-Planner.alias"))
                elif case == "mode":
                    target.chmod(0o664)
                elif case == "acl":
                    identity = (target.stat().st_dev, target.stat().st_ino)
                    real_acl_probe = AUTHORITY._descriptor_has_acl

                    def target_acl(descriptor: int) -> bool:
                        metadata = os.fstat(descriptor)
                        if (metadata.st_dev, metadata.st_ino) == identity:
                            return True
                        return real_acl_probe(descriptor)

                    patcher = mock.patch.object(
                        AUTHORITY,
                        "_descriptor_has_acl",
                        side_effect=target_acl,
                    )

                context = patcher if patcher is not None else mock.patch.object(
                    AUTHORITY,
                    "_MAX_GOAL_REFERENCE_BYTES",
                    AUTHORITY._MAX_GOAL_REFERENCE_BYTES,
                )
                with self.open_binding(skill_path, script_path) as binding, context:
                    mount_patcher = None
                    if case == "mount":
                        real_same_mount = binding._mount_module.require_same_mount

                        def reject_reference_mount(root, descriptor, label, **kwargs):
                            if str(label).startswith("goal/reference_entry_"):
                                raise ValueError(
                                    f"repository_nested_mount_rejected={label}"
                                )
                            return real_same_mount(root, descriptor, label, **kwargs)

                        mount_patcher = mock.patch.object(
                            binding._mount_module,
                            "require_same_mount",
                            side_effect=reject_reference_mount,
                        )
                    mount_context = mount_patcher if mount_patcher is not None else mock.patch.object(
                        AUTHORITY,
                        "_MAX_GOAL_REFERENCE_BUNDLE_BYTES",
                        AUTHORITY._MAX_GOAL_REFERENCE_BUNDLE_BYTES,
                    )
                    with mount_context:
                        with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                            binding.read_skill_resource_bundle()

    def test_skill_resource_bundle_rejects_toctou_and_ignores_repository_provider(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_skill_resource_layout(base)
            target = skill_path.parent / "references/Autopsy-Planner.md"
            real_read = AUTHORITY._read_held_regular_bytes
            replaced = False

            def replace_after_read(entry, *, max_bytes):
                nonlocal replaced
                payload = real_read(entry, max_bytes=max_bytes)
                if entry.name == "Autopsy-Planner.md" and not replaced:
                    replaced = True
                    displaced = target.with_suffix(".displaced")
                    target.rename(displaced)
                    target.write_bytes(b"MALICIOUS_REFERENCE_MARKER\n")
                    target.chmod(0o644)
                return payload

            with self.open_binding(skill_path, script_path) as binding:
                with mock.patch.object(
                    AUTHORITY,
                    "_read_held_regular_bytes",
                    side_effect=replace_after_read,
                ):
                    with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                        binding.read_skill_resource_bundle()
            self.assertTrue(replaced)

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_skill_resource_layout(base)
            repository = base / "target-repository"
            malicious_reference = repository / "references/Autopsy-Planner.md"
            malicious_reference.parent.mkdir(parents=True)
            marker = b"MALICIOUS_REPOSITORY_REFERENCE\n"
            malicious_reference.write_bytes(marker)
            previous_cwd = Path.cwd()
            previous_path = list(sys.path)
            try:
                os.chdir(repository)
                sys.path.insert(0, os.fspath(repository))
                with mock.patch.dict(
                    os.environ,
                    {"CODEXQB_SKILL_ROOT": os.fspath(repository)},
                    clear=False,
                ):
                    with self.open_binding(skill_path, script_path) as binding:
                        bundle = binding.read_skill_resource_bundle()
                        self.assertNotIn(marker, bundle.values())
                        self.assertEqual(
                            bundle["references/Autopsy-Planner.md"],
                            (SKILL_ROOT / "references/Autopsy-Planner.md").read_bytes(),
                        )
            finally:
                sys.path[:] = previous_path
                os.chdir(previous_cwd)

    def test_atomic_skill_root_and_scripts_replacement_are_marker_free(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_skill_resource_layout(base)
            skill_root = skill_path.parent
            with self.open_binding(skill_path, script_path) as binding:
                original = binding.read_skill_resource_bundle()
                original_digest = {
                    path: hashlib.sha256(payload).hexdigest()
                    for path, payload in original.items()
                }
                displaced = skill_root.with_name("codexqb-held-original")
                skill_root.rename(displaced)
                skill_root.mkdir()
                (skill_root / "SKILL.md").write_text("malicious\n", encoding="utf-8")
                malicious = skill_root / "references/Autopsy-Planner.md"
                malicious.parent.mkdir()
                malicious.write_bytes(b"MALICIOUS_REFERENCE_MARKER\n")
                with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                    binding.read_skill_resource_bundle()
                self.assertNotIn(b"MALICIOUS_REFERENCE_MARKER\n", original.values())
                self.assertEqual(
                    original_digest,
                    {
                        path: hashlib.sha256(payload).hexdigest()
                        for path, payload in original.items()
                    },
                )

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_runtime_layout(base)
            scripts_root = skill_path.parent / "scripts"
            with self.open_binding(skill_path, script_path) as binding:
                original = binding.read_runtime_bundle()
                original_validator = original["validate_planner_docs.py"]
                displaced = scripts_root.with_name("scripts-held-original")
                scripts_root.rename(displaced)
                scripts_root.mkdir()
                (scripts_root / "validate_planner_docs.py").write_bytes(
                    b"MALICIOUS_VALIDATOR_MARKER\n"
                )
                with self.assertRaisesRegex(ValueError, "skill_root_authority_"):
                    binding.read_runtime_bundle()
                self.assertNotIn(b"MALICIOUS_VALIDATOR_MARKER", original_validator)
                self.assertEqual(
                    hashlib.sha256(original_validator).hexdigest(),
                    hashlib.sha256(
                        (SCRIPTS_ROOT / "validate_planner_docs.py").read_bytes()
                    ).hexdigest(),
                )

    def test_revalidation_rejects_entry_replacement_and_mount_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir).resolve()
            skill_path, script_path = self.make_layout(base)

            with self.open_binding(skill_path, script_path) as binding:
                displaced = script_path.with_name("goal_run.displaced.py")
                script_path.rename(displaced)
                script_path.write_text("# replacement\n", encoding="utf-8")
                script_path.chmod(0o644)
                with self.assertRaisesRegex(ValueError, "skill_root_authority_identity_changed"):
                    binding.revalidate()

            displaced.unlink()
            script_path.unlink()
            script_path.write_text("# restored fixture\n", encoding="utf-8")
            script_path.chmod(0o644)
            with mock.patch.object(
                AUTHORITY,
                "_require_same_skill_mount",
                side_effect=ValueError("skill_root_authority_mount_mismatch"),
            ):
                with self.assertRaisesRegex(ValueError, "skill_root_authority_mount_mismatch"):
                    with self.open_binding(skill_path, script_path):
                        self.fail("nested mount mismatch unexpectedly opened")


if __name__ == "__main__":
    unittest.main()
