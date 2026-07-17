from __future__ import annotations

import importlib.util
import ast
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
import py_compile
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SKILL_ROOT = REPO_ROOT / "plugins/codexqb/skills/codexqb"
POLICY_PATH = SKILL_ROOT / "scripts/repository_io_policy.py"
LAUNCHER_PREFIX = (
    'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" '
    '--active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller'
)


def launcher_command(controller: str) -> str:
    return f"{LAUNCHER_PREFIX} {controller} --"


def request_stdin_command(controller: str) -> str:
    return f"{launcher_command(controller)} request-stdin"


def controller_stdin_surface(
    controller: str,
    argv: list[str],
    *,
    body: str | None = None,
) -> str:
    payload: dict[str, object] = {
        "schema": "codexqb.controller-argv/v1",
        "argv": argv,
    }
    if body is not None:
        payload["body"] = body
    return (
        f"```bash\n{request_stdin_command(controller)}\n```\n\n"
        "```json\n"
        f"{json.dumps(payload, indent=2, ensure_ascii=False)}\n"
        "```"
    )


def load_policy_module():
    spec = importlib.util.spec_from_file_location("codexqb_repository_io_policy", POLICY_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load policy from {POLICY_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


POLICY = load_policy_module()


def install_unchecked_hash_pyc(source: Path, marker: Path) -> Path:
    """Install a forged PEP 552 cache while restoring the reviewed source."""

    original = source.read_bytes()
    malicious = (
        "from pathlib import Path\n"
        f"Path({marker.as_posix()!r}).write_text('executed')\n"
    ).encode("utf-8")
    source.write_bytes(malicious)
    previous_prefix = sys.pycache_prefix
    try:
        sys.pycache_prefix = None
        cache = Path(importlib.util.cache_from_source(str(source)))
    finally:
        sys.pycache_prefix = previous_prefix
    cache.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(
        str(source),
        cfile=str(cache),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
    )
    source.write_bytes(original)
    return cache


def copy_checker_source(base: Path) -> Path:
    source = base / "source"
    (source / "scripts").mkdir(parents=True)
    shutil.copy2(
        REPO_ROOT / "scripts/check_repository_io_policy.py",
        source / "scripts/check_repository_io_policy.py",
    )
    shutil.copytree(
        REPO_ROOT / "plugins/codexqb",
        source / "plugins/codexqb",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
    )
    return source


def write_authoritative_plugin_manifest(plugin_root: Path) -> Path:
    files = []
    for path in sorted(plugin_root.rglob("*")):
        if not path.is_file() or path.name == "PACKAGE-MANIFEST.json":
            continue
        relative = path.relative_to(plugin_root).as_posix()
        files.append(
            {
                "path": relative,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "mode": f"{path.stat().st_mode & 0o7777:04o}",
            }
        )
    files.sort(key=lambda item: item["path"])
    encoded = json.dumps(files, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    tree_digest = hashlib.sha256(encoded).hexdigest()
    plugin_metadata = json.loads(
        (plugin_root / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
    )
    version = plugin_metadata["version"]
    manifest = {
        "package_schema_version": 3,
        "artifact_type": "plugin",
        "layout_version": 1,
        "export_mode": "worktree",
        "release_claim": False,
        "git_provenance_available": False,
        "source_inventory": "filesystem",
        "plugin_version": version,
        "git_commit": "unknown",
        "git_branch": "unknown",
        "origin_main_commit": "unknown",
        "origin_main_ref_status": "unavailable",
        "head_matches_origin_main": None,
        "working_tree_clean": None,
        "tracked_only": False,
        "include_untracked": True,
        "changelog_mentions_plugin_version": True,
        "changelog_release_state": "unreleased",
        "release_tag": f"v{version}",
        "release_tag_commit": "unknown",
        "release_tag_matches_head": None,
        "generated_at": "1970-01-01T00:00:00Z",
        "file_count": len(files),
        "tree_sha256": tree_digest,
        "content_sha256": tree_digest,
        "files": files,
    }
    target = plugin_root / "PACKAGE-MANIFEST.json"
    target.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    target.chmod(0o644)
    return target


class RepositoryIOPolicyTests(unittest.TestCase):
    def python_symbols(self, source: str, relative: str = "scripts/goal_run.py") -> set[str]:
        if "from __future__ import annotations" not in source:
            source = "from __future__ import annotations\n" + source
        return {finding.symbol for finding in POLICY.scan_python(relative, source)}

    def markdown_symbols(self, text: str, relative: str = "references/probe.md") -> set[str]:
        return {finding.symbol for finding in POLICY.scan_markdown(relative, text)}

    @staticmethod
    def mutate_semantic_definition(
        source: str,
        identity: str,
        mutation: str,
    ) -> str:
        tree = ast.parse(source)
        owner, separator, name = identity.rpartition(".")
        container: ast.Module | ast.ClassDef = tree
        if separator:
            container = next(
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == owner
            )
        index, definition = next(
            (index, node)
            for index, node in enumerate(container.body)
            if isinstance(
                node,
                (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
            )
            and node.name == name
        )
        if mutation == "nested":
            container.body[index] = ast.If(
                test=ast.Constant(value=True),
                body=[definition],
                orelse=[],
            )
        elif mutation == "relocated_rebound":
            container.body[index] = ast.If(
                test=ast.Constant(value=False),
                body=[definition],
                orelse=[],
            )
            container.body.insert(
                index + 1,
                ast.For(
                    target=ast.Name(id=name, ctx=ast.Store()),
                    iter=ast.Tuple(
                        elts=[ast.Name(id="object", ctx=ast.Load())],
                        ctx=ast.Load(),
                    ),
                    body=[ast.Pass()],
                    orelse=[],
                ),
            )
        elif mutation == "duplicate":
            duplicate = ast.parse(ast.unparse(definition)).body[0]
            container.body.insert(index + 1, duplicate)
        elif mutation == "decorated":
            definition.decorator_list.append(
                ast.Name(id="staticmethod", ctx=ast.Load())
            )
        elif mutation == "wrong_kind":
            if isinstance(definition, ast.ClassDef):
                replacement = ast.parse(f"def {name}():\n    pass\n").body[0]
            else:
                replacement = ast.parse(f"class {name}:\n    pass\n").body[0]
            replacement.decorator_list = definition.decorator_list
            container.body[index] = replacement
        else:  # pragma: no cover - test helper contract
            raise AssertionError(f"unknown semantic mutation: {mutation}")
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"

    @staticmethod
    def append_semantic_class_body(
        source: str,
        class_name: str,
        statements: str,
    ) -> str:
        tree = ast.parse(source)
        class_node = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        class_node.body.extend(ast.parse(statements).body)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"

    @staticmethod
    def mutate_semantic_function_default(
        source: str,
        identity: str,
        rebound_name: str,
    ) -> str:
        tree = ast.parse(source)
        owner, separator, name = identity.rpartition(".")
        container: ast.Module | ast.ClassDef = tree
        if separator:
            container = next(
                node
                for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == owner
            )
        function = next(
            node
            for node in container.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name == name
        )
        function.args.args.append(ast.arg(arg="_semantic_probe"))
        function.args.defaults.append(
            ast.NamedExpr(
                target=ast.Name(id=rebound_name, ctx=ast.Store()),
                value=ast.Name(id="object", ctx=ast.Load()),
            )
        )
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"

    @staticmethod
    def mutate_semantic_class_header(
        source: str,
        class_name: str,
        rebound_name: str,
        kind: str,
    ) -> str:
        tree = ast.parse(source)
        class_node = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        )
        rebound = ast.NamedExpr(
            target=ast.Name(id=rebound_name, ctx=ast.Store()),
            value=ast.Name(
                id="type" if kind == "metaclass" else "object",
                ctx=ast.Load(),
            ),
        )
        if kind == "base":
            class_node.bases.append(rebound)
        elif kind == "metaclass":
            class_node.keywords.append(ast.keyword(arg="metaclass", value=rebound))
        else:  # pragma: no cover - test helper contract
            raise AssertionError(f"unknown class header mutation: {kind}")
        ast.fix_missing_locations(tree)
        return ast.unparse(tree) + "\n"

    def test_current_source_tree_passes(self) -> None:
        self.assertEqual(POLICY.scan_tree(REPO_ROOT), [])

    def test_ast_pin_serialization_omits_python_minor_empty_fields(self) -> None:
        tree = ast.parse("def checked():\n    pass\n")
        self.assertEqual(
            POLICY._canonical_ast_dump(tree),
            "Module(body=[FunctionDef(name='checked', "
            "args=arguments(), body=[Pass()])])",
        )

    def test_outer_reviewed_runtime_registry_covers_every_runtime_source(self) -> None:
        wrapper_tree = ast.parse(
            (REPO_ROOT / "scripts/check_repository_io_policy.py").read_text(
                encoding="utf-8"
            )
        )
        assignments: dict[str, object] = {}
        for node in wrapper_tree.body:
            if not isinstance(node, (ast.Assign, ast.AnnAssign)):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            target = next(
                (
                    item
                    for item in targets
                    if isinstance(item, ast.Name)
                    and item.id
                    in {"_REVIEWED_SOURCE_SHA256", "_EXECUTED_SOURCE_NAMES"}
                ),
                None,
            )
            if target is None:
                continue
            value = node.value
            if (
                isinstance(value, ast.Call)
                and isinstance(value.func, ast.Name)
                and value.func.id == "frozenset"
                and len(value.args) == 1
            ):
                value = value.args[0]
            assignments[target.id] = ast.literal_eval(value)
        expected = {Path(path).name for path in POLICY.REQUIRED_RUNTIME}
        self.assertEqual(set(assignments["_REVIEWED_SOURCE_SHA256"]), expected)
        self.assertEqual(
            set(assignments["_EXECUTED_SOURCE_NAMES"]),
            {
                "artifact_io.py",
                "controller_store.py",
                "git_evidence.py",
                "mount_identity.py",
                "repository_evidence.py",
                "repository_io.py",
                "repository_io_policy.py",
                "safety_contracts.py",
            },
        )
        self.assertTrue(
            all(
                re.fullmatch(r"[0-9a-f]{64}", digest)
                for digest in assignments["_REVIEWED_SOURCE_SHA256"].values()
            )
        )
        for basename, expected_digest in assignments[
            "_REVIEWED_SOURCE_SHA256"
        ].items():
            with self.subTest(basename=basename):
                self.assertEqual(
                    hashlib.sha256((SKILL_ROOT / "scripts" / basename).read_bytes()).hexdigest(),
                    expected_digest,
                )

    def test_outer_linux_mountinfo_parser_rejects_every_idmapped_field(self) -> None:
        wrapper_path = REPO_ROOT / "scripts/check_repository_io_policy.py"
        wrapper_tree = ast.parse(wrapper_path.read_text(encoding="utf-8"))
        helper_names = {
            "_mountinfo_field_is_idmapped",
            "_linux_filesystem_type_from_mountinfo",
        }
        helper_nodes = [
            node
            for node in wrapper_tree.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and node.name in helper_names
        ]
        self.assertEqual({node.name for node in helper_nodes}, helper_names)
        namespace: dict[str, object] = {}
        exec(
            compile(
                ast.Module(body=helper_nodes, type_ignores=[]),
                str(wrapper_path),
                "exec",
            ),
            namespace,
        )
        parser = namespace["_linux_filesystem_type_from_mountinfo"]
        fdinfo = b"pos:\t0\nflags:\t0100000\nmnt_id:\t42\n"
        safe = b"42 31 8:1 / /repo rw,nosuid - ext4 /dev/sda1 rw\n"
        self.assertEqual(parser(fdinfo, safe), "ext4")
        for payload in (
            b"42 31 8:1 / /repo rw,nosuid idmapped - ext4 /dev/sda1 rw\n",
            b"42 31 8:1 / /repo rw,idmapped=1000 - ext4 /dev/sda1 rw\n",
            b"42 31 8:1 / /repo rw - ext4 /dev/sda1 rw,idmapped\n",
        ):
            with self.subTest(payload=payload), self.assertRaisesRegex(
                RuntimeError,
                "repository_io_policy_filesystem_idmapped",
            ):
                parser(fdinfo, payload)

        wrapper_source = wrapper_path.read_text(encoding="utf-8")
        self.assertIn("payload.f_flags", wrapper_source)
        self.assertIn("_DARWIN_MNT_LOCAL", wrapper_source)

    def test_reviewed_model_surface_registry_is_exact_and_fail_closed(self) -> None:
        expected_paths = {
            "SKILL.md",
            "agents/openai.yaml",
            *{
                path.relative_to(SKILL_ROOT).as_posix()
                for path in (SKILL_ROOT / "references").rglob("*")
                if path.is_file()
            },
        }
        self.assertEqual(set(POLICY._APPROVED_MODEL_SURFACE_SHA256), expected_paths)
        for relative, expected_digest in POLICY._APPROVED_MODEL_SURFACE_SHA256.items():
            self.assertRegex(expected_digest, r"^[0-9a-f]{64}$")
            self.assertEqual(
                hashlib.sha256((SKILL_ROOT / relative).read_bytes()).hexdigest(),
                expected_digest,
            )

        for mutation in ("tamper", "add", "delete"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temp_dir:
                repo = Path(temp_dir) / "repo"
                skill = repo / "plugins/codexqb/skills/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    repo / "plugins/codexqb",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                if mutation == "tamper":
                    target = skill / "references/probe-policy.md"
                    target.write_text(
                        target.read_text(encoding="utf-8")
                        + "\n```{powershell}\nhelper README.md\n```\n",
                        encoding="utf-8",
                    )
                elif mutation == "add":
                    (skill / "references/extra.md").write_text(
                        "helper README.md\n", encoding="utf-8"
                    )
                else:
                    (skill / "references/probe-policy.md").unlink()
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_tree(
                        repo, layout=POLICY.LAYOUT_REPOSITORY_PLUGIN
                    )
                }
                expected_symbol = (
                    "model_surface_unreviewed"
                    if mutation == "tamper"
                    else "model_surface_registry_mismatch"
                )
                self.assertIn(expected_symbol, symbols)

    def test_reviewed_plugin_metadata_pin_matches_current_bytes(self) -> None:
        metadata = REPO_ROOT / "plugins/codexqb/.codex-plugin/plugin.json"
        self.assertEqual(
            hashlib.sha256(metadata.read_bytes()).hexdigest(),
            POLICY._APPROVED_PLUGIN_METADATA_SHA256,
        )

    def test_protected_consumer_modules_are_whole_ast_pinned(self) -> None:
        self.assertEqual(
            set(POLICY._APPROVED_PROTECTED_CONSUMER_AST_DIGESTS),
            set(POLICY.PROTECTED_PYTHON),
        )
        for relative, expected_digest in POLICY._APPROVED_PROTECTED_CONSUMER_AST_DIGESTS.items():
            self.assertRegex(expected_digest, r"^[0-9a-f]{64}$")
            tree = ast.parse((SKILL_ROOT / relative).read_text(encoding="utf-8"))
            actual = hashlib.sha256(
                POLICY._canonical_ast_dump(tree).encode("utf-8")
            ).hexdigest()
            self.assertEqual(actual, expected_digest)

        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            skill = repo / "plugins/codexqb/skills/codexqb"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                repo / "plugins/codexqb",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            validator = skill / "scripts/validate_planner_docs.py"
            validator.write_text(
                validator.read_text(encoding="utf-8")
                + "\ndef _expose(x):\n    return x.repository\n"
                + "ValidationState.expose = _expose\n"
                + "def leak(state: ValidationState, cb):\n    return cb(state.expose())\n",
                encoding="utf-8",
            )
            symbols = {
                finding.symbol
                for finding in POLICY.scan_tree(
                    repo, layout=POLICY.LAYOUT_REPOSITORY_PLUGIN
                )
            }
            self.assertIn("protected_consumer_unreviewed", symbols)

    def test_skill_loader_semantic_profiles_are_final_pinned(self) -> None:
        enrolled = {
            "scripts/skill_launcher.py",
            "scripts/skill_root_authority.py",
        }
        self.assertEqual(POLICY._SEMANTIC_PROFILE_PATHS, enrolled)
        for relative in sorted(enrolled):
            with self.subTest(relative=relative):
                source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual(POLICY.scan_python(relative, source), [])
                expected_digest = POLICY._APPROVED_PROTECTED_CONSUMER_AST_DIGESTS[
                    relative
                ]
                self.assertNotEqual(expected_digest, "0" * 64)
                self.assertNotIn(relative, POLICY._APPROVED_CAPABILITY_DIGESTS)
                self.assertEqual(
                    POLICY._scan_ast_pinned_runtime(
                        relative,
                        source,
                        expected_digest=expected_digest,
                        mismatch_symbol="protected_consumer_unreviewed",
                    ),
                    [],
                )

    def test_skill_loader_semantic_profile_registries_are_exact(self) -> None:
        enrolled = set(POLICY._SEMANTIC_PROFILE_PATHS)
        for registry in (
            POLICY._PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS,
            POLICY._PROTECTED_SEMANTIC_IMPORT_BINDINGS,
            POLICY._PROTECTED_SEMANTIC_CLASSES,
            POLICY._PROTECTED_SEMANTIC_FUNCTIONS,
            POLICY._PROTECTED_SEMANTIC_ATTRIBUTE_PROBES,
            POLICY._PROTECTED_SEMANTIC_API_CALLS,
            POLICY._PROTECTED_SEMANTIC_CRITICAL_COMPARE_SHAPES,
            POLICY._PROTECTED_SEMANTIC_CRITICAL_FUNCTION_SHAPES,
            POLICY._PROTECTED_SEMANTIC_CRITICAL_GUARD_SHAPES,
            POLICY._PROTECTED_SEMANTIC_DEFINITION_DECORATORS,
            POLICY._PROTECTED_SEMANTIC_SENSITIVE_CALL_SHAPES,
            POLICY._PROTECTED_SEMANTIC_FINDING_BUDGETS,
        ):
            self.assertEqual(set(registry), enrolled)
        self.assertEqual(
            POLICY._PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS,
            {relative: frozenset({"os"}) for relative in enrolled},
        )
        self.assertTrue(enrolled.issubset(POLICY.PROTECTED_PYTHON))
        self.assertEqual(POLICY._TRUSTED_CONTROLLER_REGISTRY, {})
        self.assertEqual(
            set(POLICY._APPLY_REQUEST_STDIN_ACCESS_SHAPES),
            {"_read_controller_stdin_argv", "main"},
        )
        self.assertEqual(
            set(POLICY._APPLY_REQUEST_STDIN_FINDING_BUDGETS),
            {"execute_planned_validation", "main"},
        )

    def test_skill_loader_profiles_reject_same_symbol_argument_substitutions(
        self,
    ) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        launcher = (SKILL_ROOT / launcher_relative).read_text(encoding="utf-8")
        authority = (SKILL_ROOT / authority_relative).read_text(encoding="utf-8")
        cases = (
            (
                launcher_relative,
                launcher,
                'os.open("/", _bootstrap_directory_flags())',
                'os.open("/tmp", _bootstrap_directory_flags())',
            ),
            (
                launcher_relative,
                launcher,
                "os.pread(authority_fd, 1, metadata.st_size)",
                "os.pread(authority_fd, 2, metadata.st_size)",
            ),
            (
                launcher_relative,
                launcher,
                "os.stat(name, dir_fd=parent_fd, follow_symlinks=False)",
                "os.stat(name, dir_fd=parent_fd, follow_symlinks=True)",
            ),
            (
                launcher_relative,
                launcher,
                "os.close(descriptor)",
                "os.close(parent_fd)",
            ),
            (
                launcher_relative,
                launcher,
                "target_basename,\n            )",
                '"apply_run.py",\n            )',
            ),
            (
                authority_relative,
                authority,
                "os.listdir(binding.scripts_fd)",
                'os.listdir("/")',
            ),
            (
                authority_relative,
                authority,
                "os.listxattr(descriptor)",
                'os.listxattr("/")',
            ),
            (
                authority_relative,
                authority,
                "os.fstat(entry.fd)",
                "os.fstat(entry.parent_fd)",
            ),
            (
                authority_relative,
                authority,
                "ctypes.CDLL(None, use_errno=True)",
                'ctypes.CDLL("evil.so", use_errno=True)',
            ),
        )
        for relative, source, before, after in cases:
            with self.subTest(relative=relative, mutation=after):
                self.assertIn(before, source)
                mutated = source.replace(before, after, 1)
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_python(relative, mutated)
                }
                self.assertTrue(
                    {
                        "semantic_api_inventory_mismatch",
                        "semantic_call_shape_inventory_mismatch",
                        "semantic_ctypes_library_invalid",
                    }
                    & symbols,
                    symbols,
                )

    def test_skill_loader_profiles_reject_new_capability_surfaces(self) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        launcher = (SKILL_ROOT / launcher_relative).read_text(encoding="utf-8")
        authority = (SKILL_ROOT / authority_relative).read_text(encoding="utf-8")
        mutations = (
            (launcher_relative, launcher + '\nos.system("id")\n'),
            (launcher_relative, launcher + '\nos.popen("id")\n'),
            (launcher_relative, launcher + '\nos.execv("/bin/sh", ["sh"])\n'),
            (launcher_relative, launcher + '\nos.spawnv(0, "/bin/sh", ["sh"])\n'),
            (
                launcher_relative,
                launcher + '\nattribute = "system"\ngetattr(os, attribute)\n',
            ),
            (launcher_relative, launcher + '\nimportlib.import_module("os")\n'),
            (
                launcher_relative,
                launcher.replace(
                    "importlib.util.spec_from_loader(",
                    "importlib.util.spec_from_file_location(",
                    1,
                ),
            ),
            (launcher_relative, launcher + '\nopen("/tmp/codexqb-probe")\n'),
            (launcher_relative, launcher + '\nos.environ["CODEXQB_PROBE"]\n'),
            (launcher_relative, launcher + "\nimport socket\nsocket.socket()\n"),
            (
                launcher_relative,
                launcher + '\nimport subprocess\nsubprocess.run(["true"])\n',
            ),
            (
                authority_relative,
                authority + '\nPath("/tmp/codexqb-probe").read_text()\n',
            ),
            (
                authority_relative,
                authority + '\nctypes.CDLL("evil.so", use_errno=True)\n',
            ),
            (authority_relative, authority + "\nlibc.system\n"),
            (
                authority_relative,
                authority.replace(
                    'getattr(libc, "acl_free", None)',
                    "getattr(libc, symbol_name, None)",
                    1,
                ),
            ),
        )
        for relative, mutated in mutations:
            with self.subTest(relative=relative, tail=mutated[-80:]):
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_python(relative, mutated)
                }
                self.assertTrue(symbols)
                self.assertTrue(
                    any(
                        symbol.startswith(
                            (
                                "builtin_open",
                                "dangerous_",
                                "dynamic_",
                                "path_convenience:",
                                "process_creation:",
                                "raw_io:",
                                "semantic_",
                                "unapproved_",
                                "forbidden_",
                            )
                        )
                        for symbol in symbols
                    ),
                    symbols,
                )

    def test_skill_root_authority_rejects_every_ctypes_symbol_access_form(
        self,
    ) -> None:
        relative = "scripts/skill_root_authority.py"
        source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        for symbol in ("system", "open", "socket"):
            for expression in (
                f"libc[{symbol!r}]()",
                f"libc.{symbol}()",
                f"getattr(libc, {symbol!r})()",
            ):
                with self.subTest(symbol=symbol, expression=expression):
                    mutated = source.replace(
                        "libc = ctypes.CDLL(None, use_errno=True)",
                        "libc = ctypes.CDLL(None, use_errno=True)\n"
                        f"    {expression}",
                        1,
                    )
                    symbols = {
                        finding.symbol
                        for finding in POLICY.scan_python(relative, mutated)
                    }
                    self.assertTrue(
                        {
                            "dynamic_attribute:open",
                            "dynamic_attribute:socket",
                            "dynamic_attribute:system",
                            "semantic_attribute_probe_inventory_mismatch",
                            "semantic_ctypes_symbol_invalid",
                        }
                        & symbols,
                        symbols,
                    )
        for expression in (
            'alias = libc\n    alias["system"]()',
            'ctypes.CDLL(None, use_errno=True)["system"]()',
            '(libc := ctypes.CDLL(None, use_errno=True))["system"]()',
        ):
            with self.subTest(expression=expression):
                mutated = source.replace(
                    "libc = ctypes.CDLL(None, use_errno=True)",
                    "libc = ctypes.CDLL(None, use_errno=True)\n"
                    f"    {expression}",
                    1,
                )
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_python(relative, mutated)
                }
                self.assertTrue(
                    {
                        "semantic_ctypes_library_transport_invalid",
                        "semantic_ctypes_symbol_invalid",
                    }
                    & symbols,
                    symbols,
                )

    def test_skill_loader_profiles_reject_binding_and_control_substitutions(
        self,
    ) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        launcher = (SKILL_ROOT / launcher_relative).read_text(encoding="utf-8")
        authority = (SKILL_ROOT / authority_relative).read_text(encoding="utf-8")
        cases = (
            (
                launcher_relative,
                launcher.replace(
                    "hashlib.sha256(result).hexdigest() != _AUTHORITY_SOURCE_SHA256",
                    "hashlib.sha256(result).hexdigest() == _AUTHORITY_SOURCE_SHA256",
                    1,
                ),
                "semantic_critical_compare_mismatch",
            ),
            (
                launcher_relative,
                launcher.replace(
                    "if hashlib.sha256(result).hexdigest() "
                    "!= _AUTHORITY_SOURCE_SHA256:\n"
                    "            raise _LauncherBlocked",
                    "if not (hashlib.sha256(result).hexdigest() "
                    "!= _AUTHORITY_SOURCE_SHA256):\n"
                    "            raise _LauncherBlocked",
                    1,
                ),
                "semantic_critical_guard_mismatch",
            ),
            (
                launcher_relative,
                launcher.replace(
                    "if hashlib.sha256(result).hexdigest() "
                    "!= _AUTHORITY_SOURCE_SHA256:\n"
                    "            raise _LauncherBlocked",
                    "if hashlib.sha256(result).hexdigest() "
                    "!= _AUTHORITY_SOURCE_SHA256:\n"
                    "            pass",
                    1,
                ),
                "semantic_critical_guard_mismatch",
            ),
            (
                launcher_relative,
                launcher.replace(
                    "return isinstance(process_argv0, str) and process_argv0 == value",
                    "return isinstance(process_argv0, str) and value == value",
                    1,
                ),
                "semantic_critical_function_mismatch",
            ),
            (
                launcher_relative,
                launcher.replace(
                    "return payload\n        except (TypeError, ValueError):",
                    'payload = b"malicious"\n'
                    "            return payload\n"
                    "        except (TypeError, ValueError):",
                    1,
                ),
                "semantic_critical_function_mismatch",
            ),
            (
                launcher_relative,
                launcher + "\n_required_first_process_flags = lambda: True\n",
                "semantic_protected_binding_rebound",
            ),
            (
                launcher_relative,
                launcher + "\n_LauncherBlocked = Exception\n",
                "semantic_protected_binding_rebound",
            ),
            (
                launcher_relative,
                launcher.replace(
                    'expected_sources = object.__getattribute__(self, "_expected_sources")',
                    'expected_sources = object.__getattribute__(self, "_sources")',
                    1,
                ),
                "semantic_critical_function_mismatch",
            ),
            (
                authority_relative,
                authority + "\n_directory_flags = lambda: 0\n",
                "semantic_protected_binding_rebound",
            ),
            (
                authority_relative,
                authority + "\nSkillRootAuthority = object\n",
                "semantic_protected_binding_rebound",
            ),
            (
                authority_relative,
                authority
                + "\nSkillRootAuthority.read_script_bytes = lambda *args: b''\n",
                "semantic_protected_binding_rebound",
            ),
            (
                authority_relative,
                authority.replace(
                    "hashlib.sha256(payload).hexdigest() "
                    "!= MOUNT_IDENTITY_SOURCE_SHA256",
                    "hashlib.sha256(payload).hexdigest() "
                    "== MOUNT_IDENTITY_SOURCE_SHA256",
                    1,
                ),
                "semantic_critical_compare_mismatch",
            ),
        )
        for relative, mutated, expected in cases:
            with self.subTest(relative=relative, expected=expected):
                self.assertIn(
                    expected,
                    {
                        finding.symbol
                        for finding in POLICY.scan_python(relative, mutated)
                    },
                )

    def test_skill_loader_profiles_require_canonical_definition_placement(
        self,
    ) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        launcher = (SKILL_ROOT / launcher_relative).read_text(encoding="utf-8")
        authority = (SKILL_ROOT / authority_relative).read_text(encoding="utf-8")
        cases = (
            (launcher_relative, launcher, "_required_first_process_flags"),
            (authority_relative, authority, "_directory_flags"),
            (authority_relative, authority, "SkillRootAuthority"),
            (
                launcher_relative,
                launcher,
                "_HeldRuntimeFinder._validated_payload",
            ),
        )
        for relative, source, identity in cases:
            for mutation in (
                "nested",
                "relocated_rebound",
                "duplicate",
                "decorated",
                "wrong_kind",
            ):
                with self.subTest(
                    relative=relative,
                    identity=identity,
                    mutation=mutation,
                ):
                    mutated = self.mutate_semantic_definition(
                        source,
                        identity,
                        mutation,
                    )
                    self.assertIn(
                        "semantic_protected_definition_misplaced",
                        {
                            finding.symbol
                            for finding in POLICY.scan_python(relative, mutated)
                        },
                    )
                    if mutation == "relocated_rebound":
                        self.assertIn(
                            "semantic_protected_binding_rebound",
                            {
                                finding.symbol
                                for finding in POLICY.scan_python(
                                    relative,
                                    mutated,
                                )
                            },
                        )

    def test_skill_loader_profiles_reject_all_module_binding_forms(self) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        sources = {
            launcher_relative: (SKILL_ROOT / launcher_relative).read_text(
                encoding="utf-8"
            ),
            authority_relative: (SKILL_ROOT / authority_relative).read_text(
                encoding="utf-8"
            ),
        }
        targets = (
            (launcher_relative, "_required_first_process_flags"),
            (authority_relative, "_directory_flags"),
            (authority_relative, "SkillRootAuthority"),
        )
        for relative, target in targets:
            forms = {
                "for": f"""
for ({target}, *_semantic_rest) in ((object(),),):
    pass
""",
                "async_for": f"""
async def _semantic_async_for_probe():
    global {target}
    async for ({target}, *_semantic_rest) in _semantic_async_source:
        pass
""",
                "with": f"""
with _semantic_context as ({target}, *_semantic_rest):
    pass
""",
                "async_with": f"""
async def _semantic_async_with_probe():
    global {target}
    async with _semantic_context as ({target}, *_semantic_rest):
        pass
""",
                "except": f"""
try:
    raise RuntimeError
except RuntimeError as {target}:
    pass
""",
                "match_as": f"""
match object():
    case {target}:
        pass
""",
                "match_star": f"""
match []:
    case [*{target}]:
        pass
""",
                "match_mapping": f"""
match {{}}:
    case {{**{target}}}:
        pass
""",
            }
            for label, addition in forms.items():
                with self.subTest(relative=relative, target=target, form=label):
                    self.assertIn(
                        "semantic_protected_binding_rebound",
                        {
                            finding.symbol
                            for finding in POLICY.scan_python(
                                relative,
                                sources[relative] + addition,
                            )
                        },
                    )

            local_bindings = f"""
def _semantic_local_binding_probe():
    for ({target}, *_semantic_rest) in ((object(),),):
        pass
    with _semantic_context as ({target}, *_semantic_rest):
        pass
    try:
        raise RuntimeError
    except RuntimeError as {target}:
        pass
    match object():
        case {target}:
            pass

async def _semantic_local_async_binding_probe():
    async for ({target}, *_semantic_rest) in _semantic_async_source:
        pass
    async with _semantic_context as ({target}, *_semantic_rest):
        pass
"""
            with self.subTest(relative=relative, target=target, form="local"):
                self.assertNotIn(
                    "semantic_protected_binding_rebound",
                    {
                        finding.symbol
                        for finding in POLICY.scan_python(
                            relative,
                            sources[relative] + local_bindings,
                        )
                    },
                )

    def test_skill_loader_profiles_reject_class_method_binding_forms(self) -> None:
        relative = "scripts/skill_launcher.py"
        source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        forms = {
            "for": """
for (_validated_payload, *_semantic_rest) in ((object(),),):
    pass
""",
            "with": """
with _semantic_context as (_validated_payload, *_semantic_rest):
    pass
""",
            "except": """
try:
    raise RuntimeError
except RuntimeError as _validated_payload:
    pass
""",
            "match_as": """
match object():
    case _validated_payload:
        pass
""",
            "match_star": """
match []:
    case [*_validated_payload]:
        pass
""",
            "match_mapping": """
match {}:
    case {**_validated_payload}:
        pass
""",
        }
        for label, statements in forms.items():
            with self.subTest(form=label):
                mutated = self.append_semantic_class_body(
                    source,
                    "_HeldRuntimeFinder",
                    statements,
                )
                self.assertIn(
                    "semantic_protected_binding_rebound",
                    {
                        finding.symbol
                        for finding in POLICY.scan_python(relative, mutated)
                    },
                )

        local_method = """
async def _semantic_local_method_probe(self):
    async for _validated_payload in _semantic_async_source:
        pass
    async with _semantic_context as _validated_payload:
        pass
"""
        local_mutation = self.append_semantic_class_body(
            source,
            "_HeldRuntimeFinder",
            local_method,
        )
        self.assertNotIn(
            "semantic_protected_binding_rebound",
            {
                finding.symbol
                for finding in POLICY.scan_python(relative, local_mutation)
            },
        )

    def test_skill_loader_definition_evaluation_scopes_are_exact(self) -> None:
        launcher_relative = "scripts/skill_launcher.py"
        authority_relative = "scripts/skill_root_authority.py"
        launcher = (SKILL_ROOT / launcher_relative).read_text(encoding="utf-8")
        authority = (SKILL_ROOT / authority_relative).read_text(encoding="utf-8")
        mutations = (
            (
                authority_relative,
                self.mutate_semantic_function_default(
                    authority,
                    "_expected_basename",
                    "SkillRootAuthority",
                ),
                "module_function_default",
            ),
            (
                launcher_relative,
                self.mutate_semantic_function_default(
                    launcher,
                    "_HeldRuntimeFinder.create_module",
                    "_validated_payload",
                ),
                "class_method_default",
            ),
            (
                launcher_relative,
                self.mutate_semantic_class_header(
                    launcher,
                    "_HeldImportPath",
                    "_required_first_process_flags",
                    "base",
                ),
                "class_base",
            ),
            (
                launcher_relative,
                self.mutate_semantic_class_header(
                    launcher,
                    "_HeldImportPath",
                    "_required_first_process_flags",
                    "metaclass",
                ),
                "class_metaclass",
            ),
            (
                launcher_relative,
                launcher
                + "\n_semantic_lambda = lambda "
                "probe=(_required_first_process_flags := object): None\n",
                "lambda_default",
            ),
        )
        for relative, mutated, label in mutations:
            with self.subTest(relative=relative, mutation=label):
                self.assertIn(
                    "semantic_protected_binding_rebound",
                    {
                        finding.symbol
                        for finding in POLICY.scan_python(relative, mutated)
                    },
                )

        local_lambda = (
            launcher
            + "\n_semantic_lambda = lambda: "
            "(_required_first_process_flags := object)\n"
        )
        self.assertNotIn(
            "semantic_protected_binding_rebound",
            {
                finding.symbol
                for finding in POLICY.scan_python(
                    launcher_relative,
                    local_lambda,
                )
            },
        )

    def test_apply_request_stdin_access_is_exact_and_non_extensible(self) -> None:
        relative = "scripts/apply_run.py"
        source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        self.assertEqual(POLICY.scan_python(relative, source), [])
        mutations = (
            source.replace("sys.argv[1:]", "sys.argv[0:]", 1),
            source.replace(
                "MAX_CONTROLLER_STDIN_REQUEST_BYTES + 1",
                "-1",
                1,
            ),
            source + "\nsys.stdin.read()\n",
            source + "\nsys.argv.clear()\n",
        )
        for mutated in mutations:
            with self.subTest(tail=mutated[-80:]):
                self.assertIn(
                    "apply_request_stdin_access_inventory_mismatch",
                    {
                        finding.symbol
                        for finding in POLICY.scan_python(relative, mutated)
                    },
                )

        goal_symbols = self.python_symbols(
            "import sys\nsys.stdin.read()\nsys.argv.clear()\n",
            relative="scripts/goal_run.py",
        )
        self.assertIn("unapproved_module_attribute:sys.stdin", goal_symbols)
        self.assertIn("unapproved_module_attribute:sys.argv", goal_symbols)

    def test_skill_loader_exceptions_do_not_extend_goal_or_apply(self) -> None:
        goal_symbols = self.python_symbols(
            "import os\n"
            "import importlib\n"
            "os.system('id')\n"
            "importlib.import_module('os')\n",
            relative="scripts/goal_run.py",
        )
        self.assertIn("forbidden_module_import:os", goal_symbols)
        self.assertIn("unapproved_direct_import_module:importlib", goal_symbols)
        apply_symbols = self.python_symbols(
            "import ctypes\n"
            "def injected():\n"
            "    return ctypes.string_at(0, 1)\n",
            relative="scripts/apply_run.py",
        )
        self.assertIn(
            "unapproved_module_attribute:ctypes.string_at",
            apply_symbols,
        )

    def test_pep263_parser_differential_cannot_preserve_approved_ast(self) -> None:
        protected = {
            **POLICY._APPROVED_PROTECTED_CONSUMER_AST_DIGESTS,
            "scripts/execution_controller.py": POLICY._APPROVED_EXECUTION_CONTROLLER_AST_DIGEST,
        }
        for relative, expected_digest in protected.items():
            with self.subTest(relative=relative):
                source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
                lines = source.splitlines(keepends=True)
                lines.insert(1, "# coding: raw_unicode_escape\n")
                lines.append(
                    "# harmless "
                    + "\\u000a"
                    + "raise RuntimeError('PEP263_INJECTED')\n"
                )
                mutated = "".join(lines)
                decoded_tree = ast.parse(mutated, filename=relative)
                runtime_tree = compile(
                    mutated.encode("utf-8"),
                    relative,
                    "exec",
                    flags=ast.PyCF_ONLY_AST,
                    dont_inherit=True,
                )
                self.assertNotEqual(
                    ast.dump(decoded_tree, include_attributes=False),
                    ast.dump(runtime_tree, include_attributes=False),
                )
                if relative == "scripts/execution_controller.py":
                    findings = POLICY.scan_execution_controller(relative, mutated)
                    expected_symbol = "execution_controller_unreviewed"
                else:
                    findings = POLICY._scan_ast_pinned_runtime(
                        relative,
                        mutated,
                        expected_digest=expected_digest,
                        mismatch_symbol="protected_consumer_unreviewed",
                    )
                    expected_symbol = "protected_consumer_unreviewed"
                self.assertIn(expected_symbol, {item.symbol for item in findings})

    def test_python_bypass_corpus_is_fail_closed(self) -> None:
        cases = {
            "path_reads_and_mutations": (
                """
from pathlib import Path
def bypass(root: Path):
    root.open()
    root.read_text()
    root.read_bytes()
    root.write_text("x")
    root.write_bytes(b"x")
    root.stat(); root.lstat(); root.resolve(); root.exists(); root.is_file()
    root.glob("*"); root.rglob("*"); root.iterdir()
    root.unlink(); root.rename(root); root.replace(root); root.touch(); root.mkdir()
    root.expanduser(); root.owner(); root.group(); root.is_junction(); root.info
    root.copy(root); root.move(root)
    Path.home(); Path.cwd()
""",
                {
                    "path_convenience:open",
                    "path_convenience:read_text",
                    "path_convenience:stat",
                    "path_mutation:write_text",
                    "path_mutation:unlink",
                    "path_mutation:replace",
                    "path_mutation:mkdir",
                    "path_convenience:expanduser",
                    "raw_io:pathlib.Path.home",
                    "path_mutation:copy",
                    "path_mutation:move",
                },
            ),
            "path_internal_parser_module_is_rejected": (
                """
from pathlib import Path
def bypass(path):
    return Path.parser.exists(path), Path.parser.realpath(path)
""",
                {"path_internal_module_access:parser"},
            ),
            "receiver_alias_and_rebinding": (
                """
from pathlib import Path
from repository_io import RepositoryIO
def bypass(root: Path, repository: RepositoryIO):
    alias = root
    alias.read_text()
    repository = Path("Planner-docs/Main-Planing.md")
    repository.write_text("x")
""",
                {"path_convenience:read_text", "path_mutation:write_text"},
            ),
            "receiver_spelling_does_not_forge_facade": (
                """
class RepositoryIO:
    pass
def open_repository_io(root):
    return root
def bypass(repository: RepositoryIO):
    repository.read_text("README.md")
    with open_repository_io(".") as opened:
        opened.read_bytes("README.md")
""",
                {"path_convenience:read_text", "path_convenience:read_bytes"},
            ),
            "trusted_type_import_can_be_shadowed_only_fail_closed": (
                """
from repository_io import RepositoryIO
from fake_module import RepositoryIO
def bypass(repository: RepositoryIO):
    return repository.read_text("README.md")
""",
                {"path_convenience:read_text"},
            ),
            "lambda_and_comprehension_shadow_facade_names": (
                """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, values):
    callback = lambda repository: repository.read_text("README.md")
    leaked = [repository.read_bytes("README.md") for repository in values]
    return callback, leaked
""",
                {"path_convenience:read_text", "path_convenience:read_bytes"},
            ),
            "facade_method_rebinding_is_rejected": (
                """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, replacement):
    repository.read_text = replacement
""",
                {"repository_io_rebinding:read_text"},
            ),
            "facade_container_alias_and_post_with_scope_are_tainted": (
                """
from repository_io import RepositoryIO, open_repository_io
def bypass(root, repository: RepositoryIO):
    alias, = (repository,)
    alias._controller_engine()
    with open_repository_io(root) as opened:
        pass
    return opened._controller_engine()
""",
                {"repository_io_private_access:_controller_engine"},
            ),
            "facade_branch_join_is_order_independent": (
                """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, raw, flag):
    if flag:
        alias = raw
    else:
        alias = repository
    return alias.read_text("README.md")
""",
                {"repository_io_ambiguous_receiver:read_text"},
            ),
            "facade_transport_through_return_and_stores_is_rejected": (
                """
from repository_io import RepositoryIO
def identity(repository: RepositoryIO):
    return repository
def bypass(repository: RepositoryIO, box):
    box.value = repository
    box["repository"] = repository
    alias = identity()
    return box.value._engine, box["repository"]._engine, alias._engine
""",
                {
                    "repository_facade_transport:repository",
                    "private_attribute_access:_engine",
                },
            ),
            "facade_public_receiver_cannot_hide_callback_transport": (
                """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, callback):
    return (callback(repository), repository)[1].read_text("README.md")
""",
                {"repository_facade_transport:repository"},
            ),
            "facade_bound_methods_cannot_be_transported": (
                """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, callback):
    callback(repository.read_text)
    return repository.search, [repository.list_paths]
""",
                {
                    "repository_method_transport:read_text",
                    "repository_method_transport:search",
                    "repository_method_transport:list_paths",
                },
            ),
            "facade_opener_transport_and_manual_enter_are_tainted": (
                """
from repository_io import open_repository_io
def bypass(root):
    factory = [open_repository_io][0]
    context = open_repository_io(root)
    repository = context.__enter__()
    inline = open_repository_io(root).__enter__()._controller_engine
    aggregate = [repository][0]._controller_engine
    return factory, repository._controller_engine, inline, aggregate
""",
                {
                    "repository_opener_transport",
                    "repository_io_private_access:_controller_engine",
                },
            ),
            "opener_context_and_enter_results_cannot_escape": (
                """
from repository_io import open_repository_io
def bypass(root, callback, box):
    callback(open_repository_io(root))
    box.context = open_repository_io(root)
    first = open_repository_io(root)
    repository = first.__enter__()
    callback(first)
    second = open_repository_io(root)
    callback(second.__enter__())
    return open_repository_io(root), [repository]
""",
                {
                    "repository_opener_transport",
                    "repository_context_transport:open_repository_io",
                    "repository_context_transport:first",
                    "repository_facade_result_transport",
                    "repository_facade_transport:repository",
                },
            ),
            "context_branch_join_is_order_independent": (
                """
from repository_io import open_repository_io
def bypass(root, raw, flag):
    if flag:
        context = raw
    else:
        context = open_repository_io(root)
    repository = context.__enter__()
    return repository.read_text("README.md")
""",
                {
                    "repository_io_ambiguous_context:__enter__",
                    "repository_io_ambiguous_receiver:read_text",
                },
            ),
            "match_and_with_unpacking_cannot_forge_facades": (
                """
from repository_io import RepositoryIO, open_repository_io
def bypass(root, raw, repository: RepositoryIO):
    match raw:
        case [repository]:
            pass
    repository.read_text("README.md")
    with open_repository_io(root) as (repository, ignored):
        repository.read_bytes("README.md")
""",
                {
                    "repository_context_unpacking",
                    "repository_io_ambiguous_receiver:read_text",
                    "path_convenience:read_bytes",
                },
            ),
            "local_path_return_helpers_remain_path_tainted": (
                """
from pathlib import Path
def make(path):
    return Path(path)
def wrapper(path):
    return make(path)
def bypass(path):
    reader = wrapper(path).group
    derived = Path(path).with_suffix(".txt")
    bound = derived.exists
    parent_group = Path(path).parents[0].group()
    tuple_exists = (Path(path),)[0].exists
    conditional_group = (Path(path) if path else Path(".")).group()
    named_group = (named := Path(path)).group()
    return (
        wrapper(path).group(), derived.group(), reader, bound,
        parent_group, tuple_exists, conditional_group, named_group,
    )
""",
                {"path_convenience:group", "path_convenience:exists"},
            ),
            "repository_facade_cannot_be_constructed_directly": (
                """
from repository_io import RepositoryIO
def bypass(*args):
    repository = RepositoryIO(*args)
    return repository._controller_engine
""",
                {"repository_facade_runtime_reference"},
            ),
            "imported_opener_redefinition_drops_capability": (
                """
from contextlib import nullcontext
from repository_io import open_repository_io
def open_repository_io(root):
    return nullcontext(root)
def bypass(root):
    with open_repository_io(root) as opened:
        return opened.read_text()
""",
                {"import_binding_shadowed:open_repository_io"},
            ),
            "os_glob_and_shutil_aliases": (
                """
import os as operating
import glob as matching
import shutil as copying
from os import open as descriptor_open
from shutil import move as relocate
def bypass(root, fd):
    operating.open(root, operating.O_RDONLY)
    operating.read(fd, 10)
    operating.write(fd, b"x")
    operating.unlink(root); operating.rename(root, root); operating.mkdir(root)
    matching.glob("**/*", recursive=True)
    copying.rmtree(root)
    descriptor_open(root, 0)
    relocate(root, root)
""",
                {
                    "raw_io:os.open",
                    "raw_io:os.read",
                    "raw_io:os.write",
                    "raw_io:os.unlink",
                    "raw_io:os.rename",
                    "raw_io:os.mkdir",
                    "raw_io:glob.glob",
                    "raw_io:shutil.rmtree",
                    "dangerous_import:os.open",
                    "dangerous_import:shutil.move",
                },
            ),
            "callable_aliases_and_nonliteral_processes": (
                """
import asyncio as aio
import os as operating
import subprocess as child
from subprocess import Popen as launch
def bypass(command, environment):
    runner = child.run
    runner(command, env=environment)
    launch(command, env=environment)
    operating.system(command)
    aio.create_subprocess_exec(*command, env=environment)
""",
                {
                    "process_creation:subprocess.run",
                    "process_creation:subprocess.Popen",
                    "process_creation:os.system",
                    "process_creation:asyncio.create_subprocess_exec",
                    "dangerous_import:subprocess.Popen",
                },
            ),
            "alternate_io_and_process_constructors": (
                """
import asyncio
import gzip
import sqlite3
import tempfile
import zipfile
def bypass(loop, path):
    gzip.open(path)
    sqlite3.connect(path)
    tempfile.NamedTemporaryFile(dir=path)
    zipfile.ZipFile(path)
    loop.subprocess_exec(lambda: None, "cat", path)
""",
                {
                    "raw_io:gzip.open",
                    "raw_io:sqlite3.connect",
                    "raw_io:tempfile.NamedTemporaryFile",
                    "raw_io:zipfile.ZipFile",
                    "process_creation:receiver.subprocess_exec",
                },
            ),
            "dynamic_import_getattr_and_dict": (
                """
import importlib as loader
import os
from pathlib import Path
def bypass(root: Path, method):
    loader.import_module("os")
    __import__("pathlib")
    getattr(root, "read_text")()
    getattr(os, method)(root)
    os.__dict__["open"](root, 0)
    eval("open('README.md')")
""",
                {
                    "dynamic_import:importlib.import_module",
                    "dynamic_import:__import__",
                    "dynamic_attribute:read_text",
                    "dynamic_attribute:nonliteral",
                    "dynamic_namespace_access",
                    "dynamic_code:eval",
                },
            ),
            "aliased_dynamic_and_wildcard_imports": (
                """
from builtins import getattr as dynamic_getattr
from os import *
from pathlib import Path
def bypass(root: Path, name):
    return dynamic_getattr(root, name)
""",
                {"dynamic_attribute:nonliteral", "wildcard_import:os"},
            ),
            "qualified_and_relative_boundary_imports": (
                """
import plugins.codexqb.skills.codexqb.scripts.repository_io as qualified_io
from .repository_io import _controller_engine
def bypass(repository):
    return qualified_io._controller_engine(repository), _controller_engine(repository)
""",
                {
                    "noncanonical_boundary_import:repository_io",
                    "repository_io_private_import:_controller_engine",
                    "restricted_module_import:repository_io",
                },
            ),
            "sys_modules_cannot_recover_boundary_modules": (
                """
import sys
from sys import modules as imported_modules
def bypass():
    return sys.modules["repository_io"], imported_modules["controller_store"]
""",
                {"dynamic_namespace_access"},
            ),
            "builtin_and_type_namespace_recovery": (
                """
def bypass():
    direct = __builtins__["open"]
    recovered = ().__class__.__mro__[-1].__subclasses__()
    return direct, recovered
""",
                {"dynamic_namespace_access"},
            ),
            "repository_evidence_and_private_engine": (
                """
import repository_evidence as evidence
from repository_io import RepositoryIO, _controller_engine
def bypass(root, repository: RepositoryIO):
    evidence.capture_repository_evidence(root, [], [])
    repository.read_bytes("README.md")
    repository.root
    return _controller_engine(repository)
""",
                {
                    "raw_io:repository_evidence.capture_repository_evidence",
                    "repository_io_private_import:_controller_engine",
                    "repository_io_private_access:read_bytes",
                    "repository_io_private_access:root",
                },
            ),
            "unknown_controller_capability": (
                """
from repository_controller import controller_read_bytes, raw_engine
def bypass(repository):
    return raw_engine(repository)
""",
                {"forbidden_module_import:repository_controller"},
            ),
            "powerful_controller_capability_requires_pinned_body": (
                """
from repository_io import _controller_validation_cwd as controller_validation_cwd
def bypass(repository):
    return controller_validation_cwd(repository, ".")
""",
                {
                    "repository_io_private_import:_controller_validation_cwd",
                    "controller_capability_use:repository_io._controller_validation_cwd",
                },
            ),
            "direct_boundary_and_process_modules_are_forbidden": (
                """
import os
import subprocess
from artifact_io import read_regular_json_at
def bypass(path):
    return os.stat(path), subprocess.run(["true"]), read_regular_json_at(path, "state.json")
""",
                {
                    "forbidden_module_import:artifact_io",
                    "forbidden_module_import:os",
                    "forbidden_module_import:subprocess",
                },
            ),
            "controller_store_is_exact_and_powerful_opens_are_pinned": (
                """
from controller_store import open_controller_runs_root, arbitrary_store_reader
def bypass(root):
    return open_controller_runs_root(root, create=False), arbitrary_store_reader(root)
""",
                {
                    "controller_capability_use:controller_store.open_controller_runs_root",
                    "controller_store_unknown_import:arbitrary_store_reader",
                },
            ),
            "controller_callable_container_transport_is_pinned": (
                """
from controller_store import controller_open
def bypass(*args):
    raw = [controller_open][0]
    return raw(*args)
""",
                {
                    "controller_capability_reference:controller_store.controller_open"
                },
            ),
            "controller_import_rebinding_cannot_kill_taint": (
                """
from controller_store import controller_open
if False:
    controller_open = lambda *args: None
def bypass(*args):
    return controller_open(*args)
""",
                {
                    "import_binding_rebound:controller_open",
                    "controller_capability_reference:controller_store.controller_open",
                },
            ),
            "execution_controller_is_exact_and_powerful_calls_are_pinned": (
                """
from execution_controller import run_bounded_validation_process, arbitrary_runner
def bypass(**kwargs):
    return run_bounded_validation_process(**kwargs), arbitrary_runner(**kwargs)
""",
                {
                    "execution_capability_use:execution_controller.run_bounded_validation_process",
                    "execution_controller_unknown_import:arbitrary_runner",
                    "execution_controller_unknown_import:run_bounded_validation_process",
                },
            ),
            "repository_evidence_imports_are_positive_allowlisted": (
                """
from repository_evidence import open_repository_root_anchor, snapshot_allowed_paths
def bypass(root):
    open_repository_root_anchor(root)
    snapshot_allowed_paths(root, [])
""",
                {
                    "raw_io:repository_evidence.open_repository_root_anchor",
                    "raw_io:repository_evidence.snapshot_allowed_paths",
                    "repository_evidence_unknown_import:snapshot_allowed_paths",
                },
            ),
            "unapproved_and_local_helper_imports": (
                """
import safety_contracts
from safety_contracts import arbitrary_repository_reader
from random import random
""",
                {
                    "restricted_local_module_import:safety_contracts",
                    "local_helper_unknown_import:safety_contracts.arbitrary_repository_reader",
                    "unapproved_import_root:random",
                },
            ),
            "ctypes_dynamic_loader": (
                """
import ctypes
def bypass():
    direct = ctypes.cdll.LoadLibrary("libc.so")
    indirect = getattr(ctypes, "cdll").LoadLibrary("libc.so")
    return direct, indirect
""",
                {
                    "dangerous_callable_reference:ctypes.cdll.LoadLibrary",
                    "dynamic_attribute:cdll",
                    "raw_io:ctypes.cdll.LoadLibrary",
                },
            ),
            "argparse_implicit_file_readers": (
                """
import argparse
def bypass():
    parser = argparse.ArgumentParser(fromfile_prefix_chars="@")
    parser.add_argument("payload", type=argparse.FileType("r"))
    return parser
""",
                {
                    "raw_io:argparse.ArgumentParser.fromfile_prefix_chars",
                    "raw_io:argparse.FileType",
                },
            ),
            "argparse_fromfile_policy_cannot_be_enabled_after_init": (
                """
import argparse
def bypass():
    parser = argparse.ArgumentParser()
    parser.fromfile_prefix_chars = "@"
    return parser.parse_args(["@README.md"])
""",
                {"raw_io:argparse.ArgumentParser.fromfile_prefix_chars"},
            ),
            "stdlib_from_import_cannot_recover_reexported_module": (
                """
from argparse import _os as filesystem
def bypass(fd):
    return filesystem.read(fd, 1)
""",
                {"unapproved_from_import_module:argparse"},
            ),
            "stdlib_module_cannot_expose_reexported_module": (
                """
import argparse
def bypass():
    return argparse._os.system("true")
""",
                {
                    "reexported_module_access:argparse._os",
                    "unapproved_module_attribute:argparse._os",
                },
            ),
            "allowed_fnmatch_module_cannot_reexport_os": (
                """
import fnmatch
def bypass():
    return fnmatch.os.system("true")
""",
                {"unapproved_module_attribute:fnmatch.os"},
            ),
            "direct_module_objects_cannot_be_transported": (
                """
import argparse
import fnmatch
def bypass():
    first = [argparse][0]
    second = (lambda: fnmatch)()
    return first._os, second.os
""",
                {
                    "module_object_transport:argparse",
                    "module_object_transport:fnmatch",
                },
            ),
            "frame_and_traceback_namespaces_are_closed": (
                """
import sys
def bypass(error):
    first = sys._getframe().f_globals["__builtins__"]
    second = error.__traceback__.tb_frame.f_locals
    generator = (item for item in ())
    third = generator.gi_frame.f_builtins
    fourth = print.__self__.__import__("os")
    return first, second, third, fourth
""",
                {
                    "dynamic_namespace_access:sys._getframe",
                    "dynamic_namespace_access",
                    "dangerous_builtin_attribute:__import__",
                },
            ),
            "executable_annotation_is_never_ignored": (
                """
def bypass(value: __import__("os").system("true")):
    return value
""",
                {"executable_annotation"},
            ),
            "builtin_and_function_alias": (
                """
import builtins
from builtins import open as file_open
def bypass(path):
    first = open(path)
    reader = builtins.open
    second = reader(path)
    third = file_open(path)
    fourth = [open][0](path)
    return first, second, third, fourth
""",
                {
                    "builtin_open",
                    "dangerous_builtin_reference:open",
                    "dangerous_import:builtins.open",
                },
            ),
            "site_builtin_printer_file_gadget_is_rejected": (
                """
def bypass(path):
    license._Printer__filenames = [path]
    license._Printer__lines = None
    return repr(license)
""",
                {
                    "dangerous_builtin_reference:license",
                    "private_attribute_access:_Printer__filenames",
                },
            ),
        }
        for name, (source, expected) in cases.items():
            with self.subTest(name=name):
                symbols = self.python_symbols(source)
                self.assertTrue(expected.issubset(symbols), (expected - symbols, symbols))

    def test_future_annotations_contract_is_required(self) -> None:
        symbols = {
            finding.symbol
            for finding in POLICY.scan_python(
                "scripts/goal_run.py", "def safe(value: str) -> str:\n    return value\n"
            )
        }
        self.assertIn("future_annotations_contract_missing", symbols)

    def test_local_capability_wrappers_taint_callers_and_references(self) -> None:
        source = """
from __future__ import annotations
from repository_io import _controller_read_bytes as controller_read_bytes
def raw(repository, path):
    return controller_read_bytes(repository, path, required=True)
def indirect(repository, path):
    alias = raw
    return alias(repository, path)
def escaped(callbacks):
    callbacks.append(indirect)
"""
        symbols = self.python_symbols(source)
        self.assertIn("local_capability_reference:raw", symbols)
        self.assertIn("local_capability_reference:indirect", symbols)

    def test_function_name_does_not_grant_raw_io_capability(self) -> None:
        # This name used to be scope-allowlisted.  Body-digest capabilities
        # ensure a same-name replacement receives no authority.
        source = """
import os
def load_events(path):
    return os.open(path, os.O_RDONLY)
"""
        symbols = self.python_symbols(source, "scripts/apply_run.py")
        self.assertIn("raw_io:os.open", symbols)

    def test_ambiguous_method_names_use_path_type_and_call_signature(self) -> None:
        benign = """
def normal(match, text, evidence, timestamp):
    match.group()
    text.replace("old", "new")
    current = evidence.exists
    timestamp.replace(tzinfo=None)
    return current
"""
        self.assertEqual(self.python_symbols(benign), set())

        bypass = """
def mutate(root, target):
    root.exists()
    root.replace(target)
    alias = root.replace
    alias(target)
"""
        symbols = self.python_symbols(bypass)
        self.assertIn("path_convenience:exists", symbols)
        self.assertIn("path_mutation:replace", symbols)

        concrete_subclass = """
from pathlib import PosixPath
class ChildPath(PosixPath):
    pass
def inspect():
    path = ChildPath("README.md")
    return path.group()
"""
        self.assertIn(
            "path_convenience:group", self.python_symbols(concrete_subclass)
        )

        fake_path = """
class Path:
    def group(self):
        return "benign"
def make():
    return Path()
def normal():
    return make().group()
"""
        self.assertNotIn("path_convenience:group", self.python_symbols(fake_path))

    def test_each_path_value_flow_reaches_its_own_sink(self) -> None:
        cases = {
            "local_wrapper": (
                """
from pathlib import Path
def make(path):
    return Path(path)
def sink(path):
    return make(path).group()
""",
                "path_convenience:group",
            ),
            "preserving_method": (
                """
from pathlib import Path
def sink(path):
    return Path(path).with_suffix(".txt").group()
""",
                "path_convenience:group",
            ),
            "parents_subscript": (
                """
from pathlib import Path
def sink(path):
    return Path(path).parents[0].group()
""",
                "path_convenience:group",
            ),
            "tuple_subscript_bound_method": (
                """
from pathlib import Path
def sink(path):
    return (Path(path),)[0].exists
""",
                "path_convenience:exists",
            ),
            "conditional": (
                """
from pathlib import Path
def sink(path, flag):
    return (Path(path) if flag else Path(".")).group()
""",
                "path_convenience:group",
            ),
            "named_expression": (
                """
from pathlib import Path
def sink(path):
    return (value := Path(path)).group()
""",
                "path_convenience:group",
            ),
            "nested_helper": (
                """
from pathlib import Path
def outer(path):
    def make():
        return Path(path)
    return make().group()
""",
                "path_convenience:group",
            ),
            "awaited_async_helper": (
                """
from pathlib import Path
async def make(path):
    return Path(path)
async def sink(path):
    return (await make(path)).group()
""",
                "path_convenience:group",
            ),
            "lambda_bound_mutation": (
                """
from pathlib import Path
def sink(path, target):
    return next(map((lambda: Path(path))().replace, [target]))
""",
                "path_mutation:replace",
            ),
            "path_preserving_builtins": (
                """
from pathlib import Path
def sink(path):
    return next(iter([Path(path)])).group()
""",
                "path_convenience:group",
            ),
        }
        for name, (source, expected) in cases.items():
            with self.subTest(name=name):
                self.assertIn(expected, self.python_symbols(source))

    def test_only_canonical_runtime_import_bootstrap_may_touch_sys_path(self) -> None:
        canonical = """
import sys
from pathlib import Path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
"""
        self.assertEqual(self.python_symbols(canonical), set())

        symbols = self.python_symbols(
            canonical
            + """
sys.path.append("Planner-docs")
alias = sys
alias.meta_path = []
"""
        )
        self.assertIn("dynamic_import_state:sys.path", symbols)
        self.assertIn("dynamic_import_state:sys.meta_path", symbols)

        guarded = """
import sys
if __name__ == "__main__" and not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
):
    sys.stderr.write(
        "codexqb_controller=unsupported "
        "reason=requires_python_-I_-S_-B_first_process\\n"
    )
    raise SystemExit(2)
from pathlib import Path
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
"""
        self.assertTrue(POLICY._safe_sys_path_attribute_ids(ast.parse(guarded)))
        self.assertFalse(
            POLICY._safe_sys_path_attribute_ids(
                ast.parse(guarded.replace("codexqb_controller=unsupported", "changed"))
            )
        )

    def test_launcher_admission_exemption_requires_the_exact_early_ast(self) -> None:
        expected_basenames = {
            "scripts/apply_run.py": "apply_run.py",
            "scripts/goal_run.py": "goal_run.py",
            "scripts/validate_planner_docs.py": "validate_planner_docs.py",
        }
        for relative, expected_basename in expected_basenames.items():
            with self.subTest(relative=relative):
                source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
                tree = ast.parse(source)
                offset = int(
                    isinstance(tree.body[0], ast.Expr)
                    and isinstance(tree.body[0].value, ast.Constant)
                    and isinstance(tree.body[0].value.value, str)
                )
                prefix = ast.unparse(
                    ast.Module(body=tree.body[: offset + 6], type_ignores=[])
                ) + "\n"
                prefix_tree = ast.parse(prefix)
                safe_ids = POLICY._safe_launcher_admission_node_ids(
                    prefix_tree, relative
                )
                self.assertTrue(safe_ids)
                helper_calls = [
                    node
                    for node in ast.walk(prefix_tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "_launcher_admission_is_valid"
                ]
                self.assertEqual(len(helper_calls), 1)
                self.assertEqual(
                    ast.literal_eval(helper_calls[0].args[0]), expected_basename
                )
                original_symbols = {
                    finding.symbol
                    for finding in POLICY.scan_python(relative, prefix)
                }
                self.assertNotIn("dynamic_namespace_access", original_symbols)
                self.assertNotIn(
                    "private_attribute_access:__getattribute__", original_symbols
                )

                for label, mutated in (
                    (
                        "assurance",
                        prefix.replace(
                            "controller_observed_loader_path_unattested",
                            "changed",
                            1,
                        ),
                    ),
                    (
                        "basename",
                        prefix.replace(repr(expected_basename), repr("other.py"), 1),
                    ),
                    (
                        "ordering",
                        prefix.replace(
                            "from types import ModuleType\n",
                            "from types import ModuleType\nimport json\n",
                            1,
                        ),
                    ),
                ):
                    with self.subTest(relative=relative, mutation=label):
                        mutated_tree = ast.parse(mutated)
                        self.assertFalse(
                            POLICY._safe_launcher_admission_node_ids(
                                mutated_tree, relative
                            )
                        )
                        mutated_symbols = {
                            finding.symbol
                            for finding in POLICY.scan_python(relative, mutated)
                        }
                        self.assertIn("dynamic_namespace_access", mutated_symbols)
                        self.assertIn(
                            "private_attribute_access:__getattribute__",
                            mutated_symbols,
                        )

    def test_function_digest_never_exempts_forbidden_imports(self) -> None:
        source = """
def reviewed():
    import os
    return os
"""
        relative = "scripts/goal_run.py"
        tree = ast.parse(source)
        function = next(node for node in tree.body if isinstance(node, ast.FunctionDef))
        original = POLICY._APPROVED_CAPABILITY_DIGESTS[relative]
        POLICY._APPROVED_CAPABILITY_DIGESTS[relative] = frozenset(
            {*original, POLICY._body_digest(function)}
        )
        try:
            self.assertIn("forbidden_module_import:os", self.python_symbols(source, relative))
        finally:
            POLICY._APPROVED_CAPABILITY_DIGESTS[relative] = original

    def test_capability_digest_allowlist_has_no_stale_bodies(self) -> None:
        for relative, approved in POLICY._APPROVED_CAPABILITY_DIGESTS.items():
            tree = ast.parse((SKILL_ROOT / relative).read_text(encoding="utf-8"))
            current = {
                POLICY._body_digest(node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            with self.subTest(relative=relative):
                self.assertTrue(approved.issubset(current), approved - current)

        validator = ast.parse(
            (SKILL_ROOT / "scripts/validate_planner_docs.py").read_text(encoding="utf-8")
        )
        class_digests = {
            hashlib.sha256(
                POLICY._canonical_ast_dump(node).encode("utf-8")
            ).hexdigest()
            for node in ast.walk(validator)
            if isinstance(node, ast.ClassDef)
        }
        self.assertTrue(
            POLICY._APPROVED_VALIDATION_STATE_CLASS_DIGESTS.issubset(class_digests)
        )

    def test_repository_facade_and_exact_private_helpers_are_allowed_per_consumer(self) -> None:
        goal_source = """
from pathlib import Path
from repository_io import RepositoryIO, RepositoryIOPolicy, open_repository_io
from repository_io import (
    _controller_canonical_root as canonical_repository_root,
    _controller_evidence_digest as controller_evidence_digest,
    _controller_inventory as controller_inventory,
    _controller_path_kind as controller_path_kind,
    _controller_read_bytes as controller_read_bytes,
    _controller_regular_paths as controller_regular_paths,
    _controller_workspace_proof as controller_workspace_proof,
)
def safe(root: Path, repository: RepositoryIO):
    repository.read_text("README.md")
    repository.read_many(["README.md"])
    repository.list_paths("intake")
    repository.search("intake")
    repository.write_planner_text("step1", "Planner-docs/Main-Planing.md", "x", "missing")
    controller_evidence_digest({})
    with open_repository_io(root, RepositoryIOPolicy()) as opened:
        opened.read_text("README.md")
"""
        self.assertEqual(self.python_symbols(goal_source, "scripts/goal_run.py"), set())

        validator_source = """
from repository_io import (
    PathListing,
    RepositoryIO,
    _controller_canonical_root,
    open_repository_io,
)
def safe(repository: RepositoryIO) -> tuple[PathListing, object]:
    return (
        repository.list_paths("step3", audience="internal"),
        repository.read_text("Planner-docs/Main-Planing.md"),
    )
"""
        self.assertEqual(
            self.python_symbols(validator_source, "scripts/validate_planner_docs.py"),
            set(),
        )

        apply_source = """
from repository_io import (
    ControllerRootProof,
    RepositoryIO,
    RepositoryIOPolicy,
    _controller_baseline_digest,
    _controller_canonical_root,
    _controller_evidence_digest,
    _controller_evidence_from_snapshots,
    _controller_inventory,
    _controller_normalize_path,
    _controller_read_bytes,
    _controller_root_proof,
    _controller_regular_paths,
    _controller_snapshot_paths,
    _controller_validation_cwd,
    _controller_workspace_proof,
    open_repository_io,
)
"""
        self.assertEqual(
            self.python_symbols(apply_source, "scripts/apply_run.py"),
            {"apply_request_stdin_access_inventory_mismatch"},
        )

        private_call_source = """
from repository_io import RepositoryIO, _controller_read_bytes
def bypass(repository: RepositoryIO):
    return _controller_read_bytes(repository, "README.md")
"""
        self.assertIn(
            "controller_capability_use:repository_io._controller_read_bytes",
            self.python_symbols(private_call_source, "scripts/goal_run.py"),
        )

        validator_private_source = """
from repository_io import RepositoryIO, _controller_regular_paths
def reviewed(repository: RepositoryIO):
    return _controller_regular_paths(repository, "step3")
"""
        validator_tree = ast.parse(validator_private_source)
        validator_function = next(
            node for node in validator_tree.body if isinstance(node, ast.FunctionDef)
        )
        original_validator_digests = POLICY._APPROVED_CAPABILITY_DIGESTS[
            "scripts/validate_planner_docs.py"
        ]
        POLICY._APPROVED_CAPABILITY_DIGESTS["scripts/validate_planner_docs.py"] = (
            frozenset(
                {
                    *original_validator_digests,
                    POLICY._body_digest(validator_function),
                }
            )
        )
        try:
            self.assertEqual(
                self.python_symbols(
                    validator_private_source,
                    "scripts/validate_planner_docs.py",
                ),
                set(),
            )
        finally:
            POLICY._APPROVED_CAPABILITY_DIGESTS[
                "scripts/validate_planner_docs.py"
            ] = original_validator_digests

        validator_callback_source = """
from repository_io import RepositoryIO
def bypass(repository: RepositoryIO, callback):
    return callback(repository)
"""
        self.assertIn(
            "repository_facade_transport:repository",
            self.python_symbols(
                validator_callback_source,
                "scripts/validate_planner_docs.py",
            ),
        )

        goal_execution_source = """
from execution_controller import run_goal_planner_validator
"""
        self.assertEqual(
            self.python_symbols(goal_execution_source, "scripts/goal_run.py"), set()
        )
        apply_execution_source = """
from execution_controller import (
    ValidationProcessResult,
    run_bounded_validation_process,
    run_step4_readiness_validator,
)
"""
        self.assertEqual(
            self.python_symbols(apply_execution_source, "scripts/apply_run.py"),
            {"apply_request_stdin_access_inventory_mismatch"},
        )

        wrong_consumer_source = """
from repository_io import _controller_directories
def bypass(repository):
    return _controller_directories(repository, "intake")
"""
        self.assertIn(
            "repository_io_private_import:_controller_directories",
            self.python_symbols(wrong_consumer_source, "scripts/goal_run.py"),
        )

    def test_goal_held_byte_reader_requires_exact_import_consumer_and_body(self) -> None:
        relative = "scripts/goal_run.py"
        source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        self.assertEqual(
            POLICY._EXECUTION_CONTROLLER_ALLOWED_IMPORTS[relative],
            frozenset(
                {"read_goal_held_bytes", "run_goal_planner_validator"}
            ),
        )
        self.assertEqual(
            POLICY._GOAL_EXECUTION_CONTROLLER_IMPORT_CONTRACT,
            ("read_goal_held_bytes", "run_goal_planner_validator"),
        )
        self.assertIn(
            "execution_controller.read_goal_held_bytes",
            POLICY._POWERFUL_EXECUTION_CONTROLLER_CALLS,
        )
        reader = next(
            node
            for node in ast.parse(source).body
            if isinstance(node, ast.FunctionDef) and node.name == "read_skill_bytes"
        )
        reader_digest = POLICY._body_digest(reader)
        self.assertEqual(
            reader_digest,
            "8343857c04fadb01eaa9a66c03aad76efec3d31f371c38b505fc7aef16d1002b",
        )
        self.assertIn(
            reader_digest,
            POLICY._APPROVED_CAPABILITY_DIGESTS[relative],
        )
        self.assertEqual(
            POLICY._GOAL_HELD_READER_DEFINITION_DIGEST,
            reader_digest,
        )
        self.assertEqual(POLICY.scan_python(relative, source), [])

        canonical_import = """from execution_controller import (  # noqa: E402
    read_goal_held_bytes,
    run_goal_planner_validator,
)"""
        self.assertIn(canonical_import, source)
        import_mutations = {
            "alias_swap": """from execution_controller import (  # noqa: E402
    read_goal_held_bytes as run_goal_planner_validator,
    run_goal_planner_validator as read_goal_held_bytes,
)""",
            "self_alias": """from execution_controller import (  # noqa: E402
    read_goal_held_bytes as read_goal_held_bytes,
    run_goal_planner_validator,
)""",
            "duplicate_symbol": """from execution_controller import (  # noqa: E402
    read_goal_held_bytes,
    read_goal_held_bytes,
    run_goal_planner_validator,
)""",
            "split": """from execution_controller import read_goal_held_bytes  # noqa: E402
from execution_controller import run_goal_planner_validator  # noqa: E402""",
            "reversed": """from execution_controller import (  # noqa: E402
    run_goal_planner_validator,
    read_goal_held_bytes,
)""",
            "conditional": "if True:\n"
            + "\n".join(f"    {line}" for line in canonical_import.splitlines()),
            "duplicate_statement": canonical_import + "\n" + canonical_import,
        }
        for label, replacement in import_mutations.items():
            with self.subTest(import_mutation=label):
                mutated = source.replace(canonical_import, replacement, 1)
                self.assertIn(
                    "goal_execution_controller_import_contract_mismatch",
                    self.python_symbols(mutated, relative),
                )

        def mutate_reader_definition(kind: str) -> str:
            tree = ast.parse(source)
            index, definition = next(
                (index, node)
                for index, node in enumerate(tree.body)
                if isinstance(node, ast.FunctionDef)
                and node.name == "read_skill_bytes"
            )
            if kind in {"if_true", "if_false"}:
                tree.body[index] = ast.If(
                    test=ast.Constant(value=kind == "if_true"),
                    body=[definition],
                    orelse=[],
                )
            elif kind == "class_method":
                container = ast.parse("class _ReaderContainer:\n    pass\n").body[0]
                self.assertIsInstance(container, ast.ClassDef)
                container.body = [definition]
                tree.body[index] = container
            elif kind == "duplicate":
                duplicate = ast.parse(ast.unparse(definition)).body[0]
                tree.body.insert(index + 1, duplicate)
            else:  # pragma: no cover - test helper contract
                raise AssertionError(f"unknown reader mutation: {kind}")
            ast.fix_missing_locations(tree)
            return ast.unparse(tree) + "\n"

        for kind in ("if_true", "if_false", "class_method", "duplicate"):
            with self.subTest(reader_mutation=kind):
                self.assertIn(
                    "goal_held_reader_definition_contract_mismatch",
                    self.python_symbols(
                        mutate_reader_definition(kind),
                        relative,
                    ),
                )

        binding_import_mutations = {
            "reader_import_alias": source
            + "\nfrom safety_contracts import "
            + "redact_secret_like as read_goal_held_bytes\n",
            "validator_import_alias": source
            + "\nfrom repository_io import "
            + "_controller_canonical_root as run_goal_planner_validator\n",
            "reader_function_import_alias": source
            + "\nfrom safety_contracts import "
            + "redact_secret_like as read_skill_bytes\n",
            "wildcard_import": source + "\nfrom safety_contracts import *\n",
        }
        for label, mutated in binding_import_mutations.items():
            with self.subTest(binding_import_mutation=label):
                self.assertIn(
                    "goal_held_reader_binding_rebound",
                    self.python_symbols(mutated, relative),
                )

        for target in (
            "read_goal_held_bytes",
            "run_goal_planner_validator",
            "read_skill_bytes",
        ):
            binding_forms = {
                "assign": f"\n{target} = None\n",
                "annassign": f"\n{target}: object = None\n",
                "augassign": f"\n{target} += ()\n",
                "namedexpr": f"\n_semantic_probe = ({target} := None)\n",
                "for": f"\nfor {target} in ():\n    pass\n",
                "with": f"\nwith _semantic_context as {target}:\n    pass\n",
                "except": f"\ntry:\n    pass\nexcept Exception as {target}:\n    pass\n",
                "match_as": f"\nmatch object():\n    case {target}:\n        pass\n",
                "match_star": f"\nmatch []:\n    case [*{target}]:\n        pass\n",
                "match_mapping": f"\nmatch {{}}:\n    case {{**{target}}}:\n        pass\n",
                "comprehension": f"\n_semantic_probe = [None for {target} in ()]\n",
                "delete": f"\ndel {target}\n",
                "function_global": (
                    "\ndef _semantic_global_probe():\n"
                    f"    global {target}\n"
                    f"    {target} = None\n"
                ),
            }
            for form, addition in binding_forms.items():
                with self.subTest(binding_target=target, binding_form=form):
                    self.assertIn(
                        "goal_held_reader_binding_rebound",
                        self.python_symbols(source + addition, relative),
                    )

        reader_removed_tree = ast.parse(source)
        reader_removed_tree.body = [
            node
            for node in reader_removed_tree.body
            if not (
                isinstance(node, ast.FunctionDef)
                and node.name == "read_skill_bytes"
            )
        ]
        execution_import = next(
            node
            for node in reader_removed_tree.body
            if isinstance(node, ast.ImportFrom)
            and node.module == "execution_controller"
        )
        execution_import.names = [
            alias
            for alias in execution_import.names
            if alias.name == "run_goal_planner_validator"
        ]
        ast.fix_missing_locations(reader_removed_tree)
        reader_removed = ast.unparse(reader_removed_tree) + "\n"
        reader_removed_symbols = self.python_symbols(reader_removed, relative)
        self.assertNotIn(
            "goal_execution_controller_import_contract_mismatch",
            reader_removed_symbols,
        )
        self.assertNotIn(
            "goal_held_reader_binding_rebound",
            reader_removed_symbols,
        )
        for target in ("run_goal_planner_validator", "read_skill_bytes"):
            with self.subTest(reader_removed_binding_hijack=target):
                hijacked = (
                    reader_removed
                    + "\nfrom repository_io import "
                    + f"_controller_canonical_root as {target}\n"
                )
                self.assertIn(
                    "goal_held_reader_binding_rebound",
                    self.python_symbols(hijacked, relative),
                )

        third_import = source.replace(
            "read_goal_held_bytes,\n    run_goal_planner_validator,",
            "read_goal_held_bytes,\n"
            "    run_bounded_validation_process,\n"
            "    run_goal_planner_validator,",
            1,
        )
        self.assertIn(
            "execution_controller_unknown_import:run_bounded_validation_process",
            self.python_symbols(third_import, relative),
        )

        mutations = {
            "container_transport": source.replace(
                "return read_goal_held_bytes(relative_path)",
                "return [read_goal_held_bytes][0](relative_path)",
                1,
            ),
            "import_alias": source.replace(
                "read_goal_held_bytes,",
                "read_goal_held_bytes as held_reader,",
                1,
            ).replace(
                "return read_goal_held_bytes(relative_path)",
                "return held_reader(relative_path)",
                1,
            ),
            "unreviewed_wrapper": source
            + "\ndef _unreviewed_reader(path: str) -> bytes:\n"
            + "    return read_goal_held_bytes(path)\n",
            "module_transport": source
            + "\nUNREVIEWED_READER = read_goal_held_bytes\n",
        }
        for label, mutated in mutations.items():
            with self.subTest(mutation=label):
                self.assertIn(
                    "execution_capability_reference:"
                    "execution_controller.read_goal_held_bytes",
                    self.python_symbols(mutated, relative),
                )

        wrong_consumer = """
from execution_controller import read_goal_held_bytes
def bypass(path: str) -> bytes:
    return read_goal_held_bytes(path)
"""
        wrong_symbols = self.python_symbols(
            wrong_consumer,
            "scripts/apply_run.py",
        )
        self.assertIn(
            "execution_controller_unknown_import:read_goal_held_bytes",
            wrong_symbols,
        )
        self.assertIn(
            "execution_capability_use:execution_controller.read_goal_held_bytes",
            wrong_symbols,
        )

    def test_controller_store_is_ast_pinned_and_repository_controller_is_forbidden(self) -> None:
        store_source = (SKILL_ROOT / "scripts/controller_store.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            POLICY.scan_controller_store("scripts/controller_store.py", store_source),
            [],
        )
        store_symbols = {
            finding.symbol
            for finding in POLICY.scan_controller_store(
                "scripts/controller_store.py",
                store_source + "\ndef unsafe_store_extension():\n    return None\n",
            )
        }
        self.assertIn("controller_store_unreviewed", store_symbols)

        with tempfile.TemporaryDirectory() as temp_dir:
            skill = Path(temp_dir) / "skills/codexqb"
            scripts = skill / "scripts"
            scripts.mkdir(parents=True)
            (skill / "SKILL.md").write_text("---\nname: codexqb\n---\n", encoding="utf-8")
            for relative in POLICY.REQUIRED_RUNTIME:
                name = Path(relative).name
                (scripts / name).write_bytes((SKILL_ROOT / relative).read_bytes())
            for relative in POLICY.PROTECTED_PYTHON:
                (scripts / Path(relative).name).write_text("value = 1\n", encoding="utf-8")
            (scripts / "repository_controller.py").write_text(
                "def raw_engine(repository):\n    return repository\n",
                encoding="utf-8",
            )
            symbols = {finding.symbol for finding in POLICY.scan_tree(Path(temp_dir))}
            self.assertIn("forbidden_repository_controller_runtime", symbols)

    def test_execution_controller_is_ast_pinned_and_non_extensible(self) -> None:
        source = (SKILL_ROOT / "scripts/execution_controller.py").read_text(
            encoding="utf-8"
        )
        self.assertEqual(
            POLICY.scan_execution_controller("scripts/execution_controller.py", source),
            [],
        )
        symbols = {
            finding.symbol
            for finding in POLICY.scan_execution_controller(
                "scripts/execution_controller.py",
                source + "\ndef arbitrary_process_runner():\n    return None\n",
            )
        }
        self.assertIn("execution_controller_unreviewed", symbols)

    def test_future_trusted_controller_requires_exact_enrolment(self) -> None:
        self.assertEqual(
            POLICY.REQUIRED_RUNTIME,
            POLICY._CORE_REQUIRED_RUNTIME
            + tuple(sorted(POLICY._TRUSTED_CONTROLLER_REGISTRY)),
        )
        source = """
from repository_io import _controller_inventory

def collect(repository):
    return _controller_inventory(repository)
"""
        digest = hashlib.sha256(
            POLICY._canonical_ast_dump(ast.parse(source)).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            POLICY.scan_trusted_controller(
                "scripts/validation_isolation.py",
                source,
                expected_digest=digest,
                allowed_repository_io_imports=frozenset({"_controller_inventory"}),
            ),
            [],
        )
        wildcard_symbols = {
            finding.symbol
            for finding in POLICY.scan_trusted_controller(
                "scripts/*.py",
                source,
                expected_digest=digest,
                allowed_repository_io_imports=frozenset({"_controller_inventory"}),
            )
        }
        self.assertIn("trusted_controller_path_not_exact", wildcard_symbols)

    def test_future_trusted_controller_cannot_emit_repository_model_output(self) -> None:
        source = """
from repository_io import _controller_inventory

def collect(repository):
    _controller_inventory(repository)
    direct = repository.read_text("README.md", required=True, audience="model")
    dynamic = getattr(repository, "read_text")
    return direct, dynamic
"""
        digest = hashlib.sha256(
            POLICY._canonical_ast_dump(ast.parse(source)).encode("utf-8")
        ).hexdigest()
        symbols = {
            finding.symbol
            for finding in POLICY.scan_trusted_controller(
                "scripts/validation_isolation.py",
                source,
                expected_digest=digest,
                allowed_repository_io_imports=frozenset({"_controller_inventory"}),
            )
        }
        self.assertIn("trusted_controller_repository_output:read_text", symbols)
        self.assertIn("trusted_controller_audience_output", symbols)
        self.assertIn("trusted_controller_dynamic_access:namespace", symbols)

    def test_validation_state_aggregate_cannot_escape_to_callback(self) -> None:
        relative = "scripts/validate_planner_docs.py"
        source = (SKILL_ROOT / relative).read_text(encoding="utf-8")
        insertion = (
            "\ndef leak_validation_state(state: ValidationState, callback):\n"
            "    return callback(state)\n\n"
        )
        marker = '\nif __name__ == "__main__":'
        self.assertIn(marker, source)
        modified = source.replace(marker, insertion + marker, 1)
        inserted_line = source[: source.index(marker)].count("\n") + 3
        findings = POLICY.scan_python(relative, modified)
        self.assertTrue(
            any(
                finding.line == inserted_line
                and finding.symbol == "validation_state_transport:state"
                for finding in findings
            ),
            findings[-20:],
        )

    def test_markdown_bypass_surface_corpus_is_fail_closed(self) -> None:
        cases = {
            "non_bash_fence": "```json\ncat README.md\n```",
            "continuation": "cat \\\n+ README.md",
            "blockquote": "> cat README.md",
            "indented": "    rg secret .",
            "html_comment": "<!-- grep token README.md -->",
            "html_attribute": '<div data-command="find . -type f"></div>',
            "table": "| Tool | Command |\n|---|---|\n| shell | ls Planner-docs |",
            "plain": "cat README.md",
            "unicode_compatibility": "ｃａｔ README.md",
            "json_tool": '{"tool":"shell","command":"rg secret ."}',
            "pretty_json_tool": '{\n  "tool": "shell",\n  "command": "grep token README.md"\n}',
            "apply_patch": "apply_patch <<'PATCH'\n*** Begin Patch",
            "bare_patch_payload": "*** Begin Patch\n*** Update File: Planner-docs/Main-Planing.md",
            "git_show": "git show HEAD:README.md",
            "git_status": "git status --short --branch",
            "git_branch": "git branch --show-current",
            "git_rev_parse": "git rev-parse --show-toplevel",
            "python_c": "python3 -c \"open('README.md').read()\"",
            "python_heredoc": "python3 - <<'PY'\nopen('README.md').read()\nPY",
            "arbitrary_python_script": "python3 helper.py README.md",
            "alternate_interpreter": "ruby helper.rb README.md",
            "command_substitution": "echo $(cat README.md)",
            "bare_command_substitution": "$(cat README.md)",
            "input_redirection": "< README.md",
            "attached_input_redirection": "cat<README.md",
            "attached_heredoc": "cat<<EOF\npayload\nEOF",
            "redirect_only_builtin": ": <README.md",
            "process_substitution": "diff <(cat README.md) /dev/null",
            "brace_expanded_command": "{cat,README.md}",
            "shell_assignment": "LC_ALL=C cat README.md",
            "command_wrapper_option": "command -p cat README.md",
            "sudo_wrapper_option": "sudo -u root cat README.md",
            "xargs_wrapper_option": "xargs -n 1 cat README.md",
            "busybox_applet": "busybox cat README.md",
            "busybox_install_mode": "busybox --install /tmp/applets",
            "busybox_option_applet": "busybox -s cat README.md",
            "timeout_wrapper": "timeout 2 cat README.md",
            "dynamic_command_name": "$READER README.md",
            "embedded_command_name_expansion": "c${EMPTY}at README.md",
            "env_split_string": "env -S 'cat README.md'",
            "env_argv_zero_wrapper": "env -a harmless cat README.md",
            "setsid_option_wrapper": "setsid -f cat README.md",
            "xargs_argument_file": "xargs --arg-file README.md",
            "yaml_shell_builtin": 'command: "source helper.sh"',
            "bare_source_builtin": "source README",
            "unknown_yaml_command": "command: helper README.md",
            "unknown_json_command": '{"command":"helper README.md"}',
            "unknown_shell_fence": "```bash\nhelper README.md\n```",
            "pandoc_shell_fence": "```{.bash}\nhelper README.md\n```",
            "pandoc_multi_attribute_fence": "```{.bash .numberLines}\nhelper README.md\n```",
            "rmarkdown_shell_fence": "```{bash}\nhelper README.md\n```",
            "quarto_shell_fence": "```{bash, echo=FALSE}\nhelper README.md\n```",
            "powershell_fence": "```powershell\nhelper README.md\n```",
            "nushell_fence": "```nu\nhelper README.md\n```",
            "cmd_fence": "```cmd\nhelper README.md\n```",
            "shell_session_fence": "```shell-session\nhelper README.md\n```",
            "bash_session_fence": "```bash-session\nhelper README.md\n```",
            "long_fence_short_close": "````bash\n```\nhelper README.md\n````",
            "info_bearing_fake_close": "```bash\n```not-a-close\nhelper README.md\n```",
            "html_shell_code_block": '<pre><code class="language-shell">\nhelper README.md\n</code></pre>',
            "html_plain_code_block": "<pre><code>\nhelper README.md\n</code></pre>",
            "html_shell_script_block": '<script type="text/x-shellscript">\nhelper README.md\n</script>',
            "unknown_indented_command": "    helper README.md",
            "unknown_imperative_command": "Run helper README.md",
            "shell_if": "if cat README.md; then :; fi",
            "shell_while": "while cat README.md; do :; done",
            "shell_for": 'for f in README.md; do cat "$f"; done',
            "shell_negation": "! cat README.md",
            "shell_time": "time cat README.md",
            "shell_coproc": "coproc cat README.md",
            "shell_until": "until cat README.md; do :; done",
            "shell_function": "reader() { cat README.md; }; reader",
            "shell_function_keyword": "function reader { cat README.md; }; reader",
            "shell_brace_group": "{ cat README.md; }",
            "shell_subshell": "(cat README.md)",
            "shell_case": "case x in x) cat README.md;; esac",
            "shell_builtin_wrapper": "builtin cat README.md",
            "shell_alias": "alias reader=cat; reader README.md",
            "git_log_patch": "git log -p -- README.md",
            "git_blame": "git blame README.md",
            "yaml_argv": 'argv: ["cat", "README.md"]',
            "yaml_flow_command": "command: [cat, README.md]",
            "yaml_list_command": "- command: helper README.md",
            "yaml_quoted_command_key": '"command": helper README.md',
            "yaml_single_quoted_command_key": "'command': helper README.md",
            "yaml_nested_cmd": "  - cmd: helper README.md",
            "yaml_block_sequence_command": "command:\n  - helper\n  - README.md",
            "yaml_folded_command": "command: >\n  helper README.md",
            "toml_command": 'command = "cat README.md"',
            "toml_flow_command": 'command = ["cat", "README.md"]',
            "toml_quoted_command_key": '"command" = "helper README.md"',
            "yaml_escaped_command_key": '"comm\\u0061nd": helper README.md',
            "yaml_quoted_flow_command": '{"command": helper README.md}',
            "toml_inline_command": 'runner = { "command" = "helper README.md" }',
            "flow_map_command": "{command: cat README.md}",
            "xml_command": "<command>cat README.md</command>",
            "xml_cdata_command": "<command><![CDATA[cat README.md]]></command>",
            "xml_dtd_entity": '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>',
            "yaml_escaped_command": 'command: "\\u0063at README.md"',
            "yaml_tagged_command": '!!str command: !!str cat README.md',
            "yaml_anchored_command": 'command: &reader cat README.md',
            "yaml_alias_command": 'command: *reader',
            "ansi_c_quoted_command": "$'\\x63\\x61\\x74' README.md",
            "environment_echo": "echo $OPENAI_API_KEY",
            "alternate_file_reader": "jq . package.json",
            "absolute_executable": "/tmp/reader README.md",
            "relative_executable": "```bash\n./helper README.md\n```",
            "globbed_executable": "/bin/c?t README.md",
        }
        for name, text in cases.items():
            with self.subTest(name=name):
                self.assertIn("raw_repository_command", self.markdown_symbols(text))

        self.assertIn(
            "unsafe_reference_controls",
            self.markdown_symbols("safe\u202e cat README.md"),
        )

    def test_normal_prose_and_json_schema_are_not_shell_commands(self) -> None:
        self.assertEqual(
            self.markdown_symbols(
                "Read the report, group findings, and replace stale prose after review."
            ),
            set(),
        )
        self.assertEqual(
            self.markdown_symbols(
                '{"pattern":"^[a-f0-9]{64}$","type":"string","title":"Read"}'
            ),
            set(),
        )
        self.assertEqual(self.markdown_symbols("The threshold is < 5."), set())
        for prose in (
            "Find the root cause before changing code.",
            "Head to the next section for details.",
            "Sort the findings by severity.",
            "The `cat README.md` example is forbidden.",
            "Never run `cat README.md`; use the facade.",
        ):
            with self.subTest(prose=prose):
                self.assertEqual(self.markdown_symbols(prose), set())

    def test_arbitrary_planner_docs_commands_require_facade(self) -> None:
        cases = (
            "customtool --output Planner-docs/Main-Planing.md",
            '{"tool":"shell","command":"helper --out Planner-docs/Main-Planing.md"}',
            "python3 helper.py Planner-docs/Main-Planing.md",
            "git diff -- Planner-docs",
            "echo payload > Planner-docs/Main-Planing.md",
        )
        for text in cases:
            with self.subTest(text=text):
                self.assertIn("repository_io_command_required", self.markdown_symbols(text))

    def test_repository_io_command_grammar_accepts_only_canonical_forms(self) -> None:
        facade = request_stdin_command("repository-io")
        valid = (
            facade,
            f"Run `{facade}` and send its request through the host stdin channel.",
        )
        for command in valid:
            with self.subTest(command=command):
                self.assertEqual(self.markdown_symbols(command), set())

        invalid = (
            f"{launcher_command('repository-io')} --root . inspect --profile intake",
            f"{launcher_command('repository-io')} --root . search --profile step3",
            f"{launcher_command('repository-io')} --root . read-model --path README.md",
            f"{launcher_command('repository-io')} --root . read-model --path <repository-relative-path>",
            f"{launcher_command('repository-io')} --root . write-planner --stage step1 --path Planner-docs/Main-Planing.md --expected-missing",
            "python3 -I -S -B <CODEXQB_SKILL_ROOT>/scripts/repository_io.py --root . inspect --profile intake",
            "python3 -I -S -B \"$CODEXQB_SKILL_ROOT/scripts/repository_io.py\" --root . inspect --profile intake",
            "python3 -I -S -B plugins/codexqb/skills/codexqb/scripts/repository_io.py --root . inspect --profile intake",
            "python3 -I -S -B scripts/repository_io.py --root . inspect --profile intake",
            "python3 scripts/repository_io.py --root . inspect --profile intake",
            "python3 -I -B -S scripts/repository_io.py --root . inspect --profile intake",
            "python3 scripts/repository_io.py inspect --profile intake",
            "python3 scripts/repository_io.py --root /tmp inspect --profile intake",
            "python3 scripts/repository_io.py --root .. inspect --profile intake",
            "python3 scripts/repository_io.py --root=. inspect --profile intake",
            "python scripts/repository_io.py --root . inspect --profile intake",
            "python3 -m repository_io --root . inspect --profile intake",
            "env X=1 python3 scripts/repository_io.py --root . inspect --profile intake",
            "python3 scripts/repository_io.py --root . inspect --profile arbitrary",
            "python3 scripts/repository_io.py --root . inspect --profile intake --extra",
            "python3 scripts/repository_io.py --root . read-model --path ../secret",
            "python3 scripts/repository_io.py --root . write-planner --stage step1 --path ../README.md --expected-missing",
            "python3 scripts/repository_io.py --root . write-planner --stage step1 --path Planner-docs/Other.md --expected-missing",
            "python3 scripts/repository_io.py --root . write-planner --stage step3 --path Planner-docs/Main-Planing.md --expected-missing",
            "python3 scripts/repository_io.py --root . write-planner --stage step1 --path Planner-docs/Main-Planing.md --expected-sha256 nope",
            "python3 scripts/repository_io.py --root . inspect --profile intake | cat",
            f"{facade} extra",
            f"{facade} --path README.md",
            f"{facade} --report-json '{{}}'",
        )
        for command in invalid:
            with self.subTest(command=command):
                self.assertIn("invalid_repository_io_command", self.markdown_symbols(command))

    def test_portable_launcher_contract_is_the_only_controller_entrypoint(self) -> None:
        valid = (
            request_stdin_command("repository-io"),
            f"{launcher_command('planner-validator')} --root . --mode step3 --strict",
            f"{launcher_command('goal')} prepare --root . --stage step2",
            request_stdin_command("apply"),
            f"{launcher_command('doctor')} --json",
        )
        for command in valid:
            with self.subTest(valid=command):
                self.assertEqual(self.markdown_symbols(command), set())

        direct = (
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/repository_io.py" --root . inspect --profile intake',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/validate_planner_docs.py" --root . --mode step3 --strict',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/goal_run.py" prepare --root . --stage step2',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/apply_run.py" prepare --root . --mode direct',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/doctor.py" --json',
        )
        for command in direct:
            with self.subTest(direct=command):
                self.assertTrue(
                    {"raw_repository_command", "invalid_repository_io_command"}
                    & self.markdown_symbols(command)
                )

        invalid = (
            'python3 -I -S -B <CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller doctor -- --json',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md <CODEXQB_SKILL_ROOT>/SKILL.md --controller doctor -- --json',
            "python3 -I -S -B '<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py' --active-skill-md \"<CODEXQB_SKILL_ROOT>/SKILL.md\" --controller doctor -- --json",
            "python3 -I -S -B \"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py\" --active-skill-md '<CODEXQB_SKILL_ROOT>/SKILL.md' --controller doctor -- --json",
            'python3 -I -S -B "$CODEXQB_SKILL_ROOT/scripts/skill_launcher.py" --active-skill-md "$CODEXQB_SKILL_ROOT/SKILL.md" --controller doctor -- --json',
            'python3 -I -S -B "scripts/skill_launcher.py" --active-skill-md "SKILL.md" --controller doctor -- --json',
            'python3 -I -S -B "../sibling/codexqb/scripts/skill_launcher.py" --active-skill-md "../sibling/codexqb/SKILL.md" --controller doctor -- --json',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --controller doctor --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" -- --json',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller arbitrary -- --json',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller doctor --json',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller doctor -- -- --json',
            f"env X=1 {launcher_command('doctor')} --json",
            f"{launcher_command('repository-io')} --json",
            f"{launcher_command('planner-validator')} prepare --root . --stage step2",
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller goal -- --root . inspect --profile intake',
            f"{launcher_command('apply')} --root . inspect --profile intake",
            f"{launcher_command('apply')} prepare --root . --mode direct",
            f"{launcher_command('apply')} normalize-review --root . --run-dir <run-dir> --task-id <task-id> --review-phase spec --agent-id <agent-id> --report-json '{{}}' --actor controller",
            f"{launcher_command('doctor')} prepare --root . --stage step2",
            f"{launcher_command('apply')} -c 'print(1)'",
            f"{launcher_command('goal')} runpy goal_run.py",
            "python3 -I -S -B -c 'import runpy; runpy.run_path(\"<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py\", run_name=\"__main__\")'",
            'python3 -I -S -B -m runpy "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"',
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" --active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller doctor -- --json --controller apply',
            f"{launcher_command('doctor')} --json ; cat README.md",
            f"{launcher_command('repository-io')} --root . inspect --profile intake && echo bypass",
        )
        for command in invalid:
            with self.subTest(invalid=command):
                self.assertTrue(
                    {"raw_repository_command", "invalid_repository_io_command"}
                    & self.markdown_symbols(command)
                )

        unicode_smuggling = launcher_command("doctor").replace(
            "--controller doctor",
            "--controller doc\u2060tor",
        ) + " --json"
        self.assertIn(
            "unsafe_reference_controls",
            self.markdown_symbols(unicode_smuggling),
        )

    def test_only_exact_trusted_python_command_profiles_are_allowed(self) -> None:
        allowed = (
            f"{launcher_command('planner-validator')} --root . --mode step3 --strict",
            f"{launcher_command('planner-validator')} --root . --mode all --strict",
            f"{launcher_command('doctor')} --json",
            "python3 -B -m pytest -p no:cacheprovider tests/test_example.py -q",
            "python3 -B -m unittest discover -s tests -p 'test_*.py'",
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertEqual(self.markdown_symbols(command), set())

        rejected = (
            "python3 -I -S -B <CODEXQB_SKILL_ROOT>/scripts/validate_planner_docs.py --root . --mode all --strict",
            "python3 -I -S -B scripts/validate_planner_docs.py --root . --mode all --strict",
            "python3 scripts/validate_planner_docs.py --root . --mode all --strict",
            "python3 plugins/codexqb/skills/codexqb/scripts/doctor.py --json",
            "python3 scripts/validate_planner_docs.py --root /tmp --mode all --strict",
            "python3 scripts/validate_planner_docs.py --mode all --root . --strict",
            "python3 -m pytest tests/test_example.py",
            "python3 helper.py README.md",
        )
        for command in rejected:
            with self.subTest(command=command):
                self.assertIn("raw_repository_command", self.markdown_symbols(command))

    def test_goal_apply_controller_commands_require_exact_isolated_argv(self) -> None:
        goal = launcher_command("goal")
        apply = launcher_command("apply")
        writer_report = json.dumps(
            {
                "status": "DONE",
                "task_id": "<task-id>",
                "implementer_agent_id": "<agent-id>",
                "files_changed": ["src/example.py"],
                "concerns": [],
            },
            separators=(",", ":"),
        )
        review_report = json.dumps(
            {
                "status": "COMPLETE",
                "phase": "spec",
                "verdict": "pass",
                "task_id": "<task-id>",
                "reviewer_agent_id": "<agent-id>",
                "evidence": ["reviewed current patch and receipts"],
            },
            separators=(",", ":"),
        )
        allowed = (
            f"{goal} collect --root . --stage step15",
            f"{goal} prepare --root <project-root> --stage step2",
            f"{goal} validate --root . --goal-run <goal-run>",
            f"{goal} render --root <project-root> --goal-run <goal-run>",
            request_stdin_command("apply"),
        )
        for command in allowed:
            with self.subTest(command=command):
                self.assertEqual(self.markdown_symbols(command), set())

        apply_requests = (
            ["prepare", "--root", ".", "--mode", "subagent_serial"],
            ["validate", "--root", "<project-root>", "--run-dir", "<run-dir>"],
            ["transition", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--to", "IMPLEMENTED", "--actor", "<agent-id>"],
            ["dispatch", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--role", "implementer", "--actor", "controller"],
            ["record-agent", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--role", "implementer", "--agent-id", "<agent-id>", "--status", "completed", "--actor", "controller"],
            ["normalize-writer", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--role", "implementer", "--agent-id", "<agent-id>", "--report-json", writer_report, "--actor", "controller"],
            ["normalize-review", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--review-phase", "spec", "--agent-id", "<agent-id>", "--report-json", review_report, "--actor", "controller"],
            ["capture-evidence", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--actor", "controller"],
            ["run-validation", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--validation-id", "VAL-01", "--actor", "controller"],
            ["publish-review", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--review-phase", "final", "--actor", "controller"],
            ["reconcile", "--root", "<project-root>", "--run-dir", "<run-dir>"],
            ["recover-lock", "--root", "<project-root>", "--run-dir", "<run-dir>", "--task-id", "<task-id>", "--to", "NEEDS_CONTEXT", "--actor", "controller"],
            ["finalize", "--root", "<project-root>", "--run-dir", "<run-dir>", "--actor", "controller"],
        )
        for argv in apply_requests:
            with self.subTest(argv=argv[0]):
                self.assertEqual(
                    self.markdown_symbols(controller_stdin_surface("apply", argv)),
                    set(),
                )

        rejected = (
            f"python3 -I -S -B <CODEXQB_SKILL_ROOT>/scripts/goal_run.py prepare --root . --stage step2",
            f"{goal} --root . --stage step2",
            f"{goal} prepare --root /tmp/foreign --stage step2",
            f"{goal} prepare --root <other-root> --stage step2",
            f"{goal} prepare --root . --stage step2 --replace",
            f"{goal} prepare --root . --stage step2 --allow-commit",
            f"{goal} validate --root . --goal-run /tmp/foreign/Goal-Run.json",
            f"{goal} render --goal-run <goal-run> --root .",
            f"{apply} prepare --root . --mode subagent_serial",
            f"{apply} init --root . --mode subagent_serial",
            f"{apply} prepare --root /tmp/foreign --mode direct",
            f"{apply} prepare --root . --mode direct --allow-non-git-unsafe",
            f"{apply} prepare --root . --mode direct --allow-unverified-git-worktree",
            f"{apply} prepare --root . --mode direct --output-dir <run-dir> --resume",
            f"{apply} validate --root . --run-dir /tmp/foreign",
            f"{apply} validate --root . --run-dir <other-run-dir>",
            f"{apply} validate --run-dir <run-dir> --root .",
            f"{apply} destroy --root . --run-dir <run-dir> --yes",
            f"{apply} dispatch --root . --run-dir <run-dir> --task-id <task-id> --role task_reviewer --actor controller",
            f"{apply} dispatch --root . --run-dir <run-dir> --task-id <task-id> --role implementer --review-phase spec --actor controller",
            f"{apply} record-agent --root . --run-dir <run-dir> --task-id <task-id> --role task_reviewer --review-phase security --agent-id <agent-id> --status completed --actor controller",
            f"{apply} transition --root . --run-dir <run-dir> --task-id ../other --to VERIFIED --actor controller",
            f"{apply} normalize-writer --root . --run-dir <run-dir> --task-id <task-id> --role fixer --agent-id <agent-id> --report-json '{{\"status\":\"DONE\",\"task_id\":\"<task-id>\",\"fixer_agent_id\":\"<agent-id>\",\"fixes\":[\"not-a-fix-object\"]}}' --actor controller",
            f"{apply} normalize-writer --root . --run-dir <run-dir> --task-id <task-id> --role implementer --agent-id <agent-id> --report-json '{{\"status\":\"DONE_WITH_CONCERNS\",\"task_id\":\"<task-id>\",\"implementer_agent_id\":\"<agent-id>\",\"files_changed\":[\"src/example.py\"],\"concerns\":[\"follow-up required\"]}}' --actor controller",
            f"{apply} normalize-writer --root . --run-dir <run-dir> --task-id <task-id> --role implementer --agent-id <agent-id> --report-json '{{\"status\":\"DONE\",\"task_id\":\"<task-id>\",\"implementer_agent_id\":\"<agent-id>\",\"files_changed\":[\"../outside\"],\"concerns\":[]}}' --actor controller",
            f"{apply} normalize-writer --root . --run-dir <run-dir> --task-id <task-id> --role implementer --agent-id <agent-id> --report-json '{{\"status\":\"DONE\",\"task_id\":\"<task-id>\",\"implementer_agent_id\":\"<agent-id>\",\"files_changed\":[\"src/$PROJECT.py\"],\"concerns\":[]}}' --actor controller",
            f"{apply} normalize-review --root . --run-dir <run-dir> --task-id <task-id> --review-phase spec --agent-id <agent-id> --report-json '{{\"status\":\"COMPLETE\",\"phase\":\"spec\",\"verdict\":\"pass\",\"task_id\":\"<task-id>\",\"reviewer_agent_id\":\"<agent-id>\",\"evidence\":[\"ok\"],\"approval\":true}}' --actor controller",
            f"{apply} normalize-review --root . --run-dir <run-dir> --task-id <task-id> --review-phase spec --agent-id <agent-id> --report-json '{{\"status\":\"COMPLETE\",\"phase\":\"spec\",\"verdict\":\"pass\",\"task_id\":\"<task-id>\",\"reviewer_agent_id\":\"<agent-id>\",\"evidence\":[\"$OPENAI_API_KEY\"]}}' --actor controller",
            f"{apply} run-validation --root . --run-dir <run-dir> --task-id <task-id> --validation-id ../../command --actor controller",
            f"{apply} finalize --root . --run-dir <run-dir> --actor controller --evidence approved",
            "python3 -I -S -B scripts/apply_run.py prepare --root . --mode subagent_serial",
            "python3 plugins/codexqb/skills/codexqb/scripts/goal_run.py prepare --root . --stage step2",
            "scripts/apply_run.py prepare --root . --mode subagent_serial",
            "python3 -S -I -B scripts/apply_run.py prepare --root . --mode subagent_serial",
            f"{request_stdin_command('apply')} --root .",
            f"{request_stdin_command('apply')} --report-json '{{}}'",
        )
        for command in rejected:
            with self.subTest(command=command):
                self.assertIn("raw_repository_command", self.markdown_symbols(command))

    def test_controller_argv_provenance_unicode_json_and_actor_regressions(self) -> None:
        apply_path = "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py"
        apply = launcher_command("apply")
        smuggled_quote = (
            f"python3 -I -S -B {apply_path} --active-skill-md "
            f'"<CODEXQB_SKILL_ROOT>/SKILL.md" --controller apply -- normalize-review --root . '
            "--run-dir <run-dir> --task-id <task-id> --review-phase spec "
            "--agent-id <agent-id> --report-json "
            f"'{{\"status\":\"COMPLETE\",\"phase\":\"spec\","
            "\"verdict\":\"pass\",\"task_id\":\"<task-id>\","
            "\"reviewer_agent_id\":\"<agent-id>\","
            f"\"evidence\":[\"{apply_path}\"]}}' --actor controller"
        )
        self.assertIn("raw_repository_command", self.markdown_symbols(smuggled_quote))

        unsafe_characters = (
            "\u0085",
            "\u0090",
            "\u009b",
            "\u200e",
            "\u2065",
            "\u034f",
            *(chr(codepoint) for codepoint in range(0xFFF0, 0xFFF9)),
        )
        for character in unsafe_characters:
            command = (
                f"{launcher_command('goal')} prepare --root . "
                f"--stage step{character}2"
            )
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                self.assertIn(
                    "unsafe_reference_controls",
                    self.markdown_symbols(command),
                )

        duplicate_key_report = (
            "'{\"status\":\"DONE\",\"status\":\"DONE\","
            "\"task_id\":\"<task-id>\","
            "\"implementer_agent_id\":\"<agent-id>\","
            "\"files_changed\":[\"src/example.py\"],\"concerns\":[]}'"
        )
        duplicate_command = (
            f"{apply} normalize-writer --root . --run-dir <run-dir> "
            "--task-id <task-id> --role implementer --agent-id <agent-id> "
            f"--report-json {duplicate_key_report} --actor controller"
        )
        self.assertIn(
            "raw_repository_command",
            self.markdown_symbols(duplicate_command),
        )

        writer_report = (
            "'{\"status\":\"DONE\",\"task_id\":\"<task-id>\","
            "\"implementer_agent_id\":\"<agent-id>\","
            "\"files_changed\":[\"src/example.py\"],\"concerns\":[]}'"
        )
        review_report = (
            "'{\"status\":\"COMPLETE\",\"phase\":\"spec\","
            "\"verdict\":\"pass\",\"task_id\":\"<task-id>\","
            "\"reviewer_agent_id\":\"<agent-id>\","
            "\"evidence\":[\"reviewed current patch\"]}'"
        )
        controller_owned_with_agent_actor = (
            f"{apply} dispatch --root . --run-dir <run-dir> --task-id <task-id> --role implementer --actor <agent-id>",
            f"{apply} record-agent --root . --run-dir <run-dir> --task-id <task-id> --role implementer --agent-id <agent-id> --status completed --actor <agent-id>",
            f"{apply} normalize-writer --root . --run-dir <run-dir> --task-id <task-id> --role implementer --agent-id <agent-id> --report-json {writer_report} --actor <agent-id>",
            f"{apply} normalize-review --root . --run-dir <run-dir> --task-id <task-id> --review-phase spec --agent-id <agent-id> --report-json {review_report} --actor <agent-id>",
            f"{apply} capture-evidence --root . --run-dir <run-dir> --task-id <task-id> --actor <agent-id>",
            f"{apply} run-validation --root . --run-dir <run-dir> --task-id <task-id> --validation-id VAL-01 --actor <agent-id>",
            f"{apply} publish-review --root . --run-dir <run-dir> --task-id <task-id> --review-phase spec --actor <agent-id>",
            f"{apply} recover-lock --root . --run-dir <run-dir> --task-id <task-id> --to BLOCKED --actor <agent-id>",
            f"{apply} finalize --root . --run-dir <run-dir> --actor <agent-id>",
        )
        for command in controller_owned_with_agent_actor:
            with self.subTest(command=command):
                self.assertIn(
                    "raw_repository_command",
                    self.markdown_symbols(command),
                )

        attributed_transition = controller_stdin_surface(
            "apply",
            [
                "transition",
                "--root",
                ".",
                "--run-dir",
                "<run-dir>",
                "--task-id",
                "<task-id>",
                "--to",
                "IMPLEMENTED",
                "--actor",
                "<agent-id>",
            ],
        )
        self.assertEqual(self.markdown_symbols(attributed_transition), set())

    def test_facade_quote_and_report_whitespace_regressions(self) -> None:
        facade_path = "<CODEXQB_SKILL_ROOT>/scripts/repository_io.py"
        facade_quote_laundering = (
            f"python3 -I -S -B {facade_path} --root . read-model "
            f'--path "{facade_path}"'
        )
        self.assertIn(
            "invalid_repository_io_command",
            self.markdown_symbols(facade_quote_laundering),
        )

        repository_path_as_json_data = (
            "{\"status\":\"COMPLETE\",\"phase\":\"spec\","
            "\"verdict\":\"pass\",\"task_id\":\"<task-id>\","
            "\"reviewer_agent_id\":\"<agent-id>\","
            "\"evidence\":[\"reviewed scripts/repository_io.py\"]}"
        )
        self.assertEqual(
            self.markdown_symbols(
                controller_stdin_surface(
                    "apply",
                    [
                        "normalize-review",
                        "--root",
                        ".",
                        "--run-dir",
                        "<run-dir>",
                        "--task-id",
                        "<task-id>",
                        "--review-phase",
                        "spec",
                        "--agent-id",
                        "<agent-id>",
                        "--report-json",
                        repository_path_as_json_data,
                        "--actor",
                        "controller",
                    ],
                )
            ),
            set(),
        )

        for changed_path in (" src/example.py", "src/example.py ", "src/example.py\u00a0"):
            report = json.dumps(
                {
                    "status": "DONE",
                    "task_id": "<task-id>",
                    "implementer_agent_id": "<agent-id>",
                    "files_changed": [changed_path],
                    "concerns": [],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            command = controller_stdin_surface(
                "apply",
                [
                    "normalize-writer",
                    "--root",
                    ".",
                    "--run-dir",
                    "<run-dir>",
                    "--task-id",
                    "<task-id>",
                    "--role",
                    "implementer",
                    "--agent-id",
                    "<agent-id>",
                    "--report-json",
                    report,
                    "--actor",
                    "controller",
                ],
            )
            with self.subTest(changed_path=repr(changed_path)):
                self.assertIn(
                    "controller_stdin_request_invalid",
                    self.markdown_symbols(command),
                )

    def test_request_stdin_keeps_dynamic_json_data_out_of_shell_text(self) -> None:
        repository = request_stdin_command("repository-io")
        apply = request_stdin_command("apply")
        data_with_shell_like_text = controller_stdin_surface(
            "repository-io",
            ["--root", ".", "read-model", "--path", "docs/My Plan.md"],
        )
        body_with_shell_like_text = controller_stdin_surface(
            "repository-io",
            [
                "--root",
                ".",
                "write-planner",
                "--stage",
                "step1",
                "--path",
                "<allowed-path>",
                "--expected-missing",
            ],
            body='Literal data: $(not-run); `not-run`; "quoted value" with spaces.',
        )
        multiline_body = controller_stdin_surface(
            "repository-io",
            [
                "--root",
                ".",
                "write-planner",
                "--stage",
                "step1",
                "--path",
                "Planner-docs/Main-Planing.md",
                "--expected-missing",
            ],
            body="# Heading\n\nBody with\ttab.\r\n",
        )
        for surface in (
            data_with_shell_like_text,
            body_with_shell_like_text,
            multiline_body,
        ):
            with self.subTest(data=surface[-80:]):
                self.assertEqual(self.markdown_symbols(surface), set())

        materialized_shell = (
            f'{repository} "docs/My Plan.md"',
            f"{repository} 'docs/My Plan.md'",
            f'{repository} "unterminated',
            f"{repository} $(printf injected)",
            f"{repository} `printf injected`",
            f"{repository}; cat README.md",
            f"{repository} --path <repository-relative-path>",
            f"{apply} --report-json '{{}}'",
            f"{repository} < /tmp/request.json",
            f"{repository} <<'JSON'",
            f"echo '{{}}' | {repository}",
            f"printf '%s' '{{}}' | {apply}",
            f"env REQUEST='{{}}' {repository}",
            f"REQUEST='{{}}' {apply}",
            f"{repository} /tmp/controller-request.json",
        )
        for command in materialized_shell:
            with self.subTest(command=command):
                self.assertTrue(
                    {
                        "raw_repository_command",
                        "invalid_repository_io_command",
                    }
                    & self.markdown_symbols(command)
                )

        for tail in (
            "&& cat README.md",
            "; cat README.md",
            "| grep x",
            "--path README.md",
            "with --report-json {}",
            "/tmp/request.json",
            "< /tmp/request.json",
        ):
            for prefix in ("Run", "Please run", "You must run", "Now execute", "Then run"):
                command = f"{prefix} `{repository}` {tail}"
                with self.subTest(imperative_tail=tail, prefix=prefix):
                    self.assertTrue(
                        {
                            "raw_repository_command",
                            "invalid_repository_io_command",
                        }
                        & self.markdown_symbols(command)
                    )

        canonicalization_laundering = (
            repository.replace('"', "&quot;"),
            repository.replace('"', "&#34;"),
            repository.replace("python3 -I", "python3\u00a0-I"),
            repository.replace("python3 -I", "python3\u2003-I"),
            f"\u00a0{repository}",
            f"{repository}\u2003",
            repository.replace('"', "\uff02"),
            f"<span>{repository}</span>",
            f"> {repository}",
            f"- {repository}",
            f"$ {repository}",
        )
        for command in canonicalization_laundering:
            for surface in (
                f"```bash\n{command}\n```",
                f"```text\n{command}\n```",
                f"```python\n{command}\n```",
                f"    {command}",
                f"\t{command}",
                f"Run `{command}`.",
            ):
                with self.subTest(canonicalized=command[:30], surface=surface[:8]):
                    self.assertTrue(
                        {
                            "raw_repository_command",
                            "invalid_repository_io_command",
                        }
                        & self.markdown_symbols(surface)
                    )

        request = {
            "schema": "codexqb.controller-argv/v1",
            "argv": ["--root", ".", "inspect", "--profile", "intake"],
        }
        encoded = json.dumps(request, indent=2)
        ambiguous = (
            f"```bash\n{encoded}\n```",
            encoded,
            f"`{json.dumps(request, separators=(',', ':'))}`",
            "```json\n"
            + json.dumps({**request, "command": "cat README.md"}, indent=2)
            + "\n```",
            "```json\n"
            + '{"schema":"codexqb.controller-argv/v1","schema":"duplicate","argv":[]}'
            + "\n```",
            "```json\n"
            + json.dumps(
                {
                    "schema": "codexqb.controller-argv/v1",
                    "argv": ["python3", "-c", "print(1)"],
                },
                indent=2,
            )
            + "\n```",
        )
        for surface in ambiguous:
            with self.subTest(ambiguous=surface[:40]):
                self.assertTrue(
                    {
                        "controller_stdin_request_invalid",
                        "raw_repository_command",
                    }
                    & self.markdown_symbols(surface)
                )

        multiline_argv_ambiguity = (
            "```json\n"
            '{"schema":"codexqb.controller-argv\\u002fv1","argv":[\n'
            '  "python3",\n  "-c",\n  "print(1)"\n]}\n```',
            "```json\n"
            '{"schema":"wrong","argv":[\n'
            '  "python3",\n  "-c",\n  "print(1)"\n]}\n```',
            "```json\n"
            '{"argv":[\n  "python3",\n  "-c",\n  "print(1)"\n]}\n```',
            "```json\n"
            '{"schema":"codexqb.controller-argv/v2","argv":'
            '["--root",".","inspect","--profile","intake"]}\n```',
            "```json\n"
            '{"schema":"codexqb.controller-argv/v1","argv":[\n'
            '  "--root",\n  ".",\n  "inspect"\n]\n```',
            "```json\n{\n"
            '  "argv": ["cat", "README.md"],\n'
            f'  "argv": {json.dumps(repository)}\n'
            "}\n```",
            "```json\n"
            '{"arg\\u0076":[\n  "cat",\n  "README.md"\n]\n```',
            "```json\n"
            '{"ARGV":[\n  "cat",\n  "README.md"\n]\n```',
            "```json\n"
            "{'argv':[\n  'cat',\n  'README.md'\n]}\n```",
            "```json\n{\n  \"argv\": [\"cat\", \"README.md\"]",
            "```json\n"
            + "[" * 1000
            + '{"argv":["cat","README.md"]}'
            + "]" * 1000
            + "\n```",
            "```json\n{\"argv\":[\"cat\",\"README.md\"],\"x\":"
            + "9" * 5000
            + "}\n```",
        )
        for surface in multiline_argv_ambiguity:
            with self.subTest(multiline=surface[:60]):
                self.assertTrue(
                    {
                        "controller_stdin_request_invalid",
                        "raw_repository_command",
                    }
                    & self.markdown_symbols(surface)
                )

        wrong_body_binding = (
            controller_stdin_surface(
                "repository-io",
                ["--root", ".", "read-model", "--path", "README.md"],
                body="read requests cannot carry a body",
            ),
            controller_stdin_surface(
                "repository-io",
                [
                    "--root",
                    ".",
                    "write-planner",
                    "--stage",
                    "step1",
                    "--path",
                    "Planner-docs/Main-Planing.md",
                    "--expected-missing",
                ],
            ),
            controller_stdin_surface(
                "apply",
                ["prepare", "--root", ".", "--mode", "subagent_serial"],
                body="apply requests cannot carry a body",
            ),
            controller_stdin_surface(
                "repository-io",
                [
                    "--root",
                    ".",
                    "read-model",
                    "--path",
                    "request-stdin",
                ],
            ),
        )
        for surface in wrong_body_binding:
            with self.subTest(binding=surface[-100:]):
                self.assertIn(
                    "controller_stdin_request_invalid",
                    self.markdown_symbols(surface),
                )

        for character in ("\u2060", "\u202e", "\u034f"):
            command = repository.replace("request-stdin", f"request{character}-stdin")
            data = controller_stdin_surface(
                "repository-io",
                ["--root", ".", "read-model", "--path", f"README{character}.md"],
            )
            with self.subTest(codepoint=f"U+{ord(character):04X}"):
                self.assertIn("unsafe_reference_controls", self.markdown_symbols(command))
                self.assertIn("unsafe_reference_controls", self.markdown_symbols(data))

        escaped_surrogate = (
            '```json\n{"schema":"codexqb.controller-argv/v1",'
            '"argv":["--root",".","read-model","--path",'
            '"README\\ud800.md"]}\n```'
        )
        self.assertIn(
            "controller_stdin_request_invalid",
            self.markdown_symbols(escaped_surrogate),
        )

        for evidence in ("   ", "\u00a0"):
            report = json.dumps(
                {
                    "status": "COMPLETE",
                    "phase": "spec",
                    "verdict": "pass",
                    "task_id": "<task-id>",
                    "reviewer_agent_id": "<agent-id>",
                    "evidence": [evidence],
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            command = controller_stdin_surface(
                "apply",
                [
                    "normalize-review",
                    "--root",
                    ".",
                    "--run-dir",
                    "<run-dir>",
                    "--task-id",
                    "<task-id>",
                    "--review-phase",
                    "spec",
                    "--agent-id",
                    "<agent-id>",
                    "--report-json",
                    report,
                    "--actor",
                    "controller",
                ],
            )
            with self.subTest(evidence=repr(evidence)):
                self.assertIn(
                    "controller_stdin_request_invalid",
                    self.markdown_symbols(command),
                )

    def test_current_model_controller_command_inventory_uses_exact_grammar(self) -> None:
        source = (SKILL_ROOT / "references/apply-orchestrator.md").read_text(
            encoding="utf-8"
        )
        commands = [
            line
            for line in source.splitlines()
            if line.startswith("python3 ")
            and "--controller apply --" in line
        ]
        self.assertEqual(len(commands), 10)
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(command, request_stdin_command("apply"))
                self.assertEqual(self.markdown_symbols(command), set())
        self.assertEqual(
            source.count('"schema":"codexqb.controller-argv/v1"'),
            10,
        )
        self.assertEqual(
            {
                finding.symbol
                for finding in POLICY.scan_markdown(
                    "references/apply-orchestrator.md",
                    source,
                )
            }
            & {
                "controller_stdin_request_invalid",
                "raw_repository_command",
                "invalid_repository_io_command",
                "repository_io_command_required",
                "unsafe_reference_controls",
            },
            set(),
        )

    def test_skill_activation_requires_literal_codexqb_invocation(self) -> None:
        source = (SKILL_ROOT / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("Activation is explicit-only.", source)
        self.assertIn("explicitly invokes `$codexqb`", source)
        self.assertIn("allow_implicit_invocation: false", source)
        self.assertNotIn("Interface selection", source)
        self.assertIn(
            "Every loader-provided absolute path component must match ASCII "
            "`[A-Za-z0-9._-]+`; paths containing spaces, shell metacharacters, "
            "controls/default-ignorables/bidi, backslash, or non-ASCII are "
            "unsupported and must BLOCK before launch.",
            source,
        )

    def test_all_planner_and_handoff_commands_use_portable_launcher(self) -> None:
        surfaces = [SKILL_ROOT / "SKILL.md", *sorted((SKILL_ROOT / "references").rglob("*.md"))]
        exact_prefix = (
            'python3 -I -S -B "<CODEXQB_SKILL_ROOT>/scripts/skill_launcher.py" '
            '--active-skill-md "<CODEXQB_SKILL_ROOT>/SKILL.md" --controller '
        )
        direct_controller = re.compile(
            r"(?:repository_io|validate_planner_docs|goal_run|apply_run|doctor)\.py"
            r"`?\s+(?:--|inspect|search|read-model|write-planner|prepare|validate|"
            r"render|dispatch|record-agent|normalize-writer|normalize-review|"
            r"transition|capture-evidence|run-validation|publish-review|reconcile|"
            r"recover-lock|finalize)\b"
        )
        command_finding_symbols = {
            "controller_stdin_request_invalid",
            "raw_repository_command",
            "invalid_repository_io_command",
            "repository_io_command_required",
            "unsafe_reference_controls",
        }
        command_count = 0
        for surface in surfaces:
            relative = surface.relative_to(SKILL_ROOT).as_posix()
            source = surface.read_text(encoding="utf-8")
            with self.subTest(surface=relative):
                self.assertIsNone(direct_controller.search(source))
                for line in source.splitlines():
                    if "python3 -I -S -B" not in line:
                        continue
                    command_count += 1
                    self.assertIn(exact_prefix, line)
                    stripped = line.strip()
                    if "--controller repository-io --" in stripped:
                        self.assertEqual(
                            stripped,
                            request_stdin_command("repository-io"),
                        )
                    if "--controller apply --" in stripped:
                        self.assertEqual(
                            stripped,
                            request_stdin_command("apply"),
                        )
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_markdown(relative, source)
                }
                self.assertFalse(symbols & command_finding_symbols, symbols)
        self.assertGreater(command_count, 30)

    def test_reference_json_and_yaml_are_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            skill = Path(temp_dir) / "skills/codexqb"
            scripts = skill / "scripts"
            references = skill / "references"
            scripts.mkdir(parents=True)
            references.mkdir()
            (skill / "SKILL.md").write_text("---\nname: codexqb\n---\n", encoding="utf-8")
            for relative in POLICY.REQUIRED_RUNTIME:
                name = Path(relative).name
                (scripts / name).write_bytes((SKILL_ROOT / relative).read_bytes())
            for relative in POLICY.PROTECTED_PYTHON:
                (scripts / Path(relative).name).write_text("value = 1\n", encoding="utf-8")
            (references / "tool.json").write_text(
                '{"tool":"shell","command":"cat README.md"}\n', encoding="utf-8"
            )
            (references / "flow.yaml").write_text(
                'command: "git show HEAD:README.md"\n', encoding="utf-8"
            )
            (references / "extension.unknown").write_text(
                "busybox cat README.md\n", encoding="utf-8"
            )
            findings = POLICY.scan_tree(Path(temp_dir))
            paths = {finding.path for finding in findings if finding.symbol == "raw_repository_command"}
            self.assertIn("references/tool.json", paths)
            self.assertIn("references/flow.yaml", paths)
            self.assertIn("references/extension.unknown", paths)

    def test_non_utf8_reference_is_not_skipped(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            skill = Path(temp_dir) / "skills/codexqb"
            scripts = skill / "scripts"
            references = skill / "references"
            scripts.mkdir(parents=True)
            references.mkdir()
            (skill / "SKILL.md").write_text(
                "---\nname: codexqb\n---\n", encoding="utf-8"
            )
            for relative in POLICY.REQUIRED_RUNTIME:
                name = Path(relative).name
                (scripts / name).write_bytes((SKILL_ROOT / relative).read_bytes())
            for relative in POLICY.PROTECTED_PYTHON:
                (scripts / Path(relative).name).write_text(
                    "value = 1\n", encoding="utf-8"
                )
            (references / "opaque.probe").write_bytes(b"\xff\xfe\x00cat README.md")
            findings = POLICY.scan_tree(Path(temp_dir))
            self.assertTrue(
                any(
                    finding.path == "references/opaque.probe"
                    and finding.symbol == "repository_io_non_utf8_text"
                    for finding in findings
                ),
                findings,
            )

    def test_source_owned_runtime_parity_detects_tampered_target_checker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            skill = Path(temp_dir) / "skills/codexqb"
            scripts = skill / "scripts"
            scripts.mkdir(parents=True)
            (skill / "SKILL.md").write_text("---\nname: codexqb\n---\n", encoding="utf-8")
            for relative in POLICY.REQUIRED_RUNTIME:
                name = Path(relative).name
                (scripts / name).write_bytes((SKILL_ROOT / relative).read_bytes())
            with (scripts / "repository_io_policy.py").open("ab") as stream:
                stream.write(b"\n# tampered\n")
            symbols = {
                finding.symbol
                for finding in POLICY.scan_runtime_parity(REPO_ROOT, Path(temp_dir))
            }
            self.assertIn("trusted_runtime_mismatch", symbols)

    def test_skill_discovery_rejects_clean_decoy_and_ambiguous_roots(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for skill in (
                root / "plugins/codexqb/skills/codexqb",
                root / "skills/codexqb",
            ):
                (skill / "scripts").mkdir(parents=True)
                (skill / "SKILL.md").write_text(
                    "---\nname: codexqb\n---\n", encoding="utf-8"
                )
            (root / "skills/codexqb/SKILL.md").write_text(
                "tampered target\n", encoding="utf-8"
            )
            self.assertEqual(
                {finding.symbol for finding in POLICY.scan_tree(root)},
                {"skill_root_ambiguous"},
            )
            self.assertIn(
                "skill_root_ambiguous",
                {
                    finding.symbol
                    for finding in POLICY.scan_runtime_parity(REPO_ROOT, root)
                },
            )

    def test_script_inventory_rejects_shadow_modules_and_bytecode(self) -> None:
        for unexpected in ("json.py", "sitecustomize.py", "__pycache__"):
            with self.subTest(unexpected=unexpected), tempfile.TemporaryDirectory() as temp_dir:
                skill = Path(temp_dir) / "skills/codexqb"
                scripts = skill / "scripts"
                scripts.mkdir(parents=True)
                (skill / "SKILL.md").write_text(
                    "---\nname: codexqb\n---\n", encoding="utf-8"
                )
                for relative in POLICY.REQUIRED_RUNTIME:
                    (scripts / Path(relative).name).write_bytes(
                        (SKILL_ROOT / relative).read_bytes()
                    )
                target = scripts / unexpected
                if unexpected == "__pycache__":
                    target.mkdir()
                    (target / "json.cpython-314.pyc").write_bytes(b"forged")
                else:
                    target.write_text("raise RuntimeError('shadowed')\n", encoding="utf-8")
                findings = POLICY.scan_tree(Path(temp_dir))
                self.assertTrue(
                    any(
                        finding.symbol == "unexpected_script_entry"
                        and finding.path == f"scripts/{unexpected}"
                        for finding in findings
                    ),
                    findings,
                )

    def test_active_agent_and_plugin_metadata_are_policy_surfaces(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / "skills/codexqb"
            scripts = skill / "scripts"
            agents = skill / "agents"
            plugin_dir = root / ".codex-plugin"
            scripts.mkdir(parents=True)
            agents.mkdir()
            plugin_dir.mkdir()
            (skill / "SKILL.md").write_text(
                "---\nname: codexqb\n---\n", encoding="utf-8"
            )
            for relative in POLICY.REQUIRED_RUNTIME:
                (scripts / Path(relative).name).write_bytes(
                    (SKILL_ROOT / relative).read_bytes()
                )
            (agents / "openai.yaml").write_text(
                "interface:\n"
                "  default_prompt: 'Run cat README.md'\n"
                "policy:\n"
                "  allow_implicit_invocation: true\n",
                encoding="utf-8",
            )
            (plugin_dir / "plugin.json").write_text(
                json.dumps(
                    {
                        "skills": "./attacker-skills/",
                        "interface": {"defaultPrompt": ["Run cat README.md"]},
                    }
                ),
                encoding="utf-8",
            )
            symbols = {finding.symbol for finding in POLICY.scan_tree(root)}
            self.assertIn("raw_repository_command", symbols)
            self.assertIn("implicit_invocation_policy_invalid", symbols)
            self.assertIn("plugin_skills_path_invalid", symbols)

    def test_plugin_metadata_is_checked_from_every_supported_root_level(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            repo = Path(temp_dir) / "repo"
            plugin = repo / "plugins/codexqb"
            skill = plugin / "skills/codexqb"
            (skill / "scripts").mkdir(parents=True)
            (skill / "SKILL.md").write_text(
                "---\nname: codexqb\n---\n", encoding="utf-8"
            )
            (plugin / ".codex-plugin").mkdir()
            (plugin / ".codex-plugin/plugin.json").write_text(
                json.dumps(
                    {
                        "skills": "./repointed/",
                        "interface": {"defaultPrompt": ["Use $codexqb."]},
                    }
                ),
                encoding="utf-8",
            )
            for root in (repo, plugin, skill):
                with self.subTest(root=root):
                    self.assertIn(
                        "plugin_skills_path_invalid",
                        {finding.symbol for finding in POLICY.scan_tree(root)},
                    )

    def test_plugin_exported_skills_inventory_rejects_siblings(self) -> None:
        for kind in ("directory", "file", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temp_dir:
                repo = Path(temp_dir) / "repo"
                plugin = repo / "plugins/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    plugin,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                extra = plugin / "skills/evil"
                if kind == "directory":
                    extra.mkdir()
                    (extra / "SKILL.md").write_text(
                        "---\nname: evil\n---\n", encoding="utf-8"
                    )
                elif kind == "file":
                    extra.write_text("unexpected", encoding="utf-8")
                else:
                    outside = Path(temp_dir) / "outside-skill"
                    outside.mkdir()
                    (outside / "SKILL.md").write_text(
                        "---\nname: evil\n---\n", encoding="utf-8"
                    )
                    extra.symlink_to(outside, target_is_directory=True)
                skill = plugin / "skills/codexqb"
                for root in (repo, plugin, skill):
                    self.assertIn(
                        "plugin_skill_inventory_invalid",
                        {finding.symbol for finding in POLICY.scan_tree(root)},
                    )
                self.assertIn(
                    "plugin_skill_inventory_mismatch",
                    {
                        finding.symbol
                        for finding in POLICY.scan_runtime_parity(REPO_ROOT, repo)
                    },
                )

    def test_explicit_plugin_layout_rejects_manifest_and_activation_tampering(self) -> None:
        for kind in ("missing", "symlink", "directory"):
            with self.subTest(manifest_kind=kind), tempfile.TemporaryDirectory() as temp_dir:
                repo = Path(temp_dir) / "repo"
                plugin = repo / "plugins/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    plugin,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                manifest = plugin / ".codex-plugin/plugin.json"
                manifest.unlink()
                if kind == "symlink":
                    outside = Path(temp_dir) / "outside.json"
                    outside.write_text("{}\n", encoding="utf-8")
                    manifest.symlink_to(outside)
                elif kind == "directory":
                    manifest.mkdir()
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_tree(
                        repo, layout=POLICY.LAYOUT_REPOSITORY_PLUGIN
                    )
                }
                self.assertTrue(
                    {"plugin_metadata_missing", "plugin_metadata_not_regular", "plugin_metadata_inventory_invalid"}
                    & symbols,
                    symbols,
                )

        for relative, expected_symbol in (
            (".mcp.json", "plugin_mcp_surface"),
            ("hooks/preflight.json", "plugin_hook_surface"),
            ("skills/codexqb/agents/evil.yaml", "agent_inventory_invalid"),
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp_dir:
                repo = Path(temp_dir) / "repo"
                plugin = repo / "plugins/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    plugin,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                target = plugin / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("{}\n", encoding="utf-8")
                symbols = {
                    finding.symbol
                    for finding in POLICY.scan_tree(
                        repo, layout=POLICY.LAYOUT_REPOSITORY_PLUGIN
                    )
                }
                self.assertIn(expected_symbol, symbols)

    def test_standalone_layout_does_not_infer_plugin_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            container = Path(temp_dir) / "global"
            skill = container / "skills/codexqb"
            shutil.copytree(
                SKILL_ROOT,
                skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            sibling = container / "skills/other"
            sibling.mkdir()
            (sibling / "SKILL.md").write_text("---\nname: other\n---\n", encoding="utf-8")
            for root in (container, skill):
                for layout in (POLICY.LAYOUT_AUTO, POLICY.LAYOUT_STANDALONE_SKILL):
                    findings = POLICY.scan_tree(root, layout=layout)
                    self.assertEqual(findings, [])
            repo = Path(temp_dir) / "repo"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                repo / "plugins/codexqb",
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            (repo / "plugins/codexqb/.mcp.json").write_text("{}\n", encoding="utf-8")
            symbols = {
                finding.symbol
                for finding in POLICY.scan_tree(
                    repo, layout=POLICY.LAYOUT_STANDALONE_SKILL
                )
            }
            self.assertIn("skill_root_missing", symbols)

    def test_policy_checker_does_not_create_import_bytecode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / "skills/codexqb"
            shutil.copytree(
                SKILL_ROOT,
                skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            cache = skill / "scripts/__pycache__"
            self.assertFalse(cache.exists())
            subprocess.run(
                [
                    sys.executable,
                    str(skill / "scripts/repository_io_policy.py"),
                    "--root",
                    str(root),
                ],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertFalse(cache.exists())

    def test_outer_wrapper_never_executes_forged_bootstrap_sources(self) -> None:
        variants = (
            "policy_pyc",
            "helper_pyc",
            "pinned_helper_source",
            "doctor_source",
            "evidence_source",
            "extra_source_shadow",
            "extension_shadow",
            "package_shadow",
            "skill_parent_symlink",
            "policy_symlink",
            "policy_directory",
        )
        for variant in variants:
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                source = copy_checker_source(base)
                scripts = source / "plugins/codexqb/skills/codexqb/scripts"
                marker = base / "bootstrap-executed"
                marker_source = (
                    "from pathlib import Path\n"
                    f"Path({marker.as_posix()!r}).write_text('executed')\n"
                )
                if variant == "policy_pyc":
                    install_unchecked_hash_pyc(scripts / "repository_io_policy.py", marker)
                elif variant == "helper_pyc":
                    install_unchecked_hash_pyc(scripts / "safety_contracts.py", marker)
                elif variant == "pinned_helper_source":
                    helper = scripts / "safety_contracts.py"
                    source_text = helper.read_text(encoding="utf-8")
                    helper.write_text(
                        source_text.replace(
                            "from __future__ import annotations\n",
                            "from __future__ import annotations\n" + marker_source,
                            1,
                        ),
                        encoding="utf-8",
                    )
                elif variant in {"doctor_source", "evidence_source"}:
                    helper = scripts / (
                        "doctor.py"
                        if variant == "doctor_source"
                        else "evidence_contracts.py"
                    )
                    helper.write_text(
                        helper.read_text(encoding="utf-8") + "\n" + marker_source,
                        encoding="utf-8",
                    )
                elif variant == "extra_source_shadow":
                    (scripts / "ctypes.py").write_text(marker_source, encoding="utf-8")
                elif variant == "extension_shadow":
                    (scripts / "repository_io_policy.so").write_text(marker_source, encoding="utf-8")
                elif variant == "package_shadow":
                    package = scripts / "repository_io_policy"
                    package.mkdir()
                    (package / "__init__.py").write_text(marker_source, encoding="utf-8")
                elif variant == "skill_parent_symlink":
                    skills = source / "plugins/codexqb/skills"
                    outside_skills = base / "outside-skills"
                    skills.rename(outside_skills)
                    skills.symlink_to(outside_skills, target_is_directory=True)
                elif variant == "policy_symlink":
                    policy = scripts / "repository_io_policy.py"
                    outside = base / "outside-policy.py"
                    outside.write_text(marker_source, encoding="utf-8")
                    policy.unlink()
                    policy.symlink_to(outside)
                else:
                    policy = scripts / "repository_io_policy.py"
                    policy.unlink()
                    policy.mkdir()
                    (policy / "__init__.py").write_text(marker_source, encoding="utf-8")
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        str(source / "scripts/check_repository_io_policy.py"),
                        "--root",
                        str(source),
                        "--layout",
                        "repository-plugin",
                    ],
                    cwd=source,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertFalse(marker.exists(), (completed.stdout, completed.stderr))

    def test_authoritative_entry_ignores_hostile_python_startup_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            hostile = Path(temp_dir) / "hostile"
            hostile.mkdir()
            marker = Path(temp_dir) / "startup-executed"
            payload = (
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('executed')\n"
            )
            (hostile / "sitecustomize.py").write_text(payload, encoding="utf-8")
            (hostile / "repository_io_policy.py").write_text(payload, encoding="utf-8")
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(hostile)
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(REPO_ROOT),
                    "--layout",
                    "repository-plugin",
                ],
                cwd=REPO_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertFalse(marker.exists(), (completed.stdout, completed.stderr))
            self.assertIn("repository_io_policy=", completed.stdout)

    def test_unisolated_first_process_is_explicitly_unsupported(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            hostile = Path(temp_dir) / "hostile"
            hostile.mkdir()
            marker = Path(temp_dir) / "startup-ran-before-wrapper"
            (hostile / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(hostile)
            completed = subprocess.run(
                [
                    sys.executable,
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(REPO_ROOT),
                    "--layout",
                    "repository-plugin",
                ],
                cwd=REPO_ROOT,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            # This marker proves why a later in-script re-exec could never
            # establish authority.  The unsupported process must fail before
            # the checker emits an authoritative result.
            self.assertTrue(marker.exists())
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("requires_python_-I_-S_-B_first_process", completed.stderr)
            self.assertNotIn("authority=true", completed.stdout)

            missing_flags = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(REPO_ROOT),
                    "--layout",
                    "repository-plugin",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(missing_flags.returncode, 0)
            self.assertIn(
                "requires_python_-I_-S_-B_first_process",
                missing_flags.stderr,
            )
            optimized = subprocess.run(
                [
                    sys.executable,
                    "-O",
                    "-I",
                    "-S",
                    "-B",
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(REPO_ROOT),
                    "--layout",
                    "repository-plugin",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(optimized.returncode, 0)
            self.assertIn(
                "requires_python_-I_-S_-B_first_process",
                optimized.stderr,
            )

    def test_authoritative_target_rejects_forged_cache_and_midscan_mutation(self) -> None:
        runtime_hashes = {
            relative: hashlib.sha256((SKILL_ROOT / relative).read_bytes()).hexdigest()
            for relative in POLICY.REQUIRED_RUNTIME
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "target"
            plugin = root / "plugins/codexqb"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                plugin,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            marker = Path(temp_dir) / "target-cache-executed"
            install_unchecked_hash_pyc(
                plugin / "skills/codexqb/scripts/safety_contracts.py", marker
            )
            findings = POLICY.scan_authoritative_target(
                root,
                runtime_hashes,
                target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
            )
            self.assertIn(
                "authoritative_target_inventory_mismatch",
                {finding.symbol for finding in findings},
            )
            self.assertFalse(marker.exists())
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(root),
                    "--layout",
                    "repository-plugin",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0, completed.stdout)
            self.assertFalse(marker.exists(), (completed.stdout, completed.stderr))

        for relative in (".", "skills/codexqb/scripts"):
            with self.subTest(writable_directory=relative), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir) / "target"
                plugin = root / "plugins/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    plugin,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                target_directory = plugin if relative == "." else plugin / relative
                target_directory.chmod(0o777)
                findings = POLICY.scan_authoritative_target(
                    root,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
                )
                self.assertTrue(findings, findings)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "target"
            plugin = root / "plugins/codexqb"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                plugin,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            original_read = POLICY.controller_read_bytes
            mutated = False

            def mutate_after_last_read(repository, path, *, required=True):
                nonlocal mutated
                result = original_read(repository, path, required=required)
                if (
                    path
                    == "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"
                ):
                    transient = root / ".transient-attestation-entry"
                    transient.write_bytes(b"temporary\n")
                    transient.unlink()
                    mutated = True
                return result

            with mock.patch.object(
                POLICY, "controller_read_bytes", side_effect=mutate_after_last_read
            ):
                findings = POLICY.scan_authoritative_target(
                    root,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
                )
            self.assertTrue(mutated)
            self.assertTrue(findings, findings)

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "target"
            plugin = root / "plugins/codexqb"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                plugin,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            original_read = POLICY.controller_read_bytes
            swapped = False

            def swap_directory_after_last_read(repository, path, *, required=True):
                nonlocal swapped
                result = original_read(repository, path, required=required)
                if (
                    not swapped
                    and path
                    == "plugins/codexqb/skills/codexqb/scripts/validate_planner_docs.py"
                ):
                    agents = plugin / "skills/codexqb/agents"
                    held = Path(temp_dir) / "agents-held"
                    agents.rename(held)
                    shutil.copytree(held, agents)
                    swapped = True
                return result

            with mock.patch.object(
                POLICY,
                "controller_read_bytes",
                side_effect=swap_directory_after_last_read,
            ):
                findings = POLICY.scan_authoritative_target(
                    root,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
                )
            self.assertTrue(swapped)
            self.assertTrue(findings, findings)

    def test_authoritative_target_binds_root_parent_and_skill_chain(self) -> None:
        runtime_hashes = {
            relative: hashlib.sha256((SKILL_ROOT / relative).read_bytes()).hexdigest()
            for relative in POLICY.REQUIRED_RUNTIME
        }
        for variant in ("root", "plugins", "skill"):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                real_root = base / "real-root"
                real_plugin = real_root / "plugins/codexqb"
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb",
                    real_plugin,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                target = real_root
                if variant == "root":
                    target = base / "root-link"
                    target.symlink_to(real_root, target_is_directory=True)
                elif variant == "plugins":
                    external = base / "external-plugins"
                    (real_root / "plugins").rename(external)
                    (real_root / "plugins").symlink_to(
                        external,
                        target_is_directory=True,
                    )
                else:
                    skill = real_plugin / "skills/codexqb"
                    external = base / "external-skill"
                    skill.rename(external)
                    skill.symlink_to(external, target_is_directory=True)
                findings = POLICY.scan_authoritative_target(
                    target,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
                )
                self.assertTrue(findings, findings)

    def test_extracted_authority_binds_manifest_to_pinned_payload(self) -> None:
        runtime_hashes = {
            relative: hashlib.sha256((SKILL_ROOT / relative).read_bytes()).hexdigest()
            for relative in POLICY.REQUIRED_RUNTIME
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            plugin = Path(temp_dir) / "plugin"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                plugin,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            manifest_path = write_authoritative_plugin_manifest(plugin)
            self.assertEqual(
                POLICY.scan_authoritative_target(
                    plugin,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_EXTRACTED_PLUGIN,
                ),
                [],
            )
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            for field in ("package_schema_version", "layout_version", "file_count"):
                with self.subTest(float_field=field):
                    float_manifest = json.loads(json.dumps(manifest))
                    float_manifest[field] = float(float_manifest[field])
                    manifest_path.write_text(
                        json.dumps(float_manifest, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8",
                    )
                    symbols = {
                        finding.symbol
                        for finding in POLICY.scan_authoritative_target(
                            plugin,
                            runtime_hashes,
                            target_layout=POLICY.LAYOUT_EXTRACTED_PLUGIN,
                        )
                    }
                    self.assertIn("authoritative_manifest_invalid", symbols)
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
            self.assertIn(
                "authoritative_manifest_invalid",
                {
                    finding.symbol
                    for finding in POLICY.scan_authoritative_target(
                        plugin,
                        runtime_hashes,
                        target_layout=POLICY.LAYOUT_EXTRACTED_PLUGIN,
                    )
                },
            )
            manifest_path.chmod(0o644)
            manifest["files"][0]["sha256"] = "0" * 64
            encoded = json.dumps(
                manifest["files"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest["tree_sha256"] = hashlib.sha256(encoded).hexdigest()
            manifest["content_sha256"] = manifest["tree_sha256"]
            manifest_path.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            symbols = {
                finding.symbol
                for finding in POLICY.scan_authoritative_target(
                    plugin,
                    runtime_hashes,
                    target_layout=POLICY.LAYOUT_EXTRACTED_PLUGIN,
                )
            }
            self.assertIn("authoritative_manifest_invalid", symbols)

    @unittest.skipUnless(sys.platform == "darwin", "Darwin extended ACL probe")
    def test_authority_rejects_extended_acl_with_safe_mode_bits(self) -> None:
        chmod = shutil.which("chmod")
        if chmod is None:
            self.skipTest("chmod unavailable")
        runtime_hashes = {
            relative: hashlib.sha256((SKILL_ROOT / relative).read_bytes()).hexdigest()
            for relative in POLICY.REQUIRED_RUNTIME
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "target"
            plugin = root / "plugins/codexqb"
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb",
                plugin,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            for protected, acl in (
                (
                    plugin,
                    "everyone allow list,search,add_file,add_subdirectory,delete_child",
                ),
                (
                    plugin / "skills/codexqb/scripts/doctor.py",
                    "everyone allow read,write,append,delete",
                ),
            ):
                with self.subTest(protected=protected):
                    result = subprocess.run(
                        [chmod, "+a", acl, str(protected)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    if result.returncode != 0:
                        self.skipTest("extended ACL creation unavailable")
                    try:
                        findings = POLICY.scan_authoritative_target(
                            root,
                            runtime_hashes,
                            target_layout=POLICY.LAYOUT_REPOSITORY_PLUGIN,
                        )
                        self.assertTrue(findings, findings)
                    finally:
                        subprocess.run(
                            [chmod, "-N", str(protected)],
                            capture_output=True,
                            check=False,
                        )

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            source = copy_checker_source(base)
            protected = source / "plugins/codexqb"
            result = subprocess.run(
                [
                    chmod,
                    "+a",
                    "everyone allow list,search,add_file,add_subdirectory,delete_child",
                    str(protected),
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if result.returncode != 0:
                self.skipTest("extended ACL creation unavailable")
            try:
                completed = subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        "-S",
                        "-B",
                        str(source / "scripts/check_repository_io_policy.py"),
                        "--root",
                        str(source),
                        "--layout",
                        "repository-plugin",
                    ],
                    cwd=source,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertNotEqual(completed.returncode, 0, completed.stdout)
                self.assertNotIn("authority=true", completed.stdout)
            finally:
                subprocess.run(
                    [chmod, "-N", str(protected)],
                    capture_output=True,
                    check=False,
                )

    def test_validate_entry_isolates_every_python_startup(self) -> None:
        validate = (REPO_ROOT / "scripts/validate.sh").read_text(encoding="utf-8")
        python_lines = [
            line.strip()
            for line in validate.splitlines()
            if "python3" in line and not line.lstrip().startswith("#")
        ]
        self.assertTrue(python_lines)
        self.assertTrue(
            all("python3 -I -S -B" in line for line in python_lines),
            python_lines,
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            hostile = base / "hostile"
            hostile.mkdir()
            marker = base / "validate-startup-executed"
            payload = (
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('executed')\n"
            )
            (hostile / "sitecustomize.py").write_text(payload, encoding="utf-8")
            repo = base / "repo"
            shutil.copytree(
                REPO_ROOT,
                repo,
                ignore=shutil.ignore_patterns(
                    ".git", "__pycache__", "*.pyc", "*.pyo", "artifacts", "build", "dist"
                ),
            )
            (repo / "sitecustomize.py").write_text(payload, encoding="utf-8")
            (repo / "scripts/sitecustomize.py").write_text(payload, encoding="utf-8")
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
            subprocess.run(["git", "add", "."], cwd=repo, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=CodexQB Test",
                    "-c",
                    "user.email=codexqb@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=repo,
                check=True,
            )
            environment = dict(os.environ)
            environment["PYTHONPATH"] = str(hostile)
            environment["CODEXQB_VALIDATE_SKIP_UNITTESTS"] = "1"
            completed = subprocess.run(
                ["bash", "scripts/validate.sh", "static"],
                cwd=repo,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertFalse(marker.exists(), (completed.stdout, completed.stderr))
            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_protected_clis_require_isolated_first_process_before_imports(self) -> None:
        controllers = (
            "repository_io.py",
            "validate_planner_docs.py",
            "goal_run.py",
            "apply_run.py",
            "doctor.py",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            hostile = base / "hostile"
            hostile.mkdir()
            site_marker = base / "sitecustomize-executed"
            argparse_marker = base / "argparse-shadow-executed"
            (hostile / "sitecustomize.py").write_text(
                "from pathlib import Path\n"
                f"Path({site_marker.as_posix()!r}).write_text('executed')\n",
                encoding="utf-8",
            )
            (hostile / "argparse.py").write_text(
                "from pathlib import Path\n"
                f"Path({argparse_marker.as_posix()!r}).write_text('executed')\n"
                "raise RuntimeError('hostile argparse imported')\n",
                encoding="utf-8",
            )
            environment = {**os.environ, "PYTHONPATH": hostile.as_posix()}

            positive = subprocess.run(
                [sys.executable, "-c", "pass"],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(positive.returncode, 0, positive.stderr)
            self.assertTrue(site_marker.is_file(), "sitecustomize positive control failed")
            site_marker.unlink()

            project = base / "project"
            project.mkdir()
            for name in controllers:
                script = SKILL_ROOT / "scripts" / name
                isolated = subprocess.run(
                    [sys.executable, "-I", "-S", "-B", str(script), "--help"],
                    cwd=project,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(isolated.returncode, 2, name)
                self.assertEqual(isolated.stdout, "", name)
                self.assertEqual(
                    isolated.stderr,
                    "codexqb_controller=unsupported "
                    "reason=launcher_admission_required\n",
                    name,
                )
                self.assertFalse(site_marker.exists(), name)
                self.assertFalse(argparse_marker.exists(), name)

                direct = subprocess.run(
                    [sys.executable, str(script), "--help"],
                    cwd=project,
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(direct.returncode, 2, name)
                self.assertIn("requires_python_-I_-S_-B_first_process", direct.stderr)
                self.assertTrue(site_marker.is_file(), name)
                self.assertFalse(argparse_marker.exists(), name)
                site_marker.unlink()

            internal_validator = SKILL_ROOT / "scripts/repository_validation.py"
            isolated_validator = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(internal_validator),
                    "--help",
                ],
                cwd=project,
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(
                isolated_validator.returncode,
                0,
                isolated_validator.stdout + isolated_validator.stderr,
            )
            self.assertFalse(site_marker.exists())
            self.assertFalse(argparse_marker.exists())

            self.assertFalse((project / "Planner-docs/Goal-Runs").exists())
            self.assertFalse((project / ".codexqb/apply-runs").exists())

    def test_runtime_parity_covers_agent_and_plugin_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / "skills/codexqb"
            scripts = skill / "scripts"
            agents = skill / "agents"
            plugin_dir = root / ".codex-plugin"
            scripts.mkdir(parents=True)
            agents.mkdir()
            plugin_dir.mkdir()
            (skill / "SKILL.md").write_bytes((SKILL_ROOT / "SKILL.md").read_bytes())
            for relative in POLICY.REQUIRED_RUNTIME:
                (scripts / Path(relative).name).write_bytes(
                    (SKILL_ROOT / relative).read_bytes()
                )
            (agents / "openai.yaml").write_bytes(
                (SKILL_ROOT / "agents/openai.yaml").read_bytes()
                + b"\n# target tamper\n"
            )
            (plugin_dir / "plugin.json").write_bytes(
                (REPO_ROOT / "plugins/codexqb/.codex-plugin/plugin.json").read_bytes()
                + b"\n"
            )
            findings = POLICY.scan_runtime_parity(REPO_ROOT, root)
            mismatches = {
                finding.path
                for finding in findings
                if finding.symbol == "trusted_runtime_mismatch"
            }
            self.assertIn("agents/openai.yaml", mismatches)
            self.assertIn(".codex-plugin/plugin.json", mismatches)

    def test_runtime_parity_covers_consumers_and_transitive_helpers(self) -> None:
        for tampered_name in ("goal_run.py", "git_evidence.py", "mount_identity.py"):
            with self.subTest(tampered_name=tampered_name), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                skill = root / "skills/codexqb"
                scripts = skill / "scripts"
                shutil.copytree(
                    SKILL_ROOT,
                    skill,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
                )
                shutil.copytree(
                    REPO_ROOT / "plugins/codexqb/.codex-plugin",
                    root / ".codex-plugin",
                )
                with (scripts / tampered_name).open("ab") as stream:
                    stream.write(b"\n# target-controlled tamper\n")
                findings = POLICY.scan_runtime_parity(REPO_ROOT, root)
                self.assertTrue(
                    any(
                        finding.path == f"scripts/{tampered_name}"
                        and finding.symbol == "trusted_runtime_mismatch"
                        for finding in findings
                    ),
                    findings,
                )

    def test_source_wrapper_never_executes_target_self_checker(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / "skills/codexqb"
            scripts = skill / "scripts"
            shutil.copytree(
                SKILL_ROOT,
                skill,
                ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
            )
            shutil.copytree(
                REPO_ROOT / "plugins/codexqb/.codex-plugin",
                root / ".codex-plugin",
            )
            for relative in POLICY.PROTECTED_PYTHON:
                (scripts / Path(relative).name).write_text("value = 1\n", encoding="utf-8")
            marker = root / "target-checker-executed"
            (scripts / "repository_io_policy.py").write_text(
                "from pathlib import Path\n"
                f"Path({marker.as_posix()!r}).write_text('unsafe')\n",
                encoding="utf-8",
            )
            completed = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(REPO_ROOT / "scripts/check_repository_io_policy.py"),
                    "--root",
                    str(root),
                    "--layout",
                    "extracted-plugin",
                ],
                cwd=REPO_ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("trusted_runtime_mismatch", completed.stdout)
            self.assertFalse(marker.exists())

    def test_policy_finding_redacts_secret_and_control_filenames(self) -> None:
        token = "sk-" + "N" * 40
        finding = POLICY.PolicyFinding(f"references/{token}\n.md", 1, f"probe:{token}\n")
        self.assertNotIn(token, finding.path)
        self.assertNotIn("\n", finding.path)
        self.assertTrue(finding.path.startswith("<redacted-policy-path:"))
        self.assertNotIn(token, finding.symbol)
        self.assertNotIn("\n", finding.symbol)
        self.assertTrue(finding.symbol.startswith("redacted_policy_symbol:"))

    def test_eval_failure_diagnostics_do_not_emit_local_paths(self) -> None:
        private_path = "/" + "Users/" + "private-account/.codex/codexqb-trust/private-run"
        for index, relative in enumerate(
            (
                "evals/run_apply_behavior_smoke.py",
                "evals/run_downstream_goal_apply_dry_run.py",
                "evals/run_goal_apply_metric_checks.py",
            )
        ):
            with self.subTest(relative=relative):
                source = REPO_ROOT / relative
                spec = importlib.util.spec_from_file_location(
                    f"codexqb_eval_log_privacy_{index}",
                    source,
                )
                self.assertIsNotNone(spec)
                self.assertIsNotNone(spec.loader if spec is not None else None)
                module = importlib.util.module_from_spec(spec)
                assert spec is not None and spec.loader is not None
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                output = io.StringIO()
                with redirect_stdout(output), self.assertRaises(SystemExit):
                    module.fail(f"command_failed={private_path}")
                rendered = output.getvalue()
                self.assertNotIn(private_path, rendered)
                self.assertNotIn("private-account", rendered)
                self.assertIn("failed_code=command_failed", rendered)
                self.assertRegex(rendered, r"failed_detail_sha256=[0-9a-f]{64}")
                if relative == "evals/run_apply_behavior_smoke.py":
                    error_digest = module.subprocess_error_digest(
                        f"error={private_path}",
                        "error=controller_request_failed\nerror=second_code",
                    )
                    self.assertRegex(error_digest, r"^[0-9a-f]{64}$")
                    self.assertNotIn("private-account", error_digest)

    def test_test_controller_home_provider_is_outside_plugin_runtime(self) -> None:
        test_helpers = {
            REPO_ROOT / "tests/controller_cli_harness.py",
            REPO_ROOT / "tests/controller_test_support.py",
        }
        for helper in test_helpers:
            self.assertTrue(helper.is_file())
            self.assertFalse(helper.is_relative_to(SKILL_ROOT))
        for source in (SKILL_ROOT / "scripts").glob("*.py"):
            text = source.read_text(encoding="utf-8")
            self.assertNotIn("controller_cli_harness", text, source)
            self.assertNotIn("controller_test_support", text, source)

    def test_missing_packaged_boundary_is_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            skill = root / "skills/codexqb"
            (skill / "scripts").mkdir(parents=True)
            (skill / "references").mkdir()
            (skill / "SKILL.md").write_text("---\nname: codexqb\n---\n", encoding="utf-8")
            symbols = {finding.symbol for finding in POLICY.scan_tree(root)}
            self.assertIn("required_runtime_missing", symbols)


if __name__ == "__main__":
    unittest.main()
