#!/usr/bin/env python3
"""Fail-closed static policy for the CodexQB repository I/O boundary.

The protected controllers may use raw filesystem and process primitives for
their private run/trust-store machinery.  Those exceptional functions are
approved by a digest of their complete AST, never by their name.  Any edit to
an approved body therefore removes the capability until the changed body is
reviewed and its digest is deliberately updated here.
"""

from __future__ import annotations

import os
import sys

# Startup hooks execute before this source begins.  A direct invocation is
# therefore supported only when the complete isolation contract was supplied
# to the first interpreter process; an in-script restart cannot establish it.
if __name__ == "__main__" and not (
    sys.flags.isolated
    and sys.flags.no_site
    and sys.flags.dont_write_bytecode
    and sys.flags.optimize == 0
):
    sys.stderr.write(
        "repository_io_policy=unsupported "
        "reason=requires_python_-I_-S_-B_first_process\n"
    )
    raise SystemExit(2)

import argparse
import ast
from dataclasses import dataclass
import hashlib
import hmac
import html
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from typing import Callable, Iterable, Iterator
import unicodedata

# The source-owned checker must never manufacture an importable cache inside a
# package it is about to approve.  Pre-existing bytecode remains a hard error.
sys.dont_write_bytecode = True
# ``dont_write_bytecode`` does not disable cache reads.  Redirect cache lookup
# below the null device, with a high-entropy suffix, before importing any local
# trust helper.  That location cannot be pre-seeded as a directory, so even an
# unchecked-hash package ``__pycache__`` cannot run before inventory rejects it.
sys.pycache_prefix = os.path.join(
    os.devnull, f"codexqb-policy-{os.urandom(24).hex()}"
)

SCRIPT_DIR = Path(__file__).resolve().parent
_BOOTSTRAP_RUNTIME_NAMES = frozenset(
    {
        "apply_run.py",
        "artifact_io.py",
        "controller_store.py",
        "doctor.py",
        "evidence_contracts.py",
        "execution_controller.py",
        "git_evidence.py",
        "goal_run.py",
        "mount_identity.py",
        "repository_evidence.py",
        "repository_io.py",
        "repository_io_policy.py",
        "repository_validation.py",
        "safety_contracts.py",
        "skill_launcher.py",
        "skill_root_authority.py",
        "validate_planner_docs.py",
    }
)


def _bootstrap_inventory() -> None:
    entries: set[str] = set()
    with os.scandir(SCRIPT_DIR) as iterator:
        for entry in iterator:
            entries.add(entry.name)
            if not entry.is_file(follow_symlinks=False):
                raise RuntimeError("repository_io_policy_bootstrap_inventory_invalid")
    if entries != _BOOTSTRAP_RUNTIME_NAMES:
        raise RuntimeError("repository_io_policy_bootstrap_inventory_invalid")


_bootstrap_inventory()
while str(SCRIPT_DIR) in sys.path:
    sys.path.remove(str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR))

import controller_store as _controller_store_module  # noqa: E402
import repository_io as _repository_io_module  # noqa: E402
import safety_contracts as _safety_contracts_module  # noqa: E402


def _require_local_helper(module: object) -> None:
    origin = getattr(module, "__file__", None)
    if not isinstance(origin, str):
        raise RuntimeError("repository_io_policy_helper_origin_invalid")
    path = Path(origin).resolve(strict=True)
    if path.parent != SCRIPT_DIR or path.suffix != ".py":
        raise RuntimeError("repository_io_policy_helper_origin_invalid")


for _helper_module in (
    _controller_store_module,
    _repository_io_module,
    _safety_contracts_module,
):
    _require_local_helper(_helper_module)

from repository_io import (
    _controller_canonical_root as canonical_repository_root,
    _controller_complete_inventory as controller_complete_inventory,
    _controller_directories as controller_directories,
    _controller_path_kind as controller_path_kind,
    _controller_read_bytes as controller_read_bytes,
    _controller_regular_paths as controller_regular_paths,
    open_repository_io,
)
from safety_contracts import secret_match_locations
from controller_store import (
    CONTROLLER_O_CLOEXEC,
    CONTROLLER_O_DIRECTORY,
    CONTROLLER_O_NOFOLLOW,
    CONTROLLER_O_RDONLY,
    controller_close,
    controller_listdir,
    controller_open,
)


PROTECTED_PYTHON = (
    "scripts/repository_validation.py",
    "scripts/validate_planner_docs.py",
    "scripts/skill_launcher.py",
    "scripts/skill_root_authority.py",
    "scripts/goal_run.py",
    "scripts/apply_run.py",
)
LAYOUT_AUTO = "auto"
LAYOUT_REPOSITORY_PLUGIN = "repository-plugin"
LAYOUT_EXTRACTED_PLUGIN = "extracted-plugin"
LAYOUT_STANDALONE_SKILL = "standalone-skill"
LAYOUT_EXPECTATIONS = frozenset(
    {
        LAYOUT_AUTO,
        LAYOUT_REPOSITORY_PLUGIN,
        LAYOUT_EXTRACTED_PLUGIN,
        LAYOUT_STANDALONE_SKILL,
    }
)
# Future host-isolation controllers must be enrolled one file at a time.  The
# tuple is (reviewed whole-AST SHA-256, exact repository_io private imports).
# An enrolment intentionally changes REQUIRED_RUNTIME and therefore source,
# extracted-package, and installed parity.  Wildcard paths/imports are never
# accepted.  PR4 may add scripts/validation_isolation.py here after review.
_TRUSTED_CONTROLLER_REGISTRY: dict[str, tuple[str, frozenset[str]]] = {}

_CORE_REQUIRED_RUNTIME = (
    "scripts/safety_contracts.py",
    "scripts/artifact_io.py",
    "scripts/evidence_contracts.py",
    "scripts/git_evidence.py",
    "scripts/mount_identity.py",
    "scripts/repository_evidence.py",
    "scripts/repository_io.py",
    "scripts/controller_store.py",
    "scripts/doctor.py",
    "scripts/execution_controller.py",
    "scripts/repository_io_policy.py",
    "scripts/repository_validation.py",
    "scripts/validate_planner_docs.py",
    "scripts/skill_launcher.py",
    "scripts/skill_root_authority.py",
    "scripts/goal_run.py",
    "scripts/apply_run.py",
)
REQUIRED_MODEL_SURFACES = (
    "SKILL.md",
    "agents/openai.yaml",
)
_OPENAI_DEFAULT_PROMPT = (
    "Use $codexqb to start evidence-backed repo planning; guide comprehension, "
    "sub-plans, QA audit, Goal preview, and gated apply handoff."
)
_PLUGIN_DEFAULT_PROMPTS = (
    "Use $codexqb to inspect this repo and create an evidence-backed project comprehension plan.",
    "Use $codexqb to autopsy this project, capture ontology/comprehension evidence, and create phase sub-plans.",
    "Use $codexqb to audit evidence, traceability, readiness, compile a Goal preview, and prepare the gated implementation handoff.",
)
# Exact reviewed bytes are the authoritative extension gate for every
# model-visible surface.  The key set is compared to the descriptor-observed
# corpus on every scan; additions are never learned or baselined implicitly.
_APPROVED_MODEL_SURFACE_SHA256: dict[str, str] = {
    "SKILL.md": "df2375228505d0bcb90e7bab57979579a6ab9be339a7a5abd83a72b1dfef1380",
    "agents/openai.yaml": "d9067cc254017c17d23757a334b47ad623c63a3ceaa24bccbca65c2f041f1a24",
    "references/Autopsy-Planner.md": "d931702c68298ce3d7799a5ad849f66199033a33cd68ae36317e81f4ac5f570a",
    "references/First-Planner.md": "4cca18d46262d10be7d6086411e87a3ad653dd5d751e182b245c60127dab64d8",
    "references/Fourth-Planner.md": "938637aed660df1bd1cc79b878b86a9d835ff7afda21eefda3c6210e8e15cc8c",
    "references/Second-Planner.md": "41da50f6d751f8c85e146438a61381fecfc84513800b327a54c3fc911c3ed080",
    "references/Third-Planner.md": "2f0534bc30c3363caf31dd84421ef7f6ae868c3abd9a6fa15b1c9ff104d95666",
    "references/apply-orchestrator.md": "b779d8d371ac92f557bd96dd46715d4cb3a5e9a1c5ac5061af96aa8909420fa0",
    "references/apply-run-schema.json": "acc1701734f3a485573f01bf40ca644870a16b6ae990237cf196678f431f9946",
    "references/apply/controller.md": "7805a7d2296b634e430a3fadd01eae01debc49e4b7e63087fb4a257b0e8086eb",
    "references/apply/final-reviewer.md": "3bdbdc8336619924dce0541a8358a0f1c4f26db2dfbb2dfa87719c36466c1b83",
    "references/apply/fixer.md": "eec8f1ae50e0e3edf2794d8075ecc511f76a7d2d7906ec01ee37d5b69f89ada1",
    "references/apply/implementer.md": "9dd72e64c4319686a3d6831092542814244b389123c72b34ba407f45fc6a2270",
    "references/apply/security-reviewer.md": "fd0f646f091775099e1fb31837d9ad163c6b85e2f026c1fb5a26628aedac9de2",
    "references/apply/task-reviewer.md": "ef08ab62848e4ed38cdba7804808ae5c32274e83adabb42a58d1b6f9edf38264",
    "references/assessment-and-budget.md": "e7cd590bb9cc93f0219438bb202a57be2f6a05a6440a31b42fef120979479811",
    "references/engineering-principles.md": "8bef9d7a21c17140642a2ed0343715afe1e8946a04965581ae6297c849ed9e56",
    "references/goal-compiler.md": "816fa7544a3966ff1c0601811552715d7a47d0c11b40e1385ddbe5507d69cfa9",
    "references/goal-specs/step15.md": "00cc341eda3dfaaab0704fcc56e4726f6d010e81678ff2e97a6eaa94e7302e09",
    "references/goal-specs/step2.md": "5c54ec11f97f2953d353b5b9613d086ee6219c83fec2a0377f80507a41ef28e6",
    "references/goal-specs/step3.md": "c1c6af73af03f91f9dfbed27efe57eff974759e608121a6ea90a24594b5bbaad",
    "references/goal-specs/step4.md": "864e013c8aa3e1119c738c9d82c925ccf061e74ba54e2fd1c3f2bff2ea8da756",
    "references/handoffs/run-step2.md": "6e424211a3b1a48fd90dbfce3b37bada6f15e425ee2d760e3699ecc0f8065f1e",
    "references/handoffs/run-step3.md": "cc162e88f4ee4e15ecd86638d197fb7662749a992c8fc7cae95cf2d72ca2c124",
    "references/handoffs/run-step4.md": "ac211f6a4ea44966975fc4c6fe7679277f36a35b0c8a74c9dd50f3a64f71c16e",
    "references/planning-ledger.md": "57898331cdfeb3acc9d974514251b84f347b60dceb2158c16acf654b2a31bee3",
    "references/probe-policy.md": "00f8fe98263c504748ab4e4aaae727d87e430ff95e969e1a6bb1e68dc51d81b6",
    "references/project-comprehension-methods.md": "8b9348cf72492f2da2a095d2ef9dccd7a61f7ad428579d5a3326290dc1e26b41",
    "references/project-ontology.md": "c2dbb8d4d3bf2c012856c3dee0580886c7886d6d1c036162a924081df7ccef55",
    "references/repo-aware-intake.md": "a1e6e145e89e5238d4299ef26793482f07336fe78111a3b1a1651a5e1e16ba06",
    "references/subagent-playbook.md": "4f043463f3b39f9f528a7e85bd523392865959b9fbf4895b43cb31e531483523",
    "references/vibecoding-principles.md": "55d344319830cd818cfa0a29b47c3fb76d6ce019dd1dac72fdc5e2fde498145c",
    "references/workflow-quality.md": "854f9a6052ca7938bb7a23f2de308aad266e5300e8436396ec7d85021a4817a2",
}
_APPROVED_PLUGIN_METADATA_SHA256 = (
    "b1bfc5acf8b713d23d3df106c1213796b6dc6cd5935823635d9fde9c8d1fd8b4"
)
REQUIRED_RUNTIME = _CORE_REQUIRED_RUNTIME + tuple(
    sorted(_TRUSTED_CONTROLLER_REGISTRY)
)
_PATH_READ_METHODS = frozenset(
    {
        "open",
        "read_text",
        "read_bytes",
        "stat",
        "lstat",
        "resolve",
        "absolute",
        "exists",
        "is_file",
        "is_dir",
        "is_symlink",
        "is_mount",
        "is_socket",
        "is_fifo",
        "is_block_device",
        "is_char_device",
        "samefile",
        "glob",
        "rglob",
        "iterdir",
        "walk",
        "readlink",
        "cwd",
        "expanduser",
        "group",
        "home",
        "info",
        "is_junction",
        "owner",
    }
)
_PATH_MUTATION_METHODS = frozenset(
    {
        "write_text",
        "write_bytes",
        "unlink",
        "rename",
        "replace",
        "touch",
        "mkdir",
        "rmdir",
        "chmod",
        "lchmod",
        "symlink_to",
        "hardlink_to",
        "link_to",
        "copy",
        "copy_into",
        "move",
        "move_into",
    }
)
_PATH_METHODS = _PATH_READ_METHODS | _PATH_MUTATION_METHODS
_PATH_PRESERVING_METHODS = frozenset(
    {
        "from_uri",
        "joinpath",
        "relative_to",
        "with_name",
        "with_segments",
        "with_stem",
        "with_suffix",
    }
)

_OS_READ_APIS = frozenset(
    {
        "open",
        "fdopen",
        "read",
        "pread",
        "readv",
        "preadv",
        "stat",
        "lstat",
        "fstatat",
        "scandir",
        "listdir",
        "walk",
        "fwalk",
        "readlink",
        "access",
        "getxattr",
        "listxattr",
        "sendfile",
        "copy_file_range",
    }
)
_OS_MUTATION_APIS = frozenset(
    {
        "write",
        "pwrite",
        "writev",
        "pwritev",
        "truncate",
        "ftruncate",
        "unlink",
        "remove",
        "rename",
        "renames",
        "replace",
        "mkdir",
        "makedirs",
        "rmdir",
        "removedirs",
        "symlink",
        "link",
        "chmod",
        "fchmod",
        "lchmod",
        "chown",
        "fchown",
        "lchown",
        "mknod",
        "mkfifo",
        "chdir",
        "utime",
        "setxattr",
        "removexattr",
    }
)
_OS_IO_APIS = _OS_READ_APIS | _OS_MUTATION_APIS
_OS_PROCESS_APIS = frozenset(
    {
        "system",
        "popen",
        "fork",
        "forkpty",
        "posix_spawn",
        "posix_spawnp",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
    }
)
_OS_PATH_APIS = frozenset(
    {
        "exists",
        "lexists",
        "isfile",
        "isdir",
        "islink",
        "ismount",
        "samefile",
        "realpath",
        "getsize",
        "getmtime",
        "getatime",
        "getctime",
    }
)
_GLOB_APIS = frozenset({"glob", "iglob"})
_SHUTIL_APIS = frozenset(
    {
        "copy",
        "copy2",
        "copyfile",
        "copyfileobj",
        "copymode",
        "copystat",
        "copytree",
        "move",
        "rmtree",
        "make_archive",
        "unpack_archive",
        "chown",
    }
)
_DIRECT_IO_CONSTRUCTORS = frozenset(
    {
        "argparse.FileType",
        "bz2.open",
        "codecs.open",
        "gzip.open",
        "io.FileIO",
        "io.BufferedReader",
        "io.BufferedWriter",
        "lzma.open",
        "mmap.mmap",
        "shelve.open",
        "sqlite3.connect",
        "tarfile.open",
        "tempfile.NamedTemporaryFile",
        "tempfile.SpooledTemporaryFile",
        "tempfile.TemporaryDirectory",
        "tempfile.TemporaryFile",
        "tempfile.mkdtemp",
        "tempfile.mkstemp",
        "zipfile.ZipFile",
    }
)
_REPOSITORY_EVIDENCE_IO = frozenset(
    {
        "capture_repository_evidence",
        "read_regular_files_from_anchor",
        "snapshot_allowed_paths",
        "snapshot_git_paths",
        "snapshot_git_paths_from_anchor",
        "snapshot_repository_inventory",
        "snapshot_repository_inventory_from_anchor",
        "open_repository_root_anchor",
        "require_same_repository_mount",
    }
)
_SUBPROCESS_APIS = frozenset(
    {"run", "Popen", "call", "check_call", "check_output", "getoutput", "getstatusoutput"}
)
_ASYNC_PROCESS_APIS = frozenset({"create_subprocess_exec", "create_subprocess_shell"})
_RECEIVER_PROCESS_METHODS = frozenset({"subprocess_exec", "subprocess_shell"})
_OTHER_PROCESS_APIS = frozenset(
    {
        "multiprocessing.Process",
        "multiprocessing.Pool",
        "concurrent.futures.ProcessPoolExecutor",
        "pty.spawn",
        "ctypes.CDLL",
        "ctypes.PyDLL",
    }
)
_DYNAMIC_IMPORT_APIS = frozenset({"import_module", "__import__"})
_DANGEROUS_DYNAMIC_ATTRIBUTES = (
    _PATH_METHODS
    | _OS_IO_APIS
    | _OS_PATH_APIS
    | _GLOB_APIS
    | _SHUTIL_APIS
    | _REPOSITORY_EVIDENCE_IO
    | _SUBPROCESS_APIS
    | _ASYNC_PROCESS_APIS
    | _RECEIVER_PROCESS_METHODS
    | _OS_PROCESS_APIS
    | frozenset(name.rsplit(".", 1)[-1] for name in _DIRECT_IO_CONSTRUCTORS | _OTHER_PROCESS_APIS)
    | frozenset({"renameat2", "renameatx_np"})
)

_MODULE_CANONICAL = frozenset(
    {
        "argparse",
        "asyncio",
        "artifact_io",
        "builtins",
        "bz2",
        "codecs",
        "concurrent",
        "controller_store",
        "ctypes",
        "execution_controller",
        "glob",
        "gzip",
        "importlib",
        "io",
        "lzma",
        "mmap",
        "multiprocessing",
        "operator",
        "os",
        "pathlib",
        "repository_controller",
        "repository_evidence",
        "repository_io",
        "shelve",
        "shutil",
        "sqlite3",
        "subprocess",
        "sys",
        "pty",
        "tarfile",
        "tempfile",
        "zipfile",
    }
)
_LOCAL_BOUNDARY_MODULES = frozenset(
    {
        "artifact_io",
        "controller_store",
        "execution_controller",
        "repository_controller",
        "repository_evidence",
        "repository_io",
    }
)
_PUBLIC_REPOSITORY_METHODS = frozenset(
    {"read_text", "read_many", "list_paths", "search", "write_planner_text"}
)
_REPOSITORY_IO_ALLOWED_IMPORTS = frozenset(
    {
        "ControllerRootProof",
        "PathListing",
        "RepositoryIO",
        "RepositoryIOPolicy",
        "open_repository_io",
    }
)
_REPOSITORY_IO_CONTROLLER_IMPORTS: dict[str, frozenset[str]] = {
    "scripts/repository_validation.py": frozenset(
        {
            "_controller_read_bytes",
            "_controller_validation_inventory",
            "_controller_workspace_proof",
        }
    ),
    "scripts/goal_run.py": frozenset(
        {
            "_controller_canonical_root",
            "_controller_evidence_digest",
            "_controller_inventory",
            "_controller_path_kind",
            "_controller_read_bytes",
            "_controller_regular_paths",
            "_controller_workspace_proof",
        }
    ),
    "scripts/apply_run.py": frozenset(
        {
            "_controller_baseline_digest",
            "_controller_canonical_root",
            "_controller_evidence_digest",
            "_controller_evidence_from_snapshots",
            "_controller_inventory",
            "_controller_normalize_path",
            "_controller_read_bytes",
            "_controller_root_proof",
            "_controller_regular_paths",
            "_controller_snapshot_paths",
            "_controller_validation_cwd",
            "_controller_workspace_proof",
        }
    ),
    "scripts/validate_planner_docs.py": frozenset(
        {
            "_controller_canonical_root",
            "_controller_directories",
            "_controller_regular_paths",
        }
    ),
}
_PROTECTED_IMPORT_ROOTS: dict[str, frozenset[str]] = {
    "scripts/repository_validation.py": frozenset(
        {
            "__future__",
            "argparse",
            "hashlib",
            "json",
            "pathlib",
            "re",
            "repository_io",
            "safety_contracts",
            "sys",
        }
    ),
    "scripts/validate_planner_docs.py": frozenset(
        {
            "__future__",
            "argparse",
            "collections",
            "dataclasses",
            "json",
            "pathlib",
            "re",
            "repository_io",
            "safety_contracts",
            "sys",
            "types",
        }
    ),
    "scripts/skill_launcher.py": frozenset(
        {
            "__future__",
            "collections",
            "hashlib",
            "importlib",
            "os",
            "stat",
            "sys",
            "types",
            "typing",
        }
    ),
    "scripts/skill_root_authority.py": frozenset(
        {
            "__future__",
            "contextlib",
            "ctypes",
            "dataclasses",
            "errno",
            "hashlib",
            "os",
            "pathlib",
            "re",
            "stat",
            "sys",
            "types",
            "typing",
        }
    ),
    "scripts/goal_run.py": frozenset(
        {
            "__future__",
            "argparse",
            "collections",
            "contextlib",
            "controller_store",
            "datetime",
            "execution_controller",
            "fnmatch",
            "hashlib",
            "json",
            "pathlib",
            "re",
            "repository_io",
            "safety_contracts",
            "sys",
            "types",
        }
    ),
    "scripts/apply_run.py": frozenset(
        {
            "__future__",
            "argparse",
            "base64",
            "collections",
            "contextlib",
            "controller_store",
            "ctypes",
            "dataclasses",
            "datetime",
            "difflib",
            "errno",
            "evidence_contracts",
            "execution_controller",
            "hashlib",
            "hmac",
            "json",
            "pathlib",
            "re",
            "repository_evidence",
            "repository_io",
            "safety_contracts",
            "secrets",
            "stat",
            "sys",
            "time",
            "types",
        }
    ),
}
# Import roots alone are not a sufficient boundary: an otherwise harmless
# standard-library module can re-export a powerful module (for example
# ``argparse.os``).  Keep the direct-module and stdlib from-import surfaces
# exact per consumer.  Local helper and controller imports are checked by the
# symbol allowlists below.
_PROTECTED_DIRECT_IMPORT_MODULES: dict[str, frozenset[str]] = {
    "scripts/repository_validation.py": frozenset(
        {"argparse", "hashlib", "json", "re", "sys"}
    ),
    "scripts/validate_planner_docs.py": frozenset(
        {"argparse", "json", "re", "sys"}
    ),
    "scripts/skill_launcher.py": frozenset(
        {"hashlib", "importlib.abc", "importlib.util", "os", "stat", "sys"}
    ),
    "scripts/skill_root_authority.py": frozenset(
        {"ctypes", "errno", "hashlib", "os", "re", "stat", "sys"}
    ),
    "scripts/goal_run.py": frozenset(
        {"argparse", "fnmatch", "hashlib", "json", "re", "sys"}
    ),
    "scripts/apply_run.py": frozenset(
        {
            "argparse",
            "base64",
            "ctypes",
            "difflib",
            "errno",
            "hashlib",
            "hmac",
            "json",
            "re",
            "secrets",
            "stat",
            "sys",
            "time",
        }
    ),
}
_PROTECTED_STDLIB_FROM_IMPORTS: dict[str, dict[str, frozenset[str]]] = {
    "scripts/repository_validation.py": {
        "__future__": frozenset({"annotations"}),
        "pathlib": frozenset({"Path", "PurePosixPath"}),
    },
    "scripts/validate_planner_docs.py": {
        "__future__": frozenset({"annotations"}),
        "collections": frozenset({"defaultdict"}),
        "dataclasses": frozenset({"dataclass", "field"}),
        "pathlib": frozenset({"Path"}),
        "types": frozenset({"ModuleType"}),
    },
    "scripts/skill_launcher.py": {
        "__future__": frozenset({"annotations"}),
        "collections.abc": frozenset({"Mapping"}),
        "types": frozenset({"MappingProxyType", "ModuleType"}),
        "typing": frozenset({"Sequence"}),
    },
    "scripts/skill_root_authority.py": {
        "__future__": frozenset({"annotations"}),
        "contextlib": frozenset({"contextmanager"}),
        "dataclasses": frozenset({"dataclass"}),
        "pathlib": frozenset({"Path"}),
        "types": frozenset({"MappingProxyType", "ModuleType"}),
        "typing": frozenset({"Iterator", "Mapping"}),
    },
    "scripts/goal_run.py": {
        "__future__": frozenset({"annotations"}),
        "collections.abc": frozenset({"Iterator"}),
        "contextlib": frozenset({"contextmanager"}),
        "datetime": frozenset({"datetime", "timezone"}),
        "pathlib": frozenset({"Path"}),
        "types": frozenset({"ModuleType"}),
    },
    "scripts/apply_run.py": {
        "__future__": frozenset({"annotations"}),
        "collections.abc": frozenset({"Iterator"}),
        "contextlib": frozenset({"contextmanager"}),
        "dataclasses": frozenset({"dataclass"}),
        "datetime": frozenset({"datetime", "timezone"}),
        "pathlib": frozenset({"Path"}),
        "types": frozenset({"ModuleType"}),
    },
}
_PROTECTED_DIRECT_MODULE_ATTRIBUTES: dict[str, dict[str, frozenset[str]]] = {
    "scripts/repository_validation.py": {
        "argparse": frozenset({"ArgumentParser", "Namespace"}),
        "hashlib": frozenset({"sha256"}),
        "re": frozenset({"compile"}),
        "sys": frozenset({"argv", "flags", "path", "stderr"}),
    },
    "scripts/validate_planner_docs.py": {
        "argparse": frozenset({"ArgumentParser", "Namespace"}),
        "json": frozenset({"JSONDecodeError", "dumps", "loads"}),
        "re": frozenset(
            {
                "DOTALL",
                "IGNORECASE",
                "MULTILINE",
                "compile",
                "findall",
                "finditer",
                "fullmatch",
                "match",
                "search",
                "split",
                "sub",
            }
        ),
        "sys": frozenset({"argv", "flags", "modules", "path", "stderr"}),
    },
    "scripts/skill_launcher.py": {
        "hashlib": frozenset({"sha256"}),
        "importlib": frozenset({"abc", "machinery", "util"}),
        "importlib.abc": frozenset({"Loader", "MetaPathFinder"}),
        "importlib.machinery": frozenset({"ModuleSpec"}),
        "importlib.util": frozenset({"spec_from_loader"}),
        "os": frozenset(
            {
                "O_DIRECTORY",
                "O_CLOEXEC",
                "O_NOFOLLOW",
                "O_NONBLOCK",
                "O_RDONLY",
                "close",
                "fsdecode",
                "fspath",
                "fstat",
                "geteuid",
                "getuid",
                "open",
                "path",
                "pread",
                "stat",
                "stat_result",
            }
        ),
        "os.path": frozenset({"dirname", "join"}),
        "stat": frozenset({"S_ISDIR", "S_ISREG", "S_IWGRP", "S_IWOTH"}),
        "sys": frozenset(
            {"argv", "flags", "meta_path", "modules", "orig_argv", "path", "stderr"}
        ),
    },
    "scripts/skill_root_authority.py": {
        "ctypes": frozenset(
            {
                "CDLL",
                "POINTER",
                "byref",
                "c_int",
                "c_ssize_t",
                "c_void_p",
                "get_errno",
                "set_errno",
                "string_at",
            }
        ),
        "errno": frozenset({"ELOOP", "ENOENT", "ENOTSUP", "EOPNOTSUPP"}),
        "hashlib": frozenset({"sha256"}),
        "os": frozenset(
            {
                "O_DIRECTORY",
                "O_CLOEXEC",
                "O_NOFOLLOW",
                "O_NONBLOCK",
                "O_RDONLY",
                "close",
                "fsdecode",
                "fstat",
                "geteuid",
                "getpid",
                "getuid",
                "listdir",
                "listxattr",
                "open",
                "pread",
                "stat",
                "stat_result",
            }
        ),
        "re": frozenset({"ASCII", "compile"}),
        "stat": frozenset(
            {"S_ISDIR", "S_ISLNK", "S_ISREG", "S_IWGRP", "S_IWOTH"}
        ),
        "sys": frozenset({"modules", "platform"}),
    },
    "scripts/goal_run.py": {
        "argparse": frozenset({"ArgumentParser", "SUPPRESS"}),
        "fnmatch": frozenset({"fnmatch"}),
        "hashlib": frozenset({"sha256"}),
        "json": frozenset({"dumps"}),
        "re": frozenset(
            {
                "IGNORECASE",
                "MULTILINE",
                "compile",
                "escape",
                "findall",
                "finditer",
                "fullmatch",
                "search",
                "sub",
            }
        ),
        "sys": frozenset({"flags", "modules", "path", "stderr"}),
    },
    "scripts/apply_run.py": {
        "argparse": frozenset({"ArgumentParser"}),
        "base64": frozenset({"b64decode", "b64encode"}),
        "ctypes": frozenset(
            {"CDLL", "c_char_p", "c_int", "c_uint", "get_errno", "set_errno"}
        ),
        "difflib": frozenset({"unified_diff"}),
        "errno": frozenset({"EINVAL", "ENOSYS", "ENOTSUP", "EOPNOTSUPP"}),
        "hashlib": frozenset({"sha256"}),
        "hmac": frozenset({"compare_digest", "new"}),
        "json": frozenset({"JSONDecodeError", "dumps", "loads"}),
        "re": frozenset(
            {"IGNORECASE", "compile", "finditer", "fullmatch", "search", "split", "sub"}
        ),
        "secrets": frozenset({"token_bytes", "token_hex"}),
        "stat": frozenset(
            {
                "S_IMODE",
                "S_ISDIR",
                "S_ISLNK",
                "S_ISREG",
                "S_IWGRP",
                "S_IWOTH",
            }
        ),
        "sys": frozenset(
            {"argv", "flags", "modules", "path", "platform", "stderr", "stdin"}
        ),
        "time": frozenset(),
    },
}

# The launcher and skill-root authority deliberately use a small number of
# primitives which are forbidden to ordinary protected consumers.  Enrollment
# is digest-independent and structurally scoped: the exact import, class,
# function, module-attribute, call-shape, and finding budgets below are checked
# before the separate whole-module digest gate.  The digest sentinels remain
# RED until final pin freeze, so these profiles cannot by themselves authorize
# a production tree.
_SEMANTIC_PROFILE_PATHS = frozenset(
    {"scripts/skill_launcher.py", "scripts/skill_root_authority.py"}
)
_PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS: dict[str, frozenset[str]] = {
    "scripts/skill_launcher.py": frozenset({"os"}),
    "scripts/skill_root_authority.py": frozenset({"os"}),
}
_PROTECTED_SEMANTIC_IMPORT_BINDINGS: dict[
    str, frozenset[tuple[str, str, str]]
] = {
    "scripts/skill_launcher.py": frozenset(
        {
            ("__future__", "annotations", ""),
            ("collections.abc", "Mapping", ""),
            ("hashlib", "", ""),
            ("importlib.abc", "", ""),
            ("importlib.util", "", ""),
            ("os", "", ""),
            ("stat", "", ""),
            ("sys", "", ""),
            ("types", "MappingProxyType", ""),
            ("types", "ModuleType", ""),
            ("typing", "Sequence", ""),
        }
    ),
    "scripts/skill_root_authority.py": frozenset(
        {
            ("__future__", "annotations", ""),
            ("contextlib", "contextmanager", ""),
            ("ctypes", "", ""),
            ("dataclasses", "dataclass", ""),
            ("errno", "", ""),
            ("hashlib", "", ""),
            ("os", "", ""),
            ("pathlib", "Path", ""),
            ("re", "", ""),
            ("stat", "", ""),
            ("sys", "", ""),
            ("types", "MappingProxyType", ""),
            ("types", "ModuleType", ""),
            ("typing", "Iterator", ""),
            ("typing", "Mapping", ""),
        }
    ),
}
_PROTECTED_SEMANTIC_CLASSES: dict[str, frozenset[str]] = {
    "scripts/skill_launcher.py": frozenset(
        {
            "_HeldImportPath",
            "_HeldRuntimeContext",
            "_HeldRuntimeFinder",
            "_LauncherBlocked",
        }
    ),
    "scripts/skill_root_authority.py": frozenset(
        {"SkillRootAuthority", "_HeldEntry"}
    ),
}
_PROTECTED_SEMANTIC_FUNCTIONS: dict[str, frozenset[str]] = {
    "scripts/skill_launcher.py": frozenset(
        {
            "_HeldImportPath.__contains__",
            "_HeldImportPath.__delitem__",
            "_HeldImportPath.__iadd__",
            "_HeldImportPath.__imul__",
            "_HeldImportPath.__init__",
            "_HeldImportPath.__setitem__",
            "_HeldImportPath.append",
            "_HeldImportPath.clear",
            "_HeldImportPath.extend",
            "_HeldImportPath.insert",
            "_HeldImportPath.pop",
            "_HeldImportPath.remove",
            "_HeldImportPath.reverse",
            "_HeldImportPath.sort",
            "_HeldRuntimeContext.__delattr__",
            "_HeldRuntimeContext.__init__",
            "_HeldRuntimeContext.__setattr__",
            "_HeldRuntimeFinder.__delattr__",
            "_HeldRuntimeFinder.__init__",
            "_HeldRuntimeFinder.__setattr__",
            "_HeldRuntimeFinder._validated_payload",
            "_HeldRuntimeFinder.create_module",
            "_HeldRuntimeFinder.exec_module",
            "_HeldRuntimeFinder.find_spec",
            "_block",
            "_bootstrap_directory_flags",
            "_bootstrap_file_flags",
            "_bootstrap_identity",
            "_bootstrap_open_child",
            "_controller_exit_code",
            "_execute_held_controller",
            "_held_runtime_context",
            "_held_runtime_context_is_unchanged",
            "_held_runtime_finder_is_unchanged",
            "_immutable_source_tuple",
            "_launcher_is_exact_absolute_process_path",
            "_lexical_launcher_path_is_valid",
            "_load_reviewed_authority",
            "_parse_invocation",
            "_preimport_active_skill_path_is_valid",
            "_read_reviewed_authority_bytes",
            "_required_first_process_argv",
            "_required_first_process_flags",
            "_reviewed_goal_resource_bundle",
            "_reviewed_runtime_bundle",
            "_shell_safe_absolute_path",
            "_source_tuple_payload",
            "launcher_receipt",
            "main",
        }
    ),
    "scripts/skill_root_authority.py": frozenset(
        {
            "SkillRootAuthority.read_runtime_bundle",
            "SkillRootAuthority.read_script_bytes",
            "SkillRootAuthority.read_skill_resource_bundle",
            "SkillRootAuthority.receipt",
            "SkillRootAuthority.revalidate",
            "_darwin_descriptor_acl_is_deny_only",
            "_descriptor_has_acl",
            "_directory_flags",
            "_expected_basename",
            "_expected_uid",
            "_file_flags",
            "_goal_reference_components",
            "_lexical_absolute_components",
            "_load_held_mount_module",
            "_open_child",
            "_owner_controlled",
            "_read_authorized_script_bytes",
            "_read_held_regular_bytes",
            "_read_runtime_bundle",
            "_read_skill_resource_bundle",
            "_require_owner_and_acl",
            "_require_reviewed_script_inventory",
            "_require_same_skill_mount",
            "_require_trusted_ancestor",
            "_revalidate_binding",
            "_revalidate_entry",
            "_root_mount_resolution",
            "_stable_metadata",
            "_stat_child",
            "open_skill_root_authority",
        }
    ),
}
_PROTECTED_SEMANTIC_DEFINITION_DECORATORS: dict[
    str, dict[str, tuple[str, ...]]
] = {
    "scripts/skill_launcher.py": {},
    "scripts/skill_root_authority.py": {
        "_HeldEntry": ("dataclass(frozen=True)",),
        "SkillRootAuthority": ("dataclass(frozen=True)",),
        "open_skill_root_authority": ("contextmanager",),
    },
}
_PROTECTED_SEMANTIC_ATTRIBUTE_PROBES: dict[
    str, dict[str, dict[tuple[str, str, str, str], int]]
] = {
    "scripts/skill_launcher.py": {
        "__module__": {("getattr", "sys", "orig_argv", "()"): 1},
        "_HeldRuntimeContext.__setattr__": {
            ("getattr", "self", "_sealed", "False"): 1,
        },
        "_bootstrap_directory_flags": {
            ("getattr", "os", "O_CLOEXEC", "0"): 1,
            ("hasattr", "os", "O_DIRECTORY", ""): 1,
            ("hasattr", "os", "O_NOFOLLOW", ""): 1,
        },
        "_bootstrap_file_flags": {
            ("getattr", "os", "O_CLOEXEC", "0"): 1,
            ("getattr", "os", "O_NONBLOCK", "0"): 1,
            ("hasattr", "os", "O_NOFOLLOW", ""): 1,
            ("hasattr", "os", "pread", ""): 1,
        },
        "_execute_held_controller": {
            ("getattr", "module", "__loader__", "None"): 1,
        },
        "_load_reviewed_authority": {
            ("getattr", "module", "open_skill_root_authority", "None"): 1,
        },
        "_read_reviewed_authority_bytes": {
            ("hasattr", "os", "geteuid", ""): 1,
        },
        "_required_first_process_argv": {
            ("getattr", "sys", "orig_argv", "()"): 1,
        },
    },
    "scripts/skill_root_authority.py": {
        "_darwin_descriptor_acl_is_deny_only": {
            ("getattr", "libc", "acl_free", "None"): 1,
            ("getattr", "libc", "acl_get_fd_np", "None"): 1,
            ("getattr", "libc", "acl_to_text", "None"): 1,
        },
        "_descriptor_has_acl": {
            ("getattr", "libc", "acl_free", "None"): 1,
            ("getattr", "libc", "acl_get_fd_np", "None"): 1,
            ("hasattr", "errno", "EOPNOTSUPP", ""): 1,
        },
        "_directory_flags": {
            ("getattr", "os", "O_CLOEXEC", "0"): 1,
            ("hasattr", "os", "O_DIRECTORY", ""): 1,
            ("hasattr", "os", "O_NOFOLLOW", ""): 1,
        },
        "_expected_uid": {
            ("hasattr", "os", "geteuid", ""): 1,
            ("hasattr", "os", "getuid", ""): 1,
        },
        "_file_flags": {
            ("getattr", "os", "O_CLOEXEC", "0"): 1,
            ("getattr", "os", "O_NONBLOCK", "0"): 1,
            ("hasattr", "os", "O_NOFOLLOW", ""): 1,
        },
        "_load_held_mount_module": {
            ("getattr", "module", "<required_callable>", "None"): 1,
            ("getattr", "module", "READ_ONLY_EVIDENCE", "None"): 1,
        },
        "_read_held_regular_bytes": {
            ("hasattr", "os", "pread", ""): 1,
        },
        "_revalidate_binding": {
            ("getattr", "binding._mount_resolution", "identity", "None"): 1,
            ("getattr", "current_resolution", "identity", "None"): 1,
        },
    },
}
_PROTECTED_SEMANTIC_API_CALLS: dict[str, dict[str, dict[str, int]]] = {
    "scripts/skill_launcher.py": {
        "__module__": {"os.fsdecode": 1, "os.path.dirname": 1},
        "_HeldRuntimeFinder.exec_module": {
            "compile": 1,
            "exec": 1,
            "os.path.join": 1,
        },
        "_HeldRuntimeFinder.find_spec": {
            "importlib.util.spec_from_loader": 1,
            "os.path.join": 1,
        },
        "_bootstrap_open_child": {
            "os.close": 1,
            "os.fstat": 1,
            "os.open": 1,
            "os.stat": 2,
        },
        "_execute_held_controller": {"compile": 1, "exec": 1},
        "_load_reviewed_authority": {"compile": 1, "exec": 1},
        "_read_reviewed_authority_bytes": {
            "os.close": 1,
            "os.fstat": 1,
            "os.geteuid": 1,
            "os.getuid": 1,
            "os.open": 1,
            "os.pread": 2,
            "os.stat": 1,
        },
        "_required_first_process_argv": {"os.fsdecode": 2},
        "main": {"os.fspath": 2, "os.path.join": 1},
    },
    "scripts/skill_root_authority.py": {
        "_darwin_descriptor_acl_is_deny_only": {
            "ctypes.CDLL": 1,
            "ctypes.POINTER": 1,
            "ctypes.byref": 1,
            "ctypes.c_ssize_t": 1,
            "ctypes.set_errno": 1,
            "ctypes.string_at": 1,
        },
        "_descriptor_has_acl": {
            "ctypes.CDLL": 1,
            "ctypes.get_errno": 1,
            "ctypes.set_errno": 1,
            "os.fsdecode": 1,
            "os.listxattr": 1,
        },
        "_expected_uid": {"os.geteuid": 1, "os.getuid": 1},
        "_load_held_mount_module": {
            "compile": 1,
            "exec": 1,
            "os.getpid": 1,
        },
        "_open_child": {"os.close": 1, "os.fstat": 1, "os.open": 1},
        "_read_authorized_script_bytes": {"os.close": 1},
        "_read_held_regular_bytes": {"os.fstat": 1, "os.pread": 2},
        "_read_runtime_bundle": {"os.close": 1},
        "_read_skill_resource_bundle": {"os.close": 1, "os.fstat": 1},
        "_require_owner_and_acl": {"os.fstat": 1},
        "_require_reviewed_script_inventory": {"os.listdir": 1},
        "_require_trusted_ancestor": {"os.fstat": 1},
        "_revalidate_binding": {"os.fstat": 1},
        "_revalidate_entry": {"os.fstat": 1},
        "_stat_child": {"os.stat": 1},
        "open_skill_root_authority": {
            "os.close": 1,
            "os.fstat": 3,
            "os.open": 1,
        },
    },
}
_PROTECTED_SEMANTIC_SENSITIVE_CALL_SHAPES: dict[
    str, dict[str, dict[str, int]]
] = {
    "scripts/skill_launcher.py": {
        "_HeldRuntimeFinder.exec_module": {
            "compile(payload, origin, 'exec', flags=0, dont_inherit=True, optimize=0)": 1,
            "exec(code, module.__dict__)": 1,
            "os.path.join(self._scripts_directory, basename)": 1,
        },
        "_HeldRuntimeFinder.find_spec": {
            "importlib.util.spec_from_loader(fullname, self, "
            "origin=os.path.join(self._scripts_directory, f'{fullname}.py'))": 1,
            "os.path.join(self._scripts_directory, f'{fullname}.py')": 1,
        },
        "_bootstrap_open_child": {
            "os.close(descriptor)": 1,
            "os.fstat(descriptor)": 1,
            "os.open(name, _bootstrap_directory_flags() if directory else "
            "_bootstrap_file_flags(), dir_fd=parent_fd)": 1,
            "os.stat(name, dir_fd=parent_fd, follow_symlinks=False)": 2,
        },
        "_execute_held_controller": {
            "compile(source, controller_path, 'exec', flags=0, "
            "dont_inherit=True, optimize=0)": 1,
            "exec(code, namespace, namespace)": 1,
        },
        "_load_reviewed_authority": {
            "compile(payload, '<held-codexqb-skill-root-authority>', 'exec', "
            "flags=0, dont_inherit=True, optimize=0)": 1,
            "exec(code, module.__dict__)": 1,
        },
        "_read_reviewed_authority_bytes": {
            "os.close(descriptor)": 1,
            "os.fstat(authority_fd)": 1,
            "os.open('/', _bootstrap_directory_flags())": 1,
            "os.pread(authority_fd, 1, metadata.st_size)": 1,
            "os.pread(authority_fd, min(64 * 1024, metadata.st_size - offset), offset)": 1,
            "os.stat(_AUTHORITY_BASENAME, dir_fd=current_fd, follow_symlinks=False)": 1,
        },
        "main": {
            "os.path.join(os.fspath(binding.scripts_directory), target_basename)": 1,
        },
    },
    "scripts/skill_root_authority.py": {
        "_darwin_descriptor_acl_is_deny_only": {
            "ctypes.CDLL(None, use_errno=True)": 1,
        },
        "_descriptor_has_acl": {
            "ctypes.CDLL(None, use_errno=True)": 1,
            "os.listxattr(descriptor)": 1,
        },
        "_load_held_mount_module": {
            "compile(source, '<held-codexqb-mount-identity>', 'exec', "
            "dont_inherit=True)": 1,
            "exec(code, module.__dict__)": 1,
        },
        "_open_child": {
            "os.close(child_fd)": 1,
            "os.fstat(child_fd)": 1,
            "os.open(name, flags, dir_fd=parent_fd)": 1,
        },
        "_read_authorized_script_bytes": {"os.close(target.fd)": 1},
        "_read_held_regular_bytes": {
            "os.fstat(entry.fd)": 1,
            "os.pread(entry.fd, 1, metadata.st_size)": 1,
            "os.pread(entry.fd, min(64 * 1024, metadata.st_size - offset), offset)": 1,
        },
        "_read_runtime_bundle": {"os.close(entry.fd)": 1},
        "_read_skill_resource_bundle": {
            "os.close(entry.fd)": 1,
            "os.fstat(entry.fd)": 1,
        },
        "_require_owner_and_acl": {"os.fstat(entry.fd)": 1},
        "_require_reviewed_script_inventory": {
            "os.listdir(binding.scripts_fd)": 1,
        },
        "_require_trusted_ancestor": {"os.fstat(descriptor)": 1},
        "_revalidate_binding": {
            "os.fstat(binding._entries[0].parent_fd)": 1,
        },
        "_revalidate_entry": {"os.fstat(entry.fd)": 1},
        "_stat_child": {
            "os.stat(name, dir_fd=parent_fd, follow_symlinks=False)": 1,
        },
        "open_skill_root_authority": {
            "os.close(descriptor)": 1,
            "os.fstat(filesystem_root_fd)": 1,
            "os.fstat(mount_entry.fd)": 1,
            "os.fstat(skill_root_entry.fd)": 1,
            "os.open('/', _directory_flags())": 1,
        },
    },
}
_SEMANTIC_SENSITIVE_CALLS = frozenset(
    {
        "compile",
        "ctypes.CDLL",
        "exec",
        "importlib.util.spec_from_loader",
        "os.close",
        "os.fstat",
        "os.listdir",
        "os.listxattr",
        "os.open",
        "os.path.join",
        "os.pread",
        "os.stat",
    }
)

# These readable AST-unparse contracts cover security decisions which retain
# the same import/API counts when an operator, binding, or local value is
# substituted.  They are intentionally not digests and remain subordinate to
# the separate all-zero whole-module enrollment sentinels.
_PROTECTED_SEMANTIC_CRITICAL_FUNCTION_SHAPES: dict[str, dict[str, str]] = {
    "scripts/skill_launcher.py": {
        "_required_first_process_flags": (
            "def _required_first_process_flags() -> bool:\n"
            "    return bool(sys.flags.isolated and sys.flags.no_site and "
            "sys.flags.dont_write_bytecode and (sys.flags.optimize == 0))"
        ),
        "_required_first_process_argv": (
            "def _required_first_process_argv() -> bool:\n"
            "    return bool(_IMPORTED_AS_MAIN and len(_IMPORT_ORIG_ARGV) >= 5 "
            "and (tuple(getattr(sys, 'orig_argv', ())) == _IMPORT_ORIG_ARGV) "
            "and isinstance(_IMPORT_ORIG_ARGV[0], str) and _IMPORT_ORIG_ARGV[0] "
            "and (_IMPORT_ORIG_ARGV[1:4] == ('-I', '-S', '-B')) and "
            "(_IMPORT_ORIG_ARGV[4] == os.fsdecode(__file__)) and "
            "(tuple(sys.argv) == (os.fsdecode(__file__), "
            "*_IMPORT_ORIG_ARGV[5:])))"
        ),
        "_lexical_launcher_path_is_valid": (
            "def _lexical_launcher_path_is_valid(value: object, process_argv0: "
            "object) -> bool:\n"
            "    if not _shell_safe_absolute_path(value, "
            "expected_basename=_LAUNCHER_BASENAME):\n"
            "        return False\n"
            "    return isinstance(process_argv0, str) and process_argv0 == value"
        ),
        "_preimport_active_skill_path_is_valid": (
            "def _preimport_active_skill_path_is_valid(arguments: Sequence[str]) "
            "-> bool:\n"
            "    return bool(len(arguments) >= 2 and arguments[0] == "
            "'--active-skill-md' and _shell_safe_absolute_path(arguments[1], "
            "expected_basename='SKILL.md'))"
        ),
        "_bootstrap_directory_flags": (
            "def _bootstrap_directory_flags() -> int:\n"
            "    if not hasattr(os, 'O_DIRECTORY') or not hasattr(os, "
            "'O_NOFOLLOW'):\n"
            "        raise _LauncherBlocked\n"
            "    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | "
            "getattr(os, 'O_CLOEXEC', 0)"
        ),
        "_bootstrap_file_flags": (
            "def _bootstrap_file_flags() -> int:\n"
            "    if not hasattr(os, 'O_NOFOLLOW') or not hasattr(os, 'pread'):\n"
            "        raise _LauncherBlocked\n"
            "    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', "
            "0) | getattr(os, 'O_NONBLOCK', 0)"
        ),
        "_HeldRuntimeFinder._validated_payload": (
            "def _validated_payload(self, basename: str) -> bytes | None:\n"
            "    try:\n"
            "        sources = object.__getattribute__(self, '_sources')\n"
            "        expected_sources = object.__getattribute__(self, "
            "'_expected_sources')\n"
            "        source_sha256 = object.__getattribute__(self, "
            "'_source_sha256')\n"
            "        if sources is not expected_sources or type(sources) is not "
            "tuple or type(source_sha256) is not tuple:\n"
            "            raise ImportError\n"
            "        expected_payload = _source_tuple_payload(expected_sources, "
            "basename)\n"
            "        if expected_payload is None:\n"
            "            return None\n"
            "        payload = _source_tuple_payload(sources, basename)\n"
            "        expected_digest = next((digest for current_name, digest in "
            "source_sha256 if current_name == basename), None)\n"
            "        if type(payload) is not bytes or type(expected_digest) is "
            "not str or payload != expected_payload or "
            "(hashlib.sha256(payload).hexdigest() != expected_digest):\n"
            "            raise ImportError\n"
            "        return payload\n"
            "    except (TypeError, ValueError):\n"
            "        raise ImportError('codexqb_held_runtime_module_rejected') "
            "from None"
        ),
        "_held_runtime_finder_is_unchanged": (
            "def _held_runtime_finder_is_unchanged(finder: "
            "_HeldRuntimeFinder, *, sources: object, expected_sources: object, "
            "source_sha256: object, scripts_directory: object) -> bool:\n"
            "    try:\n"
            "        return bool(object.__getattribute__(finder, '_sources') is "
            "sources and object.__getattribute__(finder, '_expected_sources') "
            "is expected_sources and (object.__getattribute__(finder, "
            "'_source_sha256') is source_sha256) and "
            "(object.__getattribute__(finder, '_scripts_directory') is "
            "scripts_directory) and (object.__getattribute__(finder, '_sealed') "
            "is True) and (sources is expected_sources) and (type(sources) is "
            "tuple) and (type(source_sha256) is tuple) and "
            "(_immutable_source_tuple(sources) == sources) and (source_sha256 == "
            "tuple(((name, hashlib.sha256(payload).hexdigest()) for name, payload "
            "in sources))))\n"
            "    except (AttributeError, KeyError, TypeError, ValueError):\n"
            "        return False"
        ),
    },
    "scripts/skill_root_authority.py": {
        "_directory_flags": (
            "def _directory_flags() -> int:\n"
            "    if not hasattr(os, 'O_DIRECTORY') or not hasattr(os, "
            "'O_NOFOLLOW'):\n"
            "        raise "
            "ValueError('skill_root_authority_secure_open_unavailable')\n"
            "    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | "
            "getattr(os, 'O_CLOEXEC', 0)"
        ),
        "_file_flags": (
            "def _file_flags() -> int:\n"
            "    if not hasattr(os, 'O_NOFOLLOW'):\n"
            "        raise "
            "ValueError('skill_root_authority_secure_open_unavailable')\n"
            "    return os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_CLOEXEC', "
            "0) | getattr(os, 'O_NONBLOCK', 0)"
        ),
    },
}
_PROTECTED_SEMANTIC_CRITICAL_COMPARE_SHAPES: dict[
    str, dict[str, int]
] = {
    "scripts/skill_launcher.py": {
        "'goal_sha256' in state": 1,
        "'runtime_sha256' in state": 1,
        "frozenset(bundle) != frozenset(_REVIEWED_RUNTIME_SHA256)": 1,
        "hashlib.sha256(payload).hexdigest() != expected_digest": 1,
        "hashlib.sha256(payload).hexdigest() != expected_sha256": 1,
        "hashlib.sha256(payload).hexdigest() != expected_sha256[relative_path]": 1,
        "hashlib.sha256(result).hexdigest() != _AUTHORITY_SOURCE_SHA256": 1,
        "object.__getattribute__(finder, '_source_sha256') is source_sha256": 1,
        "source_sha256 == tuple(((name, hashlib.sha256(payload).hexdigest()) "
        "for name, payload in sources))": 1,
        "type(expected_digest) is not str": 1,
        "type(source_sha256) is not tuple": 1,
        "type(source_sha256) is tuple": 1,
    },
    "scripts/skill_root_authority.py": {
        "hashlib.sha256(payload).hexdigest() != MOUNT_IDENTITY_SOURCE_SHA256": 2,
    },
}
_PROTECTED_SEMANTIC_CRITICAL_GUARD_SHAPES: dict[
    str, dict[str, int]
] = {
    "scripts/skill_launcher.py": {
        "if hashlib.sha256(result).hexdigest() != _AUTHORITY_SOURCE_SHA256:\n"
        "    raise _LauncherBlocked": 1,
        "if not isinstance(bundle, Mapping) or frozenset(bundle) != "
        "frozenset(_REVIEWED_RUNTIME_SHA256):\n"
        "    raise _LauncherBlocked": 1,
        "if not isinstance(payload, bytes) or not payload or "
        "hashlib.sha256(payload).hexdigest() != expected_sha256:\n"
        "    raise _LauncherBlocked": 1,
        "if not isinstance(payload, bytes) or not payload or len(payload) > "
        "_MAX_GOAL_RESOURCE_BYTES or "
        "(hashlib.sha256(payload).hexdigest() != "
        "expected_sha256[relative_path]):\n"
        "    raise _LauncherBlocked": 1,
        "if sources is not expected_sources or type(sources) is not tuple or "
        "type(source_sha256) is not tuple:\n"
        "    raise ImportError": 1,
        "if sys.modules.get(_HELD_RUNTIME_CONTEXT_NAME) is not context or "
        "type(context_name) is not str or type(schema_version) is not int or "
        "(type(assurance) is not str) or "
        "(context_name != _HELD_RUNTIME_CONTEXT_NAME) or "
        "(schema_version != 1) or (assurance != SKILL_LAUNCHER_ASSURANCE) or "
        "(state.get('runtime_sources') is not runtime_sources) or "
        "(state.get('goal_resources') is not goal_resources) or "
        "('runtime_sha256' in state) or ('goal_sha256' in state) or "
        "(state.get('host_attested') is not False) or "
        "(state.get('verified') is not False) or "
        "(state.get('finalization_authority') is not False):\n"
        "    return False": 1,
        "if type(payload) is not bytes or type(expected_digest) is not str or "
        "payload != expected_payload or "
        "(hashlib.sha256(payload).hexdigest() != expected_digest):\n"
        "    raise ImportError": 1,
    },
    "scripts/skill_root_authority.py": {
        "if entry.name == 'mount_identity.py' and "
        "hashlib.sha256(payload).hexdigest() != "
        "MOUNT_IDENTITY_SOURCE_SHA256:\n"
        "    raise "
        "ValueError('skill_root_authority_mount_policy_digest_mismatch')": 1,
        "if hashlib.sha256(payload).hexdigest() != "
        "MOUNT_IDENTITY_SOURCE_SHA256:\n"
        "    raise "
        "ValueError('skill_root_authority_mount_policy_digest_mismatch')": 1,
    },
}
_APPLY_REQUEST_STDIN_ACCESS_SHAPES: dict[str, dict[str, int]] = {
    "_read_controller_stdin_argv": {
        "Attribute:sys.stdin": 1,
        "Attribute:sys.stdin.buffer": 1,
        "Attribute:sys.stdin.buffer.read": 1,
        "Call:sys.stdin.buffer.read(MAX_CONTROLLER_STDIN_REQUEST_BYTES + 1)": 1,
    },
    "main": {
        "Attribute:sys.argv": 1,
        "Subscript:sys.argv[1:]": 1,
    },
}
_APPLY_REQUEST_STDIN_FINDING_BUDGETS: dict[str, dict[str, int]] = {
    "execute_planned_validation": {
        "controller_capability_reference:controller_store.controller_atomic_write_json": 2,
        "controller_capability_reference:controller_store.controller_fsync": 1,
        "controller_capability_reference:controller_store.controller_read_json": 1,
        "controller_capability_use:controller_store.controller_atomic_write_json": 2,
        "controller_capability_use:controller_store.controller_fsync": 1,
        "controller_capability_use:controller_store.controller_read_json": 1,
        "execution_capability_reference:execution_controller.run_bounded_validation_process": 1,
        "execution_capability_use:execution_controller.run_bounded_validation_process": 1,
        "local_capability_reference:agent_record_sha256_at": 1,
        "local_capability_reference:append_event_at": 3,
        "local_capability_reference:current_completed_writer_record": 1,
        "local_capability_reference:load_current_change_set": 2,
        "local_capability_reference:load_or_create_apply_run_trust_key": 1,
        "local_capability_reference:normalized_command_cwd": 1,
        "local_capability_reference:open_apply_task_for_mutation": 2,
        "local_capability_reference:open_verified_apply_run_for_mutation": 1,
        "local_capability_reference:repository_receipt_snapshot": 2,
        "local_capability_reference:revalidate": 2,
        "local_capability_reference:write_regular_json_exclusive_at": 1,
    },
    "main": {
        "local_capability_reference:capture_task_change_set": 1,
        "local_capability_reference:create_apply_run": 1,
        "local_capability_reference:execute_planned_validation": 1,
        "local_capability_reference:finalize_apply_run": 1,
        "local_capability_reference:normalize_review_report": 1,
        "local_capability_reference:normalize_writer_report": 1,
        "local_capability_reference:prepare_dispatch_packet": 1,
        "local_capability_reference:publish_review_completion": 1,
        "local_capability_reference:reconcile_external_superpowers": 1,
        "local_capability_reference:record_agent_status": 1,
        "local_capability_reference:recover_stale_writer_lock": 1,
        "local_capability_reference:transition_task_state": 1,
        "local_capability_reference:validate_apply_run": 1,
    },
}

if not all(
    set(registry) == set(_SEMANTIC_PROFILE_PATHS)
    for registry in (
        _PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS,
        _PROTECTED_SEMANTIC_IMPORT_BINDINGS,
        _PROTECTED_SEMANTIC_ATTRIBUTE_PROBES,
        _PROTECTED_SEMANTIC_API_CALLS,
        _PROTECTED_SEMANTIC_CRITICAL_COMPARE_SHAPES,
        _PROTECTED_SEMANTIC_CRITICAL_FUNCTION_SHAPES,
        _PROTECTED_SEMANTIC_CRITICAL_GUARD_SHAPES,
        _PROTECTED_SEMANTIC_SENSITIVE_CALL_SHAPES,
        _PROTECTED_SEMANTIC_CLASSES,
        _PROTECTED_SEMANTIC_DEFINITION_DECORATORS,
        _PROTECTED_SEMANTIC_FUNCTIONS,
    )
):
    raise RuntimeError("protected_semantic_profile_registry_invalid")

_PROTECTED_SEMANTIC_FINDING_BUDGETS: dict[
    str, dict[str, dict[str, int]]
] = {
    "scripts/skill_launcher.py": {
        "__module__": {
            "dangerous_builtin_reference:getattr": 1,
            "dangerous_callable_reference:importlib.abc": 2,
            "dangerous_callable_reference:importlib.abc.Loader": 1,
            "dangerous_callable_reference:importlib.abc.MetaPathFinder": 1,
            "dynamic_import_state:sys.path": 1,
            "local_capability_reference:_load_reviewed_authority": 1,
            "local_capability_reference:_required_first_process_argv": 1,
            "local_capability_reference:main": 1,
        },
        "_HeldImportPath.__contains__": {
            "private_attribute_access:__contains__": 1,
        },
        "_HeldImportPath.__init__": {
            "local_capability_reference:__init__": 1,
            "private_attribute_access:__init__": 1,
            "private_attribute_access:_blocked": 1,
        },
        "_HeldRuntimeContext.__init__": {
            "local_capability_reference:__init__": 1,
            "local_capability_reference:__setattr__": 10,
            "private_attribute_access:__init__": 1,
            "private_attribute_access:__setattr__": 10,
        },
        "_HeldRuntimeContext.__setattr__": {
            "dangerous_builtin_reference:getattr": 1,
        },
        "_HeldRuntimeFinder.__init__": {
            "local_capability_reference:__setattr__": 5,
            "private_attribute_access:__setattr__": 5,
        },
        "_HeldRuntimeFinder._validated_payload": {
            "private_attribute_access:__getattribute__": 3,
        },
        "_HeldRuntimeFinder.exec_module": {
            "dangerous_builtin_reference:compile": 1,
            "dangerous_builtin_reference:exec": 1,
            "dynamic_code:compile": 1,
            "dynamic_code:exec": 1,
            "dynamic_namespace_access": 1,
            "private_attribute_access:__dict__": 1,
            "private_attribute_access:__file__": 1,
            "private_attribute_access:__package__": 1,
            "private_attribute_access:_scripts_directory": 1,
            "private_attribute_access:_validated_payload": 1,
        },
        "_HeldRuntimeFinder.find_spec": {
            "dangerous_callable_reference:importlib.util": 1,
            "dangerous_callable_reference:importlib.util.spec_from_loader": 1,
            "dynamic_import:importlib.util.spec_from_loader": 1,
            "private_attribute_access:_scripts_directory": 1,
            "private_attribute_access:_validated_payload": 1,
        },
        "_bootstrap_directory_flags": {
            "dangerous_builtin_reference:getattr": 1,
        },
        "_bootstrap_file_flags": {
            "dangerous_builtin_reference:getattr": 2,
        },
        "_bootstrap_open_child": {
            "dangerous_callable_reference:os.open": 1,
            "dangerous_callable_reference:os.stat": 2,
            "local_capability_reference:_bootstrap_directory_flags": 1,
            "local_capability_reference:_bootstrap_file_flags": 1,
            "raw_io:os.open": 1,
            "raw_io:os.stat": 2,
        },
        "_execute_held_controller": {
            "dangerous_builtin_reference:compile": 1,
            "dangerous_builtin_reference:exec": 1,
            "dangerous_builtin_reference:getattr": 1,
            "dynamic_code:compile": 1,
            "dynamic_code:exec": 1,
            "dynamic_import_state:sys.meta_path": 3,
            "dynamic_import_state:sys.path": 3,
            "dynamic_namespace_access": 7,
            "private_attribute_access:__getattribute__": 4,
        },
        "_held_runtime_context": {"dynamic_namespace_access": 1},
        "_held_runtime_context_is_unchanged": {
            "dynamic_namespace_access": 1,
            "private_attribute_access:__getattribute__": 1,
        },
        "_held_runtime_finder_is_unchanged": {
            "private_attribute_access:__getattribute__": 5,
        },
        "_load_reviewed_authority": {
            "dangerous_builtin_reference:compile": 1,
            "dangerous_builtin_reference:exec": 1,
            "dangerous_builtin_reference:getattr": 1,
            "dynamic_code:compile": 1,
            "dynamic_code:exec": 1,
            "dynamic_namespace_access": 5,
            "local_capability_reference:_read_reviewed_authority_bytes": 1,
            "private_attribute_access:__dict__": 1,
            "private_attribute_access:__file__": 1,
            "private_attribute_access:__package__": 1,
        },
        "_read_reviewed_authority_bytes": {
            "dangerous_callable_reference:os.open": 1,
            "dangerous_callable_reference:os.pread": 2,
            "dangerous_callable_reference:os.stat": 1,
            "local_capability_reference:_bootstrap_directory_flags": 1,
            "local_capability_reference:_bootstrap_open_child": 2,
            "raw_io:os.open": 1,
            "raw_io:os.pread": 2,
            "raw_io:os.stat": 1,
        },
        "_required_first_process_argv": {
            "dangerous_builtin_reference:getattr": 1,
        },
        "main": {"local_capability_reference:_execute_held_controller": 1},
    },
    "scripts/skill_root_authority.py": {
        "SkillRootAuthority.read_runtime_bundle": {
            "local_capability_reference:_read_runtime_bundle": 1,
        },
        "SkillRootAuthority.read_script_bytes": {
            "local_capability_reference:_read_authorized_script_bytes": 1,
        },
        "SkillRootAuthority.read_skill_resource_bundle": {
            "local_capability_reference:_read_skill_resource_bundle": 1,
        },
        "SkillRootAuthority.revalidate": {
            "local_capability_reference:_revalidate_binding": 1,
        },
        "_darwin_descriptor_acl_is_deny_only": {
            "dangerous_builtin_reference:getattr": 3,
            "dangerous_callable_reference:ctypes.CDLL": 1,
            "dangerous_callable_reference:ctypes.POINTER": 1,
            "dangerous_callable_reference:ctypes.byref": 1,
            "dangerous_callable_reference:ctypes.c_int": 3,
            "dangerous_callable_reference:ctypes.c_ssize_t": 2,
            "dangerous_callable_reference:ctypes.c_void_p": 4,
            "dangerous_callable_reference:ctypes.set_errno": 1,
            "dangerous_callable_reference:ctypes.string_at": 1,
            "process_creation:ctypes.CDLL": 1,
            "raw_io:ctypes.POINTER": 1,
            "raw_io:ctypes.byref": 1,
            "raw_io:ctypes.c_ssize_t": 1,
            "raw_io:ctypes.set_errno": 1,
            "raw_io:ctypes.string_at": 1,
        },
        "_descriptor_has_acl": {
            "dangerous_builtin_reference:getattr": 2,
            "dangerous_callable_reference:ctypes.CDLL": 1,
            "dangerous_callable_reference:ctypes.c_int": 3,
            "dangerous_callable_reference:ctypes.c_void_p": 2,
            "dangerous_callable_reference:ctypes.get_errno": 1,
            "dangerous_callable_reference:ctypes.set_errno": 1,
            "dangerous_callable_reference:os.listxattr": 1,
            "process_creation:ctypes.CDLL": 1,
            "raw_io:ctypes.get_errno": 1,
            "raw_io:ctypes.set_errno": 1,
            "raw_io:os.listxattr": 1,
        },
        "_directory_flags": {"dangerous_builtin_reference:getattr": 1},
        "_file_flags": {"dangerous_builtin_reference:getattr": 2},
        "_load_held_mount_module": {
            "dangerous_builtin_reference:compile": 1,
            "dangerous_builtin_reference:exec": 1,
            "dangerous_builtin_reference:getattr": 2,
            "dynamic_attribute:nonliteral": 1,
            "dynamic_code:compile": 1,
            "dynamic_code:exec": 1,
            "dynamic_namespace_access": 5,
            "local_capability_reference:_read_held_regular_bytes": 1,
            "private_attribute_access:__dict__": 1,
            "private_attribute_access:__file__": 1,
            "private_attribute_access:__package__": 1,
        },
        "_open_child": {
            "dangerous_callable_reference:os.open": 1,
            "local_capability_reference:_directory_flags": 1,
            "local_capability_reference:_file_flags": 1,
            "local_capability_reference:_stat_child": 2,
            "raw_io:os.open": 1,
        },
        "_read_authorized_script_bytes": {
            "local_capability_reference:_open_child": 1,
            "local_capability_reference:_read_held_regular_bytes": 1,
            "local_capability_reference:_require_owner_and_acl": 1,
            "local_capability_reference:_revalidate_entry": 1,
            "local_capability_reference:revalidate": 2,
            "private_attribute_access:_mount_module": 1,
            "private_attribute_access:_mount_resolution": 1,
        },
        "_read_held_regular_bytes": {
            "dangerous_callable_reference:os.pread": 2,
            "local_capability_reference:_revalidate_entry": 2,
            "raw_io:os.pread": 2,
        },
        "_read_runtime_bundle": {
            "local_capability_reference:_open_child": 1,
            "local_capability_reference:_read_held_regular_bytes": 1,
            "local_capability_reference:_require_owner_and_acl": 1,
            "local_capability_reference:_require_reviewed_script_inventory": 2,
            "local_capability_reference:_revalidate_entry": 1,
            "local_capability_reference:revalidate": 2,
            "private_attribute_access:_mount_module": 1,
            "private_attribute_access:_mount_resolution": 1,
        },
        "_read_skill_resource_bundle": {
            "local_capability_reference:_open_child": 2,
            "local_capability_reference:_read_held_regular_bytes": 1,
            "local_capability_reference:_require_owner_and_acl": 1,
            "local_capability_reference:_revalidate_entry": 1,
            "local_capability_reference:revalidate": 2,
            "private_attribute_access:_mount_module": 1,
            "private_attribute_access:_mount_resolution": 1,
        },
        "_require_owner_and_acl": {
            "local_capability_reference:_descriptor_has_acl": 1,
        },
        "_require_reviewed_script_inventory": {
            "dangerous_callable_reference:os.listdir": 1,
            "local_capability_reference:_revalidate_entry": 2,
            "private_attribute_access:_entries": 1,
            "raw_io:os.listdir": 1,
        },
        "_require_trusted_ancestor": {
            "local_capability_reference:_darwin_descriptor_acl_is_deny_only": 1,
            "local_capability_reference:_descriptor_has_acl": 1,
        },
        "_revalidate_binding": {
            "dangerous_builtin_reference:getattr": 2,
            "local_capability_reference:_require_owner_and_acl": 1,
            "local_capability_reference:_require_trusted_ancestor": 2,
            "local_capability_reference:_revalidate_entry": 1,
            "private_attribute_access:_entries": 10,
            "private_attribute_access:_mount_module": 2,
            "private_attribute_access:_mount_resolution": 1,
            "private_attribute_access:_root_metadata": 2,
        },
        "_revalidate_entry": {
            "local_capability_reference:_stat_child": 1,
        },
        "_stat_child": {
            "dangerous_callable_reference:os.stat": 1,
            "raw_io:os.stat": 1,
        },
        "open_skill_root_authority": {
            "dangerous_callable_reference:os.open": 1,
            "local_capability_reference:_directory_flags": 1,
            "local_capability_reference:_load_held_mount_module": 1,
            "local_capability_reference:_open_child": 5,
            "local_capability_reference:_require_owner_and_acl": 1,
            "local_capability_reference:_require_trusted_ancestor": 2,
            "local_capability_reference:revalidate": 1,
            "raw_io:os.open": 1,
        },
    },
}
if set(_PROTECTED_SEMANTIC_FINDING_BUDGETS) != set(_SEMANTIC_PROFILE_PATHS):
    raise RuntimeError("protected_semantic_finding_registry_invalid")
_LOCAL_HELPER_ALLOWED_IMPORTS: dict[str, dict[str, frozenset[str]]] = {
    "scripts/repository_validation.py": {
        "safety_contracts": frozenset(
            {
                "package_secret_match_locations",
                "package_secret_path_match_locations",
            }
        ),
    },
    "scripts/validate_planner_docs.py": {
        "safety_contracts": frozenset(
            {
                "exact_validation_command",
                "safe_log_text",
                "safe_validation_argv",
                "safe_validation_command_item",
                "safe_validation_cwd",
                "secret_match_locations",
            }
        ),
    },
    "scripts/goal_run.py": {
        "safety_contracts": frozenset(
            {
                "assert_safe_persistent_text",
                "budget_limit",
                "canonical_json_digest",
                "default_budget_contract",
                "glob_patterns_overlap",
                "has_secret_like",
                "implementation_contract_binding_from_bytes",
                "implementation_contract_validation_command_ids",
                "is_safe_repo_path",
                "parse_safe_persistent_json",
                "path_is_inside",
                "redact_secret_like",
                "safe_log_text",
                "serialize_safe_persistent_json",
                "token_usage_not_observed",
                "validate_budget_contract",
                "validate_token_usage",
            }
        ),
    },
    "scripts/apply_run.py": {
        "safety_contracts": frozenset(
            {
                "assert_safe_embedded_content_bytes",
                "assert_safe_persistent_text",
                "assert_safe_serialized_artifact",
                "budget_limit",
                "canonical_json_digest",
                "default_budget_contract",
                "has_secret_like",
                "implementation_contract_binding_from_bytes",
                "implementation_contract_validation_command_ids",
                "parse_safe_persistent_json",
                "path_is_inside",
                "safe_log_text",
                "safe_validation_command_item",
                "serialize_safe_persistent_json",
                "token_usage_not_observed",
                "validate_budget_contract",
                "validate_token_usage",
            }
        ),
        "evidence_contracts": frozenset(
            {
                "CONTROLLER_OBSERVER",
                "NOT_OBSERVED",
                "REVIEW_COMPLETION_OBSERVATION_SCOPE",
                "REVIEW_COMPLETION_RECEIPT_KIND",
                "REVIEW_COMPLETION_RECEIPT_VERSION",
                "VALIDATION_OBSERVATION_SCOPE",
                "VALIDATION_RECEIPT_KIND",
                "VALIDATION_RECEIPT_VERSION",
                "canonical_json_digest",
                "sign_review_completion_receipt",
                "sign_validation_receipt",
                "trust_key_id",
                "verify_review_completion_receipt",
                "verify_validation_receipt",
            }
        ),
        "repository_evidence": frozenset(
            {
                "DEFAULT_MAX_FILE_BYTES",
                "DEFAULT_MAX_PATHS",
                "DEFAULT_MAX_TOTAL_BYTES",
                "DEFAULT_SNAPSHOT_TIMEOUT_SECONDS",
                "REPOSITORY_EVIDENCE_SCHEMA_VERSION",
            }
        ),
    },
}
_LOCAL_HELPER_MODULES = frozenset(
    {
        module
        for per_consumer in _LOCAL_HELPER_ALLOWED_IMPORTS.values()
        for module in per_consumer
    }
)
_FORBIDDEN_PROTECTED_IMPORT_MODULES = frozenset(
    {"artifact_io", "os", "repository_controller", "subprocess"}
)
_EXECUTION_CONTROLLER_ALLOWED_IMPORTS: dict[str, frozenset[str]] = {
    "scripts/goal_run.py": frozenset(
        {"read_goal_held_bytes", "run_goal_planner_validator"}
    ),
    "scripts/apply_run.py": frozenset(
        {
            "ValidationProcessResult",
            "run_bounded_validation_process",
            "run_step4_readiness_validator",
        }
    ),
}
_GOAL_EXECUTION_CONTROLLER_IMPORT_CONTRACT = (
    "read_goal_held_bytes",
    "run_goal_planner_validator",
)
_GOAL_HELD_READER_DEFINITION_DIGEST = (
    "8343857c04fadb01eaa9a66c03aad76efec3d31f371c38b505fc7aef16d1002b"
)
_GOAL_HELD_READER_PROTECTED_BINDINGS = frozenset(
    {
        "read_goal_held_bytes",
        "read_skill_bytes",
        "run_goal_planner_validator",
    }
)
_REPOSITORY_EVIDENCE_ALLOWED_IMPORTS = frozenset(
    {
        "DEFAULT_MAX_FILE_BYTES",
        "DEFAULT_MAX_PATHS",
        "DEFAULT_MAX_TOTAL_BYTES",
        "DEFAULT_SNAPSHOT_TIMEOUT_SECONDS",
        "REPOSITORY_EVIDENCE_SCHEMA_VERSION",
        "open_repository_root_anchor",
        "require_same_repository_mount",
    }
)
_CONTROLLER_STORE_ALLOWED_IMPORTS: dict[str, frozenset[str]] = {
    "scripts/goal_run.py": frozenset(
        {
            "ControllerRunArtifacts",
            "GOAL_RUN_COMPONENTS",
            "canonical_repository_root",
            "controller_lexical_absolute",
            "controller_process_id",
            "goal_runs_root",
            "legacy_goal_runs_root",
            "open_goal_run_artifacts",
        }
    ),
    "scripts/apply_run.py": frozenset(
        {
            "APPLY_RUN_COMPONENTS",
            "APPLY_RUN_MUTATION",
            "CONTROLLER_O_CLOEXEC",
            "CONTROLLER_O_CREAT",
            "CONTROLLER_O_DIRECTORY",
            "CONTROLLER_O_EXCL",
            "CONTROLLER_O_NOFOLLOW",
            "CONTROLLER_O_NONBLOCK",
            "CONTROLLER_O_RDONLY",
            "CONTROLLER_O_WRONLY",
            "ControllerStatResult",
            "MountResolution",
            "READ_ONLY_EVIDENCE",
            "RUN_REPLACE_QUARANTINE_DELETE",
            "active_repository_root",
            "apply_runs_root",
            "canonical_repository_root",
            "controller_atomic_write_bytes",
            "controller_atomic_write_json",
            "controller_atomic_write_text",
            "controller_directory_entry_matches",
            "controller_chmod",
            "controller_close",
            "controller_dup",
            "controller_effective_uid",
            "controller_entry_exists",
            "controller_environment_value",
            "controller_fchmod",
            "controller_fsencode",
            "controller_fstat",
            "controller_fsync",
            "controller_home_directory",
            "controller_lexical_absolute",
            "controller_listdir",
            "controller_lstat",
            "controller_locked_directory",
            "controller_mkdir",
            "controller_open",
            "controller_path_is_mount",
            "controller_path_normalized",
            "controller_path_real_normalized",
            "controller_process_id",
            "controller_read",
            "controller_read_bytes",
            "controller_read_json",
            "controller_read_text",
            "controller_read_unvalidated_bytes",
            "controller_regular_entry_exists",
            "controller_regular_metadata",
            "controller_require_mount_assurance",
            "controller_require_same_mount",
            "controller_resolve_mount_identity",
            "controller_rmdir",
            "controller_stat",
            "controller_strerror",
            "controller_tree_is_private",
            "controller_unlink",
            "controller_unlink_regular",
            "controller_write",
            "legacy_apply_runs_root",
            "open_controller_runs_root",
            "open_controller_trust_root_fd",
            "register_active_run",
        }
    ),
}
_POWERFUL_CONTROLLER_STORE_CALLS = frozenset(
    {
        "controller_store.controller_atomic_write_bytes",
        "controller_store.controller_atomic_write_json",
        "controller_store.controller_atomic_write_text",
        "controller_store.controller_chmod",
        "controller_store.controller_close",
        "controller_store.controller_directory_entry_matches",
        "controller_store.controller_dup",
        "controller_store.controller_environment_value",
        "controller_store.controller_entry_exists",
        "controller_store.controller_fchmod",
        "controller_store.controller_fsencode",
        "controller_store.controller_fstat",
        "controller_store.controller_fsync",
        "controller_store.controller_home_directory",
        "controller_store.controller_lexical_absolute",
        "controller_store.controller_listdir",
        "controller_store.controller_lstat",
        "controller_store.controller_locked_directory",
        "controller_store.controller_mkdir",
        "controller_store.controller_open",
        "controller_store.controller_path_is_mount",
        "controller_store.controller_path_normalized",
        "controller_store.controller_path_real_normalized",
        "controller_store.controller_read",
        "controller_store.controller_read_bytes",
        "controller_store.controller_read_json",
        "controller_store.controller_read_text",
        "controller_store.controller_read_unvalidated_bytes",
        "controller_store.controller_regular_entry_exists",
        "controller_store.controller_regular_metadata",
        "controller_store.controller_require_mount_assurance",
        "controller_store.controller_require_same_mount",
        "controller_store.controller_resolve_mount_identity",
        "controller_store.controller_rmdir",
        "controller_store.controller_stat",
        "controller_store.controller_tree_is_private",
        "controller_store.controller_unlink",
        "controller_store.controller_unlink_regular",
        "controller_store.controller_write",
        "controller_store.open_goal_run_artifacts",
        "controller_store.open_controller_run_directory",
        "controller_store.open_controller_runs_root",
        "controller_store.register_active_run",
    }
)
_POWERFUL_REPOSITORY_IO_CALLS = frozenset(
    {
        "repository_io._controller_canonical_root",
        "repository_io._controller_directories",
        "repository_io._controller_inventory",
        "repository_io._controller_path_kind",
        "repository_io._controller_read_bytes",
        "repository_io._controller_regular_paths",
        "repository_io._controller_root_proof",
        "repository_io._controller_snapshot_paths",
        "repository_io._controller_validation_cwd",
        "repository_io._controller_validation_inventory",
        "repository_io._controller_workspace_proof",
    }
)
_POWERFUL_EXECUTION_CONTROLLER_CALLS = frozenset(
    {
        "execution_controller.read_goal_held_bytes",
        "execution_controller.run_bounded_validation_process",
        "execution_controller.run_goal_planner_validator",
        "execution_controller.run_step4_readiness_validator",
    }
)

# Most Path method spellings are unusual enough to reject on any receiver.  A
# few names are common on unrelated types; those are rejected only when the
# receiver is proven Path-derived by construction, assignment, or annotation.
# This keeps Match.group(), str.replace(), and Evidence.exists from forcing a
# huge capability allowlist while retaining fail-closed handling for real Path
# receivers.
_AMBIGUOUS_PATH_METHODS = frozenset({"exists", "group", "replace"})
_UNAMBIGUOUS_PATH_METHODS = _PATH_METHODS - _AMBIGUOUS_PATH_METHODS
_CONCRETE_PATH_TYPES = frozenset(
    {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"}
)
_PATH_INTERNAL_MODULE_ATTRIBUTES = frozenset({"parser", "_accessor", "_flavour"})
_DYNAMIC_IMPORT_SYS_ATTRIBUTES = frozenset(
    {"sys.meta_path", "sys.path", "sys.path_hooks", "sys.path_importer_cache"}
)
_DANGEROUS_NAMESPACE_ATTRIBUTES = frozenset(
    {
        "__base__",
        "__bases__",
        "__builtins__",
        "__closure__",
        "__code__",
        "__dict__",
        "__globals__",
        "__mro__",
        "__self__",
        "__subclasses__",
        "__traceback__",
        "ag_frame",
        "cr_frame",
        "f_back",
        "f_builtins",
        "f_globals",
        "f_locals",
        "gi_frame",
        "tb_frame",
    }
)
_DANGEROUS_NAMESPACE_NAMES = frozenset({"__builtins__", "__loader__", "__spec__"})
_DANGEROUS_NAMESPACE_CALLS = frozenset(
    {
        "sys._getframe",
        "sys._getframemodulename",
        "sys.getprofile",
        "sys.gettrace",
        "sys.setprofile",
        "sys.settrace",
    }
)
_DANGEROUS_BUILTIN_REFERENCES = frozenset(
    {
        "__import__",
        "compile",
        "copyright",
        "credits",
        "delattr",
        "eval",
        "exec",
        "getattr",
        "globals",
        "help",
        "license",
        "locals",
        "open",
        "breakpoint",
        "setattr",
        "vars",
    }
)
_DANGEROUS_BUILTIN_ATTRIBUTES = frozenset({"__import__"})

# These are complete-function AST digests for reviewed controller-only
# descriptor I/O, owner-only trust-store I/O, fixed runtime probes, and bounded
# child-process launchers.  They are deliberately source-specific and must be
# re-reviewed whenever a protected body changes.
_APPROVED_CAPABILITY_DIGESTS: dict[str, frozenset[str]] = {
    "scripts/repository_validation.py": frozenset(
        {
            "2f7e9cc9dbdf080b0d3a708ad64cf644875fbea94fb4d92e7bdb9885e3e43dcc",
            "a70ef08bc3ba2c8e16be0c30b2450f06957fe57e5b0111ecc6f9f5dda4d2a75b",
            "b2a3376d36183aef099da7a1206c02d20b4fff555a469de026de25a8eb4794f5",
        }
    ),
    "scripts/goal_run.py": frozenset(
        """
        06d632f54bb692c01847e97116e1e81be24a19052c71eaaf57f8fadab1ae9022
        092f8ab583aebbb8d84a67cf85aabdb11898ff6df9c86d4e2928cf4b9c0ef925
        1e701f29e9066fdba06897f9a8325fc191ab78ba355740d10283c157fcb0ccf9
        2340af97bb1c7265a8b4ef321d540154fecf6b85e747776c690e6e88eaefbbbb
        3d6d48485d3e6e3fa3bc73de4e816b9a4f776f220fb54516e31eb8f72d764b5e
        4aed7acd2a6c25c41df631bd6308a3f70bfaaeac504c99b6ae39aff9a5e7c21c
        4d43b64b052825de705f9086d2898e5ecc02321eb895457b372595d669287869
        51c7fa9bf7cd4f9df4fcc9ca92babb462e6ee4eb95a3ec7ece27f76bd648bc09
        567b844caf5443de6bb65c862bb93412d6aca0fd5370f81dbbf881dfe9217f4b
        5bae3c700f04c54b6906ebee4ea9f871724c848bb1ee9511bccee6b3e071b5cc
        5d27b1e2cef3b5494a7d57dd41ad9b8be56644b5cc922056dd1897aa5038f310
        6954a9ef61f2200043ac24c0e98d6fd132db9c57112307a9d58edc2231d31cc7
        79d808aec23c9ea0553e0324992cf97ed7eef883d46c05a86684d09cfc3d259e
        8343857c04fadb01eaa9a66c03aad76efec3d31f371c38b505fc7aef16d1002b
        83565187f71a830a77ad564f85a8fbf6829754bff97237e0e8f58a8f24d5a8b7
        8437f4e911c1864d31735e9c1666254e557805132f31dc37db0706d23b335ee3
        8467c75c5377476e772b18275771cfe686dbb84a7e15ba5a8bf263b8e2026445
        8470912a9606a878fff87409cccdccf3bc77ddc79000123dd0fe8aefb5929c02
        874fc37f8b0f60cc63fd23c8e49c9e8fae441ce2b1d0386c0e8483504f1354b4
        8baaa5fcd7ea3072f955ab31577e11e3a40bf0409c35b7671b47de48b7cb07a4
        8c6770897b1145fcf4669abfb35fdb311db7016106f11c1c4d262a98679256ce
        8cfe95b0dbebe13cec7bdbba437694cafc6b659fb7cfb0ac36500b3f08dda64f
        994e4a15630a4e495020b231ff84541d3b77a66109436195896877a746ce4a36
        9c389855fa067e14f89915285454ed2ce9f2be3744366ac4ace303f491c7025c
        a3742d9d810d4d7c2ad5843a8d7e2226072375c4c8d91a10b89dfa8f37ca01ff
        a69d4695600983de6eb7f6efb83e6653a6c28666adece0c5b21fcd9e33ff8d54
        c5372b363c65a9295a35ac2becb055fb1ec70764a4420f8cbcc8b9574c81b115
        c6021fba2fc0500d927a934d550b639f3ad63899574aa1238f69906c4e92e4aa
        d89f03cb1f2ee5fe303dd37e0e95eb15419e05a3bf2e59c047433a140d72c64a
        dc363b61075404f2a3742b87bb332fa12d51f990e5c3ccf8e0e92c4ecfbcc7d6
        e8e6689c5cfa0bcdd233bea119fe46bb5c37e96d5bc42f00c43475040e9a5e21
        ee14e4575cd9c0e1d75fef8b8b22a026dfa2d401f930505dfe7d9563c8b33847
        f229dae135cb73802b5995ae20e02a8de4d6f9d7cb326cb71e264a08854754ee
        f3dde1615ef249067ea1ab3f50e0aa6afd5b7354cdd1861759c8203c727abba6
        fa70cfcc9ec66bd3b8add3bb16e50bc5d4c2b0bfc586bf535452931baf2bb908
        """.split()
    ),
    "scripts/apply_run.py": frozenset(
        """
        0209ba0417aab01241b720c74c157353801fd86a92c37261260a4cad2de6b586
        064270f2f43721d17c02647cf253e17ad0ca2650ad2a65423a93221354b1cb17
        0679aa5bf2e719391dbc3aeeaa15e8932d8417455ae2960bd31d46b3a33b84eb
        085ede08158b682b96e5b666872e1136cc4ecca9b802c3874a101ad9477d2b1e
        08cb0f187a595c8bcb323e2c7325ca793a97ea02270277e56eb0f96cd5682c81
        0a2d2ef15c4c577f96e2dc2f1ff11e190f3eb42abed05af77950788355e38f50
        0aa6d305545d72de852819516b23ef23c6baef5ec9d3a3ae2c5a6f016ae66b74
        1969be20a06b99149223c2a288b317ea02dac58dcb72cdeccc540df53d243a6e
        0f9dfe5b3ea3402799e2fb6ecefaaf260c2733b89253b687b1d8b1db79ddf5ea
        13326a54c53eff2eadc17a83177b7297133998942da73766e95d2b10ca9b9b66
        1429641eef3d9b72000e043104c4db837cd80362e47d9b9945791b2684c9c967
        14a731d3a3afbe093d934a89b8a0f81e74b1690fddf6cfd1b477b29903b2b560
        15338c1cc1506816b63522e317733465ab3e037436602b45db25439f1d978230
        1534fc4ca1747976dc6c0541d09d1b99121dda5289b6433257d7599a35414ec6
        1aae2e659707c2ef324d4bc6c57383bf625bad05fedd901d4d4df502eb9ffb13
        1b4c7efd8a59e2a143664151a6f6f0a4bd6a33572580fad9f9a36a63a18d724b
        1c7064d03f6d8aa5a9d84c14b3606d34bcfa825f32ef1cbfb31f54a8fad42b57
        2480b99a3cc104a2eb792119c3ba95d4733643539d60cf1c93847129c20bfd91
        25714a7e81bca1d4e3b61fe9087345759e7b9b31bed26eed4fa8f67cc20545f7
        266e3309fd3287bed17ccffd6483dbf4f5b26f1067f30d69e9fbce157d6259de
        280b19c6041f901beab1bb0339e565b7d3ebd9fffc3fca00e337c34324ba2402
        2bd0cdf1a1d0ff45dbf9b08c1f4086d2b914d45104a10c417d4e6ff18d964704
        2c21d6d2243faf12d7f4349b41e7d002bc1819f2ddb0eced2c87fa64e4ce12c6
        2cbb6debfee7eb016ae95c388b5aaa1d4f0595795897c54e25f43a956ed32649
        2eec2e34f1896dbfe2cf4545db1deda6b8fd21cf9de47846d51858991927afed
        30eb0eae9400bab03a49863dad562319793791cef676b9289750e796e15b7a99
        31bce77b1b14709eb8a26e4af17540bccc879a18f284825c69f5b093cce14a40
        34343fa81b9d3ec86e2f216a99b9d193b5da476cf38e6f0a08199001364c9997
        355ba842cdf3e21095258be4be1b21881d9bb27adb2746cee5814d892687c160
        363a61507686677c945e7dd3f2d4597d7356b40a2d78cfd297352918c9aae640
        37bea72cf88e13da89ded91f1f832489abad61dd0f1f473253392f24b3307aeb
        3a83aba6ee46c3e5b8675b941c9c0921e2a742c357203b55df73585559a0a229
        3bfd7630237a02e667f1365575c30373e404100ebaa360a586b1933f87545ec7
        3cce9a86e4c66f12fffcde2ce29296a71cba982708422fe730f72e840168dcf7
        3d5aa455c7278e6c06eefaa095f40dd373452d9fa450a69dd8a33443ff8329c1
        40d922e8bdaecc7edb186bb56432ff5f2233fbd841916122585344839634a33a
        410140f82f7b30263ad9d089bb628c5452857faf3c4928557677b90a5c481e0d
        47602ccbaa1e0626f8dbdcf3cb967a5ac33ef08ff2e787dec1bf1877fdba0cb4
        4940cda44423f9143618a077c58ae6e3e9ca9f8ed7d6deba2d0477eeca1992f8
        4983cf739bb07f6004d99f48ff39f5682092029d65ac64fe1fffa2bef6f8ccd6
        4ce71d7048b4127a668d2b5856ed790189a247a1e9d3d57b4852b6e96b575ba6
        4dee9bd120e55c891507eb9d3b48a72096015684f33e56ae0242e49cdf459576
        50d2fc83ad7c9e12724fb69878aefecfdb982b3abbcd848e9c6bc13ba917ccdf
        51c7fa9bf7cd4f9df4fcc9ca92babb462e6ee4eb95a3ec7ece27f76bd648bc09
        523784c01b84372d9bc2388700548dee5c5390f4f028c6362cc246102f6e9b25
        527ea3c760d28c13f4b8a54ebd06bda82a1862310fac09558b7ed45ae8ebb5b7
        52fb7a8f5021b4c4db9554dd3f19f8f596b98440e5eb46e9c358211b027b35b2
        557c8ef4e798cbcafa697f22a555a8f8ea66ba597cdd4154ba48be4bec10c59e
        58d00828fe16d4d1f16fabf60e1defed677acb1a2fb10f896a80cbf18140ecba
        58fbb92b0b08d26b80f302311363e836f1df1a53c60f560b2b992bdd6a23a0b3
        59a21cb3b74a5eabb942f1247b2521eca3ca280ff7f6e9f09dd6da995b93e55d
        5a323036370300afe46c31429480bcddeea7576ffa521fe2242dfeb47f4ba650
        5d4679e616e4b4619bef5441d8c92ae926358ceed7c818125865f17383020a12
        5eae9c3acabd0eb5fe05970d70bbe622406021203b48550472ed941e1437a8d8
        5f171c6a8a4a9b6c95b2e98d7ced2e5d9895da2ccb607ea46907772ced3d589e
        5f3eee1c8546de9c8f101e702884f11ed413a4a0238bc98b468727444e99c4d4
        6917fda49a4196e885937ca328e1489396b6b1f10d8f4eb69026f55ea1dd1a06
        6b5b72499d99c2985310692758d760ddb315c8239b36bbdb6ca855c6c2cc0f0d
        6c27851c138446771d3bcb65ea73dcced06c72ed71e23261bef40ce6db95830e
        6ccaa42591ddd25e55741e90b47b4a794fbdd77a1c50cd9be22937b3bbce1167
        4ddab2529ec785091b5339fc75f6740c7f75632cac44c016075b339cc4d6a3e1
        71f77fd9c39a141f063df6dec4b285e407838d0c02f34c60db86e2431dc6ee9d
        762cdf1d4bc4231c078c15036c16add1a765fe0f29d8a98f7b3a22608de17479
        78fde9042543815c8f4c1cda81d279febe4f3a902541a141eb4139d703453642
        79c63544833b484f0d2b743c095288aa28c16622693313b0d5220a253602bd08
        7c6d1dfa67f864862d7780830daebf5d7f66aec43ab4da929ecbded2c04c9fe8
        8467c75c5377476e772b18275771cfe686dbb84a7e15ba5a8bf263b8e2026445
        854ae549ac5d796cfd7131014d888340565f2c3595ab9df71a45adc8f7b78d7f
        86282801acee3ae6a5301176701c6ab1bde56cd3c9f36b26404322bc660df9cd
        86c90e9ddcfa216feb29febb9b1b5cb5e65687a16262d1e8d2040cef1b6ad626
        86df21a3f71b7aa49a95bf0de50a5e08404586db92f4d7bc80ac44c33be57b8a
        89ec67eca989b32bb08ccb78959463c4b62985754d612f91dcc83d4476fcdfef
        8d3216be41c8095cb0934d665859bb193abaa3883025dec9622f91681ff8191c
        9166f3d9745bab1b83c173e81fff6eed0903c478e7fad71dba7a17e0973d7c1f
        919ea87f34c1dcb6a4c2cb145a3141f266049cff366530c70fa16ec9c96a305e
        92ac8920a017511364f1dafc4c6db24466de6bdbb6c81b6c77050b9584cff1d4
        961217798e264cd305cab10ed7addfddb9ede91e747e83d444942b25e50aa5b0
        98323fc302a306e8c83d75a8f1892e8d73b21c868fc04a58f4a479beb97f4e31
        9cb794f004a7d414c132b7f767fd897b72d11aa481c639a7921da0f5ed35596f
        a1eccd878687d687a5a0385b3e13a58b546e2da0a86af3a20f1bb72ae84a83b2
        a32d20debf9ba5a504717ab9985e67454b7c6099e6fc9535ec31b74b83d032d9
        a38f61fc44f64ecb30565b0b29d80d76426343f97ed46df8f54018cad8b936fd
        a3d9d31c3ad24ecaaa821e8cafeeb032093432a055b6694fc9d63ae1569a45c0
        aa13d1e05d72d5507b46ef3e9d1b60461a41a791978bf2ee765780d8b5930996
        51cc15e6f1e73276c5fa20fc160c2373066441adc7973071c46d35d206f5de5d
        ae9df518ebe95d640db5a97731487c0bb3914ee3a3a72a4e96f60017feaeaa40
        b40867ae4fc6580ab016e5f919ec2521a6bebd272553e0c16af9848e84574a4f
        b4851c8e2db2c344013142297b5dc082e098385ba421b4791c4999eadab23040
        b5001b94aea8912ce03a14616956c8b63f141bee268a0d567c9541ec0111ae56
        b5468f2a02f01f8aee6357c322016bdbdc284f1d5365b9da8b8aa2c9ae6f48d8
        b57ac217c451e7ac783da208c5ef2344cfa0796e2de8467add628fe51eebdfaa
        b9d58c98ac2c19e950c8731b60910ef4c7583139731700569eec27a1f21bb670
        bc781665c541d544d8062610b5e50296d19a493404952bff75ddf5b97b938fb0
        bd96ccad6263c6ce9d80eed55b44a0830c8459d36f48f891f4263384e0c61240
        c39cc2412c36afd050d9efee75e96406b7dab98aa2cd119bf2d9b603f511fac8
        c585dda9b43b46aff8a6fefc178a6f2fde5633e7b7ddc1078fbdc9db9a8b6675
        c7832982577f8170281384a30b5538d2b12223bb49dccd0d099ceba94fe18a24
        ca3354eacedc738f0520084e166c2fa23ae3e09e2eeac088daa1a7f80967e4f1
        ad88453b3febca019628f6e9bcdaad57800dec9be028047e4db7c03fb8ac4fea
        cacc6ea9ca34a5367188ee588b834ffa44fc2d54bfabe559c67bc0a7652f4cf5
        cc0659e99f9a9c0dc5ef442e451de1a6846bbf4f748cacd70de38f3b8b44aabd
        ce384e4d44934957e6751ab0edf290e492990eb67879eb01b3968db44a741843
        cec45a7c97d342d5b76ba28118277c816af0e40ed4a61e661e8124cff54cda0a
        ceeced2ce11d7a8d51c0bce41820f0e712ed3507fb7002ce67f67ee5d1c2f933
        d0697a03ee327e054d06ea04109699c58a3ab971717efe7fd48c511fc70e6061
        d5047b52b89d6598abd07c73c67392d7cea7104d3bd1fc09b3bdf17937db5138
        d5d188362fbaf37a9b37099e33f21ace9a10915948ba2eae5a15b15b7c85c796
        d89f03cb1f2ee5fe303dd37e0e95eb15419e05a3bf2e59c047433a140d72c64a
        db0993663ad414628d07a1872152e0db852ad81e9c8b799f14c86a8a358748e1
        db65dca97ba449a58029c499ffc2b55bb8d27ea2c6787f2408983b46815b3701
        e162c0fe9ff8e0f217e3b93e6b40c1942febc237535ccf3a8edb65e6e792b5eb
        e32c50266b5c6e9434d0ad3c0a1a7b27d947d0ff7bd052c021ad67eec9834d6c
        e3782d9feee7290149e82da6a5cf107bae1ae6d0498932825f1a5b21652558a0
        e7ab24912de7727a4b272e0bb80d8638a2f92e2bdea692977bc14cf58da1f58b
        efe55dcda080235f023ad8beeb3ae4c11cda1b7049fd13c19eb13b2c552c2c62
        f36f731473860c9e1e37208b4b6773123941e81f13b0e05e0ebd21e169663613
        f38a278f3cd3c7b72c6a65ca0a5ce6d7845d16169a906138f12dbdde7e00a002
        f88ae787a6baec7e093c95be998b420b9bc046608490f68a8dac2316e24a1701
        f9f06fa2aec4052c265e4ae28fe0ec766055acc22760903f13ddf3252d5d052e
        fbd829a464fb50b65ad7aa535bd7f514b7e33d14d02d19afb32a4de01953d9c8
        fee8eeb257f38249326fec3eea34d89105c9c48ebe4e25d56febb8e9fce3c2c4
        ff4f3aa3abee76669129a5c1b9282651152df04ed73b205a3a068e41c6d4849b
        """.split()
    ),
    "scripts/validate_planner_docs.py": frozenset(
        """
        088a1e67c504f0b8b91cd25386fb5209ca7079e146afc92ef38b1c1485633cea
        0f55209acfc2702df074a28dfebe126bc6845bab74e54ae0c8cb923b4988a51f
        049c7596058920fadbff51746cbed89eefa2cf8e15b051edeb381e805ccf742b
        19a075bdabea8c0be704dbae0ba88398344878d68241f8cc5d73da544b9fe5df
        1e85bfd95bfbbc08038e4199d9b0643a9e2bc052a398501aa735680c03961998
        27e245bf1604cf73e16855cb4e2deaba01a5d2f30803cb0dfb68b1225a3b4e4f
        3f51fd758bb2e1c3a3182aac33311829f4cb236dc8b0c46263345f0c9578b106
        3fa0ead84ce214c2c5f162538f2bc6c747a2509ffb360b5c28b5121b0e576e54
        4c9c85900698f865405bb22f4e7f2d00a9e4be86a6aa55a5b6797b6141affaa6
        4f3416bfb0f7ff46c2d69b6200be0c128726d4284c59bc1814f04ca41f9330e0
        4fdb56b27c5224c564e8835baf696ba5fda18a6d51d4bd1e92dd1063a893350e
        68bb27e178e6c8d40643289c8bf36bc685706f5628968993f44d0e161cd6c670
        6f7c74429bee03d42674eb00e4df35a0a79dfc8f3c3d10b4105f1bc0e7d69ab6
        740abb5b7751b768eab61b1dbab469a965259a5df2befa8ceefafde9f93bcb51
        7fbb987a5a68f553564fa9ea084e5e7faff18950190989936fb30927a0bd27e2
        83c4f79d89453d08fbec4cbd04b831816f27704f1225c4dd294dc6691a3c1f14
        890ba2fa148adfceff63cec0df387e55268d046f799846a6568d0cf45942b7da
        8fec25884994470d027c9358a3d45dfcfe4fe6647ee4e00c5cb4b6774e21523c
        93ca6f080e88135a21fbb0b0db64176249112a6288e913743adc89e6d7309c60
        a0f41a0b6f16dea68cfb7e292e8b321aa8d153920aeeb37e39d1d2ab4c96d4d2
        a750c5aa949389fbf5eccbc0aa4de87ee58d5c1c33b13101042d2c3165d92dd1
        af5e367e7bbf5a07f8bc67f13dd143997df2083cf13d934cec720f0af7819e18
        b759aeb49fa1f079a650293ec4270b7a966a62980763e3f2ff70507e37736275
        c0e084dd9741981ea1fa0d4fdc9ec497d9a714a1fb0b9b6fbda6bb7fddf46ff5
        d7b7479a1642107828a634bccae1846960ce2dd975f4db9bab55aefa8b613184
        e5c74481063580f20bc4f79d8562c3b654a64a1885517d4a133a95365f8e4652
        e8d2b4cc79485c80ea0fcaf71bc21fc4d24e2afdf842c697915e6d0c2b439d6c
        ed26a794b58a4831bebdd86d365cba0b9e846fe4aa5c9b7c2632eb41d9f7447a
        ee6c2de56ee295af9005af6ff05d964d66ea9ccaa5b8f0e2f0424c167fe24d6e
        ffc2a27d369cbf1e593574afaa4931287e049281a7199e2d174a4a2376e80d36
        f38579c6e1ba9f9e58a61493aa591420d678a69af2abd27ec7262c1c309f86a6
        """.split()
    ),
}
# Complete-module pins are the authoritative extension gate for each protected
# consumer.  Granular capability and taint checks remain defense in depth, but
# no insertion, post-class monkeypatch, or aggregate laundering may become
# trusted merely because a point analysis missed it.
_APPROVED_PROTECTED_CONSUMER_AST_DIGESTS: dict[str, str] = {
    "scripts/repository_validation.py": "dbb68b0da798b59f4399afc528731b7fc31faef0c2a10ccdcf723a4ad8e7be41",
    "scripts/validate_planner_docs.py": "e8fd94589fd485712df9a8a5d5e55d883db25dfbaf02fc47b0147010d86c4b0d",
    "scripts/skill_launcher.py": "ee4e60ea897a72278f68c8155682709803f340738adfae2e9ed84791e8b53124",
    "scripts/skill_root_authority.py": "2d8fd178fa8e783198d262e7338392af3c04a1d8baf26bf4daf7bc5339393681",
    "scripts/goal_run.py": "c56df0d667fc179d9ab4fac9fcbce1a83b0949a2e077b8233eeb86b6f02baef1",
    "scripts/apply_run.py": "4e48e31696bc560dabd73b42487b0c81d21c967b9e61592bc2c240d72770793c",
}
if set(_APPROVED_PROTECTED_CONSUMER_AST_DIGESTS) != set(PROTECTED_PYTHON):
    raise RuntimeError("protected_consumer_registry_invalid")
_APPROVED_VALIDATION_STATE_CLASS_DIGESTS = frozenset(
    {"741872287a767e732534396b41e7477a69c88fb72e5d783c58b4016d74f16f55"}
)
_APPROVED_CONTROLLER_STORE_AST_DIGEST = (
    "2f11056f554940e5b269caf2a958e52b088761c5f4f2b42d4f1056ca15cfa578"
)
_APPROVED_EXECUTION_CONTROLLER_AST_DIGEST = (
    "f31a63017831f9ccf799887ba137d9c2fefbc1d862c019faf88675d25b305b7c"
)

_RAW_COMMANDS = frozenset(
    {
        "cat",
        "rg",
        "ripgrep",
        "grep",
        "egrep",
        "fgrep",
        "find",
        "ls",
        "head",
        "jq",
        "tail",
        "less",
        "more",
        "cut",
        "sort",
        "uniq",
        "strings",
        "xxd",
        "od",
        "wc",
    }
)
_MUTATING_COMMANDS = frozenset(
    {
        "apply_patch",
        "awk",
        "chmod",
        "chown",
        "cp",
        "dd",
        "install",
        "ln",
        "mkdir",
        "mv",
        "patch",
        "rm",
        "rmdir",
        "rsync",
        "sed",
        "tar",
        "tee",
        "touch",
        "truncate",
        "unzip",
        "zip",
    }
)
_INTERPRETERS = frozenset({"python", "python3", "perl", "ruby", "node", "bash", "sh", "zsh", "fish"})
_DANGEROUS_SHELL_BUILTINS = frozenset({".", "eval", "exec", "source"})
_WRAPPERS = frozenset(
    {
        "busybox",
        "command",
        "env",
        "nice",
        "nohup",
        "setsid",
        "stdbuf",
        "sudo",
        "timeout",
        "toybox",
        "xargs",
    }
)
_PROFILES = frozenset({"intake", "step1", "autopsy", "step2", "step3"})
_STAGES = frozenset({"step1", "autopsy", "step2", "step3", "step4"})
_WRITE_TARGETS = {
    "step1": frozenset({"Planner-docs/Main-Planing.md"}),
    "autopsy": frozenset(
        {
            "Planner-docs/Autopsy.md",
            "Planner-docs/Project-Ontology.md",
            "Planner-docs/Project-Comprehension.md",
        }
    ),
    "step2": frozenset(
        {
            "Planner-docs/Sub-Planing-Index.md",
            "Planner-docs/Planing-Ledger.md",
            "Planner-docs/Step2-Blocked.md",
        }
    ),
    "step3": frozenset({"Planner-docs/Sub-Planing-Audit.md"}),
    "step4": frozenset({"Planner-docs/Planing-Ledger.md"}),
}
_PHASE_PLAN_PATH_RE = re.compile(
    r"Planner-docs/Faz-(?P<phase>[1-9][0-9]*)-Plans/"
    r"Faz(?P=phase)\.[1-9][0-9]*-[a-z0-9]+(?:-[a-z0-9]+)*\.md"
)
_PLACEHOLDER_RE = re.compile(r"<[A-Za-z][A-Za-z0-9._-]{0,63}>")
_PLACEHOLDER_LINE_RE = re.compile(r"^<[^<>\n]{1,2000}>$")
_ACTIVE_SKILL_ROOT_PLACEHOLDER = "<CODEXQB_SKILL_ROOT>"
_CONTROLLER_STDIN_REQUEST_SCHEMA = "codexqb.controller-argv/v1"
_ISOLATED_PYTHON_PREFIX = ("python3", "-I", "-S", "-B")
_LAUNCHER_PATH = f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/skill_launcher.py"
_ACTIVE_SKILL_MD_PATH = f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/SKILL.md"
_LAUNCHER_CONTROLLERS = frozenset(
    {"repository-io", "planner-validator", "goal", "apply", "doctor"}
)
_CONTROLLER_PATHS = frozenset(
    {
        f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/apply_run.py",
        f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/doctor.py",
        f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/goal_run.py",
        f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/repository_io.py",
        f"{_ACTIVE_SKILL_ROOT_PLACEHOLDER}/scripts/validate_planner_docs.py",
    }
)
_CONTROLLER_ROOT_ARGUMENTS = frozenset({".", "<project-root>"})
_CONTROLLER_RUN_DIR_ARGUMENT = "<run-dir>"
_CONTROLLER_GOAL_RUN_ARGUMENT = "<goal-run>"
_CONTROLLER_TASK_ID_ARGUMENT = "<task-id>"
_CONTROLLER_AGENT_ID_ARGUMENT = "<agent-id>"
_GOAL_CONTROLLER_STAGES = frozenset({"step15", "step2", "step3", "step4"})
_APPLY_CONTROLLER_MODES = frozenset(
    {"direct", "subagent_serial", "external_superpowers", "no_action"}
)
_APPLY_CONTROLLER_ROLES = frozenset(
    {"implementer", "task_reviewer", "security_reviewer", "fixer", "final_reviewer"}
)
_APPLY_CONTROLLER_REVIEW_PHASES = frozenset({"spec", "quality", "security", "final"})
_APPLY_CONTROLLER_TASK_STATES = frozenset(
    {
        "PREFLIGHT",
        "BRIEFED",
        "IMPLEMENTING",
        "IMPLEMENTED",
        "TASK_REVIEW",
        "SECURITY_REVIEW",
        "FIXING",
        "RE_REVIEW",
        "VERIFIED",
        "BLOCKED",
        "NEEDS_CONTEXT",
    }
)
_APPLY_CONTROLLER_AGENT_STATUSES = frozenset({"spawned", "completed", "failed"})
_APPLY_CONTROLLER_ROLE_PHASES = {
    "task_reviewer": frozenset({"spec", "quality"}),
    "security_reviewer": frozenset({"security"}),
    "final_reviewer": frozenset({"final"}),
}
_DEFAULT_IGNORABLE_CODEPOINT_RANGES = (
    (0x00AD, 0x00AD),
    (0x034F, 0x034F),
    (0x061C, 0x061C),
    (0x115F, 0x1160),
    (0x17B4, 0x17B5),
    (0x180B, 0x180F),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x206F),
    (0x3164, 0x3164),
    (0xFE00, 0xFE0F),
    (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0),
    (0xFFF0, 0xFFF8),
    (0x1BCA0, 0x1BCA3),
    (0x1D173, 0x1D17A),
    (0xE0000, 0xE0FFF),
)
_INLINE_CODE_RE = re.compile(r"`([^`\n]+)`")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.I)
_HTML_TAG_RE = re.compile(
    r"</?(?:blockquote|code|details|div|li|p|pre|script|span|summary|table|tbody|td|th|thead|tr)\b[^>]*>",
    re.I,
)
_HTML_ATTRIBUTE_RE = re.compile(r"(?:command|cmd|data-command|value)\s*=\s*([\"'])(.*?)\1", re.I)
_JSON_COMMAND_RE = re.compile(
    r'\"(?:command|cmd|script|argv)\"\s*:\s*\"((?:\\.|[^\"\\])*)\"',
    re.I,
)
_YAML_COMMAND_RE = re.compile(
    r"^\s*(?:-\s+)?(?:(?:![^\s]+|&[A-Za-z_][A-Za-z0-9_.-]*)\s+)*"
    r"(?P<keyquote>[\"']?)(?P<key>command|cmd|script|argv)(?P=keyquote)"
    r"\s*[:=]\s*(?P<value>.*?)\s*$",
    re.I,
)
_YAML_VALUE_DECORATOR_RE = re.compile(
    r"^\s*(?:(?:![^\s]+|&[A-Za-z_][A-Za-z0-9_.-]*)\s+)+"
)
_FLOW_COMMAND_RE = re.compile(
    r"[{,]\s*(?:command|cmd|script|argv)\s*[:=]\s*([^,}]+)", re.I
)
_QUOTED_FLOW_ASSIGNMENT_RE = re.compile(
    r"[{,]\s*(?P<key>\"(?:\\.|[^\"\\])*\"|'(?:''|[^'])*')"
    r"\s*[:=]\s*(?P<value>[^,}]+)",
    re.I,
)
_XML_COMMAND_RE = re.compile(
    r"<(?:command|cmd|script|argv)\b[^>]*>(.*?)</(?:command|cmd|script|argv)\s*>",
    re.I,
)
_IMPERATIVE_COMMAND_RE = re.compile(r"^\s*(?:\d+[.)]\s*)?(?:run|execute)\s+(.+)$", re.I)
_EMBEDDED_RAW_COMMAND_RE = re.compile(
    r"(?:^|&&|\|\||;|\||\$\(|`)\s*"
    r"(?:(?:sudo|command|xargs)\s+|env(?:\s+[A-Za-z_][A-Za-z0-9_]*=[^\s]+)*\s+)*"
    r"(?:/[^\s]*/)?(?:cat|rg|ripgrep|grep|egrep|fgrep|find|ls|apply_patch)\b",
    re.I,
)
_LIST_PREFIX_RE = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)(.*)$")
_SHELL_SPLIT_RE = re.compile(r"\s*(?:&&|\|\||;|\|)\s*")
_SHELL_CONTROL_RE = re.compile(
    r"(?:&&|\|\||[;|`]|\$\(|[<>]\(|(?:^|\s)(?:>>?|2>>?)|<<-?)"
)
_SHELL_ASSIGNMENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=.*", re.S)
_SHELL_REDIRECTION_RE = re.compile(
    r"(?:^|[^<>])(?:\d*(?:<<-?|<|>>?|>))(?![=])"
)
_SHELL_DOLLAR_FORM_RE = re.compile(r"(?:^|[\s;&|(<>=])\$(?:\(|['\"])")
_SHELL_EXPANDED_COMMAND_TOKEN_RE = re.compile(
    r"[A-Za-z0-9_./+@%-]*\$(?:[A-Za-z_@*#?!-][A-Za-z0-9_]*|\{[^{}\s]+\})"
    r"[A-Za-z0-9_./+@%-]*"
)
_ENV_SPLIT_RE = re.compile(r"(?:^|\s)(?:-S|--split-string(?:=|\s))")
_XARGS_ARG_FILE_RE = re.compile(r"(?:^|\s)(?:-a|--arg-file(?:=|\s))")
_SHELL_PROCESS_SUBSTITUTION_RE = re.compile(r"(?:<|>)\(")
_SHELL_FIRST_TOKEN_META_RE = re.compile(r"[?*\[\]]|(?:<|>)\(")
_SHELL_BRACE_EXPANSION_RE = re.compile(r"^\{[^{}\s,]+,[^{}\s,]+(?:,[^{}\s,]+)*\}$")
_AMBIGUOUS_PROSE_COMMANDS = frozenset(
    {"cut", "find", "head", "less", "more", "sort", "strings", "tail"}
)
_SHELL_RESERVED_GRAMMAR_RE = re.compile(
    r"^(?:"
    r"(?:if\s+.+;\s*then\b)|"
    r"(?:(?:while|until|for)\s+.+;\s*do\b)|"
    r"(?:case\s+.+\s+in\b.+\besac\b)|"
    r"(?:!\s+\S+)|(?:time\s+\S+)|(?:coproc\s+\S+)|"
    r"(?:builtin\s+\S+)|(?:alias\s+\S+=)|"
    r"(?:function\s+[A-Za-z_][A-Za-z0-9_]*\s*\{)|"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\s*\(\)\s*\{)|"
    r"(?:\{\s+\S+.+;\s*\})|(?:\(\s*\S+.+\))"
    r")",
    re.S,
)


def _safe_policy_path(value: object) -> str:
    text = str(value)
    if any(ord(character) < 32 or ord(character) == 127 for character in text) or secret_match_locations(text):
        digest = hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
        return f"<redacted-policy-path:{digest}>"
    return text


def _safe_policy_symbol(value: object) -> str:
    text = str(value)
    if (
        not text
        or len(text) > 240
        or any(ord(character) < 32 or ord(character) == 127 for character in text)
        or secret_match_locations(text)
    ):
        digest = hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()[:16]
        return f"redacted_policy_symbol:{digest}"
    return text


def _exception_symbol(error: BaseException) -> str:
    candidate = str(error).split("=", 1)[0]
    if re.fullmatch(r"[a-z][a-z0-9_.:-]{0,159}", candidate):
        return candidate
    return "repository_io_policy_error"


@dataclass(frozen=True, order=True)
class PolicyFinding:
    path: str
    line: int
    symbol: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _safe_policy_path(self.path))
        object.__setattr__(self, "symbol", _safe_policy_symbol(self.symbol))

    def render(self) -> str:
        return f"{self.path}:{self.line}:{self.symbol}"


@dataclass(frozen=True)
class _SkillLocation:
    skill_root: Path
    plugin_root: Path | None
    plugin_expected: bool
    layout_kind: str
    requested_layout: str


def _locate_skill_locations(
    root: Path, *, layout: str = LAYOUT_AUTO
) -> tuple[_SkillLocation, ...]:
    if layout not in LAYOUT_EXPECTATIONS:
        raise ValueError("repository_io_policy_layout_invalid")
    exact_skill_plugin = (
        root.parent.parent
        if root.name == "codexqb" and root.parent.name == "skills"
        else None
    )
    candidates = (
        (
            root / "plugins/codexqb/skills/codexqb",
            root / "plugins/codexqb",
            "repository",
        ),
        (root / "skills/codexqb", root, "plugin"),
        (root, exact_skill_plugin, "exact-skill"),
    )
    found: dict[str, _SkillLocation] = {}
    for candidate, possible_plugin_root, layout_kind in candidates:
        if (
            layout == LAYOUT_REPOSITORY_PLUGIN
            and layout_kind != "repository"
        ) or (
            layout == LAYOUT_EXTRACTED_PLUGIN
            and layout_kind != "plugin"
        ) or (
            layout == LAYOUT_STANDALONE_SKILL
            and layout_kind not in {"plugin", "exact-skill"}
        ):
            continue
        try:
            with open_repository_io(candidate) as repository:
                if controller_path_kind(repository, "SKILL.md") == "regular" and controller_path_kind(repository, "scripts") == "directory":
                    skill_root = canonical_repository_root(repository)
                else:
                    continue
            plugin_root: Path | None = None
            plugin_expected = layout in {
                LAYOUT_REPOSITORY_PLUGIN,
                LAYOUT_EXTRACTED_PLUGIN,
            }
            standalone_conflict = False
            if possible_plugin_root is not None:
                try:
                    with open_repository_io(possible_plugin_root) as plugin:
                        plugin_root = canonical_repository_root(plugin)
                        marker_kind = controller_path_kind(plugin, ".codex-plugin")
                        if (
                            layout == LAYOUT_STANDALONE_SKILL
                            and marker_kind != "missing"
                        ):
                            standalone_conflict = True
                        if layout == LAYOUT_AUTO:
                            plugin_expected = (
                                layout_kind == "repository"
                                or marker_kind != "missing"
                            )
                except (OSError, TypeError, ValueError):
                    plugin_root = None
            if standalone_conflict:
                continue
            found[skill_root.as_posix()] = _SkillLocation(
                skill_root=skill_root,
                plugin_root=plugin_root,
                plugin_expected=plugin_expected,
                layout_kind=layout_kind,
                requested_layout=layout,
            )
        except (OSError, TypeError, ValueError):
            continue
    return tuple(found[key] for key in sorted(found))


def locate_skill_root(root: Path) -> Path | None:
    locations = _locate_skill_locations(root, layout=LAYOUT_AUTO)
    return locations[0].skill_root if len(locations) == 1 else None


def _annotation_mentions(annotation: ast.expr | None, names: set[str]) -> bool:
    if annotation is None:
        return False
    return any(isinstance(node, ast.Name) and node.id in names for node in ast.walk(annotation))


def _canonical_ast_dump(node: ast.AST) -> str:
    """Serialize AST structure without Python-minor empty-field drift.

    Python 3.13 added ``ast.dump(show_empty=False)`` and Python 3.14 made
    that compact representation the default.  Python 3.12 always renders
    empty list fields, which otherwise changes every reviewed AST pin despite
    identical source semantics.  Keep the 3.14 compact grammar explicitly so
    the supported 3.12-3.14 matrix compares one fail-closed representation.
    """

    if not isinstance(node, ast.AST):
        raise TypeError("canonical_ast_dump_requires_ast")

    missing = object()

    def render(value: object) -> str:
        if isinstance(value, ast.AST):
            fields: list[str] = []
            value_type = type(value)
            for field_name in value._fields:
                try:
                    field_value = getattr(value, field_name)
                except AttributeError:
                    continue
                if (
                    field_value is None
                    and getattr(value_type, field_name, missing) is None
                ):
                    continue
                if isinstance(field_value, list) and not field_value:
                    continue
                fields.append(f"{field_name}={render(field_value)}")
            return f"{value_type.__name__}({', '.join(fields)})"
        if isinstance(value, list):
            return f"[{', '.join(render(item) for item in value)}]"
        return repr(value)

    return render(node)


def _body_digest(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    payload = _canonical_ast_dump(node)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _local_path_return_names(tree: ast.Module) -> frozenset[str]:
    """Find local helpers that return concrete Path values, to a fixed point."""

    constructors: set[str] = set()
    for statement in tree.body:
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "pathlib"
        ):
            constructors.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name in {"Path", "PosixPath", "WindowsPath"}
            )

    functions = [
        statement
        for statement in ast.walk(tree)
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]
    discovered: set[str] = set()

    def function_nodes(
        function: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> Iterator[ast.AST]:
        pending: list[ast.AST] = list(function.body)
        while pending:
            current = pending.pop()
            yield current
            if isinstance(
                current,
                (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda),
            ):
                continue
            pending.extend(ast.iter_child_nodes(current))

    for _ in range(len(functions) + 1):
        changed = False
        for function in functions:
            assignments: dict[str, ast.expr] = {}
            nodes = tuple(function_nodes(function))
            for item in nodes:
                if (
                    isinstance(item, ast.Assign)
                    and len(item.targets) == 1
                    and isinstance(item.targets[0], ast.Name)
                ):
                    assignments[item.targets[0].id] = item.value
                elif (
                    isinstance(item, ast.AnnAssign)
                    and isinstance(item.target, ast.Name)
                    and item.value is not None
                ):
                    assignments[item.target.id] = item.value

            def path_value(expression: ast.expr, seen: frozenset[str] = frozenset()) -> bool:
                if isinstance(expression, ast.Call) and isinstance(expression.func, ast.Name):
                    return expression.func.id in constructors | discovered
                if isinstance(expression, ast.Name) and expression.id in assignments:
                    if expression.id in seen:
                        return False
                    return path_value(
                        assignments[expression.id], seen | {expression.id}
                    )
                if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Div):
                    return path_value(expression.left, seen)
                if isinstance(expression, ast.Attribute) and expression.attr in {
                    "parent",
                    "parents",
                }:
                    return path_value(expression.value, seen)
                if isinstance(expression, ast.IfExp):
                    return path_value(expression.body, seen) or path_value(
                        expression.orelse, seen
                    )
                if isinstance(expression, ast.BoolOp):
                    return any(path_value(value, seen) for value in expression.values)
                return False

            if any(
                isinstance(item, ast.Return)
                and item.value is not None
                and path_value(item.value)
                for item in nodes
            ) and function.name not in discovered:
                discovered.add(function.name)
                changed = True
        if not changed:
            break
    return frozenset(discovered)


def _ambiguous_path_call_signature(name: str, node: ast.Call) -> bool:
    if name == "exists":
        return not node.args and not node.keywords
    if name == "replace":
        return len(node.args) == 1 and not node.keywords
    return False


_LAUNCHER_ADMISSION_BASENAME_BY_PATH = {
    "scripts/apply_run.py": "apply_run.py",
    "scripts/goal_run.py": "goal_run.py",
    "scripts/validate_planner_docs.py": "validate_planner_docs.py",
}


def _safe_launcher_admission_node_ids(
    tree: ast.Module,
    relative_path: str,
) -> set[int]:
    """Recognize the exact early held-runtime admission prefix."""

    expected_basename = _LAUNCHER_ADMISSION_BASENAME_BY_PATH.get(relative_path)
    if expected_basename is None:
        return set()
    canonical = ast.parse(
        f'''\
from __future__ import annotations
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

from types import ModuleType

def _launcher_admission_is_valid(expected_basename: str) -> bool:
    context = sys.modules.get("_codexqb_held_runtime_context_v1")
    if not isinstance(context, ModuleType):
        return False
    try:
        state = ModuleType.__getattribute__(context, "__dict__")
    except (AttributeError, TypeError):
        return False
    runtime_sources = state.get("runtime_sources")
    if (
        type(expected_basename) is not str
        or not expected_basename
        or type(state.get("__name__")) is not str
        or state.get("__name__") != "_codexqb_held_runtime_context_v1"
        or type(state.get("schema_version")) is not int
        or state.get("schema_version") != 1
        or type(state.get("assurance")) is not str
        or state.get("assurance")
        != "controller_observed_loader_path_unattested"
        or state.get("host_attested") is not False
        or state.get("verified") is not False
        or state.get("finalization_authority") is not False
        or "runtime_sha256" in state
        or "goal_sha256" in state
        or type(runtime_sources) is not tuple
        or not runtime_sources
    ):
        return False
    source_names: list[str] = []
    for item in runtime_sources:
        if type(item) is not tuple or len(item) != 2:
            return False
        source_name, source = item
        if (
            type(source_name) is not str
            or not source_name
            or type(source) is not bytes
            or not source
        ):
            return False
        source_names.append(source_name)
    return bool(
        tuple(source_names) == tuple(sorted(source_names))
        and len(source_names) == len(set(source_names))
        and expected_basename in source_names
    )

if __name__ == "__main__" and not _launcher_admission_is_valid(
    {expected_basename!r}
):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\\n"
    )
    raise SystemExit(2)
'''
    ).body
    body = tree.body
    offset = int(
        bool(body)
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    )
    actual = body[offset : offset + len(canonical)]
    if len(actual) != len(canonical) or [
        _canonical_ast_dump(statement)
        for statement in actual
    ] != [
        _canonical_ast_dump(statement)
        for statement in canonical
    ]:
        return set()
    return {
        id(node)
        for statement in (actual[4], actual[5])
        for node in ast.walk(statement)
    }


def _safe_sys_path_attribute_ids(
    tree: ast.Module,
    safe_launcher_admission_node_ids: set[int] | None = None,
) -> set[int]:
    """Recognize only the canonical local-runtime bootstrap pair."""

    launcher_admission_ids = safe_launcher_admission_node_ids or set()

    canonical = ast.parse(
        """
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
"""
    ).body
    expected = [
        _canonical_ast_dump(statement)
        for statement in canonical
    ]
    canonical_first_process_guard = ast.parse(
        """
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
"""
    ).body[0]
    expected_first_process_guard = _canonical_ast_dump(
        canonical_first_process_guard
    )
    body = tree.body
    for index in range(len(body) - 1):
        pair = body[index : index + 2]
        if [
            _canonical_ast_dump(statement)
            for statement in pair
        ] != expected:
            continue
        prefix = body[:index]
        first_process_guards = [
            statement
            for statement in prefix
            if _canonical_ast_dump(statement)
            == expected_first_process_guard
        ]
        if len(first_process_guards) > 1 or not all(
            isinstance(statement, (ast.Import, ast.ImportFrom))
            or (
                isinstance(statement, ast.Expr)
                and isinstance(statement.value, ast.Constant)
                and isinstance(statement.value.value, str)
            )
            or statement in first_process_guards
            or id(statement) in launcher_admission_ids
            for statement in prefix
        ):
            continue
        has_sys = any(
            isinstance(statement, ast.Import)
            and any(alias.name == "sys" and alias.asname is None for alias in statement.names)
            for statement in prefix
        )
        has_path = any(
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "pathlib"
            and any(alias.name == "Path" and alias.asname is None for alias in statement.names)
            for statement in prefix
        )
        if not has_sys or not has_path:
            continue
        return {
            id(node)
            for statement in pair
            for node in ast.walk(statement)
            if isinstance(node, ast.Attribute)
            and node.attr == "path"
            and isinstance(node.value, ast.Name)
            and node.value.id == "sys"
        }
    return set()


def _safe_main_entrypoint_reference_ids(tree: ast.Module) -> set[int]:
    """Return the ``main`` Name id from the exact import-safe CLI guard."""

    if not tree.body:
        return set()
    statement = tree.body[-1]
    if (
        not isinstance(statement, ast.If)
        or statement.orelse
        or len(statement.body) != 1
        or not isinstance(statement.test, ast.Compare)
        or not isinstance(statement.test.left, ast.Name)
        or statement.test.left.id != "__name__"
        or len(statement.test.ops) != 1
        or not isinstance(statement.test.ops[0], ast.Eq)
        or len(statement.test.comparators) != 1
        or not isinstance(statement.test.comparators[0], ast.Constant)
        or statement.test.comparators[0].value != "__main__"
        or not isinstance(statement.body[0], ast.Raise)
    ):
        return set()
    outer = statement.body[0].exc
    if (
        not isinstance(outer, ast.Call)
        or not isinstance(outer.func, ast.Name)
        or outer.func.id != "SystemExit"
        or len(outer.args) != 1
        or outer.keywords
        or not isinstance(outer.args[0], ast.Call)
        or not isinstance(outer.args[0].func, ast.Name)
        or outer.args[0].func.id != "main"
    ):
        return set()
    return {id(outer.args[0].func)}


def _safe_direct_module_receiver_ids(
    tree: ast.Module, relative_path: str
) -> set[int]:
    """Allow a direct module Name only as an approved attribute receiver."""

    aliases: dict[str, str] = {}
    approved_modules = _PROTECTED_DIRECT_IMPORT_MODULES.get(
        relative_path, frozenset()
    )
    for statement in tree.body:
        if not isinstance(statement, ast.Import):
            continue
        for alias in statement.names:
            if alias.name in approved_modules:
                root = alias.name.split(".", 1)[0]
                aliases[alias.asname or root] = (
                    root if root in _MODULE_CANONICAL else alias.name
                )
    approved_attributes = _PROTECTED_DIRECT_MODULE_ATTRIBUTES.get(
        relative_path, {}
    )
    safe = {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id in aliases
        and node.attr in approved_attributes.get(aliases[node.value.id], frozenset())
    }
    safe.update(
        id(node.args[0])
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and (
            node.func.id == "getattr"
            or (
                relative_path in _SEMANTIC_PROFILE_PATHS
                and node.func.id == "hasattr"
            )
        )
        and len(node.args) >= 2
        and isinstance(node.args[0], ast.Name)
        and node.args[0].id in aliases
        and isinstance(node.args[1], ast.Constant)
        and isinstance(node.args[1].value, str)
        and node.args[1].value
        in approved_attributes.get(aliases[node.args[0].id], frozenset())
    )
    return safe


@dataclass(frozen=True)
class _RepositoryUseSafety:
    opener_function_ids: frozenset[int]
    opener_call_ids: frozenset[int]
    context_load_ids: frozenset[int]
    enter_call_ids: frozenset[int]


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    return {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }


def _nearest_binding_scope(
    node: ast.AST, parents: dict[ast.AST, ast.AST]
) -> ast.AST:
    current = node
    scope_types = (
        ast.AsyncFunctionDef,
        ast.ClassDef,
        ast.DictComp,
        ast.FunctionDef,
        ast.GeneratorExp,
        ast.Lambda,
        ast.ListComp,
        ast.SetComp,
    )
    while current in parents:
        current = parents[current]
        if isinstance(current, scope_types):
            return current
    return current


def _repository_use_safety(tree: ast.Module) -> _RepositoryUseSafety:
    """Recognize only structural, non-transport uses of the context factory.

    A call is safe as a ``with`` context expression, or as a simple local
    context assignment whose every load is an immediate ``__enter__`` /
    ``__exit__`` call (plus an optional ``is None`` guard).  The result of
    ``__enter__`` may only be assigned to a simple local name or immediately
    consumed by an approved public RepositoryIO call.  This intentionally
    rejects callbacks, returns, containers, attribute stores, and bound-method
    transport without trying to infer their eventual destination.
    """

    aliases: set[str] = set()
    for statement in tree.body:
        if (
            isinstance(statement, ast.ImportFrom)
            and statement.level == 0
            and statement.module == "repository_io"
        ):
            aliases.update(
                alias.asname or alias.name
                for alias in statement.names
                if alias.name == "open_repository_io"
            )
    parents = _parent_map(tree)
    nodes = tuple(ast.walk(tree))

    def opener_call(node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in aliases
        )

    def immediate_method_call(node: ast.AST, method: str) -> ast.Call | None:
        parent = parents.get(node)
        if not (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr == method
        ):
            return None
        grandparent = parents.get(parent)
        if isinstance(grandparent, ast.Call) and grandparent.func is parent:
            return grandparent
        return None

    def none_identity_guard(node: ast.Name) -> bool:
        parent = parents.get(node)
        if not isinstance(parent, ast.Compare):
            return False
        operands = (parent.left, *parent.comparators)
        if node not in operands or not all(
            isinstance(operator, (ast.Is, ast.IsNot)) for operator in parent.ops
        ):
            return False
        return all(
            operand is node
            or (isinstance(operand, ast.Constant) and operand.value is None)
            for operand in operands
        )

    def safe_enter_result(call: ast.Call) -> bool:
        parent = parents.get(call)
        if isinstance(parent, ast.Assign) and parent.value is call:
            return len(parent.targets) == 1 and isinstance(parent.targets[0], ast.Name)
        if isinstance(parent, ast.AnnAssign) and parent.value is call:
            return isinstance(parent.target, ast.Name)
        if (
            isinstance(parent, ast.Attribute)
            and parent.value is call
            and parent.attr in _PUBLIC_REPOSITORY_METHODS
        ):
            grandparent = parents.get(parent)
            return isinstance(grandparent, ast.Call) and grandparent.func is parent
        return False

    safe_function_ids: set[int] = set()
    safe_call_ids: set[int] = set()
    safe_context_load_ids: set[int] = set()
    safe_enter_ids: set[int] = set()

    for call in (item for item in nodes if opener_call(item)):
        assert isinstance(call, ast.Call)
        parent = parents.get(call)
        if isinstance(parent, ast.withitem) and parent.context_expr is call:
            safe_call_ids.add(id(call))
            safe_function_ids.add(id(call.func))
            continue

        inline_enter = immediate_method_call(call, "__enter__")
        if inline_enter is not None and safe_enter_result(inline_enter):
            safe_call_ids.add(id(call))
            safe_function_ids.add(id(call.func))
            safe_enter_ids.add(id(inline_enter))
            continue

        target: ast.Name | None = None
        if (
            isinstance(parent, ast.Assign)
            and parent.value is call
            and len(parent.targets) == 1
            and isinstance(parent.targets[0], ast.Name)
        ):
            target = parent.targets[0]
        elif (
            isinstance(parent, ast.AnnAssign)
            and parent.value is call
            and isinstance(parent.target, ast.Name)
        ):
            target = parent.target
        if target is None:
            continue

        scope = _nearest_binding_scope(target, parents)
        loads = [
            item
            for item in nodes
            if isinstance(item, ast.Name)
            and isinstance(item.ctx, ast.Load)
            and item.id == target.id
            and _nearest_binding_scope(item, parents) is scope
        ]
        enter_calls = [
            method_call
            for item in loads
            if (method_call := immediate_method_call(item, "__enter__"))
            is not None
        ]
        safe_loads = {
            id(item)
            for item in loads
            if immediate_method_call(item, "__enter__") is not None
            or immediate_method_call(item, "__exit__") is not None
            or none_identity_guard(item)
        }
        if not enter_calls or any(id(item) not in safe_loads for item in loads):
            continue
        if any(not safe_enter_result(enter) for enter in enter_calls):
            continue
        safe_call_ids.add(id(call))
        safe_function_ids.add(id(call.func))
        safe_context_load_ids.update(safe_loads)
        safe_enter_ids.update(id(enter) for enter in enter_calls)

    return _RepositoryUseSafety(
        opener_function_ids=frozenset(safe_function_ids),
        opener_call_ids=frozenset(safe_call_ids),
        context_load_ids=frozenset(safe_context_load_ids),
        enter_call_ids=frozenset(safe_enter_ids),
    )


def _safe_facade_public_receiver_ids(
    tree: ast.Module, parents: dict[ast.AST, ast.AST]
) -> set[int]:
    return {
        id(node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and node.attr in _PUBLIC_REPOSITORY_METHODS
        and isinstance(node.value, ast.Name)
        and isinstance(parents.get(node), ast.Call)
        and parents[node].func is node
    }


class PythonBypassVisitor(ast.NodeVisitor):
    """Conservative name-taint and capability-aware protected-source scan."""

    def __init__(
        self,
        relative_path: str,
        *,
        safe_sys_path_attribute_ids: set[int] | None = None,
        safe_launcher_admission_node_ids: set[int] | None = None,
        safe_main_reference_ids: set[int] | None = None,
        safe_direct_module_receiver_ids: set[int] | None = None,
        repository_use_safety: _RepositoryUseSafety | None = None,
        safe_facade_public_receiver_ids: set[int] | None = None,
        parent_map: dict[ast.AST, ast.AST] | None = None,
        local_capability_names: frozenset[str] = frozenset(),
        local_path_return_names: frozenset[str] = frozenset(),
    ) -> None:
        self.relative_path = relative_path
        self.findings: list[PolicyFinding] = []
        self.function_digests: list[str] = []
        self.function_scopes: list[str] = []
        self.class_stack: list[str] = []
        self.module_aliases: dict[str, str] = {}
        self.callable_aliases: dict[str, str] = {}
        self.import_aliases: dict[str, str] = {}
        self.path_type_names: set[str] = set()
        self.repository_type_names: set[str] = set()
        self.validation_state_type_names: set[str] = set()
        self.open_repository_names: set[str] = set()
        self.repository_names: set[str] = set()
        self.facade_conflicted_names: set[str] = set()
        self.nonfacade_assigned_names: set[str] = set()
        self.repository_context_names: set[str] = set()
        self.noncontext_assigned_names: set[str] = set()
        self.context_conflicted_names: set[str] = set()
        self.validation_state_names: set[str] = set()
        self.path_names: set[str] = set()
        self.safe_sys_path_attribute_ids = safe_sys_path_attribute_ids or set()
        self.safe_launcher_admission_node_ids = (
            safe_launcher_admission_node_ids or set()
        )
        self.safe_main_reference_ids = safe_main_reference_ids or set()
        self.safe_direct_module_receiver_ids = safe_direct_module_receiver_ids or set()
        self.repository_use_safety = repository_use_safety or _RepositoryUseSafety(
            frozenset(), frozenset(), frozenset(), frozenset()
        )
        self.safe_facade_public_receiver_ids = safe_facade_public_receiver_ids or set()
        self.parent_map = parent_map or {}
        self.local_capability_names = local_capability_names
        self.local_path_return_names = local_path_return_names
        self.capability_function_digests: set[str] = set()
        self.semantic_finding_counts: dict[tuple[str, str], int] = {}

    def finding(
        self,
        node: ast.AST,
        symbol: str,
        *,
        capability_exempt: bool = True,
    ) -> None:
        if self._semantic_finding_allowed(symbol):
            return
        if capability_exempt and self.function_digests:
            self.capability_function_digests.add(self.function_digests[-1])
        if capability_exempt and self._approved_capability():
            return
        self.findings.append(PolicyFinding(self.relative_path, int(getattr(node, "lineno", 1)), symbol))

    def _semantic_finding_allowed(self, symbol: str) -> bool:
        """Consume one exact reviewed diagnostic occurrence for enrolled code."""

        scope = self.function_scopes[-1] if self.function_scopes else "__module__"
        if self.relative_path in _SEMANTIC_PROFILE_PATHS:
            limit = (
                _PROTECTED_SEMANTIC_FINDING_BUDGETS.get(self.relative_path, {})
                .get(scope, {})
                .get(symbol, 0)
            )
        elif self.relative_path == "scripts/apply_run.py":
            limit = _APPLY_REQUEST_STDIN_FINDING_BUDGETS.get(scope, {}).get(
                symbol, 0
            )
        else:
            return False
        key = (scope, symbol)
        observed = self.semantic_finding_counts.get(key, 0)
        if observed >= limit:
            return False
        self.semantic_finding_counts[key] = observed + 1
        return True

    def _approved_capability(self) -> bool:
        return bool(
            self.function_digests
            and self.function_digests[-1] in _APPROVED_CAPABILITY_DIGESTS.get(self.relative_path, frozenset())
        )

    def _canonical(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return (
                self.import_aliases.get(node.id)
                or self.callable_aliases.get(node.id)
                or self.module_aliases.get(node.id)
                or node.id
            )
        if isinstance(node, ast.Attribute):
            base = self._canonical(node.value)
            return f"{base}.{node.attr}" if base else None
        return None

    def _facade_receiver(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.repository_names
        if isinstance(node, ast.Attribute) and node.attr == "repository" and isinstance(node.value, ast.Name):
            return node.value.id in self.validation_state_names or (
                node.value.id == "self"
                and self.class_stack[-1:] == ["ValidationState"]
                and "ValidationState" in self.validation_state_type_names
            )
        if self._repository_value_expression(node):
            return True
        if self._enter_result(node):
            return True
        return False

    def _facade_receiver_conflicted(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id in self.facade_conflicted_names

    def _repository_context_receiver(self, node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Name)
            and node.id in self.repository_context_names
        ) or (
            isinstance(node, ast.Call)
            and self._canonical(node.func) == "repository_io.open_repository_io"
        )

    def _repository_context_receiver_conflicted(self, node: ast.expr) -> bool:
        return isinstance(node, ast.Name) and node.id in self.context_conflicted_names

    def _none_identity_name_use(self, node: ast.Name) -> bool:
        parent = self.parent_map.get(node)
        if not isinstance(parent, ast.Compare):
            return False
        operands = (parent.left, *parent.comparators)
        return (
            node in operands
            and all(isinstance(operator, (ast.Is, ast.IsNot)) for operator in parent.ops)
            and all(
                operand is node
                or (isinstance(operand, ast.Constant) and operand.value is None)
                for operand in operands
            )
        )

    def _reviewed_facade_argument(self, node: ast.expr) -> bool:
        parent = self.parent_map.get(node)
        if not isinstance(parent, ast.Call):
            return False
        if node not in parent.args and not any(
            keyword.value is node for keyword in parent.keywords
        ):
            return False
        canonical = self._canonical(parent.func)
        return canonical in _POWERFUL_REPOSITORY_IO_CALLS or (
            isinstance(parent.func, ast.Name)
            and canonical == parent.func.id
            and parent.func.id in self.local_capability_names
        )

    def _validation_state_use_safe(self, node: ast.Name) -> bool:
        parent = self.parent_map.get(node)
        if not (
            isinstance(parent, ast.Attribute)
            and parent.value is node
            and parent.attr != "repository"
        ):
            return self._none_identity_name_use(node)
        if parent.attr in {"errors", "mode", "root", "strict", "warnings"}:
            return True
        grandparent = self.parent_map.get(parent)
        return isinstance(grandparent, ast.Call) and grandparent.func is parent

    def _enter_result(self, node: ast.expr) -> bool:
        return (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__enter__"
            and self._repository_context_receiver(node.func.value)
        )

    def _path_expression(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.path_names
        if isinstance(node, ast.Call):
            if self._canonical(node.func) in _CONCRETE_PATH_TYPES or (
                isinstance(node.func, ast.Name) and node.func.id in self.path_type_names
            ) or (
                isinstance(node.func, ast.Name)
                and node.func.id in self.local_path_return_names
            ):
                return True
            if isinstance(node.func, ast.Lambda):
                return self._path_expression(node.func.body)
            if (
                isinstance(node.func, ast.Name)
                and node.func.id in {"iter", "list", "next", "set", "tuple"}
            ):
                return any(self._path_expression(argument) for argument in node.args)
            return (
                isinstance(node.func, ast.Attribute)
                and node.func.attr in _PATH_PRESERVING_METHODS
                and (
                    self._path_expression(node.func.value)
                    or self._canonical(node.func.value) in _CONCRETE_PATH_TYPES
                )
            )
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._path_expression(node.left)
        if isinstance(node, ast.Await):
            return self._path_expression(node.value)
        if isinstance(node, ast.NamedExpr):
            return self._path_expression(node.value)
        if isinstance(node, ast.IfExp):
            return self._path_expression(node.body) or self._path_expression(
                node.orelse
            )
        if isinstance(node, ast.BoolOp):
            return any(self._path_expression(item) for item in node.values)
        if isinstance(node, ast.Attribute) and node.attr in {"parent", "parents"}:
            return self._path_expression(node.value)
        if isinstance(node, ast.Subscript):
            if self._path_expression(node.value):
                return True
            if isinstance(node.value, (ast.List, ast.Tuple)):
                return any(self._path_expression(item) for item in node.value.elts)
        if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            return any(self._path_expression(item) for item in node.elts)
        return False

    def _repository_value_expression(self, node: ast.expr) -> bool:
        if isinstance(node, ast.Name):
            return node.id in self.repository_names
        if isinstance(node, ast.NamedExpr):
            return self._repository_value_expression(node.value)
        if isinstance(node, ast.IfExp):
            return self._repository_value_expression(
                node.body
            ) or self._repository_value_expression(node.orelse)
        if isinstance(node, ast.BoolOp):
            return any(self._repository_value_expression(item) for item in node.values)
        if isinstance(node, ast.Subscript):
            return any(
                isinstance(item, ast.Name) and item.id in self.repository_names
                for item in ast.walk(node.value)
            )
        return False

    def _path_value_expression(self, node: ast.expr) -> bool:
        if self._path_expression(node):
            return True
        if isinstance(node, ast.NamedExpr):
            return self._path_value_expression(node.value)
        if isinstance(node, ast.IfExp):
            return self._path_value_expression(node.body) or self._path_value_expression(
                node.orelse
            )
        if isinstance(node, ast.BoolOp):
            return any(self._path_value_expression(item) for item in node.values)
        if isinstance(node, ast.Subscript):
            return any(
                self._path_expression(item)
                for item in ast.walk(node.value)
                if isinstance(item, ast.expr)
            )
        return False

    def _safe_module_file_resolve(self, node: ast.Attribute) -> bool:
        call = node.value
        return (
            not self.function_digests
            and node.attr == "resolve"
            and isinstance(call, ast.Call)
            and self._canonical(call.func) == "pathlib.Path"
            and len(call.args) == 1
            and isinstance(call.args[0], ast.Name)
            and call.args[0].id == "__file__"
            and not call.keywords
        )

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        if node.name in self.import_aliases:
            self.finding(
                node,
                f"import_binding_shadowed:{node.name}",
                capability_exempt=False,
            )
        path_subclass = any(
            self._canonical(base) in _CONCRETE_PATH_TYPES
            or (isinstance(base, ast.Name) and base.id in self.path_type_names)
            for base in node.bases
        )
        previous_types = (
            set(self.path_type_names),
            set(self.repository_type_names),
            set(self.validation_state_type_names),
            set(self.open_repository_names),
        )
        class_digest = hashlib.sha256(
            _canonical_ast_dump(node).encode("utf-8")
        ).hexdigest()
        approved_validation_state = (
            self.relative_path == "scripts/validate_planner_docs.py"
            and node.name == "ValidationState"
            and class_digest in _APPROVED_VALIDATION_STATE_CLASS_DIGESTS
        )
        if approved_validation_state:
            self.validation_state_type_names.add(node.name)
        if path_subclass:
            self.path_type_names.add(node.name)
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()
        (
            self.path_type_names,
            self.repository_type_names,
            self.validation_state_type_names,
            self.open_repository_names,
        ) = previous_types
        self.repository_type_names.discard(node.name)
        self.path_type_names.discard(node.name)
        self.open_repository_names.discard(node.name)
        self.validation_state_type_names.discard(node.name)
        self.callable_aliases.pop(node.name, None)
        self.module_aliases.pop(node.name, None)
        if approved_validation_state:
            self.validation_state_type_names.add(node.name)
        if path_subclass:
            self.path_type_names.add(node.name)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node.name in self.import_aliases:
            self.finding(
                node,
                f"import_binding_shadowed:{node.name}",
                capability_exempt=False,
            )
        previous = (
            set(self.repository_names),
            set(self.facade_conflicted_names),
            set(self.nonfacade_assigned_names),
            set(self.repository_context_names),
            set(self.noncontext_assigned_names),
            set(self.context_conflicted_names),
            set(self.validation_state_names),
            set(self.path_names),
            dict(self.callable_aliases),
            dict(self.module_aliases),
            set(self.path_type_names),
            set(self.repository_type_names),
            set(self.validation_state_type_names),
            set(self.open_repository_names),
        )
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            if argument.arg in self.import_aliases:
                self.finding(
                    argument,
                    f"import_binding_shadowed:{argument.arg}",
                    capability_exempt=False,
                )
            if _annotation_mentions(argument.annotation, self.repository_type_names):
                self.repository_names.add(argument.arg)
            if _annotation_mentions(argument.annotation, self.validation_state_type_names):
                self.validation_state_names.add(argument.arg)
            if _annotation_mentions(argument.annotation, self.path_type_names):
                self.path_names.add(argument.arg)
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self.path_type_names.discard(argument.arg)
            self.repository_type_names.discard(argument.arg)
            self.validation_state_type_names.discard(argument.arg)
            self.open_repository_names.discard(argument.arg)
        semantic_scope = ".".join((*self.class_stack, node.name))
        self.function_scopes.append(semantic_scope)
        self.function_digests.append(_body_digest(node))
        annotation_nodes = [
            argument.annotation
            for argument in (
                *node.args.posonlyargs,
                *node.args.args,
                *node.args.kwonlyargs,
            )
            if argument.annotation is not None
        ]
        if node.returns is not None:
            annotation_nodes.append(node.returns)
        for annotation in annotation_nodes:
            if any(
                isinstance(
                    item,
                    (
                        ast.Await,
                        ast.Call,
                        ast.DictComp,
                        ast.GeneratorExp,
                        ast.Lambda,
                        ast.ListComp,
                        ast.NamedExpr,
                        ast.SetComp,
                        ast.Yield,
                        ast.YieldFrom,
                    ),
                )
                for item in ast.walk(annotation)
            ):
                self.finding(
                    annotation,
                    "executable_annotation",
                    capability_exempt=False,
                )
        # Type annotations are inert policy metadata; scanning their attribute
        # names as live callable references would misclassify e.g.
        # `subprocess.Popen[bytes]`.  Defaults and decorators are executable and
        # remain in scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for statement in node.body:
            self.visit(statement)
        self.function_digests.pop()
        self.function_scopes.pop()
        (
            self.repository_names,
            self.facade_conflicted_names,
            self.nonfacade_assigned_names,
            self.repository_context_names,
            self.noncontext_assigned_names,
            self.context_conflicted_names,
            self.validation_state_names,
            self.path_names,
            self.callable_aliases,
            self.module_aliases,
            self.path_type_names,
            self.repository_type_names,
            self.validation_state_type_names,
            self.open_repository_names,
        ) = previous
        self.repository_type_names.discard(node.name)
        self.path_type_names.discard(node.name)
        self.open_repository_names.discard(node.name)
        self.validation_state_type_names.discard(node.name)
        self.callable_aliases.pop(node.name, None)
        self.module_aliases.pop(node.name, None)

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Import(self, node: ast.Import) -> None:
        if self.function_digests or self.class_stack:
            self.finding(node, "non_module_import", capability_exempt=False)
        for alias in node.names:
            root = alias.name.split(".", 1)[0]
            leaf = alias.name.rsplit(".", 1)[-1]
            policy_module = leaf if leaf in _LOCAL_BOUNDARY_MODULES else root
            local = alias.asname or root
            self.path_type_names.discard(local)
            self.repository_type_names.discard(local)
            self.validation_state_type_names.discard(local)
            self.open_repository_names.discard(local)
            self.callable_aliases.pop(local, None)
            self.module_aliases.pop(local, None)
            if root not in _PROTECTED_IMPORT_ROOTS.get(
                self.relative_path, frozenset()
            ):
                self.finding(
                    node,
                    f"unapproved_import_root:{root}",
                    capability_exempt=False,
                )
            if alias.name not in _PROTECTED_DIRECT_IMPORT_MODULES.get(
                self.relative_path, frozenset()
            ):
                self.finding(
                    node,
                    f"unapproved_direct_import_module:{alias.name}",
                    capability_exempt=False,
                )
            if root in _LOCAL_HELPER_MODULES:
                self.finding(
                    node,
                    f"restricted_local_module_import:{root}",
                    capability_exempt=False,
                )
            if leaf in _LOCAL_BOUNDARY_MODULES and alias.name != leaf:
                self.finding(
                    node,
                    f"noncanonical_boundary_import:{leaf}",
                    capability_exempt=False,
                )
            if (
                policy_module in _FORBIDDEN_PROTECTED_IMPORT_MODULES
                and policy_module
                not in _PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS.get(
                    self.relative_path, frozenset()
                )
            ):
                self.finding(
                    node,
                    f"forbidden_module_import:{policy_module}",
                    capability_exempt=False,
                )
            elif policy_module in {"repository_io", "controller_store", "execution_controller"}:
                self.finding(
                    node,
                    f"restricted_module_import:{policy_module}",
                    capability_exempt=False,
                )
            if policy_module in _MODULE_CANONICAL:
                self.module_aliases[local] = policy_module
                self.import_aliases[local] = policy_module
            elif root in _MODULE_CANONICAL:
                self.module_aliases[local] = root
                self.import_aliases[local] = root
            else:
                self.import_aliases[local] = alias.name

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if self.function_digests or self.class_stack:
            self.finding(node, "non_module_import", capability_exempt=False)
        module = node.module or ""
        module_root = module.split(".", 1)[0]
        module_leaf = module.rsplit(".", 1)[-1]
        boundary_module = module_leaf if module_leaf in _LOCAL_BOUNDARY_MODULES else module
        noncanonical_boundary = module_leaf in _LOCAL_BOUNDARY_MODULES and (
            module != module_leaf or node.level != 0
        )
        if (
            node.level != 0
            or module_root not in _PROTECTED_IMPORT_ROOTS.get(
                self.relative_path, frozenset()
            )
        ):
            self.finding(
                node,
                f"unapproved_import_root:{module_root or 'relative'}",
                capability_exempt=False,
            )
        stdlib_allowed = _PROTECTED_STDLIB_FROM_IMPORTS.get(
            self.relative_path, {}
        ).get(module)
        helper_known = module in _LOCAL_HELPER_ALLOWED_IMPORTS.get(
            self.relative_path, {}
        )
        boundary_known = boundary_module in {
            "artifact_io",
            "controller_store",
            "execution_controller",
            "repository_controller",
            "repository_evidence",
            "repository_io",
        }
        if stdlib_allowed is None and not helper_known and not boundary_known:
            self.finding(
                node,
                f"unapproved_from_import_module:{module or 'relative'}",
                capability_exempt=False,
            )
        for alias in node.names:
            local = alias.asname or alias.name
            canonical = f"{boundary_module}.{alias.name}" if boundary_module else alias.name
            self.path_type_names.discard(local)
            self.repository_type_names.discard(local)
            self.validation_state_type_names.discard(local)
            self.open_repository_names.discard(local)
            self.callable_aliases.pop(local, None)
            self.module_aliases.pop(local, None)
            if alias.name == "*" and (
                module in _MODULE_CANONICAL or module.split(".", 1)[0] in _MODULE_CANONICAL
            ):
                self.finding(
                    node,
                    f"wildcard_import:{module}",
                    capability_exempt=False,
                )
            if stdlib_allowed is not None and alias.name not in stdlib_allowed:
                self.finding(
                    node,
                    f"unapproved_from_import_symbol:{module}.{alias.name}",
                    capability_exempt=False,
                )
            if noncanonical_boundary:
                self.finding(
                    node,
                    f"noncanonical_boundary_import:{module_leaf}",
                    capability_exempt=False,
                )
            if module == "pathlib" and alias.name in {
                "Path",
                "PosixPath",
                "WindowsPath",
            }:
                self.path_type_names.add(local)
                self.callable_aliases[local] = canonical
            elif boundary_module == "repository_io" and alias.name == "RepositoryIO":
                self.repository_type_names.add(local)
            elif boundary_module == "repository_io" and alias.name == "open_repository_io":
                self.open_repository_names.add(local)
                self.callable_aliases[local] = canonical
            elif boundary_module in _MODULE_CANONICAL or module_root in _MODULE_CANONICAL:
                self.callable_aliases[local] = canonical
            self.import_aliases[local] = canonical
            policy_module = module_leaf if module_leaf in _LOCAL_BOUNDARY_MODULES else module_root
            if (
                policy_module in _FORBIDDEN_PROTECTED_IMPORT_MODULES
                and policy_module
                not in _PROTECTED_FORBIDDEN_IMPORT_EXCEPTIONS.get(
                    self.relative_path, frozenset()
                )
            ):
                self.finding(
                    node,
                    f"forbidden_module_import:{policy_module}",
                    capability_exempt=False,
                )
            helper_allowed = _LOCAL_HELPER_ALLOWED_IMPORTS.get(
                self.relative_path, {}
            ).get(module)
            if helper_allowed is not None and alias.name not in helper_allowed:
                self.finding(
                    node,
                    f"local_helper_unknown_import:{module}.{alias.name}",
                    capability_exempt=False,
                )
            repository_io_allowed = _REPOSITORY_IO_ALLOWED_IMPORTS | _REPOSITORY_IO_CONTROLLER_IMPORTS.get(
                self.relative_path, frozenset()
            )
            if boundary_module == "repository_io" and alias.name not in repository_io_allowed:
                self.finding(
                    node,
                    f"repository_io_private_import:{alias.name}",
                    capability_exempt=False,
                )
            if boundary_module == "repository_evidence" and alias.name not in _REPOSITORY_EVIDENCE_ALLOWED_IMPORTS:
                self.finding(
                    node,
                    f"repository_evidence_unknown_import:{alias.name}",
                    capability_exempt=False,
                )
            controller_store_allowed = _CONTROLLER_STORE_ALLOWED_IMPORTS.get(
                self.relative_path, frozenset()
            )
            if boundary_module == "controller_store" and alias.name not in controller_store_allowed:
                self.finding(
                    node,
                    f"controller_store_unknown_import:{alias.name}",
                    capability_exempt=False,
                )
            execution_controller_allowed = _EXECUTION_CONTROLLER_ALLOWED_IMPORTS.get(
                self.relative_path, frozenset()
            )
            if (
                boundary_module == "execution_controller"
                and alias.name not in execution_controller_allowed
            ):
                self.finding(
                    node,
                    f"execution_controller_unknown_import:{alias.name}",
                    capability_exempt=False,
                )
            if canonical == "sys.modules":
                self.finding(
                    node,
                    "dynamic_namespace_access",
                    capability_exempt=False,
                )
            if self._dangerous_canonical(canonical) or canonical in {"builtins.open", "io.open"}:
                self.finding(node, f"dangerous_import:{canonical}")
        self.generic_visit(node)

    def _bind_target(self, target: ast.expr, value: ast.expr | None) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            values = value.elts if isinstance(value, (ast.Tuple, ast.List)) else ()
            for index, item in enumerate(target.elts):
                self._bind_target(item, values[index] if index < len(values) else value)
            return
        if not isinstance(target, ast.Name):
            return
        if target.id in self.import_aliases:
            self.finding(
                target,
                f"import_binding_rebound:{target.id}",
                capability_exempt=False,
            )
            return
        canonical = self._canonical(value) if value is not None else None
        self.module_aliases.pop(target.id, None)
        if canonical:
            self.callable_aliases[target.id] = canonical
        elif target.id in self.callable_aliases:
            # Rebinding cannot silently preserve a safe capability.
            self.callable_aliases.pop(target.id, None)
        if value is not None and self._path_value_expression(value):
            self.path_names.add(target.id)
        enter_result = value is not None and self._enter_result(value)
        repository_value = value is not None and (
            self._repository_value_expression(value) or enter_result
        )
        if repository_value:
            self.repository_names.add(target.id)
            if target.id in self.nonfacade_assigned_names:
                self.facade_conflicted_names.add(target.id)
            if (
                enter_result
                and isinstance(value, ast.Call)
                and isinstance(value.func, ast.Attribute)
                and self._repository_context_receiver_conflicted(value.func.value)
            ):
                self.facade_conflicted_names.add(target.id)
        else:
            self.nonfacade_assigned_names.add(target.id)
        if not repository_value and target.id in self.repository_names:
            # Flow joins are fail-closed.  A facade name shadowed on any path
            # must not keep the public-method exemption.
            self.facade_conflicted_names.add(target.id)
        context_value = value is not None and (
            (
                isinstance(value, ast.Call)
                and self._canonical(value.func)
                == "repository_io.open_repository_io"
            )
            or (
                isinstance(value, ast.Name)
                and value.id in self.repository_context_names
            )
        )
        none_sentinel = isinstance(value, ast.Constant) and value.value is None
        if context_value:
            self.repository_context_names.add(target.id)
            if target.id in self.noncontext_assigned_names:
                self.context_conflicted_names.add(target.id)
        elif not none_sentinel:
            self.noncontext_assigned_names.add(target.id)
            if target.id in self.repository_context_names:
                self.context_conflicted_names.add(target.id)
        if value is not None and isinstance(value, ast.Name) and value.id in self.validation_state_names:
            self.validation_state_names.add(target.id)
        canonical_value = self._canonical(value) if value is not None else None
        if canonical_value != "pathlib.Path":
            self.path_type_names.discard(target.id)
        if canonical_value != "repository_io.RepositoryIO":
            self.repository_type_names.discard(target.id)
        if canonical_value != "repository_io.open_repository_io":
            self.open_repository_names.discard(target.id)

    def _reject_capability_assignment(self, target: ast.expr) -> None:
        if isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._reject_capability_assignment(item)
            return
        if isinstance(target, ast.Attribute) and self._facade_receiver(target.value):
            self.finding(target, f"repository_io_rebinding:{target.attr}")

    def visit_Assign(self, node: ast.Assign) -> None:
        # Visit the value first so `reader = path.read_text` is reported before
        # the alias is recorded.
        self.visit(node.value)
        for target in node.targets:
            self._reject_capability_assignment(target)
            self._bind_target(target, node.value)
            self.visit(target)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value is not None:
            self.visit(node.value)
        self._reject_capability_assignment(node.target)
        self._bind_target(node.target, node.value)
        if isinstance(node.target, ast.Name):
            if _annotation_mentions(node.annotation, self.repository_type_names):
                self.repository_names.add(node.target.id)
            if _annotation_mentions(node.annotation, self.validation_state_type_names):
                self.validation_state_names.add(node.target.id)
            if _annotation_mentions(node.annotation, self.path_type_names):
                self.path_names.add(node.target.id)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self.visit(node.value)
        self._reject_capability_assignment(node.target)
        self._bind_target(node.target, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.visit(node.value)
        self._reject_capability_assignment(node.target)
        self._bind_target(node.target, None)
        self.visit(node.target)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._bind_target(target, None)
            self.visit(target)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            self.visit(item.context_expr)
            call = item.context_expr
            if (
                isinstance(call, ast.Call)
                and self._canonical(call.func) in {"repository_io.open_repository_io", *self.open_repository_names}
                and isinstance(item.optional_vars, ast.Name)
            ):
                previously_nonfacade = (
                    item.optional_vars.id in self.nonfacade_assigned_names
                )
                self._bind_target(item.optional_vars, None)
                self.repository_names.add(item.optional_vars.id)
                if previously_nonfacade:
                    self.facade_conflicted_names.add(item.optional_vars.id)
                else:
                    self.nonfacade_assigned_names.discard(item.optional_vars.id)
            elif item.optional_vars is not None:
                self._bind_target(item.optional_vars, None)
                if (
                    isinstance(call, ast.Call)
                    and self._canonical(call.func)
                    in {"repository_io.open_repository_io", *self.open_repository_names}
                ):
                    self.finding(
                        item.optional_vars,
                        "repository_context_unpacking",
                        capability_exempt=False,
                    )
                self.visit(item.optional_vars)
        for statement in node.body:
            self.visit(statement)
        # A ``with ... as name`` binding remains in Python scope after the
        # suite.  Retain its facade taint so post-with private access cannot
        # masquerade as an unrelated receiver.

    visit_AsyncWith = visit_With

    def _bind_match_pattern(self, pattern: ast.pattern) -> None:
        if isinstance(pattern, ast.MatchValue):
            self.visit(pattern.value)
            return
        if isinstance(pattern, ast.MatchSingleton):
            return
        if isinstance(pattern, ast.MatchSequence):
            for nested in pattern.patterns:
                self._bind_match_pattern(nested)
            return
        if isinstance(pattern, ast.MatchMapping):
            for key in pattern.keys:
                self.visit(key)
            for nested in pattern.patterns:
                self._bind_match_pattern(nested)
            if pattern.rest:
                self._bind_target(
                    ast.Name(id=pattern.rest, ctx=ast.Store()), None
                )
            return
        if isinstance(pattern, ast.MatchClass):
            self.visit(pattern.cls)
            for nested in (*pattern.patterns, *pattern.kwd_patterns):
                self._bind_match_pattern(nested)
            return
        if isinstance(pattern, ast.MatchStar):
            if pattern.name:
                self._bind_target(
                    ast.Name(id=pattern.name, ctx=ast.Store()), None
                )
            return
        if isinstance(pattern, ast.MatchAs):
            if pattern.pattern is not None:
                self._bind_match_pattern(pattern.pattern)
            if pattern.name:
                self._bind_target(
                    ast.Name(id=pattern.name, ctx=ast.Store()), None
                )
            return
        if isinstance(pattern, ast.MatchOr):
            for nested in pattern.patterns:
                self._bind_match_pattern(nested)

    def visit_Match(self, node: ast.Match) -> None:
        self.visit(node.subject)
        for case in node.cases:
            self._bind_match_pattern(case.pattern)
            if case.guard is not None:
                self.visit(case.guard)
            for statement in case.body:
                self.visit(statement)

    def visit_For(self, node: ast.For) -> None:
        self.visit(node.iter)
        self._bind_target(node.target, None)
        self.visit(node.target)
        for statement in (*node.body, *node.orelse):
            self.visit(statement)

    visit_AsyncFor = visit_For

    def visit_Lambda(self, node: ast.Lambda) -> None:
        previous = (
            set(self.repository_names),
            set(self.facade_conflicted_names),
            set(self.nonfacade_assigned_names),
            set(self.repository_context_names),
            set(self.noncontext_assigned_names),
            set(self.context_conflicted_names),
            set(self.validation_state_names),
            set(self.path_names),
            set(self.path_type_names),
            set(self.repository_type_names),
            set(self.validation_state_type_names),
            set(self.open_repository_names),
        )
        for default in (*node.args.defaults, *node.args.kw_defaults):
            if default is not None:
                self.visit(default)
        for argument in (*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs):
            self._bind_target(ast.Name(id=argument.arg, ctx=ast.Store()), None)
        self.visit(node.body)
        (
            self.repository_names,
            self.facade_conflicted_names,
            self.nonfacade_assigned_names,
            self.repository_context_names,
            self.noncontext_assigned_names,
            self.context_conflicted_names,
            self.validation_state_names,
            self.path_names,
            self.path_type_names,
            self.repository_type_names,
            self.validation_state_type_names,
            self.open_repository_names,
        ) = previous

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if node.type is not None:
            self.visit(node.type)
        if node.name:
            self._bind_target(ast.Name(id=node.name, ctx=ast.Store()), None)
        for statement in node.body:
            self.visit(statement)

    def _visit_comprehension_scope(
        self,
        generators: list[ast.comprehension],
        outputs: tuple[ast.expr, ...],
    ) -> None:
        previous = (
            set(self.repository_names),
            set(self.facade_conflicted_names),
            set(self.nonfacade_assigned_names),
            set(self.repository_context_names),
            set(self.noncontext_assigned_names),
            set(self.context_conflicted_names),
            set(self.validation_state_names),
            set(self.path_names),
            dict(self.callable_aliases),
            dict(self.module_aliases),
            set(self.path_type_names),
            set(self.repository_type_names),
            set(self.validation_state_type_names),
            set(self.open_repository_names),
        )
        for generator in generators:
            self.visit(generator.iter)
            self._bind_target(generator.target, None)
            self.visit(generator.target)
            for condition in generator.ifs:
                self.visit(condition)
        for output in outputs:
            self.visit(output)
        (
            self.repository_names,
            self.facade_conflicted_names,
            self.nonfacade_assigned_names,
            self.repository_context_names,
            self.noncontext_assigned_names,
            self.context_conflicted_names,
            self.validation_state_names,
            self.path_names,
            self.callable_aliases,
            self.module_aliases,
            self.path_type_names,
            self.repository_type_names,
            self.validation_state_type_names,
            self.open_repository_names,
        ) = previous

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self._visit_comprehension_scope(node.generators, (node.elt,))

    visit_SetComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self._visit_comprehension_scope(node.generators, (node.key, node.value))

    def visit_Attribute(self, node: ast.Attribute) -> None:
        canonical_node = self._canonical(node)
        context_receiver = self._repository_context_receiver(node.value)
        launcher_admission_safe = id(node) in self.safe_launcher_admission_node_ids
        if node.attr == "fromfile_prefix_chars":
            self.finding(
                node,
                "raw_io:argparse.ArgumentParser.fromfile_prefix_chars",
                capability_exempt=False,
            )
        if (
            node.attr.startswith("_")
            and node.attr != "__name__"
            and not (node.attr in {"__enter__", "__exit__"} and context_receiver)
            and not launcher_admission_safe
        ):
            self.finding(
                node,
                f"private_attribute_access:{node.attr}",
                capability_exempt=False,
            )
        if (
            (
                node.attr in _DANGEROUS_NAMESPACE_ATTRIBUTES
                or canonical_node == "sys.modules"
            )
            and not launcher_admission_safe
        ):
            self.finding(
                node,
                "dynamic_namespace_access",
                capability_exempt=False,
            )
        if canonical_node in _DANGEROUS_NAMESPACE_CALLS:
            self.finding(
                node,
                f"dynamic_namespace_access:{canonical_node}",
                capability_exempt=False,
            )
        if node.attr in _DANGEROUS_BUILTIN_ATTRIBUTES:
            self.finding(
                node,
                f"dangerous_builtin_attribute:{node.attr}",
                capability_exempt=False,
            )
        if node.attr in self.local_capability_names:
            self.finding(node, f"local_capability_reference:{node.attr}")
        if canonical_node in _POWERFUL_REPOSITORY_IO_CALLS:
            self.finding(node, f"controller_capability_reference:{canonical_node}")
        if canonical_node in _POWERFUL_CONTROLLER_STORE_CALLS:
            self.finding(node, f"controller_capability_reference:{canonical_node}")
        if canonical_node in _POWERFUL_EXECUTION_CONTROLLER_CALLS:
            self.finding(node, f"execution_capability_reference:{canonical_node}")
        canonical_receiver = self._canonical(node.value)
        if (
            node.attr in _PATH_INTERNAL_MODULE_ATTRIBUTES
            and (
                canonical_receiver in _CONCRETE_PATH_TYPES
                or self._path_expression(node.value)
            )
        ):
            self.finding(
                node,
                f"path_internal_module_access:{node.attr}",
                capability_exempt=False,
            )
        direct_module_attributes = _PROTECTED_DIRECT_MODULE_ATTRIBUTES.get(
            self.relative_path, {}
        )
        if (
            canonical_receiver in direct_module_attributes
            and node.attr not in direct_module_attributes[canonical_receiver]
        ):
            self.finding(
                node,
                f"unapproved_module_attribute:{canonical_receiver}.{node.attr}",
                capability_exempt=False,
            )
        if (
            canonical_receiver in direct_module_attributes
            and node.attr.lstrip("_") in _MODULE_CANONICAL
        ):
            self.finding(
                node,
                f"reexported_module_access:{canonical_receiver}.{node.attr}",
                capability_exempt=False,
            )
        if (
            canonical_node in _DYNAMIC_IMPORT_SYS_ATTRIBUTES
            and id(node) not in self.safe_sys_path_attribute_ids
            and not launcher_admission_safe
        ):
            self.finding(
                node,
                f"dynamic_import_state:{canonical_node}",
                capability_exempt=False,
            )
        facade_receiver = self._facade_receiver(node.value)
        facade_conflicted = self._facade_receiver_conflicted(node.value)
        parent = self.parent_map.get(node)
        if (
            facade_receiver
            and node.attr in _PUBLIC_REPOSITORY_METHODS
            and not (isinstance(parent, ast.Call) and parent.func is node)
        ):
            self.finding(
                node,
                f"repository_method_transport:{node.attr}",
                capability_exempt=False,
            )
        facade_object = (
            node.attr == "repository"
            and isinstance(node.value, ast.Name)
            and (
                node.value.id in self.validation_state_names
                or (
                    node.value.id == "self"
                    and self.class_stack[-1:] == ["ValidationState"]
                    and "ValidationState" in self.validation_state_type_names
                )
            )
        )
        if facade_object:
            next_parent = self.parent_map.get(node)
            final_parent = self.parent_map.get(next_parent) if next_parent else None
            if not (
                isinstance(next_parent, ast.Attribute)
                and next_parent.value is node
                and next_parent.attr in _PUBLIC_REPOSITORY_METHODS
                and isinstance(final_parent, ast.Call)
                and final_parent.func is next_parent
            ) and not self._reviewed_facade_argument(node):
                self.finding(
                    node,
                    "repository_facade_transport:repository",
                    capability_exempt=False,
                )
        if facade_receiver and facade_conflicted:
            self.finding(node, f"repository_io_ambiguous_receiver:{node.attr}")
        if (
            context_receiver
            and self._repository_context_receiver_conflicted(node.value)
            and node.attr in {"__enter__", "__exit__"}
        ):
            self.finding(
                node,
                f"repository_io_ambiguous_context:{node.attr}",
                capability_exempt=False,
            )
        if facade_receiver and node.attr not in _PUBLIC_REPOSITORY_METHODS:
            self.finding(node, f"repository_io_private_access:{node.attr}")
        module_receiver = canonical_receiver in _MODULE_CANONICAL or canonical_receiver in {"os.path", "pathlib.Path"}
        path_operation = node.attr in _UNAMBIGUOUS_PATH_METHODS or self._path_expression(node.value)
        if (
            node.attr in _PATH_METHODS
            and path_operation
            and not module_receiver
            and (not facade_receiver or facade_conflicted)
            and not self._safe_module_file_resolve(node)
        ):
            kind = "path_mutation" if node.attr in _PATH_MUTATION_METHODS else "path_convenience"
            self.finding(node, f"{kind}:{node.attr}")
        dangerous_reference = self._dangerous_canonical(canonical_node)
        if dangerous_reference:
            self.finding(node, f"dangerous_callable_reference:{dangerous_reference}")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if node.id in _DANGEROUS_NAMESPACE_NAMES:
            self.finding(
                node,
                "dynamic_namespace_access",
                capability_exempt=False,
            )
        if isinstance(node.ctx, ast.Load) and node.id in _DANGEROUS_BUILTIN_REFERENCES:
            self.finding(node, f"dangerous_builtin_reference:{node.id}")
        if not isinstance(node.ctx, ast.Load):
            return
        canonical = self._canonical(node)
        if (
            node.id in self.repository_names
            and id(node) not in self.safe_facade_public_receiver_ids
            and not self._none_identity_name_use(node)
            and not self._reviewed_facade_argument(node)
        ):
            self.finding(node, f"repository_facade_transport:{node.id}")
        if (
            node.id in self.repository_context_names
            and id(node) not in self.repository_use_safety.context_load_ids
        ):
            self.finding(
                node,
                f"repository_context_transport:{node.id}",
                capability_exempt=False,
            )
        if (
            node.id in self.validation_state_names
            and not self._validation_state_use_safe(node)
        ):
            self.finding(node, f"validation_state_transport:{node.id}")
        if (
            canonical
            in _PROTECTED_DIRECT_MODULE_ATTRIBUTES.get(self.relative_path, {})
            and id(node) not in self.safe_direct_module_receiver_ids
        ):
            self.finding(
                node,
                f"module_object_transport:{canonical}",
                capability_exempt=False,
            )
        if (
            canonical == "repository_io.open_repository_io"
            and id(node) not in self.repository_use_safety.opener_function_ids
        ):
            self.finding(
                node,
                "repository_opener_transport",
                capability_exempt=False,
            )
        if canonical == "repository_io.RepositoryIO":
            self.finding(
                node,
                "repository_facade_runtime_reference",
                capability_exempt=False,
            )
        if (
            node.id in self.local_capability_names
            and id(node) not in self.safe_main_reference_ids
        ):
            self.finding(node, f"local_capability_reference:{node.id}")
        if canonical in _POWERFUL_REPOSITORY_IO_CALLS:
            self.finding(node, f"controller_capability_reference:{canonical}")
        if canonical in _POWERFUL_CONTROLLER_STORE_CALLS:
            self.finding(node, f"controller_capability_reference:{canonical}")
        if canonical in _POWERFUL_EXECUTION_CONTROLLER_CALLS:
            self.finding(node, f"execution_capability_reference:{canonical}")

    def _dangerous_canonical(self, canonical: str | None) -> str | None:
        if not canonical:
            return None
        if canonical.startswith("os.path.") and canonical.rsplit(".", 1)[-1] in _OS_PATH_APIS:
            return canonical
        prefix, _, name = canonical.rpartition(".")
        if prefix == "os" and name in _OS_IO_APIS | _OS_PROCESS_APIS:
            return canonical
        if prefix == "glob" and name in _GLOB_APIS:
            return canonical
        if prefix == "shutil" and name in _SHUTIL_APIS:
            return canonical
        if prefix == "repository_evidence" and name in _REPOSITORY_EVIDENCE_IO:
            return canonical
        if prefix == "subprocess" and name in _SUBPROCESS_APIS:
            return canonical
        if prefix == "asyncio" and name in _ASYNC_PROCESS_APIS:
            return canonical
        if canonical.startswith("importlib."):
            return canonical
        if canonical.startswith("ctypes."):
            return canonical
        if prefix in {"pathlib.Path", "pathlib.PosixPath", "pathlib.WindowsPath"} and name in _PATH_METHODS:
            return canonical
        if canonical in _DIRECT_IO_CONSTRUCTORS | _OTHER_PROCESS_APIS:
            return canonical
        return None

    def visit_Call(self, node: ast.Call) -> None:
        canonical = self._canonical(node.func)
        if (
            canonical == "repository_io.open_repository_io"
            and id(node) not in self.repository_use_safety.opener_call_ids
        ):
            self.finding(
                node,
                "repository_context_transport:open_repository_io",
                capability_exempt=False,
            )
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "__enter__"
            and self._repository_context_receiver(node.func.value)
            and id(node) not in self.repository_use_safety.enter_call_ids
        ):
            self.finding(
                node,
                "repository_facade_result_transport",
                capability_exempt=False,
            )
        if canonical == "argparse.ArgumentParser" and any(
            keyword.arg == "fromfile_prefix_chars"
            and not (
                isinstance(keyword.value, ast.Constant)
                and keyword.value.value is None
            )
            for keyword in node.keywords
        ):
            self.finding(
                node,
                "raw_io:argparse.ArgumentParser.fromfile_prefix_chars",
            )
        if canonical in _POWERFUL_REPOSITORY_IO_CALLS:
            self.finding(node, f"controller_capability_use:{canonical}")
        if canonical in _POWERFUL_EXECUTION_CONTROLLER_CALLS:
            self.finding(node, f"execution_capability_use:{canonical}")
        if canonical in _POWERFUL_CONTROLLER_STORE_CALLS:
            self.finding(node, f"controller_capability_use:{canonical}")
        if isinstance(node.func, ast.Attribute) and node.func.attr in _RECEIVER_PROCESS_METHODS:
            self.finding(node, f"process_creation:receiver.{node.func.attr}")
        if isinstance(node.func, ast.Attribute) and node.func.attr in _PATH_METHODS:
            canonical_receiver = self._canonical(node.func.value)
            module_receiver = canonical_receiver in _MODULE_CANONICAL or canonical_receiver in {
                "os.path",
                "pathlib.Path",
            }
            path_operation = (
                node.func.attr in _UNAMBIGUOUS_PATH_METHODS
                or self._path_expression(node.func.value)
                or _ambiguous_path_call_signature(node.func.attr, node)
            )
            if (
                path_operation
                and not module_receiver
                and (
                    not self._facade_receiver(node.func.value)
                    or self._facade_receiver_conflicted(node.func.value)
                )
                and not self._safe_module_file_resolve(node.func)
            ):
                kind = (
                    "path_mutation"
                    if node.func.attr in _PATH_MUTATION_METHODS
                    else "path_convenience"
                )
                self.finding(node, f"{kind}:{node.func.attr}")
        elif isinstance(node.func, ast.Name) and canonical:
            aliased_method = canonical.rsplit(".", 1)[-1]
            if (
                aliased_method in _AMBIGUOUS_PATH_METHODS
                and _ambiguous_path_call_signature(aliased_method, node)
            ):
                kind = (
                    "path_mutation"
                    if aliased_method in _PATH_MUTATION_METHODS
                    else "path_convenience"
                )
                self.finding(node, f"{kind}:{aliased_method}")
        if canonical in {"open", "builtins.open", "io.open"}:
            self.finding(node, "builtin_open")
        dangerous = self._dangerous_canonical(canonical)
        if dangerous:
            if (
                dangerous.startswith(("subprocess.", "asyncio."))
                or dangerous in _OTHER_PROCESS_APIS
                or dangerous.startswith("os.") and dangerous.rsplit(".", 1)[-1] in _OS_PROCESS_APIS
            ):
                self.finding(node, f"process_creation:{dangerous}")
            elif dangerous.startswith("importlib."):
                self.finding(node, f"dynamic_import:{dangerous}")
            else:
                self.finding(node, f"raw_io:{dangerous}")

        if canonical in {"__import__", "builtins.__import__"}:
            self.finding(node, "dynamic_import:__import__")
        if canonical in {"eval", "exec", "compile", "builtins.eval", "builtins.exec", "builtins.compile"}:
            self.finding(node, f"dynamic_code:{canonical.rsplit('.', 1)[-1]}")
        if (
            canonical in {
                "getattr",
                "setattr",
                "delattr",
                "builtins.getattr",
                "builtins.setattr",
                "builtins.delattr",
                "__getattribute__",
                "__setattr__",
                "__delattr__",
            }
            or (
                canonical is not None
                and canonical.endswith(
                    (".__getattribute__", ".__setattr__", ".__delattr__")
                )
            )
        ) and id(node) not in self.safe_launcher_admission_node_ids:
            attribute = node.args[1].value if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant) else None
            dynamic_receiver = self._canonical(node.args[0]) if node.args else None
            if (
                not isinstance(attribute, str)
                or attribute in _DANGEROUS_DYNAMIC_ATTRIBUTES
                or dynamic_receiver == "ctypes"
                or (
                    dynamic_receiver is not None
                    and dynamic_receiver.startswith("ctypes.")
                )
            ):
                self.finding(node, f"dynamic_attribute:{attribute if isinstance(attribute, str) else 'nonliteral'}")
        if canonical in {"operator.attrgetter", "operator.methodcaller", "builtins.getattr"}:
            self.finding(node, "dynamic_attribute:indirect")
        if canonical in {"vars", "builtins.vars", "globals", "builtins.globals", "locals", "builtins.locals"}:
            self.finding(node, f"dynamic_namespace_call:{canonical}")
        self.generic_visit(node)


def _parse_python_source(relative_path: str, text: str) -> ast.Module:
    """Parse the same UTF-8 bytes Python would execute, including cookies."""

    tree = compile(
        text.encode("utf-8"),
        relative_path,
        "exec",
        flags=ast.PyCF_ONLY_AST,
        dont_inherit=True,
        optimize=0,
    )
    if not isinstance(tree, ast.Module):  # pragma: no cover - compile contract
        raise SyntaxError("python_module_ast_required")
    return tree


def _semantic_dotted_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _semantic_dotted_name(node.value)
        return f"{base}.{node.attr}" if base else None
    return None


def _semantic_probe_default(node: ast.AST) -> str:
    if isinstance(node, ast.Constant) and node.value in {None, False, 0}:
        return repr(node.value)
    if isinstance(node, ast.Tuple) and not node.elts:
        return "()"
    return "<dynamic>"


class _SemanticProfileInventory(ast.NodeVisitor):
    """Exact, digest-independent inventory for the two privileged loaders."""

    def __init__(self, relative_path: str, tree: ast.Module) -> None:
        self.relative_path = relative_path
        self.tree = tree
        self.parent_map = _parent_map(tree)
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.function_global_names: list[frozenset[str]] = []
        self.classes: list[str] = []
        self.functions: list[str] = []
        self.protected_definition_counts = {
            name: 0
            for name in (
                set(_PROTECTED_SEMANTIC_CLASSES[relative_path])
                | set(_PROTECTED_SEMANTIC_FUNCTIONS[relative_path])
            )
        }
        self.critical_function_shapes: dict[str, str] = {}
        self.critical_compare_shapes: dict[str, int] = {}
        self.critical_guard_shapes: dict[str, int] = {}
        self.import_bindings: list[tuple[str, str, str]] = []
        self.api_calls: dict[str, dict[str, int]] = {}
        self.sensitive_call_shapes: dict[str, dict[str, int]] = {}
        self.attribute_probes: dict[
            str, dict[tuple[str, str, str, str], int]
        ] = {}
        self.ctypes_library_names: set[str] = set()
        self.allowed_ctypes_library_load_ids: set[int] = set()
        self.findings: list[PolicyFinding] = []

    def _scope(self) -> str:
        return self.function_stack[-1] if self.function_stack else "__module__"

    @staticmethod
    def _increment(mapping: dict[object, int], key: object) -> None:
        mapping[key] = mapping.get(key, 0) + 1

    def _finding(self, node: ast.AST, symbol: str) -> None:
        self.findings.append(
            PolicyFinding(
                self.relative_path,
                int(getattr(node, "lineno", 1)),
                symbol,
            )
        )

    @staticmethod
    def _target_names(node: ast.AST) -> set[str]:
        if isinstance(node, ast.Name):
            return {node.id}
        if isinstance(node, (ast.List, ast.Tuple)):
            return {
                name
                for element in node.elts
                for name in _SemanticProfileInventory._target_names(element)
            }
        if isinstance(node, ast.Starred):
            return _SemanticProfileInventory._target_names(node.value)
        return set()

    @staticmethod
    def _function_globals(
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> frozenset[str]:
        names: set[str] = set()

        def collect(current: ast.AST) -> None:
            if isinstance(current, ast.Global):
                names.update(current.names)
                return
            if isinstance(
                current,
                (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef, ast.Lambda),
            ):
                return
            for child in ast.iter_child_nodes(current):
                collect(child)

        for statement in node.body:
            collect(statement)
        return frozenset(names)

    def _module_protected_binding_names(self) -> frozenset[str]:
        functions = _PROTECTED_SEMANTIC_FUNCTIONS[self.relative_path]
        return frozenset(
            {name for name in functions if "." not in name}
            | set(_PROTECTED_SEMANTIC_CLASSES[self.relative_path])
        )

    def _protected_binding_names(self) -> frozenset[str]:
        if self.function_stack:
            return frozenset(
                self._module_protected_binding_names()
                & self.function_global_names[-1]
            )
        functions = _PROTECTED_SEMANTIC_FUNCTIONS[self.relative_path]
        if not self.class_stack:
            return self._module_protected_binding_names()
        prefix = ".".join(self.class_stack) + "."
        return frozenset(
            name[len(prefix) :]
            for name in functions
            if name.startswith(prefix) and "." not in name[len(prefix) :]
        )

    def _check_protected_rebinding(self, node: ast.AST) -> None:
        protected = self._protected_binding_names()
        rebound = self._target_names(node) & protected
        dotted = _semantic_dotted_name(node)
        protected_roots = {
            name.split(".", 1)[0]
            for name in (
                set(_PROTECTED_SEMANTIC_FUNCTIONS[self.relative_path])
                | set(_PROTECTED_SEMANTIC_CLASSES[self.relative_path])
            )
        }
        if rebound or (
            not self.function_stack
            and not self.class_stack
            and dotted is not None
            and dotted.split(".", 1)[0] in protected_roots
        ):
            self._finding(node, "semantic_protected_binding_rebound")

    def _check_protected_binding_name(
        self,
        name: str | None,
        node: ast.AST,
    ) -> None:
        if name is not None and name in self._protected_binding_names():
            self._finding(node, "semantic_protected_binding_rebound")

    def _definition_is_canonical(
        self,
        node: ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef,
        qualified: str,
    ) -> bool:
        protected_classes = _PROTECTED_SEMANTIC_CLASSES[self.relative_path]
        protected_functions = _PROTECTED_SEMANTIC_FUNCTIONS[self.relative_path]
        expected_decorators = _PROTECTED_SEMANTIC_DEFINITION_DECORATORS[
            self.relative_path
        ].get(qualified, ())
        actual_decorators = tuple(
            ast.unparse(decorator) for decorator in node.decorator_list
        )
        if actual_decorators != expected_decorators:
            return False
        parent = self.parent_map.get(node)
        if qualified in protected_classes:
            return type(node) is ast.ClassDef and isinstance(parent, ast.Module)
        if qualified not in protected_functions or type(node) is not ast.FunctionDef:
            return False
        owner, separator, _name = qualified.rpartition(".")
        if not separator:
            return isinstance(parent, ast.Module)
        return (
            isinstance(parent, ast.ClassDef)
            and parent.name == owner
            and isinstance(self.parent_map.get(parent), ast.Module)
        )

    def _visit_arguments_in_enclosing_scope(self, arguments: ast.arguments) -> None:
        for argument in (
            *arguments.posonlyargs,
            *arguments.args,
            *arguments.kwonlyargs,
        ):
            if argument.annotation is not None:
                self.visit(argument.annotation)
        if arguments.vararg is not None and arguments.vararg.annotation is not None:
            self.visit(arguments.vararg.annotation)
        if arguments.kwarg is not None and arguments.kwarg.annotation is not None:
            self.visit(arguments.kwarg.annotation)
        for default in arguments.defaults:
            self.visit(default)
        for default in arguments.kw_defaults:
            if default is not None:
                self.visit(default)

    def _visit_function_header_in_enclosing_scope(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        for decorator in node.decorator_list:
            self.visit(decorator)
        self._visit_arguments_in_enclosing_scope(node.args)
        if node.returns is not None:
            self.visit(node.returns)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        qualified = ".".join((*self.class_stack, node.name))
        self.classes.append(qualified)
        if qualified in self.protected_definition_counts:
            self.protected_definition_counts[qualified] += 1
            if not self._definition_is_canonical(node, qualified):
                self._finding(
                    node,
                    "semantic_protected_definition_misplaced",
                )
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        for keyword in node.keywords:
            self.visit(keyword.value)
        for type_parameter in getattr(node, "type_params", ()):
            self.visit(type_parameter)
        self.class_stack.append(node.name)
        for statement in node.body:
            self.visit(statement)
        self.class_stack.pop()

    def visit_FunctionDef(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> None:
        if self.function_stack:
            qualified = f"{self.function_stack[-1]}.{node.name}"
        else:
            qualified = ".".join((*self.class_stack, node.name))
        self.functions.append(qualified)
        if qualified in self.protected_definition_counts:
            self.protected_definition_counts[qualified] += 1
            if not self._definition_is_canonical(node, qualified):
                self._finding(
                    node,
                    "semantic_protected_definition_misplaced",
                )
        if qualified in _PROTECTED_SEMANTIC_CRITICAL_FUNCTION_SHAPES[
            self.relative_path
        ]:
            self.critical_function_shapes[qualified] = ast.unparse(node)
        self._visit_function_header_in_enclosing_scope(node)
        self.function_stack.append(qualified)
        self.function_global_names.append(self._function_globals(node))
        for statement in node.body:
            self.visit(statement)
        self.function_global_names.pop()
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_arguments_in_enclosing_scope(node.args)
        self.function_stack.append("<lambda>")
        self.function_global_names.append(frozenset())
        self.visit(node.body)
        self.function_global_names.pop()
        self.function_stack.pop()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.import_bindings.append((alias.name, "", alias.asname or ""))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = ("." * node.level) + (node.module or "")
        for alias in node.names:
            self.import_bindings.append(
                (module, alias.name, alias.asname or "")
            )
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self._check_protected_rebinding(target)
        if (
            isinstance(node.value, ast.Call)
            and _semantic_dotted_name(node.value.func) == "ctypes.CDLL"
        ):
            self.ctypes_library_names.update(
                target.id for target in node.targets if isinstance(target, ast.Name)
            )
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self._check_protected_rebinding(node.target)
        if (
            isinstance(node.value, ast.Call)
            and _semantic_dotted_name(node.value.func) == "ctypes.CDLL"
        ):
            if isinstance(node.target, ast.Name):
                self.ctypes_library_names.add(node.target.id)
            else:
                self._finding(node, "semantic_ctypes_library_transport_invalid")
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self._check_protected_rebinding(node.target)
        self.generic_visit(node)

    def visit_NamedExpr(self, node: ast.NamedExpr) -> None:
        self._check_protected_rebinding(node.target)
        if (
            isinstance(node.value, ast.Call)
            and _semantic_dotted_name(node.value.func) == "ctypes.CDLL"
        ):
            if isinstance(node.target, ast.Name):
                self.ctypes_library_names.add(node.target.id)
            else:  # pragma: no cover - NamedExpr grammar requires Name
                self._finding(node, "semantic_ctypes_library_transport_invalid")
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete) -> None:
        for target in node.targets:
            self._check_protected_rebinding(target)
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self._check_protected_rebinding(node.target)
        self.generic_visit(node)

    visit_AsyncFor = visit_For

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars is not None:
                self._check_protected_rebinding(item.optional_vars)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self._check_protected_binding_name(node.name, node)
        self.generic_visit(node)

    def visit_MatchAs(self, node: ast.MatchAs) -> None:
        self._check_protected_binding_name(node.name, node)
        self.generic_visit(node)

    def visit_MatchStar(self, node: ast.MatchStar) -> None:
        self._check_protected_binding_name(node.name, node)
        self.generic_visit(node)

    def visit_MatchMapping(self, node: ast.MatchMapping) -> None:
        self._check_protected_binding_name(node.rest, node)
        self.generic_visit(node)

    def visit_Compare(self, node: ast.Compare) -> None:
        shape = ast.unparse(node)
        lowered = shape.lower()
        if "sha256" in lowered or "digest" in lowered:
            self._increment(self.critical_compare_shapes, shape)
        self.generic_visit(node)

    def _visit_critical_guard(
        self, node: ast.If | ast.IfExp | ast.While | ast.Assert
    ) -> None:
        relevant = any(
            isinstance(item, ast.Compare)
            and (
                "sha256" in ast.unparse(item).lower()
                or "digest" in ast.unparse(item).lower()
            )
            for item in ast.walk(node.test)
        )
        if relevant:
            self._increment(self.critical_guard_shapes, ast.unparse(node))
        self.generic_visit(node)

    visit_If = _visit_critical_guard
    visit_IfExp = _visit_critical_guard
    visit_While = _visit_critical_guard
    visit_Assert = _visit_critical_guard

    def visit_Attribute(self, node: ast.Attribute) -> None:
        receiver = _semantic_dotted_name(node.value)
        inline_library = (
            isinstance(node.value, ast.Call)
            and _semantic_dotted_name(node.value.func) == "ctypes.CDLL"
        ) or (
            isinstance(node.value, ast.NamedExpr)
            and isinstance(node.value.value, ast.Call)
            and _semantic_dotted_name(node.value.value.func) == "ctypes.CDLL"
        )
        if receiver in self.ctypes_library_names or inline_library:
            self._finding(node, "semantic_ctypes_symbol_invalid")
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        receiver = _semantic_dotted_name(node.value)
        inline_library = (
            isinstance(node.value, ast.Call)
            and _semantic_dotted_name(node.value.func) == "ctypes.CDLL"
        ) or (
            isinstance(node.value, ast.NamedExpr)
            and isinstance(node.value.value, ast.Call)
            and _semantic_dotted_name(node.value.value.func) == "ctypes.CDLL"
        )
        if receiver in self.ctypes_library_names or inline_library:
            self._finding(node, "semantic_ctypes_symbol_invalid")
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if (
            isinstance(node.ctx, ast.Load)
            and node.id in self.ctypes_library_names
            and id(node) not in self.allowed_ctypes_library_load_ids
        ):
            self._finding(node, "semantic_ctypes_library_transport_invalid")

    def visit_Call(self, node: ast.Call) -> None:
        canonical = _semantic_dotted_name(node.func)
        scope = self._scope()
        if canonical in {"getattr", "hasattr"}:
            receiver = _semantic_dotted_name(node.args[0]) if node.args else None
            if (
                canonical == "getattr"
                and node.args
                and isinstance(node.args[0], ast.Name)
                and node.args[0].id in self.ctypes_library_names
            ):
                self.allowed_ctypes_library_load_ids.add(id(node.args[0]))
            attribute = "<dynamic>"
            if len(node.args) >= 2:
                if (
                    isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                ):
                    attribute = node.args[1].value
                elif (
                    self.relative_path == "scripts/skill_root_authority.py"
                    and scope == "_load_held_mount_module"
                    and isinstance(node.args[1], ast.Name)
                    and node.args[1].id == "name"
                ):
                    attribute = "<required_callable>"
            default = ""
            if canonical == "getattr":
                default = (
                    _semantic_probe_default(node.args[2])
                    if len(node.args) == 3
                    else "<dynamic>"
                )
            if node.keywords or receiver is None or (
                canonical == "hasattr" and len(node.args) != 2
            ):
                receiver = receiver or "<dynamic>"
                attribute = "<dynamic>"
            probes = self.attribute_probes.setdefault(scope, {})
            self._increment(
                probes,
                (canonical, receiver, attribute, default),
            )

        if canonical and (
            canonical.startswith(("os.", "ctypes.", "importlib."))
            or canonical in {"__import__", "compile", "eval", "exec", "open"}
        ):
            calls = self.api_calls.setdefault(scope, {})
            self._increment(calls, canonical)
        if canonical in _SEMANTIC_SENSITIVE_CALLS:
            shapes = self.sensitive_call_shapes.setdefault(scope, {})
            self._increment(shapes, ast.unparse(node))

        if canonical == "ctypes.CDLL" and not (
            len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value is None
            and len(node.keywords) == 1
            and node.keywords[0].arg == "use_errno"
            and isinstance(node.keywords[0].value, ast.Constant)
            and node.keywords[0].value.value is True
        ):
            self._finding(node, "semantic_ctypes_library_invalid")

        if canonical == "importlib.util.spec_from_loader" and not (
            len(node.args) == 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "fullname"
            and isinstance(node.args[1], ast.Name)
            and node.args[1].id == "self"
            and len(node.keywords) == 1
            and node.keywords[0].arg == "origin"
            and isinstance(node.keywords[0].value, ast.Call)
            and _semantic_dotted_name(node.keywords[0].value.func) == "os.path.join"
        ):
            self._finding(node, "semantic_importlib_loader_invalid")

        if canonical == "compile":
            expected_keywords = (
                {"dont_inherit"}
                if self.relative_path == "scripts/skill_root_authority.py"
                else {"dont_inherit", "flags", "optimize"}
            )
            if not (
                len(node.args) == 3
                and isinstance(node.args[2], ast.Constant)
                and node.args[2].value == "exec"
                and {keyword.arg for keyword in node.keywords} == expected_keywords
                and all(keyword.arg is not None for keyword in node.keywords)
            ):
                self._finding(node, "semantic_compile_shape_invalid")

        if canonical == "exec" and not (
            node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "code"
            and not node.keywords
            and len(node.args) in {2, 3}
        ):
            self._finding(node, "semantic_exec_shape_invalid")
        self.generic_visit(node)


def _semantic_profile_findings(
    relative_path: str, tree: ast.Module
) -> list[PolicyFinding]:
    if relative_path not in _SEMANTIC_PROFILE_PATHS:
        return []
    visitor = _SemanticProfileInventory(relative_path, tree)
    visitor.visit(tree)
    if any(
        count != 1 for count in visitor.protected_definition_counts.values()
    ):
        visitor.findings.append(
            PolicyFinding(
                relative_path,
                1,
                "semantic_protected_definition_misplaced",
            )
        )
    if (
        len(visitor.classes) != len(_PROTECTED_SEMANTIC_CLASSES[relative_path])
        or frozenset(visitor.classes)
        != _PROTECTED_SEMANTIC_CLASSES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_class_inventory_mismatch")
        )
    if (
        len(visitor.functions)
        != len(_PROTECTED_SEMANTIC_FUNCTIONS[relative_path])
        or frozenset(visitor.functions)
        != _PROTECTED_SEMANTIC_FUNCTIONS[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_function_inventory_mismatch")
        )
    expected_imports = _PROTECTED_SEMANTIC_IMPORT_BINDINGS[relative_path]
    if (
        len(visitor.import_bindings) != len(expected_imports)
        or frozenset(visitor.import_bindings) != expected_imports
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_import_inventory_mismatch")
        )
    if visitor.api_calls != _PROTECTED_SEMANTIC_API_CALLS[relative_path]:
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_api_inventory_mismatch")
        )
    if (
        visitor.critical_function_shapes
        != _PROTECTED_SEMANTIC_CRITICAL_FUNCTION_SHAPES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_critical_function_mismatch")
        )
    if (
        visitor.critical_compare_shapes
        != _PROTECTED_SEMANTIC_CRITICAL_COMPARE_SHAPES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_critical_compare_mismatch")
        )
    if (
        visitor.critical_guard_shapes
        != _PROTECTED_SEMANTIC_CRITICAL_GUARD_SHAPES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_critical_guard_mismatch")
        )
    if (
        visitor.sensitive_call_shapes
        != _PROTECTED_SEMANTIC_SENSITIVE_CALL_SHAPES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_call_shape_inventory_mismatch")
        )
    if (
        visitor.attribute_probes
        != _PROTECTED_SEMANTIC_ATTRIBUTE_PROBES[relative_path]
    ):
        visitor.findings.append(
            PolicyFinding(relative_path, 1, "semantic_attribute_probe_inventory_mismatch")
        )
    return sorted(set(visitor.findings))


class _ApplyRequestStdinAccessInventory(ast.NodeVisitor):
    """Exact sys.argv/stdin surface for Apply's request-stdin admission."""

    def __init__(self) -> None:
        self.function_stack: list[str] = []
        self.shapes: dict[str, dict[str, int]] = {}

    def _scope(self) -> str:
        return self.function_stack[-1] if self.function_stack else "__module__"

    def _record(self, kind: str, node: ast.AST) -> None:
        values = self.shapes.setdefault(self._scope(), {})
        shape = f"{kind}:{ast.unparse(node)}"
        values[shape] = values.get(shape, 0) + 1

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        qualified = (
            f"{self.function_stack[-1]}.{node.name}"
            if self.function_stack
            else node.name
        )
        self.function_stack.append(qualified)
        self.generic_visit(node)
        self.function_stack.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_Attribute(self, node: ast.Attribute) -> None:
        canonical = _semantic_dotted_name(node)
        if canonical and canonical.startswith(("sys.argv", "sys.stdin")):
            self._record("Attribute", node)
        self.generic_visit(node)

    def visit_Subscript(self, node: ast.Subscript) -> None:
        canonical = _semantic_dotted_name(node.value)
        if canonical and canonical.startswith(("sys.argv", "sys.stdin")):
            self._record("Subscript", node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        canonical = _semantic_dotted_name(node.func)
        if canonical and canonical.startswith(("sys.argv", "sys.stdin")):
            self._record("Call", node)
        self.generic_visit(node)


def _apply_request_stdin_access_findings(
    relative_path: str, tree: ast.Module
) -> list[PolicyFinding]:
    if relative_path != "scripts/apply_run.py":
        return []
    visitor = _ApplyRequestStdinAccessInventory()
    visitor.visit(tree)
    if visitor.shapes == _APPLY_REQUEST_STDIN_ACCESS_SHAPES:
        return []
    return [
        PolicyFinding(
            relative_path,
            1,
            "apply_request_stdin_access_inventory_mismatch",
        )
    ]


def _goal_held_reader_contract_findings(
    relative_path: str,
    tree: ast.Module,
) -> list[PolicyFinding]:
    """Bind the Goal held-byte capability to one import and one definition."""

    if relative_path != "scripts/goal_run.py":
        return []
    findings: list[PolicyFinding] = []
    parents = _parent_map(tree)
    execution_imports: list[ast.Import | ast.ImportFrom] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.split(".")[-1:] == ["execution_controller"]:
                execution_imports.append(node)
        elif isinstance(node, ast.Import) and any(
            alias.name.split(".")[-1:] == ["execution_controller"]
            for alias in node.names
        ):
            execution_imports.append(node)
    reader_definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(
            node,
            (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef),
        )
        and node.name == "read_skill_bytes"
    ]
    reader_surface_observed = bool(
        reader_definitions
        or any(
            isinstance(node, ast.Name) and node.id == "read_goal_held_bytes"
            for node in ast.walk(tree)
        )
        or any(
            isinstance(node, ast.ImportFrom)
            and any(alias.name == "read_goal_held_bytes" for alias in node.names)
            for node in execution_imports
        )
    )
    import_valid = bool(
        reader_surface_observed
        and len(execution_imports) == 1
        and type(execution_imports[0]) is ast.ImportFrom
        and parents.get(execution_imports[0]) is tree
        and execution_imports[0].level == 0
        and execution_imports[0].module == "execution_controller"
        and tuple(
            (alias.name, alias.asname) for alias in execution_imports[0].names
        )
        == tuple(
            (name, None) for name in _GOAL_EXECUTION_CONTROLLER_IMPORT_CONTRACT
        )
    )
    if reader_surface_observed and not import_valid:
        node = execution_imports[0] if execution_imports else tree
        findings.append(
            PolicyFinding(
                relative_path,
                int(getattr(node, "lineno", 1)),
                "goal_execution_controller_import_contract_mismatch",
            )
        )

    reader_valid = bool(
        reader_surface_observed
        and len(reader_definitions) == 1
        and type(reader_definitions[0]) is ast.FunctionDef
        and parents.get(reader_definitions[0]) is tree
        and _body_digest(reader_definitions[0])
        == _GOAL_HELD_READER_DEFINITION_DIGEST
    )
    if reader_surface_observed and not reader_valid:
        node = reader_definitions[0] if reader_definitions else tree
        findings.append(
            PolicyFinding(
                relative_path,
                int(getattr(node, "lineno", 1)),
                "goal_held_reader_definition_contract_mismatch",
            )
        )

    validator_only_import_valid = bool(
        not reader_surface_observed
        and len(execution_imports) == 1
        and type(execution_imports[0]) is ast.ImportFrom
        and parents.get(execution_imports[0]) is tree
        and execution_imports[0].level == 0
        and execution_imports[0].module == "execution_controller"
        and tuple(
            (alias.name, alias.asname) for alias in execution_imports[0].names
        )
        == (("run_goal_planner_validator", None),)
    )
    canonical_import = (
        execution_imports[0]
        if import_valid or validator_only_import_valid
        else None
    )
    canonical_reader = reader_definitions[0] if reader_valid else None
    rebound_nodes: list[ast.AST] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".", 1)[0]
                if (
                    alias.name == "*"
                    or local_name in _GOAL_HELD_READER_PROTECTED_BINDINGS
                ):
                    rebound_nodes.append(node)
        elif isinstance(node, ast.ImportFrom) and node is not canonical_import:
            for alias in node.names:
                local_name = alias.asname or alias.name
                if (
                    alias.name == "*"
                    or local_name in _GOAL_HELD_READER_PROTECTED_BINDINGS
                ):
                    rebound_nodes.append(node)
        elif isinstance(
            node,
            (ast.AsyncFunctionDef, ast.ClassDef, ast.FunctionDef),
        ):
            if (
                node is not canonical_reader
                and node.name in _GOAL_HELD_READER_PROTECTED_BINDINGS
            ):
                rebound_nodes.append(node)
        elif isinstance(node, ast.Name) and isinstance(
            node.ctx,
            (ast.Del, ast.Store),
        ):
            if node.id in _GOAL_HELD_READER_PROTECTED_BINDINGS:
                rebound_nodes.append(node)
        elif isinstance(node, ast.ExceptHandler):
            if node.name in _GOAL_HELD_READER_PROTECTED_BINDINGS:
                rebound_nodes.append(node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)):
            if node.name in _GOAL_HELD_READER_PROTECTED_BINDINGS:
                rebound_nodes.append(node)
        elif isinstance(node, ast.MatchMapping):
            if node.rest in _GOAL_HELD_READER_PROTECTED_BINDINGS:
                rebound_nodes.append(node)
    for node in rebound_nodes:
        findings.append(
            PolicyFinding(
                relative_path,
                int(getattr(node, "lineno", 1)),
                "goal_held_reader_binding_rebound",
            )
        )
    return findings


def scan_python(relative_path: str, text: str) -> list[PolicyFinding]:
    try:
        tree = _parse_python_source(relative_path, text)
    except SyntaxError as exc:
        return [PolicyFinding(relative_path, int(exc.lineno or 1), "invalid_python")]
    findings: list[PolicyFinding] = []
    future_annotations = [
        statement
        for statement in tree.body
        if isinstance(statement, ast.ImportFrom)
        and statement.level == 0
        and statement.module == "__future__"
        and [alias.name for alias in statement.names] == ["annotations"]
    ]
    if len(future_annotations) != 1:
        findings.append(
            PolicyFinding(relative_path, 1, "future_annotations_contract_missing")
        )
    findings.extend(_semantic_profile_findings(relative_path, tree))
    findings.extend(_apply_request_stdin_access_findings(relative_path, tree))
    findings.extend(_goal_held_reader_contract_findings(relative_path, tree))

    names_by_digest: dict[str, set[str]] = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names_by_digest.setdefault(_body_digest(node), set()).add(node.name)

    local_capability_names: set[str] = set()
    parents = _parent_map(tree)
    repository_safety = _repository_use_safety(tree)
    path_return_names = _local_path_return_names(tree)
    safe_launcher_admission_node_ids = _safe_launcher_admission_node_ids(
        tree, relative_path
    )
    safe_sys_path_attribute_ids = _safe_sys_path_attribute_ids(
        tree, safe_launcher_admission_node_ids
    )
    visitor: PythonBypassVisitor | None = None
    # The call/reference graph can be recursive, so discover capability-taint
    # to a fixed point.  A wrapper around a reviewed descriptor primitive is a
    # capability too; otherwise an unreviewed caller could invoke the wrapper
    # and bypass the body-digest gate.
    for _ in range(len(names_by_digest) + 1):
        visitor = PythonBypassVisitor(
            relative_path,
            safe_sys_path_attribute_ids=safe_sys_path_attribute_ids,
            safe_launcher_admission_node_ids=safe_launcher_admission_node_ids,
            safe_main_reference_ids=_safe_main_entrypoint_reference_ids(tree),
            safe_direct_module_receiver_ids=_safe_direct_module_receiver_ids(
                tree, relative_path
            ),
            repository_use_safety=repository_safety,
            safe_facade_public_receiver_ids=_safe_facade_public_receiver_ids(
                tree, parents
            ),
            parent_map=parents,
            local_capability_names=frozenset(local_capability_names),
            local_path_return_names=path_return_names,
        )
        visitor.visit(tree)
        discovered = {
            name
            for digest in visitor.capability_function_digests
            for name in names_by_digest.get(digest, set())
        }
        if discovered.issubset(local_capability_names):
            break
        local_capability_names.update(discovered)
    if visitor is None:  # pragma: no cover - the loop always executes once
        return findings
    findings.extend(visitor.findings)
    return sorted(set(findings))


def _scan_ast_pinned_runtime(
    relative_path: str,
    text: str,
    *,
    expected_digest: str,
    mismatch_symbol: str,
) -> list[PolicyFinding]:
    try:
        tree = _parse_python_source(relative_path, text)
    except SyntaxError as exc:
        return [PolicyFinding(relative_path, int(exc.lineno or 1), "invalid_python")]
    digest = hashlib.sha256(_canonical_ast_dump(tree).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, expected_digest):
        return [PolicyFinding(relative_path, 1, mismatch_symbol)]
    return []


def scan_controller_store(relative_path: str, text: str) -> list[PolicyFinding]:
    """Require the reviewed owner-only controller store implementation."""

    return _scan_ast_pinned_runtime(
        relative_path,
        text,
        expected_digest=_APPROVED_CONTROLLER_STORE_AST_DIGEST,
        mismatch_symbol="controller_store_unreviewed",
    )


def scan_execution_controller(relative_path: str, text: str) -> list[PolicyFinding]:
    """Require the reviewed, non-extensible process execution boundary."""

    return _scan_ast_pinned_runtime(
        relative_path,
        text,
        expected_digest=_APPROVED_EXECUTION_CONTROLLER_AST_DIGEST,
        mismatch_symbol="execution_controller_unreviewed",
    )


def scan_trusted_controller(
    relative_path: str,
    text: str,
    *,
    expected_digest: str,
    allowed_repository_io_imports: frozenset[str],
) -> list[PolicyFinding]:
    """Validate one explicitly registered host/controller boundary.

    This is deliberately not a filename-pattern exemption.  A future
    controller is trusted only when its exact relative path, exact private
    repository-I/O imports, and whole-module AST digest are enrolled together.
    Public/model-facing RepositoryIO output is never available to this class of
    controller.
    """

    findings: list[PolicyFinding] = []
    if (
        re.fullmatch(r"scripts/[a-z][a-z0-9_]*\.py", relative_path) is None
        or relative_path in _CORE_REQUIRED_RUNTIME
    ):
        findings.append(
            PolicyFinding(relative_path, 1, "trusted_controller_path_not_exact")
        )
    if re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None:
        findings.append(
            PolicyFinding(relative_path, 1, "trusted_controller_digest_invalid")
        )
    if any(
        re.fullmatch(r"_controller_[a-z][a-z0-9_]*", name) is None
        for name in allowed_repository_io_imports
    ):
        findings.append(
            PolicyFinding(relative_path, 1, "trusted_controller_import_registry_invalid")
        )
    try:
        tree = _parse_python_source(relative_path, text)
    except SyntaxError as exc:
        findings.append(
            PolicyFinding(relative_path, int(exc.lineno or 1), "invalid_python")
        )
        return sorted(set(findings))

    digest = hashlib.sha256(_canonical_ast_dump(tree).encode("utf-8")).hexdigest()
    if not hmac.compare_digest(digest, expected_digest):
        findings.append(
            PolicyFinding(relative_path, 1, "trusted_controller_unreviewed")
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.rsplit(".", 1)[-1] == "repository_io":
                    findings.append(
                        PolicyFinding(
                            relative_path,
                            int(getattr(node, "lineno", 1)),
                            "trusted_controller_repository_module_import",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module.rsplit(".", 1)[-1] != "repository_io":
                continue
            noncanonical = node.level != 0 or module != "repository_io"
            for alias in node.names:
                if noncanonical or alias.name not in allowed_repository_io_imports:
                    findings.append(
                        PolicyFinding(
                            relative_path,
                            int(getattr(node, "lineno", 1)),
                            f"trusted_controller_repository_import:{alias.name}",
                        )
                    )
        elif isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr in _PUBLIC_REPOSITORY_METHODS:
                findings.append(
                    PolicyFinding(
                        relative_path,
                        int(getattr(node, "lineno", 1)),
                        f"trusted_controller_repository_output:{node.func.attr}",
                    )
                )
            if any(keyword.arg == "audience" for keyword in node.keywords):
                findings.append(
                    PolicyFinding(
                        relative_path,
                        int(getattr(node, "lineno", 1)),
                        "trusted_controller_audience_output",
                    )
                )
            if (
                isinstance(node.func, ast.Name)
                and node.func.id == "getattr"
                and (
                    len(node.args) < 2
                    or not isinstance(node.args[1], ast.Constant)
                    or node.args[1].value in _PUBLIC_REPOSITORY_METHODS
                )
            ):
                attribute = (
                    node.args[1].value
                    if len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant)
                    and isinstance(node.args[1].value, str)
                    else "nonliteral"
                )
                findings.append(
                    PolicyFinding(
                        relative_path,
                        int(getattr(node, "lineno", 1)),
                        f"trusted_controller_dynamic_access:{attribute}",
                    )
                )
        if isinstance(node, ast.Attribute) and node.attr in _DANGEROUS_NAMESPACE_ATTRIBUTES:
            findings.append(
                PolicyFinding(
                    relative_path,
                    int(getattr(node, "lineno", 1)),
                    "trusted_controller_dynamic_access:namespace",
                )
            )
        if isinstance(node, ast.Name) and node.id in (
            _DANGEROUS_NAMESPACE_NAMES | _DANGEROUS_BUILTIN_REFERENCES
        ):
            findings.append(
                PolicyFinding(
                    relative_path,
                    int(getattr(node, "lineno", 1)),
                    "trusted_controller_dynamic_access:namespace",
                )
            )
    return sorted(set(findings))


def _json_command_strings(value: object) -> Iterator[str]:
    """Yield only explicit command-bearing JSON values.

    Treating every JSON string as executable makes ordinary schemas look like
    shell programs (for example, a regex ending in ``$"``).  Command-bearing
    keys remain fail-closed, including nested objects and argv arrays.
    """

    if isinstance(value, list):
        for item in value:
            yield from _json_command_strings(item)
        return
    if not isinstance(value, dict):
        return
    for key, item in value.items():
        if str(key).casefold() in {"command", "cmd", "script", "argv"}:
            if isinstance(item, str):
                yield item
            elif isinstance(item, list) and item and all(
                isinstance(argument, str) for argument in item
            ):
                yield shlex.join(item)
            else:
                # A malformed command field is still traversed so a nested
                # executable value cannot hide behind an unexpected shape.
                yield from _json_command_strings(item)
            continue
        yield from _json_command_strings(item)


def _xml_command_value(value: str) -> str:
    candidate = html.unescape(value).strip()
    if candidate.startswith("<![CDATA[") and candidate.endswith("]]>"):
        candidate = candidate[9:-3]
    return re.sub(r"<[^>]*>", " ", candidate).strip()


def _clean_command_surface(line: str) -> str:
    value = unicodedata.normalize("NFKC", html.unescape(line)).strip()
    while value.startswith(">"):
        value = value[1:].lstrip()
    match = _LIST_PREFIX_RE.match(value)
    if match:
        value = match.group(1).strip()
    if value.startswith("$ "):
        value = value[1:].lstrip()
    return _HTML_TAG_RE.sub(" ", value).strip()


def _shell_syntax_fragment(value: str) -> str:
    """Remove policy placeholders before interpreting shell metacharacters."""

    return _PLACEHOLDER_RE.sub("PLACEHOLDER", value)


def _command_syntax_evidence(tokens: list[str], fragment: str) -> bool:
    fragment = _shell_syntax_fragment(fragment)
    tokens = _shell_tokens(fragment) or tokens
    if len(tokens) < 2:
        return bool(
            _SHELL_REDIRECTION_RE.search(fragment)
            or _SHELL_PROCESS_SUBSTITUTION_RE.search(fragment)
        )
    operand = tokens[1]
    return bool(
        operand.startswith(("-", ".", "/", "~", "$", "<", ">"))
        or "/" in operand
        or re.search(r"\.[A-Za-z0-9_-]{1,12}(?:$|[?#])", operand)
        or _SHELL_REDIRECTION_RE.search(fragment)
        or _SHELL_PROCESS_SUBSTITUTION_RE.search(fragment)
    )


def _surface_starts_command(value: str) -> bool:
    if not value or value.startswith("`"):
        return False
    if _PLACEHOLDER_RE.fullmatch(value) or _PLACEHOLDER_LINE_RE.fullmatch(value):
        return False
    value = _shell_syntax_fragment(value)
    if _SHELL_RESERVED_GRAMMAR_RE.search(value):
        return True
    if _SHELL_DOLLAR_FORM_RE.search(value):
        return True
    if _SHELL_PROCESS_SUBSTITUTION_RE.search(value):
        return True
    leading_input = re.match(r"^\s*\d*<<?\s*(?P<target>\S+)", value)
    if leading_input and re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)", leading_input.group("target")) is None:
        return True
    tokens = _shell_tokens(value)
    if tokens is None:
        return bool(
            _LAUNCHER_PATH in value
            or any(path in value for path in _CONTROLLER_PATHS)
            or re.match(
                r'^\s*["\']?python(?:3(?:\.\d+)?)?(?:\s|["\'])',
                value,
            )
        )
    if not tokens:
        return False
    if _dynamic_shell_surface(tokens, value):
        return True
    unwrapped = _unwrap_command(tokens)
    if not unwrapped:
        return False
    name = _command_name(unwrapped)
    raw_name = unwrapped[0]
    path_executable = len(unwrapped) >= 2 and raw_name.startswith(
        ("/", "./", "../", "~/")
    )
    raw_name_is_command = name in _RAW_COMMANDS and (
        name not in _AMBIGUOUS_PROSE_COMMANDS
        or _command_syntax_evidence(unwrapped, value)
    )
    redirect_command = _SHELL_REDIRECTION_RE.search(value) is not None and (
        name == ":"
        or name in _RAW_COMMANDS | _MUTATING_COMMANDS | _INTERPRETERS
        or re.match(r"^\S+[<>]", value) is not None
    )
    if (
        raw_name_is_command
        or redirect_command
        or name in _MUTATING_COMMANDS | _INTERPRETERS
        or name in {"git", "echo", "printf"}
        or _dangerous_shell_builtin(unwrapped)
        or name in _WRAPPERS
        or _python_command_name(name)
        or name == "repository_io.py"
        or name in {"apply_run.py", "goal_run.py"}
        or path_executable
    ):
        return True
    return (
        len(unwrapped) >= 2
        and unwrapped[1].startswith("-")
        and re.fullmatch(r"-+>", unwrapped[1]) is None
        and bool(re.fullmatch(r"[a-z0-9_./+@%-]+", name))
    )


def _inline_context_has_shell_syntax(value: str) -> bool:
    cleaned = _clean_command_surface(value)
    return bool(
        _SHELL_CONTROL_RE.search(cleaned)
        or _SHELL_REDIRECTION_RE.search(cleaned)
        or _SHELL_DOLLAR_FORM_RE.search(cleaned)
        or _SHELL_PROCESS_SUBSTITUTION_RE.search(cleaned)
        or "\\" in cleaned
        or re.search(r"(?:^|\s)--[A-Za-z0-9]", cleaned)
        or re.search(r"(?:^|\s)(?:/|~/|\.{1,2}/)\S*", cleaned)
        or any(_SHELL_ASSIGNMENT_RE.fullmatch(token) for token in cleaned.split())
    )


def _inline_controller_context_is_unsafe(
    line: str,
    match: re.Match[str],
) -> bool:
    command = match.group(1)
    tokens = _shell_tokens(command)
    if not (
        tokens is not None
        and len(tokens) >= 10
        and tokens[8] in {"repository-io", "apply"}
        and _approved_controller_command(tokens, command)
    ):
        return False
    before = line[: match.start()]
    after = line[match.end() :]
    cleaned_before = _clean_command_surface(before)
    cleaned_after = _clean_command_surface(after)
    if _inline_context_has_shell_syntax(before) or _inline_context_has_shell_syntax(after):
        return True
    if cleaned_before and _surface_starts_command(cleaned_before):
        return True
    if cleaned_after in {"", "."}:
        return False
    return re.fullmatch(
        r",?\s*(?:and|then)\s+"
        r"(?:send|pass|retain|compare|review|record)\b"
        r"[A-Za-z0-9 _.,'()\-]*[.]?",
        cleaned_after,
        re.I,
    ) is None


def _line_candidates(
    line: str,
    *,
    force_executable: bool = False,
    indented_surface: bool = False,
    literal_code_surface: bool = False,
) -> Iterator[tuple[str, bool]]:
    seen: set[tuple[str, bool]] = set()

    def emit(
        value: str,
        *,
        executable_surface: bool,
        preserve_shell_bytes: bool = False,
    ) -> Iterator[tuple[str, bool]]:
        # Inside an executable fence, Markdown/HTML canonicalization is not a
        # presentation wrapper: it changes the bytes the shell would parse.
        # Strip only structural indentation/whitespace for the raw fence line.
        cleaned = (
            value.strip(" \t")
            if preserve_shell_bytes
            else _clean_command_surface(value)
        )
        item = (cleaned, executable_surface)
        if cleaned and item not in seen:
            seen.add(item)
            yield item

    # Parse complete or comma-terminated JSON members before treating a fenced
    # line as shell.  This keeps ordinary schema fields non-executable while
    stripped_json = line.strip()
    json_variants = [stripped_json.rstrip(",")]
    if re.match(r'^"(?:\\.|[^"\\])+"\s*:', json_variants[0]):
        json_variants.append("{" + json_variants[0] + "}")
    for json_variant in json_variants:
        if not json_variant.startswith(("{", "[", '"')):
            continue
        parsed_ok, parsed_line = _json_value_without_duplicate_keys(json_variant)
        if not parsed_ok:
            continue
        for value in _json_command_strings(parsed_line):
            yield from emit(value, executable_surface=True)
        return

    json_property = re.match(r'^\s*"(?P<key>[^"\\]+)"\s*:', line)
    if (
        json_property is not None
        and json_property.group("key").casefold()
        not in {"command", "cmd", "script", "argv"}
    ):
        return

    cleaned_line = _clean_command_surface(line)
    imperative_surface = bool(
        re.match(r"^\s*(?:\d+[.)]\s*)?(?:run|execute)\s+`", cleaned_line, re.I)
    )
    inline_controller_unsafe = any(
        _inline_controller_context_is_unsafe(line, match)
        for match in _INLINE_CODE_RE.finditer(line)
    )
    # A backtick-wrapped fragment embedded in prose is descriptive, not a
    # complete command surface.  A line containing only that fragment is
    # handled by the inline-code branch below.
    cleaned_tokens = _shell_tokens(cleaned_line) or []
    indented_code = bool(
        indented_surface
        and cleaned_tokens
        and cleaned_tokens[0] == cleaned_tokens[0].casefold()
        and (
            _surface_starts_command(cleaned_line)
            or _command_syntax_evidence(cleaned_tokens, cleaned_line)
        )
    )
    yield from emit(
        line,
        executable_surface=force_executable
        or indented_code
        or inline_controller_unsafe
        or _surface_starts_command(cleaned_line),
        preserve_shell_bytes=(
            force_executable or indented_code or literal_code_surface
        ),
    )
    for match in _INLINE_CODE_RE.finditer(line):
        whole_inline = bool(re.fullmatch(r"`[^`\n]+`", line.strip()))
        yield from emit(
            match.group(1),
            executable_surface=force_executable or whole_inline or imperative_surface,
            preserve_shell_bytes=(
                force_executable
                or indented_code
                or literal_code_surface
                or whole_inline
                or imperative_surface
            ),
        )
    for match in _HTML_ATTRIBUTE_RE.finditer(html.unescape(line)):
        yield from emit(match.group(2), executable_surface=True)
    for match in _HTML_COMMENT_RE.finditer(html.unescape(line)):
        yield from emit(match.group(1), executable_surface=True)
    for match in _XML_COMMAND_RE.finditer(html.unescape(line)):
        yield from emit(
            _xml_command_value(match.group(1)), executable_surface=True
        )
    for match in _JSON_COMMAND_RE.finditer(line):
        try:
            value = json.loads(f'"{match.group(1)}"')
        except json.JSONDecodeError:
            continue
        yield from emit(value, executable_surface=True)
    yaml_match = _YAML_COMMAND_RE.match(line)
    yaml_key: str | None = None
    value: str | None = None
    if yaml_match:
        yaml_key = yaml_match.group("key").casefold()
        value = yaml_match.group("value").strip()
    else:
        quoted_assignment = re.match(
            r"^\s*(?:-\s+)?(?P<key>\"(?:\\.|[^\"\\])*\"|'(?:''|[^'])*')"
            r"\s*[:=]\s*(?P<value>.*?)\s*$",
            line,
        )
        if quoted_assignment is not None:
            encoded_key = quoted_assignment.group("key")
            try:
                decoded_key = (
                    json.loads(encoded_key)
                    if encoded_key.startswith('"')
                    else encoded_key[1:-1].replace("''", "'")
                )
            except (json.JSONDecodeError, UnicodeDecodeError):
                decoded_key = ""
            if decoded_key.casefold() in {"command", "cmd", "script", "argv"}:
                yaml_key = decoded_key.casefold()
                value = quoted_assignment.group("value").strip()
    if yaml_key is not None and value is not None:
        if len(value) >= 2 and value[0] == value[-1] == '"':
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                pass
        elif len(value) >= 2 and value[0] == value[-1] == "'":
            value = value[1:-1].replace("''", "'")
        value = _YAML_VALUE_DECORATOR_RE.sub("", value)
        if not value or value in {">", ">-", ">+", "|", "|-", "|+"}:
            value = "dynamic-structured-command"
        if value.lstrip().startswith("*"):
            value = "eval yaml-alias"
        if yaml_key == "argv" and value.startswith("["):
            try:
                argv = json.loads(value)
            except json.JSONDecodeError:
                argv = [item.strip().strip("\"'") for item in value[1:-1].split(",")]
            if isinstance(argv, list) and all(isinstance(item, str) for item in argv):
                value = shlex.join(argv)
        yield from emit(value, executable_surface=True)
    for flow_match in _FLOW_COMMAND_RE.finditer(line):
        yield from emit(flow_match.group(1), executable_surface=True)
    for flow_match in _QUOTED_FLOW_ASSIGNMENT_RE.finditer(line):
        encoded_key = flow_match.group("key")
        try:
            decoded_key = (
                json.loads(encoded_key)
                if encoded_key.startswith('"')
                else encoded_key[1:-1].replace("''", "'")
            )
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
        if decoded_key.casefold() in {"command", "cmd", "script", "argv"}:
            yield from emit(flow_match.group("value"), executable_surface=True)
    imperative_match = _IMPERATIVE_COMMAND_RE.match(_clean_command_surface(line))
    if imperative_match and _INLINE_CODE_RE.search(imperative_match.group(1)) is None:
        candidate = imperative_match.group(1)
        candidate_tokens = _shell_tokens(candidate) or []
        if candidate_tokens and candidate_tokens[0] == candidate_tokens[0].casefold() and (
            _surface_starts_command(candidate)
            or _command_syntax_evidence(candidate_tokens, candidate)
        ):
            yield from emit(candidate, executable_surface=True)
    if line.strip().startswith("|") or line.strip().endswith("|") or line.count("|") >= 2:
        for cell in line.split("|"):
            cleaned_cell = _clean_command_surface(cell)
            yield from emit(
                cell,
                executable_surface=force_executable
                or _surface_starts_command(cleaned_cell),
            )
    stripped = line.strip()
    if stripped.startswith(("{", "[", '"')):
        parsed_ok, parsed = _json_value_without_duplicate_keys(stripped)
        if parsed_ok:
            for value in _json_command_strings(parsed):
                yield from emit(value, executable_surface=True)


def _shell_tokens(fragment: str) -> list[str] | None:
    try:
        return shlex.split(fragment, posix=True)
    except ValueError:
        return None


def _dynamic_shell_surface(tokens: list[str], fragment: str) -> bool:
    if not tokens:
        return False
    fragment = _shell_syntax_fragment(fragment)
    normalized_tokens = _shell_tokens(fragment) or tokens
    tokens = normalized_tokens
    original_name = os.path.basename(tokens[0]).lower()
    return (
        _SHELL_PROCESS_SUBSTITUTION_RE.search(fragment) is not None
        or (
            len(tokens) >= 2
            and _SHELL_FIRST_TOKEN_META_RE.search(tokens[0]) is not None
        )
        or _SHELL_BRACE_EXPANSION_RE.fullmatch(tokens[0]) is not None
        or (
            len(tokens) >= 2
            and _SHELL_EXPANDED_COMMAND_TOKEN_RE.fullmatch(tokens[0]) is not None
        )
        or (original_name == "env" and _ENV_SPLIT_RE.search(fragment) is not None)
        or (
            original_name == "xargs"
            and _XARGS_ARG_FILE_RE.search(fragment) is not None
        )
        or (
            original_name in {"busybox", "toybox"}
            and any(token.startswith("-") and token != "--" for token in tokens[1:])
        )
    )


def _unwrap_command(tokens: list[str]) -> list[str]:
    remaining = list(tokens)
    while remaining:
        while remaining and _SHELL_ASSIGNMENT_RE.fullmatch(remaining[0]):
            remaining.pop(0)
        if not remaining:
            break
        name = os.path.basename(remaining[0]).lower()
        if name == "env":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option == "--":
                    break
                if option in {
                    "-a",
                    "--argv0",
                    "-u",
                    "--unset",
                    "-C",
                    "--chdir",
                    "-S",
                    "--split-string",
                } and remaining:
                    remaining.pop(0)
            while remaining and _SHELL_ASSIGNMENT_RE.fullmatch(remaining[0]):
                remaining.pop(0)
            continue
        if name == "command":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                if remaining.pop(0) == "--":
                    break
            continue
        if name == "sudo":
            remaining.pop(0)
            value_options = {
                "-C", "--chdir", "-D", "--close-from", "-g", "--group",
                "-h", "--host", "-p", "--prompt", "-R", "--chroot",
                "-r", "--role", "-T", "--command-timeout", "-t", "--type",
                "-u", "--user",
            }
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option == "--":
                    break
                if option in value_options and remaining:
                    remaining.pop(0)
            continue
        if name == "xargs":
            remaining.pop(0)
            value_options = {
                "-a", "--arg-file", "-d", "--delimiter", "-E", "-I",
                "-L", "--max-lines", "-n", "--max-args", "-P", "--max-procs",
                "-s", "--max-chars",
            }
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option == "--":
                    break
                if option in value_options and remaining:
                    remaining.pop(0)
            continue
        if name in {"busybox", "toybox", "nohup"}:
            remaining.pop(0)
            while remaining and remaining[0] == "--":
                remaining.pop(0)
            continue
        if name == "setsid":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                if remaining.pop(0) == "--":
                    break
            continue
        if name in {"nice", "stdbuf"}:
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option in {"-n", "--adjustment", "-i", "-o", "-e"} and remaining:
                    remaining.pop(0)
            continue
        if name == "timeout":
            remaining.pop(0)
            while remaining and remaining[0].startswith("-"):
                option = remaining.pop(0)
                if option in {"-k", "--kill-after", "-s", "--signal"} and remaining:
                    remaining.pop(0)
            if remaining:
                remaining.pop(0)  # duration
            continue
        break
    return remaining


def _command_name(tokens: list[str]) -> str:
    return os.path.basename(tokens[0]).lower() if tokens else ""


def _dangerous_shell_builtin(tokens: list[str]) -> bool:
    name = _command_name(tokens)
    if name in {"eval", "exec"}:
        return True
    if (
        name not in {".", "source"}
        or len(tokens) < 2
        or (name == "source" and tokens[0] != "source")
    ):
        return False
    return True


def _python_command_name(name: str) -> bool:
    return bool(re.fullmatch(r"python(?:3(?:\.\d+)?)?", name))


def _reference_character_is_unsafe(character: str) -> bool:
    codepoint = ord(character)
    return (
        unicodedata.category(character) in {"Cc", "Cf", "Cs"}
        or any(
            lower <= codepoint <= upper
            for lower, upper in _DEFAULT_IGNORABLE_CODEPOINT_RANGES
        )
    )


def _launcher_has_exact_quoted_prefix(
    fragment: str,
    controller: str,
) -> bool:
    if controller not in _LAUNCHER_CONTROLLERS:
        return False
    prefix = " ".join(
        (
            *_ISOLATED_PYTHON_PREFIX,
            f'"{_LAUNCHER_PATH}"',
            "--active-skill-md",
            f'"{_ACTIVE_SKILL_MD_PATH}"',
            "--controller",
            controller,
            "--",
        )
    )
    return fragment == prefix or fragment.startswith(prefix + " ")


def _controller_value_is_literal(value: str) -> bool:
    return (
        bool(value)
        and not value.startswith("-")
        and not any(_reference_character_is_unsafe(character) for character in value)
        and not any(character in value for character in "$`\\'\"")
    )


def _controller_options_match(
    arguments: list[str],
    schema: tuple[tuple[str, Callable[[str], bool]], ...],
) -> bool:
    if len(arguments) != len(schema) * 2:
        return False
    for index, (expected_flag, predicate) in enumerate(schema):
        flag = arguments[index * 2]
        value = arguments[index * 2 + 1]
        if flag != expected_flag or not predicate(value):
            return False
    return True


def _controller_root_argument(value: str) -> bool:
    return value in _CONTROLLER_ROOT_ARGUMENTS


def _controller_run_dir_argument(value: str) -> bool:
    return value == _CONTROLLER_RUN_DIR_ARGUMENT


def _controller_task_id_argument(value: str) -> bool:
    return value == _CONTROLLER_TASK_ID_ARGUMENT


def _controller_agent_id_argument(value: str) -> bool:
    return value == _CONTROLLER_AGENT_ID_ARGUMENT


def _controller_actor_argument(value: str) -> bool:
    return value in {"controller", _CONTROLLER_AGENT_ID_ARGUMENT}


def _controller_only_actor_argument(value: str) -> bool:
    return value == "controller"


def _controller_relative_report_path(value: object) -> bool:
    return (
        isinstance(value, str)
        and value.strip() == value
        and _controller_value_is_literal(value)
        and not any(character in value for character in "*?[]{}")
        and _safe_relative_token(value, planner_only=False)
        and not _PLACEHOLDER_RE.fullmatch(value)
    )


def _controller_report_string_list(
    value: object,
    *,
    require_nonempty: bool = False,
) -> bool:
    return (
        isinstance(value, list)
        and len(value) <= 32
        and all(
            isinstance(item, str)
            and len(item) <= 512
            and (not require_nonempty or bool(item.strip()))
            and (not item or _controller_value_is_literal(item))
            for item in value
        )
    )


def _json_nesting_is_bounded(value: str, *, limit: int = 64) -> bool:
    depth = 0
    in_string = False
    escaped = False
    for character in value:
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character in "[{":
            depth += 1
            if depth > limit:
                return False
        elif character in "]}":
            depth -= 1
            if depth < 0:
                return False
    return True


def _json_value_without_duplicate_keys(value: str) -> tuple[bool, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate_controller_json_key")
            result[key] = item
        return result

    try:
        encoded_size = len(value.encode("utf-8"))
    except UnicodeEncodeError:
        return False, None
    if encoded_size > 4 * 1024 * 1024 or not _json_nesting_is_bounded(value):
        return False, None
    try:
        payload = json.loads(value, object_pairs_hook=reject_duplicate_keys)
    except (
        json.JSONDecodeError,
        UnicodeDecodeError,
        ValueError,
        RecursionError,
        MemoryError,
    ):
        return False, None
    return True, payload


def _controller_json_object(value: str) -> dict[str, object] | None:
    valid, payload = _json_value_without_duplicate_keys(value)
    if not valid:
        return None
    return payload if isinstance(payload, dict) else None


def _controller_json_value_is_literal(value: object, *, depth: int = 0) -> bool:
    if depth > 8:
        return False
    if value is None or isinstance(value, (bool, int, float)):
        return not isinstance(value, float) or value == value
    if isinstance(value, str):
        return not value or _controller_value_is_literal(value)
    if isinstance(value, list):
        return len(value) <= 256 and all(
            _controller_json_value_is_literal(item, depth=depth + 1)
            for item in value
        )
    if isinstance(value, dict):
        return len(value) <= 64 and all(
            isinstance(key, str)
            and bool(key)
            and _controller_value_is_literal(key)
            and _controller_json_value_is_literal(item, depth=depth + 1)
            for key, item in value.items()
        )
    return False


def _controller_sha256_argument(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _controller_fixer_item_is_safe(value: object) -> bool:
    if not isinstance(value, dict) or not _controller_json_value_is_literal(value):
        return False
    files_changed = value.get("files_changed")
    return (
        isinstance(files_changed, list)
        and bool(files_changed)
        and len(files_changed) == len(set(files_changed))
        and all(_controller_relative_report_path(item) for item in files_changed)
    )


def _controller_writer_report_argument(value: str, role: str) -> bool:
    if len(value.encode("utf-8")) > 16 * 1024:
        return False
    payload = _controller_json_object(value)
    if payload is None:
        return False
    agent_key = f"{role}_agent_id"
    collection_key = "fixes" if role == "fixer" else "files_changed"
    allowed_fields = {
        "status",
        "task_id",
        "brief_sha256",
        "implementation_contract_digest",
        "task_contract_digest",
        agent_key,
        collection_key,
        "concerns",
        "validation_receipt_ids",
        "change_set_id",
        "diff_sha256",
        "controller_decision",
        "blocker",
        "evidence",
    }
    required_fields = {"status", "task_id", agent_key, collection_key}
    if role == "implementer":
        required_fields.add("concerns")
    if not required_fields.issubset(payload) or set(payload) - allowed_fields:
        return False
    status = payload.get("status")
    if (
        status not in {"DONE", "DONE_WITH_CONCERNS", "NEEDS_CONTEXT", "BLOCKED"}
        or payload.get("task_id") != _CONTROLLER_TASK_ID_ARGUMENT
        or payload.get(agent_key) != _CONTROLLER_AGENT_ID_ARGUMENT
    ):
        return False
    for field in ("brief_sha256", "task_contract_digest", "change_set_id", "diff_sha256"):
        if field in payload and not _controller_sha256_argument(payload.get(field)):
            return False
    if "implementation_contract_digest" in payload and (
        payload.get("implementation_contract_digest") is not None
        and not _controller_sha256_argument(payload.get("implementation_contract_digest"))
    ):
        return False
    receipt_ids = payload.get("validation_receipt_ids")
    if receipt_ids is not None and (
        not isinstance(receipt_ids, list)
        or len(receipt_ids) != len(set(receipt_ids))
        or not all(_controller_sha256_argument(item) for item in receipt_ids)
    ):
        return False
    for field in ("controller_decision", "blocker"):
        item = payload.get(field)
        if field in payload and (
            not isinstance(item, str)
            or (item and not _controller_value_is_literal(item))
        ):
            return False
    if status == "DONE_WITH_CONCERNS" and (
        not isinstance(payload.get("controller_decision"), str)
        or not str(payload.get("controller_decision")).strip()
    ):
        return False
    if "evidence" in payload and not _controller_report_string_list(
        payload.get("evidence")
    ):
        return False
    concerns = payload.get("concerns")
    if concerns is not None and not _controller_report_string_list(
        concerns,
        require_nonempty=True,
    ):
        return False
    collection = payload.get(collection_key)
    collection_is_safe = (
        isinstance(collection, list)
        and len(collection) <= 64
        and all(_controller_fixer_item_is_safe(item) for item in collection)
        if role == "fixer"
        else isinstance(collection, list)
        and len(collection) <= 256
        and len(collection) == len(set(collection))
        and all(_controller_relative_report_path(item) for item in collection)
    )
    if not collection_is_safe:
        return False
    if role == "implementer":
        evidence_fields = {
            "brief_sha256",
            "implementation_contract_digest",
            "task_contract_digest",
            "validation_receipt_ids",
            "change_set_id",
            "diff_sha256",
        }
        present_evidence_fields = evidence_fields.intersection(payload)
        if present_evidence_fields and present_evidence_fields != evidence_fields:
            return False
        if present_evidence_fields and (
            status != "DONE"
            or not collection
            or not isinstance(receipt_ids, list)
            or not receipt_ids
        ):
            return False
    return True


def _controller_review_report_argument(value: str, phase: str) -> bool:
    if len(value.encode("utf-8")) > 16 * 1024:
        return False
    payload = _controller_json_object(value)
    if payload is None:
        return False
    if not isinstance(payload, dict) or set(payload) != {
        "status",
        "phase",
        "verdict",
        "task_id",
        "reviewer_agent_id",
        "evidence",
    }:
        return False
    verdicts = (
        {"pass", "fail", "cannot_verify"}
        if phase == "spec"
        else {"pass", "fail", "needs_fixes", "cannot_verify"}
    )
    return (
        payload.get("status") == "COMPLETE"
        and payload.get("phase") == phase
        and payload.get("verdict") in verdicts
        and payload.get("task_id") == _CONTROLLER_TASK_ID_ARGUMENT
        and payload.get("reviewer_agent_id") == _CONTROLLER_AGENT_ID_ARGUMENT
        and bool(payload.get("evidence"))
        and _controller_report_string_list(
            payload.get("evidence"),
            require_nonempty=True,
        )
    )


def _approved_goal_controller_arguments(arguments: list[str]) -> bool:
    if not arguments:
        return False
    command = arguments[0]
    options = arguments[1:]
    if command in {"collect", "prepare"}:
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                ("--stage", lambda value: value in _GOAL_CONTROLLER_STAGES),
            ),
        )
    if command in {"validate", "render"}:
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                (
                    "--goal-run",
                    lambda value: value == _CONTROLLER_GOAL_RUN_ARGUMENT,
                ),
            ),
        )
    return False


def _approved_apply_controller_arguments(arguments: list[str]) -> bool:
    if not arguments:
        return False
    command = arguments[0]
    options = arguments[1:]
    root_run_task = (
        ("--root", _controller_root_argument),
        ("--run-dir", _controller_run_dir_argument),
        ("--task-id", _controller_task_id_argument),
    )
    if command == "prepare":
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                ("--mode", lambda value: value in _APPLY_CONTROLLER_MODES),
            ),
        )
    if command == "validate":
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                ("--run-dir", _controller_run_dir_argument),
            ),
        )
    if command == "transition":
        return _controller_options_match(
            options,
            root_run_task
            + (
                ("--to", lambda value: value in _APPLY_CONTROLLER_TASK_STATES),
                ("--actor", _controller_actor_argument),
            ),
        )
    if command in {"dispatch", "record-agent"}:
        minimum = root_run_task + (
            ("--role", lambda value: value in _APPLY_CONTROLLER_ROLES),
        )
        role_index = 7
        if len(options) <= role_index:
            return False
        role = options[role_index]
        phase_schema: tuple[tuple[str, Callable[[str], bool]], ...] = ()
        if role in _APPLY_CONTROLLER_ROLE_PHASES:
            phase_schema = (
                (
                    "--review-phase",
                    lambda value: value in _APPLY_CONTROLLER_ROLE_PHASES[role],
                ),
            )
        if command == "dispatch":
            return _controller_options_match(
                options,
                minimum
                + phase_schema
                + (("--actor", _controller_only_actor_argument),),
            )
        return _controller_options_match(
            options,
            minimum
            + phase_schema
            + (
                ("--agent-id", _controller_agent_id_argument),
                (
                    "--status",
                    lambda value: value in _APPLY_CONTROLLER_AGENT_STATUSES,
                ),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "normalize-writer":
        role_index = 7
        if len(options) <= role_index or options[role_index] not in {
            "fixer",
            "implementer",
        }:
            return False
        role = options[role_index]
        return _controller_options_match(
            options,
            root_run_task
            + (
                ("--role", lambda value: value == role),
                ("--agent-id", _controller_agent_id_argument),
                (
                    "--report-json",
                    lambda value: _controller_writer_report_argument(value, role),
                ),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "normalize-review":
        phase_index = 7
        if len(options) <= phase_index or options[phase_index] not in (
            _APPLY_CONTROLLER_REVIEW_PHASES
        ):
            return False
        phase = options[phase_index]
        return _controller_options_match(
            options,
            root_run_task
            + (
                ("--review-phase", lambda value: value == phase),
                ("--agent-id", _controller_agent_id_argument),
                (
                    "--report-json",
                    lambda value: _controller_review_report_argument(value, phase),
                ),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "capture-evidence":
        return _controller_options_match(
            options,
            root_run_task + (("--actor", _controller_only_actor_argument),),
        )
    if command == "run-validation":
        return _controller_options_match(
            options,
            root_run_task
            + (
                (
                    "--validation-id",
                    lambda value: value == "<validation-id>"
                    or (
                        re.fullmatch(r"VAL-[0-9]{2,4}", value) is not None
                        and set(value[4:]) != {"0"}
                    ),
                ),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "publish-review":
        return _controller_options_match(
            options,
            root_run_task
            + (
                (
                    "--review-phase",
                    lambda value: value in _APPLY_CONTROLLER_REVIEW_PHASES,
                ),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "reconcile":
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                ("--run-dir", _controller_run_dir_argument),
            ),
        )
    if command == "recover-lock":
        return _controller_options_match(
            options,
            root_run_task
            + (
                ("--to", lambda value: value in {"BLOCKED", "NEEDS_CONTEXT"}),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    if command == "finalize":
        return _controller_options_match(
            options,
            (
                ("--root", _controller_root_argument),
                ("--run-dir", _controller_run_dir_argument),
                ("--actor", _controller_only_actor_argument),
            ),
        )
    return False


def _approved_python_command(tokens: list[str], fragment: str) -> bool:
    if _approved_controller_command(tokens, fragment):
        return True
    if (
        len(tokens) == 8
        and tokens[1:6] == ["-B", "-m", "pytest", "-p", "no:cacheprovider"]
        and _safe_relative_token(tokens[6], planner_only=False)
        and tokens[6].startswith("tests/")
        and tokens[6].endswith(".py")
        and tokens[7:] == ["-q"]
    ):
        return True
    return tokens == [
        "python3",
        "-B",
        "-m",
        "unittest",
        "discover",
        "-s",
        "tests",
        "-p",
        "test_*.py",
    ]


def _approved_controller_command(tokens: list[str], fragment: str) -> bool:
    if len(tokens) < 10 or _SHELL_CONTROL_RE.search(
        _shell_syntax_fragment(fragment)
    ):
        return False
    if tuple(tokens[:4]) != _ISOLATED_PYTHON_PREFIX:
        return False
    if (
        tokens[4] != _LAUNCHER_PATH
        or tokens[5:8] != ["--active-skill-md", _ACTIVE_SKILL_MD_PATH, "--controller"]
        or tokens[8] not in _LAUNCHER_CONTROLLERS
        or tokens[9] != "--"
        or not _launcher_has_exact_quoted_prefix(fragment, tokens[8])
    ):
        return False
    if not all(
        token
        and not any(
            ord(character) < 32 or ord(character) == 127
            for character in token
        )
        for token in tokens[4:]
    ):
        return False
    controller = tokens[8]
    arguments = tokens[10:]
    if controller == "repository-io":
        return arguments == ["request-stdin"]
    if controller == "planner-validator":
        return (
            len(arguments) == 5
            and arguments[:2] == ["--root", "."]
            and arguments[2] == "--mode"
            and arguments[3]
            in {"step1", "autopsy", "step2", "step3-preflight", "step3", "step4", "all"}
            and arguments[4:] == ["--strict"]
        )
    if controller == "goal":
        return _approved_goal_controller_arguments(arguments)
    if controller == "apply":
        return arguments == ["request-stdin"]
    return controller == "doctor" and arguments in ([], ["--json"])


def _safe_relative_token(value: str, *, planner_only: bool) -> bool:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        return False
    if _PLACEHOLDER_RE.fullmatch(value):
        return True
    if "\\" in value or value.startswith(("/", "~")):
        return False
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts:
        return False
    return not planner_only or path.parts[:1] == ("Planner-docs",)


def _write_target_allowed(stage: str, path: str) -> bool:
    if _PLACEHOLDER_RE.fullmatch(path):
        return True
    return path in _WRITE_TARGETS.get(stage, frozenset()) or (
        stage == "step2" and _PHASE_PLAN_PATH_RE.fullmatch(path) is not None
    )


def _approved_repository_io_arguments(arguments: list[str]) -> bool:
    if len(arguments) < 3 or arguments[:2] != ["--root", "."]:
        return False
    command = arguments[2]
    if command in {"inspect", "search"}:
        return (
            len(arguments) == 5
            and arguments[3] == "--profile"
            and arguments[4] in _PROFILES
        )
    if command == "read-model":
        return (
            len(arguments) == 5
            and arguments[3] == "--path"
            and _safe_relative_token(arguments[4], planner_only=False)
        )
    if command != "write-planner" or len(arguments) not in {8, 9}:
        return False
    if (
        arguments[3] != "--stage"
        or arguments[4] not in _STAGES
        or arguments[5] != "--path"
    ):
        return False
    if not _safe_relative_token(arguments[6], planner_only=True):
        return False
    if not _write_target_allowed(arguments[4], arguments[6]):
        return False
    if len(arguments) == 8:
        return arguments[7] == "--expected-missing"
    return arguments[7] == "--expected-sha256" and bool(
        re.fullmatch(r"[0-9a-f]{64}", arguments[8])
        or _PLACEHOLDER_RE.fullmatch(arguments[8])
    )


def _controller_stdin_request_kind(value: str) -> str | None:
    """Validate one model-visible stdin request as data, never shell text."""

    payload = _controller_json_object(value)
    if payload is None or payload.get("schema") != _CONTROLLER_STDIN_REQUEST_SCHEMA:
        return None
    if set(payload) not in (
        {"schema", "argv"},
        {"schema", "argv", "body"},
    ):
        return None
    argv = payload.get("argv")
    if (
        not isinstance(argv, list)
        or not argv
        or len(argv) > 64
        or any(
            not isinstance(argument, str)
            or not argument
            or argument == "request-stdin"
            or len(argument) > 16 * 1024
            or any(_reference_character_is_unsafe(character) for character in argument)
            for argument in argv
        )
    ):
        return None
    arguments = list(argv)
    body = payload.get("body") if "body" in payload else None
    if body is not None and (
        not isinstance(body, str)
        or any(
            character not in "\n\r\t" and _reference_character_is_unsafe(character)
            for character in body
        )
        or len(body.encode("utf-8")) > 4 * 1024 * 1024
    ):
        return None
    if _approved_repository_io_arguments(arguments):
        write_request = len(arguments) >= 3 and arguments[2] == "write-planner"
        if write_request != (body is not None):
            return None
        return "repository-io"
    if body is None and _approved_apply_controller_arguments(arguments):
        return "apply"
    return None


def _repository_io_facade_command(fragment: str) -> bool:
    tokens = _shell_tokens(fragment)
    return bool(
        tokens is not None
        and len(tokens) >= 10
        and tokens[4] == _LAUNCHER_PATH
        and tokens[7:9] == ["--controller", "repository-io"]
        and _approved_controller_command(tokens, fragment)
    )


def _direct_repository_io_surface(tokens: list[str]) -> bool:
    """Return whether repository_io is the command entrypoint, not data."""

    unwrapped = _unwrap_command(tokens)
    if not unwrapped:
        return False
    if _command_name(unwrapped) == "repository_io.py":
        return True
    if not _python_command_name(_command_name(unwrapped)):
        return False

    index = 1
    while index < len(unwrapped):
        token = unwrapped[index]
        if token in {"-c", "--command"}:
            return False
        if token == "-m":
            return index + 1 < len(unwrapped) and unwrapped[index + 1] in {
                "repository_io",
                "scripts.repository_io",
            }
        if token == "--":
            index += 1
            return index < len(unwrapped) and os.path.basename(
                unwrapped[index]
            ) == "repository_io.py"
        if token in {"-W", "-X"}:
            index += 2
            continue
        if token.startswith("-"):
            index += 1
            continue
        return os.path.basename(token) == "repository_io.py"
    return False


def _looks_like_command(fragment: str, *, executable_surface: bool) -> bool:
    syntax_fragment = _shell_syntax_fragment(fragment)
    tokens = _shell_tokens(fragment)
    if not tokens:
        return False
    dynamic_shell = _dynamic_shell_surface(tokens, fragment)
    if not executable_surface:
        return False
    unwrapped = _unwrap_command(tokens)
    if not unwrapped:
        return executable_surface and dynamic_shell
    name = _command_name(unwrapped)
    raw_name = unwrapped[0]
    path_executable = len(unwrapped) >= 2 and raw_name.startswith(
        ("/", "./", "../", "~/")
    )
    arbitrary_planner_command = (
        "Planner-docs" in fragment
        and len(unwrapped) >= 2
        and bool(re.fullmatch(r"[a-z0-9_./+@%-]+", name))
        and name not in {
            "with",
            "through",
            "only",
            "use",
            "read",
            "publish",
            "after",
            "before",
            "write-planner",
        }
        and (
            unwrapped[1].startswith("-")
            or raw_name.startswith(("./", "/"))
        )
    )
    facade_reference = any(
        os.path.basename(token) == "repository_io.py"
        for token in unwrapped
    ) or any(
        token == "-m"
        and index + 1 < len(unwrapped)
        and "repository_io" in unwrapped[index + 1]
        for index, token in enumerate(unwrapped)
    )
    controller_reference = any(token in _CONTROLLER_PATHS for token in unwrapped)
    launcher_reference = any(token == _LAUNCHER_PATH for token in unwrapped)
    known_command = (
        name
        in (
            _RAW_COMMANDS
            | _MUTATING_COMMANDS
            | _INTERPRETERS
            | frozenset({"git", "echo", "printf"})
        )
        or _python_command_name(name)
        or facade_reference
        or controller_reference
        or launcher_reference
    )
    return (
        dynamic_shell
        or known_command
        or path_executable
        or arbitrary_planner_command
        or _dangerous_shell_builtin(unwrapped)
        or _SHELL_REDIRECTION_RE.search(syntax_fragment) is not None
        or bool(unwrapped)
    )


def _classify_command(fragment: str, *, executable_surface: bool) -> tuple[str, ...]:
    surface_tokens = _shell_tokens(fragment)
    if surface_tokens is None:
        return ("raw_repository_command",) if executable_surface else ()
    if not _looks_like_command(fragment, executable_surface=executable_surface):
        return ()
    repository_io_launcher_surface = bool(
        len(surface_tokens) >= 9
        and surface_tokens[4:9]
        == [
            _LAUNCHER_PATH,
            "--active-skill-md",
            _ACTIVE_SKILL_MD_PATH,
            "--controller",
            "repository-io",
        ]
    )
    if _direct_repository_io_surface(surface_tokens) or repository_io_launcher_surface:
        if not executable_surface:
            return ()
        return () if _repository_io_facade_command(fragment) else ("invalid_repository_io_command",)
    controller_tokens = _shell_tokens(fragment) or []
    if executable_surface and _approved_controller_command(
        controller_tokens, fragment
    ):
        return ()
    original_tokens = _shell_tokens(fragment) or []
    syntax_fragment = _shell_syntax_fragment(fragment)
    dynamic_shell = _dynamic_shell_surface(original_tokens, fragment)
    tokens = _unwrap_command(original_tokens)
    name = _command_name(tokens)
    raw_name = tokens[0] if tokens else ""
    findings: list[str] = []
    if (
        name in _RAW_COMMANDS | _MUTATING_COMMANDS
        or _dangerous_shell_builtin(tokens)
        or dynamic_shell
        or _EMBEDDED_RAW_COMMAND_RE.search(fragment)
        or _SHELL_DOLLAR_FORM_RE.search(fragment)
        or re.search(r"`[^`]+`", fragment)
    ):
        findings.append("raw_repository_command")
    if name in {"echo", "printf"} and re.search(r"\$(?:[A-Za-z_]|{|\()", fragment):
        findings.append("raw_repository_command")
    if name == "git":
        findings.append("raw_repository_command")
    if (
        len(tokens) >= 2
        and raw_name.startswith(("/", "./", "../", "~/"))
        and name != "repository_io.py"
    ):
        findings.append("raw_repository_command")
    if name in _INTERPRETERS and (
        any(token in {"-c", "--eval", "-e"} for token in tokens[1:])
        or "<<" in fragment
    ):
        findings.append("raw_repository_command")
    if name in _INTERPRETERS and not _python_command_name(name):
        findings.append("raw_repository_command")
    if _python_command_name(name) and not _approved_python_command(tokens, fragment):
        findings.append("raw_repository_command")
    if executable_surface and "Planner-docs" in fragment:
        findings.append("repository_io_command_required")
    if _SHELL_REDIRECTION_RE.search(syntax_fragment):
        findings.append("raw_repository_command")
    if (
        executable_surface
        and name
        and not findings
        and not (
            _python_command_name(name)
            and _approved_python_command(tokens, fragment)
        )
    ):
        findings.append("raw_repository_command")
    return tuple(dict.fromkeys(findings))


def _logical_lines(text: str) -> Iterator[tuple[int, str]]:
    pending: list[str] = []
    start = 1
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not pending:
            start = line_number
        pending.append(line.rstrip(" \t"))
        if line.rstrip(" \t").endswith("\\"):
            pending[-1] = pending[-1][:-1]
            continue
        yield start, " ".join(part.strip(" \t") for part in pending)
        pending = []
    if pending:
        yield start, " ".join(part.strip(" \t") for part in pending)


def _markdown_fence_language(suffix: str) -> str:
    fence_info = suffix.strip()
    language = fence_info.split(maxsplit=1)[0].casefold() if fence_info else ""
    if fence_info.startswith("{") and "}" in fence_info:
        attributes = fence_info[1:fence_info.index("}")].strip()
        language = re.split(r"[\s,]+", attributes, maxsplit=1)[0].casefold()
        language = language.lstrip(".")
    return language


def _controller_stdin_data_fences(
    relative_path: str,
    lines: list[str],
) -> tuple[set[int], list[PolicyFinding]]:
    """Locate reviewed JSON data fences and reject code/data ambiguity."""

    data_lines: set[int] = set()
    findings: list[PolicyFinding] = []
    fence_character: str | None = None
    fence_length = 0
    fence_language = ""
    fence_start = 0
    content: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, start=1):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence_character is None:
            if fence is None:
                continue
            marker = fence.group(1)
            fence_character = marker[0]
            fence_length = len(marker)
            fence_language = _markdown_fence_language(fence.group(2))
            fence_start = line_number
            content = []
            continue
        if fence is not None:
            marker = fence.group(1)
            if (
                marker[0] == fence_character
                and len(marker) >= fence_length
                and not fence.group(2).strip()
            ):
                encoded = "\n".join(item for _, item in content)
                parsed_ok, parsed = _json_value_without_duplicate_keys(encoded)
                parsed_schema = (
                    parsed.get("schema") if isinstance(parsed, dict) else None
                )
                controller_schema = parsed_schema == _CONTROLLER_STDIN_REQUEST_SCHEMA
                controller_schema_family = bool(
                    isinstance(parsed_schema, str)
                    and parsed_schema.startswith("codexqb.controller-argv/")
                )
                malformed_controller_data = bool(
                    not parsed_ok
                    and (
                        fence_language == "json"
                        or "codexqb.controller-argv" in encoded
                    )
                )
                if controller_schema:
                    kind = _controller_stdin_request_kind(encoded) if fence_language == "json" else None
                    if kind is None:
                        findings.append(
                            PolicyFinding(
                                relative_path,
                                fence_start,
                                "controller_stdin_request_invalid",
                            )
                        )
                    else:
                        data_lines.update(number for number, _ in content)
                elif (
                    controller_schema_family
                    or malformed_controller_data
                ):
                    findings.append(
                        PolicyFinding(
                            relative_path,
                            fence_start,
                            "controller_stdin_request_invalid",
                        )
                    )
                    if not parsed_ok and fence_language == "json":
                        findings.append(
                            PolicyFinding(
                                relative_path,
                                fence_start,
                                "raw_repository_command",
                            )
                        )
                elif parsed_ok:
                    for candidate in _json_command_strings(parsed):
                        for symbol in _classify_command(
                            candidate,
                            executable_surface=True,
                        ):
                            findings.append(
                                PolicyFinding(relative_path, fence_start, symbol)
                            )
                if fence_language == "json":
                    data_lines.update(number for number, _ in content)
                fence_character = None
                fence_length = 0
                fence_language = ""
                fence_start = 0
                content = []
                continue
        content.append((line_number, line))
    if fence_character is not None:
        encoded = "\n".join(item for _, item in content)
        if (
            fence_language == "json"
            or "codexqb.controller-argv" in encoded
        ):
            findings.append(
                PolicyFinding(
                    relative_path,
                    fence_start,
                    "controller_stdin_request_invalid",
                )
            )
        if fence_language == "json":
            data_lines.update(number for number, _ in content)
    return data_lines, findings


def scan_markdown(relative_path: str, text: str) -> list[PolicyFinding]:
    """Scan every text reference surface, independent of markup language."""

    findings: list[PolicyFinding] = []
    if any(
        _reference_character_is_unsafe(character)
        and character not in "\n\r\t"
        for character in text
    ):
        findings.append(PolicyFinding(relative_path, 1, "unsafe_reference_controls"))
    lines = text.splitlines()
    controller_data_lines, controller_data_findings = _controller_stdin_data_fences(
        relative_path,
        lines,
    )
    findings.extend(controller_data_findings)
    indented_code_lines = {
        line_number
        for line_number, line in enumerate(lines, start=1)
        if line.startswith("    ") or line.startswith("\t")
    }
    code_fence_lines: set[int] = set()
    shell_fence_lines: set[int] = set()
    fence_character: str | None = None
    fence_length = 0
    shell_fence = False
    for line_number, line in enumerate(lines, start=1):
        fence = re.match(r"^ {0,3}(`{3,}|~{3,})(.*)$", line)
        if fence is not None:
            marker = fence.group(1)
            suffix = fence.group(2)
            if fence_character is None:
                fence_character = marker[0]
                fence_length = len(marker)
                language = _markdown_fence_language(suffix)
                shell_fence = language in {
                    "",
                    "ash",
                    "bat",
                    "bash",
                    "cmd",
                    "console",
                    "csh",
                    "dash",
                    "fish",
                    "ksh",
                    "nu",
                    "nushell",
                    "powershell",
                    "pwsh",
                    "sh",
                    "shell",
                    "shell-session",
                    "tcsh",
                    "terminal",
                    "xonsh",
                    "zsh",
                    "bash-session",
                }
                continue
            elif (
                marker[0] == fence_character
                and len(marker) >= fence_length
                and not suffix.strip()
            ):
                fence_character = None
                fence_length = 0
                shell_fence = False
                continue
        if fence_character is not None:
            code_fence_lines.add(line_number)
            if shell_fence:
                shell_fence_lines.add(line_number)
    html_execution_lines: set[int] = set()
    html_execution_depth = 0
    for line_number, line in enumerate(lines, start=1):
        decoded = html.unescape(line)
        openings = len(re.findall(r"<(?:pre|code|script)\b[^>]*>", decoded, re.I))
        closings = len(re.findall(r"</(?:pre|code|script)\s*>", decoded, re.I))
        content = re.sub(
            r"</?(?:pre|code|script)\b[^>]*>", " ", decoded, flags=re.I
        ).strip()
        if (html_execution_depth > 0 or openings > 0) and content:
            html_execution_lines.add(line_number)
        html_execution_depth = max(
            0, html_execution_depth + openings - closings
        )
    dtd_line = next(
        (
            line_number
            for line_number, line in enumerate(lines, start=1)
            if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", line, re.I)
        ),
        None,
    )
    if dtd_line is not None:
        findings.append(PolicyFinding(relative_path, dtd_line, "raw_repository_command"))
    patch_marker_line = next(
        (
            index
            for index, line in enumerate(lines, start=1)
            if line.strip() in {"*** Begin Patch", "*** Update File", "*** Add File", "*** Delete File"}
            or line.strip().startswith(("*** Update File:", "*** Add File:", "*** Delete File:"))
        ),
        None,
    )
    if patch_marker_line is not None:
        findings.append(PolicyFinding(relative_path, patch_marker_line, "raw_repository_command"))
        if "Planner-docs" in text:
            findings.append(
                PolicyFinding(relative_path, patch_marker_line, "repository_io_command_required")
            )
    whole_json_ok, whole_json = _json_value_without_duplicate_keys(text)
    if whole_json_ok:
        if (
            isinstance(whole_json, dict)
            and whole_json.get("schema") == _CONTROLLER_STDIN_REQUEST_SCHEMA
        ):
            findings.append(
                PolicyFinding(relative_path, 1, "controller_stdin_request_invalid")
            )
        for candidate in _json_command_strings(whole_json):
            for symbol in _classify_command(candidate, executable_surface=True):
                findings.append(PolicyFinding(relative_path, 1, symbol))
        return sorted(set(findings))
    if text.lstrip().startswith(("{", "[")) and text.rstrip().endswith(("}", "]")):
        findings.append(
            PolicyFinding(relative_path, 1, "controller_stdin_request_invalid")
        )
    for line_number, logical_line in _logical_lines(text):
        if line_number in controller_data_lines:
            continue
        for candidate, executable_surface in _line_candidates(
            logical_line,
            force_executable=(
                line_number in shell_fence_lines
                or line_number in html_execution_lines
            ),
            indented_surface=line_number in indented_code_lines,
            literal_code_surface=line_number in code_fence_lines,
        ):
            segments = [candidate]
            if _SHELL_CONTROL_RE.search(candidate):
                segments.extend(part for part in _SHELL_SPLIT_RE.split(candidate) if part)
            for segment in segments:
                for symbol in _classify_command(
                    segment.strip(" \t"),
                    executable_surface=executable_surface,
                ):
                    findings.append(PolicyFinding(relative_path, line_number, symbol))
    return sorted(set(findings))


def _plugin_metadata_findings(location: _SkillLocation) -> list[PolicyFinding]:
    if not location.plugin_expected:
        return []
    if location.plugin_root is None:
        if location.plugin_expected:
            return [
                PolicyFinding(
                    ".codex-plugin/plugin.json",
                    1,
                    "plugin_root_unavailable",
                )
            ]
        return []
    relative = ".codex-plugin/plugin.json"
    findings: list[PolicyFinding] = []
    try:
        skill_entries = _descriptor_directory_entries(
            location.plugin_root, ("skills",)
        )
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding("skills", 1, _exception_symbol(exc)))
    else:
        if skill_entries != ("codexqb",):
            findings.append(
                PolicyFinding("skills", 1, "plugin_skill_inventory_invalid")
            )
    try:
        with open_repository_io(location.plugin_root) as plugin:
            manifest_kind = controller_path_kind(plugin, relative)
            if manifest_kind == "missing":
                return [PolicyFinding(relative, 1, "plugin_metadata_missing")]
            if manifest_kind != "regular":
                return [PolicyFinding(relative, 1, "plugin_metadata_not_regular")]
            evidence = controller_read_bytes(plugin, relative, required=True)
            data = evidence.data
        if data is None:
            raise ValueError("plugin_metadata_missing")
        if not hmac.compare_digest(
            hashlib.sha256(data).hexdigest(),
            _APPROVED_PLUGIN_METADATA_SHA256,
        ):
            findings.append(
                PolicyFinding(relative, 1, "plugin_metadata_unreviewed")
            )
        payload = json.loads(data.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return [PolicyFinding(relative, 1, "plugin_metadata_invalid")]
    except (OSError, TypeError, ValueError) as exc:
        return [PolicyFinding(relative, 1, _exception_symbol(exc))]
    if not isinstance(payload, dict) or payload.get("skills") != "./skills/":
        findings.append(PolicyFinding(relative, 1, "plugin_skills_path_invalid"))
    interface = payload.get("interface") if isinstance(payload, dict) else None
    prompts = interface.get("defaultPrompt") if isinstance(interface, dict) else None
    if not isinstance(prompts, list) or not prompts or not all(
        isinstance(prompt, str) for prompt in prompts
    ):
        findings.append(PolicyFinding(relative, 1, "plugin_default_prompt_invalid"))
    else:
        if tuple(prompts) != _PLUGIN_DEFAULT_PROMPTS:
            findings.append(
                PolicyFinding(relative, 1, "plugin_default_prompt_invalid")
            )
        for prompt in prompts:
            findings.extend(scan_markdown(relative, prompt))
    return sorted(set(findings))


def _openai_metadata_findings(text: str) -> list[PolicyFinding]:
    relative = "agents/openai.yaml"
    findings = list(scan_markdown(relative, text))
    matches = re.findall(
        r"(?m)^\s*allow_implicit_invocation\s*:\s*([^#\s]+)\s*(?:#.*)?$",
        text,
    )
    if matches != ["false"]:
        findings.append(
            PolicyFinding(relative, 1, "implicit_invocation_policy_invalid")
        )
    prompt_matches = re.findall(
        r'(?m)^\s*default_prompt\s*:\s*(?:"([^"\n]*)"|\'([^\'\n]*)\'|([^#\n]+?))\s*(?:#.*)?$',
        text,
    )
    prompts = [next((part for part in match if part), "") for match in prompt_matches]
    if prompts != [_OPENAI_DEFAULT_PROMPT]:
        findings.append(PolicyFinding(relative, 1, "agent_default_prompt_invalid"))
    return sorted(set(findings))


def _descriptor_directory_entries(
    root: Path, components: tuple[str, ...]
) -> tuple[str, ...]:
    root_fd = -1
    current_fd = -1
    flags = (
        CONTROLLER_O_RDONLY
        | CONTROLLER_O_DIRECTORY
        | CONTROLLER_O_NOFOLLOW
        | CONTROLLER_O_CLOEXEC
    )
    try:
        root_fd = controller_open(root, flags)
        current_fd = root_fd
        for component in components:
            next_fd = controller_open(component, flags, dir_fd=current_fd)
            if current_fd != root_fd:
                controller_close(current_fd)
            current_fd = next_fd
        entries = controller_listdir(current_fd)
        if not all(isinstance(entry, str) for entry in entries):
            raise ValueError("script_inventory_invalid")
        return tuple(sorted(entries))
    finally:
        if current_fd >= 0 and current_fd != root_fd:
            controller_close(current_fd)
        if root_fd >= 0:
            controller_close(root_fd)


def _script_directory_entries(skill_root: Path) -> tuple[str, ...]:
    return _descriptor_directory_entries(skill_root, ("scripts",))


def _exact_directory_inventory_findings(
    root: Path,
    components: tuple[str, ...],
    expected: dict[str, str],
    *,
    symbol: str,
) -> list[PolicyFinding]:
    label = "/".join(components) or "."
    findings: list[PolicyFinding] = []
    try:
        entries = _descriptor_directory_entries(root, components)
    except (OSError, TypeError, ValueError) as exc:
        return [PolicyFinding(label, 1, _exception_symbol(exc))]
    if (
        set(entries) != set(expected)
        or any(not entry.isascii() for entry in entries)
        or len({entry.casefold() for entry in entries}) != len(entries)
    ):
        findings.append(PolicyFinding(label, 1, symbol))
    try:
        with open_repository_io(root) as repository:
            for name, expected_kind in expected.items():
                relative = "/".join((*components, name))
                if controller_path_kind(repository, relative) != expected_kind:
                    findings.append(PolicyFinding(relative, 1, symbol))
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding(label, 1, _exception_symbol(exc)))
    return sorted(set(findings))


def _skill_layout_findings(location: _SkillLocation) -> list[PolicyFinding]:
    findings = _exact_directory_inventory_findings(
        location.skill_root,
        (),
        {
            "SKILL.md": "regular",
            "agents": "directory",
            "references": "directory",
            "scripts": "directory",
        },
        symbol="skill_root_inventory_invalid",
    )
    findings.extend(
        _exact_directory_inventory_findings(
            location.skill_root,
            ("agents",),
            {"openai.yaml": "regular"},
            symbol="agent_inventory_invalid",
        )
    )
    return sorted(set(findings))


def _plugin_tree_findings(location: _SkillLocation) -> list[PolicyFinding]:
    if not location.plugin_expected:
        return []
    if location.plugin_root is None:
        return [PolicyFinding(".", 1, "plugin_root_unavailable")]
    expected_root = {
        ".codex-plugin": "directory",
        "skills": "directory",
    }
    if location.requested_layout == LAYOUT_EXTRACTED_PLUGIN:
        expected_root["PACKAGE-MANIFEST.json"] = "regular"
    elif location.requested_layout == LAYOUT_AUTO:
        try:
            with open_repository_io(location.plugin_root) as plugin:
                if controller_path_kind(plugin, "PACKAGE-MANIFEST.json") == "regular":
                    expected_root["PACKAGE-MANIFEST.json"] = "regular"
        except (OSError, TypeError, ValueError):
            pass
    findings = _exact_directory_inventory_findings(
        location.plugin_root,
        (),
        expected_root,
        symbol="plugin_root_inventory_invalid",
    )
    findings.extend(
        _exact_directory_inventory_findings(
            location.plugin_root,
            (".codex-plugin",),
            {"plugin.json": "regular"},
            symbol="plugin_metadata_inventory_invalid",
        )
    )
    findings.extend(
        _exact_directory_inventory_findings(
            location.plugin_root,
            ("skills",),
            {"codexqb": "directory"},
            symbol="plugin_skill_inventory_invalid",
        )
    )
    try:
        with open_repository_io(location.plugin_root) as plugin:
            paths = controller_regular_paths(plugin, "intake")
            directories = controller_directories(plugin, "intake")
        relative_paths = tuple(sorted(set(paths) | set(directories)))
        folded: set[str] = set()
        for relative in relative_paths:
            parts = PurePosixPath(relative).parts
            if not relative.isascii():
                findings.append(
                    PolicyFinding(relative, 1, "plugin_path_non_ascii")
                )
            casefolded = relative.casefold()
            if casefolded in folded:
                findings.append(
                    PolicyFinding(relative, 1, "plugin_path_casefold_collision")
                )
            folded.add(casefolded)
            if any(part.casefold() == "hooks" for part in parts):
                findings.append(PolicyFinding(relative, 1, "plugin_hook_surface"))
            if parts and parts[-1].casefold() == ".mcp.json":
                findings.append(PolicyFinding(relative, 1, "plugin_mcp_surface"))
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding(".", 1, _exception_symbol(exc)))
    return sorted(set(findings))


def _unexpected_script_findings(entries: tuple[str, ...]) -> list[PolicyFinding]:
    allowed = {Path(relative).name for relative in REQUIRED_RUNTIME}
    findings: list[PolicyFinding] = []
    for entry in entries:
        if entry not in allowed:
            findings.append(
                PolicyFinding(f"scripts/{entry}", 1, "unexpected_script_entry")
            )
    return sorted(set(findings))


def _parity_skill_paths(paths: tuple[str, ...]) -> tuple[str, ...]:
    selected = set(REQUIRED_RUNTIME) | set(REQUIRED_MODEL_SURFACES)
    selected.update(path for path in paths if path.startswith("references/"))
    return tuple(sorted(selected))


_AUTHORITATIVE_MANIFEST_FIELDS = frozenset(
    {
        "package_schema_version",
        "artifact_type",
        "layout_version",
        "export_mode",
        "release_claim",
        "git_provenance_available",
        "source_inventory",
        "plugin_version",
        "git_commit",
        "git_branch",
        "origin_main_commit",
        "origin_main_ref_status",
        "head_matches_origin_main",
        "working_tree_clean",
        "tracked_only",
        "include_untracked",
        "changelog_mentions_plugin_version",
        "changelog_release_state",
        "release_tag",
        "release_tag_commit",
        "release_tag_matches_head",
        "generated_at",
        "file_count",
        "tree_sha256",
        "content_sha256",
        "files",
    }
)


def _authoritative_manifest_valid(
    data: bytes,
    *,
    expected_hashes: dict[str, str],
    expected_modes: dict[str, str],
    plugin_version: str,
) -> bool:
    """Bind an extracted plugin manifest to the already pinned payload."""

    if len(data) > 4 * 1024 * 1024:
        return False

    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate_manifest_key")
            result[key] = value
        return result

    try:
        manifest = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return False
    if not isinstance(manifest, dict) or set(manifest) != _AUTHORITATIVE_MANIFEST_FIELDS:
        return False
    if (
        manifest.get("package_schema_version") != 3
        or type(manifest.get("package_schema_version")) is not int
        or manifest.get("artifact_type") != "plugin"
        or manifest.get("layout_version") != 1
        or type(manifest.get("layout_version")) is not int
        or manifest.get("export_mode") not in {"strict_release", "worktree", "source_package"}
        or manifest.get("source_inventory") not in {"git_index", "filesystem"}
        or manifest.get("origin_main_ref_status") not in {"absent", "present", "unavailable"}
        or manifest.get("plugin_version") != plugin_version
        or manifest.get("release_tag") != f"v{plugin_version}"
    ):
        return False
    for field in (
        "release_claim",
        "git_provenance_available",
        "tracked_only",
        "include_untracked",
        "changelog_mentions_plugin_version",
    ):
        if not isinstance(manifest.get(field), bool):
            return False
    for field in (
        "head_matches_origin_main",
        "working_tree_clean",
        "release_tag_matches_head",
    ):
        if manifest.get(field) is not None and not isinstance(manifest.get(field), bool):
            return False
    for field in (
        "git_commit",
        "git_branch",
        "origin_main_commit",
        "changelog_release_state",
        "release_tag_commit",
        "generated_at",
    ):
        value = manifest.get(field)
        if not isinstance(value, str) or not value or len(value) > 4096:
            return False
    raw_files = manifest.get("files")
    if (
        not isinstance(raw_files, list)
        or len(raw_files) != len(expected_hashes)
        or manifest.get("file_count") != len(expected_hashes)
        or type(manifest.get("file_count")) is not int
    ):
        return False
    normalized_files: list[dict[str, str]] = []
    for item in raw_files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode"}:
            return False
        path = item.get("path")
        digest = item.get("sha256")
        mode = item.get("mode")
        if (
            not isinstance(path, str)
            or path not in expected_hashes
            or digest != expected_hashes[path]
            or mode != expected_modes.get(path)
            or mode not in {"0644", "0755"}
        ):
            return False
        normalized_files.append({"path": path, "sha256": digest, "mode": mode})
    if [item["path"] for item in normalized_files] != sorted(expected_hashes):
        return False
    encoded = json.dumps(
        normalized_files,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    tree_digest = hashlib.sha256(encoded).hexdigest()
    return (
        manifest.get("tree_sha256") == tree_digest
        and manifest.get("content_sha256") == tree_digest
    )


def scan_captured_runtime_parity(
    target_root: Path,
    trusted_runtime_sha256: dict[str, str],
    *,
    target_layout: str,
) -> list[PolicyFinding]:
    """Compare target runtime to descriptor-held hashes from the outer wrapper."""

    if (
        set(trusted_runtime_sha256) != set(REQUIRED_RUNTIME)
        or any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in trusted_runtime_sha256.values()
        )
    ):
        return [PolicyFinding("scripts", 1, "captured_runtime_registry_invalid")]
    locations = _locate_skill_locations(
        Path(os.path.abspath(target_root)), layout=target_layout
    )
    if not locations:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_missing")]
    if len(locations) != 1:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_ambiguous")]
    location = locations[0]
    findings = _skill_layout_findings(location) + _plugin_tree_findings(location)
    try:
        with open_repository_io(location.skill_root) as target:
            target_paths = controller_regular_paths(target, "intake")
            for relative in REQUIRED_RUNTIME:
                actual = controller_read_bytes(target, relative, required=True).data
                if actual is None or not hmac.compare_digest(
                    hashlib.sha256(actual).hexdigest(),
                    trusted_runtime_sha256[relative],
                ):
                    findings.append(
                        PolicyFinding(relative, 1, "trusted_runtime_mismatch")
                    )
            if controller_regular_paths(target, "intake") != target_paths:
                raise ValueError("captured_runtime_inventory_changed")
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding("scripts", 1, _exception_symbol(exc)))
    return sorted(set(findings))


def scan_authoritative_target(
    target_root: Path,
    trusted_runtime_sha256: dict[str, str],
    *,
    target_layout: str,
) -> list[PolicyFinding]:
    """Attest the complete target export in one descriptor-bound session."""

    if target_layout == LAYOUT_AUTO:
        return [PolicyFinding(".", 1, "authoritative_layout_required")]
    layout_profile = {
        LAYOUT_REPOSITORY_PLUGIN: (
            "plugins/codexqb",
            "plugins/codexqb/skills/codexqb/",
            "plugins/codexqb/.codex-plugin/plugin.json",
            None,
        ),
        LAYOUT_EXTRACTED_PLUGIN: (
            "",
            "skills/codexqb/",
            ".codex-plugin/plugin.json",
            "PACKAGE-MANIFEST.json",
        ),
        LAYOUT_STANDALONE_SKILL: ("", "", None, None),
    }.get(target_layout)
    if layout_profile is None:
        return [PolicyFinding(".", 1, "authoritative_layout_invalid")]
    if (
        set(trusted_runtime_sha256) != set(REQUIRED_RUNTIME)
        or any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in trusted_runtime_sha256.values()
        )
    ):
        return [PolicyFinding("scripts", 1, "captured_runtime_registry_invalid")]
    scope_prefix, skill_prefix, metadata_path, manifest_path = layout_profile

    expected_hashes = {
        f"{skill_prefix}{relative}": digest
        for relative, digest in trusted_runtime_sha256.items()
    }
    expected_hashes.update(
        {
            f"{skill_prefix}{relative}": digest
            for relative, digest in _APPROVED_MODEL_SURFACE_SHA256.items()
        }
    )
    if metadata_path is not None:
        expected_hashes[metadata_path] = _APPROVED_PLUGIN_METADATA_SHA256
    allowed_regular = set(expected_hashes)
    if manifest_path is not None:
        allowed_regular.add(manifest_path)
    expected_directories: set[str] = set()
    for relative in allowed_regular:
        parent = PurePosixPath(relative).parent
        while parent != PurePosixPath("."):
            expected_directories.add(parent.as_posix())
            parent = parent.parent

    findings: list[PolicyFinding] = []
    try:
        # The supplied root is the only authority anchor.  Layout components
        # are traversed descriptor-relatively inside this one session; no
        # independently resolved plugin or skill path can escape the chain.
        with open_repository_io(Path(os.path.abspath(target_root))) as target:
            inventory = controller_complete_inventory(target, scope_prefix)
            paths = tuple(
                str(item["path"])
                for item in inventory
                if item.get("kind") == "regular"
            )
            inventory_modes = {
                str(item["path"]): str(item["mode"])
                for item in inventory
                if item.get("kind") == "regular"
            }
            directories = tuple(
                str(item["path"])
                for item in inventory
                if item.get("kind") == "directory"
            )
            root_records = tuple(
                item
                for item in inventory
                if item.get("kind") == "root" and item.get("path") == "."
            )
            if (
                len(root_records) != 1
                or set(paths) != allowed_regular
                or set(directories) != expected_directories
            ):
                findings.append(
                    PolicyFinding(".", 1, "authoritative_target_inventory_mismatch")
                )
            plugin_version = ""
            for relative, expected_digest in sorted(expected_hashes.items()):
                actual = controller_read_bytes(target, relative, required=True).data
                if actual is None or not hmac.compare_digest(
                    hashlib.sha256(actual).hexdigest(), expected_digest
                ):
                    findings.append(
                        PolicyFinding(relative, 1, "trusted_runtime_mismatch")
                    )
                if actual is not None and relative == metadata_path:
                    try:
                        metadata = json.loads(actual.decode("utf-8"))
                        version = metadata.get("version") if isinstance(metadata, dict) else None
                        if isinstance(version, str):
                            plugin_version = version
                    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
                        plugin_version = ""
            if manifest_path is not None:
                manifest = controller_read_bytes(
                    target, manifest_path, required=True
                ).data
                if (
                    manifest is None
                    or not plugin_version
                    or inventory_modes.get(manifest_path) != "0644"
                    or not _authoritative_manifest_valid(
                        manifest,
                        expected_hashes=expected_hashes,
                        expected_modes=inventory_modes,
                        plugin_version=plugin_version,
                    )
                ):
                    findings.append(
                        PolicyFinding(
                            manifest_path,
                            1,
                            "authoritative_manifest_invalid",
                        )
                    )
            if controller_complete_inventory(target, scope_prefix) != inventory:
                raise ValueError("authoritative_target_inventory_changed")
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding(".", 1, _exception_symbol(exc)))
    return sorted(set(findings))


def scan_runtime_parity(
    trusted_root: Path,
    target_root: Path,
    *,
    target_layout: str = LAYOUT_AUTO,
) -> list[PolicyFinding]:
    """Compare target checker/runtime bytes using the trusted source checker."""

    trusted_locations = _locate_skill_locations(
        Path(os.path.abspath(trusted_root)), layout=LAYOUT_REPOSITORY_PLUGIN
    )
    target_locations = _locate_skill_locations(
        Path(os.path.abspath(target_root)), layout=target_layout
    )
    if not trusted_locations:
        return [PolicyFinding("skills/codexqb", 1, "trusted_skill_root_missing")]
    if len(trusted_locations) != 1:
        return [PolicyFinding("skills/codexqb", 1, "trusted_skill_root_ambiguous")]
    if not target_locations:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_missing")]
    if len(target_locations) != 1:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_ambiguous")]
    trusted_location = trusted_locations[0]
    target_location = target_locations[0]
    trusted_skill = trusted_location.skill_root
    target_skill = target_location.skill_root
    findings: list[PolicyFinding] = []
    findings.extend(_skill_layout_findings(target_location))
    findings.extend(_plugin_tree_findings(target_location))
    try:
        findings.extend(
            _unexpected_script_findings(_script_directory_entries(target_skill))
        )
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding("scripts", 1, _exception_symbol(exc)))
    try:
        with open_repository_io(trusted_skill) as trusted, open_repository_io(target_skill) as target:
            trusted_paths = controller_regular_paths(trusted, "intake")
            target_paths = controller_regular_paths(target, "intake")
            expected_paths = _parity_skill_paths(trusted_paths)
            target_parity_paths = set(_parity_skill_paths(target_paths))
            for relative in expected_paths:
                expected = controller_read_bytes(trusted, relative, required=True).data
                actual = controller_read_bytes(target, relative, required=True).data
                if expected is None or actual is None or not hmac.compare_digest(
                    hashlib.sha256(expected).digest(), hashlib.sha256(actual).digest()
                ):
                    findings.append(PolicyFinding(relative, 1, "trusted_runtime_mismatch"))
            for relative in sorted(target_parity_paths - set(expected_paths)):
                findings.append(
                    PolicyFinding(relative, 1, "unexpected_parity_surface")
                )
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding("skills/codexqb", 1, _exception_symbol(exc)))
    if target_location.plugin_expected and trusted_location.plugin_root is not None:
        if target_location.plugin_root is None:
            findings.append(
                PolicyFinding(
                    ".codex-plugin/plugin.json", 1, "plugin_metadata_missing"
                )
            )
        else:
            try:
                trusted_skill_entries = _descriptor_directory_entries(
                    trusted_location.plugin_root, ("skills",)
                )
                target_skill_entries = _descriptor_directory_entries(
                    target_location.plugin_root, ("skills",)
                )
                if (
                    trusted_skill_entries != ("codexqb",)
                    or target_skill_entries != trusted_skill_entries
                ):
                    findings.append(
                        PolicyFinding(
                            "skills", 1, "plugin_skill_inventory_mismatch"
                        )
                    )
                with open_repository_io(trusted_location.plugin_root) as trusted_plugin, open_repository_io(target_location.plugin_root) as target_plugin:
                    expected = controller_read_bytes(
                        trusted_plugin,
                        ".codex-plugin/plugin.json",
                        required=True,
                    ).data
                    actual = controller_read_bytes(
                        target_plugin,
                        ".codex-plugin/plugin.json",
                        required=True,
                    ).data
                if (
                    expected is None
                    or actual is None
                    or not hmac.compare_digest(
                        hashlib.sha256(expected).digest(),
                        hashlib.sha256(actual).digest(),
                    )
                ):
                    findings.append(
                        PolicyFinding(
                            ".codex-plugin/plugin.json",
                            1,
                            "trusted_runtime_mismatch",
                        )
                    )
            except (OSError, TypeError, ValueError) as exc:
                findings.append(
                    PolicyFinding(
                        ".codex-plugin/plugin.json", 1, _exception_symbol(exc)
                    )
                )
    return sorted(set(findings))


def scan_tree(root: Path, *, layout: str = LAYOUT_AUTO) -> list[PolicyFinding]:
    root = Path(os.path.abspath(root))
    locations = _locate_skill_locations(root, layout=layout)
    if not locations:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_missing")]
    if len(locations) != 1:
        return [PolicyFinding("skills/codexqb", 1, "skill_root_ambiguous")]
    location = locations[0]
    skill_root = location.skill_root
    findings: list[PolicyFinding] = []
    try:
        with open_repository_io(skill_root) as repository:
            for relative in REQUIRED_RUNTIME:
                if controller_path_kind(repository, relative) != "regular":
                    findings.append(PolicyFinding(relative, 1, "required_runtime_missing"))
            paths = controller_regular_paths(repository, "intake")
            findings.extend(
                _unexpected_script_findings(
                    _script_directory_entries(location.skill_root)
                )
            )
            for relative in PROTECTED_PYTHON:
                try:
                    evidence = repository.read_text(relative, required=True, audience="internal")
                    text = evidence.text or ""
                except (OSError, TypeError, ValueError) as exc:
                    findings.append(PolicyFinding(relative, 1, _exception_symbol(exc)))
                    continue
                findings.extend(
                    _scan_ast_pinned_runtime(
                        relative,
                        text,
                        expected_digest=_APPROVED_PROTECTED_CONSUMER_AST_DIGESTS[
                            relative
                        ],
                        mismatch_symbol="protected_consumer_unreviewed",
                    )
                )
                findings.extend(scan_python(relative, text))
            controller_relative = "scripts/repository_controller.py"
            if controller_path_kind(repository, controller_relative) != "missing":
                findings.append(
                    PolicyFinding(
                        controller_relative,
                        1,
                        "forbidden_repository_controller_runtime",
                    )
                )
            store_relative = "scripts/controller_store.py"
            try:
                store_evidence = repository.read_text(
                    store_relative, required=True, audience="internal"
                )
                findings.extend(
                    scan_controller_store(store_relative, store_evidence.text or "")
                )
            except (OSError, TypeError, ValueError) as exc:
                findings.append(
                    PolicyFinding(store_relative, 1, _exception_symbol(exc))
                )
            execution_relative = "scripts/execution_controller.py"
            try:
                execution_evidence = repository.read_text(
                    execution_relative, required=True, audience="internal"
                )
                findings.extend(
                    scan_execution_controller(
                        execution_relative, execution_evidence.text or ""
                    )
                )
            except (OSError, TypeError, ValueError) as exc:
                findings.append(
                    PolicyFinding(execution_relative, 1, _exception_symbol(exc))
                )
            for trusted_relative, (
                trusted_digest,
                trusted_imports,
            ) in sorted(_TRUSTED_CONTROLLER_REGISTRY.items()):
                try:
                    trusted_evidence = repository.read_text(
                        trusted_relative, required=True, audience="internal"
                    )
                    findings.extend(
                        scan_trusted_controller(
                            trusted_relative,
                            trusted_evidence.text or "",
                            expected_digest=trusted_digest,
                            allowed_repository_io_imports=trusted_imports,
                        )
                    )
                except (OSError, TypeError, ValueError) as exc:
                    findings.append(
                        PolicyFinding(trusted_relative, 1, _exception_symbol(exc))
                    )
            reference_paths = [
                path
                for path in paths
                if path in REQUIRED_MODEL_SURFACES or path.startswith("references/")
            ]
            if set(reference_paths) != set(_APPROVED_MODEL_SURFACE_SHA256):
                findings.append(
                    PolicyFinding(
                        "references", 1, "model_surface_registry_mismatch"
                    )
                )
            if "SKILL.md" not in reference_paths:
                findings.append(PolicyFinding("SKILL.md", 1, "required_skill_missing"))
            if "agents/openai.yaml" not in reference_paths:
                findings.append(
                    PolicyFinding(
                        "agents/openai.yaml", 1, "required_model_surface_missing"
                    )
                )
            for relative in sorted(reference_paths):
                try:
                    raw_evidence = controller_read_bytes(
                        repository, relative, required=True
                    )
                    if raw_evidence.data is None:
                        raise ValueError("model_surface_missing")
                    expected_digest = _APPROVED_MODEL_SURFACE_SHA256.get(relative)
                    if expected_digest is None or not hmac.compare_digest(
                        hashlib.sha256(raw_evidence.data).hexdigest(),
                        expected_digest,
                    ):
                        findings.append(
                            PolicyFinding(
                                relative, 1, "model_surface_unreviewed"
                            )
                        )
                    evidence = repository.read_text(
                        relative, required=True, audience="internal"
                    )
                    text = evidence.text or ""
                except (OSError, TypeError, ValueError) as exc:
                    findings.append(PolicyFinding(relative, 1, _exception_symbol(exc)))
                    continue
                if relative == "agents/openai.yaml":
                    findings.extend(_openai_metadata_findings(text))
                else:
                    findings.extend(scan_markdown(relative, text))
            if controller_regular_paths(repository, "intake") != paths:
                raise ValueError("repository_io_inventory_changed")
    except (OSError, TypeError, ValueError) as exc:
        findings.append(PolicyFinding("skills/codexqb", 1, _exception_symbol(exc)))
    findings.extend(_skill_layout_findings(location))
    findings.extend(_plugin_tree_findings(location))
    findings.extend(_plugin_metadata_findings(location))
    return sorted(set(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--layout", choices=sorted(LAYOUT_EXPECTATIONS), default=LAYOUT_AUTO)
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    findings = scan_tree(Path(args.root), layout=args.layout)
    if findings:
        print("repository_io_policy=failed")
        for finding in findings:
            print(f"finding={finding.render()}")
        return 1
    # A packaged self-checker and its in-file pins can be changed together.
    # Only the outer repository-owned wrapper may claim authority after
    # independent held-byte parity and source-anchor revalidation.
    print(f"repository_io_policy=passed authority=false layout={args.layout}")
    return 0


__all__ = [
    "PolicyFinding",
    "locate_skill_root",
    "scan_markdown",
    "scan_controller_store",
    "scan_execution_controller",
    "scan_trusted_controller",
    "scan_python",
    "scan_captured_runtime_parity",
    "scan_authoritative_target",
    "scan_runtime_parity",
    "scan_tree",
]


if __name__ == "__main__":
    raise SystemExit(main())
