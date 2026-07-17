#!/usr/bin/env python3
"""Create a sanitized CodexQB source zip with mode-specific provenance.

The default strict-release mode requires an exact Git root, clean tracked tree,
dated changelog release heading, and matching version tag at HEAD. Explicit
worktree and Gitless source-package modes are non-release exports.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from functools import partial
import hashlib
import json
import os
import re
import secrets
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
import zipfile
from pathlib import Path


SAFETY_DIR = Path(__file__).resolve().parents[1] / "plugins/codexqb/skills/codexqb/scripts"
if str(SAFETY_DIR) not in sys.path:
    sys.path.insert(0, str(SAFETY_DIR))
SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

from safety_contracts import (  # noqa: E402
    package_secret_match_locations,
    package_secret_path_match_locations,
)
from git_evidence import trusted_git_executable  # noqa: E402
from mount_identity import (  # noqa: E402
    MountIdentityError,
    MountResolution,
    NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION,
    require_mount_assurance,
    require_same_mount,
    resolve_mount_identity,
)
from repository_evidence import (  # noqa: E402
    RepositoryRootAnchor,
    normalize_repo_relative_path,
    open_repository_root_anchor,
    read_regular_files_from_anchor,
    revalidate_repository_root_anchor,
    require_same_repository_mount,
    snapshot_git_paths_from_anchor,
)
from verify_package_manifest import (  # noqa: E402
    MAX_MANIFEST_BYTES,
    MAX_MANIFEST_FILES,
    MAX_PACKAGE_UNCOMPRESSED_BYTES,
    manifest_contract_errors,
    manifest_entries,
    portable_path_key,
    verify_zip,
)
from package_policy import (  # noqa: E402
    ARTIFACT_TYPES,
    COMMON_DENIED_PARTS,
    COMMON_DENIED_SUFFIXES,
    LAYOUT_VERSION,
    MAX_ARTIFACT_FILE_BYTES,
    MAX_CANONICAL_ZIP_MEMBERS,
    PACKAGE_MANIFEST_NAME,
    PACKAGE_SCHEMA_VERSION,
    PLUGIN_ACTIVATION_PATH,
    PLUGIN_ARTIFACT,
    PLUGIN_SKILL_PATH,
    SOURCE_ARTIFACT,
    archive_prefix,
    default_artifact_filename,
    denied_path_reason,
    payload_is_zip_archive,
    plugin_activation_contract_errors,
    plugin_skill_contract_errors,
    source_to_artifact_path,
)


IGNORED_PARTS = set(COMMON_DENIED_PARTS)
BLOCKED_SUFFIXES = set(COMMON_DENIED_SUFFIXES)
BLOCKED_RE = re.compile(
    r"(^|/)(\.git|\.codexqb|__pycache__|\.env|artifacts|logs|tmp|__MACOSX)(/|$)|"
    r"\.pyc$|\.pem$|\.key$|\.local($|\.)",
    re.IGNORECASE,
)
STRICT_RELEASE_MODE = "strict_release"
WORKTREE_MODE = "worktree"
SOURCE_PACKAGE_MODE = "source_package"
MAX_EXPORT_FILE_BYTES = MAX_ARTIFACT_FILE_BYTES
MAX_EXPORT_PAYLOAD_BYTES = min(
    256 * 1024 * 1024,
    MAX_PACKAGE_UNCOMPRESSED_BYTES - MAX_MANIFEST_BYTES,
)
GIT_COMMAND_TIMEOUT_SECONDS = 10
MAX_GIT_COMMAND_OUTPUT_BYTES = 16 * 1024 * 1024
GIT_OUTPUT_CHUNK_BYTES = 64 * 1024
SOURCE_WALK_TIMEOUT_SECONDS = 60
SAFE_EXPORT_FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9_]*")
GitRoot = Path | RepositoryRootAnchor


def _git_root_path(root: GitRoot) -> Path:
    return root.path if isinstance(root, RepositoryRootAnchor) else root


def git_subprocess_environment() -> dict[str, str]:
    """Remove inherited repository-routing controls from strict Git evidence."""

    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.upper().startswith("GIT_")
    }
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    environment["PATH"] = os.defpath
    return environment


def git_command(args: list[str]) -> list[str]:
    return [
        trusted_git_executable(),
        "--no-replace-objects",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.ignorestat=false",
        "-c",
        "core.untrackedCache=false",
        *args,
    ]


def _terminate_git_process_group(process: subprocess.Popen[bytes]) -> None:
    """Stop Git and any descendants that still hold its output pipes open."""

    if os.name == "posix":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except ProcessLookupError:
            return
        except OSError:
            pass
    try:
        if process.poll() is None:
            process.kill()
    except OSError:
        pass


def _terminate_and_reap_git_process_group(process: subprocess.Popen[bytes]) -> bool:
    """Kill the isolated group and synchronously reap its leader."""

    _terminate_git_process_group(process)
    for _attempt in range(2):
        try:
            process.wait(timeout=5)
            return True
        except subprocess.TimeoutExpired:
            _terminate_git_process_group(process)
    return False


def _enter_anchored_git_root(root_fd: int) -> None:
    os.fchdir(root_fd)
    os.close(root_fd)


def _run_bounded_git_process(root: GitRoot, args: list[str]) -> tuple[int, bytes] | None:
    """Run trusted Git with a combined, streaming stdout/stderr memory bound."""

    popen_kwargs: dict[str, object] = {
        "cwd": _git_root_path(root),
        "env": git_subprocess_environment(),
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "start_new_session": os.name == "posix",
    }
    if isinstance(root, RepositoryRootAnchor):
        revalidate_repository_root_anchor(root)
        if os.name != "posix" or threading.active_count() != 1:
            raise ValueError("repository_root_anchor_process_isolation_unavailable")
        popen_kwargs.update(
            {
                "cwd": None,
                "pass_fds": (root.fd,),
                "preexec_fn": partial(_enter_anchored_git_root, root.fd),
            }
        )
    selector: selectors.BaseSelector | None = None
    stdout = bytearray()
    total_output_bytes = 0
    deadline = time.monotonic() + GIT_COMMAND_TIMEOUT_SECONDS
    failed = False
    try:
        process = subprocess.Popen(
            git_command(args),
            **popen_kwargs,
        )
    except (OSError, ValueError):
        return None

    try:
        if process.stdout is None or process.stderr is None:
            _terminate_and_reap_git_process_group(process)
            return None
        selector = selectors.DefaultSelector()
        for pipe in (process.stdout, process.stderr):
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                _terminate_git_process_group(process)
                break
            for key, _ in selector.select(min(0.1, remaining)):
                try:
                    chunk = os.read(
                        key.fileobj.fileno(),
                        min(
                            GIT_OUTPUT_CHUNK_BYTES,
                            MAX_GIT_COMMAND_OUTPUT_BYTES - total_output_bytes + 1,
                        ),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                total_output_bytes += len(chunk)
                if key.fileobj is process.stdout:
                    stdout.extend(chunk)
                if total_output_bytes > MAX_GIT_COMMAND_OUTPUT_BYTES:
                    failed = True
                    _terminate_git_process_group(process)
                    break
            if failed:
                break
        if not failed:
            try:
                process.wait(timeout=max(0.0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                failed = True
                _terminate_git_process_group(process)
    except (OSError, ValueError):
        failed = True
        _terminate_git_process_group(process)
    except BaseException:
        _terminate_and_reap_git_process_group(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        for pipe in (process.stdout, process.stderr):
            if pipe is not None and not pipe.closed:
                pipe.close()

    if not _terminate_and_reap_git_process_group(process):
        failed = True
    if isinstance(root, RepositoryRootAnchor):
        revalidate_repository_root_anchor(root)
    if failed or process.returncode is None:
        return None
    return int(process.returncode), bytes(stdout)


def run_git(root: GitRoot, args: list[str]) -> list[str] | None:
    completed = _run_bounded_git_process(root, args)
    if completed is None:
        return None
    returncode, stdout = completed
    if returncode != 0:
        return None
    return [line for line in os.fsdecode(stdout).splitlines() if line.strip()]


def run_git_paths(root: GitRoot, args: list[str]) -> list[str] | None:
    """Read a NUL-delimited Git pathname result without splitting valid newlines."""

    completed = _run_bounded_git_process(root, args)
    if completed is None:
        return None
    returncode, stdout = completed
    if returncode != 0:
        return None
    try:
        return [os.fsdecode(item) for item in _iter_nul_records(stdout)]
    except ValueError as exc:
        if str(exc) == "git_path_inventory_limit_exceeded":
            raise ValueError("package_file_count_limit_exceeded") from exc
        return None


def run_git_bytes(root: GitRoot, args: list[str]) -> bytes | None:
    """Return raw Git output so NUL-delimited path records stay unambiguous."""

    completed = _run_bounded_git_process(root, args)
    if completed is None:
        return None
    returncode, stdout = completed
    if returncode != 0:
        return None
    return stdout


def _iter_nul_records(data: bytes):
    """Yield at most the declared package path limit without split amplification."""

    offset = 0
    count = 0
    while offset < len(data):
        end = data.find(b"\0", offset)
        if end < 0 or end == offset:
            raise ValueError("git_path_inventory_malformed")
        count += 1
        if count > MAX_MANIFEST_FILES:
            raise ValueError("git_path_inventory_limit_exceeded")
        yield data[offset:end]
        offset = end + 1


def parse_git_index_inventory(
    data: bytes,
) -> tuple[dict[str, tuple[str, str, str]], list[str]]:
    """Parse ``git ls-files --stage -v -z`` and reject non-normal index state."""

    if data and not data.endswith(b"\0"):
        return {}, ["git_index_inventory_malformed"]
    inventory: dict[str, tuple[str, str, str]] = {}
    errors: list[str] = []
    try:
        records = _iter_nul_records(data)
        for record in records:
            try:
                header, raw_path = record.split(b"\t", 1)
            except ValueError:
                errors.append("git_index_inventory_malformed")
                continue
            fields = header.split(b" ")
            if len(fields) != 4 or not raw_path:
                errors.append("git_index_inventory_malformed")
                continue
            raw_tag, raw_mode, raw_oid, raw_stage = fields
            if (
                len(raw_tag) != 1
                or re.fullmatch(rb"[0-7]{6}", raw_mode) is None
                or re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", raw_oid) is None
                or raw_stage != b"0"
            ):
                errors.append("git_index_inventory_malformed")
                continue
            try:
                tag = raw_tag.decode("ascii")
                mode = raw_mode.decode("ascii")
                oid = raw_oid.decode("ascii")
            except UnicodeDecodeError:
                errors.append("git_index_inventory_malformed")
                continue
            path = os.fsdecode(raw_path)
            if not path or path in inventory:
                errors.append("git_index_inventory_malformed")
                continue
            inventory[path] = (tag, mode, oid)
            if tag == "S" or tag.islower():
                errors.append("git_index_trust_flags_present")
            elif tag != "H":
                errors.append("git_index_state_unsupported")
    except ValueError as exc:
        if str(exc) == "git_path_inventory_limit_exceeded":
            errors.append("git_index_inventory_limit_exceeded")
        else:
            errors.append("git_index_inventory_malformed")
    return inventory, list(dict.fromkeys(errors))


def git_index_inventory(
    root: GitRoot,
) -> tuple[dict[str, tuple[str, str, str]], list[str]]:
    data = run_git_bytes(
        root,
        ["ls-files", "--stage", "-v", "-z", "--cached", "--full-name", "--"],
    )
    if data is None:
        return {}, ["git_index_inventory_unavailable"]
    return parse_git_index_inventory(data)


def parse_git_tree_inventory(
    data: bytes,
) -> tuple[dict[str, tuple[str, str]], list[str]]:
    """Parse an exact commit tree into path -> (mode, object id)."""

    if data and not data.endswith(b"\0"):
        return {}, ["git_release_tree_inventory_malformed"]
    inventory: dict[str, tuple[str, str]] = {}
    errors: list[str] = []
    try:
        records = _iter_nul_records(data)
        for record in records:
            try:
                header, raw_path = record.split(b"\t", 1)
            except ValueError:
                errors.append("git_release_tree_inventory_malformed")
                continue
            fields = header.split(b" ")
            if len(fields) != 3 or not raw_path:
                errors.append("git_release_tree_inventory_malformed")
                continue
            raw_mode, raw_type, raw_oid = fields
            if (
                raw_type != b"blob"
                or raw_mode not in {b"100644", b"100755"}
                or re.fullmatch(rb"(?:[0-9a-f]{40}|[0-9a-f]{64})", raw_oid) is None
            ):
                errors.append("git_release_tree_entry_unsupported")
                continue
            path = os.fsdecode(raw_path)
            if not path or path in inventory:
                errors.append("git_release_tree_inventory_malformed")
                continue
            inventory[path] = (raw_mode.decode("ascii"), raw_oid.decode("ascii"))
    except ValueError as exc:
        if str(exc) == "git_path_inventory_limit_exceeded":
            errors.append("git_release_tree_inventory_limit_exceeded")
        else:
            errors.append("git_release_tree_inventory_malformed")
    return inventory, list(dict.fromkeys(errors))


def git_tree_inventory(
    root: GitRoot,
    ref: str,
) -> tuple[dict[str, tuple[str, str]], list[str]]:
    data = run_git_bytes(root, ["ls-tree", "-r", "-z", "--full-tree", ref, "--"])
    if data is None:
        return {}, ["git_release_tree_inventory_unavailable"]
    return parse_git_tree_inventory(data)


def git_object_format(root: GitRoot) -> str | None:
    value = run_git_text(root, ["rev-parse", "--show-object-format"])
    return value if value in {"sha1", "sha256"} else None


def git_blob_oid(data: bytes, object_format: str) -> str:
    digest = hashlib.new(object_format)
    digest.update(f"blob {len(data)}\0".encode("ascii"))
    digest.update(data)
    return digest.hexdigest()


def run_git_text(root: GitRoot, args: list[str]) -> str | None:
    lines = run_git(root, args)
    if lines is None:
        return None
    return "\n".join(lines).strip()


def in_git_checkout(root: GitRoot) -> bool:
    top_level = run_git_text(root, ["rev-parse", "--show-toplevel"])
    if top_level is None:
        return False
    try:
        root_path = _git_root_path(root)
        return Path(top_level).resolve() == root_path.resolve()
    except OSError:
        return False


def git_commit(root: GitRoot, ref: str = "HEAD") -> str | None:
    return run_git_text(root, ["rev-parse", "--verify", ref])


def git_branch(root: GitRoot) -> str:
    return run_git_text(root, ["branch", "--show-current"]) or "unknown"


def git_status(root: GitRoot) -> str | None:
    clean = safe_worktree_clean(root)
    if clean is None:
        return None
    return "" if clean else "dirty"


def git_status_excluding(root: GitRoot, excluded: list[str]) -> str | None:
    clean = safe_worktree_clean(root, excluded_untracked=excluded)
    if clean is None:
        return None
    return "" if clean else "dirty"


def origin_main_provenance(root: GitRoot) -> tuple[str, str | None]:
    commits = run_git(
        root,
        ["for-each-ref", "--format=%(objectname)", "refs/remotes/origin/main"],
    )
    if commits is None:
        return "unavailable", None
    if not commits:
        return "absent", None
    if len(commits) != 1 or re.fullmatch(r"[a-f0-9]{40,64}", commits[0]) is None:
        return "unavailable", None
    return "present", commits[0]


def origin_main_commit(root: GitRoot) -> str | None:
    return origin_main_provenance(root)[1]


def plugin_version_from_bytes(data: bytes | None) -> str:
    if data is None:
        return "unknown"
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return "unknown"
    if not isinstance(document, dict):
        return "unknown"
    version = document.get("version")
    return version if isinstance(version, str) and version else "unknown"


def plugin_version(root: GitRoot) -> str:
    root_path = _git_root_path(root)
    if isinstance(root, RepositoryRootAnchor):
        try:
            payload = read_regular_files_from_anchor(
                root,
                ["plugins/codexqb/.codex-plugin/plugin.json"],
                max_bytes=MAX_EXPORT_FILE_BYTES,
                max_total_bytes=MAX_EXPORT_FILE_BYTES,
                max_paths=1,
            )[0]
        except ValueError as exc:
            if str(exc).startswith("repository_evidence_target_unavailable="):
                return "unknown"
            raise _payload_read_error(exc) from exc
        return plugin_version_from_bytes(payload.data)
    plugin = root_path / "plugins/codexqb/.codex-plugin/plugin.json"
    try:
        data = plugin.read_bytes()
    except OSError:
        data = None
    return plugin_version_from_bytes(data)


def changelog_release_state_from_bytes(data: bytes | None, version: str) -> str:
    if data is None or version == "unknown":
        return "unknown" if version == "unknown" else "missing"
    text = data.decode("utf-8", errors="replace")
    release_heading = re.compile(
        rf"^##[ \t]+\[?{re.escape(version)}\]?[ \t]+-[ \t]+(?P<date>[0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})[ \t]*$",
        re.MULTILINE,
    )
    for match in release_heading.finditer(text):
        try:
            datetime.strptime(match.group("date"), "%Y-%m-%d")
        except ValueError:
            continue
        return "released"
    if re.search(rf"(?<![0-9A-Za-z]){re.escape(version)}(?![0-9A-Za-z])", text):
        return "unreleased"
    return "missing"


def changelog_release_state(root: GitRoot, version: str) -> str:
    root_path = _git_root_path(root)
    if isinstance(root, RepositoryRootAnchor):
        try:
            payload = read_regular_files_from_anchor(
                root,
                ["CHANGELOG.md"],
                max_bytes=MAX_EXPORT_FILE_BYTES,
                max_total_bytes=MAX_EXPORT_FILE_BYTES,
                max_paths=1,
            )[0]
        except ValueError as exc:
            if str(exc).startswith("repository_evidence_target_unavailable="):
                return "missing" if version != "unknown" else "unknown"
            raise _payload_read_error(exc) from exc
        return changelog_release_state_from_bytes(payload.data, version)
    changelog = root_path / "CHANGELOG.md"
    try:
        data = changelog.read_bytes()
    except OSError:
        data = None
    return changelog_release_state_from_bytes(data, version)


def changelog_mentions_version(root: GitRoot, version: str) -> bool:
    return changelog_release_state(root, version) in {"released", "unreleased"}


def release_tag(version: str) -> str:
    return f"v{version}" if version != "unknown" else "unknown"


def release_tag_commit(root: GitRoot, version: str) -> str | None:
    if version == "unknown" or not in_git_checkout(root):
        return None
    return run_git_text(
        root,
        ["rev-parse", "--verify", f"refs/tags/{release_tag(version)}^{{commit}}"],
    )


def export_mode(
    *,
    source_package: bool,
    include_untracked: bool,
    allow_dirty: bool,
    allow_head_mismatch: bool,
) -> str:
    worktree_flags = include_untracked or allow_dirty or allow_head_mismatch
    if source_package and worktree_flags:
        raise ValueError("source_package_mode_conflicts_with_git_worktree_flags")
    if source_package:
        return SOURCE_PACKAGE_MODE
    if worktree_flags:
        return WORKTREE_MODE
    return STRICT_RELEASE_MODE


def _anchored_source_paths(anchor: RepositoryRootAnchor) -> list[Path]:
    """Enumerate a bounded source-package tree through descriptor-relative walks."""

    deadline = time.monotonic() + SOURCE_WALK_TIMEOUT_SECONDS
    visited = 0
    candidates: list[Path] = []

    def walk(directory_fd: int, prefix: tuple[str, ...], depth: int) -> None:
        nonlocal visited
        if depth > 128:
            raise ValueError("package_source_directory_depth_exceeded")
        if time.monotonic() > deadline:
            raise ValueError("package_source_walk_deadline_exceeded")
        try:
            with os.scandir(directory_fd) as iterator:
                names = []
                for entry in iterator:
                    if time.monotonic() > deadline:
                        raise ValueError("package_source_walk_deadline_exceeded")
                    visited += 1
                    if visited > MAX_MANIFEST_FILES:
                        raise ValueError("package_file_count_limit_exceeded")
                    names.append(entry.name)
        except OSError as exc:
            raise ValueError("package_source_walk_failed") from exc
        for name in names:
            if time.monotonic() > deadline:
                raise ValueError("package_source_walk_deadline_exceeded")
            if name in {"", ".", ".."}:
                raise ValueError("package_manifest_preflight_failed=path_not_portable")
            rel = "/".join((*prefix, name))
            try:
                normalized = normalize_repo_relative_path(rel)
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            except (OSError, TypeError, ValueError) as exc:
                raise ValueError(f"package_source_walk_changed={rel}") from exc
            if normalized != rel:
                raise ValueError("package_manifest_preflight_failed=path_not_portable")
            relative = Path(rel)
            if stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                candidates.append(anchor.path / relative)
                continue
            if not stat.S_ISDIR(metadata.st_mode):
                continue
            if IGNORED_PARTS.intersection(part.casefold() for part in relative.parts):
                continue
            if metadata.st_dev != anchor.metadata.st_dev:
                raise ValueError(f"package_source_directory_escape={rel}")
            try:
                child_fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
                opened = os.fstat(child_fd)
            except OSError as exc:
                raise ValueError(f"package_source_walk_changed={rel}") from exc
            try:
                if (
                    not stat.S_ISDIR(opened.st_mode)
                    or opened.st_dev != anchor.metadata.st_dev
                    or (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                ):
                    raise ValueError(f"package_source_walk_changed={rel}")
                require_same_repository_mount(anchor, child_fd, rel)
                walk(child_fd, (*prefix, name), depth + 1)
                after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError(f"package_source_walk_changed={rel}")
            finally:
                os.close(child_fd)

    revalidate_repository_root_anchor(anchor)
    walk(anchor.fd, (), 0)
    revalidate_repository_root_anchor(anchor)
    result = sorted(candidates, key=lambda path: path.relative_to(anchor.path).as_posix())
    if time.monotonic() > deadline:
        raise ValueError("package_source_walk_deadline_exceeded")
    return result


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def candidate_paths(
    root: GitRoot,
    *,
    include_untracked: bool,
    mode: str,
    index_inventory: dict[str, tuple[str, str, str]] | None,
) -> list[Path]:
    root_path = _git_root_path(root)
    if mode == SOURCE_PACKAGE_MODE:
        if isinstance(root, RepositoryRootAnchor):
            return _anchored_source_paths(root)
        with open_repository_root_anchor(root_path) as anchor:
            return _anchored_source_paths(anchor)
    if index_inventory is None:
        raise ValueError("git_tracked_file_inventory_unavailable")
    rels = set(index_inventory)
    if include_untracked:
        untracked = run_git_paths(
            root,
            ["ls-files", "-z", "--others", "--exclude-standard"],
        )
        if untracked is None:
            raise ValueError("git_untracked_file_inventory_unavailable")
        rels.update(untracked)
    if len(rels) > MAX_MANIFEST_FILES:
        raise ValueError("package_file_count_limit_exceeded")
    for rel in rels:
        try:
            normalized = normalize_repo_relative_path(rel)
        except (TypeError, ValueError) as exc:
            raise ValueError("git_file_inventory_path_invalid") from exc
        if normalized != rel:
            raise ValueError("git_file_inventory_path_invalid")
    return [root_path / rel for rel in sorted(rels)]


def file_digest(
    root: Path,
    path: Path,
    data: bytes,
    mode: int,
    *,
    artifact_type: str = SOURCE_ARTIFACT,
) -> dict[str, str]:
    source_rel = path.relative_to(root).as_posix()
    rel = source_to_artifact_path(source_rel, artifact_type)
    if rel is None:
        raise ValueError("package_artifact_path_unmapped")
    return {
        "path": rel,
        "sha256": sha256_bytes(data),
        "mode": f"{mode:04o}",
    }


def tree_digest(entries: list[dict[str, str]]) -> str:
    payload = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(payload)


def reproducible_generated_at() -> str:
    """Return one path-independent, reproducible manifest timestamp."""

    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        epoch = 315532800  # 1980-01-01T00:00:00Z, matching ZIP's minimum date.
    else:
        if re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
            raise ValueError("source_date_epoch_invalid")
        try:
            epoch = int(raw)
            generated = datetime.fromtimestamp(epoch, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("source_date_epoch_invalid") from exc
        if generated.year > 9999:
            raise ValueError("source_date_epoch_invalid")
    try:
        generated = datetime.fromtimestamp(epoch, timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise ValueError("source_date_epoch_invalid") from exc
    return generated.isoformat(timespec="seconds").replace("+00:00", "Z")


def package_manifest(
    root: GitRoot,
    files: list[Path],
    *,
    include_untracked: bool,
    mode: str,
    payloads: dict[Path, bytes],
    modes: dict[Path, int],
    index_errors: list[str],
    artifact_type: str = SOURCE_ARTIFACT,
) -> dict[str, object]:
    root_path = _git_root_path(root).resolve()
    entries = sorted(
        (
            file_digest(
                root_path,
                path,
                payloads[path],
                modes[path],
                artifact_type=artifact_type,
            )
            for path in files
        ),
        key=lambda item: item["path"],
    )
    version = plugin_version_from_bytes(
        payloads.get(root_path / "plugins/codexqb/.codex-plugin/plugin.json")
    )
    changelog_state = (
        changelog_release_state(root, version)
        if artifact_type == PLUGIN_ARTIFACT
        else changelog_release_state_from_bytes(
            payloads.get(root_path / "CHANGELOG.md"),
            version,
        )
    )
    git_provenance = in_git_checkout(root)
    head_value = git_commit(root) if git_provenance else None
    head = head_value or "unknown"
    origin_status, origin = (
        origin_main_provenance(root) if git_provenance else ("unavailable", None)
    )
    status = git_status(root) if git_provenance else None
    tag = release_tag(version)
    tag_commit = release_tag_commit(root, version) if git_provenance else None
    source_inventory = "filesystem" if mode == SOURCE_PACKAGE_MODE else "git_index"
    content_sha256 = tree_digest(entries)
    return {
        "package_schema_version": PACKAGE_SCHEMA_VERSION,
        "artifact_type": artifact_type,
        "layout_version": LAYOUT_VERSION,
        "export_mode": mode,
        "release_claim": mode == STRICT_RELEASE_MODE,
        "git_provenance_available": git_provenance,
        "source_inventory": source_inventory,
        "plugin_version": version,
        "git_commit": head,
        "git_branch": git_branch(root) if git_provenance else "unknown",
        "origin_main_commit": origin or "unknown",
        "origin_main_ref_status": origin_status,
        "head_matches_origin_main": (head == origin) if origin else None,
        "working_tree_clean": (
            status == "" and not index_errors if status is not None else None
        ),
        "tracked_only": mode != SOURCE_PACKAGE_MODE and not include_untracked,
        "include_untracked": True if mode == SOURCE_PACKAGE_MODE else include_untracked,
        "changelog_mentions_plugin_version": changelog_state in {"released", "unreleased"},
        "changelog_release_state": changelog_state,
        "release_tag": tag,
        "release_tag_commit": tag_commit or "unknown",
        "release_tag_matches_head": (
            tag_commit == head_value if tag_commit is not None and head_value is not None else None
        ),
        "generated_at": reproducible_generated_at(),
        "file_count": len(files),
        "tree_sha256": content_sha256,
        "content_sha256": content_sha256,
        "files": entries,
    }


def release_blockers(
    root: GitRoot,
    *,
    mode: str,
    allow_dirty: bool,
    allow_head_mismatch: bool,
    index_errors: list[str] | None = None,
) -> list[str]:
    if mode == SOURCE_PACKAGE_MODE:
        return [] if plugin_version(root) != "unknown" else ["plugin_version_unknown"]
    if not in_git_checkout(root):
        return [
            "git_metadata_required_for_strict_export"
            if mode == STRICT_RELEASE_MODE
            else "git_metadata_required_for_worktree_export"
        ]
    blockers: list[str] = list(index_errors or [])
    status = git_status(root)
    if status is None:
        blockers.append("git_status_unavailable")
    elif status and not allow_dirty:
        blockers.append("working_tree_dirty")
    origin_status, origin = origin_main_provenance(root)
    head = git_commit(root)
    if head is None:
        blockers.append("git_head_unavailable")
    elif origin_status == "unavailable":
        blockers.append("origin_main_ref_status_unavailable")
    elif origin and head != origin and not allow_head_mismatch:
        blockers.append(f"head_mismatch_origin_main={head[:12]}!={origin[:12]}")
    version = plugin_version(root)
    if version == "unknown":
        blockers.append("plugin_version_unknown")
    elif mode == STRICT_RELEASE_MODE:
        state = changelog_release_state(root, version)
        if state == "unreleased":
            blockers.append(f"changelog_version_unreleased={version}")
        elif state != "released":
            blockers.append(f"changelog_release_heading_missing={version}")
        tag = release_tag(version)
        tag_commit = release_tag_commit(root, version)
        if tag_commit is None:
            blockers.append(f"release_tag_missing={tag}")
        elif head is not None and tag_commit != head:
            blockers.append(f"release_tag_head_mismatch={tag}")
    return blockers


def strict_source_blockers(
    root: GitRoot,
    manifest: dict[str, object],
    files: list[Path],
    payloads: dict[Path, bytes],
    modes: dict[Path, int],
    initial_index: dict[str, tuple[str, str, str]],
) -> list[str]:
    """Bind strict package bytes and modes to the exact release commit."""

    blockers: list[str] = []
    commit = manifest.get("git_commit")
    if not isinstance(commit, str) or re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit) is None:
        return ["strict_release_commit_invalid"]
    tree, tree_errors = git_tree_inventory(root, commit)
    blockers.extend(tree_errors)
    object_format = git_object_format(root)
    if object_format is None:
        blockers.append("git_object_format_unavailable")

    index_at_start = {
        path: (mode, oid)
        for path, (_tag, mode, oid) in initial_index.items()
    }
    if not tree_errors and index_at_start != tree:
        blockers.append("strict_index_not_release_commit")

    if not tree_errors and object_format is not None:
        root_path = _git_root_path(root)
        for path in files:
            rel = path.relative_to(root_path).as_posix()
            expected = tree.get(rel)
            if expected is None:
                blockers.append("strict_payload_not_release_commit")
                break
            expected_mode, expected_oid = expected
            package_mode = modes[path]
            normalized_expected_mode = 0o755 if expected_mode == "100755" else 0o644
            if package_mode != normalized_expected_mode:
                blockers.append("strict_payload_mode_not_release_commit")
                break
            if git_blob_oid(payloads[path], object_format) != expected_oid:
                blockers.append("strict_payload_not_release_commit")
                break
        blockers.extend(strict_worktree_blockers(root, tree, object_format))

    current_index, current_index_errors = git_index_inventory(root)
    blockers.extend(current_index_errors)
    if not current_index_errors and current_index != initial_index:
        blockers.append("git_index_changed_during_export")
    current_status = git_status(root)
    if current_status is None:
        blockers.append("git_status_unavailable_during_export")
    elif current_status:
        blockers.append("working_tree_changed_during_export")
    if git_commit(root) != commit:
        blockers.append("git_head_changed_during_export")
    version = manifest.get("plugin_version")
    if not isinstance(version, str) or release_tag_commit(root, version) != commit:
        blockers.append("git_release_tag_changed_during_export")
    return list(dict.fromkeys(blockers))


def strict_worktree_blockers(
    root: GitRoot,
    tree: dict[str, tuple[str, str]],
    object_format: str,
) -> list[str]:
    """Hash every tracked path, including sanitizer-excluded files, against HEAD."""

    if not isinstance(root, RepositoryRootAnchor):
        try:
            with open_repository_root_anchor(root) as anchor:
                return strict_worktree_blockers(anchor, tree, object_format)
        except (TypeError, ValueError):
            return ["strict_worktree_not_release_commit"]
    try:
        snapshot = snapshot_git_paths_from_anchor(
            root,
            tree.keys(),
            object_format=object_format,
            max_bytes=MAX_EXPORT_FILE_BYTES,
            max_total_bytes=MAX_EXPORT_PAYLOAD_BYTES,
            max_paths=MAX_MANIFEST_FILES,
        )
    except (TypeError, ValueError) as exc:
        if "limit" in str(exc) or "budget" in str(exc):
            return ["strict_worktree_verification_limit_exceeded"]
        return ["strict_worktree_not_release_commit"]
    entries = {entry["path"]: entry for entry in snapshot}
    for path, (expected_mode, expected_oid) in tree.items():
        entry = entries.get(path)
        if entry is None or entry.get("state") != "present":
            return ["strict_worktree_not_release_commit"]
        if entry.get("git_mode") != expected_mode:
            return ["strict_worktree_mode_not_release_commit"]
        if entry.get("git_blob_oid") != expected_oid:
            return ["strict_worktree_not_release_commit"]
    return []


def safe_worktree_clean(
    root: GitRoot,
    *,
    excluded_untracked: list[str] | tuple[str, ...] = (),
) -> bool | None:
    """Check index, raw tracked bytes, and untracked names without ``git status``.

    ``git status`` can execute repository-configured clean/process filters.  The
    release boundary instead compares no-exec plumbing inventories and hashes
    descriptor-opened worktree bytes directly.  Filtered or line-normalized
    repositories are conservatively reported dirty.
    """

    head = git_commit(root)
    if head is None:
        return None
    index, index_errors = git_index_inventory(root)
    tree, tree_errors = git_tree_inventory(root, head)
    object_format = git_object_format(root)
    if object_format is None:
        return None
    if index_errors or tree_errors:
        return False
    index_tree = {
        path: (mode, oid)
        for path, (_tag, mode, oid) in index.items()
    }
    if index_tree != tree:
        return False
    if strict_worktree_blockers(root, tree, object_format):
        return False
    untracked = run_git_paths(
        root,
        ["ls-files", "-z", "--others", "--exclude-standard"],
    )
    if untracked is None:
        return None
    excluded = set(excluded_untracked)
    return not any(path not in excluded for path in untracked)


def final_strict_release_blockers(
    root: GitRoot,
    manifest: dict[str, object],
    initial_index: dict[str, tuple[str, str, str]],
    transient_outputs: list[Path],
) -> list[str]:
    """Recheck mutable Git release evidence immediately before publication."""

    blockers: list[str] = []
    current_index, index_errors = git_index_inventory(root)
    blockers.extend(index_errors)
    if not index_errors and current_index != initial_index:
        blockers.append("git_index_changed_during_export")
    transient_relatives = [
        relative
        for candidate in transient_outputs
        if (
            relative := output_relative_path_by_identity(
                _git_root_path(root),
                candidate,
            )
        )
        is not None
    ]
    status = git_status_excluding(
        root,
        transient_relatives,
    )
    if status is None:
        blockers.append("git_status_unavailable_during_export")
    elif status:
        blockers.append("working_tree_changed_during_export")
    commit = manifest.get("git_commit")
    if not isinstance(commit, str) or git_commit(root) != commit:
        blockers.append("git_head_changed_during_export")
    version = manifest.get("plugin_version")
    if (
        not isinstance(version, str)
        or not isinstance(commit, str)
        or release_tag_commit(root, version) != commit
    ):
        blockers.append("git_release_tag_changed_during_export")
    origin_status, origin_commit = origin_main_provenance(root)
    if (
        origin_status != manifest.get("origin_main_ref_status")
        or (origin_commit or "unknown") != manifest.get("origin_main_commit")
        or ((commit == origin_commit) if origin_commit else None)
        != manifest.get("head_matches_origin_main")
    ):
        blockers.append("origin_main_changed_during_export")
    return list(dict.fromkeys(blockers))


def strict_manifest_blockers(manifest: dict[str, object]) -> list[str]:
    expected = {
        "export_mode": STRICT_RELEASE_MODE,
        "release_claim": True,
        "git_provenance_available": True,
        "source_inventory": "git_index",
        "working_tree_clean": True,
        "tracked_only": True,
        "include_untracked": False,
        "changelog_release_state": "released",
        "release_tag_matches_head": True,
    }
    blockers = [
        f"strict_release_manifest_provenance_incomplete={field}"
        for field, value in expected.items()
        if manifest.get(field) != value
    ]
    if manifest.get("git_commit") == "unknown":
        blockers.append("strict_release_manifest_provenance_incomplete=git_commit")
    if manifest.get("release_tag_commit") == "unknown":
        blockers.append("strict_release_manifest_provenance_incomplete=release_tag_commit")
    origin_status = manifest.get("origin_main_ref_status")
    if origin_status not in {"absent", "present"}:
        blockers.append("strict_release_manifest_provenance_incomplete=origin_main_ref_status")
    elif origin_status == "present" and manifest.get("head_matches_origin_main") is not True:
        blockers.append("strict_release_manifest_provenance_incomplete=head_matches_origin_main")
    return blockers


def _included_candidate_paths(
    anchor: RepositoryRootAnchor,
    paths: list[Path],
    output: Path,
    *,
    artifact_type: str = SOURCE_ARTIFACT,
) -> list[str]:
    root = anchor.path
    output_rel = output_relative_path_by_identity(root, output)
    output_key = portable_path_key(output_rel) if output_rel is not None else None
    included: list[str] = []
    for path in paths:
        try:
            rel = path.relative_to(root).as_posix()
            normalized = normalize_repo_relative_path(rel)
        except (TypeError, ValueError) as exc:
            raise ValueError("package_manifest_preflight_failed=path_not_portable") from exc
        if normalized != rel:
            raise ValueError("package_manifest_preflight_failed=path_not_portable")
        if package_secret_path_match_locations(rel):
            raise ValueError("secret_like_path")
        if output_key is not None and portable_path_key(rel) == output_key:
            continue
        if rel == PACKAGE_MANIFEST_NAME:
            continue
        artifact_rel = source_to_artifact_path(rel, artifact_type)
        if artifact_rel is None:
            continue
        if denied_path_reason(artifact_rel, artifact_type) is not None:
            continue
        included.append(rel)
        if len(included) > MAX_MANIFEST_FILES:
            raise ValueError("package_file_count_limit_exceeded")
    revalidate_repository_root_anchor(anchor)
    return included


def _payload_read_error(exc: ValueError) -> ValueError:
    message = str(exc)
    mappings = (
        ("repository_evidence_symlink_rejected=", "symlink_rejected="),
        ("repository_evidence_file_too_large=", "package_file_size_limit_exceeded="),
        (
            "repository_evidence_target_must_be_owner_controlled_regular_file=",
            "non_regular_file_rejected=",
        ),
        ("repository_evidence_target_unavailable=", "read_error="),
    )
    for prefix, replacement in mappings:
        if message.startswith(prefix):
            return ValueError(replacement + message.removeprefix(prefix))
    if message == "repository_evidence_total_bytes_exceeded":
        return ValueError("package_payload_size_limit_exceeded")
    if message == "repository_evidence_deadline_exceeded":
        return ValueError("package_source_read_deadline_exceeded")
    if message in {
        "repository_evidence_path_count_exceeded",
        "repository_evidence_path_read_budget_exceeded",
    }:
        return ValueError("package_file_count_limit_exceeded")
    return exc


def collect_anchored_payloads(
    anchor: RepositoryRootAnchor,
    paths: list[Path],
    output: Path,
    *,
    artifact_type: str = SOURCE_ARTIFACT,
) -> tuple[list[Path], dict[Path, bytes], dict[Path, int], dict[str, int]]:
    """Filter and read package payloads only through the opened root inode."""

    relatives = _included_candidate_paths(
        anchor,
        paths,
        output,
        artifact_type=artifact_type,
    )
    try:
        anchored_payloads = read_regular_files_from_anchor(
            anchor,
            relatives,
            max_bytes=MAX_EXPORT_FILE_BYTES,
            max_total_bytes=MAX_EXPORT_PAYLOAD_BYTES,
            max_paths=MAX_MANIFEST_FILES,
        )
    except ValueError as exc:
        raise _payload_read_error(exc) from exc

    files: list[Path] = []
    payloads: dict[Path, bytes] = {}
    modes: dict[Path, int] = {}
    for payload in anchored_payloads:
        path = anchor.path / payload.path
        if package_secret_path_match_locations(payload.path):
            raise ValueError("secret_like_path")
        if payload_is_zip_archive(payload.data):
            raise ValueError(f"package_nested_zip_rejected={payload.path}")
        if package_secret_match_locations(payload.data, path.suffix):
            raise ValueError("secret_like_content")
        files.append(path)
        payloads[path] = payload.data
        modes[path] = payload.mode
    counters = {
        "file_count": len(files),
        "payload_bytes": sum(len(payloads[path]) for path in files),
    }
    revalidate_repository_root_anchor(anchor)
    return files, payloads, modes, counters


def zip_file_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.extra = b""
    info.comment = b""
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def canonical_output_path(output: Path) -> tuple[Path, tuple[int, int]]:
    if output.name in {"", ".", ".."}:
        raise ValueError("output_filename_invalid")
    try:
        parent = output.parent.resolve(strict=True)
        metadata = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("output_parent_unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("output_parent_not_directory")
    return parent / output.name, (metadata.st_dev, metadata.st_ino)


def git_metadata_paths(root: GitRoot) -> tuple[list[Path], list[str]]:
    root_path = _git_root_path(root)
    git_dir_value = run_git_text(root, ["rev-parse", "--absolute-git-dir"])
    common_dir_value = run_git_text(root, ["rev-parse", "--git-common-dir"])
    if git_dir_value is None or common_dir_value is None:
        return [], ["git_metadata_path_unavailable"]
    paths: list[Path] = []
    for value in (git_dir_value, common_dir_value):
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root_path / candidate
        try:
            resolved = candidate.resolve(strict=True)
        except OSError:
            return [], ["git_metadata_path_unavailable"]
        if resolved not in paths:
            paths.append(resolved)
    return paths, []


def directory_identity_contains(parent: Path, child_parent: Path) -> bool | None:
    """Compare directory ancestry by inode so case aliases cannot bypass guards."""

    try:
        parent_metadata = os.stat(parent, follow_symlinks=False)
    except OSError:
        return None
    expected = (parent_metadata.st_dev, parent_metadata.st_ino)
    current = child_parent
    while True:
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError:
            return None
        if (metadata.st_dev, metadata.st_ino) == expected:
            return True
        if current.parent == current:
            return False
        current = current.parent


def output_relative_path_by_identity(root: Path, output: Path) -> str | None:
    """Derive a repo-relative output path without trusting path spelling/case."""

    try:
        root_metadata = os.stat(root, follow_symlinks=False)
    except OSError:
        return None
    expected = (root_metadata.st_dev, root_metadata.st_ino)
    components = [output.name]
    current = output.parent
    while True:
        try:
            metadata = os.stat(current, follow_symlinks=False)
        except OSError:
            return None
        if (metadata.st_dev, metadata.st_ino) == expected:
            return Path(*reversed(components)).as_posix()
        if current.parent == current:
            return None
        components.append(current.name)
        current = current.parent


def output_contract_blockers(
    root: GitRoot,
    output: Path,
    *,
    git_checkout: bool,
    index_inventory: dict[str, tuple[str, str, str]] | None,
    index_errors: list[str],
) -> list[str]:
    root_path = _git_root_path(root)
    blockers: list[str] = []
    if git_checkout:
        metadata_paths, metadata_errors = git_metadata_paths(root)
        blockers.extend(metadata_errors)
        for path in metadata_paths:
            identity_match = directory_identity_contains(path, output.parent)
            if identity_match is None:
                blockers.append("output_ancestor_identity_unavailable")
            elif identity_match:
                blockers.append("output_inside_git_metadata")
    output_rel = output_relative_path_by_identity(root_path, output)
    if output_rel is not None and git_checkout:
        inventory_unusable = any(
            error in {"git_index_inventory_unavailable", "git_index_inventory_malformed"}
            for error in index_errors
        )
        if inventory_unusable or index_inventory is None:
            blockers.append("git_index_inventory_required_for_output_safety")
        else:
            try:
                output_key = portable_path_key(output_rel)
                tracked_keys = {portable_path_key(path) for path in index_inventory}
            except (TypeError, UnicodeError):
                blockers.append("output_path_portability_unavailable")
            else:
                if output_key in tracked_keys:
                    blockers.append("output_collides_with_tracked_source")
                elif output.exists():
                    for tracked_path in index_inventory:
                        candidate = root_path / tracked_path
                        try:
                            if candidate.exists() and os.path.samefile(output, candidate):
                                blockers.append("output_collides_with_tracked_source")
                                break
                        except OSError:
                            blockers.append("output_source_identity_unavailable")
                            break
    if output.suffix.lower() != ".zip":
        blockers.append("output_must_have_zip_suffix")
    return list(dict.fromkeys(blockers))


def require_output_parent_identity(
    parent: Path,
    parent_descriptor: int,
    expected: tuple[int, int],
    mount_resolution: MountResolution | None = None,
) -> None:
    try:
        descriptor_metadata = os.fstat(parent_descriptor)
        path_metadata = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise ValueError("output_parent_identity_unavailable") from exc
    descriptor_identity = (descriptor_metadata.st_dev, descriptor_metadata.st_ino)
    path_identity = (path_metadata.st_dev, path_metadata.st_ino)
    if (
        not stat.S_ISDIR(descriptor_metadata.st_mode)
        or not stat.S_ISDIR(path_metadata.st_mode)
        or descriptor_identity != expected
        or path_identity != expected
    ):
        raise ValueError("output_parent_changed_during_export")
    if mount_resolution is None:
        return
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_output_primitives_unavailable")
    flags |= os.O_DIRECTORY | os.O_NOFOLLOW
    reopened_descriptor = -1
    try:
        reopened_descriptor = os.open(parent, flags)
        reopened_metadata = os.fstat(reopened_descriptor)
        if (
            not stat.S_ISDIR(reopened_metadata.st_mode)
            or (reopened_metadata.st_dev, reopened_metadata.st_ino) != expected
        ):
            raise ValueError("output_parent_changed_during_export")
        require_package_output_mount(mount_resolution, reopened_descriptor)
    except OSError as exc:
        raise ValueError("output_parent_changed_during_export") from exc
    finally:
        if reopened_descriptor >= 0:
            os.close(reopened_descriptor)


def require_package_output_mount(
    root_resolution: MountResolution,
    descriptor: int,
) -> None:
    try:
        require_same_mount(root_resolution, descriptor, ".")
    except MountIdentityError:
        raise
    except (TypeError, ValueError) as exc:
        raise ValueError("package_output_nested_mount_rejected") from exc


def require_existing_output_mount(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int, int, int, int] | None,
    root_resolution: MountResolution,
) -> None:
    if expected_identity is None:
        return
    descriptor = open_output_descriptor_at(parent_descriptor, name)
    try:
        if output_identity_from_metadata(os.fstat(descriptor)) != expected_identity:
            raise ValueError("output_target_changed_during_export")
        require_package_output_mount(root_resolution, descriptor)
    finally:
        os.close(descriptor)


def require_verified_published_output(
    parent_descriptor: int,
    name: str,
    expected_identity: tuple[int, int, int, int, int],
    root_resolution: MountResolution,
) -> None:
    descriptor = open_output_descriptor_at(parent_descriptor, name)
    try:
        require_package_output_mount(root_resolution, descriptor)
        if (
            output_identity_from_metadata(os.fstat(descriptor)) != expected_identity
            or output_identity_at(parent_descriptor, name) != expected_identity
        ):
            raise ValueError("package_publish_identity_mismatch")
        with os.fdopen(os.dup(descriptor), "rb", closefd=True) as published_file:
            verification_errors = verify_zip(published_file)
        if verification_errors:
            raise ValueError(
                "published_package_verification_failed="
                + ",".join(verification_errors)
            )
        if (
            output_identity_from_metadata(os.fstat(descriptor)) != expected_identity
            or output_identity_at(parent_descriptor, name) != expected_identity
        ):
            raise ValueError("package_publish_identity_mismatch")
    finally:
        os.close(descriptor)
    require_existing_output_mount(
        parent_descriptor,
        name,
        expected_identity,
        root_resolution,
    )


def output_identity_from_metadata(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    if stat.S_ISLNK(metadata.st_mode):
        raise ValueError("output_target_symlink_rejected")
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError("output_target_non_regular_rejected")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def initial_output_identity(output: Path) -> tuple[int, int, int, int, int] | None:
    try:
        metadata = os.lstat(output)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("output_target_unavailable") from exc
    return output_identity_from_metadata(metadata)


def output_identity_at(parent_descriptor: int, name: str) -> tuple[int, int, int, int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("output_target_unavailable") from exc
    return output_identity_from_metadata(metadata)


def raw_output_identity_at(
    parent_descriptor: int,
    name: str,
) -> tuple[int, int, int, int, int] | None:
    try:
        metadata = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ValueError("output_target_unavailable") from exc
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
    )


def open_output_descriptor_at(parent_descriptor: int, name: str) -> int:
    if any(not hasattr(os, flag) for flag in ("O_NOFOLLOW", "O_CLOEXEC")):
        raise ValueError("secure_output_primitives_unavailable")
    descriptor = -1
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=parent_descriptor,
        )
        output_identity_from_metadata(os.fstat(descriptor))
        return descriptor
    except (NotImplementedError, OSError, ValueError) as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise ValueError("published_output_open_failed") from exc


def create_output_backup(
    parent_descriptor: int,
    output_name: str,
    expected_identity: tuple[int, int, int, int, int],
) -> tuple[str, int]:
    """Create and pin a same-directory hard-link backup of an existing output."""

    for _attempt in range(128):
        backup_name = f".{output_name}.{secrets.token_hex(16)}.backup"
        try:
            os.link(
                output_name,
                backup_name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            continue
        except (NotImplementedError, OSError) as exc:
            raise ValueError("output_backup_create_failed") from exc
        descriptor = -1
        try:
            descriptor = open_output_descriptor_at(parent_descriptor, backup_name)
            if (
                output_identity_from_metadata(os.fstat(descriptor)) != expected_identity
                or output_identity_at(parent_descriptor, backup_name) != expected_identity
                or output_identity_at(parent_descriptor, output_name) != expected_identity
            ):
                raise ValueError("output_target_changed_during_export")
            return backup_name, descriptor
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                os.unlink(backup_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            raise
    raise ValueError("output_backup_name_exhausted")


def require_unchanged_output(
    parent_descriptor: int,
    name: str,
    expected: tuple[int, int, int, int, int] | None,
) -> None:
    current = output_identity_at(parent_descriptor, name)
    if expected is None and current is not None:
        raise ValueError("output_target_appeared_during_export")
    if expected is not None and current != expected:
        raise ValueError("output_target_changed_during_export")


def create_secure_package_temp(parent_descriptor: int, output_name: str) -> tuple[str, int]:
    required_flags = ("O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, flag) for flag in required_flags):
        raise ValueError("secure_output_primitives_unavailable")
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
    for _attempt in range(128):
        temp_name = f".{output_name}.{secrets.token_hex(16)}.tmp"
        try:
            descriptor = os.open(temp_name, flags, 0o600, dir_fd=parent_descriptor)
        except FileExistsError:
            continue
        except (NotImplementedError, OSError) as exc:
            raise ValueError("secure_output_temp_create_failed") from exc
        return temp_name, descriptor
    raise ValueError("secure_output_temp_name_exhausted")


def create_zip(
    root: Path,
    output: Path,
    *,
    include_untracked: bool = False,
    allow_dirty: bool = False,
    allow_head_mismatch: bool = False,
    source_package: bool = False,
    artifact_type: str = SOURCE_ARTIFACT,
) -> int:
    if artifact_type not in ARTIFACT_TYPES:
        raise ValueError("package_artifact_type_invalid")
    root = root.resolve()
    output, output_parent_identity = canonical_output_path(output)
    original_output_identity = initial_output_identity(output)
    mode = export_mode(
        source_package=source_package,
        include_untracked=include_untracked,
        allow_dirty=allow_dirty,
        allow_head_mismatch=allow_head_mismatch,
    )
    with open_repository_root_anchor(root) as anchor:
        count = _create_zip_from_anchor(
            anchor,
            output,
            output_parent_identity=output_parent_identity,
            original_output_identity=original_output_identity,
            mode=mode,
            include_untracked=include_untracked,
            allow_dirty=allow_dirty,
            allow_head_mismatch=allow_head_mismatch,
            artifact_type=artifact_type,
        )
        revalidate_repository_root_anchor(anchor)
        return count


def _create_zip_from_anchor(
    anchor: RepositoryRootAnchor,
    output: Path,
    *,
    output_parent_identity: tuple[int, int],
    original_output_identity: tuple[int, int, int, int, int] | None,
    mode: str,
    include_untracked: bool,
    allow_dirty: bool,
    allow_head_mismatch: bool,
    artifact_type: str,
) -> int:
    root = anchor.path
    require_mount_assurance(
        anchor.mount_resolution,
        NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION,
    )
    revalidate_repository_root_anchor(anchor)
    index_inventory: dict[str, tuple[str, str, str]] | None = None
    index_errors: list[str] = []
    git_checkout = in_git_checkout(anchor)
    if git_checkout:
        index_inventory, index_errors = git_index_inventory(anchor)
    output_blockers = output_contract_blockers(
        anchor,
        output,
        git_checkout=git_checkout,
        index_inventory=index_inventory,
        index_errors=index_errors,
    )
    if output_blockers:
        raise ValueError(";".join(output_blockers))
    blockers = release_blockers(
        anchor,
        mode=mode,
        allow_dirty=allow_dirty,
        allow_head_mismatch=allow_head_mismatch,
        index_errors=index_errors if mode != SOURCE_PACKAGE_MODE else None,
    )
    if blockers:
        raise ValueError(";".join(blockers))
    candidates = candidate_paths(
        anchor,
        include_untracked=include_untracked,
        mode=mode,
        index_inventory=index_inventory,
    )
    files, payloads, modes, counters = collect_anchored_payloads(
        anchor,
        candidates,
        output,
        artifact_type=artifact_type,
    )
    plugin_manifest_path = root / "plugins/codexqb/.codex-plugin/plugin.json"
    if plugin_manifest_path not in payloads:
        raise ValueError("package_plugin_manifest_missing")
    if artifact_type == PLUGIN_ARTIFACT:
        required_plugin_skill = root / f"plugins/codexqb/{PLUGIN_SKILL_PATH}"
        required_plugin_activation = root / f"plugins/codexqb/{PLUGIN_ACTIVATION_PATH}"
        runtime_contract_errors = [
            *plugin_skill_contract_errors(payloads.get(required_plugin_skill)),
            *plugin_activation_contract_errors(payloads.get(required_plugin_activation)),
        ]
        if runtime_contract_errors:
            raise ValueError(";".join(runtime_contract_errors))
    manifest = package_manifest(
        anchor,
        files,
        include_untracked=include_untracked,
        mode=mode,
        payloads=payloads,
        modes=modes,
        index_errors=index_errors,
        artifact_type=artifact_type,
    )
    if mode == STRICT_RELEASE_MODE:
        manifest_blockers = strict_manifest_blockers(manifest)
        if manifest_blockers:
            raise ValueError(";".join(manifest_blockers))
        if index_inventory is None:
            raise ValueError("git_index_inventory_unavailable")
        source_blockers = strict_source_blockers(
            anchor,
            manifest,
            files,
            payloads,
            modes,
            index_inventory,
        )
        if source_blockers:
            raise ValueError(";".join(source_blockers))
    _validated_entries, manifest_entry_errors = manifest_entries(manifest)
    manifest_errors = [*manifest_entry_errors, *manifest_contract_errors(manifest)]
    if manifest_errors:
        raise ValueError("package_manifest_preflight_failed=" + ",".join(manifest_errors))
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError("package_manifest_size_limit_exceeded")
    if package_secret_match_locations(manifest_bytes, ".json"):
        raise ValueError("secret_like_manifest")
    if counters["payload_bytes"] + len(manifest_bytes) > MAX_PACKAGE_UNCOMPRESSED_BYTES:
        raise ValueError("package_uncompressed_size_limit_exceeded")
    if len(files) + 1 > MAX_CANONICAL_ZIP_MEMBERS:
        raise ValueError("package_zip_member_count_limit_exceeded")

    parent_flags = os.O_RDONLY
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("secure_output_primitives_unavailable")
    parent_flags |= os.O_DIRECTORY | os.O_NOFOLLOW
    try:
        parent_descriptor = os.open(output.parent, parent_flags)
    except OSError as exc:
        raise ValueError("output_parent_open_failed") from exc
    temp_name: str | None = None
    temp_descriptor = -1
    package_file = None
    published_descriptor = -1
    backup_name: str | None = None
    backup_descriptor = -1
    preserve_backup_on_failure = False
    primary_error: BaseException | None = None
    try:
        output_parent_mount_resolution = resolve_mount_identity(
            parent_descriptor,
            reconcile=True,
        )
        require_mount_assurance(
            output_parent_mount_resolution,
            NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION,
        )
        require_package_output_mount(
            output_parent_mount_resolution,
            parent_descriptor,
        )
        revalidate_repository_root_anchor(anchor)
        require_output_parent_identity(
            output.parent,
            parent_descriptor,
            output_parent_identity,
            output_parent_mount_resolution,
        )
        require_unchanged_output(parent_descriptor, output.name, original_output_identity)
        require_existing_output_mount(
            parent_descriptor,
            output.name,
            original_output_identity,
            output_parent_mount_resolution,
        )
        temp_name, temp_descriptor = create_secure_package_temp(parent_descriptor, output.name)
        require_package_output_mount(
            output_parent_mount_resolution,
            temp_descriptor,
        )
        package_file = os.fdopen(temp_descriptor, "w+b", closefd=True)
        temp_descriptor = -1
        prefix = archive_prefix(artifact_type)
        archive_items = sorted(
            (
                source_to_artifact_path(path.relative_to(root).as_posix(), artifact_type),
                path,
            )
            for path in files
        )
        with zipfile.ZipFile(package_file, "w", compression=zipfile.ZIP_STORED) as archive:
            for rel, path in archive_items:
                if rel is None:
                    raise ValueError("package_artifact_path_unmapped")
                archive.writestr(
                    zip_file_info(f"{prefix}{rel}", modes[path]),
                    payloads[path],
                )
            archive.writestr(
                zip_file_info(f"{prefix}{PACKAGE_MANIFEST_NAME}", 0o644),
                manifest_bytes,
            )
        package_file.flush()
        os.fchmod(package_file.fileno(), 0o644)
        os.fsync(package_file.fileno())
        package_file.seek(0)
        verification_errors = verify_zip(package_file)
        if verification_errors:
            raise ValueError(
                "package_verification_failed=" + ",".join(verification_errors)
            )
        verified_temp_identity = output_identity_from_metadata(
            os.fstat(package_file.fileno())
        )
        if original_output_identity is not None:
            require_unchanged_output(
                parent_descriptor,
                output.name,
                original_output_identity,
            )
            backup_name, backup_descriptor = create_output_backup(
                parent_descriptor,
                output.name,
                original_output_identity,
            )
            require_package_output_mount(
                output_parent_mount_resolution,
                backup_descriptor,
            )
        if mode == STRICT_RELEASE_MODE:
            if index_inventory is None:
                raise ValueError("git_index_inventory_unavailable")
            final_release_blockers = final_strict_release_blockers(
                anchor,
                manifest,
                index_inventory,
                [
                    output.parent / temp_name,
                    *([output.parent / backup_name] if backup_name is not None else []),
                ],
            )
            if final_release_blockers:
                raise ValueError(";".join(final_release_blockers))
        revalidate_repository_root_anchor(anchor)
        require_output_parent_identity(
            output.parent,
            parent_descriptor,
            output_parent_identity,
            output_parent_mount_resolution,
        )
        require_unchanged_output(parent_descriptor, output.name, original_output_identity)
        if output_identity_at(parent_descriptor, temp_name) != verified_temp_identity:
            raise ValueError("package_temp_changed_during_export")
        require_existing_output_mount(
            parent_descriptor,
            temp_name,
            verified_temp_identity,
            output_parent_mount_resolution,
        )
        publication_attempted = False
        published_raw_identity: tuple[int, int, int, int, int] | None = None
        try:
            publication_attempted = True
            try:
                os.replace(
                    temp_name,
                    output.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
            except (NotImplementedError, OSError) as exc:
                raise ValueError("atomic_output_publish_failed") from exc
            temp_name = None
            revalidate_repository_root_anchor(anchor)
            require_output_parent_identity(
                output.parent,
                parent_descriptor,
                output_parent_identity,
                output_parent_mount_resolution,
            )
            published_raw_identity = raw_output_identity_at(
                parent_descriptor,
                output.name,
            )
            published_descriptor = open_output_descriptor_at(parent_descriptor, output.name)
            require_package_output_mount(
                output_parent_mount_resolution,
                published_descriptor,
            )
            published_identity = output_identity_from_metadata(
                os.fstat(published_descriptor)
            )
            path_identity = output_identity_at(parent_descriptor, output.name)
            open_temp_identity = output_identity_from_metadata(
                os.fstat(package_file.fileno())
            )
            if not (
                published_identity == verified_temp_identity
                and path_identity == verified_temp_identity
                and open_temp_identity == verified_temp_identity
            ):
                raise ValueError("package_publish_identity_mismatch")
            with os.fdopen(os.dup(published_descriptor), "rb", closefd=True) as published_file:
                published_verification_errors = verify_zip(published_file)
            if published_verification_errors:
                raise ValueError(
                    "published_package_verification_failed="
                    + ",".join(published_verification_errors)
                )
            post_verification_identity = output_identity_from_metadata(
                os.fstat(published_descriptor)
            )
            if (
                post_verification_identity != verified_temp_identity
                or output_identity_at(parent_descriptor, output.name) != verified_temp_identity
            ):
                raise ValueError("package_publish_identity_mismatch")
            try:
                os.fsync(parent_descriptor)
            except OSError as exc:
                raise RuntimeError("package_publish_commit_state_unknown") from exc
            if output_identity_at(parent_descriptor, output.name) != verified_temp_identity:
                raise ValueError("package_publish_identity_mismatch")
            revalidate_repository_root_anchor(anchor)
            require_output_parent_identity(
                output.parent,
                parent_descriptor,
                output_parent_identity,
                output_parent_mount_resolution,
            )
            require_verified_published_output(
                parent_descriptor,
                output.name,
                verified_temp_identity,
                output_parent_mount_resolution,
            )
            revalidate_repository_root_anchor(anchor)
            require_output_parent_identity(
                output.parent,
                parent_descriptor,
                output_parent_identity,
                output_parent_mount_resolution,
            )
            require_verified_published_output(
                parent_descriptor,
                output.name,
                verified_temp_identity,
                output_parent_mount_resolution,
            )
        except BaseException as publication_error:
            if publication_attempted:
                try:
                    current_raw_identity = raw_output_identity_at(
                        parent_descriptor,
                        output.name,
                    )
                    if (
                        published_raw_identity is None
                        and current_raw_identity != original_output_identity
                    ):
                        published_raw_identity = current_raw_identity
                    if original_output_identity is None:
                        if current_raw_identity is not None:
                            if (
                                published_raw_identity is None
                                or current_raw_identity != published_raw_identity
                            ):
                                raise ValueError("published_output_changed_before_rollback")
                            require_existing_output_mount(
                                parent_descriptor,
                                output.name,
                                published_raw_identity,
                                output_parent_mount_resolution,
                            )
                            os.unlink(output.name, dir_fd=parent_descriptor)
                    elif current_raw_identity != original_output_identity:
                        if (
                            backup_name is None
                            or backup_descriptor < 0
                            or published_raw_identity is None
                            or current_raw_identity != published_raw_identity
                            or output_identity_at(parent_descriptor, backup_name)
                            != original_output_identity
                            or output_identity_from_metadata(os.fstat(backup_descriptor))
                            != original_output_identity
                        ):
                            raise ValueError("output_backup_changed_before_rollback")
                        require_existing_output_mount(
                            parent_descriptor,
                            output.name,
                            published_raw_identity,
                            output_parent_mount_resolution,
                        )
                        require_existing_output_mount(
                            parent_descriptor,
                            backup_name,
                            original_output_identity,
                            output_parent_mount_resolution,
                        )
                        os.replace(
                            backup_name,
                            output.name,
                            src_dir_fd=parent_descriptor,
                            dst_dir_fd=parent_descriptor,
                        )
                        backup_name = None
                        if (
                            output_identity_at(parent_descriptor, output.name)
                            != original_output_identity
                        ):
                            raise ValueError("output_rollback_identity_mismatch")
                        require_existing_output_mount(
                            parent_descriptor,
                            output.name,
                            original_output_identity,
                            output_parent_mount_resolution,
                        )
                    os.fsync(parent_descriptor)
                except BaseException:
                    if backup_name is not None:
                        preserve_backup_on_failure = True
                    raise RuntimeError("package_publish_rollback_failed") from publication_error
            raise
        if backup_name is not None:
            preserve_backup_on_failure = True
            try:
                if (
                    backup_descriptor < 0
                    or output_identity_at(parent_descriptor, backup_name)
                    != original_output_identity
                    or output_identity_from_metadata(os.fstat(backup_descriptor))
                    != original_output_identity
                ):
                    raise ValueError("output_backup_changed_before_cleanup")
                require_existing_output_mount(
                    parent_descriptor,
                    backup_name,
                    original_output_identity,
                    output_parent_mount_resolution,
                )
                os.unlink(backup_name, dir_fd=parent_descriptor)
                backup_name = None
                os.fsync(parent_descriptor)
            except BaseException as exc:
                raise RuntimeError("package_backup_cleanup_state_unknown") from exc
            preserve_backup_on_failure = False
    except BaseException as exc:
        primary_error = exc
        raise
    finally:
        cleanup_error: RuntimeError | None = None
        if backup_descriptor >= 0:
            os.close(backup_descriptor)
        if published_descriptor >= 0:
            os.close(published_descriptor)
        if package_file is not None:
            package_file.close()
        if temp_descriptor >= 0:
            os.close(temp_descriptor)
        if temp_name is not None:
            try:
                os.unlink(temp_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                cleanup_error = RuntimeError("package_temp_cleanup_state_unknown")
        if backup_name is not None and not preserve_backup_on_failure:
            try:
                os.unlink(backup_name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            except OSError:
                if cleanup_error is None:
                    cleanup_error = RuntimeError("package_backup_cleanup_state_unknown")
        os.close(parent_descriptor)
        if cleanup_error is not None:
            if primary_error is None:
                raise cleanup_error
            if primary_error.__cause__ is None:
                primary_error.__cause__ = cleanup_error
    return len(files)


def safe_export_failure_code(exc: BaseException) -> str:
    value = str(exc).partition("=")[0]
    if len(value) <= 80 and SAFE_EXPORT_FAILURE_CODE_RE.fullmatch(value):
        return value
    return "sanitized_export_failed"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Create a reproducible CodexQB plugin or source package."
    )
    parser.add_argument("--root", default=".")
    parser.add_argument("--output")
    parser.add_argument(
        "--artifact-type",
        choices=sorted(ARTIFACT_TYPES),
        default=SOURCE_ARTIFACT,
        help="Create an installable plugin-root artifact or a full source artifact.",
    )
    parser.add_argument(
        "--provenance-mode",
        choices=("strict-release", "worktree", "filesystem"),
        help="Explicit provenance policy; legacy flags remain available for compatibility.",
    )
    parser.add_argument(
        "--include-untracked",
        action="store_true",
        help="Include untracked, non-ignored files after symlink and secret scanning.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow a dirty Git worktree. Intended only for explicit worktree exports.",
    )
    parser.add_argument(
        "--allow-head-mismatch",
        action="store_true",
        help="Allow HEAD to differ from refs/remotes/origin/main when that ref is available.",
    )
    parser.add_argument(
        "--source-package",
        action="store_true",
        help="Export an extracted/Gitless source tree as a non-release filesystem package.",
    )
    args = parser.parse_args(argv)
    if args.provenance_mode is not None and any(
        (
            args.include_untracked,
            args.allow_dirty,
            args.allow_head_mismatch,
            args.source_package,
        )
    ):
        parser.error("--provenance-mode conflicts with legacy mode flags")
    if args.source_package and args.artifact_type != SOURCE_ARTIFACT:
        parser.error("legacy --source-package is valid only for a source artifact")
    include_untracked = args.include_untracked
    allow_dirty = args.allow_dirty
    allow_head_mismatch = args.allow_head_mismatch
    source_package = args.source_package
    if args.provenance_mode == "worktree":
        include_untracked = True
        allow_dirty = True
        allow_head_mismatch = True
    elif args.provenance_mode == "filesystem":
        source_package = True
    try:
        mode = export_mode(
            source_package=source_package,
            include_untracked=include_untracked,
            allow_dirty=allow_dirty,
            allow_head_mismatch=allow_head_mismatch,
        )
        root = Path(args.root)
        output = Path(args.output) if args.output else Path(
            default_artifact_filename(args.artifact_type, plugin_version(root), mode)
        )
        count = create_zip(
            root,
            output,
            include_untracked=include_untracked,
            allow_dirty=allow_dirty,
            allow_head_mismatch=allow_head_mismatch,
            source_package=source_package,
            artifact_type=args.artifact_type,
        )
    except Exception as exc:
        print("sanitized_export=failed")
        print(f"error_code={safe_export_failure_code(exc)}")
        return 1
    print(f"sanitized_export=created")
    print(f"artifact_type={args.artifact_type}")
    print(f"export_mode={mode}")
    print(f"file_count={count}")
    print("output=created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
