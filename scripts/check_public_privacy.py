#!/usr/bin/env python3
"""Scan local-path and machine-identifier metadata without disclosing paths.

Current public documentation is scanned alongside every regular blob reachable
from public Git refs. Credential/package-secret hygiene is a separate package
scanner contract and is intentionally not claimed by this metadata policy.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time


SAFETY_DIR = Path(__file__).resolve().parents[1] / "plugins/codexqb/skills/codexqb/scripts"
if str(SAFETY_DIR) not in sys.path:
    sys.path.insert(0, str(SAFETY_DIR))

from git_evidence import capture_git_workspace_evidence, trusted_git_executable  # noqa: E402
from safety_contracts import (  # noqa: E402
    PACKAGE_SECRET_PATH_RULE_NAMES,
    package_secret_path_match_locations,
)
from repository_evidence import (  # noqa: E402
    open_repository_root_anchor,
    read_regular_files_from_anchor,
    snapshot_allowed_paths,
)


PUBLIC_FILES = {
    "README.md",
    "CHANGELOG.md",
    "docs/USAGE.md",
    "docs/MAINTAINING.md",
    "docs/INSTALLATION.md",
    "docs/FEEDBACK-CLOSURE-AUDIT.md",
    "docs/history-privacy-baseline.json",
    "docs/revision/CODEXQB-0.3-RELEASE-FOUNDATION.md",
}
PUBLIC_DIRS = {
    "docs/release-audits",
    "docs/release-evidence",
    "docs/superpowers/plans",
}
PRIVATE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("mac_user_path", re.compile(r"/" + r"Users/")),
    ("linux_home_path", re.compile(r"/" + r"home/")),
    ("private_tmp_path", re.compile(r"/private/(?:tmp|var)/")),
    ("codex_attachment_path", re.compile(re.escape(".codex") + r"/" + r"attachments/")),
    ("windows_user_path", re.compile(r"[A-Za-z]:\\Users\\")),
    (
        "local_uuid",
        re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"),
    ),
    ("codex_live_agent_id", re.compile(r"\b019e[a-f0-9]{28}\b")),
)
OPAQUE_BINARY_EXCLUDED_RULES = frozenset({"local_uuid"})
BASELINE_RELATIVE_PATH = "docs/history-privacy-baseline.json"
SHA256_RE = re.compile(r"[a-f0-9]{64}")
MAX_HISTORY_COMMITS = 10_000
MAX_HISTORY_TREE_ENTRIES = 1_000_000
MAX_HISTORY_BLOBS = 100_000
MAX_HISTORY_BLOB_BYTES = 64 * 1024 * 1024
MAX_HISTORY_TOTAL_BYTES = 512 * 1024 * 1024
MAX_HISTORY_FINDINGS = 10_000
MAX_HISTORY_PATH_BYTES = 4_096
MAX_COMMIT_PARENT_HEADERS = 10_000
HISTORY_DEADLINE_SECONDS = 60
MAX_CURRENT_PATHS = 4_096
MAX_CURRENT_FILE_BYTES = 64 * 1024 * 1024
MAX_CURRENT_TOTAL_BYTES = 512 * 1024 * 1024
MAX_CURRENT_FINDINGS = 10_000
MAX_CURRENT_PATH_BYTES = 4_096
CURRENT_DEADLINE_SECONDS = 60
MAX_ANNOTATED_TAG_DEPTH = 64
MAX_GIT_OUTPUT_BYTES = 64 * 1024 * 1024
SCAN_POLICY_NAME = "public_metadata_privacy_v1"
PUBLIC_METADATA_TEXT_SUFFIXES = frozenset(
    {
        ".cfg",
        ".conf",
        ".css",
        ".csv",
        ".html",
        ".ini",
        ".js",
        ".json",
        ".jsx",
        ".lock",
        ".md",
        ".py",
        ".rst",
        ".sh",
        ".sql",
        ".toml",
        ".ts",
        ".tsv",
        ".tsx",
        ".txt",
        ".xml",
        ".yaml",
        ".yml",
    }
)
PUBLIC_METADATA_TEXT_NAMES = frozenset(
    {".editorconfig", ".gitattributes", ".gitignore", "LICENSE", "Makefile", "NOTICE"}
)


class PrivacyScanError(ValueError):
    """One stable, content-free privacy scanner failure."""


def _require_history_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise PrivacyScanError("history_scan_deadline_exceeded")


def _require_current_deadline(deadline: float | None) -> None:
    if deadline is not None and time.monotonic() >= deadline:
        raise PrivacyScanError("current_scan_deadline_exceeded")


def git_tracked(root: Path) -> set[str] | None:
    try:
        evidence = capture_git_workspace_evidence(root)
    except (OSError, ValueError):
        return None
    if evidence.get("is_git") is not True:
        return None
    return {str(path) for path in evidence.get("tracked_paths", []) if isinstance(path, str)}


def is_public_path(relative: str) -> bool:
    return relative in PUBLIC_FILES or any(
        relative.startswith(directory + "/") for directory in PUBLIC_DIRS
    )


def history_path_is_in_scope(relative: str) -> bool:
    """Cover every non-empty path reachable from a selected public ref."""

    return bool(relative)


def candidate_files(root: Path, *, deadline: float | None = None) -> list[Path]:
    """Return one fixed-budget inventory of current public regular files."""

    candidates: set[Path] = set()
    entries_seen = 0

    def consume_entry() -> None:
        nonlocal entries_seen
        _require_current_deadline(deadline)
        entries_seen += 1
        if entries_seen > MAX_CURRENT_PATHS:
            raise PrivacyScanError("current_scan_path_limit_exceeded")

    for rel in PUBLIC_FILES:
        _require_current_deadline(deadline)
        path = root / rel
        if os.path.lexists(path):
            consume_entry()
            candidates.add(path)
    for rel_dir in PUBLIC_DIRS:
        _require_current_deadline(deadline)
        base = root / rel_dir
        if base.is_symlink():
            raise PrivacyScanError("current_scan_file_unavailable")
        if not base.is_dir():
            continue
        pending = [base]
        while pending:
            _require_current_deadline(deadline)
            directory = pending.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = []
                    for entry in iterator:
                        consume_entry()
                        entries.append(entry)
            except OSError as exc:
                raise PrivacyScanError("current_scan_file_unavailable") from exc
            for entry in sorted(entries, key=lambda item: item.name):
                _require_current_deadline(deadline)
                try:
                    if entry.is_symlink():
                        raise PrivacyScanError("current_scan_file_unavailable")
                    if entry.is_dir(follow_symlinks=False):
                        pending.append(Path(entry.path))
                    elif entry.is_file(follow_symlinks=False):
                        candidates.add(Path(entry.path))
                    else:
                        raise PrivacyScanError("current_scan_file_unavailable")
                except OSError as exc:
                    raise PrivacyScanError("current_scan_file_unavailable") from exc
    _require_current_deadline(deadline)
    return sorted(candidates)


def _uses_known_text_policy(relative: str) -> bool:
    name = relative.rsplit("/", 1)[-1]
    return name in PUBLIC_METADATA_TEXT_NAMES or Path(name).suffix.casefold() in PUBLIC_METADATA_TEXT_SUFFIXES


def scan_bytes(
    data: bytes,
    relative: str,
    *,
    deadline: float | None = None,
    deadline_error: str = "history_scan_deadline_exceeded",
    finding_limit: int = MAX_HISTORY_FINDINGS,
    finding_limit_error: str = "history_scan_finding_limit_exceeded",
) -> list[tuple[str, int]]:
    """Scan metadata without treating undecodable binary payloads as text errors."""

    def require_deadline() -> None:
        if deadline_error == "current_scan_deadline_exceeded":
            _require_current_deadline(deadline)
        else:
            _require_history_deadline(deadline)

    require_deadline()
    if _uses_known_text_policy(relative):
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return [("public_text_invalid_utf8", 0)]
        patterns = PRIVATE_PATTERNS
    else:
        # Latin-1 is a byte-preserving projection. ASCII metadata tokens remain
        # contiguous and detectable without decoding binary bytes permissively.
        # A context-free UUID is excluded for opaque binary payloads because
        # format/container UUIDs are not evidence of local-machine metadata.
        text = data.decode("latin-1")
        patterns = tuple(
            item for item in PRIVATE_PATTERNS if item[0] not in OPAQUE_BINARY_EXCLUDED_RULES
        )
    require_deadline()
    findings: list[tuple[str, int]] = []
    for line_number, line in enumerate(io.StringIO(text), start=1):
        for rule, pattern in patterns:
            if pattern.search(line):
                if len(findings) >= finding_limit:
                    raise PrivacyScanError(finding_limit_error)
                findings.append((rule, line_number))
        require_deadline()
    return findings


def current_findings(root: Path) -> tuple[list[dict[str, object]], int]:
    deadline = time.monotonic() + CURRENT_DEADLINE_SECONDS
    findings: list[dict[str, object]] = []
    files = candidate_files(root, deadline=deadline)
    relatives: list[str] = []
    for path in files:
        _require_current_deadline(deadline)
        relative = path.relative_to(root).as_posix()
        try:
            encoded_relative = relative.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PrivacyScanError("current_scan_path_invalid_utf8") from exc
        if len(encoded_relative) > MAX_CURRENT_PATH_BYTES:
            raise PrivacyScanError("current_scan_path_bytes_exceeded")
        relatives.append(relative)
    try:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PrivacyScanError("current_scan_deadline_exceeded")
        with open_repository_root_anchor(root) as anchor:
            payloads = read_regular_files_from_anchor(
                anchor,
                relatives,
                max_bytes=MAX_CURRENT_FILE_BYTES,
                max_total_bytes=MAX_CURRENT_TOTAL_BYTES,
                max_paths=MAX_CURRENT_PATHS,
                timeout_seconds=remaining,
            )
    except PrivacyScanError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        if str(exc) == "repository_evidence_deadline_exceeded":
            raise PrivacyScanError("current_scan_deadline_exceeded") from exc
        raise PrivacyScanError("current_scan_file_unavailable") from exc
    _require_current_deadline(deadline)
    if [payload.path for payload in payloads] != relatives:
        raise PrivacyScanError("current_scan_inventory_changed")
    for payload in payloads:
        _require_current_deadline(deadline)
        path_rules = {
            rule
            for rule, _line in scan_bytes(
                payload.path.encode("utf-8"),
                "repository-current-path.txt",
                deadline=deadline,
                deadline_error="current_scan_deadline_exceeded",
                finding_limit=MAX_CURRENT_FINDINGS,
                finding_limit_error="current_scan_finding_limit_exceeded",
            )
        }
        path_rules.update(
            rule for rule, _offset in package_secret_path_match_locations(payload.path)
        )
        path_sha256 = hashlib.sha256(payload.path.encode("utf-8")).hexdigest()
        for rule in sorted(path_rules):
            if len(findings) >= MAX_CURRENT_FINDINGS:
                raise PrivacyScanError("current_scan_finding_limit_exceeded")
            findings.append(
                {
                    "scope": "current",
                    "path_sha256": path_sha256,
                    "line": 0,
                    "rule": rule,
                }
            )
        for rule, line_number in scan_bytes(
            payload.data,
            payload.path,
            deadline=deadline,
            deadline_error="current_scan_deadline_exceeded",
            finding_limit=MAX_CURRENT_FINDINGS,
            finding_limit_error="current_scan_finding_limit_exceeded",
        ):
            if len(findings) >= MAX_CURRENT_FINDINGS:
                raise PrivacyScanError("current_scan_finding_limit_exceeded")
            findings.append(
                {
                    "scope": "current",
                    "path_sha256": path_sha256,
                    "line": line_number,
                    "rule": rule,
                }
            )
    _require_current_deadline(deadline)
    return findings, len(files)


def _git_environment() -> dict[str, str]:
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_NO_LAZY_FETCH": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.defpath,
        }
    )
    return environment


def _terminate(process: subprocess.Popen[bytes]) -> None:
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        elif process.poll() is None:
            process.kill()
    except (OSError, ProcessLookupError):
        pass


def _run_git(
    root: Path,
    args: list[str],
    *,
    deadline: float,
    maximum_output: int = MAX_GIT_OUTPUT_BYTES,
) -> bytes:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise PrivacyScanError("history_scan_deadline_exceeded")
    command = [
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
    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            env=_git_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=os.name == "posix",
        )
    except (OSError, ValueError) as exc:
        raise PrivacyScanError("history_scan_git_unavailable") from exc
    output = bytearray()
    selector: selectors.BaseSelector | None = None
    try:
        if process.stdout is None:
            raise PrivacyScanError("history_scan_git_unavailable")
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise PrivacyScanError("history_scan_deadline_exceeded")
            for key, _ in selector.select(min(0.1, remaining)):
                chunk = os.read(key.fileobj.fileno(), min(64 * 1024, maximum_output - len(output) + 1))
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output.extend(chunk)
                if len(output) > maximum_output:
                    raise PrivacyScanError("history_scan_git_output_limit_exceeded")
        try:
            return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise PrivacyScanError("history_scan_deadline_exceeded") from exc
        if return_code != 0:
            raise PrivacyScanError("history_scan_git_command_failed")
        return bytes(output)
    except BaseException:
        _terminate(process)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _terminate(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        if process.stdout is not None and not process.stdout.closed:
            process.stdout.close()


def _nul_records(data: bytes) -> list[bytes]:
    return list(_iter_nul_records(data))


def _nul_fields(data: bytes) -> list[bytes]:
    """Split a bounded NUL field stream while preserving empty fields."""

    if data and not data.endswith(b"\0"):
        raise PrivacyScanError("history_scan_git_output_malformed")
    return data.split(b"\0")[:-1] if data else []


def _iter_nul_records(data: bytes):
    """Yield NUL-delimited records without allocating a second full record list."""

    if data and not data.endswith(b"\0"):
        raise PrivacyScanError("history_scan_git_output_malformed")
    start = 0
    while start < len(data):
        end = data.find(b"\0", start)
        if end < 0:
            raise PrivacyScanError("history_scan_git_output_malformed")
        if end > start:
            yield data[start:end]
        start = end + 1


def _exact_git_root(root: Path, deadline: float) -> bool:
    try:
        value = _run_git(root, ["rev-parse", "--show-toplevel"], deadline=deadline, maximum_output=8192)
        return Path(os.fsdecode(value).strip()).resolve(strict=True) == root
    except PrivacyScanError as exc:
        if str(exc) == "history_scan_git_command_failed":
            return False
        raise
    except (OSError, ValueError):
        return False


def _public_ref_oids(root: Path, deadline: float) -> list[str]:
    head = _run_git(
        root,
        ["rev-parse", "HEAD"],
        deadline=deadline,
        maximum_output=128,
    ).strip()
    raw = _run_git(
        root,
        [
            "for-each-ref",
            "--format=%(objectname)%00%(refname)%00%(symref)%00",
            "refs/remotes/origin",
            "refs/tags",
        ],
        deadline=deadline,
        maximum_output=4 * 1024 * 1024,
    )
    records = _nul_fields(raw.replace(b"\n", b""))
    if len(records) % 3:
        raise PrivacyScanError("history_scan_ref_inventory_malformed")
    if len(records) // 3 > MAX_HISTORY_COMMITS:
        raise PrivacyScanError("history_scan_public_ref_limit_exceeded")
    try:
        head_oid = head.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PrivacyScanError("history_scan_ref_inventory_malformed") from exc
    if not re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", head_oid):
        raise PrivacyScanError("history_scan_ref_inventory_malformed")
    symbolic_head = _run_git(
        root,
        ["rev-parse", "--symbolic-full-name", "HEAD"],
        deadline=deadline,
        maximum_output=4096,
    ).strip()
    try:
        symbolic_head_name = symbolic_head.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PrivacyScanError("history_scan_ref_metadata_invalid_utf8") from exc
    _reject_unsafe_ref_metadata(symbolic_head_name, deadline)
    oids: list[str] = [head_oid]
    for index in range(0, len(records), 3):
        oid_bytes, ref_bytes, symref_bytes = records[index : index + 3]
        try:
            oid = oid_bytes.decode("ascii")
            ref_name = ref_bytes.decode("utf-8")
            symref_name = symref_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrivacyScanError("history_scan_ref_metadata_invalid_utf8") from exc
        if not re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", oid):
            raise PrivacyScanError("history_scan_ref_inventory_malformed")
        if not ref_name.startswith(("refs/remotes/origin/", "refs/tags/")):
            raise PrivacyScanError("history_scan_ref_inventory_malformed")
        _reject_unsafe_ref_metadata(ref_name, deadline)
        if symref_name:
            _reject_unsafe_ref_metadata(symref_name, deadline)
        if ref_name == "refs/remotes/origin/HEAD":
            continue
        oids.append(oid)
    if not oids:
        raise PrivacyScanError("history_scan_public_refs_missing")
    return sorted(set(oids))


def _reject_unsafe_ref_metadata(ref_name: str, deadline: float) -> None:
    _require_history_deadline(deadline)
    if scan_bytes(
        ref_name.encode("utf-8"),
        "repository-ref-name.txt",
        deadline=deadline,
    ) or package_secret_path_match_locations(ref_name):
        raise PrivacyScanError("history_scan_ref_metadata_rejected")
    _require_history_deadline(deadline)


def _annotated_tag_payloads(
    root: Path,
    ref_oids: list[str],
    deadline: float,
) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    total_bytes = 0
    for ref_oid in ref_oids:
        current = ref_oid
        for _depth in range(MAX_ANNOTATED_TAG_DEPTH + 1):
            _require_history_deadline(deadline)
            object_type = _run_git(
                root,
                ["cat-file", "-t", current],
                deadline=deadline,
                maximum_output=64,
            ).strip()
            if object_type != b"tag":
                break
            if current in payloads:
                break
            if len(payloads) >= MAX_HISTORY_COMMITS:
                raise PrivacyScanError("history_scan_tag_limit_exceeded")
            data = _run_git(
                root,
                ["cat-file", "tag", current],
                deadline=deadline,
                maximum_output=MAX_HISTORY_BLOB_BYTES,
            )
            total_bytes += len(data)
            if total_bytes > MAX_HISTORY_TOTAL_BYTES:
                raise PrivacyScanError("history_scan_total_bytes_exceeded")
            target = _tag_target_oid(data)
            payloads[current] = data
            current = target
        else:
            raise PrivacyScanError("history_scan_tag_depth_exceeded")
    _require_history_deadline(deadline)
    return payloads


def _tag_target_oid(data: bytes) -> str:
    first_line = data.split(b"\n", 1)[0]
    if not first_line.startswith(b"object "):
        raise PrivacyScanError("history_scan_tag_object_malformed")
    try:
        target = first_line.removeprefix(b"object ").decode("ascii")
    except UnicodeDecodeError as exc:
        raise PrivacyScanError("history_scan_tag_object_malformed") from exc
    if re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", target) is None:
        raise PrivacyScanError("history_scan_tag_object_malformed")
    return target


def _commit_parent_oids(data: bytes, deadline: float) -> set[str]:
    """Parse one raw commit header with fixed parent and allocation bounds."""

    header_end = data.find(b"\n\n")
    if header_end < 0:
        raise PrivacyScanError("history_scan_commit_object_malformed")
    parents: set[str] = set()
    parent_headers = 0
    tree_count = 0
    start = 0
    while start < header_end:
        _require_history_deadline(deadline)
        end = data.find(b"\n", start, header_end)
        if end < 0:
            end = header_end
        line = data[start:end]
        if line.startswith(b"tree "):
            tree_count += 1
        elif line.startswith(b"parent "):
            parent_headers += 1
            if parent_headers > MAX_COMMIT_PARENT_HEADERS:
                raise PrivacyScanError("history_scan_commit_parent_limit_exceeded")
            try:
                parent = line.removeprefix(b"parent ").decode("ascii")
            except UnicodeDecodeError as exc:
                raise PrivacyScanError("history_scan_commit_object_malformed") from exc
            if re.fullmatch(r"[a-f0-9]{40}(?:[a-f0-9]{24})?", parent) is None:
                raise PrivacyScanError("history_scan_commit_object_malformed")
            parents.add(parent)
        start = end + 1
    if tree_count != 1:
        raise PrivacyScanError("history_scan_commit_object_malformed")
    _require_history_deadline(deadline)
    return parents


def _raw_reachable_commit_payloads(
    root: Path,
    ref_oids: list[str],
    tag_payloads: dict[str, bytes],
    deadline: float,
) -> dict[str, bytes]:
    seeds: set[str] = set()
    for ref_oid in ref_oids:
        current = ref_oid
        seen_tags: set[str] = set()
        while current in tag_payloads:
            if current in seen_tags or len(seen_tags) >= MAX_ANNOTATED_TAG_DEPTH:
                raise PrivacyScanError("history_scan_tag_depth_exceeded")
            seen_tags.add(current)
            current = _tag_target_oid(tag_payloads[current])
        object_type = _run_git(
            root,
            ["cat-file", "-t", current],
            deadline=deadline,
            maximum_output=64,
        ).strip()
        if object_type != b"commit":
            raise PrivacyScanError("history_scan_public_ref_target_unsupported")
        seeds.add(current)
        if len(seeds) > MAX_HISTORY_COMMITS:
            raise PrivacyScanError("history_scan_commit_limit_exceeded")

    payloads: dict[str, bytes] = {}
    pending = sorted(seeds, reverse=True)
    queued = set(seeds)
    total_bytes = sum(len(data) for data in tag_payloads.values())
    while pending:
        _require_history_deadline(deadline)
        commit_oid = pending.pop()
        queued.discard(commit_oid)
        if commit_oid in payloads:
            continue
        if len(payloads) >= MAX_HISTORY_COMMITS:
            raise PrivacyScanError("history_scan_commit_limit_exceeded")
        data = _run_git(
            root,
            ["cat-file", "commit", commit_oid],
            deadline=deadline,
            maximum_output=MAX_HISTORY_BLOB_BYTES,
        )
        total_bytes += len(data)
        if total_bytes > MAX_HISTORY_TOTAL_BYTES:
            raise PrivacyScanError("history_scan_total_bytes_exceeded")
        parents = _commit_parent_oids(data, deadline)
        payloads[commit_oid] = data
        for parent in sorted(parents, reverse=True):
            if parent in payloads or parent in queued:
                continue
            if len(payloads) + len(queued) >= MAX_HISTORY_COMMITS:
                raise PrivacyScanError("history_scan_commit_limit_exceeded")
            pending.append(parent)
            queued.add(parent)
    _require_history_deadline(deadline)
    return payloads


def _reject_active_git_grafts(root: Path, deadline: float) -> None:
    raw = _run_git(
        root,
        ["rev-parse", "--git-path", "info/grafts"],
        deadline=deadline,
        maximum_output=8192,
    )
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if not raw or b"\x00" in raw or b"\n" in raw or b"\r" in raw:
        raise PrivacyScanError("history_scan_git_path_malformed")
    grafts_path = raw if os.path.isabs(raw) else os.path.join(os.fsencode(root), raw)
    try:
        grafts_present = os.path.lexists(grafts_path)
    except (OSError, TypeError, ValueError) as exc:
        raise PrivacyScanError("history_scan_grafts_state_unavailable") from exc
    if grafts_present:
        raise PrivacyScanError("history_scan_grafts_present")
    _require_history_deadline(deadline)


def _record_object_metadata_findings(
    records: set[tuple[str, str, str]],
    *,
    data: bytes,
    object_label: str,
    deadline: float,
) -> None:
    rules = {rule for rule, _line in scan_bytes(data, "git-object-metadata.txt", deadline=deadline)}
    if not rules:
        return
    content_sha256 = hashlib.sha256(data).hexdigest()
    label_sha256 = hashlib.sha256(object_label.encode("ascii")).hexdigest()
    _add_history_records(
        records,
        content_sha256=content_sha256,
        path_sha256=label_sha256,
        rules=rules,
    )
    _require_history_deadline(deadline)


def _add_history_records(
    records: set[tuple[str, str, str]],
    *,
    content_sha256: str,
    path_sha256: str,
    rules: object,
) -> None:
    """Insert bounded history records without materializing an unbounded update."""

    if isinstance(rules, (str, bytes, bytearray)):
        raise TypeError("history_finding_rules_must_be_iterable")
    try:
        ordered_rules = sorted(set(rules))  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError("history_finding_rules_must_be_iterable") from exc
    for rule in ordered_rules:
        if not isinstance(rule, str):
            raise TypeError("history_finding_rule_must_be_string")
        record = (content_sha256, path_sha256, rule)
        if record in records:
            continue
        if len(records) >= MAX_HISTORY_FINDINGS:
            raise PrivacyScanError("history_scan_finding_limit_exceeded")
        records.add(record)


def _materialize_history_findings(
    records: set[tuple[str, str, str]],
) -> list[dict[str, str]]:
    if len(records) > MAX_HISTORY_FINDINGS:
        raise PrivacyScanError("history_scan_finding_limit_exceeded")
    return [
        {
            "scope": "history",
            "blob_sha256": blob_sha256,
            "path_sha256": path_sha256,
            "rule": rule,
        }
        for blob_sha256, path_sha256, rule in sorted(records)
    ]


def history_findings(root: Path) -> tuple[list[dict[str, str]], dict[str, int], bool]:
    deadline = time.monotonic() + HISTORY_DEADLINE_SECONDS
    if not _exact_git_root(root, deadline):
        try:
            evidence = capture_git_workspace_evidence(root)
        except (OSError, ValueError) as exc:
            raise PrivacyScanError("history_scan_git_evidence_unavailable") from exc
        if evidence.get("is_git") is not True:
            raise PrivacyScanError("history_scan_git_repository_required")
        raise PrivacyScanError("history_scan_root_not_exact")
    shallow = _run_git(
        root,
        ["rev-parse", "--is-shallow-repository"],
        deadline=deadline,
        maximum_output=64,
    ).strip()
    if shallow != b"false":
        raise PrivacyScanError("history_scan_shallow_repository")
    _reject_active_git_grafts(root, deadline)
    ref_oids = _public_ref_oids(root, deadline)
    _require_history_deadline(deadline)
    try:
        _run_git(
            root,
            ["fsck", "--connectivity-only", "--no-dangling", "--no-reflogs", *ref_oids],
            deadline=deadline,
            maximum_output=1024 * 1024,
        )
    except PrivacyScanError as exc:
        if str(exc) == "history_scan_git_command_failed":
            raise PrivacyScanError("history_scan_missing_object") from exc
        raise
    tag_payloads = _annotated_tag_payloads(root, ref_oids, deadline)
    commit_payloads = _raw_reachable_commit_payloads(
        root,
        ref_oids,
        tag_payloads,
        deadline,
    )
    commits = sorted(commit_payloads)
    counters = {
        "commits": len(commits),
        "tree_entries": 0,
        "blobs": 0,
        "bytes": 0,
    }
    blob_cache: dict[tuple[str, bool], tuple[str, tuple[str, ...]]] = {}
    records: set[tuple[str, str, str]] = set()
    for tag_oid, tag_data in sorted(tag_payloads.items()):
        _require_history_deadline(deadline)
        counters["bytes"] += len(tag_data)
        if counters["bytes"] > MAX_HISTORY_TOTAL_BYTES:
            raise PrivacyScanError("history_scan_total_bytes_exceeded")
        _record_object_metadata_findings(
            records,
            data=tag_data,
            object_label=f"git-object/tag/{tag_oid}",
            deadline=deadline,
        )
    for commit in commits:
        _require_history_deadline(deadline)
        commit_object = commit_payloads[commit]
        counters["bytes"] += len(commit_object)
        if counters["bytes"] > MAX_HISTORY_TOTAL_BYTES:
            raise PrivacyScanError("history_scan_total_bytes_exceeded")
        _record_object_metadata_findings(
            records,
            data=commit_object,
            object_label=f"git-object/commit/{commit}",
            deadline=deadline,
        )
        tree = _run_git(
            root,
            ["ls-tree", "-r", "-z", "--full-tree", commit],
            deadline=deadline,
        )
        _require_history_deadline(deadline)
        for record in _iter_nul_records(tree):
            _require_history_deadline(deadline)
            counters["tree_entries"] += 1
            if counters["tree_entries"] > MAX_HISTORY_TREE_ENTRIES:
                raise PrivacyScanError("history_scan_tree_entry_limit_exceeded")
            try:
                header, raw_path = record.split(b"\t", 1)
                _mode, object_type, raw_oid = header.split(b" ")
            except ValueError as exc:
                raise PrivacyScanError("history_scan_tree_inventory_malformed") from exc
            try:
                relative = raw_path.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise PrivacyScanError("history_scan_path_invalid_utf8") from exc
            if len(raw_path) > MAX_HISTORY_PATH_BYTES:
                raise PrivacyScanError("history_scan_path_bytes_exceeded")
            path_rules = {
                rule
                for rule, _line in scan_bytes(
                    relative.encode("utf-8"),
                    "repository-tree-path.txt",
                    deadline=deadline,
                )
            }
            path_rules.update(
                rule for rule, _offset in package_secret_path_match_locations(relative)
            )
            _require_history_deadline(deadline)
            path_sha256 = hashlib.sha256(relative.encode("utf-8")).hexdigest()
            if path_rules:
                tree_entry_sha256 = hashlib.sha256(record).hexdigest()
                _add_history_records(
                    records,
                    content_sha256=tree_entry_sha256,
                    path_sha256=path_sha256,
                    rules=path_rules,
                )
            if object_type != b"blob" or _mode not in {b"100644", b"100755", b"120000"}:
                continue
            try:
                blob_oid = raw_oid.decode("ascii")
            except UnicodeDecodeError as exc:
                raise PrivacyScanError("history_scan_tree_inventory_malformed") from exc
            content_profile = "git-symlink-target.txt" if _mode == b"120000" else relative
            scan_key = (blob_oid, _uses_known_text_policy(content_profile))
            if scan_key not in blob_cache:
                counters["blobs"] += 1
                if counters["blobs"] > MAX_HISTORY_BLOBS:
                    raise PrivacyScanError("history_scan_blob_limit_exceeded")
                data = _run_git(
                    root,
                    ["cat-file", "blob", blob_oid],
                    deadline=deadline,
                    maximum_output=MAX_HISTORY_BLOB_BYTES,
                )
                _require_history_deadline(deadline)
                counters["bytes"] += len(data)
                if counters["bytes"] > MAX_HISTORY_TOTAL_BYTES:
                    raise PrivacyScanError("history_scan_total_bytes_exceeded")
                blob_sha256 = hashlib.sha256(data).hexdigest()
                _require_history_deadline(deadline)
                content_rules = tuple(
                    sorted(
                        {
                            rule
                            for rule, _line in scan_bytes(
                                data,
                                content_profile,
                                deadline=deadline,
                            )
                        }
                    )
                )
                blob_cache[scan_key] = (blob_sha256, content_rules)
            blob_sha256, rules = blob_cache[scan_key]
            _add_history_records(
                records,
                content_sha256=blob_sha256,
                path_sha256=path_sha256,
                rules=rules,
            )
            _require_history_deadline(deadline)
    _require_history_deadline(deadline)
    findings = _materialize_history_findings(records)
    _require_history_deadline(deadline)
    _reject_active_git_grafts(root, deadline)
    return findings, counters, True


def load_baseline(root: Path) -> set[tuple[str, str, str]]:
    try:
        snapshot = snapshot_allowed_paths(
            root,
            [BASELINE_RELATIVE_PATH],
            max_bytes=1024 * 1024,
            max_total_bytes=2 * 1024 * 1024,
            max_paths=1,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise PrivacyScanError("history_privacy_baseline_invalid") from exc
    if snapshot[0]["state"] == "missing":
        return set()
    try:
        with open_repository_root_anchor(root) as anchor:
            encoded = read_regular_files_from_anchor(
                anchor,
                [BASELINE_RELATIVE_PATH],
                max_bytes=1024 * 1024,
                max_total_bytes=1024 * 1024,
                max_paths=1,
            )[0].data
        payload = json.loads(encoded.decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError, ValueError) as exc:
        raise PrivacyScanError("history_privacy_baseline_invalid") from exc
    if not isinstance(payload, list):
        raise PrivacyScanError("history_privacy_baseline_invalid")
    entries: set[tuple[str, str, str]] = set()
    for item in payload:
        if not isinstance(item, dict) or set(item) != {"blob_sha256", "path_sha256", "rule"}:
            raise PrivacyScanError("history_privacy_baseline_invalid")
        blob_sha256 = item.get("blob_sha256")
        path_sha256 = item.get("path_sha256")
        rule = item.get("rule")
        if (
            not isinstance(blob_sha256, str)
            or SHA256_RE.fullmatch(blob_sha256) is None
            or not isinstance(path_sha256, str)
            or SHA256_RE.fullmatch(path_sha256) is None
            or not isinstance(rule, str)
            or rule
            not in (
                {name for name, _pattern in PRIVATE_PATTERNS}
                | PACKAGE_SECRET_PATH_RULE_NAMES
                | {"public_text_invalid_utf8"}
            )
        ):
            raise PrivacyScanError("history_privacy_baseline_invalid")
        entry = (blob_sha256, path_sha256, rule)
        if entry in entries:
            raise PrivacyScanError("history_privacy_baseline_duplicate")
        entries.add(entry)
    return entries


def _history_key(finding: dict[str, str]) -> tuple[str, str, str]:
    return finding["blob_sha256"], finding["path_sha256"], finding["rule"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", default=".")
    parser.add_argument("--scope", choices=("current", "history", "all"), default="all")
    parser.add_argument("--format", dest="output_format", choices=("text", "json"), default="text")
    parser.add_argument("--require-empty-baseline", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    current: list[dict[str, object]] = []
    history: list[dict[str, str]] = []
    current_count = 0
    history_counters = {"commits": 0, "tree_entries": 0, "blobs": 0, "bytes": 0}
    history_applicable = False
    errors: list[str] = []
    baseline: set[tuple[str, str, str]] = set()
    unexpected_history: list[dict[str, str]] = []
    try:
        if args.scope in {"history", "all"} or args.require_empty_baseline:
            baseline = load_baseline(root)
        if args.require_empty_baseline and baseline:
            raise PrivacyScanError("history_privacy_baseline_must_be_empty")
        if args.scope in {"current", "all"}:
            current, current_count = current_findings(root)
        if args.scope in {"history", "all"}:
            history, history_counters, history_applicable = history_findings(root)
            found_keys = {_history_key(finding) for finding in history}
            unexpected_history = [finding for finding in history if _history_key(finding) not in baseline]
            if history_applicable and baseline - found_keys:
                errors.append("history_privacy_baseline_stale")
    except PrivacyScanError as exc:
        errors.append(str(exc))
    failed = bool(current or unexpected_history or errors)
    payload = {
        "status": "failed" if failed else "passed",
        "scanner_contract": SCAN_POLICY_NAME,
        "scope": args.scope,
        "history_applicable": history_applicable,
        "current_files_scanned": current_count,
        "history_counts": history_counters,
        "baseline_count": len(baseline),
        "baseline_matches": len(history) - len(unexpected_history),
        "findings": [*current, *unexpected_history],
        "errors": errors,
    }
    if args.output_format == "json":
        print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    else:
        print(f"public_privacy_check={payload['status']}")
        for error in errors:
            print(error)
        for finding in current:
            print(
                "current_metadata_privacy_finding="
                f"path_sha256:{finding['path_sha256']}:"
                f"line:{finding['line']}:rule:{finding['rule']}"
            )
        for finding in unexpected_history:
            print(
                "history_privacy_finding="
                f"path_sha256:{finding['path_sha256']}:"
                f"blob_sha256:{finding['blob_sha256']}:"
                f"rule:{finding['rule']}"
            )
        print(f"public_privacy_current_files_scanned={current_count}")
        print(f"public_privacy_history_commits_scanned={history_counters['commits']}")
        print(f"public_privacy_history_blobs_scanned={history_counters['blobs']}")
        print(f"public_privacy_history_baseline_matches={payload['baseline_matches']}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
