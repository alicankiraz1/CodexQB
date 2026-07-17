#!/usr/bin/env python3
"""Verify a CodexQB package manifest against a ZIP or extracted directory."""

from __future__ import annotations

import argparse
from bisect import bisect_left
from datetime import datetime
import hashlib
import json
import os
import re
import stat
import struct
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO


SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
SAFETY_DIR = SCRIPTS_DIR.parent / "plugins/codexqb/skills/codexqb/scripts"
if str(SAFETY_DIR) not in sys.path:
    sys.path.insert(0, str(SAFETY_DIR))

from package_policy import (  # noqa: E402
    ARTIFACT_TYPES,
    LAYOUT_VERSION,
    LEGACY_PACKAGE_SCHEMA_VERSION,
    MAX_ARTIFACT_FILE_BYTES,
    MAX_CANONICAL_ZIP_MEMBERS,
    MAX_PACKAGE_ARCHIVE_BYTES,
    MAX_PACKAGE_CENTRAL_DIRECTORY_BYTES,
    PACKAGE_MANIFEST_NAME,
    PACKAGE_SCHEMA_VERSION,
    PLUGIN_ACTIVATION_PATH,
    PLUGIN_ARTIFACT,
    PLUGIN_MANIFEST_ALLOWED_KEYS,
    PLUGIN_SKILL_PATH,
    SOURCE_ARCHIVE_PREFIX,
    SOURCE_ARTIFACT,
    archive_prefix,
    canonical_relative_path,
    denied_path_reason,
    manifest_member,
    payload_is_zip_archive,
    plugin_activation_contract_errors,
    plugin_skill_contract_errors,
)
from safety_contracts import (  # noqa: E402
    package_secret_match_locations,
    package_secret_path_match_locations,
)
from mount_identity import (  # noqa: E402
    MountIdentityError,
    MountResolution,
    READ_ONLY_EVIDENCE,
    SECURE_MOUNT_IDENTITY_UNAVAILABLE,
    require_mount_assurance,
    require_same_mount,
    resolve_mount_identity,
)


PACKAGE_PREFIX = SOURCE_ARCHIVE_PREFIX
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_SHA_RE = re.compile(r"^[a-f0-9]{40}(?:[a-f0-9]{24})?$")
VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_MANIFEST_FILES = 100_000
MAX_PACKAGE_UNCOMPRESSED_BYTES = 512 * 1024 * 1024
RUNTIME_CACHE_PARTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"}
SAFE_DIRECTORY_MODES = {0o700, 0o750, 0o755}
LOCAL_FILE_HEADER = struct.Struct("<4s5H3L2H")
LOCAL_FILE_SIGNATURE = b"PK\x03\x04"
CENTRAL_DIRECTORY_HEADER = struct.Struct("<4s6H3L5H2L")
CENTRAL_DIRECTORY_SIGNATURE = b"PK\x01\x02"
END_OF_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x05\x06"
END_OF_CENTRAL_DIRECTORY_SIZE = 22
ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b"PK\x06\x06"
ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE = b"PK\x06\x07"
FileIdentity = tuple[int, int, int, int, int, int, int]
LEGACY_REQUIRED_MANIFEST_FIELDS = {
    "package_schema_version",
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
    "files",
}
REQUIRED_MANIFEST_FIELDS = {
    *LEGACY_REQUIRED_MANIFEST_FIELDS,
    "artifact_type",
    "layout_version",
    "content_sha256",
}


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_manifest_key")
        result[key] = value
    return result


def parse_manifest(data: bytes) -> tuple[dict[str, object] | None, list[str]]:
    if len(data) > MAX_MANIFEST_BYTES:
        return None, ["package_manifest_too_large"]
    try:
        manifest = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return None, ["package_manifest_invalid_json"]
    if not isinstance(manifest, dict):
        return None, ["package_manifest_must_be_object"]
    return manifest, []


def safe_manifest_path(value: object) -> str | None:
    return canonical_relative_path(value)


def safe_archive_name(
    value: str,
    package_prefix: str = PACKAGE_PREFIX,
) -> tuple[str, bool] | None:
    """Return one canonical package member name and whether it is a directory."""

    if not value or "\x00" in value or "\\" in value:
        return None
    is_directory = value.endswith("/")
    candidate = value[:-1] if is_directory else value
    if not candidate or candidate.endswith("/"):
        return None
    canonical = canonical_relative_path(candidate)
    if canonical is None:
        return None
    path = PurePosixPath(canonical)
    if package_prefix:
        prefix_root = package_prefix.rstrip("/")
        if not path.parts or path.parts[0] != prefix_root:
            return None
        if not is_directory and len(path.parts) == 1:
            return None
    return canonical, is_directory


def exact_bool(value: object, expected: bool) -> bool:
    return isinstance(value, bool) and value is expected


def portable_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def optional_bool(value: object) -> bool:
    return value is None or isinstance(value, bool)


def valid_timestamp(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None


def manifest_entries(manifest: dict[str, object]) -> tuple[list[dict[str, str]], list[str]]:
    errors: list[str] = []
    raw_entries = manifest.get("files")
    if not isinstance(raw_entries, list):
        return [], ["package_manifest_files_invalid"]
    if len(raw_entries) > MAX_MANIFEST_FILES:
        return [], ["package_manifest_file_limit_exceeded"]
    entries: list[dict[str, str]] = []
    seen: set[str] = set()
    seen_portable: set[str] = {portable_path_key(PACKAGE_MANIFEST_NAME)}
    portable_records: list[tuple[str, int]] = [
        (portable_path_key(PACKAGE_MANIFEST_NAME), 0)
    ]
    artifact_type = (
        SOURCE_ARTIFACT
        if manifest.get("package_schema_version") == LEGACY_PACKAGE_SCHEMA_VERSION
        else manifest.get("artifact_type")
    )
    for index, item in enumerate(raw_entries, start=1):
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "mode"}:
            errors.append(f"package_manifest_file_invalid=index-{index}")
            continue
        path = safe_manifest_path(item.get("path"))
        digest = item.get("sha256")
        mode = item.get("mode")
        if (
            path is None
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(mode, str)
            or mode not in {"0644", "0755"}
        ):
            errors.append(f"package_manifest_file_invalid=index-{index}")
            continue
        if artifact_type in ARTIFACT_TYPES and denied_path_reason(path, artifact_type) is not None:
            errors.append(f"package_manifest_denied_path=index-{index}")
            continue
        if package_secret_path_match_locations(path):
            errors.append(f"package_manifest_secret_path=index-{index}")
            continue
        if path == PACKAGE_MANIFEST_NAME or path in seen:
            errors.append(f"package_manifest_file_duplicate=index-{index}")
            continue
        portable = portable_path_key(path)
        if portable in seen_portable:
            errors.append(f"package_manifest_file_case_collision=index-{index}")
            continue
        seen.add(path)
        seen_portable.add(portable)
        portable_records.append((portable, index))
        entries.append({"path": path, "sha256": digest, "mode": mode})
    portable_records.sort(key=lambda item: item[0])
    ancestor_conflict_indexes = {
        current_index
        for (previous, _previous_index), (current, current_index) in zip(
            portable_records,
            portable_records[1:],
        )
        if current.startswith(previous + "/")
    }
    errors.extend(
        f"package_manifest_file_ancestor_conflict=index-{index}"
        for index in sorted(ancestor_conflict_indexes)
    )
    if [item["path"] for item in entries] != sorted(item["path"] for item in entries):
        errors.append("package_manifest_files_not_sorted")
    file_count = manifest.get("file_count")
    if not isinstance(file_count, int) or isinstance(file_count, bool) or file_count != len(entries):
        errors.append("package_manifest_file_count_mismatch")
    encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if manifest.get("tree_sha256") != sha256_bytes(encoded):
        errors.append("package_manifest_tree_digest_mismatch")
    return entries, errors


def manifest_contract_errors(manifest: dict[str, object]) -> list[str]:
    errors: list[str] = []
    schema_version = manifest.get("package_schema_version")
    expected_fields = (
        LEGACY_REQUIRED_MANIFEST_FIELDS
        if schema_version == LEGACY_PACKAGE_SCHEMA_VERSION
        else REQUIRED_MANIFEST_FIELDS
    )
    if set(manifest) != expected_fields:
        errors.append("package_manifest_fields_invalid")
    if (
        not isinstance(schema_version, int)
        or isinstance(schema_version, bool)
        or schema_version not in {LEGACY_PACKAGE_SCHEMA_VERSION, PACKAGE_SCHEMA_VERSION}
    ):
        errors.append("package_manifest_schema_version_invalid")
    if schema_version == PACKAGE_SCHEMA_VERSION:
        if manifest.get("artifact_type") not in ARTIFACT_TYPES:
            errors.append("package_manifest_artifact_type_invalid")
        layout_version = manifest.get("layout_version")
        if (
            not isinstance(layout_version, int)
            or isinstance(layout_version, bool)
            or layout_version != LAYOUT_VERSION
        ):
            errors.append("package_manifest_layout_version_invalid")
        content_sha256 = manifest.get("content_sha256")
        if (
            not isinstance(content_sha256, str)
            or SHA256_RE.fullmatch(content_sha256) is None
            or content_sha256 != manifest.get("tree_sha256")
        ):
            errors.append("package_manifest_content_digest_invalid")
    mode = manifest.get("export_mode")
    if mode not in {"strict_release", "worktree", "source_package"}:
        errors.append("package_manifest_export_mode_invalid")
        return errors

    version = manifest.get("plugin_version")
    if not isinstance(version, str) or VERSION_RE.fullmatch(version) is None:
        errors.append("package_manifest_plugin_version_invalid")
    elif manifest.get("release_tag") != f"v{version}":
        errors.append("package_manifest_release_tag_invalid")
    for field in (
        "release_claim",
        "git_provenance_available",
        "tracked_only",
        "include_untracked",
        "changelog_mentions_plugin_version",
    ):
        if not isinstance(manifest.get(field), bool):
            errors.append(f"package_manifest_boolean_invalid={field}")
    for field in ("head_matches_origin_main", "working_tree_clean", "release_tag_matches_head"):
        if not optional_bool(manifest.get(field)):
            errors.append(f"package_manifest_optional_boolean_invalid={field}")
    if not valid_timestamp(manifest.get("generated_at")):
        errors.append("package_manifest_generated_at_invalid")
    if not isinstance(manifest.get("tree_sha256"), str) or SHA256_RE.fullmatch(
        manifest.get("tree_sha256", "")
    ) is None:
        errors.append("package_manifest_tree_digest_invalid")
    if manifest.get("source_inventory") not in {"git_index", "filesystem"}:
        errors.append("package_manifest_source_inventory_invalid")
    if manifest.get("origin_main_ref_status") not in {"absent", "present", "unavailable"}:
        errors.append("package_manifest_origin_status_invalid")
    if manifest.get("changelog_release_state") not in {
        "released",
        "unreleased",
        "missing",
        "unknown",
    }:
        errors.append("package_manifest_changelog_state_invalid")
    mentions_expected = manifest.get("changelog_release_state") in {"released", "unreleased"}
    if isinstance(manifest.get("changelog_mentions_plugin_version"), bool) and (
        manifest.get("changelog_mentions_plugin_version") is not mentions_expected
    ):
        errors.append("package_manifest_changelog_relationship_invalid")

    if mode == "strict_release":
        expected = {
            "release_claim": True,
            "git_provenance_available": True,
            "source_inventory": "git_index",
            "working_tree_clean": True,
            "tracked_only": True,
            "include_untracked": False,
            "changelog_mentions_plugin_version": True,
            "changelog_release_state": "released",
            "release_tag_matches_head": True,
        }
        for field, value in expected.items():
            actual = manifest.get(field)
            if isinstance(value, bool):
                matches = exact_bool(actual, value)
            else:
                matches = actual == value and type(actual) is type(value)
            if not matches:
                errors.append(f"strict_release_manifest_invalid={field}")
        git_commit = manifest.get("git_commit")
        tag_commit = manifest.get("release_tag_commit")
        if not isinstance(manifest.get("git_branch"), str):
            errors.append("strict_release_manifest_invalid=git_branch")
        if not isinstance(git_commit, str) or GIT_SHA_RE.fullmatch(git_commit) is None:
            errors.append("strict_release_manifest_invalid=git_commit")
        if (
            not isinstance(tag_commit, str)
            or GIT_SHA_RE.fullmatch(tag_commit) is None
            or tag_commit != git_commit
        ):
            errors.append("strict_release_manifest_invalid=release_tag_commit")
        origin_status = manifest.get("origin_main_ref_status")
        origin_commit = manifest.get("origin_main_commit")
        if origin_status not in {"absent", "present"}:
            errors.append("strict_release_manifest_invalid=origin_main_ref_status")
        elif origin_status == "present":
            if (
                not isinstance(origin_commit, str)
                or GIT_SHA_RE.fullmatch(origin_commit) is None
                or origin_commit != git_commit
                or not exact_bool(manifest.get("head_matches_origin_main"), True)
            ):
                errors.append("strict_release_manifest_invalid=origin_main_commit")
        elif origin_commit != "unknown" or manifest.get("head_matches_origin_main") is not None:
            errors.append("strict_release_manifest_invalid=origin_main_absence")
    elif not exact_bool(manifest.get("release_claim"), False):
        errors.append("non_release_package_claim_invalid")
    if mode == "worktree":
        if not exact_bool(manifest.get("git_provenance_available"), True):
            errors.append("worktree_manifest_invalid=git_provenance_available")
        if manifest.get("source_inventory") != "git_index":
            errors.append("worktree_manifest_invalid=source_inventory")
        git_commit = manifest.get("git_commit")
        if not isinstance(git_commit, str) or GIT_SHA_RE.fullmatch(git_commit) is None:
            errors.append("worktree_manifest_invalid=git_commit")
        if not isinstance(manifest.get("git_branch"), str):
            errors.append("worktree_manifest_invalid=git_branch")
        if not isinstance(manifest.get("working_tree_clean"), bool):
            errors.append("worktree_manifest_invalid=working_tree_clean")
        include_untracked = manifest.get("include_untracked")
        if isinstance(include_untracked, bool) and not exact_bool(
            manifest.get("tracked_only"), not include_untracked
        ):
            errors.append("worktree_manifest_invalid=tracked_only")
        origin_status = manifest.get("origin_main_ref_status")
        origin_commit = manifest.get("origin_main_commit")
        if origin_status == "present":
            if (
                not isinstance(origin_commit, str)
                or GIT_SHA_RE.fullmatch(origin_commit) is None
                or not isinstance(manifest.get("head_matches_origin_main"), bool)
                or manifest.get("head_matches_origin_main") is not (origin_commit == git_commit)
            ):
                errors.append("worktree_manifest_invalid=origin_main_commit")
        elif origin_status == "absent":
            if origin_commit != "unknown" or manifest.get("head_matches_origin_main") is not None:
                errors.append("worktree_manifest_invalid=origin_main_absence")
        else:
            errors.append("worktree_manifest_invalid=origin_main_ref_status")
        tag_commit = manifest.get("release_tag_commit")
        if tag_commit == "unknown":
            if manifest.get("release_tag_matches_head") is not None:
                errors.append("worktree_manifest_invalid=release_tag_matches_head")
        elif (
            not isinstance(tag_commit, str)
            or GIT_SHA_RE.fullmatch(tag_commit) is None
            or not isinstance(manifest.get("release_tag_matches_head"), bool)
            or manifest.get("release_tag_matches_head") is not (tag_commit == git_commit)
        ):
            errors.append("worktree_manifest_invalid=release_tag_commit")
    if mode == "source_package":
        expected = {
            "source_inventory": "filesystem",
            "tracked_only": False,
            "include_untracked": True,
        }
        for field, value in expected.items():
            actual = manifest.get(field)
            if isinstance(value, bool):
                matches = exact_bool(actual, value)
            else:
                matches = actual == value and type(actual) is type(value)
            if not matches:
                errors.append(f"source_package_manifest_invalid={field}")
        git_provenance = manifest.get("git_provenance_available")
        if exact_bool(git_provenance, False):
            unavailable_expected = {
                "git_commit": "unknown",
                "git_branch": "unknown",
                "origin_main_commit": "unknown",
                "origin_main_ref_status": "unavailable",
                "head_matches_origin_main": None,
                "working_tree_clean": None,
                "release_tag_commit": "unknown",
                "release_tag_matches_head": None,
            }
            for field, value in unavailable_expected.items():
                actual = manifest.get(field)
                if actual != value or type(actual) is not type(value):
                    errors.append(f"source_package_manifest_invalid={field}")
        elif exact_bool(git_provenance, True):
            git_commit = manifest.get("git_commit")
            if not isinstance(git_commit, str) or GIT_SHA_RE.fullmatch(git_commit) is None:
                errors.append("source_package_manifest_invalid=git_commit")
            if not isinstance(manifest.get("git_branch"), str):
                errors.append("source_package_manifest_invalid=git_branch")
            if not isinstance(manifest.get("working_tree_clean"), bool):
                errors.append("source_package_manifest_invalid=working_tree_clean")
            origin_status = manifest.get("origin_main_ref_status")
            origin_commit = manifest.get("origin_main_commit")
            if origin_status == "present":
                if (
                    not isinstance(origin_commit, str)
                    or GIT_SHA_RE.fullmatch(origin_commit) is None
                    or not isinstance(manifest.get("head_matches_origin_main"), bool)
                    or manifest.get("head_matches_origin_main") is not (origin_commit == git_commit)
                ):
                    errors.append("source_package_manifest_invalid=origin_main_commit")
            elif origin_status in {"absent", "unavailable"}:
                if origin_commit != "unknown" or manifest.get("head_matches_origin_main") is not None:
                    errors.append("source_package_manifest_invalid=origin_main_absence")
            else:
                errors.append("source_package_manifest_invalid=origin_main_ref_status")
            tag_commit = manifest.get("release_tag_commit")
            if tag_commit != "unknown" and (
                not isinstance(tag_commit, str) or GIT_SHA_RE.fullmatch(tag_commit) is None
            ):
                errors.append("source_package_manifest_invalid=release_tag_commit")
            if tag_commit == "unknown":
                if manifest.get("release_tag_matches_head") is not None:
                    errors.append("source_package_manifest_invalid=release_tag_matches_head")
            elif not isinstance(manifest.get("release_tag_matches_head"), bool):
                errors.append("source_package_manifest_invalid=release_tag_matches_head")
            elif manifest.get("release_tag_matches_head") is not (tag_commit == git_commit):
                errors.append("source_package_manifest_invalid=release_tag_commit_relationship")
        else:
            errors.append("source_package_manifest_invalid=git_provenance_available")
    return errors


def zip_member_evidence(
    archive: zipfile.ZipFile,
    info: zipfile.ZipInfo,
) -> tuple[str, bool, bool]:
    digest = hashlib.sha256()
    payload = bytearray()
    with archive.open(info, "r") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            payload.extend(chunk)
    return (
        digest.hexdigest(),
        payload_is_zip_archive(payload),
        bool(package_secret_match_locations(bytes(payload), Path(info.filename).suffix)),
    )


def zip_member_sha256(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> str:
    """Compatibility wrapper for callers that only need the member digest."""

    return zip_member_evidence(archive, info)[0]


def canonical_zip_flag_bits(name: str) -> int:
    try:
        name.encode("ascii")
    except UnicodeEncodeError:
        return 0x800
    return 0


def canonical_zip_envelope_errors(
    archive: zipfile.ZipFile,
    infos: list[zipfile.ZipInfo],
) -> list[str]:
    """Reject bytes outside the exact v3 local-member/central-directory envelope."""

    handle = archive.fp
    if handle is None or not infos:
        return ["package_zip_envelope_invalid"]
    try:
        original_position = handle.tell()
        handle.seek(0, os.SEEK_END)
        archive_size = handle.tell()
        if archive_size < END_OF_CENTRAL_DIRECTORY_SIZE:
            return ["package_zip_envelope_invalid"]
        handle.seek(0)
        first_signature = handle.read(4)
        handle.seek(archive_size - END_OF_CENTRAL_DIRECTORY_SIZE)
        final_record = handle.read(END_OF_CENTRAL_DIRECTORY_SIZE)
        for index, info in enumerate(infos):
            handle.seek(info.header_offset)
            raw_header = handle.read(LOCAL_FILE_HEADER.size)
            if len(raw_header) != LOCAL_FILE_HEADER.size:
                return ["package_zip_envelope_invalid"]
            (
                signature,
                extract_version,
                flag_bits,
                compression,
                modified_time,
                modified_date,
                crc,
                compressed_size,
                uncompressed_size,
                filename_length,
                extra_length,
            ) = LOCAL_FILE_HEADER.unpack(raw_header)
            encoded_name = (
                info.filename.encode("ascii")
                if canonical_zip_flag_bits(info.filename) == 0
                else info.filename.encode("utf-8")
            )
            if (
                signature != LOCAL_FILE_SIGNATURE
                or extract_version != info.extract_version
                or flag_bits != info.flag_bits
                or compression != info.compress_type
                or modified_time != 0
                or modified_date != 33
                or crc != info.CRC
                or compressed_size != info.compress_size
                or uncompressed_size != info.file_size
                or filename_length != len(encoded_name)
                or extra_length != 0
            ):
                return ["package_zip_envelope_invalid"]
            member_end = (
                info.header_offset
                + LOCAL_FILE_HEADER.size
                + filename_length
                + extra_length
                + info.compress_size
            )
            expected_next_offset = (
                infos[index + 1].header_offset
                if index + 1 < len(infos)
                else archive.start_dir
            )
            if member_end != expected_next_offset:
                return ["package_zip_envelope_invalid"]
    except (AttributeError, OSError, OverflowError, TypeError, ValueError):
        return ["package_zip_envelope_invalid"]
    finally:
        try:
            handle.seek(original_position)
        except (NameError, OSError, ValueError):
            pass
    if len(final_record) == END_OF_CENTRAL_DIRECTORY_SIZE:
        (
            end_signature,
            disk_number,
            central_directory_disk,
            entries_on_disk,
            entries_total,
            central_directory_size,
            central_directory_offset,
            comment_length,
        ) = struct.unpack("<4s4H2LH", final_record)
    else:
        end_signature = b""
        disk_number = central_directory_disk = -1
        entries_on_disk = entries_total = -1
        central_directory_size = central_directory_offset = -1
        comment_length = -1
    end_record_offset = archive_size - END_OF_CENTRAL_DIRECTORY_SIZE
    if (
        len(infos) > MAX_CANONICAL_ZIP_MEMBERS
        or infos[0].header_offset != 0
        or first_signature != LOCAL_FILE_SIGNATURE
        or archive.comment != b""
        or len(final_record) != END_OF_CENTRAL_DIRECTORY_SIZE
        or end_signature != END_OF_CENTRAL_DIRECTORY_SIGNATURE
        or disk_number != 0
        or central_directory_disk != 0
        or entries_on_disk != len(infos)
        or entries_total != len(infos)
        or central_directory_offset != archive.start_dir
        or central_directory_size != end_record_offset - archive.start_dir
        or comment_length != 0
    ):
        return ["package_zip_envelope_invalid"]
    return []


def archive_entry_has_ancestor_conflict(
    portable: str,
    is_directory: bool,
    member_types: dict[str, bool],
    descendant_ancestors: set[str],
) -> bool:
    """Compatibility helper with depth-bounded lookups and no prior-entry scan."""

    parts = portable.split("/")
    return any(
        member_types.get("/".join(parts[:depth])) is False
        for depth in range(1, len(parts))
    ) or (not is_directory and portable in descendant_ancestors)


def plugin_manifest_payload_errors(
    data: bytes,
    *,
    plugin_version: object,
    artifact_type: str,
    packaged_files: set[str],
) -> list[str]:
    try:
        payload = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError):
        return ["package_plugin_manifest_invalid"]
    if not isinstance(payload, dict):
        return ["package_plugin_manifest_invalid"]
    errors: list[str] = []
    if payload.get("version") != plugin_version:
        errors.append("package_plugin_version_mismatch")
    if payload.get("name") != "codexqb" and (
        artifact_type == PLUGIN_ARTIFACT or "name" in payload
    ):
        errors.append("package_plugin_name_invalid")
    if set(payload) - PLUGIN_MANIFEST_ALLOWED_KEYS:
        errors.append("package_plugin_manifest_fields_invalid")
    if artifact_type == PLUGIN_ARTIFACT:
        skills = payload.get("skills")
        if skills != "./skills/":
            errors.append("package_plugin_skills_path_invalid")
        if PLUGIN_SKILL_PATH not in packaged_files:
            errors.append("package_plugin_skills_missing")
        if PLUGIN_ACTIVATION_PATH not in packaged_files:
            errors.append("package_plugin_activation_missing")
    return errors


def _zip_extra_field_errors(data: bytes) -> list[str]:
    """Validate bounded extra-field framing and identify ZIP64 records."""

    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            return ["package_zip_envelope_invalid"]
        header_id, payload_size = struct.unpack_from("<HH", data, offset)
        offset += 4
        if payload_size > len(data) - offset:
            return ["package_zip_envelope_invalid"]
        if header_id == 0x0001:
            return ["package_zip_zip64_rejected"]
        offset += payload_size
    return []


def zip_stream_preflight_errors(handle: BinaryIO) -> list[str]:
    """Bound and validate the raw ZIP container before ``ZipFile`` allocates."""

    try:
        original_position = handle.tell()
    except (AttributeError, OSError, ValueError):
        return ["package_zip_invalid"]
    try:
        handle.seek(0, os.SEEK_END)
        archive_size = handle.tell()
        if archive_size > MAX_PACKAGE_ARCHIVE_BYTES:
            return ["package_zip_archive_size_exceeded"]
        if archive_size < END_OF_CENTRAL_DIRECTORY_SIZE:
            return ["package_zip_envelope_invalid"]

        end_record_offset = archive_size - END_OF_CENTRAL_DIRECTORY_SIZE
        handle.seek(end_record_offset)
        final_record = handle.read(END_OF_CENTRAL_DIRECTORY_SIZE)
        if len(final_record) != END_OF_CENTRAL_DIRECTORY_SIZE:
            return ["package_zip_envelope_invalid"]
        (
            end_signature,
            disk_number,
            central_directory_disk,
            entries_on_disk,
            entries_total,
            central_directory_size,
            central_directory_offset,
            comment_length,
        ) = struct.unpack("<4s4H2LH", final_record)
        if end_signature != END_OF_CENTRAL_DIRECTORY_SIGNATURE:
            return ["package_zip_envelope_invalid"]

        locator_signature = b""
        if end_record_offset >= 20:
            handle.seek(end_record_offset - 20)
            locator_signature = handle.read(4)
        zip64_marker = (
            central_directory_size == 0xFFFFFFFF
            or central_directory_offset == 0xFFFFFFFF
            or locator_signature == ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE
        )
        if zip64_marker:
            return ["package_zip_zip64_rejected"]
        if entries_total > MAX_CANONICAL_ZIP_MEMBERS:
            return ["package_zip_entry_limit_exceeded"]
        if entries_on_disk == 0xFFFF:
            return ["package_zip_zip64_rejected"]
        if (
            disk_number != 0
            or central_directory_disk != 0
            or entries_on_disk != entries_total
            or entries_total == 0
            or comment_length != 0
        ):
            return ["package_zip_envelope_invalid"]
        if central_directory_size > MAX_PACKAGE_CENTRAL_DIRECTORY_BYTES:
            return ["package_zip_central_directory_size_exceeded"]
        if (
            central_directory_size < entries_total * CENTRAL_DIRECTORY_HEADER.size
            or central_directory_offset < LOCAL_FILE_HEADER.size
            or central_directory_offset + central_directory_size != end_record_offset
        ):
            return ["package_zip_envelope_invalid"]

        handle.seek(0)
        if handle.read(4) != LOCAL_FILE_SIGNATURE:
            return ["package_zip_envelope_invalid"]

        central_entries: list[
            tuple[int, bytes, int, int, int, int, int, int, int, int]
        ] = []
        cursor = central_directory_offset
        for _index in range(entries_total):
            if cursor + CENTRAL_DIRECTORY_HEADER.size > end_record_offset:
                return ["package_zip_envelope_invalid"]
            handle.seek(cursor)
            raw_header = handle.read(CENTRAL_DIRECTORY_HEADER.size)
            if len(raw_header) != CENTRAL_DIRECTORY_HEADER.size:
                return ["package_zip_envelope_invalid"]
            (
                signature,
                _create_version,
                extract_version,
                flag_bits,
                compression,
                modified_time,
                modified_date,
                crc,
                compressed_size,
                uncompressed_size,
                filename_length,
                extra_length,
                member_comment_length,
                disk_start,
                _internal_attr,
                _external_attr,
                local_header_offset,
            ) = CENTRAL_DIRECTORY_HEADER.unpack(raw_header)
            if signature != CENTRAL_DIRECTORY_SIGNATURE:
                return ["package_zip_envelope_invalid"]
            if (
                compressed_size == 0xFFFFFFFF
                or uncompressed_size == 0xFFFFFFFF
                or local_header_offset == 0xFFFFFFFF
                or disk_start == 0xFFFF
            ):
                return ["package_zip_zip64_rejected"]
            if disk_start != 0 or flag_bits & 0x08:
                return ["package_zip_envelope_invalid"]
            record_size = (
                CENTRAL_DIRECTORY_HEADER.size
                + filename_length
                + extra_length
                + member_comment_length
            )
            if record_size < CENTRAL_DIRECTORY_HEADER.size or cursor + record_size > end_record_offset:
                return ["package_zip_envelope_invalid"]
            filename = handle.read(filename_length)
            extra = handle.read(extra_length)
            if len(filename) != filename_length or len(extra) != extra_length:
                return ["package_zip_envelope_invalid"]
            extra_errors = _zip_extra_field_errors(extra)
            if extra_errors:
                return extra_errors
            central_entries.append(
                (
                    local_header_offset,
                    filename,
                    extract_version,
                    flag_bits,
                    compression,
                    modified_time,
                    modified_date,
                    crc,
                    compressed_size,
                    uncompressed_size,
                )
            )
            cursor += record_size
        if cursor != end_record_offset:
            return ["package_zip_envelope_invalid"]

        ordered_entries = sorted(central_entries, key=lambda item: item[0])
        expected_offset = 0
        for (
            local_header_offset,
            central_filename,
            extract_version,
            flag_bits,
            compression,
            modified_time,
            modified_date,
            crc,
            compressed_size,
            uncompressed_size,
        ) in ordered_entries:
            if local_header_offset != expected_offset:
                return ["package_zip_envelope_invalid"]
            handle.seek(local_header_offset)
            local_header = handle.read(LOCAL_FILE_HEADER.size)
            if len(local_header) != LOCAL_FILE_HEADER.size:
                return ["package_zip_envelope_invalid"]
            (
                local_signature,
                local_extract_version,
                local_flag_bits,
                local_compression,
                local_modified_time,
                local_modified_date,
                local_crc,
                local_compressed_size,
                local_uncompressed_size,
                local_filename_length,
                local_extra_length,
            ) = LOCAL_FILE_HEADER.unpack(local_header)
            if (
                local_signature != LOCAL_FILE_SIGNATURE
                or local_extract_version != extract_version
                or local_flag_bits != flag_bits
                or local_compression != compression
                or local_modified_time != modified_time
                or local_modified_date != modified_date
                or local_crc != crc
                or local_compressed_size != compressed_size
                or local_uncompressed_size != uncompressed_size
                or local_filename_length != len(central_filename)
            ):
                return ["package_zip_envelope_invalid"]
            local_filename = handle.read(local_filename_length)
            local_extra = handle.read(local_extra_length)
            if local_filename != central_filename or len(local_extra) != local_extra_length:
                return ["package_zip_envelope_invalid"]
            extra_errors = _zip_extra_field_errors(local_extra)
            if extra_errors:
                return extra_errors
            expected_offset = (
                local_header_offset
                + LOCAL_FILE_HEADER.size
                + local_filename_length
                + local_extra_length
                + compressed_size
            )
        if expected_offset != central_directory_offset:
            return ["package_zip_envelope_invalid"]
        return []
    except (MemoryError, OSError, OverflowError, struct.error, TypeError, ValueError):
        return ["package_zip_invalid"]
    finally:
        try:
            handle.seek(original_position)
        except (OSError, ValueError):
            pass


def snapshot_zip_stream(source: BinaryIO, destination: BinaryIO) -> list[str]:
    """Copy one bounded input into a private seekable snapshot and restore position."""

    try:
        original_position = source.tell()
        source.seek(0)
    except (AttributeError, OSError, ValueError):
        return ["package_zip_invalid"]
    total = 0
    try:
        while True:
            remaining = MAX_PACKAGE_ARCHIVE_BYTES + 1 - total
            if remaining <= 0:
                return ["package_zip_archive_size_exceeded"]
            chunk = source.read(min(1024 * 1024, remaining))
            if not isinstance(chunk, bytes):
                return ["package_zip_invalid"]
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_PACKAGE_ARCHIVE_BYTES:
                return ["package_zip_archive_size_exceeded"]
            destination.write(chunk)
        destination.flush()
        destination.seek(0)
        return []
    except (MemoryError, OSError, TypeError, ValueError):
        return ["package_zip_invalid"]
    finally:
        try:
            source.seek(original_position)
        except (OSError, ValueError):
            pass


def verify_zip(
    path: Path | BinaryIO,
    *,
    expected_artifact_type: str | None = None,
) -> list[str]:
    owned_handle: BinaryIO | None = None
    descriptor = -1
    try:
        if isinstance(path, (str, bytes, os.PathLike)):
            if any(
                not hasattr(os, flag)
                for flag in ("O_CLOEXEC", "O_NONBLOCK", "O_NOFOLLOW")
            ):
                return ["package_zip_invalid"]
            flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
            descriptor = os.open(path, flags)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode):
                return ["package_zip_invalid"]
            owned_handle = os.fdopen(descriptor, "rb", closefd=True)
            descriptor = -1
            source: BinaryIO = owned_handle
        else:
            source = path
        with tempfile.TemporaryFile(mode="w+b") as snapshot:
            snapshot_errors = snapshot_zip_stream(source, snapshot)
            if snapshot_errors:
                return snapshot_errors
            preflight_errors = zip_stream_preflight_errors(snapshot)
            if preflight_errors:
                return preflight_errors
            return _verify_zip_after_preflight(
                snapshot,
                expected_artifact_type=expected_artifact_type,
            )
    except (MemoryError, OSError, TypeError, ValueError):
        return ["package_zip_invalid"]
    finally:
        if owned_handle is not None:
            owned_handle.close()
        elif descriptor >= 0:
            os.close(descriptor)


def _verify_zip_after_preflight(
    path: Path | BinaryIO,
    *,
    expected_artifact_type: str | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                errors.append("package_zip_duplicate_entry")
            if len(infos) > MAX_MANIFEST_FILES + 1:
                return [*errors, "package_zip_entry_limit_exceeded"]
            if sum(info.file_size for info in infos) > MAX_PACKAGE_UNCOMPRESSED_BYTES:
                return [*errors, "package_zip_uncompressed_size_exceeded"]
            oversized_members = {
                info.filename
                for info in infos
                if info.file_size > MAX_ARTIFACT_FILE_BYTES
            }
            if oversized_members:
                errors.append("package_zip_file_size_limit_exceeded")
            manifest_candidates = (
                PACKAGE_MANIFEST_NAME,
                f"{PACKAGE_PREFIX}{PACKAGE_MANIFEST_NAME}",
            )
            manifest_matches = [
                candidate
                for candidate in manifest_candidates
                if names.count(candidate) == 1
            ]
            if (
                len(manifest_matches) != 1
                or sum(names.count(candidate) for candidate in manifest_candidates) != 1
            ):
                return [*errors, "package_manifest_missing_or_duplicate"]
            manifest_name = manifest_matches[0]
            manifest_info = archive.getinfo(manifest_name)
            if manifest_info.file_size > MAX_MANIFEST_BYTES:
                return [*errors, "package_manifest_too_large"]
            manifest_data = archive.read(manifest_name)
            if package_secret_match_locations(manifest_data, ".json"):
                errors.append("package_manifest_secret_content_rejected")
            manifest, parse_errors = parse_manifest(manifest_data)
            errors.extend(parse_errors)
            if manifest is None:
                return errors
            entries, entry_errors = manifest_entries(manifest)
            errors.extend(entry_errors)
            errors.extend(manifest_contract_errors(manifest))
            schema_version = manifest.get("package_schema_version")
            artifact_type = (
                SOURCE_ARTIFACT
                if schema_version == LEGACY_PACKAGE_SCHEMA_VERSION
                else manifest.get("artifact_type")
            )
            if artifact_type not in ARTIFACT_TYPES:
                artifact_type = (
                    PLUGIN_ARTIFACT
                    if manifest_name == PACKAGE_MANIFEST_NAME
                    else SOURCE_ARTIFACT
                )
            if expected_artifact_type is not None and artifact_type != expected_artifact_type:
                errors.append("package_artifact_type_mismatch")
            expected_manifest_name = manifest_member(artifact_type)
            if manifest_name != expected_manifest_name:
                errors.append("package_manifest_layout_mismatch")
            prefix = archive_prefix(artifact_type)
            normalized_names: set[str] = set()
            portable_names: set[str] = set()
            member_records: list[tuple[str, bool]] = []
            actual_files: set[str] = set()
            member_evidence: dict[str, tuple[str, bool]] = {}
            for member_index, info in enumerate(infos, start=1):
                safe_name = safe_archive_name(info.filename, prefix)
                if safe_name is None:
                    errors.append("package_zip_entry_path_invalid")
                    continue
                normalized, is_directory = safe_name
                if package_secret_path_match_locations(normalized):
                    errors.append(f"package_zip_secret_path_rejected=index-{member_index}")
                    continue
                portable = portable_path_key(normalized)
                if normalized in normalized_names or portable in portable_names:
                    errors.append("package_zip_entry_collision")
                normalized_names.add(normalized)
                portable_names.add(portable)
                member_records.append((portable, is_directory))
                if info.is_dir() is not is_directory:
                    errors.append("package_zip_entry_type_invalid")
                unix_mode = info.external_attr >> 16
                file_type = stat.S_IFMT(unix_mode)
                permissions = stat.S_IMODE(unix_mode)
                expected_type = stat.S_IFDIR if is_directory else stat.S_IFREG
                allowed_permissions = {0o755} if is_directory else {0o644, 0o755}
                if file_type != expected_type or permissions not in allowed_permissions:
                    errors.append("package_zip_entry_type_invalid")
                if normalized == expected_manifest_name and permissions != 0o644:
                    errors.append("package_zip_manifest_mode_invalid")
                if info.flag_bits & 0x1:
                    errors.append("package_zip_encrypted_entry")
                relative = normalized[len(prefix) :]
                if relative != PACKAGE_MANIFEST_NAME and denied_path_reason(
                    relative,
                    artifact_type,
                ) is not None:
                    errors.append("package_zip_denied_path")
                if not is_directory:
                    if relative != PACKAGE_MANIFEST_NAME:
                        actual_files.add(relative)
                        if info.filename not in oversized_members:
                            evidence = zip_member_evidence(archive, info)
                            member_evidence[normalized] = evidence
                            if evidence[1]:
                                errors.append("package_zip_nested_zip_rejected")
                            if evidence[2]:
                                errors.append("package_zip_secret_content_rejected")
                if is_directory:
                    errors.append("package_zip_directory_entry_rejected")
                if info.compress_type != zipfile.ZIP_STORED:
                    errors.append("package_zip_compression_invalid")
                expected_external_attr = (stat.S_IFREG | permissions) << 16
                if (
                    info.date_time != (1980, 1, 1, 0, 0, 0)
                    or info.extra
                    or info.comment
                    or info.create_system != 3
                    or info.create_version != 20
                    or info.extract_version != 20
                    or info.internal_attr != 0
                    or info.external_attr != expected_external_attr
                    or info.volume != 0
                    or info.reserved != 0
                    or info.flag_bits != canonical_zip_flag_bits(info.filename)
                ):
                    errors.append("package_zip_metadata_invalid")
            member_records.sort(key=lambda item: item[0])
            if any(
                current.startswith(previous + "/") and not previous_is_directory
                for (previous, previous_is_directory), (current, _current_is_directory) in zip(
                    member_records,
                    member_records[1:],
                )
            ):
                errors.append("package_zip_entry_ancestor_conflict")
            errors.extend(canonical_zip_envelope_errors(archive, infos))
            expected_files = {item["path"] for item in entries}
            if actual_files != expected_files:
                errors.append("package_manifest_file_set_mismatch")
            expected_order = [f"{prefix}{item['path']}" for item in entries]
            expected_order.append(expected_manifest_name)
            if names != expected_order:
                errors.append("package_zip_member_order_invalid")
            for index, item in enumerate(entries, start=1):
                archive_name = f"{prefix}{item['path']}"
                try:
                    info = archive.getinfo(archive_name)
                except KeyError:
                    continue
                actual_mode = stat.S_IMODE(info.external_attr >> 16)
                if actual_mode != int(item["mode"], 8):
                    errors.append(f"package_file_mode_mismatch=index-{index}")
                evidence = member_evidence.get(archive_name)
                if evidence is None:
                    continue
                if evidence[0] != item["sha256"]:
                    errors.append(f"package_file_digest_mismatch=index-{index}")
            plugin_path = (
                ".codex-plugin/plugin.json"
                if artifact_type == PLUGIN_ARTIFACT
                else "plugins/codexqb/.codex-plugin/plugin.json"
            )
            if plugin_path not in expected_files:
                errors.append("package_plugin_manifest_missing")
            else:
                try:
                    plugin_info = archive.getinfo(f"{prefix}{plugin_path}")
                except KeyError:
                    errors.append("package_plugin_manifest_invalid")
                else:
                    if plugin_info.file_size > MAX_MANIFEST_BYTES:
                        errors.append("package_plugin_manifest_too_large")
                    else:
                        errors.extend(
                            plugin_manifest_payload_errors(
                                archive.read(plugin_info),
                                plugin_version=manifest.get("plugin_version"),
                                artifact_type=artifact_type,
                                packaged_files=expected_files,
                            )
                        )
            if artifact_type == PLUGIN_ARTIFACT:
                runtime_payloads: dict[str, bytes | None] = {}
                for runtime_path in (PLUGIN_SKILL_PATH, PLUGIN_ACTIVATION_PATH):
                    if runtime_path not in expected_files:
                        runtime_payloads[runtime_path] = None
                        continue
                    try:
                        runtime_info = archive.getinfo(f"{prefix}{runtime_path}")
                    except KeyError:
                        runtime_payloads[runtime_path] = None
                        continue
                    if runtime_info.file_size > MAX_MANIFEST_BYTES:
                        errors.append("package_plugin_runtime_metadata_too_large")
                        runtime_payloads[runtime_path] = None
                    else:
                        runtime_payloads[runtime_path] = archive.read(runtime_info)
                errors.extend(
                    plugin_skill_contract_errors(
                        runtime_payloads.get(PLUGIN_SKILL_PATH)
                    )
                )
                errors.extend(
                    plugin_activation_contract_errors(
                        runtime_payloads.get(PLUGIN_ACTIVATION_PATH)
                    )
                )
    except (MemoryError, OSError, zipfile.BadZipFile, RuntimeError):
        return ["package_zip_invalid"]
    return list(dict.fromkeys(errors))


def metadata_identity(metadata: os.stat_result) -> FileIdentity:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
        metadata.st_nlink,
    )


def directory_identity(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)


def secure_directory_flags() -> int | None:
    if any(not hasattr(os, name) for name in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")):
        return None
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def secure_regular_flags() -> int | None:
    if any(not hasattr(os, name) for name in ("O_NOFOLLOW", "O_CLOEXEC")):
        return None
    return (
        os.O_RDONLY
        | os.O_NOFOLLOW
        | os.O_CLOEXEC
        | getattr(os, "O_NONBLOCK", 0)
    )


def open_regular_descriptor(
    root_descriptor: int,
    relative: str,
    root_resolution: MountResolution | None = None,
) -> tuple[int, os.stat_result] | None:
    """Open one regular file through descriptor-anchored, no-follow traversal."""

    directory_flags = secure_directory_flags()
    regular_flags = secure_regular_flags()
    parts = PurePosixPath(relative).parts
    if directory_flags is None or regular_flags is None or not parts:
        return None
    current_descriptor = -1
    result_descriptor = -1
    try:
        current_descriptor = os.dup(root_descriptor)
        for part in parts[:-1]:
            next_descriptor = os.open(
                part,
                directory_flags,
                dir_fd=current_descriptor,
            )
            metadata = os.fstat(next_descriptor)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(next_descriptor)
                return None
            os.close(current_descriptor)
            current_descriptor = next_descriptor
        result_descriptor = os.open(
            parts[-1],
            regular_flags,
            dir_fd=current_descriptor,
        )
        opened_metadata = os.fstat(result_descriptor)
        if not stat.S_ISREG(opened_metadata.st_mode):
            os.close(result_descriptor)
            result_descriptor = -1
            return None
        if root_resolution is not None:
            require_same_mount(root_resolution, result_descriptor, relative)
        descriptor = result_descriptor
        result_descriptor = -1
        return descriptor, opened_metadata
    except (NotImplementedError, OSError, TypeError, ValueError):
        return None
    finally:
        if result_descriptor >= 0:
            os.close(result_descriptor)
        if current_descriptor >= 0:
            os.close(current_descriptor)


def regular_file_bytes(
    root_descriptor: int,
    relative: str,
    maximum_bytes: int,
    root_resolution: MountResolution | None = None,
) -> tuple[bytes, str, FileIdentity] | None:
    opened = open_regular_descriptor(root_descriptor, relative, root_resolution)
    if opened is None:
        return None
    descriptor, before = opened
    if before.st_size > maximum_bytes:
        os.close(descriptor)
        return None
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            data = handle.read(maximum_bytes + 1)
            after = os.fstat(handle.fileno())
    except OSError:
        return None
    if (
        len(data) > maximum_bytes
        or len(data) != after.st_size
        or metadata_identity(before) != metadata_identity(after)
    ):
        return None
    return data, f"{stat.S_IMODE(after.st_mode):04o}", metadata_identity(after)


def regular_file_evidence(
    root_descriptor: int,
    relative: str,
    maximum_bytes: int,
    root_resolution: MountResolution | None = None,
) -> tuple[str | None, int, str | None, FileIdentity | None, bool, bool]:
    opened = open_regular_descriptor(root_descriptor, relative, root_resolution)
    if opened is None:
        return None, 0, None, None, False, False
    descriptor, before = opened
    if before.st_size > maximum_bytes:
        os.close(descriptor)
        return (
            None,
            0,
            f"{stat.S_IMODE(before.st_mode):04o}",
            metadata_identity(before),
            False,
            False,
        )
    digest = hashlib.sha256()
    payload = bytearray()
    total = 0
    try:
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            while total <= maximum_bytes:
                chunk = handle.read(min(1024 * 1024, maximum_bytes - total + 1))
                if not chunk:
                    break
                total += len(chunk)
                if total > maximum_bytes:
                    break
                digest.update(chunk)
                payload.extend(chunk)
            after = os.fstat(handle.fileno())
    except OSError:
        return None, total, None, None, False, False
    mode = f"{stat.S_IMODE(after.st_mode):04o}"
    if (
        total > maximum_bytes
        or total != after.st_size
        or metadata_identity(before) != metadata_identity(after)
    ):
        return None, total, mode, metadata_identity(after), False, False
    return (
        digest.hexdigest(),
        total,
        mode,
        metadata_identity(after),
        payload_is_zip_archive(payload),
        bool(package_secret_match_locations(bytes(payload), Path(relative).suffix)),
    )


def regular_file_sha256(
    root_descriptor: int,
    relative: str,
    maximum_bytes: int,
) -> tuple[str | None, int, str | None, FileIdentity | None]:
    """Compatibility wrapper for callers that only need digest evidence."""

    digest, total, mode, identity, _nested_zip, _secret_content = regular_file_evidence(
        root_descriptor,
        relative,
        maximum_bytes,
    )
    return digest, total, mode, identity


def regular_file_prefix(root_descriptor: int, relative: str, length: int = 4) -> bytes | None:
    opened = open_regular_descriptor(root_descriptor, relative)
    if opened is None:
        return None
    descriptor, before = opened
    try:
        data = os.read(descriptor, length)
        after = os.fstat(descriptor)
    except OSError:
        return None
    finally:
        os.close(descriptor)
    if metadata_identity(before) != metadata_identity(after):
        return None
    return data


def directory_inventory(
    root_descriptor: int,
    *,
    strict_artifact: bool = False,
    artifact_type: str = SOURCE_ARTIFACT,
    root_resolution: MountResolution | None = None,
    expected_file_paths: tuple[str, ...] | None = None,
) -> tuple[dict[str, FileIdentity], int, bool, bool, list[str]]:
    """Inventory a package tree without following path-based ancestor swaps."""

    directory_flags = secure_directory_flags()
    if directory_flags is None:
        return {}, 0, True, False, ["package_directory_secure_open_unavailable"]
    file_identities: dict[str, FileIdentity] = {}
    actual_uncompressed_bytes = 0
    actual_entry_count = 0
    walk_failed = False
    inventory_limit_exceeded = False
    errors: list[str] = []
    seen_regular_inodes: set[tuple[int, int]] = set()

    def walk(directory_descriptor: int, prefix: str, in_runtime_cache: bool) -> None:
        nonlocal actual_entry_count
        nonlocal actual_uncompressed_bytes
        nonlocal inventory_limit_exceeded
        nonlocal walk_failed
        if inventory_limit_exceeded:
            return
        try:
            with os.scandir(directory_descriptor) as iterator:
                names: list[str] = []
                remaining_entries = MAX_MANIFEST_FILES + 1 - actual_entry_count
                for entry in iterator:
                    names.append(entry.name)
                    if len(names) > remaining_entries:
                        inventory_limit_exceeded = True
                        return
        except (NotImplementedError, OSError, TypeError):
            walk_failed = True
            return
        for name in names:
            actual_entry_count += 1
            if actual_entry_count > MAX_MANIFEST_FILES + 1:
                inventory_limit_exceeded = True
                return
            relative = f"{prefix}/{name}" if prefix else name
            if canonical_relative_path(relative) is None:
                errors.append("package_directory_path_invalid")
                continue
            if package_secret_path_match_locations(relative):
                errors.append("package_directory_secret_path_rejected")
                continue
            try:
                metadata = os.stat(
                    name,
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except (NotImplementedError, OSError):
                walk_failed = True
                continue
            if stat.S_ISLNK(metadata.st_mode):
                errors.append("package_directory_symlink_rejected")
                continue
            if stat.S_ISDIR(metadata.st_mode):
                if strict_artifact and denied_path_reason(relative, artifact_type) is not None:
                    errors.append("package_directory_denied_path")
                    continue
                if strict_artifact:
                    if stat.S_IMODE(metadata.st_mode) not in SAFE_DIRECTORY_MODES:
                        errors.append("package_directory_mode_invalid")
                    if expected_file_paths is not None:
                        directory_prefix = relative + "/"
                        candidate_index = bisect_left(
                            expected_file_paths,
                            directory_prefix,
                        )
                        if (
                            candidate_index >= len(expected_file_paths)
                            or not expected_file_paths[candidate_index].startswith(
                                directory_prefix
                            )
                        ):
                            errors.append("package_directory_unexpected_directory")
                child_descriptor = -1
                try:
                    child_descriptor = os.open(
                        name,
                        directory_flags,
                        dir_fd=directory_descriptor,
                    )
                    opened_metadata = os.fstat(child_descriptor)
                    if (
                        not stat.S_ISDIR(opened_metadata.st_mode)
                        or directory_identity(metadata) != directory_identity(opened_metadata)
                    ):
                        walk_failed = True
                        continue
                    if root_resolution is not None:
                        try:
                            require_same_mount(
                                root_resolution,
                                child_descriptor,
                                relative,
                            )
                        except MountIdentityError:
                            errors.append(SECURE_MOUNT_IDENTITY_UNAVAILABLE)
                            continue
                        except (TypeError, ValueError):
                            errors.append("package_directory_nested_mount_rejected")
                            continue
                    walk(
                        child_descriptor,
                        relative,
                        in_runtime_cache or name in RUNTIME_CACHE_PARTS,
                    )
                except (NotImplementedError, OSError):
                    walk_failed = True
                finally:
                    if child_descriptor >= 0:
                        os.close(child_descriptor)
                continue
            if not stat.S_ISREG(metadata.st_mode):
                errors.append("package_directory_special_file_rejected")
                continue
            if strict_artifact:
                inode_identity = (metadata.st_dev, metadata.st_ino)
                if metadata.st_nlink != 1:
                    errors.append("package_directory_hardlink_rejected")
                if inode_identity in seen_regular_inodes:
                    errors.append("package_directory_duplicate_inode_rejected")
                seen_regular_inodes.add(inode_identity)
            if metadata.st_size > MAX_ARTIFACT_FILE_BYTES:
                errors.append("package_directory_file_size_limit_exceeded")
            if strict_artifact and denied_path_reason(relative, artifact_type) is not None:
                errors.append("package_directory_denied_path")
                continue
            if root_resolution is not None:
                opened = open_regular_descriptor(
                    directory_descriptor,
                    name,
                )
                if opened is None:
                    walk_failed = True
                    continue
                file_descriptor, opened_metadata = opened
                try:
                    if metadata_identity(metadata) != metadata_identity(opened_metadata):
                        walk_failed = True
                        continue
                    try:
                        require_same_mount(
                            root_resolution,
                            file_descriptor,
                            relative,
                        )
                    except MountIdentityError:
                        errors.append(SECURE_MOUNT_IDENTITY_UNAVAILABLE)
                        continue
                    except (TypeError, ValueError):
                        errors.append("package_directory_nested_mount_rejected")
                        continue
                finally:
                    os.close(file_descriptor)
            if not strict_artifact and (name == ".DS_Store" or in_runtime_cache):
                continue
            actual_uncompressed_bytes += metadata.st_size
            file_identities[relative] = metadata_identity(metadata)

    walk(root_descriptor, "", False)
    return (
        file_identities,
        actual_uncompressed_bytes,
        walk_failed,
        inventory_limit_exceeded,
        errors,
    )


def verify_directory(
    root: Path,
    *,
    strict_artifact: bool = False,
    expected_artifact_type: str | None = None,
) -> list[str]:
    directory_flags = secure_directory_flags()
    if directory_flags is None:
        return ["package_directory_secure_open_unavailable"]
    try:
        root_descriptor = os.open(root, directory_flags)
    except (NotImplementedError, OSError):
        return ["package_directory_root_invalid"]
    try:
        try:
            root_metadata = os.fstat(root_descriptor)
        except OSError:
            return ["package_directory_root_invalid"]
        if not stat.S_ISDIR(root_metadata.st_mode):
            return ["package_directory_root_invalid"]
        if strict_artifact and stat.S_IMODE(root_metadata.st_mode) not in SAFE_DIRECTORY_MODES:
            return ["package_directory_root_mode_invalid"]
        root_resolution: MountResolution | None = None
        if strict_artifact:
            try:
                root_resolution = resolve_mount_identity(
                    root_descriptor,
                    reconcile=True,
                )
                require_mount_assurance(root_resolution, READ_ONLY_EVIDENCE)
                require_same_mount(root_resolution, root_descriptor, ".")
            except MountIdentityError:
                return [SECURE_MOUNT_IDENTITY_UNAVAILABLE]
            except (TypeError, ValueError):
                return ["package_directory_mount_identity_invalid"]
        manifest_result = regular_file_bytes(
            root_descriptor,
            PACKAGE_MANIFEST_NAME,
            MAX_MANIFEST_BYTES,
            root_resolution,
        )
        if manifest_result is None:
            return ["package_manifest_missing_or_invalid"]
        manifest_data, manifest_mode, manifest_identity = manifest_result
        manifest, parse_errors = parse_manifest(manifest_data)
        if package_secret_match_locations(manifest_data, ".json"):
            parse_errors = [*parse_errors, "package_manifest_secret_content_rejected"]
        if manifest is None:
            return parse_errors
        entries, entry_errors = manifest_entries(manifest)
        errors = [*parse_errors, *entry_errors, *manifest_contract_errors(manifest)]
        schema_version = manifest.get("package_schema_version")
        artifact_type = (
            SOURCE_ARTIFACT
            if schema_version == LEGACY_PACKAGE_SCHEMA_VERSION
            else manifest.get("artifact_type")
        )
        if artifact_type not in ARTIFACT_TYPES:
            artifact_type = SOURCE_ARTIFACT
        if expected_artifact_type is not None and artifact_type != expected_artifact_type:
            errors.append("package_artifact_type_mismatch")
        if manifest_mode != "0644":
            errors.append("package_directory_manifest_mode_invalid")
        expected_files = {item["path"] for item in entries}
        expected_file_paths = tuple(sorted(expected_files))
        (
            initial_file_identities,
            actual_uncompressed_bytes,
            walk_failed,
            inventory_limit_exceeded,
            inventory_errors,
        ) = directory_inventory(
            root_descriptor,
            strict_artifact=strict_artifact,
            artifact_type=artifact_type,
            root_resolution=root_resolution,
            expected_file_paths=expected_file_paths if strict_artifact else None,
        )
        errors.extend(inventory_errors)
        actual_files = set(initial_file_identities) - {PACKAGE_MANIFEST_NAME}
        if initial_file_identities.get(PACKAGE_MANIFEST_NAME) != manifest_identity:
            errors.append("package_manifest_changed_during_verification")
        if walk_failed:
            errors.append("package_directory_inventory_unavailable")
        if inventory_limit_exceeded:
            errors.append("package_directory_entry_limit_exceeded")
        if actual_uncompressed_bytes > MAX_PACKAGE_UNCOMPRESSED_BYTES:
            errors.append("package_directory_size_limit_exceeded")
        if actual_files != expected_files:
            errors.append("package_manifest_file_set_mismatch")
        if (
            actual_uncompressed_bytes <= MAX_PACKAGE_UNCOMPRESSED_BYTES
            and not inventory_limit_exceeded
        ):
            remaining_bytes = MAX_PACKAGE_UNCOMPRESSED_BYTES - len(manifest_data)
            for index, item in enumerate(entries, start=1):
                per_file_budget = min(
                    MAX_ARTIFACT_FILE_BYTES,
                    max(0, remaining_bytes),
                )
                (
                    digest,
                    bytes_read,
                    actual_mode,
                    opened_identity,
                    nested_zip,
                    secret_content,
                ) = regular_file_evidence(
                    root_descriptor,
                    item["path"],
                    per_file_budget,
                    root_resolution,
                )
                remaining_bytes = max(0, remaining_bytes - bytes_read)
                if nested_zip:
                    errors.append(f"package_file_nested_zip_rejected=index-{index}")
                if secret_content:
                    errors.append(f"package_file_secret_content_rejected=index-{index}")
                if digest is None:
                    errors.append(f"package_file_unreadable_or_oversized=index-{index}")
                    continue
                if opened_identity != initial_file_identities.get(item["path"]):
                    errors.append(f"package_file_changed_during_verification=index-{index}")
                if actual_mode != item["mode"]:
                    errors.append(f"package_file_mode_mismatch=index-{index}")
                if digest != item["sha256"]:
                    errors.append(f"package_file_digest_mismatch=index-{index}")
        plugin_path = (
            ".codex-plugin/plugin.json"
            if artifact_type == PLUGIN_ARTIFACT
            else "plugins/codexqb/.codex-plugin/plugin.json"
        )
        if plugin_path not in expected_files:
            errors.append("package_plugin_manifest_missing")
        else:
            plugin_result = regular_file_bytes(
                root_descriptor,
                plugin_path,
                MAX_MANIFEST_BYTES,
                root_resolution,
            )
            if plugin_result is None:
                errors.append("package_plugin_manifest_invalid")
            else:
                errors.extend(
                    plugin_manifest_payload_errors(
                        plugin_result[0],
                        plugin_version=manifest.get("plugin_version"),
                        artifact_type=artifact_type,
                        packaged_files=expected_files,
                    )
                )
        if artifact_type == PLUGIN_ARTIFACT:
            runtime_payloads: dict[str, bytes | None] = {}
            for runtime_path in (PLUGIN_SKILL_PATH, PLUGIN_ACTIVATION_PATH):
                if runtime_path not in expected_files:
                    runtime_payloads[runtime_path] = None
                    continue
                runtime_result = regular_file_bytes(
                    root_descriptor,
                    runtime_path,
                    MAX_MANIFEST_BYTES,
                    root_resolution,
                )
                if runtime_result is None:
                    errors.append("package_plugin_runtime_metadata_invalid")
                    runtime_payloads[runtime_path] = None
                else:
                    runtime_payloads[runtime_path] = runtime_result[0]
            errors.extend(
                plugin_skill_contract_errors(runtime_payloads.get(PLUGIN_SKILL_PATH))
            )
            errors.extend(
                plugin_activation_contract_errors(
                    runtime_payloads.get(PLUGIN_ACTIVATION_PATH)
                )
            )
        try:
            final_root_metadata = os.stat(root, follow_symlinks=False)
        except (NotImplementedError, OSError):
            errors.append("package_directory_root_changed")
        else:
            if (
                not stat.S_ISDIR(final_root_metadata.st_mode)
                or directory_identity(final_root_metadata)
                != directory_identity(root_metadata)
            ):
                errors.append("package_directory_root_changed")
            elif strict_artifact and stat.S_IMODE(
                final_root_metadata.st_mode
            ) not in SAFE_DIRECTORY_MODES:
                errors.append("package_directory_root_mode_invalid")
        final_root_descriptor = -1
        try:
            final_root_descriptor = os.open(root, directory_flags)
            reopened_root_metadata = os.fstat(final_root_descriptor)
            if (
                not stat.S_ISDIR(reopened_root_metadata.st_mode)
                or directory_identity(reopened_root_metadata)
                != directory_identity(root_metadata)
            ):
                errors.append("package_directory_root_changed")
            elif strict_artifact and stat.S_IMODE(
                reopened_root_metadata.st_mode
            ) not in SAFE_DIRECTORY_MODES:
                errors.append("package_directory_root_mode_invalid")
            elif root_resolution is not None:
                try:
                    require_same_mount(
                        root_resolution,
                        final_root_descriptor,
                        ".",
                    )
                except MountIdentityError:
                    errors.append(SECURE_MOUNT_IDENTITY_UNAVAILABLE)
                except (TypeError, ValueError):
                    errors.append("package_directory_root_mount_changed")
        except (NotImplementedError, OSError):
            errors.append("package_directory_root_changed")
        finally:
            if final_root_descriptor >= 0:
                os.close(final_root_descriptor)
        if not inventory_limit_exceeded:
            (
                final_file_identities,
                final_uncompressed_bytes,
                final_walk_failed,
                final_inventory_limit_exceeded,
                final_inventory_errors,
            ) = directory_inventory(
                root_descriptor,
                strict_artifact=strict_artifact,
                artifact_type=artifact_type,
                root_resolution=root_resolution,
                expected_file_paths=expected_file_paths if strict_artifact else None,
            )
            errors.extend(final_inventory_errors)
            if final_walk_failed:
                errors.append("package_directory_inventory_unavailable")
            if final_inventory_limit_exceeded:
                errors.append("package_directory_entry_limit_exceeded")
            if (
                final_file_identities != initial_file_identities
                or final_uncompressed_bytes != actual_uncompressed_bytes
            ):
                errors.append("package_directory_changed_during_verification")
        completion_root_descriptor = -1
        try:
            completion_root_descriptor = os.open(root, directory_flags)
            completion_root_metadata = os.fstat(completion_root_descriptor)
            if (
                not stat.S_ISDIR(completion_root_metadata.st_mode)
                or directory_identity(completion_root_metadata)
                != directory_identity(root_metadata)
            ):
                errors.append("package_directory_root_changed")
            elif strict_artifact and stat.S_IMODE(
                completion_root_metadata.st_mode
            ) not in SAFE_DIRECTORY_MODES:
                errors.append("package_directory_root_mode_invalid")
            elif root_resolution is not None:
                try:
                    require_same_mount(
                        root_resolution,
                        completion_root_descriptor,
                        ".",
                    )
                except MountIdentityError:
                    errors.append(SECURE_MOUNT_IDENTITY_UNAVAILABLE)
                except (TypeError, ValueError):
                    errors.append("package_directory_root_mount_changed")
        except (NotImplementedError, OSError):
            errors.append("package_directory_root_changed")
        finally:
            if completion_root_descriptor >= 0:
                os.close(completion_root_descriptor)
        return list(dict.fromkeys(errors))
    finally:
        os.close(root_descriptor)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify CodexQB package manifest integrity.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--zip", dest="zip_path")
    group.add_argument("--root")
    parser.add_argument("--strict-artifact", action="store_true")
    parser.add_argument(
        "--expected-artifact-type",
        choices=sorted(ARTIFACT_TYPES),
    )
    args = parser.parse_args(argv)
    errors = (
        verify_zip(
            Path(args.zip_path),
            expected_artifact_type=args.expected_artifact_type,
        )
        if args.zip_path
        else verify_directory(
            Path(args.root),
            strict_artifact=args.strict_artifact,
            expected_artifact_type=args.expected_artifact_type,
        )
    )
    if errors:
        print("package_manifest_verification=failed")
        for error in errors:
            print(error)
        return 1
    print("package_manifest_verification=passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
