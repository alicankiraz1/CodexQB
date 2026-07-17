#!/usr/bin/env python3
"""Shared, dependency-free CodexQB package layout and denylist policy."""

from __future__ import annotations

import io
import json
from pathlib import PurePosixPath
import unicodedata
import zipfile


PACKAGE_MANIFEST_NAME = "PACKAGE-MANIFEST.json"
LEGACY_PACKAGE_SCHEMA_VERSION = 2
PACKAGE_SCHEMA_VERSION = 3
LAYOUT_VERSION = 1
MAX_ARTIFACT_FILE_BYTES = 64 * 1024 * 1024
MAX_CANONICAL_ZIP_MEMBERS = 0xFFFE
MAX_PACKAGE_ARCHIVE_BYTES = 576 * 1024 * 1024
MAX_PACKAGE_CENTRAL_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_ARTIFACT_PATH_BYTES = 4096
MAX_ARTIFACT_PATH_COMPONENTS = 64
MAX_ARTIFACT_COMPONENT_BYTES = 255

PLUGIN_ARTIFACT = "plugin"
SOURCE_ARTIFACT = "source"
ARTIFACT_TYPES = {PLUGIN_ARTIFACT, SOURCE_ARTIFACT}

# These files are local-checkout controllers, not package payload.  An
# extracted tree is evidence consumed by the trusted outer launcher and must
# never carry a self-validation entry point that can be mistaken for authority.
SOURCE_CONTROLLER_ONLY_PATHS = frozenset(
    {
        "scripts/run_extracted_validation.py",
        "scripts/validate.sh",
    }
)
SOURCE_FORBIDDEN_CONTROLLER_PATHS = frozenset(
    {
        *SOURCE_CONTROLLER_ONLY_PATHS,
        # Reserved permanently: repo-owned HMAC/source-authority issuance was
        # removed because same-UID repository code cannot protect such a key.
        "scripts/issue_trusted_source_authority.py",
    }
)
_SOURCE_CONTROLLER_ONLY_FOLDED_PATHS = frozenset(
    path.casefold() for path in SOURCE_FORBIDDEN_CONTROLLER_PATHS
)

PLUGIN_SOURCE_PREFIX = "plugins/codexqb/"
SOURCE_ARCHIVE_PREFIX = "CodexQB/"
PLUGIN_SKILL_PATH = "skills/codexqb/SKILL.md"
PLUGIN_ACTIVATION_PATH = "skills/codexqb/agents/openai.yaml"

COMMON_DENIED_PARTS = {
    ".git",
    ".codexqb",
    "__macosx",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".cache",
    ".tox",
    ".venv",
    "artifacts",
    "build",
    "dist",
    "logs",
    "node_modules",
    "tmp",
    "venv",
}
COMMON_DENIED_SUFFIXES = {".pyc", ".pem", ".key", ".tmp", ".zip"}
PLUGIN_ALLOWED_TOP_LEVEL = {
    ".codex-plugin",
    "skills",
    PACKAGE_MANIFEST_NAME,
}
PLUGIN_MANIFEST_ALLOWED_KEYS = {
    "name",
    "version",
    "description",
    "author",
    "homepage",
    "repository",
    "license",
    "keywords",
    "skills",
    "interface",
}
ZIP_MAGICS = (
    b"PK\x01\x02",  # central directory entry
    b"PK\x03\x04",  # local file header
    b"PK\x05\x05",  # digital signature
    b"PK\x05\x06",  # end of central directory
    b"PK\x06\x06",  # ZIP64 end of central directory
    b"PK\x06\x07",  # ZIP64 end locator
    b"PK\x06\x08",  # archive extra-data record
    b"PK\x07\x08",  # data descriptor / spanning marker
)
WINDOWS_ILLEGAL_CHARACTERS = frozenset('<>:"|?*')
WINDOWS_RESERVED_BASENAMES = {
    "aux",
    "con",
    "nul",
    "prn",
    *(f"com{index}" for index in range(1, 10)),
    *(f"lpt{index}" for index in range(1, 10)),
    *(f"com{index}" for index in ("¹", "²", "³")),
    *(f"lpt{index}" for index in ("¹", "²", "³")),
}


def canonical_relative_path(value: object) -> str | None:
    """Return one NFC-normalized portable relative path or ``None``."""

    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > MAX_ARTIFACT_PATH_BYTES:
        return None
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or len(path.parts) > MAX_ARTIFACT_PATH_COMPONENTS
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        return None
    for part in path.parts:
        try:
            part_bytes = part.encode("utf-8")
        except UnicodeEncodeError:
            return None
        if (
            len(part_bytes) > MAX_ARTIFACT_COMPONENT_BYTES
            or part.endswith((" ", "."))
            or any(character in WINDOWS_ILLEGAL_CHARACTERS for character in part)
            or any(ord(character) < 32 for character in part)
            or part.split(".", 1)[0].casefold() in WINDOWS_RESERVED_BASENAMES
        ):
            return None
    canonical = path.as_posix()
    if canonical != value or unicodedata.normalize("NFC", canonical) != canonical:
        return None
    return canonical


def archive_prefix(artifact_type: str) -> str:
    if artifact_type == PLUGIN_ARTIFACT:
        return ""
    if artifact_type == SOURCE_ARTIFACT:
        return SOURCE_ARCHIVE_PREFIX
    raise ValueError("package_artifact_type_invalid")


def manifest_member(artifact_type: str) -> str:
    return f"{archive_prefix(artifact_type)}{PACKAGE_MANIFEST_NAME}"


def source_to_artifact_path(source_path: str, artifact_type: str) -> str | None:
    """Map a repository-relative path into one artifact-relative path."""

    canonical = canonical_relative_path(source_path)
    if canonical is None:
        raise ValueError("package_manifest_preflight_failed=path_not_portable")
    if artifact_type == SOURCE_ARTIFACT:
        if source_controller_path(canonical):
            return None
        return canonical
    if artifact_type != PLUGIN_ARTIFACT:
        raise ValueError("package_artifact_type_invalid")
    if not canonical.startswith(PLUGIN_SOURCE_PREFIX):
        return None
    mapped = canonical.removeprefix(PLUGIN_SOURCE_PREFIX)
    if canonical_relative_path(mapped) is None:
        raise ValueError("package_plugin_path_invalid")
    return mapped


def denied_path_reason(path: str, artifact_type: str) -> str | None:
    """Return a stable reason when an artifact-relative path is forbidden."""

    canonical = canonical_relative_path(path)
    if canonical is None:
        return "path_not_portable"
    if artifact_type == SOURCE_ARTIFACT and source_controller_path(canonical):
        return "source_controller_path"
    pure = PurePosixPath(canonical)
    folded_parts = tuple(part.casefold() for part in pure.parts)
    folded_name = pure.name.casefold()
    if COMMON_DENIED_PARTS.intersection(folded_parts):
        return "denied_component"
    if any(
        part.startswith(".env")
        or part.endswith(".local")
        or ".local." in part
        for part in folded_parts
    ):
        return "denied_component"
    if (
        folded_name == ".ds_store"
        or folded_name.startswith("._")
        or folded_name.startswith(".env")
    ):
        return "denied_filename"
    if folded_name.endswith(".local") or ".local." in folded_name:
        return "denied_filename"
    if pure.suffix.casefold() in COMMON_DENIED_SUFFIXES:
        return "denied_suffix"
    if artifact_type == PLUGIN_ARTIFACT:
        top = folded_parts[0]
        if top == ".github" or top == ".agents" or top in {"docs", "tests", "evals"}:
            return "plugin_non_runtime_path"
        if pure.parts[0] not in PLUGIN_ALLOWED_TOP_LEVEL:
            return "plugin_non_runtime_path"
        if top == ".codex-plugin" and canonical not in {
            ".codex-plugin",
            ".codex-plugin/plugin.json",
        }:
            return "plugin_manifest_path_invalid"
        if top == "skills" and canonical != "skills" and (
            len(pure.parts) < 2 or pure.parts[1] != "codexqb"
        ):
            return "plugin_skill_tree_invalid"
    elif artifact_type != SOURCE_ARTIFACT:
        return "artifact_type_invalid"
    return None


def source_controller_path(path: str) -> bool:
    """Return whether a portable source path aliases controller-only code.

    Portable package policy is intentionally stricter than the current host's
    filesystem.  A case-only alias that is distinct on Linux aliases the
    controller entrypoint on default macOS and Windows filesystems, so it must
    be denied at export, ZIP verification, extraction, and root verification.
    """

    canonical = canonical_relative_path(path)
    return (
        canonical is not None
        and canonical.casefold() in _SOURCE_CONTROLLER_ONLY_FOLDED_PATHS
    )


def payload_has_zip_magic(data: bytes | bytearray) -> bool:
    return any(data.startswith(magic) for magic in ZIP_MAGICS)


def payload_is_zip_archive(data: bytes | bytearray) -> bool:
    """Recognize ZIP records and valid ZIP polyglots, including ZIP64."""

    if payload_has_zip_magic(data):
        return True
    try:
        return zipfile.is_zipfile(io.BytesIO(data))
    except (OSError, ValueError):
        return False


def plugin_skill_contract_errors(data: bytes | None) -> list[str]:
    """Validate the canonical, invokable CodexQB skill frontmatter."""

    if data is None:
        return ["package_plugin_skills_missing"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["package_plugin_skill_frontmatter_invalid"]
    if "\x00" in text or "\r" in text or "\t" in text:
        return ["package_plugin_skill_frontmatter_invalid"]
    lines = text.split("\n")
    if len(lines) < 5 or lines[0] != "---" or lines[3] != "---":
        return ["package_plugin_skill_frontmatter_invalid"]
    errors: list[str] = []
    if lines[1] != "name: codexqb":
        errors.append("package_plugin_skill_name_invalid")
    description_prefix = "description: "
    if not lines[2].startswith(description_prefix):
        errors.append("package_plugin_skill_description_invalid")
    else:
        description = lines[2].removeprefix(description_prefix)
        if (
            not description
            or len(description) > 512
            or any(ord(character) < 32 for character in description)
        ):
            errors.append("package_plugin_skill_description_invalid")
    if not any(line.strip() for line in lines[4:]):
        errors.append("package_plugin_skill_body_missing")
    return errors


def _canonical_quoted_scalar(value: str) -> str | None:
    value = value.strip()
    if not value.startswith('"') or "\\u" in value.casefold():
        return None
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    if (
        not isinstance(parsed, str)
        or not parsed
        or any(
            ord(character) < 0x20
            or 0x7F <= ord(character) <= 0x9F
            or 0xD800 <= ord(character) <= 0xDFFF
            for character in parsed
        )
    ):
        return None
    return parsed


def plugin_activation_contract_errors(data: bytes | None) -> list[str]:
    """Validate canonical activation metadata and its explicit-only policy."""

    if data is None:
        return ["package_plugin_activation_missing"]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return ["package_plugin_activation_invalid"]
    if "\x00" in text or "\r" in text:
        return ["package_plugin_activation_invalid"]
    records: list[str] = []
    for line in text.split("\n"):
        if "\t" in line:
            return ["package_plugin_activation_invalid"]
        line = line.rstrip(" ")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        records.append(line)
    if len(records) != 6:
        return ["package_plugin_activation_invalid"]
    if records[0] != "interface:" or records[4] != "policy:":
        return ["package_plugin_activation_invalid"]
    if records[5] != "  allow_implicit_invocation: false":
        return ["package_plugin_implicit_invocation_not_disabled"]
    values: dict[str, str] = {}
    for index, key in (
        (1, "display_name"),
        (2, "short_description"),
        (3, "default_prompt"),
    ):
        prefix = f"  {key}:"
        record = records[index]
        if not record.startswith(prefix):
            return ["package_plugin_activation_invalid"]
        raw_value = record[len(prefix) :]
        if raw_value and not raw_value.startswith(" "):
            return ["package_plugin_activation_invalid"]
        parsed = _canonical_quoted_scalar(raw_value)
        if parsed is None:
            return ["package_plugin_activation_invalid"]
        values[key] = parsed
    if (
        values["display_name"] != "CodexQB"
        or len(values["short_description"]) > 80
        or "$codexqb" not in values["default_prompt"]
        or len(values["default_prompt"]) > 220
    ):
        return ["package_plugin_activation_invalid"]
    return []


def default_artifact_filename(
    artifact_type: str,
    plugin_version: str,
    export_mode: str,
) -> str:
    if artifact_type not in ARTIFACT_TYPES:
        raise ValueError("package_artifact_type_invalid")
    stem = (
        f"codexqb-plugin-{plugin_version}"
        if artifact_type == PLUGIN_ARTIFACT
        else f"CodexQB-source-{plugin_version}"
    )
    suffix = {
        "strict_release": "",
        "worktree": "-worktree",
        "source_package": "-filesystem",
    }.get(export_mode)
    if suffix is None:
        raise ValueError("package_export_mode_invalid")
    return f"{stem}{suffix}.zip"
