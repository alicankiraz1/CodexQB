from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
import zipfile
from bisect import bisect_left as stdlib_bisect_left
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from tests.test_export_sanitized import (
    EXPORT_MODULE,
    VALID_PLUGIN_ACTIVATION,
    VALID_PLUGIN_SKILL,
    git,
    git_commit_all,
    valid_empty_zip64,
    valid_zip_polyglot,
    write_minimal_codexqb_tree,
)


REPO_ROOT = Path(__file__).resolve().parents[1]
VERIFIER = REPO_ROOT / "scripts/verify_package_manifest.py"
MANIFEST_MEMBER = "CodexQB/PACKAGE-MANIFEST.json"


def load_verifier_module():
    spec = importlib.util.spec_from_file_location("codexqb_verify_package_manifest", VERIFIER)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load package verifier from {VERIFIER}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


VERIFY_MODULE = load_verifier_module()
PACKAGE_SAFETY = sys.modules[VERIFY_MODULE.package_secret_match_locations.__module__]


def create_source_package(base: Path, *, git_checkout: bool = False) -> tuple[Path, Path]:
    root = base / "source"
    root.mkdir()
    if git_checkout:
        git(root, "init")
    write_minimal_codexqb_tree(root)
    if git_checkout:
        git_commit_all(root)
    output = base / "CodexQB-source-package.zip"
    EXPORT_MODULE.create_zip(root, output, source_package=True)
    return root, output


def create_plugin_package(base: Path) -> tuple[Path, Path]:
    root = base / "plugin-source"
    root.mkdir()
    write_minimal_codexqb_tree(root)
    (root / "plugins/codexqb/.codex-plugin/plugin.json").write_text(
        json.dumps(
            {
                "name": "codexqb",
                "version": "0.3.0",
                "skills": "./skills/",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    skill = root / "plugins/codexqb/skills/codexqb/SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text(VALID_PLUGIN_SKILL, encoding="utf-8")
    activation = root / "plugins/codexqb/skills/codexqb/agents/openai.yaml"
    activation.parent.mkdir()
    activation.write_text(VALID_PLUGIN_ACTIVATION, encoding="utf-8")
    output = base / "codexqb-plugin-0.3.0.zip"
    EXPORT_MODULE.create_zip(
        root,
        output,
        source_package=True,
        artifact_type="plugin",
    )
    return root, output


def extract_with_modes(archive_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(destination)
        for info in archive.infolist():
            if info.is_dir():
                continue
            (destination / info.filename).chmod(stat.S_IMODE(info.external_attr >> 16))


def extracted_package(base: Path) -> tuple[Path, Path]:
    _root, output = create_source_package(base)
    extracted = base / "extracted"
    extract_with_modes(output, extracted)
    return output, extracted / "CodexQB"


def rewrite_zip(
    source: Path,
    destination: Path,
    *,
    replacements: dict[str, bytes] | None = None,
    appended: list[tuple[zipfile.ZipInfo, bytes]] | None = None,
) -> None:
    replacements = replacements or {}
    appended = appended or []
    with zipfile.ZipFile(source) as original, zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as rewritten:
        for info in original.infolist():
            rewritten.writestr(info, replacements.get(info.filename, original.read(info.filename)))
        for info, data in appended:
            rewritten.writestr(info, data)


def manifest_bytes_with_mutation(source: Path, mutate) -> bytes:
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read(MANIFEST_MEMBER).decode("utf-8"))
    mutate(manifest)
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def rewrite_manifest_bound_file(
    source: Path,
    destination: Path,
    *,
    artifact_type: str,
    relative_path: str,
    data: bytes,
) -> None:
    prefix = "" if artifact_type == "plugin" else "CodexQB/"
    manifest_member = f"{prefix}PACKAGE-MANIFEST.json"
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read(manifest_member).decode("utf-8"))
        payloads = {
            info.filename: archive.read(info)
            for info in archive.infolist()
        }
    entry = next(
        item for item in manifest["files"] if item["path"] == relative_path
    )
    entry["sha256"] = hashlib.sha256(data).hexdigest()
    encoded = json.dumps(
        manifest["files"],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest["tree_sha256"] = hashlib.sha256(encoded).hexdigest()
    manifest["content_sha256"] = manifest["tree_sha256"]
    with zipfile.ZipFile(
        destination,
        "w",
        compression=zipfile.ZIP_STORED,
    ) as rewritten:
        for item in manifest["files"]:
            path = item["path"]
            payload = data if path == relative_path else payloads[f"{prefix}{path}"]
            rewritten.writestr(
                EXPORT_MODULE.zip_file_info(
                    f"{prefix}{path}",
                    int(item["mode"], 8),
                ),
                payload,
            )
        rewritten.writestr(
            EXPORT_MODULE.zip_file_info(manifest_member, 0o644),
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )


def append_manifest_bound_file(
    source: Path,
    destination: Path,
    *,
    artifact_type: str,
    relative_path: str,
    data: bytes,
    mode: str = "0644",
) -> None:
    prefix = "" if artifact_type == "plugin" else "CodexQB/"
    manifest_member = f"{prefix}PACKAGE-MANIFEST.json"
    with zipfile.ZipFile(source) as archive:
        manifest = json.loads(archive.read(manifest_member).decode("utf-8"))
        payloads = {
            info.filename: archive.read(info)
            for info in archive.infolist()
        }
    manifest["files"].append(
        {
            "path": relative_path,
            "sha256": hashlib.sha256(data).hexdigest(),
            "mode": mode,
        }
    )
    manifest["files"].sort(key=lambda item: item["path"])
    manifest["file_count"] = len(manifest["files"])
    encoded = json.dumps(
        manifest["files"],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    manifest["tree_sha256"] = hashlib.sha256(encoded).hexdigest()
    manifest["content_sha256"] = manifest["tree_sha256"]
    payloads[f"{prefix}{relative_path}"] = data
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_STORED) as rewritten:
        for item in manifest["files"]:
            path = item["path"]
            rewritten.writestr(
                EXPORT_MODULE.zip_file_info(
                    f"{prefix}{path}",
                    int(item["mode"], 8),
                ),
                payloads[f"{prefix}{path}"],
            )
        rewritten.writestr(
            EXPORT_MODULE.zip_file_info(manifest_member, 0o644),
            (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        )


def create_legacy_v2_package(base: Path) -> Path:
    """Create the canonical legacy manifest fixture without relaxing ZIP bytes."""

    _root, output = create_source_package(base)
    legacy = base / "legacy-v2.zip"

    def legacy_manifest(manifest: dict[str, object]) -> None:
        manifest["package_schema_version"] = 2
        manifest.pop("artifact_type")
        manifest.pop("layout_version")
        manifest.pop("content_sha256")

    rewrite_zip(
        output,
        legacy,
        replacements={
            MANIFEST_MEMBER: manifest_bytes_with_mutation(output, legacy_manifest)
        },
    )
    return legacy


def write_sparse_zip_envelope(
    path: Path,
    *,
    entry_count: int,
    central_directory_size: int,
) -> None:
    """Write an EOCD-consistent sparse input for parser-before-budget tests."""

    central_directory_offset = 4
    with path.open("wb") as handle:
        handle.write(b"PK\x03\x04")
        handle.seek(central_directory_offset + central_directory_size)
        handle.write(
            struct.pack(
                "<IHHHHIIH",
                0x06054B50,
                0,
                0,
                entry_count,
                entry_count,
                central_directory_size,
                central_directory_offset,
                0,
            )
        )


class PackageManifestTests(unittest.TestCase):
    def test_source_package_verifies_as_zip_and_extracted_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output, extracted = extracted_package(Path(temp_dir))

            self.assertEqual(VERIFY_MODULE.verify_zip(output), [])
            self.assertEqual(VERIFY_MODULE.verify_directory(extracted), [])
            self.assertEqual(
                VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="source",
                ),
                [],
            )

    def test_shared_policy_rejects_regression_paths_for_each_artifact_type(self) -> None:
        for path in (
            ".git/config",
            "__MACOSX/metadata",
            ".DS_Store",
            "._README.md",
            ".cache/payload.bin",
            ".env/credentials.txt",
            "config.local/credentials.txt",
            "__pycache__/module.py",
            "module.pyc",
            "node_modules/package/index.js",
            "scratch.tmp",
            "tmp/cache.txt",
            "nested.ZIP",
            ".git./config",
            "trailing-dot./file.txt",
            "trailing-space /file.txt",
            "CON.txt",
            "COM¹.txt",
            "COM²",
            "COM³.log",
            "LPT¹.txt",
            "LPT²",
            "LPT³.log",
            "illegal:name.txt",
        ):
            with self.subTest(artifact_type="source", path=path):
                self.assertIsNotNone(
                    VERIFY_MODULE.denied_path_reason(path, "source")
                )
        for path in (
            "._plugin.json",
            ".env/credentials.txt",
            ".github/workflows/validate.yml",
            ".agents/plugins/marketplace.json",
            ".mcp.json",
            "hooks/preflight.json",
            "README.md",
            "docs/MAINTAINING.md",
            "scripts/activate.py",
            "skills/evil/SKILL.md",
            "tests/test_plugin.py",
        ):
            with self.subTest(artifact_type="plugin", path=path):
                self.assertIsNotNone(
                    VERIFY_MODULE.denied_path_reason(path, "plugin")
                )

    def test_portable_paths_have_bounded_depth_and_encoded_lengths(self) -> None:
        self.assertIsNone(
            VERIFY_MODULE.canonical_relative_path("/".join(["a"] * 65))
        )
        self.assertIsNone(
            VERIFY_MODULE.canonical_relative_path("/".join(["a" * 64] * 64))
        )
        self.assertIsNone(
            VERIFY_MODULE.canonical_relative_path("a" * 256)
        )
        self.assertIsNone(VERIFY_MODULE.canonical_relative_path("bad-\ud800"))
        self.assertEqual(
            VERIFY_MODULE.canonical_relative_path("skills/codexqb/SKILL.md"),
            "skills/codexqb/SKILL.md",
        )

    def test_plugin_package_verifies_after_real_extraction_with_manifest_parity(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_plugin_package(base)
            extracted = base / "plugin-extracted"
            extract_with_modes(output, extracted)

            self.assertEqual(
                VERIFY_MODULE.verify_zip(
                    output,
                    expected_artifact_type="plugin",
                ),
                [],
            )
            self.assertEqual(
                VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="plugin",
                ),
                [],
            )
            package_manifest = json.loads(
                (extracted / "PACKAGE-MANIFEST.json").read_text(encoding="utf-8")
            )
            plugin_manifest = json.loads(
                (extracted / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                package_manifest["plugin_version"],
                plugin_manifest["version"],
            )

    def test_strict_plugin_root_rejects_unexpected_empty_directories(self) -> None:
        for label, relative in (
            ("skill-subtree", "skills/codexqb/unexpected-empty"),
            ("activation-subtree", "skills/codexqb/agents/unexpected-empty"),
        ):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, output = create_plugin_package(base)
                extracted = base / "plugin-extracted"
                extract_with_modes(output, extracted)
                (extracted / relative).mkdir()

                self.assertIn(
                    "package_directory_unexpected_directory",
                    VERIFY_MODULE.verify_directory(
                        extracted,
                        strict_artifact=True,
                        expected_artifact_type="plugin",
                    ),
                )

    def test_strict_plugin_root_rejects_world_writable_expected_directories(self) -> None:
        for relative in (
            ".codex-plugin",
            "skills",
            "skills/codexqb",
            "skills/codexqb/agents",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, output = create_plugin_package(base)
                extracted = base / "plugin-extracted"
                extract_with_modes(output, extracted)
                (extracted / relative).chmod(0o777)

                self.assertIn(
                    "package_directory_mode_invalid",
                    VERIFY_MODULE.verify_directory(
                        extracted,
                        strict_artifact=True,
                        expected_artifact_type="plugin",
                    ),
                )

    def test_strict_plugin_root_accepts_restrictive_expected_directory_modes(self) -> None:
        expected_directories = (
            ".codex-plugin",
            "skills",
            "skills/codexqb",
            "skills/codexqb/agents",
        )
        for mode in (0o700, 0o750, 0o755):
            with self.subTest(mode=oct(mode)), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, output = create_plugin_package(base)
                extracted = base / "plugin-extracted"
                extract_with_modes(output, extracted)
                extracted.chmod(mode)
                for relative in expected_directories:
                    (extracted / relative).chmod(mode)

                self.assertEqual(
                    VERIFY_MODULE.verify_directory(
                        extracted,
                        strict_artifact=True,
                        expected_artifact_type="plugin",
                    ),
                    [],
                )

    def test_strict_plugin_root_accepts_safe_root_modes_and_rejects_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_plugin_package(base)
            extracted = base / "plugin-extracted"
            extract_with_modes(output, extracted)

            for mode in (0o700, 0o755):
                with self.subTest(mode=oct(mode)):
                    extracted.chmod(mode)
                    self.assertEqual(
                        VERIFY_MODULE.verify_directory(
                            extracted,
                            strict_artifact=True,
                            expected_artifact_type="plugin",
                        ),
                        [],
                    )

            extracted.chmod(0o777)
            self.assertIn(
                "package_directory_root_mode_invalid",
                VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="plugin",
                ),
            )

    def test_plugin_verifier_requires_metadata_and_the_invokable_skill_entry(self) -> None:
        missing_metadata_errors = VERIFY_MODULE.plugin_manifest_payload_errors(
            b'{"version":"0.3.0"}',
            plugin_version="0.3.0",
            artifact_type="plugin",
            packaged_files={"skills/codexqb/SKILL.md"},
        )
        self.assertIn("package_plugin_name_invalid", missing_metadata_errors)
        self.assertIn("package_plugin_skills_path_invalid", missing_metadata_errors)

        unexpected_surface_errors = VERIFY_MODULE.plugin_manifest_payload_errors(
            b'{"name":"codexqb","version":"0.3.0","skills":"./skills/",'
            b'"hooks":"./hooks/"}',
            plugin_version="0.3.0",
            artifact_type="plugin",
            packaged_files={
                "skills/codexqb/SKILL.md",
                "skills/codexqb/agents/openai.yaml",
            },
        )
        self.assertIn(
            "package_plugin_manifest_fields_invalid",
            unexpected_surface_errors,
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_plugin_package(base)
            tampered = base / "junk-only-plugin.zip"
            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(
                    archive.read("PACKAGE-MANIFEST.json").decode("utf-8")
                )
                payloads = {
                    info.filename: archive.read(info)
                    for info in archive.infolist()
                }
            skill_entry = next(
                item
                for item in manifest["files"]
                if item["path"] == "skills/codexqb/SKILL.md"
            )
            skill_entry["path"] = "skills/junk.txt"
            skill_entry["sha256"] = hashlib.sha256(b"not invokable\n").hexdigest()
            manifest["files"].sort(key=lambda item: item["path"])
            encoded = json.dumps(
                manifest["files"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest["tree_sha256"] = hashlib.sha256(encoded).hexdigest()
            manifest["content_sha256"] = manifest["tree_sha256"]
            with zipfile.ZipFile(
                tampered,
                "w",
                compression=zipfile.ZIP_STORED,
            ) as rewritten:
                for item in manifest["files"]:
                    path = item["path"]
                    data = (
                        b"not invokable\n"
                        if path == "skills/junk.txt"
                        else payloads[path]
                    )
                    rewritten.writestr(
                        EXPORT_MODULE.zip_file_info(path, int(item["mode"], 8)),
                        data,
                    )
                rewritten.writestr(
                    EXPORT_MODULE.zip_file_info("PACKAGE-MANIFEST.json", 0o644),
                    (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode(
                        "utf-8"
                    ),
                )

            self.assertIn(
                "package_plugin_skills_missing",
                VERIFY_MODULE.verify_zip(
                    tampered,
                    expected_artifact_type="plugin",
                ),
            )

            invalid_skill = base / "invalid-skill.zip"
            rewrite_manifest_bound_file(
                output,
                invalid_skill,
                artifact_type="plugin",
                relative_path="skills/codexqb/SKILL.md",
                data=b"not frontmatter\n",
            )
            self.assertIn(
                "package_plugin_skill_frontmatter_invalid",
                VERIFY_MODULE.verify_zip(
                    invalid_skill,
                    expected_artifact_type="plugin",
                ),
            )
            invalid_skill_root = base / "invalid-skill-root"
            extract_with_modes(invalid_skill, invalid_skill_root)
            self.assertIn(
                "package_plugin_skill_frontmatter_invalid",
                VERIFY_MODULE.verify_directory(
                    invalid_skill_root,
                    strict_artifact=True,
                    expected_artifact_type="plugin",
                ),
            )

            implicit_activation = base / "implicit-activation.zip"
            rewrite_manifest_bound_file(
                output,
                implicit_activation,
                artifact_type="plugin",
                relative_path="skills/codexqb/agents/openai.yaml",
                data=VALID_PLUGIN_ACTIVATION.replace(
                    "allow_implicit_invocation: false",
                    "allow_implicit_invocation: true",
                ).encode("utf-8"),
            )
            self.assertIn(
                "package_plugin_implicit_invocation_not_disabled",
                VERIFY_MODULE.verify_zip(
                    implicit_activation,
                    expected_artifact_type="plugin",
                ),
            )

    def test_plugin_zip_and_extracted_root_reject_extra_skill_and_auto_surface(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_plugin_package(base)
            extra_skill = base / "extra-skill.zip"
            append_manifest_bound_file(
                output,
                extra_skill,
                artifact_type="plugin",
                relative_path="skills/evil/SKILL.md",
                data=VALID_PLUGIN_SKILL.encode("utf-8"),
            )

            zip_errors = VERIFY_MODULE.verify_zip(
                extra_skill,
                expected_artifact_type="plugin",
            )
            self.assertTrue(
                any(error.startswith("package_manifest_denied_path=") for error in zip_errors)
            )
            extracted = base / "extra-skill-root"
            extract_with_modes(extra_skill, extracted)
            directory_errors = VERIFY_MODULE.verify_directory(
                extracted,
                strict_artifact=True,
                expected_artifact_type="plugin",
            )
            self.assertTrue(
                any(
                    error.startswith("package_manifest_denied_path=")
                    for error in directory_errors
                )
            )
            self.assertIn("package_directory_denied_path", directory_errors)

            plugin_manifest = json.loads(
                (extracted / ".codex-plugin/plugin.json").read_text(encoding="utf-8")
            )
            plugin_manifest["hooks"] = "./hooks/"
            manifest_surface = base / "manifest-surface.zip"
            rewrite_manifest_bound_file(
                output,
                manifest_surface,
                artifact_type="plugin",
                relative_path=".codex-plugin/plugin.json",
                data=(
                    json.dumps(plugin_manifest, sort_keys=True) + "\n"
                ).encode("utf-8"),
            )
            self.assertIn(
                "package_plugin_manifest_fields_invalid",
                VERIFY_MODULE.verify_zip(
                    manifest_surface,
                    expected_artifact_type="plugin",
                ),
            )

    def test_schema_v2_source_package_remains_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            legacy = create_legacy_v2_package(base)

            self.assertEqual(VERIFY_MODULE.verify_zip(legacy), [])

    def test_zip_preflight_rejects_zip64_before_zipfile_constructor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package = Path(temp_dir) / "zip64.zip"
            package.write_bytes(valid_empty_zip64())

            with mock.patch.object(
                VERIFY_MODULE.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile constructor must not run"),
            ) as constructor:
                errors = VERIFY_MODULE.verify_zip(package)

            constructor.assert_not_called()
            self.assertIn("package_zip_zip64_rejected", errors)

    def test_zip_preflight_rejects_entry_count_before_zipfile_constructor(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package = Path(temp_dir) / "too-many-entries.zip"
            entry_count = VERIFY_MODULE.MAX_CANONICAL_ZIP_MEMBERS + 1
            write_sparse_zip_envelope(
                package,
                entry_count=entry_count,
                central_directory_size=entry_count * 46,
            )

            with mock.patch.object(
                VERIFY_MODULE.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile constructor must not run"),
            ) as constructor:
                errors = VERIFY_MODULE.verify_zip(package)

            constructor.assert_not_called()
            self.assertIn("package_zip_entry_limit_exceeded", errors)

    def test_zip_preflight_rejects_central_directory_budget_before_parser(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            package = Path(temp_dir) / "central-directory-budget.zip"
            central_directory_limit = getattr(
                VERIFY_MODULE,
                "MAX_PACKAGE_CENTRAL_DIRECTORY_BYTES",
                64 * 1024 * 1024,
            )
            write_sparse_zip_envelope(
                package,
                entry_count=1,
                central_directory_size=central_directory_limit + 1,
            )

            with mock.patch.object(
                VERIFY_MODULE.zipfile,
                "ZipFile",
                side_effect=AssertionError("ZipFile constructor must not run"),
            ) as constructor:
                errors = VERIFY_MODULE.verify_zip(package)

            constructor.assert_not_called()
            self.assertIn("package_zip_central_directory_size_exceeded", errors)

    def test_verify_zip_uses_immutable_snapshot_after_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, package = create_plugin_package(base)
            real_preflight = VERIFY_MODULE.zip_stream_preflight_errors
            preflight_calls = 0

            def preflight_then_mutate_original(source):
                nonlocal preflight_calls
                preflight_calls += 1
                errors = real_preflight(source)
                self.assertEqual(errors, [])
                package.write_bytes(valid_empty_zip64())
                return errors

            with mock.patch.object(
                VERIFY_MODULE,
                "zip_stream_preflight_errors",
                side_effect=preflight_then_mutate_original,
            ):
                errors = VERIFY_MODULE.verify_zip(
                    package,
                    expected_artifact_type="plugin",
                )

            self.assertEqual(preflight_calls, 1)
            self.assertEqual(errors, [])
            self.assertEqual(package.read_bytes(), valid_empty_zip64())

    def test_strict_directory_membership_uses_bounded_bisect_for_deep_paths(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "artifact"
            root.mkdir()
            (root / "d25000/a").mkdir(parents=True)
            (root / "unexpected-empty").mkdir()
            expected_file_paths = tuple(
                f"d{index:05d}/" + "a/" * 62 + "file.txt"
                for index in range(50_000)
            )
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    VERIFY_MODULE,
                    "bisect_left",
                    wraps=stdlib_bisect_left,
                ) as membership_probe:
                    _files, _bytes, _walk_failed, _limit, errors = (
                        VERIFY_MODULE.directory_inventory(
                            descriptor,
                            strict_artifact=True,
                            artifact_type="source",
                            expected_file_paths=expected_file_paths,
                        )
                    )
            finally:
                os.close(descriptor)

            self.assertEqual(membership_probe.call_count, 3)
            self.assertEqual(errors, ["package_directory_unexpected_directory"])

    def test_schema_v2_rejects_prefix_trailer_and_global_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            legacy = create_legacy_v2_package(base)
            raw = legacy.read_bytes()
            variants = {
                "prefix": b"SECRET-PREFIX" + raw,
                "trailer": raw + b"SECRET-TRAILER",
            }
            for label, payload in variants.items():
                with self.subTest(label=label):
                    tampered = base / f"legacy-{label}.zip"
                    tampered.write_bytes(payload)
                    self.assertIn(
                        "package_zip_envelope_invalid",
                        VERIFY_MODULE.verify_zip(tampered),
                    )

            commented = base / "legacy-commented.zip"
            shutil.copyfile(legacy, commented)
            with zipfile.ZipFile(commented, "a") as archive:
                archive.comment = b"SECRET-COMMENT"
            self.assertIn(
                "package_zip_envelope_invalid",
                VERIFY_MODULE.verify_zip(commented),
            )

    def test_schema_v2_rejects_unbound_member_metadata_and_directories(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            legacy = create_legacy_v2_package(base)
            with zipfile.ZipFile(legacy) as archive:
                infos = archive.infolist()
                payloads = {info.filename: archive.read(info) for info in infos}

            metadata_variants = {
                "member-comment": lambda info: setattr(info, "comment", b"SECRET"),
                "member-extra": lambda info: setattr(
                    info,
                    "extra",
                    struct.pack("<HH", 0xCAFE, 6) + b"SECRET",
                ),
            }
            for label, mutate in metadata_variants.items():
                with self.subTest(label=label):
                    tampered = base / f"legacy-{label}.zip"
                    with zipfile.ZipFile(
                        tampered,
                        "w",
                        compression=zipfile.ZIP_STORED,
                    ) as rewritten:
                        for index, source_info in enumerate(infos):
                            info = copy.copy(source_info)
                            if index == 0:
                                mutate(info)
                            rewritten.writestr(info, payloads[source_info.filename])
                    self.assertIn(
                        "package_zip_metadata_invalid",
                        VERIFY_MODULE.verify_zip(tampered),
                    )

            for label, member_name in (
                ("allowed-directory", "CodexQB/allowed-empty/"),
                ("denied-directory", "CodexQB/.git/"),
            ):
                with self.subTest(label=label):
                    directory_info = zipfile.ZipInfo(
                        member_name,
                        date_time=(1980, 1, 1, 0, 0, 0),
                    )
                    directory_info.create_system = 3
                    directory_info.external_attr = (stat.S_IFDIR | 0o755) << 16
                    tampered = base / f"legacy-{label}.zip"
                    rewrite_zip(
                        legacy,
                        tampered,
                        appended=[(directory_info, b"")],
                    )
                    self.assertIn(
                        "package_zip_directory_entry_rejected",
                        VERIFY_MODULE.verify_zip(tampered),
                    )

    def test_schema_v2_rejects_reordered_members(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            legacy = create_legacy_v2_package(base)
            tampered = base / "legacy-reordered.zip"
            with zipfile.ZipFile(legacy) as archive:
                infos = archive.infolist()
                payloads = {info.filename: archive.read(info) for info in infos}
            with zipfile.ZipFile(
                tampered,
                "w",
                compression=zipfile.ZIP_STORED,
            ) as rewritten:
                for info in reversed(infos):
                    rewritten.writestr(info, payloads[info.filename])

            self.assertIn(
                "package_zip_member_order_invalid",
                VERIFY_MODULE.verify_zip(tampered),
            )

    def test_source_package_with_available_git_provenance_verifies(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _root, output = create_source_package(Path(temp_dir), git_checkout=True)

            self.assertEqual(VERIFY_MODULE.verify_zip(output), [])

    def test_extracted_runtime_caches_are_ignored_but_cache_symlinks_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            cache = extracted / ".pytest_cache/nested"
            cache.mkdir(parents=True)
            (cache / "state.txt").write_text("runtime cache\n", encoding="utf-8")
            pycache = extracted / "scripts/__pycache__"
            pycache.mkdir(parents=True)
            (pycache / "module.pyc").write_bytes(b"runtime bytecode")
            (extracted / ".DS_Store").write_bytes(b"finder metadata")

            self.assertEqual(VERIFY_MODULE.verify_directory(extracted), [])
            self.assertIn(
                "package_directory_denied_path",
                VERIFY_MODULE.verify_directory(extracted, strict_artifact=True),
            )

            if hasattr(Path, "symlink_to"):
                (cache / "escape").symlink_to(extracted / "README.md")
                self.assertIn(
                    "package_directory_symlink_rejected",
                    VERIFY_MODULE.verify_directory(extracted),
                )

    def test_extracted_inventory_stops_iteration_at_entry_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            maximum_calls = VERIFY_MODULE.MAX_MANIFEST_FILES + 2

            class BoundedDirectoryIterator:
                def __init__(self) -> None:
                    self.calls = 0

                def __enter__(self):
                    return self

                def __exit__(self, exc_type, exc_value, traceback):
                    return False

                def __iter__(self):
                    return self

                def __next__(self):
                    self.calls += 1
                    if self.calls > maximum_calls:
                        raise AssertionError(
                            "directory inventory read past the bounded entry budget"
                        )
                    return SimpleNamespace(name=f"entry-{self.calls}")

            iterator = BoundedDirectoryIterator()
            with mock.patch.object(
                VERIFY_MODULE.os,
                "scandir",
                return_value=iterator,
            ):
                errors = VERIFY_MODULE.verify_directory(extracted)

            self.assertEqual(iterator.calls, maximum_calls)
            self.assertIn("package_directory_entry_limit_exceeded", errors)

    def test_tampered_zip_file_digest_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)
            tampered = base / "tampered.zip"
            rewrite_zip(
                output,
                tampered,
                replacements={"CodexQB/README.md": b"tampered\n"},
            )

            errors = VERIFY_MODULE.verify_zip(tampered)
            self.assertTrue(any(error.startswith("package_file_digest_mismatch=") for error in errors))

    def test_deeply_nested_manifest_is_rejected_without_recursion_crash(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            output, extracted = extracted_package(base)
            depth = 1_000_000
            nested = ("[" * depth + "0" + "]" * depth).encode("ascii")

            tampered = base / "deep-manifest.zip"
            rewrite_zip(
                output,
                tampered,
                replacements={MANIFEST_MEMBER: nested},
            )
            self.assertIn(
                "package_manifest_invalid_json",
                VERIFY_MODULE.verify_zip(tampered),
            )

            manifest_path = extracted / "PACKAGE-MANIFEST.json"
            manifest_path.write_bytes(nested)
            manifest_path.chmod(0o644)
            self.assertIn(
                "package_manifest_invalid_json",
                VERIFY_MODULE.verify_directory(extracted),
            )

    def test_extracted_tamper_extra_and_missing_files_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            readme = extracted / "README.md"
            readme.write_text("tampered\n", encoding="utf-8")
            (extracted / "unexpected.txt").write_text("extra\n", encoding="utf-8")

            errors = VERIFY_MODULE.verify_directory(extracted)
            self.assertIn("package_manifest_file_set_mismatch", errors)
            self.assertTrue(any(error.startswith("package_file_digest_mismatch=") for error in errors))

            readme.unlink()
            self.assertIn(
                "package_manifest_file_set_mismatch",
                VERIFY_MODULE.verify_directory(extracted),
            )

    @unittest.skipUnless(hasattr(os, "link"), "hardlink support required")
    def test_strict_extracted_root_rejects_external_hardlinks(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            readme = extracted / "README.md"
            outside = base / "outside-readme.md"
            outside.write_bytes(readme.read_bytes())
            outside.chmod(stat.S_IMODE(readme.stat().st_mode))
            readme.unlink()
            os.link(outside, readme)

            errors = VERIFY_MODULE.verify_directory(
                extracted,
                strict_artifact=True,
                expected_artifact_type="source",
            )
            self.assertIn("package_directory_hardlink_rejected", errors)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_manifest_fifo_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            manifest = extracted / "PACKAGE-MANIFEST.json"
            manifest.unlink()
            os.mkfifo(manifest)

            started = time.monotonic()
            errors = VERIFY_MODULE.verify_directory(
                extracted,
                strict_artifact=True,
                expected_artifact_type="source",
            )
            elapsed = time.monotonic() - started

            self.assertLess(elapsed, 2.0)
            self.assertIn("package_manifest_missing_or_invalid", errors)

    def test_extracted_root_path_swap_is_detected_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            replacement = base / "replacement"
            replacement.mkdir()
            real_stat = os.stat

            def swapped_root_stat(path, *args, **kwargs):
                if (
                    Path(path) == extracted
                    and kwargs.get("dir_fd") is None
                    and kwargs.get("follow_symlinks") is False
                ):
                    return real_stat(replacement, follow_symlinks=False)
                return real_stat(path, *args, **kwargs)

            with mock.patch.object(
                VERIFY_MODULE.os,
                "stat",
                side_effect=swapped_root_stat,
            ):
                errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="source",
                )

            self.assertIn("package_directory_root_changed", errors)

    def test_extracted_root_mount_change_is_detected_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            real_require_same_mount = VERIFY_MODULE.require_same_mount
            root_checks = 0

            def reject_reopened_root(root_resolution, descriptor, relative_path):
                nonlocal root_checks
                if relative_path == ".":
                    root_checks += 1
                    if root_checks == 3:
                        raise ValueError("simulated_root_mount_change")
                return real_require_same_mount(
                    root_resolution,
                    descriptor,
                    relative_path,
                )

            with mock.patch.object(
                VERIFY_MODULE,
                "require_same_mount",
                side_effect=reject_reopened_root,
            ):
                errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="source",
                )

            self.assertEqual(root_checks, 3)
            self.assertIn("package_directory_root_mount_changed", errors)

    def test_tree_digest_duplicate_and_non_release_claim_tampering_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            manifest_path = extracted / "PACKAGE-MANIFEST.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))

            bad_tree = copy.deepcopy(original)
            bad_tree["tree_sha256"] = "0" * 64
            manifest_path.write_text(json.dumps(bad_tree), encoding="utf-8")
            self.assertIn(
                "package_manifest_tree_digest_mismatch",
                VERIFY_MODULE.verify_directory(extracted),
            )

            duplicate = copy.deepcopy(original)
            duplicate["files"].append(copy.deepcopy(duplicate["files"][0]))
            duplicate["file_count"] += 1
            manifest_path.write_text(json.dumps(duplicate), encoding="utf-8")
            duplicate_errors = VERIFY_MODULE.verify_directory(extracted)
            self.assertTrue(
                any(error.startswith("package_manifest_file_duplicate=") for error in duplicate_errors)
            )

            false_release = copy.deepcopy(original)
            false_release["release_claim"] = True
            manifest_path.write_text(json.dumps(false_release), encoding="utf-8")
            self.assertIn(
                "non_release_package_claim_invalid",
                VERIFY_MODULE.verify_directory(extracted),
            )

    def test_manifest_paths_reject_noncanonical_backslash_unicode_and_ancestor_collisions(self) -> None:
        self.assertIsNone(VERIFY_MODULE.safe_manifest_path("a//b"))
        self.assertIsNone(VERIFY_MODULE.safe_manifest_path("..\\escaped.txt"))
        for value in (
            ".git./config",
            "trailing-dot./file.txt",
            "trailing-space /file.txt",
            "CON.txt",
            "COM¹.txt",
            "LPT³.log",
            "illegal:name.txt",
        ):
            with self.subTest(value=value):
                self.assertIsNone(VERIFY_MODULE.safe_manifest_path(value))
        digest = hashlib.sha256(b"x").hexdigest()
        manifest = {
            "files": [
                {"path": "a", "sha256": digest, "mode": "0644"},
                {"path": "a/b", "sha256": digest, "mode": "0644"},
                {"path": "é.txt", "sha256": digest, "mode": "0644"},
                {"path": "e\u0301.txt", "sha256": digest, "mode": "0644"},
                {
                    "path": "package-manifest.json",
                    "sha256": digest,
                    "mode": "0644",
                },
            ],
            "file_count": 5,
            "tree_sha256": "0" * 64,
        }

        _entries, errors = VERIFY_MODULE.manifest_entries(manifest)
        self.assertTrue(any(error.startswith("package_manifest_file_ancestor_conflict=") for error in errors))
        self.assertTrue(
            any(
                error.startswith("package_manifest_file_case_collision=")
                or error.startswith("package_manifest_file_invalid=")
                for error in errors
            )
        )

    def test_extracted_manifest_name_case_collision_is_reserved(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            lowercase_manifest = extracted / "package-manifest.json"
            if lowercase_manifest.exists():
                self.skipTest("case-insensitive filesystem cannot represent the collision")
            shadow = b"shadow manifest\n"
            lowercase_manifest.write_bytes(shadow)
            lowercase_manifest.chmod(0o644)
            manifest_path = extracted / "PACKAGE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"].append(
                {
                    "path": "package-manifest.json",
                    "sha256": hashlib.sha256(shadow).hexdigest(),
                    "mode": "0644",
                }
            )
            manifest["files"].sort(key=lambda item: item["path"])
            manifest["file_count"] = len(manifest["files"])
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

            errors = VERIFY_MODULE.verify_directory(
                extracted,
                strict_artifact=True,
            )
            self.assertTrue(
                any(
                    error.startswith("package_manifest_file_case_collision=")
                    for error in errors
                )
            )

    def test_zip_verifier_rejects_manifest_listed_denylist_and_nested_magic(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)
            tampered = base / "denylisted.zip"
            additions = {
                ".git/config": b"[core]\n",
                ".git./config": b"[core]\n",
                "._README.md": b"appledouble metadata\n",
                ".env/credentials.txt": b"local only\n",
                "scratch.tmp": b"temporary\n",
                "tmp/cache.txt": b"cache\n",
                "disguised.bin": b"PK\x03\x04payload",
                "polyglot.bin": valid_zip_polyglot(),
                "zip64.bin": valid_empty_zip64(),
            }
            with zipfile.ZipFile(output) as archive:
                infos = archive.infolist()
                payloads = {info.filename: archive.read(info) for info in infos}
                manifest = json.loads(payloads[MANIFEST_MEMBER].decode("utf-8"))
            for path, data in additions.items():
                manifest["files"].append(
                    {
                        "path": path,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "mode": "0644",
                    }
                )
            manifest["files"].sort(key=lambda item: item["path"])
            manifest["file_count"] = len(manifest["files"])
            encoded = json.dumps(
                manifest["files"],
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
            manifest["tree_sha256"] = hashlib.sha256(encoded).hexdigest()
            manifest["content_sha256"] = manifest["tree_sha256"]
            payloads[MANIFEST_MEMBER] = (
                json.dumps(manifest, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
            with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_STORED) as rewritten:
                for item in manifest["files"]:
                    member = f"CodexQB/{item['path']}"
                    data = additions.get(item["path"], payloads.get(member))
                    self.assertIsNotNone(data)
                    info = zipfile.ZipInfo(member, date_time=(1980, 1, 1, 0, 0, 0))
                    info.create_system = 3
                    info.compress_type = zipfile.ZIP_STORED
                    info.external_attr = (stat.S_IFREG | int(item["mode"], 8)) << 16
                    rewritten.writestr(info, data)
                manifest_info = zipfile.ZipInfo(
                    MANIFEST_MEMBER,
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                manifest_info.create_system = 3
                manifest_info.compress_type = zipfile.ZIP_STORED
                manifest_info.external_attr = (stat.S_IFREG | 0o644) << 16
                rewritten.writestr(manifest_info, payloads[MANIFEST_MEMBER])

            errors = VERIFY_MODULE.verify_zip(tampered)
            self.assertTrue(
                any(error.startswith("package_manifest_denied_path=") for error in errors)
            )
            self.assertIn("package_zip_denied_path", errors)
            self.assertIn("package_zip_nested_zip_rejected", errors)

    def test_schema_v3_zip_envelope_rejects_prefix_trailer_and_global_comment(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)
            raw = output.read_bytes()
            variants = {
                "prefix": b"SECRET-PREFIX" + raw,
                "trailer": raw + b"SECRET-TRAILER",
            }
            eocd_offset = len(raw) - VERIFY_MODULE.END_OF_CENTRAL_DIRECTORY_SIZE
            for label, field_offset in {
                "disk-number": 4,
                "central-directory-disk": 6,
                "entries-on-disk": 8,
                "entries-total": 10,
            }.items():
                payload = bytearray(raw)
                struct.pack_into("<H", payload, eocd_offset + field_offset, 1)
                variants[label] = bytes(payload)
            for label, payload in variants.items():
                with self.subTest(label=label):
                    tampered = base / f"{label}.zip"
                    tampered.write_bytes(payload)
                    errors = VERIFY_MODULE.verify_zip(tampered)
                    self.assertTrue(
                        {
                            "package_zip_envelope_invalid",
                            "package_zip_invalid",
                        }.intersection(errors)
                    )

            commented = base / "commented.zip"
            shutil.copyfile(output, commented)
            with zipfile.ZipFile(commented, "a") as archive:
                archive.comment = b"noncanonical-comment"
            self.assertIn(
                "package_zip_envelope_invalid",
                VERIFY_MODULE.verify_zip(commented),
            )

    def test_schema_v3_zip_member_metadata_is_fully_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)
            mutations = {
                "create-system": lambda info: setattr(info, "create_system", 0),
                "create-version": lambda info: setattr(info, "create_version", 99),
                "internal-attr": lambda info: setattr(info, "internal_attr", 1),
            }
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    tampered = base / f"metadata-{label}.zip"
                    with zipfile.ZipFile(output) as original, zipfile.ZipFile(
                        tampered,
                        "w",
                        compression=zipfile.ZIP_STORED,
                    ) as rewritten:
                        for index, source_info in enumerate(original.infolist()):
                            info = copy.copy(source_info)
                            if index == 0:
                                mutate(info)
                            rewritten.writestr(info, original.read(source_info))
                    self.assertIn(
                        "package_zip_metadata_invalid",
                        VERIFY_MODULE.verify_zip(tampered),
                    )

    def test_zip_traversal_and_symlink_members_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)

            traversal_info = zipfile.ZipInfo("../../escaped/")
            traversal_info.external_attr = (stat.S_IFDIR | 0o755) << 16
            traversal = base / "traversal.zip"
            rewrite_zip(output, traversal, appended=[(traversal_info, b"")])
            self.assertIn("package_zip_entry_path_invalid", VERIFY_MODULE.verify_zip(traversal))

            symlink_info = zipfile.ZipInfo("CodexQB/link")
            symlink_info.create_system = 3
            symlink_info.external_attr = (stat.S_IFLNK | 0o777) << 16
            symlink = base / "symlink.zip"
            rewrite_zip(output, symlink, appended=[(symlink_info, b"README.md")])
            self.assertIn("package_zip_entry_type_invalid", VERIFY_MODULE.verify_zip(symlink))

    def test_zip_rejects_unsafe_regular_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, output = create_source_package(base)
            tampered = base / "unsafe-mode.zip"
            with zipfile.ZipFile(output) as original, zipfile.ZipFile(
                tampered,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as rewritten:
                for original_info in original.infolist():
                    info = copy.copy(original_info)
                    if info.filename == "CodexQB/README.md":
                        info.external_attr = (stat.S_IFREG | 0o4777) << 16
                    rewritten.writestr(info, original.read(original_info.filename))

            self.assertIn(
                "package_zip_entry_type_invalid",
                VERIFY_MODULE.verify_zip(tampered),
            )

    def test_manifest_binds_safe_file_modes_in_zip_and_extracted_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            output, extracted = extracted_package(base)
            tampered = base / "safe-but-wrong-mode.zip"
            with zipfile.ZipFile(output) as original, zipfile.ZipFile(
                tampered,
                "w",
                compression=zipfile.ZIP_DEFLATED,
            ) as rewritten:
                for original_info in original.infolist():
                    info = copy.copy(original_info)
                    if info.filename == "CodexQB/README.md":
                        info.external_attr = (stat.S_IFREG | 0o755) << 16
                    rewritten.writestr(info, original.read(original_info.filename))

            self.assertTrue(
                any(
                    error.startswith("package_file_mode_mismatch=")
                    for error in VERIFY_MODULE.verify_zip(tampered)
                )
            )

            (extracted / "README.md").chmod(0o755)
            self.assertTrue(
                any(
                    error.startswith("package_file_mode_mismatch=")
                    for error in VERIFY_MODULE.verify_directory(extracted)
                )
            )

    def test_extra_standalone_pyc_is_not_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            (extracted / "standalone.pyc").write_bytes(b"executable bytecode")

            self.assertIn(
                "package_manifest_file_set_mismatch",
                VERIFY_MODULE.verify_directory(extracted),
            )

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symlink support required")
    def test_descriptor_walk_rejects_ancestor_symlink_swap(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            replacement = base / "replacement-plugins"
            shutil.copytree(extracted / "plugins", replacement)
            original_plugins = base / "original-plugins"
            real_open = VERIFY_MODULE.os.open
            fired = False

            def swap_before_directory_open(path, flags, mode=0o777, *, dir_fd=None):
                nonlocal fired
                if not fired and dir_fd is not None and path == "plugins":
                    fired = True
                    (extracted / "plugins").rename(original_plugins)
                    (extracted / "plugins").symlink_to(
                        replacement,
                        target_is_directory=True,
                    )
                return real_open(path, flags, mode, dir_fd=dir_fd)

            with mock.patch.object(
                VERIFY_MODULE.os,
                "open",
                side_effect=swap_before_directory_open,
            ):
                errors = VERIFY_MODULE.verify_directory(extracted)

            self.assertTrue(fired)
            self.assertNotEqual(errors, [])
            self.assertTrue(
                "package_directory_inventory_unavailable" in errors
                or "package_directory_symlink_rejected" in errors
            )

    def test_real_directory_swap_cannot_hide_an_extra_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            replacement = base / "replacement-plugins"
            shutil.copytree(extracted / "plugins", replacement)
            (replacement / "evil.py").write_text("print('unexpected')\n", encoding="utf-8")
            original_plugins = base / "original-plugins"
            real_evidence = VERIFY_MODULE.regular_file_evidence
            fired = False

            def swap_before_hash(
                root_descriptor,
                relative,
                maximum_bytes,
                root_resolution=None,
            ):
                nonlocal fired
                if not fired:
                    fired = True
                    (extracted / "plugins").rename(original_plugins)
                    replacement.rename(extracted / "plugins")
                return real_evidence(
                    root_descriptor,
                    relative,
                    maximum_bytes,
                    root_resolution,
                )

            with mock.patch.object(
                VERIFY_MODULE,
                "regular_file_evidence",
                side_effect=swap_before_hash,
            ):
                errors = VERIFY_MODULE.verify_directory(extracted)

            self.assertTrue(fired)
            self.assertIn("package_directory_changed_during_verification", errors)

    def test_late_plugin_manifest_mutation_after_semantic_read_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            target = extracted / "plugins/codexqb/.codex-plugin/plugin.json"
            real_contract_check = VERIFY_MODULE.plugin_manifest_payload_errors
            fired = False

            def mutate_after_semantic_read(data, **kwargs):
                nonlocal fired
                contract_errors = real_contract_check(data, **kwargs)
                fired = True
                target.write_text("{}\n", encoding="utf-8")
                target.chmod(0o644)
                return contract_errors

            with mock.patch.object(
                VERIFY_MODULE,
                "plugin_manifest_payload_errors",
                side_effect=mutate_after_semantic_read,
            ):
                errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="source",
                )

            self.assertTrue(fired)
            self.assertTrue(
                "package_directory_changed_during_verification" in errors
                or any(
                    error.startswith("package_file_changed_during_verification=")
                    for error in errors
                )
            )

    def test_root_swap_after_final_inventory_is_detected_before_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _output, extracted = extracted_package(base)
            replacement = base / "replacement-artifact"
            shutil.copytree(extracted, replacement)
            replacement_plugin = (
                replacement / "plugins/codexqb/.codex-plugin/plugin.json"
            )
            replacement_plugin.write_text("{}\n", encoding="utf-8")
            replacement_plugin.chmod(0o644)
            displaced = base / "verified-artifact-displaced"
            real_inventory = VERIFY_MODULE.directory_inventory
            inventory_calls = 0

            def swap_root_after_final_inventory(*args, **kwargs):
                nonlocal inventory_calls
                result = real_inventory(*args, **kwargs)
                inventory_calls += 1
                if inventory_calls == 2:
                    extracted.rename(displaced)
                    replacement.rename(extracted)
                return result

            with mock.patch.object(
                VERIFY_MODULE,
                "directory_inventory",
                side_effect=swap_root_after_final_inventory,
            ):
                errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                    expected_artifact_type="source",
                )

            self.assertEqual(inventory_calls, 2)
            self.assertTrue(
                "package_directory_root_changed" in errors
                or "package_directory_root_mount_changed" in errors
            )

    def test_extracted_nested_zip_check_and_hash_share_one_descriptor_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            target = extracted / "README.md"
            nested = valid_zip_polyglot()
            safe = b"S" * len(nested)
            manifest_path = extracted / "PACKAGE-MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            readme_entry = next(
                item for item in manifest["files"] if item["path"] == "README.md"
            )
            readme_entry["sha256"] = hashlib.sha256(nested).hexdigest()
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
            target.write_bytes(safe)
            target.chmod(0o644)
            initial_metadata = target.stat()
            real_evidence = VERIFY_MODULE.regular_file_evidence
            fired = False

            def swap_before_combined_read(
                root_descriptor,
                relative,
                maximum_bytes,
                root_resolution=None,
            ):
                nonlocal fired
                if not fired and relative == "README.md":
                    fired = True
                    target.write_bytes(nested)
                    os.utime(
                        target,
                        ns=(
                            initial_metadata.st_atime_ns,
                            initial_metadata.st_mtime_ns,
                        ),
                    )
                return real_evidence(
                    root_descriptor,
                    relative,
                    maximum_bytes,
                    root_resolution,
                )

            with (
                mock.patch.object(
                    VERIFY_MODULE,
                    "regular_file_evidence",
                    side_effect=swap_before_combined_read,
                ),
                mock.patch.object(
                    VERIFY_MODULE,
                    "regular_file_prefix",
                    side_effect=AssertionError("separate prefix read must not occur"),
                ),
            ):
                errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                )

            self.assertTrue(fired)
            self.assertTrue(
                any(error.startswith("package_file_nested_zip_rejected=") for error in errors)
            )
            self.assertIn("package_directory_changed_during_verification", errors)

    def test_ancestor_checks_remain_linear_at_manifest_limit(self) -> None:
        digest = hashlib.sha256(b"x").hexdigest()
        entries = [
            {
                "path": f"flat/{index:06d}.txt",
                "sha256": digest,
                "mode": "0644",
            }
            for index in range(VERIFY_MODULE.MAX_MANIFEST_FILES)
        ]
        encoded = json.dumps(entries, sort_keys=True, separators=(",", ":")).encode("utf-8")
        manifest = {
            "files": entries,
            "file_count": len(entries),
            "tree_sha256": hashlib.sha256(encoded).hexdigest(),
        }

        started = time.monotonic()
        parsed, errors = VERIFY_MODULE.manifest_entries(manifest)
        elapsed = time.monotonic() - started

        self.assertEqual(errors, [])
        self.assertEqual(len(parsed), VERIFY_MODULE.MAX_MANIFEST_FILES)
        self.assertLess(elapsed, 5.0)

        class IterationForbiddenDict(dict):
            def __iter__(self):
                raise AssertionError("archive ancestor checks must not scan prior entries")

        self.assertFalse(
            VERIFY_MODULE.archive_entry_has_ancestor_conflict(
                "codexqb/new.txt",
                False,
                IterationForbiddenDict({"codexqb/old.txt": False}),
                {"codexqb"},
            )
        )

    def test_extracted_directory_enforces_cumulative_size_limit_without_unbounded_read(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _output, extracted = extracted_package(Path(temp_dir))
            packaged_files = [
                path
                for path in extracted.rglob("*")
                if path.is_file()
            ]
            actual_total = sum(path.stat().st_size for path in packaged_files)
            largest_file = max(path.stat().st_size for path in packaged_files)
            self.assertGreater(actual_total, largest_file)
            patched_limit = actual_total - 1
            with (
                mock.patch.object(
                    VERIFY_MODULE,
                    "MAX_PACKAGE_UNCOMPRESSED_BYTES",
                    patched_limit,
                ),
                mock.patch.object(
                    VERIFY_MODULE,
                    "regular_file_evidence",
                    wraps=VERIFY_MODULE.regular_file_evidence,
                ) as digest_mock,
            ):
                errors = VERIFY_MODULE.verify_directory(extracted)

            self.assertIn("package_directory_size_limit_exceeded", errors)
            self.assertEqual(digest_mock.call_count, 0)

    def test_zip_and_extracted_verifiers_enforce_the_per_file_limit(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            output, extracted = extracted_package(Path(temp_dir))
            with mock.patch.object(VERIFY_MODULE, "MAX_ARTIFACT_FILE_BYTES", 1):
                zip_errors = VERIFY_MODULE.verify_zip(output)
                directory_errors = VERIFY_MODULE.verify_directory(
                    extracted,
                    strict_artifact=True,
                )

            self.assertIn("package_zip_file_size_limit_exceeded", zip_errors)
            self.assertIn(
                "package_directory_file_size_limit_exceeded",
                directory_errors,
            )

    def test_zip_and_extracted_verifiers_reject_manifest_bound_secret_bytes(self) -> None:
        credential = "this-is-a-real-long-password-value"
        utf32_fixture = "sk-" + "U" * 40
        joined_fixture = "sk-" + "J" * 40
        neutral_join_tail = "N" * 40
        neutral_join_fixture = "sk-" + neutral_join_tail
        fixtures = (
            ("payload.bin", b"\xff" + ("sk-" + "C" * 40).encode("ascii"), None),
            ("payload-utf32.bin", utf32_fixture.encode("utf-32-be"), utf32_fixture),
            ("invalid.py", b"print('safe')\n\xff", None),
            ("settings-bytes.py", ("PASSWORD = " + repr(credential.encode("utf-8")) + "\n").encode("utf-8"), credential),
            (
                "settings-bytes-concat.py",
                (
                    "PASSWORD = "
                    + repr("this-is-a-real-".encode("utf-8"))
                    + " + "
                    + repr("long-password-value".encode("utf-8"))
                    + "\n"
                ).encode("utf-8"),
                credential,
            ),
            (
                "constant-join.py",
                (
                    "API_KEY = ''.join(("
                    + repr("sk-")
                    + ", "
                    + repr("J" * 40)
                    + "))\n"
                ).encode("utf-8"),
                joined_fixture,
            ),
            (
                "neutral-join.py",
                (
                    "message = ''.join(("
                    + repr("sk-")
                    + ", "
                    + repr(neutral_join_tail)
                    + "))\n"
                ).encode("utf-8"),
                neutral_join_fixture,
            ),
            (
                "argument-join.py",
                (
                    "print(''.join(("
                    + repr("sk-")
                    + ", "
                    + repr(neutral_join_tail)
                    + ")))\n"
                ).encode("utf-8"),
                neutral_join_fixture,
            ),
            (
                "neutral-bytes-join.py",
                (
                    "message = b''.join(("
                    + repr(b"sk-")
                    + ", "
                    + repr(neutral_join_tail.encode())
                    + "))\n"
                ).encode("utf-8"),
                neutral_join_fixture,
            ),
            (
                "argument-bytes-join.py",
                (
                    "print(b''.join(("
                    + repr(b"sk-")
                    + ", "
                    + repr(neutral_join_tail.encode())
                    + ")))\n"
                ).encode("utf-8"),
                neutral_join_fixture,
            ),
        )
        for relative_path, data, fixture in fixtures:
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, original = create_source_package(base)
                forged = base / "forged.zip"
                append_manifest_bound_file(
                    original,
                    forged,
                    artifact_type="source",
                    relative_path=relative_path,
                    data=data,
                )
                extracted = base / "extracted"
                extract_with_modes(forged, extracted)

                zip_errors = VERIFY_MODULE.verify_zip(forged)
                directory_errors = VERIFY_MODULE.verify_directory(
                    extracted / "CodexQB",
                    strict_artifact=True,
                )
                self.assertIn(
                    "package_zip_secret_content_rejected",
                    zip_errors,
                )
                self.assertTrue(
                    any(
                        error.startswith("package_file_secret_content_rejected=")
                        for error in directory_errors
                    )
                )
                for secret in (credential, fixture):
                    if secret is not None:
                        self.assertNotIn(secret, repr(zip_errors) + repr(directory_errors))

    def test_zip_and_extracted_verifiers_reject_secret_paths_and_accept_bytes_placeholder(self) -> None:
        fixture = "sk-" + "P" * 40
        variants = (f"{fixture}.txt", f"safe/{fixture}/payload.txt")
        for relative_path in variants:
            with self.subTest(path_hash=hashlib.sha256(relative_path.encode()).hexdigest()), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, original = create_source_package(base)
                forged = base / "forged.zip"
                append_manifest_bound_file(
                    original,
                    forged,
                    artifact_type="source",
                    relative_path=relative_path,
                    data=b"safe file body\n",
                )
                extracted = base / "extracted"
                extract_with_modes(forged, extracted)

                zip_errors = VERIFY_MODULE.verify_zip(forged)
                directory_errors = VERIFY_MODULE.verify_directory(
                    extracted / "CodexQB",
                    strict_artifact=True,
                )

                self.assertTrue(
                    any("secret_path" in error for error in zip_errors),
                    zip_errors,
                )
                self.assertTrue(
                    any("secret_path" in error for error in directory_errors),
                    directory_errors,
                )
                self.assertNotIn(fixture, repr(zip_errors) + repr(directory_errors))

        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            _root, original = create_source_package(base)
            forged = base / "placeholder.zip"
            append_manifest_bound_file(
                original,
                forged,
                artifact_type="source",
                relative_path="settings.py",
                data=("PASSWORD = " + repr(b"${PASSWORD}") + "\n").encode("utf-8"),
            )
            extracted = base / "placeholder-extracted"
            extract_with_modes(forged, extracted)
            self.assertNotIn("package_zip_secret_content_rejected", VERIFY_MODULE.verify_zip(forged))
            self.assertFalse(
                any(
                    "secret_content" in error
                    for error in VERIFY_MODULE.verify_directory(
                        extracted / "CodexQB",
                        strict_artifact=True,
                    )
                )
            )

    def test_zip_and_extracted_verifiers_scan_complete_manifest_provenance(self) -> None:
        generic_value = "manifest-credential-value"
        variants = (
            ("provider", "sk-" + "M" * 40),
            ("generic", "PASSWORD=" + generic_value),
        )
        for label, fixture in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, original = create_source_package(base)
                forged = base / "secret-manifest.zip"

                def mutate(manifest: dict[str, object]) -> None:
                    manifest["git_branch"] = fixture

                rewrite_zip(
                    original,
                    forged,
                    replacements={MANIFEST_MEMBER: manifest_bytes_with_mutation(original, mutate)},
                )
                extracted = base / "secret-manifest-extracted"
                extract_with_modes(forged, extracted)

                zip_errors = VERIFY_MODULE.verify_zip(forged)
                directory_errors = VERIFY_MODULE.verify_directory(
                    extracted / "CodexQB",
                    strict_artifact=True,
                )

                self.assertIn("package_manifest_secret_content_rejected", zip_errors)
                self.assertIn("package_manifest_secret_content_rejected", directory_errors)
                self.assertNotIn(fixture, repr(zip_errors) + repr(directory_errors))

    def test_zip_verifier_rejects_utf16_secret_across_binary_scan_windows(self) -> None:
        fixture = "sk-" + "W" * 40
        variants = (
            ("le", b"\xff\xfe" + fixture.encode("utf-16-le")),
            ("be", b"\xfe\xff" + fixture.encode("utf-16-be")),
        )
        for label, encoded in variants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, original = create_source_package(base)
                forged = base / f"forged-{label}.zip"
                data = b"\x81" * 60 + encoded + b"\x82"
                append_manifest_bound_file(
                    original,
                    forged,
                    artifact_type="source",
                    relative_path=f"payload-{label}.bin",
                    data=data,
                )
                with (
                    mock.patch.object(PACKAGE_SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 64),
                    mock.patch.object(PACKAGE_SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 64),
                ):
                    errors = VERIFY_MODULE.verify_zip(forged)

                self.assertIn("package_zip_secret_content_rejected", errors)
                self.assertNotIn(fixture, repr(errors))

    def test_zip_verifier_rejects_manifest_bound_source_credentials(self) -> None:
        fixture = "this-is-a-real-long-password-value"
        variants = (
            ("settings.py", "PASSWORD = " + repr(fixture) + "\n"),
            ("settings.json", json.dumps({"password": fixture}) + "\n"),
            ("default.py", "def f(password=" + repr(fixture) + "):\n    pass\n"),
        )
        for relative_path, text in variants:
            with self.subTest(path=relative_path), tempfile.TemporaryDirectory() as temp_dir:
                base = Path(temp_dir)
                _root, original = create_source_package(base)
                forged = base / "forged.zip"
                append_manifest_bound_file(
                    original,
                    forged,
                    artifact_type="source",
                    relative_path=relative_path,
                    data=text.encode("utf-8"),
                )

                errors = VERIFY_MODULE.verify_zip(forged)

                self.assertIn("package_zip_secret_content_rejected", errors)
                self.assertNotIn(fixture, repr(errors))

    def test_regular_file_evidence_returns_structured_failure_when_identity_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            payload = root / "payload.txt"
            payload.write_text("safe\n", encoding="utf-8")
            identity = VERIFY_MODULE.metadata_identity(payload.stat())
            changed_identity = (*identity[:-4], identity[-4] + 1, *identity[-3:])
            root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                with mock.patch.object(
                    VERIFY_MODULE,
                    "metadata_identity",
                    side_effect=(identity, changed_identity, changed_identity),
                ):
                    result = VERIFY_MODULE.regular_file_evidence(
                        root_descriptor,
                        payload.name,
                        1024,
                    )
            finally:
                os.close(root_descriptor)

            self.assertEqual(len(result), 6)
            digest, total, mode, observed_identity, nested_zip, secret_content = result
            self.assertIsNone(digest)
            self.assertEqual(total, len(b"safe\n"))
            self.assertEqual(mode, "0644")
            self.assertEqual(observed_identity, changed_identity)
            self.assertFalse(nested_zip)
            self.assertFalse(secret_content)

    def test_boolean_type_tricks_and_forged_strict_provenance_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            _root, output = create_source_package(Path(temp_dir))
            with zipfile.ZipFile(output) as archive:
                manifest = json.loads(archive.read(MANIFEST_MEMBER).decode("utf-8"))

            type_trick = copy.deepcopy(manifest)
            type_trick["package_schema_version"] = True
            type_trick["file_count"] = True
            type_trick["release_claim"] = 1
            type_errors = [
                *VERIFY_MODULE.manifest_entries(type_trick)[1],
                *VERIFY_MODULE.manifest_contract_errors(type_trick),
            ]
            self.assertIn("package_manifest_schema_version_invalid", type_errors)
            self.assertIn("package_manifest_file_count_mismatch", type_errors)
            self.assertIn("non_release_package_claim_invalid", type_errors)

            forged = copy.deepcopy(manifest)
            forged.update(
                {
                    "export_mode": "strict_release",
                    "release_claim": True,
                    "git_provenance_available": True,
                    "source_inventory": "git_index",
                    "working_tree_clean": True,
                    "tracked_only": True,
                    "include_untracked": False,
                    "changelog_mentions_plugin_version": True,
                    "changelog_release_state": "released",
                    "release_tag_matches_head": True,
                    "git_commit": "unknown",
                    "release_tag_commit": "unknown",
                    "origin_main_ref_status": "unavailable",
                }
            )
            forged_errors = VERIFY_MODULE.manifest_contract_errors(forged)
            self.assertIn("strict_release_manifest_invalid=git_commit", forged_errors)
            self.assertIn("strict_release_manifest_invalid=release_tag_commit", forged_errors)
            self.assertIn("strict_release_manifest_invalid=origin_main_ref_status", forged_errors)


if __name__ == "__main__":
    unittest.main()
