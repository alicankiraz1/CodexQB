from __future__ import annotations

import importlib.util
import json
import time
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = REPO_ROOT / "plugins/codexqb/skills/codexqb/scripts/safety_contracts.py"
SPEC = importlib.util.spec_from_file_location("codexqb_safety_contracts", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
SAFETY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SAFETY)

OUTPUT_SHA256 = "a" * 64


def assemble_fixture(*parts: str) -> str:
    return "".join(parts)


def command(argv: list[str], **overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "id": "VAL-01",
        "argv": argv,
        "cwd": ".",
        "expected_exit_code": 0,
        "timeout_seconds": 120,
        "network": "deny",
        "probe_tier": 1,
    }
    payload.update(overrides)
    return payload


class SafetyContractsTests(unittest.TestCase):
    def synthetic_secret_fixtures(self) -> list[tuple[str, str, str]]:
        return [
            ("openrouter", "openrouter_api_key", "sk-" + "or-v1-" + "A" * 32),
            ("openai", "openai_api_key", "sk-" + "B" * 40),
            ("github_fine_grained", "github_pat", "github_" + "pat_" + "C" * 32),
            ("github_classic", "github_legacy_pat", "gh" + "p_" + "D" * 32),
            ("anthropic", "anthropic_api_key", "sk-" + "ant-api03-" + "E" * 40),
            ("huggingface", "huggingface_token", "hf" + "_" + "F" * 32),
            ("gitlab", "gitlab_token", "gl" + "pat-" + "G" * 32),
            ("stripe", "stripe_secret_key", "sk" + "_live_" + "H" * 32),
            ("stripe_webhook", "stripe_webhook_secret", "wh" + "sec_" + "I" * 32),
            ("google_api", "google_api_key", "AI" + "za" + "J" * 35),
            ("google_client", "google_oauth_client_secret", "GOC" + "SPX-" + "K" * 32),
            ("google_access", "google_oauth_access_token", "ya" + "29." + "L" * 32),
            ("aws_access", "aws_access_key", "AK" + "IA" + "M" * 16),
            (
                "aws_secret",
                "aws_secret_access_key",
                "AWS_" + "SECRET_ACCESS_KEY=" + "N" * 40,
            ),
            ("aws_session", "aws_session_token", "AWS_" + "SESSION_TOKEN=" + "O" * 48),
            ("slack", "slack_token", "xox" + "b-" + "P" * 32),
            ("slack_app", "slack_app_token", "xapp" + "-" + "Q" * 32),
            (
                "slack_webhook",
                "slack_webhook",
                "https://hooks." + "slack.com/services/" + "R" * 10 + "/" + "S" * 10 + "/" + "T" * 32,
            ),
            ("jwt", "jwt", "eyJ" + "U" * 12 + "." + "V" * 16 + "." + "W" * 20),
            ("private_key", "private_key", assemble_fixture("-----BEGIN ", "PRIVATE ", "KEY-----")),
            ("provider_assignment", "provider_credential_assignment", "HF_" + "TOKEN=" + "X" * 32),
            ("generic_assignment", "generic_credential_assignment", "password=" + "Y" * 32),
            (
                "punctuated_password",
                "generic_credential_assignment",
                assemble_fixture("pass", 'word="P@ssw0rd!', "Z" * 16, '"'),
            ),
            ("bearer", "authorization_bearer", "Authorization: Bearer " + "a" * 32),
            (
                "basic",
                "authorization_basic",
                assemble_fixture("Authorization: ", "Basic ", "dXNlcjpwYXNz"),
            ),
            ("uri", "uri_userinfo_credential", "postgres://user:" + "p" * 16 + "@example.invalid/db"),
        ]

    def test_secret_families_are_detected_redacted_and_never_echoed(self) -> None:
        for provider, expected, fixture in self.synthetic_secret_fixtures():
            with self.subTest(provider=provider):
                findings = SAFETY.secret_findings(fixture)
                self.assertIn(expected, findings)
                locations = SAFETY.secret_match_locations(fixture)
                self.assertTrue(any(name == expected for name, _ in locations))
                if fixture in repr(locations):
                    self.fail(f"finding metadata leaked fixture for {provider}")

                try:
                    SAFETY.assert_safe_persistent_text(fixture)
                except ValueError as exc:
                    message = str(exc)
                    if fixture in message:
                        self.fail(f"persistent rejection leaked fixture for {provider}")
                    self.assertIn(expected, message)
                else:
                    self.fail(f"persistent write accepted fixture for {provider}")

                redacted = SAFETY.redact_secret_like(fixture)
                if fixture in redacted:
                    self.fail(f"redaction leaked fixture for {provider}")
                self.assertIn("<redacted:", redacted)

                diagnostic = SAFETY.safe_log_text("failure=" + fixture + "\nnext")
                if fixture in diagnostic:
                    self.fail(f"safe log leaked fixture for {provider}")
                self.assertNotIn("\n", diagnostic)

    def test_secret_scanner_limits_input_and_never_truncates_to_pass(self) -> None:
        with mock.patch.object(SAFETY, "MAX_SECRET_SCAN_CHARACTERS", 64):
            oversized = "Z" * 65
            self.assertEqual(SAFETY.secret_findings(oversized), ["secret_scan_input_too_large"])
            with self.assertRaisesRegex(ValueError, "persistent_artifact_secret_rejected=secret_scan_input_too_large"):
                SAFETY.assert_safe_persistent_text(oversized)
            self.assertEqual(SAFETY.safe_log_text(oversized), "<redacted:unsafe-diagnostic>")

    def test_package_scanner_fails_closed_for_invalid_known_text(self) -> None:
        fixtures = (
            (b"print('safe')\n\xff", ".py"),
            (("gl" + "pat-" + "U" * 32).encode("utf-16"), ".txt"),
        )
        for data, suffix in fixtures:
            with self.subTest(suffix=suffix):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(data, suffix),
                    [("package_text_invalid_utf8", 0)],
                )

    def test_package_scanner_covers_binary_boundaries_and_suffixless_payloads(self) -> None:
        fixture = ("sk-" + "Q" * 40).encode("ascii")
        with (
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 64),
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 64),
        ):
            payload = b"\xff" * 60 + fixture + b"\x00\xfe"
            locations = SAFETY.package_secret_match_locations(payload, "")
        self.assertIn(("openai_api_key", 60), locations)
        self.assertNotIn(fixture.decode("ascii"), repr(locations))
        self.assertEqual(
            SAFETY.package_secret_match_locations(b"\x89PNG\r\n\x1a\n\x00\xffclean", ".png"),
            [],
        )

    def test_package_scanner_covers_utf16_endianness_bom_and_alignment(self) -> None:
        fixture = "sk-" + "U" * 40
        prefix = b"\x81\x82\x83"
        variants = (
            ("le-no-bom", fixture.encode("utf-16-le"), len(prefix)),
            ("be-no-bom", fixture.encode("utf-16-be"), len(prefix)),
            ("le-bom", b"\xff\xfe" + fixture.encode("utf-16-le"), len(prefix) + 2),
            ("be-bom", b"\xfe\xff" + fixture.encode("utf-16-be"), len(prefix) + 2),
        )
        for label, encoded, expected_offset in variants:
            with self.subTest(label=label):
                locations = SAFETY.package_secret_match_locations(prefix + encoded, "")
                self.assertIn(("openai_api_key", expected_offset), locations)
                self.assertNotIn(fixture, repr(locations))

    def test_package_scanner_covers_utf32_endianness_bom_alignment_and_windows(self) -> None:
        fixture = "sk-" + "U" * 40
        variants = (
            ("le-no-bom", b"", fixture.encode("utf-32-le")),
            ("be-no-bom", b"", fixture.encode("utf-32-be")),
            ("le-bom", b"\xff\xfe\x00\x00", fixture.encode("utf-32-le")),
            ("be-bom", b"\x00\x00\xfe\xff", fixture.encode("utf-32-be")),
        )
        for label, bom, encoded in variants:
            for phase in range(4):
                for suffix in ("", ".bin", ".dat"):
                    with self.subTest(label=label, phase=phase, suffix=suffix):
                        prefix = b"\x81" * phase
                        locations = SAFETY.package_secret_match_locations(
                            prefix + bom + encoded,
                            suffix,
                        )
                        self.assertIn(
                            ("openai_api_key", len(prefix) + len(bom)),
                            locations,
                        )
                        self.assertNotIn(fixture, repr(locations))

        prefix = b"\x82" * 61
        with (
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 64),
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 256),
        ):
            locations = SAFETY.package_secret_match_locations(
                prefix + fixture.encode("utf-32-le"),
                "",
            )
        self.assertEqual(locations.count(("openai_api_key", len(prefix))), 1)
        self.assertNotIn(fixture, repr(locations))

    def test_package_scanner_preserves_non_ascii_utf_assignment_values(self) -> None:
        encodings = ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be")
        for secret in ("é" * 40, "密碼值" * 16):
            fixture = "password=" + secret
            for encoding in encodings:
                with self.subTest(encoding=encoding, codepoint=ord(secret[0])):
                    started = time.perf_counter()
                    locations = SAFETY.package_secret_match_locations(
                        fixture.encode(encoding),
                        "",
                    )
                    self.assertIn(("generic_credential_assignment", 0), locations)
                    self.assertNotIn(secret, repr(locations))
                    self.assertLess(time.perf_counter() - started, 1.0)
                    self.assertEqual(
                        SAFETY.package_secret_match_locations(
                            fixture.encode(encoding),
                            ".txt",
                        ),
                        [("package_text_invalid_utf8", 0)],
                    )

        byte_fixtures = (
            ("utf8-cjk", ("password=" + "密碼值" * 16).encode("utf-8")),
            ("utf8-cyrillic", ("password=" + "тайна" * 10).encode("utf-8")),
            ("opaque-password", b"password=" + b"\xff" * 40),
            ("opaque-api-key", b"api_key=" + b"\x80\x81" * 20),
        )
        for label, encoded in byte_fixtures:
            with self.subTest(binary_value=label):
                locations = SAFETY.package_secret_match_locations(encoded, "")
                self.assertIn(("generic_credential_assignment", 0), locations)
                self.assertNotIn(repr(encoded), repr(locations))

        secret = "密碼值" * 16
        fixture = "password=" + secret
        prefix = b"\x82" * 61
        with (
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 64),
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 512),
        ):
            for encoding in encodings:
                with self.subTest(boundary_encoding=encoding):
                    locations = SAFETY.package_secret_match_locations(
                        prefix + fixture.encode(encoding),
                        ".bin",
                    )
                    self.assertEqual(
                        locations.count(
                            ("generic_credential_assignment", len(prefix))
                        ),
                        1,
                    )
                    self.assertNotIn(secret, repr(locations))

    def test_package_scanner_cue_anchors_wide_structural_records(self) -> None:
        ascii_secret = "V" * 40
        forms = (
            ("block", "name: password\nvalue: " + ascii_secret + "\n"),
            ("table", "| password | " + ascii_secret + " |\n"),
        )
        boms = {
            "utf-16-le": b"\xff\xfe",
            "utf-16-be": b"\xfe\xff",
            "utf-32-le": b"\xff\xfe\x00\x00",
            "utf-32-be": b"\x00\x00\xfe\xff",
        }
        with (
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 64),
            mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 512),
        ):
            for encoding, bom in boms.items():
                for label, fixture in forms:
                    for include_bom in (False, True):
                        for prefix_length in (0, 2, 3, 61, 63, 64, 65):
                            with self.subTest(
                                encoding=encoding,
                                form=label,
                                bom=include_bom,
                                prefix_length=prefix_length,
                            ):
                                prefix = b"\x81" * prefix_length
                                marker = bom if include_bom else b""
                                locations = SAFETY.package_secret_match_locations(
                                    prefix + marker + fixture.encode(encoding),
                                    "",
                                )
                                expected_offset = len(prefix) + len(marker)
                                if label == "table":
                                    expected_offset += len("|".encode(encoding))
                                self.assertIn(
                                    (
                                        "generic_credential_assignment",
                                        expected_offset,
                                    ),
                                    locations,
                                )
                                self.assertNotIn(ascii_secret, repr(locations))

        non_ascii_secret = "密碼值" * 16
        for encoding in boms:
            for label, template in (
                ("block", "name: password\nvalue: {}\n"),
                ("table", "| password | {} |\n"),
            ):
                with self.subTest(
                    encoding=encoding,
                    non_ascii_form=label,
                ):
                    prefix = b"\x82" * 3
                    locations = SAFETY.package_secret_match_locations(
                        prefix + template.format(non_ascii_secret).encode(encoding),
                        "",
                    )
                    expected_offset = len(prefix)
                    if label == "table":
                        expected_offset += len("|".encode(encoding))
                    self.assertIn(
                        ("generic_credential_assignment", expected_offset),
                        locations,
                    )
                    self.assertNotIn(non_ascii_secret, repr(locations))

    def test_package_scanner_covers_shortest_utf16_assignment_across_windows(self) -> None:
        fixture = assemble_fixture("Api", "Key=x")
        for endian in ("utf-16-le", "utf-16-be"):
            with self.subTest(endian=endian), (
                mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_WINDOW_BYTES", 12)
            ), mock.patch.object(SAFETY, "PACKAGE_BINARY_SCAN_OVERLAP_BYTES", 16):
                prefix = b"\x80" * 7
                locations = SAFETY.package_secret_match_locations(prefix + fixture.encode(endian), "")
                self.assertIn(("generic_credential_assignment", len(prefix)), locations)
                self.assertNotIn(fixture, repr(locations))

    def test_known_source_text_scans_semantic_credentials_and_preserves_placeholders(self) -> None:
        fixture = "this-is-a-real-long-password-value"
        unsafe = (
            (".py", "PASSWORD = " + repr(fixture)),
            (".json", '{"password":' + json.dumps(fixture) + "}"),
            (".sh", "export PASSWORD=" + repr(fixture) + "\n"),
        )
        for suffix, text in unsafe:
            with self.subTest(suffix=suffix):
                locations = SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix)
                self.assertTrue(
                    any(name == "generic_credential_assignment" for name, _offset in locations)
                )
                self.assertNotIn(fixture, repr(locations))

        safe = (
            (".py", 'PASSWORD = "${PASSWORD}"\n'),
            (".json", '{"password":"${PASSWORD}"}\n'),
            (".sh", 'export PASSWORD="${PASSWORD}"\n'),
        )
        for suffix, text in safe:
            with self.subTest(placeholder_suffix=suffix):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix),
                    [],
                )

    def test_package_document_scanner_routes_bounded_structural_credential_contexts(self) -> None:
        fixture = "V" * 40
        unsafe = (
            (
                "markdown-pair",
                ".md",
                "release failure: password, '" + fixture + "'\n",
                "generic_credential_assignment",
                len("release failure: "),
            ),
            (
                "markdown-table",
                ".md",
                "| Field | Value |\n| --- | --- |\n| password | " + fixture + " |\n",
                "generic_credential_assignment",
                len("| Field | Value |\n| --- | --- |\n|"),
            ),
            (
                "text-failure-tuple",
                ".txt",
                "failure=('password', {'value': '" + fixture + "'})\n",
                "generic_credential_assignment",
                len("failure=('"),
            ),
            (
                "yaml-name-value",
                ".yaml",
                "- name: AWS_SECRET_ACCESS_KEY\n  value: " + fixture + "\n",
                "aws_secret_access_key",
                0,
            ),
        )
        for label, suffix, text, expected, expected_offset in unsafe:
            with self.subTest(label=label):
                self.assertIn(expected, SAFETY.secret_findings(text))
                locations = SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix)
                self.assertIn((expected, expected_offset), locations)
                self.assertNotIn(fixture, repr(locations))

        placeholders = (
            (".md", "password, '${PASSWORD}'\n"),
            (".md", "| password | ${PASSWORD} |\n"),
            (".txt", "failure=('password', {'value': '${PASSWORD}'})\n"),
            (
                ".yaml",
                "- name: AWS_SECRET_ACCESS_KEY\n  value: ${AWS_SECRET_ACCESS_KEY}\n",
            ),
        )
        for suffix, text in placeholders:
            with self.subTest(placeholder_suffix=suffix, text_hash=hash(text)):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix),
                    [],
                )

        source_fixture = (
            "PAIR_FIXTURE = " + repr("password, '" + fixture + "'") + "\n"
            "TABLE_FIXTURE = " + repr("| password | " + fixture + " |") + "\n"
            "BLOCK_FIXTURE = "
            + repr("name: AWS_SECRET_ACCESS_KEY\nvalue: " + fixture)
            + "\n"
        )
        self.assertEqual(
            SAFETY.package_secret_match_locations(source_fixture.encode("utf-8"), ".py"),
            [],
        )

    def test_python_constant_join_credentials_are_scanned_and_placeholders_remain_safe(self) -> None:
        fixture = "sk-" + "J" * 40
        source = "API_KEY = ''.join((" + repr("sk-") + ", " + repr("J" * 40) + "))\n"
        locations = SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py")
        self.assertIn(("openai_api_key", 0), locations)
        self.assertNotIn(fixture, repr(locations))

        bytes_source = (
            "API_KEY = b''.join(["
            + repr(b"sk-")
            + ", "
            + repr(b"J" * 40)
            + "])\n"
        )
        bytes_locations = SAFETY.package_secret_match_locations(
            bytes_source.encode("utf-8"),
            ".py",
        )
        self.assertTrue(any(name == "openai_api_key" for name, _ in bytes_locations))
        self.assertNotIn(fixture, repr(bytes_locations))

        tail = "N" * 40
        neutral_sources = (
            "message = ''.join((" + repr("sk-") + ", " + repr(tail) + "))\n",
            "print(''.join((" + repr("sk-") + ", " + repr(tail) + ")))\n",
            "message = b''.join((" + repr(b"sk-") + ", " + repr(tail.encode()) + "))\n",
            "print(b''.join((" + repr(b"sk-") + ", " + repr(tail.encode()) + ")))\n",
        )
        neutral_fixture = "sk-" + tail
        for neutral_source in neutral_sources:
            with self.subTest(context=neutral_source.split("=", 1)[0].strip()):
                neutral_locations = SAFETY.package_secret_match_locations(
                    neutral_source.encode("utf-8"),
                    ".py",
                )
                self.assertTrue(
                    any(name == "openai_api_key" for name, _ in neutral_locations)
                )
                self.assertNotIn(neutral_fixture, repr(neutral_locations))

        placeholder = "API_KEY = ''.join(('${', 'API_KEY', '}'))\n"
        self.assertEqual(
            SAFETY.package_secret_match_locations(placeholder.encode("utf-8"), ".py"),
            [],
        )
        neutral_placeholder = "print(''.join(('${', 'API_KEY', '}')))\n"
        self.assertEqual(
            SAFETY.package_secret_match_locations(
                neutral_placeholder.encode("utf-8"),
                ".py",
            ),
            [],
        )

    def test_semantic_generic_assignments_are_scanned_in_comments_literals_and_json_notes(self) -> None:
        fixture = "semantic-credential-value"
        assignment = "PASSWORD=" + fixture
        unsafe = (
            ("python-comment", ".py", "# " + assignment + "\n"),
            (
                "python-docstring",
                ".py",
                "def fixture():\n    \"\"\"" + assignment + "\"\"\"\n",
            ),
            ("shell-comment", ".sh", "# " + assignment + "\n"),
            ("shell-heredoc", ".sh", "cat <<'EOF'\n" + assignment + "\nEOF\n"),
            ("json-note", ".json", json.dumps({"note": assignment}) + "\n"),
            (
                "json-escaped-note",
                ".json",
                '{"note":"P\\u0041SSWORD\\u003d' + fixture + '"}\n',
            ),
            (
                "python-constant-concat",
                ".py",
                'print("PASS" + "WORD=" + ' + repr(fixture) + ")\n",
            ),
            (
                "python-constant-fstring",
                ".py",
                assemble_fixture('print(f"PASS', "WORD={", repr(fixture), '}\")\n'),
            ),
        )
        for label, suffix, text in unsafe:
            with self.subTest(label=label):
                locations = SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix)
                self.assertTrue(
                    any(name == "generic_credential_assignment" for name, _ in locations)
                )
                self.assertNotIn(fixture, repr(locations))

        placeholder = "PASSWORD=" + "${PASSWORD}"
        safe = (
            (".py", "# " + placeholder + "\n"),
            (
                ".py",
                "def fixture():\n    \"\"\"" + placeholder + "\"\"\"\n",
            ),
            (".sh", "# " + placeholder + "\n"),
            (".sh", "cat <<'EOF'\n" + placeholder + "\nEOF\n"),
            (".json", json.dumps({"note": placeholder}) + "\n"),
            (
                ".py",
                'print("PASS" + "WORD=" + ' + repr("${PASSWORD}") + ")\n",
            ),
            (
                ".py",
                assemble_fixture(
                    'print(f"PASS',
                    "WORD={",
                    repr("${PASSWORD}"),
                    '}\")\n',
                ),
            ),
        )
        for suffix, text in safe:
            with self.subTest(placeholder_suffix=suffix, text_hash=hash(text)):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(text.encode("utf-8"), suffix),
                    [],
                )

    def test_package_python_ast_closes_constant_obfuscation_and_aliases(self) -> None:
        provider_fixture = "sk-" + "V" * 40
        generic_fixture = "this-is-a-real-long-password-value"
        payloads = (
            ("adjacent", 'TOKEN = "sk-" "' + "V" * 40 + '"\n', "openai_api_key"),
            ("hex", 'TOKEN = "\\x73\\x6b\\x2d' + "V" * 40 + '"\n', "openai_api_key"),
            ("secret-key", "secret_key = " + repr(generic_fixture) + "\n", "generic_credential_assignment"),
            ("camel", "accessToken = " + repr(generic_fixture) + "\n", "generic_credential_assignment"),
            (
                "concat",
                "PASSWORD = " + repr("this-is-a-real-") + " + " + repr("long-password-value") + "\n",
                "generic_credential_assignment",
            ),
            (
                "constant-fstring",
                assemble_fixture("PASS", 'WORD = f"', generic_fixture, '"\n'),
                "generic_credential_assignment",
            ),
        )
        for label, source, expected in payloads:
            with self.subTest(label=label):
                locations = SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py")
                self.assertTrue(any(name == expected for name, _offset in locations))
                self.assertNotIn(provider_fixture, repr(locations))
                self.assertNotIn(generic_fixture, repr(locations))

        placeholder_source = "PASSWORD = " + repr("${") + " + " + repr("PASSWORD}") + "\n"
        self.assertEqual(
            SAFETY.package_secret_match_locations(placeholder_source.encode("utf-8"), ".py"),
            [],
        )

    def test_package_python_ast_covers_defaults_keys_destructuring_and_setters(self) -> None:
        fixture = "python-context-credential-value"
        unsafe = (
            "def f(password=" + repr(fixture) + "):\n    pass\n",
            "async def f(*, password=" + repr(fixture) + "):\n    pass\n",
            "handler = lambda password=" + repr(fixture) + ": None\n",
            'config["PASS" + "WORD"] = ' + repr(fixture) + "\n",
            'config = {"PASS" + "WORD": ' + repr(fixture) + "}\n",
            "(password, other) = (" + repr(fixture) + ", 'safe')\n",
            "config.setdefault('PASSWORD', " + repr(fixture) + ")\n",
            "os.putenv('PASSWORD', " + repr(fixture) + ")\n",
            "setenv('PASSWORD', " + repr(fixture.encode("utf-8")) + ")\n",
        )
        for index, source in enumerate(unsafe):
            with self.subTest(unsafe=index):
                locations = SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py")
                self.assertTrue(
                    any(name == "generic_credential_assignment" for name, _ in locations)
                )
                self.assertNotIn(fixture, repr(locations))

        placeholder = "${PASSWORD}"
        safe = (
            "def f(password=" + repr(placeholder) + "):\n    pass\n",
            'config["PASS" + "WORD"] = ' + repr(placeholder) + "\n",
            'config = {"PASS" + "WORD": ' + repr(placeholder) + "}\n",
            "(password, other) = (" + repr(placeholder) + ", 'safe')\n",
            "config.setdefault('PASSWORD', " + repr(placeholder) + ")\n",
            "os.putenv('PASSWORD', " + repr(placeholder) + ")\n",
        )
        for index, source in enumerate(safe):
            with self.subTest(placeholder=index):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py"),
                    [],
                )

    def test_package_python_bytes_literals_and_constant_concatenation(self) -> None:
        fixture = "this-is-a-real-long-password-value"
        variants = (
            "PASSWORD = " + repr(fixture.encode("utf-8")) + "\n",
            (
                "PASSWORD = "
                + repr("this-is-a-real-".encode("utf-8"))
                + " + "
                + repr("long-password-value".encode("utf-8"))
                + "\n"
            ),
        )
        for index, source in enumerate(variants):
            with self.subTest(index=index):
                locations = SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py")
                self.assertTrue(
                    any(name == "generic_credential_assignment" for name, _ in locations)
                )
                self.assertNotIn(fixture, repr(locations))

        placeholders = (
            "PASSWORD = " + repr(b"${PASSWORD}") + "\n",
            "PASSWORD = " + repr(b"${") + " + " + repr(b"PASSWORD}") + "\n",
        )
        for index, source in enumerate(placeholders):
            with self.subTest(placeholder=index):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(source.encode("utf-8"), ".py"),
                    [],
                )

    def test_package_path_scanner_rejects_secret_file_and_directory_names(self) -> None:
        fixture = "sk-" + "P" * 40
        variants = (f"{fixture}.txt", f"safe/{fixture}/payload.txt")
        for relative in variants:
            with self.subTest(relative_hash=hash(relative)):
                locations = SAFETY.package_secret_path_match_locations(relative)
                self.assertTrue(any(name == "openai_api_key" for name, _ in locations))
                self.assertNotIn(fixture, repr(locations))
        self.assertEqual(
            SAFETY.package_secret_path_match_locations("safe/${TOKEN}/payload.txt"),
            [],
        )

    def test_config_and_javascript_assignments_and_placeholders(self) -> None:
        fixture = "this-is-a-real-long-password-value"
        config_suffixes = (".cfg", ".conf", ".ini", ".toml", ".yaml", ".yml")
        script_suffixes = (".js", ".jsx", ".ts", ".tsx")
        for suffix in config_suffixes:
            with self.subTest(unsafe_suffix=suffix):
                unsafe = "password = " + json.dumps(fixture) + "\n"
                locations = SAFETY.package_secret_match_locations(unsafe.encode("utf-8"), suffix)
                self.assertTrue(any(name == "generic_credential_assignment" for name, _ in locations))
                self.assertNotIn(fixture, repr(locations))
            with self.subTest(placeholder_suffix=suffix):
                safe = 'password = "${PASSWORD}"\n'
                self.assertEqual(SAFETY.package_secret_match_locations(safe.encode("utf-8"), suffix), [])
        for suffix in script_suffixes:
            with self.subTest(unsafe_suffix=suffix):
                unsafe = "const accessToken = " + json.dumps(fixture) + ";\n"
                locations = SAFETY.package_secret_match_locations(unsafe.encode("utf-8"), suffix)
                self.assertTrue(any(name == "generic_credential_assignment" for name, _ in locations))
                self.assertNotIn(fixture, repr(locations))
            with self.subTest(placeholder_suffix=suffix):
                safe = 'const accessToken = "${ACCESS_TOKEN}";\n'
                self.assertEqual(SAFETY.package_secret_match_locations(safe.encode("utf-8"), suffix), [])

    def test_package_known_text_oversize_short_circuits_parsers(self) -> None:
        with mock.patch.object(SAFETY, "MAX_SECRET_SCAN_CHARACTERS", 64):
            SAFETY._PACKAGE_SECRET_SCAN_CACHE.clear()
            oversized = ("Z" * 65).encode("utf-8")
            started = time.monotonic()
            with mock.patch.object(SAFETY.ast, "parse", side_effect=AssertionError("AST parser called")):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(oversized, ".py"),
                    [("secret_scan_input_too_large", 0)],
                )
            with mock.patch.object(SAFETY.json, "loads", side_effect=AssertionError("JSON parser called")):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(oversized, ".json"),
                    [("secret_scan_input_too_large", 0)],
                )
            with mock.patch.object(
                SAFETY,
                "_credential_assignment_matches",
                side_effect=AssertionError("shell parser called"),
            ):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(oversized, ".sh"),
                    [("secret_scan_input_too_large", 0)],
                )
            self.assertLess(time.monotonic() - started, 0.5)

    def test_package_fstring_constant_evaluation_is_linear_and_bounded(self) -> None:
        joined = SAFETY.ast.JoinedStr(values=[SAFETY.ast.Constant(value="x") for _ in range(20_000)])
        with mock.patch.object(SAFETY, "PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS", 25_000):
            started = time.monotonic()
            self.assertEqual(len(SAFETY._bounded_python_constant_string(joined)), 20_000)
            self.assertLess(time.monotonic() - started, 0.5)

    def test_package_scan_cache_reuses_only_redacted_metadata(self) -> None:
        source = ("PASSWORD = " + repr("this-is-a-real-long-password-value") + "\n").encode("utf-8")
        SAFETY._PACKAGE_SECRET_SCAN_CACHE.clear()
        with mock.patch.object(
            SAFETY,
            "_package_python_match_locations",
            wraps=SAFETY._package_python_match_locations,
        ) as scanner:
            first = SAFETY.package_secret_match_locations(source, ".py")
            for _ in range(4):
                self.assertEqual(SAFETY.package_secret_match_locations(source, ".py"), first)
            self.assertEqual(scanner.call_count, 1)
        first.append(("caller_mutation", 0))
        self.assertNotIn(
            ("caller_mutation", 0),
            SAFETY.package_secret_match_locations(source, ".py"),
        )

    def test_secret_scanner_preserves_documentation_placeholders_and_common_safe_shapes(self) -> None:
        safe_values = [
            "task-spec.yaml",
            "skill-specific",
            "sk-abc",
            "github_" + "pat_<redacted>",
            "sk-" + "ant-api03-<redacted>",
            "hf_token",
            "HF_TOKEN=${HF_TOKEN}",
            "gl" + "pat-<redacted>",
            "pk" + "_live_" + "A" * 48,
            "sk" + "_live_<redacted>",
            "AI" + "za<redacted>",
            "AIDA" + "B" * 16,
            "AWS_" + "SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}",
            "xox" + "b-<redacted>",
            "1.2.3",
            "header.payload.signature",
            "BEGIN PRIVATE KEY",
            "a" * 64,
            "password=<redacted>",
            assemble_fixture("OPENROUTER_", "API_", "KEY=your_openrouter_api_key"),
        ]
        for index, value in enumerate(safe_values):
            with self.subTest(case=index):
                self.assertEqual(SAFETY.secret_findings(value), [])

    def test_safe_json_serialization_rejects_nested_secret_without_echoing_it(self) -> None:
        fixture = "sk-" + "Z" * 40
        try:
            SAFETY.serialize_safe_persistent_json(
                {"actor": "worker", "summary": {"evidence": [fixture]}},
            )
        except ValueError as exc:
            message = str(exc)
            if fixture in message:
                self.fail("safe JSON rejection leaked fixture")
            self.assertIn("openai_api_key", message)
        else:
            self.fail("safe JSON serialization accepted nested secret")

    def test_semantic_json_escape_and_duplicate_keys_fail_closed(self) -> None:
        fixture = "sk-" + "A" * 40
        escaped = "sk-" + "\\u0041" * 40
        payloads = [
            '{"summary":"' + escaped + '"}',
            '{"summary":"' + escaped + '","summary":"safe"}',
        ]
        for index, payload in enumerate(payloads):
            with self.subTest(case=index):
                try:
                    SAFETY.parse_safe_persistent_json(payload)
                except ValueError as exc:
                    if fixture in str(exc):
                        self.fail(f"semantic JSON rejection leaked fixture for case {index}")
                else:
                    self.fail(f"semantic JSON accepted escaped or duplicate fixture for case {index}")

    def test_utf16_embedded_secret_is_rejected_before_base64(self) -> None:
        fixture = "gl" + "pat-" + "U" * 32
        encoded = fixture.encode("utf-16-le")
        try:
            SAFETY.assert_safe_embedded_content_bytes(encoded)
        except ValueError as exc:
            if fixture in str(exc):
                self.fail("UTF-16 rejection leaked fixture")
            self.assertIn("gitlab_token", str(exc))
        else:
            self.fail("UTF-16 embedded secret was accepted")

    def test_assignment_placeholders_must_match_exactly(self) -> None:
        safe_values = [
            'OPENAI_API_KEY=""',
            'HF_TOKEN="${HF_TOKEN}"',
            'GITHUB_TOKEN="<redacted>"',
            'OPENAI_API_KEY="your_openai_api_key"',
            "password=YOUR_PASSWORD",
            "OPENAI_API_KEY=<redacted:openai_api_key>",
            "password=<redacted:generic_credential_assignment>",
            "postgres://user:<redacted>@example.invalid/db",
            "https://user:placeholder@example.invalid/",
        ]
        for index, value in enumerate(safe_values):
            with self.subTest(safe=index):
                self.assertEqual(SAFETY.secret_findings(value), [])

        suffix = "S" * 24
        unsafe_values = [
            ("provider_credential_assignment", "OPENAI_API_KEY=${OPENAI_API_KEY}" + suffix),
            ("provider_credential_assignment", "OPENAI_API_KEY=YOUR_OPENAI_API_KEY" + suffix),
            ("provider_credential_assignment", "OPENAI_API_KEY=<redacted>" + suffix),
            ("aws_secret_access_key", "AWS_SECRET_ACCESS_KEY=<redacted>" + suffix),
            ("aws_session_token", "AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN}" + suffix),
            ("generic_credential_assignment", "password=<redacted>" + suffix),
            ("generic_credential_assignment", "password=<redacted>," + suffix),
            ("generic_credential_assignment", "password=${PASSWORD}," + suffix),
            ("generic_credential_assignment", "password=YOUR_PASSWORD," + suffix),
            ("generic_credential_assignment", "password=placeholder," + suffix),
            ("generic_credential_assignment", 'password="<redacted>"' + suffix),
            ("generic_credential_assignment", "password='${PASSWORD}'" + suffix),
            (
                "uri_userinfo_credential",
                "postgres://user:<redacted>@" + suffix + "@example.invalid/db",
            ),
        ]
        for expected, value in unsafe_values:
            with self.subTest(finding=expected):
                self.assertIn(expected, SAFETY.secret_findings(value))

    def test_contextual_common_credential_names_are_covered_without_policy_false_positives(self) -> None:
        fixtures = [
            ("generic_credential_assignment", "MY_API_KEY=" + "A" * 32),
            ("generic_credential_assignment", "DATABASE_PASSWORD=" + "B" * 32),
            ("generic_credential_assignment", "GITHUB_CLIENT_SECRET=" + "C" * 40),
            (
                "aws_secret_access_key",
                assemble_fixture('{"Secret', 'AccessKey":"', "D" * 40, '"}'),
            ),
            (
                "aws_session_token",
                assemble_fixture('{"Session', 'Token":"', "E" * 48, '"}'),
            ),
            ("provider_credential_assignment", "SLACK_SIGNING_SECRET=" + "F" * 32),
            ("generic_credential_assignment", "SERVICE_API_KEY_PROD=" + "G" * 32),
            (
                "generic_credential_assignment",
                assemble_fixture('"database', "Pass", 'word":"', "H" * 32, '"'),
            ),
            (
                "generic_credential_assignment",
                assemble_fixture('"my', "Api", 'Key":"', "I" * 32, '"'),
            ),
            (
                "generic_credential_assignment",
                assemble_fixture('"github', "Client", 'Secret":"', "J" * 40, '"'),
            ),
            (
                "provider_credential_assignment",
                assemble_fixture('"slack', "Signing", 'Secret":"', "K" * 32, '"'),
            ),
            (
                "provider_credential_assignment",
                assemble_fixture('"openai', "Api", 'Key":"', "L" * 32, '"'),
            ),
            ("generic_credential_assignment", "SECRET_KEY=" + "M" * 40),
            ("generic_credential_assignment", "DJANGO_SECRET_KEY=" + "N" * 40),
            ("generic_credential_assignment", "SECRET_KEY_BASE=" + "O" * 40),
            ("generic_credential_assignment", "APP_SECRET=" + "P" * 40),
            ("generic_credential_assignment", "PRIVATE_TOKEN=" + "Q" * 40),
        ]
        for expected, fixture in fixtures:
            with self.subTest(expected=expected):
                self.assertIn(expected, SAFETY.secret_findings(fixture))
                diagnostic = SAFETY.safe_log_text(fixture)
                self.assertNotIn(fixture, diagnostic)

        safe_controls = [
            "MY_API_KEY=${MY_API_KEY}",
            "DATABASE_PASSWORD=<redacted>",
            "PASSWORD_POLICY=strict",
            "CLIENT_SECRET_ROTATION_DAYS=30",
            "API_KEY_FORMAT=uuid",
            '"databasePassword":"${databasePassword}"',
            '"openaiApiKey":"$openaiApiKey"',
            "{password: <redacted>, next: value}",
            "password: <redacted>,",
            "PASSWORD=${PASSWORD}; export PASSWORD",
            'password = "<redacted>".',
        ]
        for fixture in safe_controls:
            with self.subTest(safe=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])

    def test_human_readable_and_provider_credential_labels_are_covered(self) -> None:
        fixtures = [
            ("generic_credential_assignment", "API Key: " + "A" * 32),
            ("generic_credential_assignment", "Client Secret: " + "B" * 32),
            ("generic_credential_assignment", "Access Token: " + "C" * 32),
            ("generic_credential_assignment", '{"api key":"' + "D" * 32 + '"}'),
            ("aws_secret_access_key", "AWS Secret Access Key: " + "E" * 40),
            ("aws_session_token", "AWS Session Token: " + "F" * 48),
            ("provider_credential_assignment", "OpenAI API Key: " + "G" * 32),
            ("provider_credential_assignment", "GitHub Token: " + "H" * 32),
            ("provider_credential_assignment", "Slack Signing Secret: " + "I" * 32),
            ("provider_credential_assignment", "Google Client Secret: " + "J" * 32),
            ("aws_secret_access_key", "Secret Access Key: " + "K" * 40),
            ("aws_secret_access_key", "secret_access_key=" + "L" * 40),
            ("aws_session_token", "Session Token: " + "M" * 48),
            ("aws_session_token", "session_token=" + "N" * 48),
        ]
        for expected, fixture in fixtures:
            with self.subTest(expected=expected, fixture=fixture[:24]):
                self.assertIn(expected, SAFETY.secret_findings(fixture))

        safe_placeholders = [
            "API Key: ${API_KEY}",
            "Client Secret: YOUR_CLIENT_SECRET",
            "AWS Secret Access Key: ${AWS_SECRET_ACCESS_KEY}",
            "Session Token: <redacted>",
            '"Google Client Secret":"${GOOGLE_CLIENT_SECRET}"',
        ]
        for fixture in safe_placeholders:
            with self.subTest(safe=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])

    def test_structured_and_adjacent_credential_contexts_fail_closed(self) -> None:
        secret = "S" * 40
        fixtures = [
            "| AWS Secret Access Key | " + secret + " |",
            "AWS Secret Access Key -> " + secret,
            "AWS Secret Access Key => " + secret,
            "AWS Secret Access Key — " + secret,
            '["AWS Secret Access Key","' + secret + '"]',
            '{"headers":[["AWS Secret Access Key","' + secret + '"]]}',
            '{"name":"AWS_SECRET_ACCESS_KEY","value":"' + secret + '"}',
            '{"key":"AWS Secret Access Key","value":"' + secret + '"}',
            '{"credential_name":"AWS Secret Access Key","credential_value":"' + secret + '"}',
            '{"env":[{"secretName":"AWS Secret Access Key","secretValue":"' + secret + '"}]}',
            "- name: AWS_SECRET_ACCESS_KEY\n  value: " + secret,
            "credential_name: AWS Secret Access Key\ncredential_value: " + secret,
            "Credential: AWS Secret Access Key\nValue: " + secret,
            '{"name":"Authorization","value":"Bearer ' + secret + '"}',
        ]
        for index, fixture in enumerate(fixtures):
            with self.subTest(case=index):
                self.assertTrue(SAFETY.secret_findings(fixture))
                with self.assertRaises(ValueError):
                    SAFETY.assert_safe_persistent_text(fixture)
                self.assertNotIn(secret, SAFETY.safe_log_text(fixture))

        safe_placeholders = [
            "| AWS Secret Access Key | ${AWS_SECRET_ACCESS_KEY} |",
            '["AWS Secret Access Key","${AWS_SECRET_ACCESS_KEY}"]',
            '{"name":"AWS_SECRET_ACCESS_KEY","value":"<redacted>"}',
            "- name: AWS_SECRET_ACCESS_KEY\n  value: YOUR_AWS_SECRET_ACCESS_KEY",
        ]
        for fixture in safe_placeholders:
            with self.subTest(safe=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])

    def test_prefixed_non_json_and_duplicate_structured_contexts_never_leak(self) -> None:
        secret = "V" * 40
        fixtures = [
            'failure={"name":"AWS_SECRET_ACCESS_KEY","value":"' + secret + '"}',
            "failure={'name':'AWS_SECRET_ACCESS_KEY','value':'" + secret + "'}",
            "name=AWS_SECRET_ACCESS_KEY,value=" + secret,
            "credential_name: AWS Secret Access Key, credential_value: " + secret,
            'failure=["AWS Secret Access Key","' + secret + '"]',
            '{"name":"AWS_SECRET_ACCESS_KEY","value":"'
            + secret
            + '","name":"safe","value":"safe"}',
            '{"name":"AWS_SECRET_ACCESS_KEY","value":"'
            + "\\u0056" * 40
            + '","name":"safe","value":"safe"}',
            'failure={broken ["AWS Secret Access Key","' + secret + '"]',
            'failure={"outer":["AWS Secret Access Key","' + secret + '"]',
            "failure=['AWS Secret Access Key','" + secret + "']",
            "headers=[('AWS Secret Access Key','" + secret + "')]",
            "failure=('AWS Secret Access Key','" + secret + "')",
            "failure=('password', b'hunter2')",
            "failure=('API_KEY', u'abcd1234')",
            "failure=('password', r'letmein123')",
            "headers=[(b'Authorization', b'Basic dXNlcjpwYXNz')]",
            "failure=('password', bytearray(b'hunter2'))",
            "failure=('password', bytes(b'hunter2'))",
            assemble_fixture("pass", "word='''hunter2'''"),
            assemble_fixture("API_", 'KEY="""abcd1234"""'),
            "failure=('password', '''hunter2''')",
            "failure=('password', `hunter2`)",
        ]
        for index, fixture in enumerate(fixtures):
            with self.subTest(case=index):
                self.assertTrue(SAFETY.secret_findings(fixture))
                diagnostic = SAFETY.safe_log_text(fixture)
                self.assertNotIn(secret, diagnostic)
                self.assertNotIn("\\u0056" * 8, diagnostic)

        safe_pairs = [
            "['AWS Secret Access Key','${AWS_SECRET_ACCESS_KEY}']",
            "AWS Secret Access Key documentation",
            "| AWS Secret Access Key | <redacted> |",
            "PASSWORD is required.",
            "OPENAI_API_KEY must be supplied via the environment.",
            "failure=('password', `<redacted>`)",
        ]
        for fixture in safe_pairs:
            with self.subTest(safe=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])

    def test_pair_context_parser_preserves_suffix_matches_with_many_prefix_segments(self) -> None:
        secret = "V" * 40
        fixtures = [
            "alpha-beta-gamma-delta-epsilon-api-key, '" + secret + "'",
            "'" + "-".join(["segment"] * 48 + ["api", "key"]) + "', '" + secret + "'",
        ]
        for fixture in fixtures:
            with self.subTest(length=len(fixture)):
                started = time.perf_counter()
                self.assertIn("generic_credential_assignment", SAFETY.secret_findings(fixture))
                self.assertLess(time.perf_counter() - started, 1.0)

    def test_pair_context_parser_preserves_underscore_and_mixed_suffixes(self) -> None:
        secret = "V" * 40
        underscore = "_".join(["segment"] * 64 + ["api", "key"])
        mixed = ""
        separators = ("-", ".", " ", "_")
        for count in range(64, 128):
            candidate = "".join(
                "segment" + separators[index % len(separators)]
                for index in range(count)
            ) + "api_key"
            if candidate[-SAFETY.MAX_PAIR_CONTEXT_LABEL_CHARACTERS] == "_":
                mixed = candidate
                break
        self.assertTrue(mixed)
        fixtures = (underscore, mixed)
        for label in fixtures:
            fixture = f"'{label}', '{secret}'"
            with self.subTest(label_length=len(label)):
                started = time.perf_counter()
                self.assertIn(
                    "generic_credential_assignment",
                    SAFETY.secret_findings(fixture),
                )
                self.assertLess(time.perf_counter() - started, 1.0)
                started = time.perf_counter()
                self.assertTrue(
                    any(
                        name == "generic_credential_assignment"
                        for name, _offset in SAFETY.package_secret_match_locations(
                            fixture.encode("utf-8"),
                            ".txt",
                        )
                    )
                )
                self.assertLess(time.perf_counter() - started, 1.0)

        adversarial_label = "_".join(["segment"] * 8192 + ["api", "key"])
        adversarial = f"'{adversarial_label}', '{secret}'"
        started = time.perf_counter()
        self.assertIn(
            "generic_credential_assignment",
            SAFETY.secret_findings(adversarial),
        )
        self.assertLess(time.perf_counter() - started, 2.0)

    def test_pair_context_concatenation_cannot_suppress_a_literal_secret(self) -> None:
        secret = "V" * 40
        fixtures = (
            f"failure=('password', '{secret}' + '')",
            f'failure=("password", "{secret}" + "safe")',
            f"failure=('client_secret', b'{secret}' + b'')",
            f"failure=('password', value: '{secret}' + '')",
        )
        for fixture in fixtures:
            with self.subTest(prefix=fixture[:32]):
                self.assertIn(
                    "generic_credential_assignment",
                    SAFETY.secret_findings(fixture),
                )
                locations = SAFETY.package_secret_match_locations(
                    fixture.encode("utf-8"),
                    ".txt",
                )
                self.assertTrue(
                    any(
                        name == "generic_credential_assignment"
                        for name, _offset in locations
                    )
                )
                self.assertNotIn(secret, repr(locations))

        placeholder = "failure=('password', '$PASSWORD')"
        self.assertEqual(SAFETY.secret_findings(placeholder), [])
        self.assertEqual(
            SAFETY.package_secret_match_locations(
                placeholder.encode("utf-8"),
                ".txt",
            ),
            [],
        )
        placeholder_concatenations = (
            "failure=('password', '$PASSWORD' + '')",
            "failure=('password', '${' + 'PASSWORD}')",
            "failure=('password', '<redacted>' + '')",
        )
        for fixture in placeholder_concatenations:
            with self.subTest(placeholder_concat=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])
                self.assertEqual(
                    SAFETY.package_secret_match_locations(
                        fixture.encode("utf-8"),
                        ".txt",
                    ),
                    [],
                )

        unsupported = "failure=('password', '$PASSWORD' + runtime_value)"
        unsupported_expressions = (
            unsupported,
            "failure=('password', '$PASSWORD' + '' runtime_value)",
            "failure=('password', '$PASSWORD' + '' * 5)",
            "failure=('password', '$PASSWORD' + '' .format())",
            "failure=('password', '$PASSWORD' + ''[0])",
            "failure=('password', '$PASSWORD' + '' 'adjacent')",
            f"failure=('password', '$PASSWORD' + '' and '{secret}')",
            f"failure=('password', '$PASSWORD' + ''\n and '{secret}')",
            f"failure=('password', '$PASSWORD' + '' # note\n + '{secret}')",
            "failure=('password', '$' + b'PASSWORD')",
        )
        for fixture in unsupported_expressions:
            with self.subTest(unsupported=fixture[:48]):
                self.assertIn(
                    "secret_scan_credential_expression_unsupported",
                    SAFETY.secret_findings(fixture),
                )
                with self.assertRaises(ValueError):
                    SAFETY.assert_safe_persistent_text(fixture)
                self.assertTrue(
                    any(
                        name == "secret_scan_credential_expression_unsupported"
                        for name, _offset in SAFETY.package_secret_match_locations(
                            fixture.encode("utf-8"),
                            ".txt",
                        )
                    )
                )
                if secret in fixture:
                    self.assertNotIn(secret, SAFETY.safe_log_text(fixture))

    def test_pair_context_expression_grammar_precedes_placeholder_suppression(self) -> None:
        secret = "V" * 40
        unsupported = (
            f"failure=('password', ('$PASSWORD' + '') and '{secret}')",
            f"failure=('password', ['$PASSWORD' + ''] and '{secret}')",
            f"failure=('password', {{'value': '$PASSWORD' + ''}} and '{secret}')",
            f"failure=('password', '$PASSWORD' and '{secret}')",
            f"failure=('password', '$PASSWORD' or '{secret}')",
            f"failure=('password', '$PASSWORD' * 0 + '{secret}')",
            f"failure=('password', '$PASSWORD'[0] + '{secret}')",
            f"failure=('password', '$PASSWORD'.format() + '{secret}')",
            f"failure=('password', '$PASSWORD' runtime_value + '{secret}')",
            f"failure=('password', '$PASSWORD' '{secret}')",
            f"failure=('password', '$PASSWORD' # note\n + '{secret}')",
            f"failure=('password', f'{secret}' + '')",
            f"failure=('password', F'{secret}')",
            f"failure=('password', fr'{secret}' + '')",
            f"failure=('password', rf'{secret}')",
            f"failure=('password', str('{secret}') + '')",
            f"failure=('password', memoryview(b'{secret}') + b'')",
            f"failure=('password', bytes(b'$PASSWORD') and b'{secret}')",
            f"failure=('password', {{'value': str('{secret}')}})",
            f"failure=('password', (lambda: '$PASSWORD')() and '{secret}')",
        )
        for fixture in unsupported:
            with self.subTest(unsupported=fixture[:56]):
                self.assertIn(
                    "secret_scan_credential_expression_unsupported",
                    SAFETY.secret_findings(fixture),
                )
                with self.assertRaises(ValueError) as caught:
                    SAFETY.assert_safe_persistent_text(fixture)
                self.assertNotIn(secret, str(caught.exception))
                self.assertNotIn(
                    secret,
                    SAFETY.safe_log_text(fixture, max_characters=16_384),
                )
                for suffix in (".txt", ""):
                    with self.subTest(suffix=suffix):
                        locations = SAFETY.package_secret_match_locations(
                            fixture.encode("utf-8"),
                            suffix,
                        )
                        self.assertTrue(
                            any(
                                name == "secret_scan_credential_expression_unsupported"
                                for name, _offset in locations
                            ),
                            locations,
                        )
                        self.assertNotIn(secret, repr(locations))

        boundary_truncation = (
            "failure=('password', '$PASSWORD'"
            + (" " * 4084)
            + "+ '"
            + secret
            + "')"
        )
        self.assertIn(
            "secret_scan_structured_context_limit",
            SAFETY.secret_findings(boundary_truncation),
        )
        with self.assertRaises(ValueError):
            SAFETY.assert_safe_persistent_text(boundary_truncation)
        self.assertNotIn(
            secret,
            SAFETY.safe_log_text(boundary_truncation, max_characters=16_384),
        )
        for suffix in (".txt", ""):
            locations = SAFETY.package_secret_match_locations(
                boundary_truncation.encode("utf-8"),
                suffix,
            )
            self.assertTrue(
                any(
                    name == "secret_scan_structured_context_limit"
                    for name, _offset in locations
                ),
                locations,
            )
            self.assertNotIn(secret, repr(locations))

        safe_placeholders = (
            "failure=('password', '$PASSWORD')",
            "failure=['password', '${PASSWORD}']",
            "failure=('password', {'value': '<redacted>'})",
            "password, '$PASSWORD'\n",
            "failure=('password', '$' + 'PASSWORD')",
            "failure=('password', '${' + 'PASSWORD}')",
            "failure=('password', b'$' + b'PASSWORD')",
            "failure=('password', r'$' + u'PASSWORD')",
            "password, '$' + 'PASSWORD'\n",
        )
        for fixture in safe_placeholders:
            with self.subTest(safe_placeholder=fixture):
                self.assertEqual(SAFETY.secret_findings(fixture), [])
                SAFETY.assert_safe_persistent_text(fixture)
                for suffix in (".txt", ""):
                    self.assertEqual(
                        SAFETY.package_secret_match_locations(
                            fixture.encode("utf-8"),
                            suffix,
                        ),
                        [],
                    )

    def test_unknown_package_payloads_preserve_structural_credential_pairs(self) -> None:
        secret = "V" * 40
        fixtures = (
            ("", f"failure=('password','{secret}')"),
            ("", '{"name":"password","value":"' + secret + '"}'),
            (".jsonl", '{"name":"password","value":"' + secret + '"}'),
            ("", "name: password\nvalue: " + secret + "\n"),
            (".blob", "| password | " + secret + " |\n"),
        )
        for suffix, fixture in fixtures:
            with self.subTest(suffix=suffix, prefix=fixture[:16]):
                locations = SAFETY.package_secret_match_locations(
                    fixture.encode("utf-8"),
                    suffix,
                )
                self.assertTrue(
                    any(
                        name == "generic_credential_assignment"
                        for name, _offset in locations
                    )
                )
                self.assertNotIn(secret, repr(locations))

        wide_fixture = f"failure=('password','{secret}')"
        for encoding in ("utf-16-le", "utf-16-be", "utf-32-le", "utf-32-be"):
            with self.subTest(structural_encoding=encoding):
                locations = SAFETY.package_secret_match_locations(
                    wide_fixture.encode(encoding),
                    "",
                )
                self.assertTrue(
                    any(
                        name == "generic_credential_assignment"
                        for name, _offset in locations
                    )
                )
                self.assertNotIn(secret, repr(locations))

        boundary_fixture = (
            "password\n"
            + "Z" * (8189 - len("password\n"))
            + "\npassword"
            + " " * 64
            + ", '"
            + secret
            + "'"
        )
        boundary_locations = SAFETY.package_secret_match_locations(
            boundary_fixture.encode("utf-8"),
            "",
        )
        self.assertTrue(
            any(
                name == "generic_credential_assignment"
                for name, _offset in boundary_locations
            )
        )
        self.assertNotIn(secret, repr(boundary_locations))

        safe = b"failure=('password','$PASSWORD')"
        self.assertEqual(SAFETY.package_secret_match_locations(safe, ""), [])

    def test_tracked_high_entropy_binary_remains_clean_and_bounded(self) -> None:
        payload = (REPO_ROOT / "docs/assets/codexqb-workflow.png").read_bytes()
        started = time.perf_counter()
        self.assertEqual(
            SAFETY.package_secret_match_locations(payload, ".png"),
            [],
        )
        self.assertLess(time.perf_counter() - started, 5.0)

    def test_markdown_package_scanner_applies_visible_label_semantics(self) -> None:
        secret = "V" * 40
        labels = (
            r"api\-key",
            "api&#45;key",
            "**password**",
            "~~password~~",
            "`password`",
            "[password](https://example.invalid)",
            "<span>password</span>",
            "pass&#119;ord",
            "**api&#45;key**",
            "[pass&#119;ord](https://example.invalid)",
            r"<span>api\-key</span>",
        )
        for label in labels:
            fixture = (
                "| Field | Value |\n"
                "| --- | --- |\n"
                f"| {label} | {secret} |\n"
            )
            with self.subTest(label=label):
                self.assertIn(
                    "generic_credential_assignment",
                    SAFETY.secret_findings(fixture),
                )
                locations = SAFETY.package_secret_match_locations(
                    fixture.encode("utf-8"),
                    ".md",
                )
                self.assertTrue(
                    any(
                        name == "generic_credential_assignment"
                        for name, _offset in locations
                    )
                )
                self.assertNotIn(secret, repr(locations))

        direct_fixtures = (
            (r"sk\-" + "A" * 40, "openai_api_key"),
            ("sk&#45;" + "A" * 40, "openai_api_key"),
            ("**password**=" + secret, "generic_credential_assignment"),
            (
                "[password](https://example.invalid)=" + secret,
                "generic_credential_assignment",
            ),
        )
        for fixture, expected in direct_fixtures:
            with self.subTest(direct=fixture[:20]):
                self.assertIn(expected, SAFETY.secret_findings(fixture))
                locations = SAFETY.package_secret_match_locations(
                    fixture.encode("utf-8"),
                    ".md",
                )
                self.assertIn((expected, 0), locations)
                self.assertNotIn(secret, repr(locations))

        rendered_suffix_fixtures = (
            (".rst", "``password``=" + secret),
            (".html", "<b>password</b>=" + secret),
            (".xml", "<label>password</label>=" + secret),
            (".txt", "pass&#119;ord=" + secret),
            (".html", "name: password\nvalue: " + secret + "\n"),
            (".xml", "| password | " + secret + " |\n"),
            (
                ".html",
                "<table><tr><td>password</td><td>"
                + secret
                + "</td></tr></table>",
            ),
            (".html", "<dl><dt>password</dt><dd>" + secret + "</dd></dl>"),
            (
                ".xml",
                "<record><name>password</name><value>"
                + secret
                + "</value></record>",
            ),
            (
                ".xml",
                "<record><cqb:credential-name>password</cqb:credential-name>"
                "<cqb:credential-value>"
                + secret
                + "</cqb:credential-value></record>",
            ),
        )
        for suffix, fixture in rendered_suffix_fixtures:
            with self.subTest(rendered_suffix=suffix):
                self.assertIn(
                    "generic_credential_assignment",
                    SAFETY.secret_findings(fixture),
                )
                self.assertIn(
                    ("generic_credential_assignment", 0),
                    SAFETY.package_secret_match_locations(
                        fixture.encode("utf-8"),
                        suffix,
                    ),
                )

        rendered_placeholders = (
            (
                ".html",
                "<table><tr><td>password</td><td>${PASSWORD}</td></tr></table>",
            ),
            (
                ".xml",
                "<record><name>password</name><value>${PASSWORD}</value></record>",
            ),
        )
        for suffix, fixture in rendered_placeholders:
            with self.subTest(rendered_placeholder=suffix):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(
                        fixture.encode("utf-8"),
                        suffix,
                    ),
                    [],
                )

        for relative in (
            "README.md",
            "docs/USAGE.md",
            "docs/MAINTAINING.md",
            "requirements-ci.txt",
        ):
            with self.subTest(safe_markdown=relative):
                self.assertEqual(
                    SAFETY.package_secret_match_locations(
                        (REPO_ROOT / relative).read_bytes(),
                        Path(relative).suffix,
                    ),
                    [],
                )

    def test_secret_scanner_large_regression_fixtures_remain_bounded(self) -> None:
        dispatch_packet = json.dumps(
            {
                "dispatch_packet_schema_version": 1,
                "task_id": "TASK-001",
                "producer": "controller",
                "role": "implementer",
                "acceptance_checks": [
                    f"planner-check-{index:04d}: repository boundary remains deterministic and safe"
                    for index in range(240)
                ],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        self.assertGreater(len(dispatch_packet.encode("utf-8")), 10 * 1024)
        started = time.perf_counter()
        self.assertEqual(SAFETY.secret_findings(dispatch_packet), [])
        self.assertLess(time.perf_counter() - started, 1.0)

        for size in (1024 * 1024, 8 * 1024 * 1024):
            separators = "," * size
            started = time.perf_counter()
            self.assertIn(
                "secret_scan_structured_context_limit",
                SAFETY.secret_findings(separators),
            )
            self.assertLess(time.perf_counter() - started, 2.0)
            started = time.perf_counter()
            self.assertIn(
                ("secret_scan_structured_context_limit", 0),
                SAFETY.package_secret_match_locations(
                    separators.encode("ascii"),
                    "",
                ),
            )
            self.assertLess(time.perf_counter() - started, 5.0)

        mixed_separators = ("field,value," * 100_000).encode("ascii")
        started = time.perf_counter()
        self.assertIn(
            ("secret_scan_structured_context_limit", 0),
            SAFETY.package_secret_match_locations(mixed_separators, ""),
        )
        self.assertLess(time.perf_counter() - started, 2.0)

        invalid_separators = b"\xff," * (4 * 1024 * 1024)
        started = time.perf_counter()
        self.assertIn(
            ("secret_scan_structured_context_limit", 0),
            SAFETY.package_secret_match_locations(invalid_separators, ""),
        )
        self.assertLess(time.perf_counter() - started, 2.0)

        no_match = "Z" * (900 * 1024)
        started = time.perf_counter()
        self.assertEqual(SAFETY.secret_findings(no_match), [])
        self.assertLess(time.perf_counter() - started, 10.0)

        started = time.perf_counter()
        self.assertEqual(
            SAFETY.package_secret_match_locations(no_match.encode("utf-8"), ".txt"),
            [],
        )
        self.assertLess(time.perf_counter() - started, 10.0)

        repeated_label = (
            "alpha-beta-gamma-delta-epsilon-api-label, safe-value\n"
            * ((900 * 1024) // 55 + 1)
        )[: 900 * 1024]
        started = time.perf_counter()
        self.assertIn(
            "secret_scan_structured_context_limit",
            SAFETY.secret_findings(repeated_label),
        )
        self.assertLess(time.perf_counter() - started, 10.0)
        started = time.perf_counter()
        self.assertTrue(
            any(
                name == "secret_scan_structured_context_limit"
                for name, _offset in SAFETY.package_secret_match_locations(
                    repeated_label.encode("utf-8"),
                    ".txt",
                )
            ),
        )
        self.assertLess(time.perf_counter() - started, 10.0)

        suffixless_binary = b"\x00\xff\x81\xfe" * ((8 * 1024 * 1024) // 4)
        started = time.perf_counter()
        self.assertEqual(
            SAFETY.package_secret_match_locations(suffixless_binary, ""),
            [],
        )
        self.assertLess(time.perf_counter() - started, 10.0)

    def test_opaque_binary_without_ascii_letters_skips_expensive_projections(self) -> None:
        opaque = b"\x00\xff\x81\xfe" * ((8 * 1024 * 1024) // 4)
        with mock.patch.object(
            SAFETY,
            "_package_direct_match_locations",
            side_effect=AssertionError("direct projection scan must be skipped"),
        ), mock.patch.object(
            SAFETY,
            "PACKAGE_STRUCTURAL_CREDENTIAL_CUE_RE",
        ) as structural_cue:
            structural_cue.search.side_effect = AssertionError(
                "structural projection scan must be skipped"
            )
            self.assertEqual(SAFETY._package_binary_match_locations(opaque), [])
            structural_cue.search.assert_not_called()

        # The fast path is keyed on letter absence, not on the credential value.
        # A numeric value beside an ASCII credential label must remain visible.
        self.assertIn(
            ("generic_credential_assignment", 0),
            SAFETY._package_binary_match_locations(
                assemble_fixture("pass", "word=12345678901234567890").encode(
                    "ascii"
                )
            ),
        )

    def test_oversized_structured_context_fails_before_large_node_traversal(self) -> None:
        with mock.patch.object(SAFETY, "MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS", 128):
            payload = "[" + ",".join("0" for _ in range(100)) + "]"
            for fixture in (payload, "prefix=" + payload, "failure={\"payload\":" + payload + "}"):
                with self.subTest(prefix=fixture[:8]):
                    self.assertIn("secret_scan_structured_context_input_limit", SAFETY.secret_findings(fixture))
                    with self.assertRaises(ValueError):
                        SAFETY.assert_safe_persistent_text(fixture)

    def test_high_cardinality_lines_and_fields_fail_closed_without_materializing_lists(self) -> None:
        with mock.patch.object(SAFETY, "MAX_MARKUP_TOKENS", 32):
            self.assertIn("secret_scan_structured_context_limit", SAFETY.secret_findings("|" * 1000))
            self.assertIn(
                "secret_scan_structured_context_limit",
                SAFETY.secret_findings("name:x," * 1000),
            )
        self.assertIn(
            "secret_scan_structured_context_limit",
            SAFETY.secret_findings("\n" * 10_000),
        )

    def test_detector_labels_are_safe_diagnostics_not_credential_assignments(self) -> None:
        for label in ("openai_api_key", "openrouter_api_key", "provider_credential_assignment"):
            diagnostic = f"secret_pattern={label}::Planner-docs/leak.md:1"
            with self.subTest(label=label):
                self.assertEqual(SAFETY.secret_findings(diagnostic), [])
                self.assertEqual(SAFETY.safe_log_text(diagnostic), diagnostic)

    def test_malformed_markup_scans_scale_linearly(self) -> None:
        def elapsed(value: str) -> float:
            started = time.perf_counter()
            self.assertIn(
                SAFETY.secret_findings(value),
                ([], ["secret_scan_semantic_expansion_limit"]),
            )
            return time.perf_counter() - started

        for prefix in ("<a", "[", "[x]("):
            with self.subTest(prefix=prefix):
                small = elapsed(prefix * 2_000)
                large = elapsed(prefix * 8_000)
                self.assertLess(large, small * 8 + 0.25)

    def test_renderer_visible_entities_and_terminal_controls_fail_closed(self) -> None:
        fixture = "sk-" + "R" * 40
        entity_encoded = "".join(f"&#{ord(character)};" for character in fixture)
        ansi_split = fixture[:7] + "\x1b[31m" + fixture[7:]
        zero_width_split = fixture[:7] + "\u200b" + fixture[7:]
        for label, disguised in (
            ("html_entity", entity_encoded),
            ("ansi", ansi_split),
            ("zero_width", zero_width_split),
        ):
            with self.subTest(label=label):
                self.assertIn("openai_api_key", SAFETY.secret_findings(disguised))
                with self.assertRaises(ValueError):
                    SAFETY.assert_safe_persistent_text(disguised)

        with self.assertRaises(ValueError):
            SAFETY.serialize_safe_persistent_json({"actor": ansi_split})
        diagnostic = SAFETY.safe_log_text("failure=" + ansi_split)
        self.assertNotIn(fixture, diagnostic)
        self.assertNotIn("\x1b", diagnostic)

    def test_renderer_controls_bidi_and_markdown_markup_cannot_reassemble_a_secret(self) -> None:
        fixture = "sk-" + "T" * 40
        prefix, suffix = fixture[:8], fixture[8:]
        disguised_values = [
            prefix + "\u009d0;hidden\u009c" + suffix,
            prefix + "\x1b%@" + suffix,
            "sk-@\b" + "T" * 40,
            "\u202e" + fixture[::-1] + "\u202c",
            prefix + "<!--hidden-->" + suffix,
            prefix + "<span></span>" + suffix,
            "sk-**" + "T" * 40 + "**",
            "sk-[" + "T" * 40 + "](https://example.invalid)",
            "sk-*" + "T" * 40 + "*",
            "sk\\-" + "T" * 40,
            "github\\_pat_" + "T" * 40,
            "hf\\_" + "T" * 40,
            prefix + '<span title="x>y"></span>' + suffix,
            prefix + "<span hidden>;</span>" + suffix,
            prefix + '<span style="display:none">;</span>' + suffix,
            prefix + "<script>;</script>" + suffix,
            prefix + "<template>;</template>" + suffix,
            prefix + "\ufe0f" + suffix,
            prefix + "\u034f" + suffix,
            prefix + "\U000e0100" + suffix,
            prefix + "\u3164" + suffix,
            prefix + "\u2065" + suffix,
        ]
        for index, disguised in enumerate(disguised_values):
            with self.subTest(case=index):
                self.assertTrue(SAFETY.secret_findings(disguised))
                with self.assertRaises(ValueError):
                    SAFETY.assert_safe_persistent_text(disguised)
                diagnostic = SAFETY.safe_log_text(disguised)
                self.assertNotIn(fixture, diagnostic)
                self.assertFalse(any(ord(character) == 0x1B for character in diagnostic))

    def test_structured_authorization_headers_are_scanned_with_key_value_context(self) -> None:
        fixtures = [
            {"Authorization": "Bearer " + "U" * 40},
            {"headers": {"authorization": "Basic " + "V" * 24}},
            {"Proxy-Authorization": "Bearer " + "W" * 40},
        ]
        for index, payload in enumerate(fixtures):
            with self.subTest(case=index):
                with self.assertRaises(ValueError):
                    SAFETY.serialize_safe_persistent_json(payload)

        safe_headers = [
            {"Authorization": "Bearer <redacted>"},
            {"authorization": "none"},
        ]
        for payload in safe_headers:
            SAFETY.serialize_safe_persistent_json(payload)

        diagnostic_fixture = "Bearer " + "X" * 40
        diagnostic = SAFETY.safe_log_text(
            'failure={"Authorization":"' + diagnostic_fixture + '"}'
        )
        self.assertNotIn(diagnostic_fixture, diagnostic)

    def test_nested_reversible_escapes_are_rejected_in_diagnostics(self) -> None:
        fixture = "sk-" + "A" * 40
        nested = "sk-" + ("\\u005c\\u00750041" * 40)
        escaped = "sk-" + ("\\u0041" * 40)
        for value in (escaped, nested):
            with self.subTest(depth=value.count("\\u005c")):
                self.assertIn("openai_api_key", SAFETY.secret_findings(value))
                diagnostic = SAFETY.safe_log_text("failure=" + value)
                self.assertNotIn(value, diagnostic)
                self.assertNotIn(fixture, diagnostic)

    def test_oversized_credential_contexts_fail_closed_and_logs_never_leak_the_tail(self) -> None:
        long_assignment_value = "Q" * 5000
        long_uri_value = "R" * 600
        fixtures = [
            (
                "generic_credential_assignment",
                assemble_fixture("pass", 'word="', long_assignment_value, '"'),
                long_assignment_value[-128:],
            ),
            (
                "uri_userinfo_credential",
                "postgres://user:" + long_uri_value + "@example.invalid/db",
                long_uri_value[-128:],
            ),
        ]
        for expected, fixture, tail in fixtures:
            with self.subTest(expected=expected):
                self.assertIn(expected, SAFETY.secret_findings(fixture))
                diagnostic = SAFETY.safe_log_text(fixture)
                self.assertNotIn(tail, diagnostic)
                self.assertLessEqual(len(diagnostic), SAFETY.MAX_SAFE_LOG_CHARACTERS)

    def test_semantic_normalization_expansion_is_bounded_and_fails_closed(self) -> None:
        with mock.patch.object(SAFETY, "MAX_SECRET_SCAN_CHARACTERS", 1024):
            expanding = "\ufdfa" * 100
            self.assertEqual(
                SAFETY.secret_findings(expanding),
                ["secret_scan_semantic_expansion_limit"],
            )
            with self.assertRaisesRegex(ValueError, "secret_scan_semantic_expansion_limit"):
                SAFETY.assert_safe_persistent_text(expanding)

    def test_full_private_key_block_is_fully_redacted(self) -> None:
        body = "M" * 96
        fixture = assemble_fixture(
            "-----BEGIN ",
            "PRIVATE ",
            "KEY-----\n",
            body,
            "\n-----END ",
            "PRIVATE ",
            "KEY-----",
        )
        diagnostic = SAFETY.safe_log_text("failure=" + fixture)
        if body in diagnostic or "-----END " in diagnostic:
            self.fail("private-key body or footer leaked from safe log")
        self.assertIn("<redacted:private_key>", diagnostic)

    def test_structured_validation_accepts_only_narrow_read_only_profiles(self) -> None:
        positive = [
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_example.py", "-q"],
            [
                "python3",
                "-B",
                "-m",
                "pytest",
                "-p",
                "no:cacheprovider",
                "tests/test_example.py",
                "--collect-only",
                "-q",
            ],
            ["python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
            ["ruff", "check", "--no-fix", "--no-cache", "."],
            ["ruff", "check", "--no-fix", "--no-cache", "src", "tests"],
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for argv in positive:
                with self.subTest(argv=argv):
                    self.assertTrue(SAFETY.safe_validation_command_item(command(argv), root=root))

            evidence = command(positive[0], exit_code=0, output_sha256=OUTPUT_SHA256)
            self.assertFalse(SAFETY.safe_validation_command_item(evidence, root=root))
            self.assertTrue(SAFETY.safe_validation_command_item(evidence, root=root, evidence=True))

    def test_structured_validation_rejects_mutation_output_and_opaque_command_profiles(self) -> None:
        unsafe_argv = [
            ["ruff", "check", "--fix", "."],
            ["ruff", "check", "--fix-only", "."],
            ["ruff", "check", "--unsafe-fixes", "."],
            ["ruff", "check", "--add-noqa", "."],
            ["ruff", "check", "--output-file", ".env", "."],
            ["ruff", "check", "--output-file=.env", "."],
            ["pytest", "--basetemp=.git"],
            ["pytest", "--basetemp", ".git"],
            ["pytest", "--junitxml=.env"],
            ["pytest", "--junit-xml", ".env"],
            ["pytest", "--cache-clear"],
            ["pytest", "-o", "cache_dir=.git"],
            ["pytest", "--override-ini=cache_dir=.git"],
            ["pytest", "--unknown-output=.env"],
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "--unknown-option"],
            ["python3", "-B", "-m", "unittest", "--unknown-option"],
            ["ruff", "check", "--no-fix", "--no-cache", "--unknown-option", "."],
            ["python3", "-m", "pytest", "tests/test_example.py", "-q"],
            ["python3", "-m", "pytest", "--basetemp=.git"],
            ["python", "-B", "-m", "unittest", "tests.test_example"],
            ["python3.14", "-B", "-m", "unittest", "tests.test_example"],
            ["python3.999", "-B", "-m", "unittest", "tests.test_example"],
            ["python3.１２", "-B", "-m", "unittest", "tests.test_example"],
            ["python3", "-m", "compileall", "."],
            ["mypy", "--cache-dir=.git", "src"],
            ["mypy", "--junit-xml=.env", "src"],
            ["npm", "run", "lint", "--", "--fix"],
            ["npm", "run", "test", "--", "--updateSnapshot"],
            ["npm", "run", "build"],
            ["make", "check"],
            ["uv", "run", "pytest", "tests"],
            ["cargo", "test", "--target-dir=.git"],
            ["go", "test", "-o", ".env", "./..."],
            ["tools/pytest", "tests"],
            ["./ruff", "check", "."],
            ["pytest", "@args.txt"],
            ["pytest", "tests", ">", ".env"],
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for argv in unsafe_argv:
                with self.subTest(argv=argv):
                    self.assertFalse(SAFETY.safe_validation_command_item(command(argv), root=root))

    def test_structured_validation_rejects_unsafe_or_ambiguous_envelopes(self) -> None:
        base = command(
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_example.py", "-q"]
        )
        cases = [
            {key: value}
            for key, value in [
                ("cwd", "../outside"),
                ("cwd", "..\\outside"),
                ("cwd", "/tmp"),
                ("cwd", ".git"),
                ("cwd", ".env"),
                ("network", "local"),
                ("network", "live"),
                ("network", "allow"),
                ("network", None),
                ("probe_tier", True),
                ("probe_tier", 0),
                ("probe_tier", 2),
                ("probe_tier", 3),
                ("probe_tier", 999),
                ("expected_exit_code", True),
                ("expected_exit_code", 1),
                ("timeout_seconds", True),
                ("timeout_seconds", 0),
                ("timeout_seconds", 3601),
                ("shell", True),
                ("command", "rm -rf ."),
                ("env", {"PYTEST_ADDOPTS": "--basetemp=.git"}),
                ("stdout_path", ".env"),
            ]
        ]
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            outside = Path(temp_dir).parent / f"{Path(temp_dir).name}-outside"
            outside.mkdir()
            try:
                (root / "outside-link").symlink_to(outside, target_is_directory=True)
                cases.append({"cwd": "outside-link"})
                for overrides in cases:
                    with self.subTest(overrides=overrides):
                        payload = dict(base)
                        payload.update(overrides)
                        self.assertFalse(SAFETY.safe_validation_command_item(payload, root=root))
            finally:
                outside.rmdir()

    def test_structured_validation_requires_the_complete_envelope(self) -> None:
        base = command(
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_example.py", "-q"]
        )
        required = {
            "id",
            "argv",
            "cwd",
            "expected_exit_code",
            "timeout_seconds",
            "network",
            "probe_tier",
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            for field in sorted(required):
                with self.subTest(missing=field):
                    payload = dict(base)
                    del payload[field]
                    self.assertFalse(SAFETY.safe_validation_command_item(payload, root=root))

            self.assertFalse(
                SAFETY.safe_validation_command_item({**base, "exit_code": 0}, root=root),
                "evidence without an output hash must fail closed",
            )
            self.assertFalse(
                SAFETY.safe_validation_command_item(
                    {**base, "exit_code": 0, "output_sha256": OUTPUT_SHA256},
                    root=root,
                ),
                "planned commands must reject evidence-only fields",
            )

    def test_structured_validation_rejects_repo_local_module_and_executable_shadows(self) -> None:
        pytest_command = command(
            ["python3", "-B", "-m", "pytest", "-p", "no:cacheprovider", "tests/test_example.py", "-q"]
        )
        unittest_command = command(["python3", "-B", "-m", "unittest", "tests.test_example"])
        ruff_command = command(["ruff", "check", "--no-fix", "--no-cache", "."])
        for shadow, payload in [
            ("pytest.py", pytest_command),
            ("unittest.py", unittest_command),
            ("python3", unittest_command),
            ("ruff", ruff_command),
        ]:
            with self.subTest(shadow=shadow), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                (root / shadow).write_text("raise SystemExit('shadow')\n", encoding="utf-8")
                self.assertFalse(SAFETY.safe_validation_command_item(payload, root=root))

        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            tools = root / "tools"
            tools.mkdir()
            (tools / "ruff").write_text("raise SystemExit('shadow')\n", encoding="utf-8")
            payload = command(["ruff", "check", "--no-fix", "--no-cache", "."], cwd="tools")
            self.assertFalse(SAFETY.safe_validation_command_item(payload, root=root))

        for startup_hook in ("sitecustomize.py", "usercustomize.py"):
            with self.subTest(startup_hook=startup_hook), tempfile.TemporaryDirectory() as temp_dir:
                root = Path(temp_dir)
                (root / startup_hook).write_text("raise SystemExit('shadow')\n", encoding="utf-8")
                self.assertFalse(SAFETY.safe_validation_command_item(unittest_command, root=root))

    def test_structured_validation_rejects_symlinked_targets_outside_repo(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir, tempfile.TemporaryDirectory() as outside_dir:
            root = Path(temp_dir)
            outside = Path(outside_dir)
            (outside / "test_external.py").write_text("raise SystemExit('external')\n", encoding="utf-8")
            (root / "external-tests").symlink_to(outside, target_is_directory=True)
            payloads = [
                command(
                    [
                        "python3",
                        "-B",
                        "-m",
                        "pytest",
                        "-p",
                        "no:cacheprovider",
                        "external-tests/test_external.py",
                    ]
                ),
                command(["ruff", "check", "--no-fix", "--no-cache", "external-tests"]),
            ]
            for payload in payloads:
                with self.subTest(argv=payload["argv"]):
                    self.assertFalse(SAFETY.safe_validation_command_item(payload, root=root))

    def test_legacy_command_is_compatibility_only(self) -> None:
        legacy = {
            "id": "VAL-01",
            "command": "python3 -B -m pytest -p no:cacheprovider tests/test_example.py -q",
            "expected_result": "exit_code_0",
        }
        self.assertFalse(SAFETY.safe_validation_command_item(legacy))
        self.assertTrue(SAFETY.safe_validation_command_item(legacy, allow_legacy=True))


if __name__ == "__main__":
    unittest.main()
