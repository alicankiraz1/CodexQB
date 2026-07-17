#!/usr/bin/env python3
"""Shared safety checks for CodexQB local helper scripts.

The helpers in this directory are artifact validators and preview compilers,
not executors. This module keeps command, path, and secret checks consistent
across planner validation, Goal previews, apply-run artifacts, and sanitized
exports.
"""

from __future__ import annotations

import ast
from array import array
from collections import OrderedDict
import fnmatch
import hashlib
import html
import io
import json
import re
import shlex
import tokenize
import unicodedata
from collections.abc import Iterator, Sequence
from pathlib import Path


MAX_SECRET_SCAN_CHARACTERS = 16 * 1024 * 1024
MAX_SECRET_MATCH_LOCATIONS = 256
PACKAGE_BINARY_SCAN_WINDOW_BYTES = 8 * 1024 * 1024
PACKAGE_BINARY_SCAN_OVERLAP_BYTES = 264 * 1024
PACKAGE_UTF16_MIN_ASCII_UNITS = 8
PACKAGE_UTF32_MIN_ASCII_UNITS = 8
PACKAGE_SECRET_SCAN_CACHE_MAX_ENTRIES = 4096
PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS = 4096
PACKAGE_PYTHON_CONSTANT_MAX_DEPTH = 64
PACKAGE_PYTHON_CONSTANT_MAX_PARTS = 4096
PACKAGE_PYTHON_TOKEN_MAX_COUNT = 1_000_000
MAX_SAFE_LOG_CHARACTERS = 4096
MAX_MARKUP_TOKENS = 4096
MAX_STRUCTURED_CONTEXT_NODES = 65_536
MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS = 1024 * 1024
SECRET_REDACTION_MARKER = "<redacted>"
PACKAGE_KNOWN_TEXT_SUFFIXES = frozenset(
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
PACKAGE_CONFIG_TEXT_SUFFIXES = frozenset({".cfg", ".conf", ".ini", ".toml", ".yaml", ".yml"})
PACKAGE_SCRIPT_TEXT_SUFFIXES = frozenset({".js", ".jsx", ".ts", ".tsx"})
PACKAGE_BINARY_PROJECTION_TABLE = bytes(
    value if value in {9, 10, 13} or 0x20 <= value <= 0x7E else 10
    for value in range(256)
)
PACKAGE_UTF16_LE_ASCII_RUN_RE = re.compile(
    rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){%d}" % PACKAGE_UTF16_MIN_ASCII_UNITS
)
PACKAGE_UTF16_BE_ASCII_RUN_RE = re.compile(
    rb"(?:\x00[\x09\x0a\x0d\x20-\x7e]){%d}" % PACKAGE_UTF16_MIN_ASCII_UNITS
)
PACKAGE_UTF32_LE_ASCII_RUN_RE = re.compile(
    rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00\x00\x00){%d}"
    % PACKAGE_UTF32_MIN_ASCII_UNITS
)
PACKAGE_UTF32_BE_ASCII_RUN_RE = re.compile(
    rb"(?:\x00\x00\x00[\x09\x0a\x0d\x20-\x7e]){%d}"
    % PACKAGE_UTF32_MIN_ASCII_UNITS
)
PACKAGE_SEMANTIC_SECRET_MARKERS = (
    "sk-",
    "gh",
    "github_pat_",
    "hf_",
    "gl",
    "sk_",
    "rk_",
    "whsec_",
    "aiza",
    "gocspx-",
    "ya29.",
    "akia",
    "asia",
    "xox",
    "xapp-",
    "hooks.slack.com",
    "eyj",
    "authorization",
    "private key",
    "pgp private",
    "://",
)
_PACKAGE_SECRET_SCAN_CACHE: OrderedDict[
    tuple[bytes, int, str, tuple[object, ...]],
    tuple[tuple[str, int], ...],
] = OrderedDict()
_PRIVATE_KEY_KIND_EXPRESSION = r"(?:RSA |OPENSSH |DSA |EC |ENCRYPTED )?PRIVATE KEY|PGP PRIVATE KEY BLOCK"

SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("openrouter_api_key", re.compile(r"(?<![A-Za-z0-9_])sk-or-v1-[A-Za-z0-9_-]{20,4096}", re.IGNORECASE)),
    (
        "openai_api_key",
        re.compile(r"(?<![A-Za-z0-9_])sk-(?!(?:or-v1|ant)-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,4096}"),
    ),
    ("github_pat", re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{20,4096}")),
    ("github_legacy_pat", re.compile(r"(?<![A-Za-z0-9_])gh[opusr]_[A-Za-z0-9]{20,4096}")),
    (
        "anthropic_api_key",
        re.compile(r"(?<![A-Za-z0-9_])sk-ant-(?:(?:api|admin)\d{2}-)?[A-Za-z0-9_-]{20,4096}"),
    ),
    ("huggingface_token", re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z0-9]{20,4096}")),
    (
        "gitlab_token",
        re.compile(r"(?<![A-Za-z0-9_])gl(?:pat|dt|rt|cbt|ptt|ft|oas|soat|ffct|imt)-[A-Za-z0-9_-]{16,4096}"),
    ),
    ("stripe_secret_key", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,4096}")),
    ("stripe_webhook_secret", re.compile(r"(?<![A-Za-z0-9_])whsec_[A-Za-z0-9]{16,4096}")),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9_])AIza[0-9A-Za-z_-]{35,512}")),
    ("google_oauth_client_secret", re.compile(r"(?<![A-Za-z0-9_])GOCSPX-[A-Za-z0-9_-]{20,4096}")),
    ("google_oauth_access_token", re.compile(r"(?<![A-Za-z0-9_.-])ya29\.[A-Za-z0-9._-]{20,4096}")),
    (
        "aws_access_key",
        re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),
    ),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9-])xox[baprs]-[A-Za-z0-9-]{20,4096}", re.IGNORECASE)),
    ("slack_app_token", re.compile(r"(?<![A-Za-z0-9-])xapp-[A-Za-z0-9-]{20,4096}", re.IGNORECASE)),
    (
        "slack_webhook",
        re.compile(
            r"https://hooks\.slack\.com/services/[A-Za-z0-9]{8,64}/[A-Za-z0-9]{8,64}/[A-Za-z0-9_-]{20,256}",
            re.IGNORECASE,
        ),
    ),
    (
        "jwt",
        re.compile(
            r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,8192}"
        ),
    ),
    (
        "authorization_bearer",
        re.compile(
            r"\bAuthorization[\"']?\s*:\s*[\"']?\s*Bearer\s+[A-Za-z0-9._~+/-]{16,4096}",
            re.IGNORECASE,
        ),
    ),
    (
        "authorization_basic",
        re.compile(
            r"\bAuthorization[\"']?\s*:\s*[\"']?\s*Basic\s+[A-Za-z0-9+/]{8,4096}={0,2}",
            re.IGNORECASE,
        ),
    ),
    (
        "private_key",
        re.compile(
            rf"(?:-----BEGIN (?P<private_key_kind>{_PRIVATE_KEY_KIND_EXPRESSION})-----"
            rf"[\s\S]{{0,262144}}?-----END (?P=private_key_kind)-----|"
            rf"-----BEGIN (?:{_PRIVATE_KEY_KIND_EXPRESSION})-----)",
            re.IGNORECASE,
        ),
    ),
)
PACKAGE_SECRET_PATH_RULE_NAMES = frozenset(
    {
        *(name for name, _pattern in SECRET_PATTERNS),
        "aws_secret_access_key",
        "aws_session_token",
        "generic_credential_assignment",
        "provider_credential_assignment",
        "secret_match_limit_exceeded",
        "secret_scan_input_too_large",
        "unsafe_control_sequence",
        "uri_userinfo_credential",
    }
)

PROVIDER_CREDENTIAL_NAMES = frozenset(
    {
        "OPENAI_API_KEY",
        "OPENROUTER_API_KEY",
        "ANTHROPIC_API_KEY",
        "HF_TOKEN",
        "HUGGINGFACE_TOKEN",
        "GITHUB_TOKEN",
        "GH_TOKEN",
        "GITLAB_TOKEN",
        "STRIPE_SECRET_KEY",
        "GOOGLE_API_KEY",
        "GOOGLE_CLIENT_SECRET",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "SLACK_TOKEN",
        "SLACK_SIGNING_SECRET",
    }
)
GENERIC_CREDENTIAL_NAMES = frozenset(
    {
        "API_KEY",
        "ACCESS_TOKEN",
        "AUTH_TOKEN",
        "CLIENT_SECRET",
        "REFRESH_TOKEN",
        "PASSWORD",
        "SIGNING_SECRET",
        "WEBHOOK_SECRET",
    }
)
_PROVIDER_CREDENTIAL_NAME_EXPRESSION = (
    r"OPENAI_API_KEY|OPENROUTER_API_KEY|ANTHROPIC_API_KEY|HF_TOKEN|HUGGINGFACE_TOKEN|"
    r"GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|STRIPE_SECRET_KEY|GOOGLE_API_KEY|GOOGLE_CLIENT_SECRET|"
    r"AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|SLACK_TOKEN|SLACK_SIGNING_SECRET|"
    r"SecretAccessKey|SessionToken|Secret[ ._-]+Access[ ._-]+Key|Session[ ._-]+Token|"
    r"OpenAI[ ._-]+API[ ._-]+Key|OpenRouter[ ._-]+API[ ._-]+Key|"
    r"Anthropic[ ._-]+API[ ._-]+Key|Hugging[ ._-]+Face[ ._-]+Token|"
    r"GitHub[ ._-]+Token|GitLab[ ._-]+Token|Stripe[ ._-]+Secret[ ._-]+Key|"
    r"Google[ ._-]+API[ ._-]+Key|Google[ ._-]+Client[ ._-]+Secret|"
    r"AWS[ ._-]+Secret[ ._-]+Access[ ._-]+Key|AWS[ ._-]+Session[ ._-]+Token|"
    r"Slack[ ._-]+Token|Slack[ ._-]+Signing[ ._-]+Secret"
)
_GENERIC_CREDENTIAL_STEM_EXPRESSION = (
    r"api[ ._-]?key|access[ ._-]?token|auth[ ._-]?token|client[ ._-]?secret|"
    r"refresh[ ._-]?token|password|signing[ ._-]?secret|webhook[ ._-]?secret|"
    r"secret[ ._-]?key(?:[ ._-]?base)?|app[ ._-]?secret|private[ ._-]?token"
)
_CREDENTIAL_NAME_SEGMENT_EXPRESSION = r"[A-Za-z][A-Za-z0-9]{0,31}"
_CAMEL_CREDENTIAL_NAME_EXPRESSION = (
    r"(?:[A-Za-z][A-Za-z0-9]{0,63})?"
    r"(?:ApiKey|AccessToken|AuthToken|ClientSecret|RefreshToken|Password|SigningSecret|WebhookSecret|"
    r"SecretKey(?:Base)?|AppSecret|PrivateToken)"
    r"(?:Prod|Dev|Test|Staging|Ci|V[0-9]{1,2})?"
)
_CREDENTIAL_NAME_EXPRESSION = (
    rf"(?:{_PROVIDER_CREDENTIAL_NAME_EXPRESSION}|"
    rf"(?:{_CREDENTIAL_NAME_SEGMENT_EXPRESSION}[ ._-]){{0,4}}"
    rf"(?:{_GENERIC_CREDENTIAL_STEM_EXPRESSION})"
    rf"(?:[ ._-](?:PROD|DEV|TEST|STAGING|CI|V[0-9]{{1,2}}))?|"
    rf"{_CAMEL_CREDENTIAL_NAME_EXPRESSION})"
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    rf"\b(?P<name>{_CREDENTIAL_NAME_EXPRESSION})\b[\"']?[ \t]*(?:->|=>|[:=\u2013\u2014])[ \t]*"
    rf'(?:'
    rf'(?:br|rb|b|r|u)?"""(?P<triple_double>[\s\S]{{0,4096}}?)"""|'
    rf"(?:br|rb|b|r|u)?'''(?P<triple_single>[\s\S]{{0,4096}}?)'''|"
    rf'(?:br|rb|b|r|u)?"(?P<double>[^"\r\n]{{0,4096}})"|'
    rf"(?:br|rb|b|r|u)?'(?P<single>[^'\r\n]{{0,4096}})'|"
    rf"`(?P<backtick>[^`\r\n]{{0,4096}})`|"
    rf"(?P<bare>[^\s#|]{{1,4096}}))",
    re.IGNORECASE,
)
CREDENTIAL_NAME_FULL_RE = re.compile(rf"(?:{_CREDENTIAL_NAME_EXPRESSION})", re.IGNORECASE)
PAIR_CONTEXT_LABEL_RE = re.compile(
    rf"(?:{_CREDENTIAL_NAME_EXPRESSION}|Authorization|Proxy[ ._-]+Authorization)",
    re.IGNORECASE,
)
CONTEXT_FIELD_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:[-*+][ \t]+)?"
    r"(?P<field>name|key|credential(?:[ ._-]+name)?|secret[ ._-]+name|credential)"
    r"[ \t]*:[ \t]*(?P<value>[^\r\n]{0,4096})[ \t]*$",
    re.IGNORECASE,
)
CONTEXT_VALUE_LINE_RE = re.compile(
    r"^(?P<indent>[ \t]*)(?:[-*+][ \t]+)?"
    r"(?P<field>value|credential[ ._-]+value|secret[ ._-]+value)"
    r"[ \t]*:[ \t]*(?P<value>[^\r\n]{0,4096})[ \t]*$",
    re.IGNORECASE,
)
INLINE_CONTEXT_FIELD_PREFIX_RE = re.compile(
    r"(?<![A-Za-z0-9_])[\"']?"
    r"(?P<field>name|key|credential(?:[ ._-]+name)?|secret[ ._-]+name|credential|"
    r"value|credential[ ._-]+value|secret[ ._-]+value)"
    r"[\"']?[ \t]*[:=][ \t]*",
    re.IGNORECASE,
)
URI_USERINFO_PREFIX_RE = re.compile(
    r"\b[a-z][a-z0-9+.-]{1,15}://(?P<user>[^/\s:@]{1,128}):",
    re.IGNORECASE,
)
MARKDOWN_BACKSLASH_ESCAPE_RE = re.compile(r"\\([!\"#$%&'()*+,\-./:;<=>?@\[\]\\^_`{|}~])")
BACKSLASH_UNICODE_ESCAPE_RE = re.compile(r"\\u([0-9A-Fa-f]{4})")
BACKSLASH_HEX_ESCAPE_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")
UNSAFE_ASCII_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

SHELL_METACHAR_RE = re.compile(r"(?:&&|\|\||[;&|<>`]|[$]\(|\n|\r)")
MUTATING_EXECUTABLES = {
    "rm",
    "rmdir",
    "mv",
    "cp",
    "chmod",
    "chown",
    "sudo",
    "su",
    "ssh",
    "scp",
    "rsync",
    "curl",
    "wget",
    "kubectl",
    "terraform",
    "docker",
    "gh",
    "git",
    "bash",
    "sh",
    "zsh",
}

SAFE_PYTHON_MODULES = {"pytest", "unittest"}
VALIDATION_COMMAND_REQUIRED_FIELDS = frozenset(
    {
        "id",
        "argv",
        "cwd",
        "expected_exit_code",
        "timeout_seconds",
        "network",
        "probe_tier",
    }
)
VALIDATION_EVIDENCE_HASH_FIELDS = frozenset(
    {
        "output_sha256",
        "stdout_sha256",
        "stderr_sha256",
        "combined_output_sha256",
        "artifact_sha256",
    }
)
VALIDATION_EVIDENCE_FIELDS = VALIDATION_COMMAND_REQUIRED_FIELDS | VALIDATION_EVIDENCE_HASH_FIELDS | {"exit_code"}
LEGACY_VALIDATION_COMMAND_FIELDS = frozenset({"id", "command", "expected_result"})
VALIDATION_ID_RE = re.compile(r"VAL-[A-Z0-9_.-]{1,60}")
SHA256_RE = re.compile(r"[a-f0-9]{64}")
SENSITIVE_VALIDATION_PATH_PARTS = frozenset(
    {
        ".aws",
        ".codex",
        ".codexqb",
        ".config",
        ".env",
        ".git",
        ".gnupg",
        ".ssh",
        "credential",
        "credentials",
        "secret",
        "secrets",
    }
)
BUDGET_SCHEMA_VERSION = 1
BUDGET_INT_LIMITS = {
    "soft_input_token_limit": (1, 10_000_000),
    "hard_total_token_limit": (1, 10_000_000),
    "max_subagent_total_tokens": (0, 10_000_000),
    "max_agent_attempts_per_role": (1, 10),
    "max_fix_cycles": (0, 10),
    "max_selected_tasks": (0, 50),
    "checkpoint_after_tasks": (1, 50),
}
DEFAULT_BUDGET_CONTRACT = {
    "budget_schema_version": BUDGET_SCHEMA_VERSION,
    "soft_input_token_limit": 300_000,
    "hard_total_token_limit": 600_000,
    "max_subagent_total_tokens": 250_000,
    "max_agent_attempts_per_role": 2,
    "max_fix_cycles": 2,
    "max_selected_tasks": 4,
    "checkpoint_after_tasks": 1,
    "pause_on_soft_limit": True,
    "enforcement_mode": "advisory_or_runtime_supported",
}
TOKEN_USAGE_NOT_OBSERVED = {
    "status": "not_observed",
    "input_tokens": "not_observed",
    "output_tokens": "not_observed",
    "total_tokens": "not_observed",
    "source": "runtime_not_available",
}
IMPLEMENTATION_CONTRACT_SECTION_RE = re.compile(
    r"^### Implementation Contract[ \t]*\n+(?P<body>.*?)(?=^### |^## |\Z)",
    re.DOTALL | re.IGNORECASE | re.MULTILINE,
)
IMPLEMENTATION_CONTRACT_JSON_RE = re.compile(r"```json\s*(?P<json>.*?)\s*```", re.DOTALL | re.IGNORECASE)


def _canonical_credential_name(value: str) -> str:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value)
    normalized = re.sub(r"[\s.-]+", "_", normalized).upper()
    collapsed = normalized.replace("_", "")
    alias = {
        "SECRETACCESSKEY": "AWS_SECRET_ACCESS_KEY",
        "SESSIONTOKEN": "AWS_SESSION_TOKEN",
    }.get(collapsed)
    if alias is not None:
        return alias
    for provider_name in PROVIDER_CREDENTIAL_NAMES:
        if collapsed == provider_name.replace("_", ""):
            return provider_name
    return {
        "APIKEY": "API_KEY",
        "ACCESSTOKEN": "ACCESS_TOKEN",
        "AUTHTOKEN": "AUTH_TOKEN",
        "CLIENTSECRET": "CLIENT_SECRET",
        "REFRESHTOKEN": "REFRESH_TOKEN",
        "PASSWORD": "PASSWORD",
        "SIGNINGSECRET": "SIGNING_SECRET",
        "WEBHOOKSECRET": "WEBHOOK_SECRET",
    }.get(collapsed, normalized)


def _credential_name_is_generic(value: str) -> bool:
    normalized = value.upper().replace("-", "_")
    return any(
        re.search(rf"(?:^|_){re.escape(stem)}(?:_|$)", normalized)
        for stem in GENERIC_CREDENTIAL_NAMES
    )


def _credential_placeholder_is_exact(name: str, value: str) -> bool:
    canonical = _canonical_credential_name(name)
    variable = re.fullmatch(r"\$(?:\{(?P<braced>[A-Za-z][A-Za-z0-9_-]{0,127})\}|(?P<bare>[A-Za-z][A-Za-z0-9_-]{0,127}))", value)
    if variable is not None:
        variable_name = str(variable.group("braced") or variable.group("bare"))
        return _canonical_credential_name(variable_name) == canonical
    exact = {
        f"${canonical}",
        f"${{{canonical}}}",
        f"YOUR_{canonical}",
        f"your_{canonical.lower()}",
    }
    if value in exact:
        return True
    if re.fullmatch(r"<redacted:[a-z0-9_.-]{1,80}>", value, re.IGNORECASE):
        return True
    return value.lower() in {
        "<redacted>",
        "<token>",
        "<secret>",
        "redacted",
        "placeholder",
        "changeme",
        "change_me",
        "change-me",
        "not_set",
        "not-set",
        "none",
        "null",
    }


def _credential_assignment_matches(text: str) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    for match in CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        diagnostic_prefix = text[max(0, match.start() - 32) : match.start()].lower()
        if diagnostic_prefix.endswith(("<redacted:", "secret_pattern=")):
            continue
        group = next(
            name
            for name in ("triple_double", "triple_single", "double", "single", "backtick", "bare")
            if match.group(name) is not None
        )
        value = str(match.group(group) or "").strip()
        value_end = match.end(group)
        if group == "bare" and not value.startswith("${"):
            trimmed = value.rstrip("}]")
            value_end -= len(value) - len(trimmed)
            value = trimmed
        if group == "bare" and value and value[-1] in ",;." and (
            match.end() == len(text)
            or text[match.end()].isspace()
            or text[match.end()] in "}]"
        ):
            value = value[:-1]
            value_end -= 1
        raw_name = str(match.group("name"))
        name = _canonical_credential_name(raw_name)
        quoted_boundary = False
        if group != "bare" and match.end() < len(text) and text[match.end()] in ".,:;!?)]}":
            quoted_boundary = match.end() + 1 == len(text) or text[match.end() + 1].isspace()
        quoted_suffix = (
            group != "bare"
            and match.end() < len(text)
            and text[match.end()] not in " \t\r\n,}]#;"
            and not quoted_boundary
        )
        if not value or (_credential_placeholder_is_exact(name, value) and not quoted_suffix):
            continue
        if any(character.isspace() for character in raw_name) and len(value) < 16:
            continue
        if name == "AWS_SECRET_ACCESS_KEY":
            label = "aws_secret_access_key"
        elif name == "AWS_SESSION_TOKEN":
            label = "aws_session_token"
        elif name in PROVIDER_CREDENTIAL_NAMES:
            label = "provider_credential_assignment"
        else:
            label = "generic_credential_assignment"
        matches.append((label, match.start(), max(match.end(), value_end)))
        if len(matches) > MAX_SECRET_MATCH_LOCATIONS:
            break
    return matches


def _uri_credential_matches(text: str) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    for match in URI_USERINFO_PREFIX_RE.finditer(text):
        password_start = match.end()
        authority_end = password_start
        while authority_end < len(text) and text[authority_end] not in "/?#\t\r\n ":
            authority_end += 1
        password_end = text.rfind("@", password_start, authority_end)
        if password_end < password_start or password_end == password_start:
            continue
        password = text[password_start:password_end]
        if _credential_placeholder_is_exact("PASSWORD", password):
            continue
        matches.append(("uri_userinfo_credential", match.start(), password_end + 1))
        if len(matches) > MAX_SECRET_MATCH_LOCATIONS:
            break
    return matches


def _strip_terminal_escape_sequences(text: str) -> str:
    """Remove bounded ANSI/ECMA-48 controls before security-visible scanning.

    This is intentionally a small fail-safe parser rather than a permissive
    regular expression.  It handles CSI, OSC, DCS/SOS/PM/APC strings, and
    ordinary two-byte escape sequences without emitting their hidden payload.
    """

    if all(marker not in text for marker in ("\x1b", "\x90", "\x98", "\x9b", "\x9d", "\x9e", "\x9f")):
        return text

    output: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        character = text[index]
        codepoint = ord(character)
        if character == "\x1b":
            index += 1
            if index >= length:
                continue
            introducer = text[index]
            index += 1
            if introducer == "[":
                while index < length:
                    final = ord(text[index])
                    index += 1
                    if 0x40 <= final <= 0x7E:
                        break
                continue
            if introducer == "]":
                while index < length:
                    if text[index] == "\x07":
                        index += 1
                        break
                    if ord(text[index]) == 0x9C:
                        index += 1
                        break
                    if text[index] == "\x1b" and index + 1 < length and text[index + 1] == "\\":
                        index += 2
                        break
                    index += 1
                continue
            if introducer in {"P", "X", "^", "_"}:
                while index < length:
                    if ord(text[index]) == 0x9C:
                        index += 1
                        break
                    if text[index] == "\x1b" and index + 1 < length and text[index + 1] == "\\":
                        index += 2
                        break
                    index += 1
                continue
            if 0x20 <= ord(introducer) <= 0x2F:
                while index < length and 0x20 <= ord(text[index]) <= 0x2F:
                    index += 1
                if index < length and 0x30 <= ord(text[index]) <= 0x7E:
                    index += 1
            continue
        if codepoint == 0x9B:  # C1 CSI
            index += 1
            while index < length:
                final = ord(text[index])
                index += 1
                if 0x40 <= final <= 0x7E:
                    break
            continue
        if codepoint == 0x9D:  # C1 OSC
            index += 1
            while index < length:
                if text[index] == "\x07" or ord(text[index]) == 0x9C:
                    index += 1
                    break
                if text[index] == "\x1b" and index + 1 < length and text[index + 1] == "\\":
                    index += 2
                    break
                index += 1
            continue
        if codepoint in {0x90, 0x98, 0x9E, 0x9F}:  # C1 DCS/SOS/PM/APC
            index += 1
            while index < length:
                if ord(text[index]) == 0x9C:
                    index += 1
                    break
                if text[index] == "\x1b" and index + 1 < length and text[index + 1] == "\\":
                    index += 2
                    break
                index += 1
            continue
        output.append(character)
        index += 1
    return "".join(output)


def _remove_invisible_control_characters(text: str) -> str:
    """Remove non-layout control/format characters that can split a token."""

    if text.isascii() and UNSAFE_ASCII_CONTROL_RE.search(text) is None:
        return text
    return "".join(
        character
        for character in text
        if character in {"\t", "\n", "\r"}
        or (
            unicodedata.category(character) not in {"Cc", "Cf"}
            and not _is_default_ignorable_codepoint(ord(character))
        )
    )


def _is_default_ignorable_codepoint(codepoint: int) -> bool:
    return (
        codepoint == 0x034F
        or 0x115F <= codepoint <= 0x1160
        or 0x17B4 <= codepoint <= 0x17B5
        or 0x180B <= codepoint <= 0x180F
        or codepoint == 0x2065
        or codepoint == 0x3164
        or 0xFE00 <= codepoint <= 0xFE0F
        or codepoint == 0xFFA0
        or 0xFFF0 <= codepoint <= 0xFFF8
        or 0x1BCA0 <= codepoint <= 0x1BCA3
        or 0x1D173 <= codepoint <= 0x1D17A
        or 0xE0000 <= codepoint <= 0xE0FFF
    )


def _unsafe_persistent_control_offsets(text: str) -> Iterator[int]:
    if text.isascii():
        yield from (match.start() for match in UNSAFE_ASCII_CONTROL_RE.finditer(text))
        return
    for index, character in enumerate(text):
        if character not in {"\t", "\n", "\r"} and unicodedata.category(character) in {"Cc", "Cf"}:
            yield index


def _bounded_nfkc(text: str) -> str:
    if text.isascii():
        return text
    parts: list[str] = []
    total = 0
    for offset in range(0, len(text), 4096):
        part = unicodedata.normalize("NFKC", text[offset : offset + 4096])
        total += len(part)
        if total > MAX_SECRET_SCAN_CHARACTERS:
            raise ValueError("secret_scan_semantic_expansion_limit")
        parts.append(part)
    return "".join(parts)


def _html_markup_tokens(text: str) -> list[tuple[int, int, str, bool, bool]]:
    tokens: list[tuple[int, int, str, bool, bool]] = []
    index = 0
    work = 0
    while index < len(text):
        start = text.find("<", index)
        if start < 0:
            break
        work += max(1, start - index + 1)
        if work > MAX_SECRET_SCAN_CHARACTERS * 4:
            raise ValueError("secret_scan_semantic_expansion_limit")
        if text.startswith("<!--", start):
            end = text.find("-->", start + 4)
            tokens.append((start, len(text) if end < 0 else end + 3, "#comment", False, True))
            if len(tokens) > MAX_MARKUP_TOKENS:
                raise ValueError("secret_scan_semantic_expansion_limit")
            index = len(text) if end < 0 else end + 3
            continue
        cursor = start + 1
        closing = False
        if cursor < len(text) and text[cursor] == "/":
            closing = True
            cursor += 1
        if cursor >= len(text):
            break
        if text[cursor] in "!?":
            name = text[cursor]
            cursor += 1
        elif text[cursor].isalpha():
            name_start = cursor
            while cursor < len(text) and (text[cursor].isalnum() or text[cursor] in ":_-"):
                cursor += 1
            name = text[name_start:cursor].lower()
        else:
            index = start + 1
            continue
        quote: str | None = None
        end = cursor
        while end < len(text):
            work += 1
            if work > MAX_SECRET_SCAN_CHARACTERS * 4:
                raise ValueError("secret_scan_semantic_expansion_limit")
            character = text[end]
            if quote is not None:
                if character == quote:
                    quote = None
            elif character in {"\"", "'"}:
                quote = character
            elif character == ">":
                break
            end += 1
        if end >= len(text):
            # No later candidate can close before the end we just scanned.
            # Stopping here keeps malformed tag-like text strictly linear.
            break
        token_text = text[start : end + 1]
        self_closing = name in {"!", "?"} or token_text.rstrip().endswith("/>")
        tokens.append((start, end + 1, name, closing, self_closing))
        if len(tokens) > MAX_MARKUP_TOKENS:
            raise ValueError("secret_scan_semantic_expansion_limit")
        index = end + 1
    return tokens


def _markdown_link_projection(text: str) -> str:
    """Keep link labels and remove destinations in a bounded single pass."""

    pieces: list[str] = []
    cursor = 0
    search = 0
    work = 0
    length = len(text)
    while search < length:
        start = text.find("[", search)
        if start < 0:
            break
        close = text.find("]", start + 1)
        work += max(1, (start - search) + (length - start if close < 0 else close - start + 1))
        if work > MAX_SECRET_SCAN_CHARACTERS * 4:
            raise ValueError("secret_scan_semantic_expansion_limit")
        if close < 0:
            break
        suffix = close + 1
        destination_end = -1
        destination_opened = False
        if suffix < length and text[suffix] == "(":
            destination_opened = True
            destination_end = text.find(")", suffix + 1)
        elif suffix < length and text[suffix] == "[":
            destination_opened = True
            destination_end = text.find("]", suffix + 1)
        if destination_end < 0:
            if destination_opened:
                # We just proved that this delimiter has no closer anywhere in
                # the remaining text; rescanning later openers would be O(n^2).
                break
            # Advancing beyond the matched label avoids rescanning an unmatched
            # delimiter suffix from every earlier opening bracket.
            search = close + 1
            continue
        visible_start = start
        if start > cursor and text[start - 1] == "!":
            visible_start = start - 1
        pieces.append(text[cursor:visible_start])
        pieces.append(text[start + 1 : close])
        cursor = destination_end + 1
        search = cursor
    pieces.append(text[cursor:])
    return "".join(pieces)


def _remove_text_ranges(text: str, ranges: list[tuple[int, int]]) -> str:
    if not ranges:
        return text
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.append(text[cursor:start])
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


def _html_projection(text: str, *, remove_element_content: bool) -> str:
    tokens = _html_markup_tokens(text)
    ranges = [(start, end) for start, end, _, _, _ in tokens]
    if remove_element_content:
        stack: list[tuple[str, int]] = []
        for start, end, name, closing, self_closing in tokens:
            if name == "#comment" or self_closing:
                continue
            if not closing:
                stack.append((name, start))
                continue
            for stack_index in range(len(stack) - 1, -1, -1):
                if stack[stack_index][0] == name:
                    ranges.append((stack[stack_index][1], end))
                    del stack[stack_index:]
                    break
    return _remove_text_ranges(text, ranges)


def _markdown_visible_projection(text: str, *, remove_html_content: bool = False) -> str:
    projected = _html_projection(text, remove_element_content=remove_html_content)
    projected = _markdown_link_projection(projected)
    projected = MARKDOWN_BACKSLASH_ESCAPE_RE.sub(lambda match: match.group(1), projected)
    projected = projected.replace("*", "").replace("__", "").replace("~~", "").replace("`", "")
    return projected


def _reversible_escape_projection(text: str) -> str:
    projected = BACKSLASH_UNICODE_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), text)
    return BACKSLASH_HEX_ESCAPE_RE.sub(lambda match: chr(int(match.group(1), 16)), projected)


def _semantic_secret_scan_candidates(text: str) -> Iterator[str]:
    """Return bounded renderer-visible forms used by every secret sink.

    Markdown renderers decode HTML entities and terminals consume ANSI control
    sequences. NFKC and invisible-control removal close equivalent visual
    splits without attempting arbitrary URL/base64 decoding.
    """

    current = text
    for _ in range(4):
        yield current
        if (
            current.isascii()
            and UNSAFE_ASCII_CONTROL_RE.search(current) is None
            and all(marker not in current for marker in ("\x1b", "&", "<", "[", "*", "`", "\\"))
            and "__" not in current
            and "~~" not in current
        ):
            return
        normalized = _bounded_nfkc(
            _remove_invisible_control_characters(_strip_terminal_escape_sequences(current))
        )
        if normalized != current:
            yield normalized
        decoded = html.unescape(normalized)
        if len(decoded) > MAX_SECRET_SCAN_CHARACTERS:
            raise ValueError("secret_scan_semantic_expansion_limit")
        if decoded != normalized:
            yield decoded
        projected = _markdown_visible_projection(decoded)
        if projected != decoded:
            yield projected
        hidden_projected = _markdown_visible_projection(decoded, remove_html_content=True)
        if hidden_projected not in {decoded, projected}:
            yield hidden_projected
        escaped = _reversible_escape_projection(projected)
        if escaped != projected:
            yield escaped
        hidden_escaped = _reversible_escape_projection(hidden_projected)
        if hidden_escaped not in {hidden_projected, escaped}:
            yield hidden_escaped
        if escaped == current:
            break
        current = escaped
    else:
        raise ValueError("secret_scan_semantic_depth_limit")


def _canonical_context_field_name(value: str) -> str:
    value = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value.strip())
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def _strip_context_field_value(value: str) -> str:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
        return value[1:-1].strip()
    return value


def _credential_context_findings(name: str, value: str) -> list[str]:
    """Scan a decoded label/value pair without recursively parsing JSON."""

    if not isinstance(name, str) or not isinstance(value, str):
        return []
    clean_name = _strip_context_field_value(name)
    clean_value = _strip_context_field_value(value)
    normalized_name = re.sub(r"[\s_.-]+", "-", clean_name.strip().lower())
    if normalized_name in {"authorization", "proxy-authorization"}:
        combined = f"Authorization: {clean_value}"
    elif CREDENTIAL_NAME_FULL_RE.fullmatch(clean_name.strip()) is not None:
        combined = f"{clean_name}={clean_value}"
    else:
        return []
    if len(combined) > MAX_SECRET_SCAN_CHARACTERS:
        return ["secret_scan_input_too_large"]
    findings: list[str] = []
    for candidate in _semantic_secret_scan_candidates(combined):
        findings.extend(name for name, pattern in SECRET_PATTERNS if pattern.search(candidate))
        findings.extend(name for name, _, _ in _credential_assignment_matches(candidate))
    return list(dict.fromkeys(findings))


def _iter_text_lines_keepends(text: str) -> Iterator[tuple[int, str]]:
    """Yield one line at a time without materializing a split-lines list."""

    start = 0
    while start < len(text):
        newline = text.find("\n", start)
        end = len(text) if newline < 0 else newline + 1
        yield start, text[start:end]
        start = end


def _named_credential_block_matches(text: str) -> list[tuple[str, int, int]]:
    """Find adjacent YAML/Markdown name/value fields in bounded linear work."""

    matches: list[tuple[str, int, int]] = []
    pending: tuple[int, re.Match[str], bool] | None = None
    line_count = 0
    for offset, line in _iter_text_lines_keepends(text):
        line_count += 1
        if line_count > MAX_MARKUP_TOKENS:
            return matches + [("secret_scan_structured_context_limit", offset, offset)]
        content = line.rstrip("\r\n")
        if pending is not None:
            label_offset, label_match, skipped_blank = pending
            if not content.strip() and not skipped_blank:
                pending = (label_offset, label_match, True)
                continue
            value_match = CONTEXT_VALUE_LINE_RE.fullmatch(content)
            if value_match is not None and len(str(value_match.group("indent"))) >= len(
                str(label_match.group("indent"))
            ):
                credential_name = _strip_context_field_value(str(label_match.group("value")))
                credential_value = _strip_context_field_value(str(value_match.group("value")))
                findings = _credential_context_findings(credential_name, credential_value)
                matches.extend((finding, label_offset, offset + len(line)) for finding in findings)
                if len(matches) > MAX_SECRET_MATCH_LOCATIONS:
                    return matches
            pending = None

        label_match = CONTEXT_FIELD_LINE_RE.fullmatch(content)
        if label_match is None:
            continue
        credential_name = _strip_context_field_value(str(label_match.group("value")))
        if not credential_name:
            continue
        pending = (offset, label_match, False)
    return matches


def _markdown_table_credential_matches(text: str) -> list[tuple[str, int, int]]:
    matches: list[tuple[str, int, int]] = []
    line_count = 0
    for offset, line in _iter_text_lines_keepends(text):
        line_count += 1
        if line_count > MAX_MARKUP_TOKENS:
            return matches + [("secret_scan_structured_context_limit", offset, offset)]
        leading_pipe = re.match(r"[ \t]*\|", line)
        if leading_pipe is None or line.find("|", leading_pipe.end()) < 0:
            continue
        previous: tuple[str | None, int, int, bool] | None = None
        cell_start = 0
        search = 0
        cell_count = 0
        while True:
            separator = line.find("|", search)
            final_cell = separator < 0
            if final_cell:
                separator = len(line)
            cell_count += 1
            if cell_count > MAX_MARKUP_TOKENS:
                return matches + [("secret_scan_structured_context_limit", offset, offset)]
            oversized = separator - cell_start > 4096
            cell = None if oversized else line[cell_start:separator].strip()
            current = (cell, offset + cell_start, offset + separator, oversized)
            if previous is not None and previous[0]:
                if current[3] and CREDENTIAL_NAME_FULL_RE.fullmatch(previous[0]) is not None:
                    matches.append(("secret_scan_structured_context_limit", previous[1], current[2]))
                elif current[0]:
                    findings = _credential_context_findings(previous[0], current[0])
                    matches.extend((finding, previous[1], current[2]) for finding in findings)
                if len(matches) > MAX_SECRET_MATCH_LOCATIONS:
                    return matches
            previous = current
            if final_cell:
                break
            cell_start = separator + 1
            search = cell_start
    return matches


def _strip_inline_context_value(value: str) -> str:
    value = value.strip().rstrip(",;").strip()
    while value and value[-1] in "}]":
        value = value[:-1].rstrip()
    while value and value[0] in "[{":
        value = value[1:].lstrip()
    return _strip_context_field_value(value)


def _inline_credential_context_matches(text: str) -> list[tuple[str, int, int]]:
    """Find same-line name/value records without relying on JSON syntax."""

    matches: list[tuple[str, int, int]] = []
    label_fields = {"name", "key", "credential", "credential_name", "secret_name"}
    value_fields = {"value", "credential_value", "secret_value"}
    line_count = 0
    for offset, line in _iter_text_lines_keepends(text):
        line_count += 1
        if line_count > MAX_MARKUP_TOKENS:
            return matches + [("secret_scan_structured_context_limit", offset, offset)]
        previous_match: re.Match[str] | None = None
        previous_record: tuple[str, str | None, int, int, bool] | None = None
        examined = 0

        def record(field_match: re.Match[str], value_end: int) -> tuple[str, str | None, int, int, bool]:
            oversized = value_end - field_match.end() > 4096
            value = None if oversized else _strip_inline_context_value(line[field_match.end() : value_end])
            return (
                _canonical_context_field_name(str(field_match.group("field"))),
                value,
                offset + field_match.start(),
                offset + value_end,
                oversized,
            )

        def compare(
            left: tuple[str, str | None, int, int, bool],
            right: tuple[str, str | None, int, int, bool],
        ) -> bool:
            if right[2] - left[2] > 512:
                return False
            label = left if left[0] in label_fields else right if right[0] in label_fields else None
            value = left if left[0] in value_fields else right if right[0] in value_fields else None
            if label is None or value is None:
                return False
            if label[4] or value[4] or label[1] is None or value[1] is None:
                matches.append(("secret_scan_structured_context_limit", min(left[2], right[2]), max(left[3], right[3])))
                return len(matches) > MAX_SECRET_MATCH_LOCATIONS
            findings = _credential_context_findings(label[1], value[1])
            matches.extend((finding, min(left[2], right[2]), max(left[3], right[3])) for finding in findings)
            return len(matches) > MAX_SECRET_MATCH_LOCATIONS

        for field_match in INLINE_CONTEXT_FIELD_PREFIX_RE.finditer(line):
            examined += 1
            if examined > MAX_MARKUP_TOKENS:
                return matches + [("secret_scan_structured_context_limit", offset, offset)]
            if previous_match is not None:
                current_record = record(previous_match, field_match.start())
                if previous_record is not None and compare(previous_record, current_record):
                    return matches
                previous_record = current_record
            previous_match = field_match
        if previous_match is not None:
            current_record = record(previous_match, len(line))
            if previous_record is not None and compare(previous_record, current_record):
                return matches
    return matches


def _credential_pair_context_matches(text: str) -> list[tuple[str, int, int]]:
    """Find credential-label/string pairs even inside partial diagnostic syntax."""

    matches: list[tuple[str, int, int]] = []
    examined = 0
    for label_match in PAIR_CONTEXT_LABEL_RE.finditer(text):
        examined += 1
        if examined > MAX_SECRET_MATCH_LOCATIONS:
            return matches + [("secret_match_limit_exceeded", 0, 0)]
        if label_match.start() > 0 and (text[label_match.start() - 1].isalnum() or text[label_match.start() - 1] == "_"):
            continue
        if label_match.end() < len(text) and (text[label_match.end()].isalnum() or text[label_match.end()] == "_"):
            continue
        prefix = text[max(0, label_match.start() - 20) : label_match.start()].lower()
        if (
            prefix.endswith("<redacted:")
            or prefix.endswith("${")
            or prefix.endswith("$")
            or prefix.endswith("secret_pattern=")
        ):
            continue
        separator = label_match.end()
        while separator < len(text) and text[separator] in " \t\"'":
            separator += 1
        if separator >= len(text) or text[separator] != ",":
            continue
        cursor = separator + 1
        boundary = min(len(text), cursor + 4096)
        while cursor < boundary and text[cursor] in " \t\r\n[](){}":
            cursor += 1
        if cursor >= len(text):
            continue
        if cursor >= boundary:
            matches.append(("secret_scan_structured_context_limit", label_match.start(), boundary))
            continue
        possible_field = re.match(
            r"[\"']?(?P<field>[A-Za-z][A-Za-z0-9 ._-]{0,31})[\"']?[ \t]*[:=][ \t]*",
            text[cursor:boundary],
        )
        if possible_field is not None:
            field = _canonical_context_field_name(str(possible_field.group("field")))
            if field not in {"value", "credential_value", "secret_value"}:
                continue
            cursor += possible_field.end()
            if cursor >= len(text):
                continue
            while cursor < boundary and text[cursor] in " \t\r\n":
                cursor += 1
            if cursor >= len(text):
                continue
            if cursor >= boundary:
                matches.append(("secret_scan_structured_context_limit", label_match.start(), boundary))
                continue
        wrapper_match = re.match(r"(?i:bytearray|bytes)[ \t]*\([ \t]*", text[cursor:boundary])
        wrapper_opened = wrapper_match is not None
        if wrapper_match is not None:
            cursor += wrapper_match.end()
        prefix_match = re.match(r"(?i:br|rb|b|r|u)?", text[cursor:boundary])
        literal_start = cursor + (prefix_match.end() if prefix_match is not None else 0)
        delimiter = ""
        for candidate_delimiter in ('"""', "'''", "\"", "'", "`"):
            if text.startswith(candidate_delimiter, literal_start):
                delimiter = candidate_delimiter
                break
        if not delimiter:
            continue
        value_start = literal_start + len(delimiter)
        value_end = value_start
        escaped = False
        while value_end < boundary:
            character = text[value_end]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif text.startswith(delimiter, value_end):
                break
            value_end += 1
        if value_end >= boundary or value_end >= len(text):
            matches.append(("secret_scan_structured_context_limit", label_match.start(), boundary))
            continue
        value = text[value_start:value_end]
        tail = value_end + len(delimiter)
        while tail < len(text) and text[tail] in " \t":
            tail += 1
        if wrapper_opened:
            if tail >= len(text) or text[tail] != ")":
                matches.append(("secret_scan_structured_context_limit", label_match.start(), min(boundary, tail)))
                continue
            tail += 1
            while tail < len(text) and text[tail] in " \t":
                tail += 1
        if tail < len(text) and text[tail] == "+":
            continue
        if CREDENTIAL_NAME_FULL_RE.fullmatch(value) is not None:
            continue
        findings = _credential_context_findings(label_match.group(0), value)
        matches.extend((finding, label_match.start(), value_end + 1) for finding in findings)
        if len(matches) > MAX_SECRET_MATCH_LOCATIONS:
            break
    return matches


def _structured_credential_findings(value: object) -> list[str]:
    """Inspect common decoded JSON credential records with bounded traversal."""

    findings: list[str] = []
    stack: list[tuple[object, int]] = [(value, 0)]
    visited = 0
    label_fields = {"name", "key", "credential", "credential_name", "secret_name"}
    value_fields = {"value", "credential_value", "secret_value"}
    while stack:
        item, depth = stack.pop()
        visited += 1
        if visited > MAX_STRUCTURED_CONTEXT_NODES:
            findings.append("secret_scan_structured_context_limit")
            break
        if depth > 256:
            findings.append("persistent_json_nesting_too_deep")
            break
        if isinstance(item, dict):
            if len(item) > MAX_STRUCTURED_CONTEXT_NODES - visited:
                findings.append("secret_scan_structured_context_limit")
                break
            normalized_items: dict[str, object] = {}
            for key, child in item.items():
                if isinstance(key, str):
                    normalized_items[_canonical_context_field_name(key)] = child
                    if isinstance(child, str):
                        findings.extend(_credential_context_findings(key, child))
                stack.append((child, depth + 1))
            labels = [normalized_items[field] for field in label_fields if field in normalized_items]
            values = [normalized_items[field] for field in value_fields if field in normalized_items]
            for label in labels:
                if not isinstance(label, str):
                    continue
                for child in values:
                    if isinstance(child, str):
                        findings.extend(_credential_context_findings(label, child))
        elif isinstance(item, (list, tuple)):
            if len(item) > MAX_STRUCTURED_CONTEXT_NODES - visited:
                findings.append("secret_scan_structured_context_limit")
                break
            if len(item) == 2 and isinstance(item[0], str) and isinstance(item[1], str):
                findings.extend(_credential_context_findings(item[0], item[1]))
            stack.extend((child, depth + 1) for child in item)
    return list(dict.fromkeys(findings))


def _json_fragment_candidates(text: str) -> Iterator[str]:
    """Yield disjoint balanced JSON-like fragments using one pass."""

    index = 0
    start = -1
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    yielded = 0
    while index < len(text):
        character = text[index]
        if not stack:
            if character not in "[{":
                index += 1
                continue
            start = index
            stack.append(character)
            quote = None
            escaped = False
            index += 1
            continue
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"\"", "'"}:
            quote = character
        elif character in "[{":
            stack.append(character)
            if len(stack) > 256:
                raise ValueError("persistent_json_nesting_too_deep")
        elif character in "]}":
            expected = "[" if character == "]" else "{"
            if stack[-1] != expected:
                stack.clear()
                start = -1
            else:
                stack.pop()
                if not stack and start >= 0:
                    yielded += 1
                    if yielded > MAX_MARKUP_TOKENS:
                        raise ValueError("secret_scan_structured_context_limit")
                    yield text[start : index + 1]
                    start = -1
        index += 1


def _oversized_structured_context_present(text: str) -> bool:
    """Detect a large JSON/Python-like span before renderer projections copy it."""

    if len(text) <= MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS:
        return False
    index = 0
    start = -1
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    while index < len(text):
        if not stack:
            object_start = text.find("{", index)
            array_start = text.find("[", index)
            candidates = [position for position in (object_start, array_start) if position >= 0]
            if not candidates:
                return False
            start = min(candidates)
            stack.append(text[start])
            quote = None
            escaped = False
            index = start + 1
            continue
        if index - start > MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS:
            return True
        character = text[index]
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
        elif character in {"\"", "'"}:
            quote = character
        elif character in "[{":
            stack.append(character)
            if len(stack) > 256:
                return True
        elif character in "]}":
            expected = "[" if character == "]" else "{"
            if stack[-1] != expected:
                stack.clear()
            else:
                stack.pop()
        index += 1
    return bool(stack and len(text) - start > MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS)


def _json_credential_findings(text: str) -> list[str]:
    findings: list[str] = []
    for fragment in _json_fragment_candidates(text):
        if len(fragment) > MAX_STRUCTURED_CONTEXT_INPUT_CHARACTERS:
            findings.append("secret_scan_structured_context_input_limit")
            continue
        try:
            value = json.loads(fragment, object_pairs_hook=_reject_duplicate_json_keys)
        except json.JSONDecodeError:
            continue
        except ValueError as exc:
            if str(exc) == "persistent_json_duplicate_key":
                findings.append("persistent_json_duplicate_key")
            continue
        except (TypeError, RecursionError):
            continue
        findings.extend(_structured_credential_findings(value))
    return list(dict.fromkeys(findings))


def _raw_secret_findings(text: str) -> list[str]:
    findings: list[str] = []
    for scanner in (
        _named_credential_block_matches,
        _markdown_table_credential_matches,
        _inline_credential_context_matches,
    ):
        scanned = [name for name, _, _ in scanner(text)]
        findings.extend(scanned)
        if any(_is_scan_limit_finding(name) for name in scanned):
            return findings
    findings.extend(name for name, pattern in SECRET_PATTERNS if pattern.search(text))
    for scanner in (
        _credential_assignment_matches,
        _credential_pair_context_matches,
        _uri_credential_matches,
    ):
        scanned = [name for name, _, _ in scanner(text)]
        findings.extend(scanned)
        if any(_is_scan_limit_finding(name) for name in scanned):
            return findings
    if next(_unsafe_persistent_control_offsets(text), None) is not None:
        findings.append("unsafe_control_sequence")
    return findings


def _is_scan_limit_finding(name: str) -> bool:
    return name in {
        "persistent_json_nesting_too_deep",
        "secret_match_limit_exceeded",
        "secret_scan_input_too_large",
        "secret_scan_structured_context_input_limit",
        "secret_scan_structured_context_limit",
    } or name.startswith("secret_scan_semantic_")


def secret_findings(text: str) -> list[str]:
    if not isinstance(text, str):
        raise TypeError("secret scan input must be text")
    if len(text) > MAX_SECRET_SCAN_CHARACTERS:
        return ["secret_scan_input_too_large"]
    if _oversized_structured_context_present(text):
        return ["secret_scan_structured_context_input_limit"]
    try:
        findings: list[str] = []
        for candidate in _semantic_secret_scan_candidates(text):
            raw_findings = _raw_secret_findings(candidate)
            findings.extend(raw_findings)
            if any(_is_scan_limit_finding(name) for name in raw_findings):
                return list(dict.fromkeys(findings))
            json_findings = _json_credential_findings(candidate)
            findings.extend(json_findings)
            if any(_is_scan_limit_finding(name) for name in json_findings):
                return list(dict.fromkeys(findings))
    except ValueError as exc:
        label = str(exc)
        return [label if label.startswith("secret_scan_semantic_") else "secret_scan_semantic_expansion_limit"]
    return list(dict.fromkeys(findings))


def secret_match_locations(text: str) -> list[tuple[str, int]]:
    """Return bounded finding labels and offsets, never credential text."""

    if not isinstance(text, str):
        raise TypeError("secret scan input must be text")
    if len(text) > MAX_SECRET_SCAN_CHARACTERS:
        return [("secret_scan_input_too_large", 0)]
    if _oversized_structured_context_present(text):
        return [("secret_scan_structured_context_input_limit", 0)]
    locations: list[tuple[str, int]] = []
    limit_exceeded = False
    try:
        for candidate in _semantic_secret_scan_candidates(text):
            structural_locations: list[tuple[str, int]] = []
            for scanner in (
                _named_credential_block_matches,
                _markdown_table_credential_matches,
                _inline_credential_context_matches,
            ):
                for name, start, _ in scanner(candidate):
                    if _is_scan_limit_finding(name):
                        return [(name, start)]
                    structural_locations.append((name, start))
                    if len(locations) + len(structural_locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                if limit_exceeded:
                    break
            if limit_exceeded:
                break
            for offset in _unsafe_persistent_control_offsets(candidate):
                if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                    limit_exceeded = True
                    break
                locations.append(("unsafe_control_sequence", offset))
            if limit_exceeded:
                break
            for name, pattern in SECRET_PATTERNS:
                for match in pattern.finditer(candidate):
                    if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                    locations.append((name, match.start()))
                if limit_exceeded:
                    break
            if not limit_exceeded:
                for name, start, _ in _credential_assignment_matches(candidate):
                    if _is_scan_limit_finding(name):
                        return [(name, start)]
                    if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                    locations.append((name, start))
            if not limit_exceeded:
                locations.extend(structural_locations)
            if not limit_exceeded:
                for name, start, _ in _credential_pair_context_matches(candidate):
                    if _is_scan_limit_finding(name):
                        return [(name, start)]
                    if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                    locations.append((name, start))
            if not limit_exceeded:
                for name, start, _ in _uri_credential_matches(candidate):
                    if _is_scan_limit_finding(name):
                        return [(name, start)]
                    if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                    locations.append((name, start))
            if not limit_exceeded:
                for name in _json_credential_findings(candidate):
                    if _is_scan_limit_finding(name):
                        return [(name, 0)]
                    if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                        limit_exceeded = True
                        break
                    locations.append((name, 0))
            if limit_exceeded:
                break
    except ValueError as exc:
        label = str(exc)
        return [
            (
                label if label.startswith("secret_scan_semantic_") else "secret_scan_semantic_expansion_limit",
                0,
            )
        ]
    locations.sort(key=lambda item: (item[1], item[0]))
    if limit_exceeded:
        return locations + [("secret_match_limit_exceeded", 0)]
    return locations


def literal_secret_match_locations(text: str) -> list[tuple[str, int]]:
    """Return high-confidence literal findings for source/package hygiene.

    Source code intentionally contains regexes, escaped controls, detector
    labels, and synthetic fixture construction. Package scans therefore use
    only literal provider/private-key/header patterns plus real control bytes;
    runtime artifacts continue to use the full semantic policy above.
    """

    if not isinstance(text, str):
        raise TypeError("secret scan input must be text")
    if len(text) > MAX_SECRET_SCAN_CHARACTERS:
        return [("secret_scan_input_too_large", 0)]
    locations: list[tuple[str, int]] = []
    for offset in _unsafe_persistent_control_offsets(text):
        locations.append(("unsafe_control_sequence", offset))
        if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
            return locations + [("secret_match_limit_exceeded", 0)]
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            locations.append((name, match.start()))
            if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                return locations + [("secret_match_limit_exceeded", 0)]
    for name, start, _ in _uri_credential_matches(text):
        locations.append((name, start))
        if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
            return locations + [("secret_match_limit_exceeded", 0)]
    return sorted(locations, key=lambda item: (item[1], item[0]))


def _package_semantic_string_locations(
    value: str,
    offset: int,
) -> list[tuple[str, int]]:
    """Scan one decoded source literal without treating escaped controls as bytes."""

    if len(value) > MAX_SECRET_SCAN_CHARACTERS:
        return [("secret_scan_input_too_large", offset)]
    locations = [
        (name, offset + start)
        for name, start, _end in _credential_assignment_matches(value)
    ]
    lowered = value.casefold()
    if any(marker in lowered for marker in PACKAGE_SEMANTIC_SECRET_MARKERS):
        for name, pattern in SECRET_PATTERNS:
            locations.extend((name, offset + match.start()) for match in pattern.finditer(value))
        locations.extend((name, offset + start) for name, start, _ in _uri_credential_matches(value))
    return _bounded_package_locations(locations)


def _package_python_comment_locations(
    text: str,
    line_offsets: Sequence[int],
) -> list[tuple[str, int]]:
    """Scan decoded Python comments without treating source syntax as a value."""

    locations: list[tuple[str, int]] = []
    visited = 0
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for token in tokens:
            visited += 1
            if visited > PACKAGE_PYTHON_TOKEN_MAX_COUNT:
                return _bounded_package_locations(
                    [*locations, ("secret_scan_structured_context_limit", 0)]
                )
            if token.type != tokenize.COMMENT:
                continue
            line_number, column = token.start
            if not 1 <= line_number <= len(line_offsets):
                return [("package_python_parse_failed", 0)]
            token_offset = line_offsets[line_number - 1] + column
            locations.extend(
                (name, token_offset + start)
                for name, start, _end in _credential_assignment_matches(token.string)
            )
            if len(locations) > MAX_SECRET_MATCH_LOCATIONS:
                break
    except (IndentationError, SyntaxError, tokenize.TokenError):
        return [("package_python_parse_failed", 0)]
    return _bounded_package_locations(locations)


def _python_target_names(target: ast.AST, *, depth: int = 0) -> tuple[str, ...]:
    if depth > PACKAGE_PYTHON_CONSTANT_MAX_DEPTH:
        raise ValueError("secret_scan_structured_context_limit")
    if isinstance(target, ast.Name):
        return (target.id,)
    if isinstance(target, ast.Attribute):
        return (target.attr,)
    if isinstance(target, ast.Subscript):
        key = _bounded_python_constant_string(target.slice, depth=depth + 1)
        return (key,) if isinstance(key, str) else ()
    if isinstance(target, (ast.List, ast.Tuple)):
        return tuple(
            name
            for item in target.elts
            for name in _python_target_names(item, depth=depth + 1)
        )
    return ()


def _python_target_value_bindings(
    target: ast.AST,
    value: ast.AST,
    *,
    depth: int = 0,
) -> list[tuple[tuple[str, ...], ast.AST]]:
    """Pair destructured Python targets with their corresponding value nodes."""

    if depth > PACKAGE_PYTHON_CONSTANT_MAX_DEPTH:
        raise ValueError("secret_scan_structured_context_limit")
    if (
        isinstance(target, (ast.List, ast.Tuple))
        and isinstance(value, (ast.List, ast.Tuple))
        and len(target.elts) == len(value.elts)
    ):
        bindings: list[tuple[tuple[str, ...], ast.AST]] = []
        for target_item, value_item in zip(target.elts, value.elts):
            bindings.extend(
                _python_target_value_bindings(
                    target_item,
                    value_item,
                    depth=depth + 1,
                )
            )
        return bindings
    return [(_python_target_names(target, depth=depth + 1), value)]


def _python_argument_default_bindings(
    arguments: ast.arguments,
) -> list[tuple[tuple[str, ...], ast.AST]]:
    positional = [*arguments.posonlyargs, *arguments.args]
    bindings = [
        ((argument.arg,), default)
        for argument, default in zip(positional[-len(arguments.defaults) :], arguments.defaults)
    ] if arguments.defaults else []
    bindings.extend(
        ((argument.arg,), default)
        for argument, default in zip(arguments.kwonlyargs, arguments.kw_defaults)
        if default is not None
    )
    return bindings


def _python_call_binding_nodes(
    node: ast.Call,
) -> list[tuple[tuple[str, ...], ast.AST]]:
    """Recognize fixed two-argument credential-setting APIs."""

    function_name = ""
    if isinstance(node.func, ast.Name):
        function_name = node.func.id
    elif isinstance(node.func, ast.Attribute):
        function_name = node.func.attr
    if function_name not in {"putenv", "setdefault", "setenv"}:
        return []
    if len(node.args) != 2 or node.keywords:
        return []
    key = _bounded_python_constant_string(node.args[0])
    return [((key,), node.args[1])] if isinstance(key, str) else []


def _python_node_offset(node: ast.AST, line_offsets: Sequence[int]) -> int:
    line_number = getattr(node, "lineno", 1)
    if not isinstance(line_number, int) or not 1 <= line_number <= len(line_offsets):
        return 0
    return line_offsets[line_number - 1]


def _package_credential_binding_findings(name: str, value: str | bytes) -> list[str]:
    """Preserve source-level credential-name aliases as non-secret placeholders."""

    if isinstance(value, bytes):
        try:
            decoded = value.decode("utf-8")
        except UnicodeDecodeError:
            clean_name = name.strip()
            if CREDENTIAL_NAME_FULL_RE.fullmatch(clean_name) is None or not value:
                return []
            canonical_name = _canonical_credential_name(clean_name)
            if canonical_name == "AWS_SECRET_ACCESS_KEY":
                return ["aws_secret_access_key"]
            if canonical_name == "AWS_SESSION_TOKEN":
                return ["aws_session_token"]
            if canonical_name in PROVIDER_CREDENTIAL_NAMES:
                return ["provider_credential_assignment"]
            return ["generic_credential_assignment"]
        value = decoded
    canonical_name = _canonical_credential_name(name)
    if value == canonical_name:
        return []
    return _credential_context_findings(name, value)


def _is_bounded_python_literal_join(node: ast.AST) -> bool:
    """Recognize only a literal str/bytes join over a literal sequence."""

    return bool(
        isinstance(node, ast.Call)
        and not node.keywords
        and len(node.args) == 1
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "join"
        and isinstance(node.func.value, ast.Constant)
        and isinstance(node.func.value.value, (str, bytes))
        and isinstance(node.args[0], (ast.List, ast.Tuple))
    )


def _bounded_python_constant_string(
    node: ast.AST,
    *,
    depth: int = 0,
) -> str | bytes | None:
    """Evaluate only side-effect-free constant text/bytes under strict bounds."""

    if depth > PACKAGE_PYTHON_CONSTANT_MAX_DEPTH:
        raise ValueError("secret_scan_structured_context_limit")
    if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
        value = node.value
    elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _bounded_python_constant_string(node.left, depth=depth + 1)
        right = _bounded_python_constant_string(node.right, depth=depth + 1)
        if left is None or right is None or type(left) is not type(right):
            return None
        value = left + right
    elif isinstance(node, ast.JoinedStr):
        parts: list[str] = []
        total = 0
        for item in node.values:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                part = item.value
            elif (
                isinstance(item, ast.FormattedValue)
                and item.conversion in {-1, ord("s")}
                and item.format_spec is None
                and isinstance(item.value, ast.Constant)
                and isinstance(item.value.value, (str, int, float, bool))
            ):
                part = str(item.value.value)
            else:
                return None
            total += len(part)
            if total > PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS:
                raise ValueError("secret_scan_structured_context_limit")
            parts.append(part)
        value = "".join(parts)
    elif _is_bounded_python_literal_join(node):
        assert isinstance(node, ast.Call)
        assert isinstance(node.func, ast.Attribute)
        assert isinstance(node.func.value, ast.Constant)
        assert isinstance(node.args[0], (ast.List, ast.Tuple))
        separator = node.func.value.value
        elements = node.args[0].elts
        if len(elements) > PACKAGE_PYTHON_CONSTANT_MAX_PARTS:
            raise ValueError("secret_scan_structured_context_limit")
        parts: list[str] | list[bytes]
        parts = []
        total = 0
        for item in elements:
            part = _bounded_python_constant_string(item, depth=depth + 1)
            if part is None or type(part) is not type(separator):
                return None
            total += len(part)
            if parts:
                total += len(separator)
            if total > PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS:
                raise ValueError("secret_scan_structured_context_limit")
            parts.append(part)
        value = separator.join(parts)
    else:
        return None
    if len(value) > PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS:
        raise ValueError("secret_scan_structured_context_limit")
    return value


def _package_python_match_locations(text: str) -> list[tuple[str, int]]:
    """Scan Python literals and credential bindings using the parsed source tree."""

    locations = literal_secret_match_locations(text)
    if any(_is_scan_limit_finding(name) for name, _offset in locations):
        return _bounded_package_locations(locations)
    try:
        tree = ast.parse(text)
    except (MemoryError, RecursionError, SyntaxError, ValueError):
        return _bounded_package_locations([*locations, ("package_python_parse_failed", 0)])
    line_offsets = array("I", [0])
    line_offsets.extend(match.end() for match in re.finditer("\n", text))
    locations.extend(_package_python_comment_locations(text, line_offsets))
    if any(_is_scan_limit_finding(name) for name, _offset in locations):
        return _bounded_package_locations(locations)
    stack: list[ast.AST] = [tree]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > MAX_STRUCTURED_CONTEXT_NODES:
            locations.append(("secret_scan_structured_context_limit", 0))
            break
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            semantic_locations = _package_semantic_string_locations(node.value, 0)
            if semantic_locations:
                offset = _python_node_offset(node, line_offsets)
                locations.extend((name, offset + relative) for name, relative in semantic_locations)
        elif isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            offset = _python_node_offset(node, line_offsets)
            locations.extend(
                (name, offset + relative)
                for name, relative in _package_binary_match_locations(node.value)
            )
        if isinstance(node, (ast.BinOp, ast.JoinedStr)) or _is_bounded_python_literal_join(node):
            try:
                expression_value = _bounded_python_constant_string(node)
            except ValueError:
                locations.append(
                    ("secret_scan_structured_context_limit", _python_node_offset(node, line_offsets))
                )
            else:
                expression_offset = _python_node_offset(node, line_offsets)
                if isinstance(expression_value, str):
                    locations.extend(
                        (name, expression_offset + relative)
                        for name, relative in _package_semantic_string_locations(
                            expression_value,
                            0,
                        )
                    )
                elif isinstance(expression_value, bytes):
                    locations.extend(
                        (name, expression_offset + relative)
                        for name, relative in _package_binary_match_locations(expression_value)
                    )
        bindings: list[tuple[str, str | bytes]] = []
        binding_nodes: list[tuple[tuple[str, ...], ast.AST]] = []
        try:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    binding_nodes.extend(_python_target_value_bindings(target, node.value))
            elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
                binding_nodes.extend(_python_target_value_bindings(node.target, node.value))
            elif isinstance(node, ast.Dict):
                for key_node, value_node in zip(node.keys, node.values):
                    if key_node is None:
                        continue
                    key = _bounded_python_constant_string(key_node)
                    if isinstance(key, str):
                        binding_nodes.append(((key,), value_node))
            elif isinstance(node, ast.keyword) and node.arg is not None:
                binding_nodes.append(((node.arg,), node.value))
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                binding_nodes.extend(_python_argument_default_bindings(node.args))
            elif isinstance(node, ast.Call):
                binding_nodes.extend(_python_call_binding_nodes(node))
        except ValueError:
            locations.append(
                ("secret_scan_structured_context_limit", _python_node_offset(node, line_offsets))
            )
            binding_nodes = []
        for names, value_node in binding_nodes:
            try:
                value = _bounded_python_constant_string(value_node)
            except ValueError:
                locations.append(
                    ("secret_scan_structured_context_limit", _python_node_offset(value_node, line_offsets))
                )
                continue
            if value is not None:
                bindings.extend((name, value) for name in names)
        if bindings:
            offset = _python_node_offset(node, line_offsets)
        for name, value in bindings:
            locations.extend(
                (finding, offset)
                for finding in _package_credential_binding_findings(name, value)
            )
        stack.extend(ast.iter_child_nodes(node))
    return _bounded_package_locations(locations)


def _package_json_match_locations(text: str) -> list[tuple[str, int]]:
    """Scan a canonical JSON document after decoding strings and object structure."""

    locations = literal_secret_match_locations(text)
    if any(_is_scan_limit_finding(name) for name, _offset in locations):
        return _bounded_package_locations(locations)
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except (MemoryError, RecursionError, TypeError, ValueError, json.JSONDecodeError):
        return _bounded_package_locations([*locations, ("package_json_parse_failed", 0)])
    has_context_hint = bool(
        CREDENTIAL_ASSIGNMENT_RE.search(text)
        or PAIR_CONTEXT_LABEL_RE.search(text)
        or "\\u" in text
    )
    if not has_context_hint:
        return _bounded_package_locations(locations)
    locations.extend((finding, 0) for finding in _structured_credential_findings(value))
    stack: list[object] = [value]
    visited = 0
    while stack:
        item = stack.pop()
        visited += 1
        if visited > MAX_STRUCTURED_CONTEXT_NODES:
            locations.append(("secret_scan_structured_context_limit", 0))
            break
        if isinstance(item, str):
            locations.extend(_package_semantic_string_locations(item, 0))
        elif isinstance(item, dict):
            stack.extend(item.keys())
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return _bounded_package_locations(locations)


def _package_shell_match_locations(text: str) -> list[tuple[str, int]]:
    """Scan shell assignments line-by-line, including comment text."""

    locations = literal_secret_match_locations(text)
    if any(_is_scan_limit_finding(name) for name, _offset in locations):
        return _bounded_package_locations(locations)
    for offset, line in _iter_text_lines_keepends(text):
        locations.extend(
            (name, offset + start)
            for name, start, _ in _credential_assignment_matches(line)
        )
    return _bounded_package_locations(locations)


def _bounded_package_locations(
    locations: list[tuple[str, int]],
) -> list[tuple[str, int]]:
    """Deduplicate package findings while keeping a hard metadata bound."""

    ordered = sorted(set(locations), key=lambda item: (item[1], item[0]))
    if len(ordered) <= MAX_SECRET_MATCH_LOCATIONS:
        return ordered
    return [
        *ordered[: MAX_SECRET_MATCH_LOCATIONS - 1],
        ("secret_match_limit_exceeded", 0),
    ]


def _package_direct_match_locations(text: str) -> list[tuple[str, int]]:
    """Scan one offset-preserving byte projection without semantic expansion."""

    if len(text) > MAX_SECRET_SCAN_CHARACTERS:
        return [("secret_scan_input_too_large", 0)]
    locations: list[tuple[str, int]] = [
        ("unsafe_control_sequence", offset)
        for offset in _unsafe_persistent_control_offsets(text)
    ]
    for name, pattern in SECRET_PATTERNS:
        locations.extend((name, match.start()) for match in pattern.finditer(text))
    locations.extend((name, start) for name, start, _ in _credential_assignment_matches(text))
    locations.extend((name, start) for name, start, _ in _uri_credential_matches(text))
    return _bounded_package_locations(locations)


def _package_assignment_text_match_locations(text: str) -> list[tuple[str, int]]:
    """Scan configuration and JavaScript-family assignment syntax explicitly."""

    return _package_direct_match_locations(text)


def _package_binary_match_locations(data: bytes) -> list[tuple[str, int]]:
    """Scan arbitrary bytes in bounded overlapping, offset-preserving windows."""

    locations: list[tuple[str, int]] = []
    seen: set[tuple[str, int]] = set()
    for core_start in range(0, len(data), PACKAGE_BINARY_SCAN_WINDOW_BYTES):
        core_end = min(len(data), core_start + PACKAGE_BINARY_SCAN_WINDOW_BYTES)
        window_start = max(0, core_start - PACKAGE_BINARY_SCAN_OVERLAP_BYTES)
        window_end = min(len(data), core_end + PACKAGE_BINARY_SCAN_OVERLAP_BYTES)
        window = data[window_start:window_end]
        def projections() -> Iterator[tuple[str, int, int]]:
            yield (
                window.translate(PACKAGE_BINARY_PROJECTION_TABLE).decode("ascii"),
                0,
                1,
            )
            le_pair_starts = {
                match.start() % 2 for match in PACKAGE_UTF16_LE_ASCII_RUN_RE.finditer(window)
            }
            be_pair_starts = {
                match.start() % 2 for match in PACKAGE_UTF16_BE_ASCII_RUN_RE.finditer(window)
            }
            for pair_start in le_pair_starts | be_pair_starts:
                unit_count = (len(window) - pair_start) // 2
                if unit_count <= 0:
                    continue
                unit_end = pair_start + unit_count * 2
                first = window[pair_start:unit_end:2]
                second = window[pair_start + 1 : unit_end : 2]
                for characters, zero_guards, plausible_starts in (
                    (first, second, le_pair_starts),
                    (second, first, be_pair_starts),
                ):
                    if pair_start not in plausible_starts:
                        continue
                    projected = bytes(
                        PACKAGE_BINARY_PROJECTION_TABLE[character]
                        if guard == 0
                        else 10
                        for character, guard in zip(characters, zero_guards)
                    ).decode("ascii")
                    yield projected, pair_start, 2
            le_quad_starts = {
                match.start() % 4 for match in PACKAGE_UTF32_LE_ASCII_RUN_RE.finditer(window)
            }
            be_quad_starts = {
                match.start() % 4 for match in PACKAGE_UTF32_BE_ASCII_RUN_RE.finditer(window)
            }
            for quad_start in le_quad_starts | be_quad_starts:
                unit_count = (len(window) - quad_start) // 4
                if unit_count <= 0:
                    continue
                unit_end = quad_start + unit_count * 4
                lanes = tuple(
                    window[quad_start + lane : unit_end : 4]
                    for lane in range(4)
                )
                for characters, zero_guards, plausible_starts in (
                    (lanes[0], lanes[1:], le_quad_starts),
                    (lanes[3], lanes[:3], be_quad_starts),
                ):
                    if quad_start not in plausible_starts:
                        continue
                    projected = bytes(
                        PACKAGE_BINARY_PROJECTION_TABLE[character]
                        if all(guard == 0 for guard in guards)
                        else 10
                        for character, guards in zip(characters, zip(*zero_guards))
                    ).decode("ascii")
                    yield projected, quad_start, 4

        for projected, projection_start, stride in projections():
            for name, relative_offset in _package_direct_match_locations(projected):
                absolute_offset = window_start + projection_start + stride * relative_offset
                if not core_start <= absolute_offset < core_end:
                    continue
                item = (name, absolute_offset)
                if item in seen:
                    continue
                seen.add(item)
                locations.append(item)
                if len(locations) >= MAX_SECRET_MATCH_LOCATIONS:
                    return [
                        *sorted(locations, key=lambda entry: (entry[1], entry[0]))[
                            : MAX_SECRET_MATCH_LOCATIONS - 1
                        ],
                        ("secret_match_limit_exceeded", 0),
                    ]
    return sorted(locations, key=lambda item: (item[1], item[0]))


def _package_secret_scan_policy_key() -> tuple[object, ...]:
    return (
        MAX_SECRET_SCAN_CHARACTERS,
        MAX_SECRET_MATCH_LOCATIONS,
        MAX_STRUCTURED_CONTEXT_NODES,
        PACKAGE_BINARY_SCAN_WINDOW_BYTES,
        PACKAGE_BINARY_SCAN_OVERLAP_BYTES,
        PACKAGE_UTF16_MIN_ASCII_UNITS,
        PACKAGE_UTF32_MIN_ASCII_UNITS,
        PACKAGE_PYTHON_CONSTANT_MAX_CHARACTERS,
        PACKAGE_PYTHON_CONSTANT_MAX_DEPTH,
        PACKAGE_PYTHON_CONSTANT_MAX_PARTS,
        PACKAGE_PYTHON_TOKEN_MAX_COUNT,
        id(SECRET_PATTERNS),
        id(CREDENTIAL_ASSIGNMENT_RE),
    )


def package_secret_match_locations(data: bytes, suffix: str) -> list[tuple[str, int]]:
    """Return redacted secret metadata for one package payload.

    Known text formats must be canonical UTF-8. Arbitrary or binary payloads
    are scanned as bounded ASCII projections so undecodable bytes can never
    turn into an implicit allow decision. Returned metadata contains only
    detector labels and byte/character offsets, never matched content.
    """

    if not isinstance(data, bytes):
        raise TypeError("package secret scan input must be bytes")
    if not isinstance(suffix, str):
        raise TypeError("package secret scan suffix must be text")
    normalized_suffix = suffix.casefold()
    cache_key = (
        hashlib.sha256(data).digest(),
        len(data),
        normalized_suffix,
        _package_secret_scan_policy_key(),
    )
    cached = _PACKAGE_SECRET_SCAN_CACHE.get(cache_key)
    if cached is not None:
        _PACKAGE_SECRET_SCAN_CACHE.move_to_end(cache_key)
        return list(cached)
    if normalized_suffix in PACKAGE_KNOWN_TEXT_SUFFIXES:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            locations = [("package_text_invalid_utf8", 0)]
        else:
            scanners = {
                ".json": _package_json_match_locations,
                ".py": _package_python_match_locations,
                ".sh": _package_shell_match_locations,
            }
            scanners.update(
                {
                    suffix_name: _package_assignment_text_match_locations
                    for suffix_name in PACKAGE_CONFIG_TEXT_SUFFIXES | PACKAGE_SCRIPT_TEXT_SUFFIXES
                }
            )
            scanner = scanners.get(normalized_suffix, _package_direct_match_locations)
            locations = _bounded_package_locations(scanner(text))
    else:
        locations = _package_binary_match_locations(data)
    _PACKAGE_SECRET_SCAN_CACHE[cache_key] = tuple(locations)
    _PACKAGE_SECRET_SCAN_CACHE.move_to_end(cache_key)
    while len(_PACKAGE_SECRET_SCAN_CACHE) > PACKAGE_SECRET_SCAN_CACHE_MAX_ENTRIES:
        _PACKAGE_SECRET_SCAN_CACHE.popitem(last=False)
    return list(locations)


def package_secret_path_match_locations(relative: str) -> list[tuple[str, int]]:
    """Return redacted secret metadata for a package-relative path.

    The caller must never serialize the original path after a finding. The
    result contains only detector labels and character offsets.
    """

    if not isinstance(relative, str):
        raise TypeError("package secret path scan input must be text")
    if len(relative) > MAX_SECRET_SCAN_CHARACTERS:
        return [("secret_scan_input_too_large", 0)]
    return _package_direct_match_locations(relative)


def has_secret_like(text: str) -> bool:
    return bool(secret_findings(text))


def assert_safe_persistent_text(text: str) -> str:
    """Reject secret-shaped or unbounded text before a persistent write.

    Error messages expose only detector labels, never matched values.
    """

    findings = secret_findings(text)
    if findings:
        raise ValueError(f"persistent_artifact_secret_rejected={','.join(findings)}")
    return text


def assert_safe_persistent_bytes(encoded: bytes) -> bytes:
    if not isinstance(encoded, bytes):
        raise TypeError("persistent artifact content must be bytes")
    if len(encoded) > MAX_SECRET_SCAN_CHARACTERS:
        raise ValueError("persistent_artifact_scan_input_too_large")
    try:
        text = encoded.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("persistent_artifact_must_be_utf8_text") from None
    assert_safe_persistent_text(text)
    return encoded


def assert_safe_serialized_artifact(name: str, encoded: bytes) -> bytes:
    """Validate both raw and decoded semantics for persistent text formats."""

    assert_safe_persistent_bytes(encoded)
    lower_name = name.lower()
    if not lower_name.endswith((".json", ".jsonl")):
        return encoded
    text = encoded.decode("utf-8")
    try:
        if lower_name.endswith(".json"):
            values = [parse_safe_persistent_json(text)]
        else:
            values = [parse_safe_persistent_json(line) for line in text.splitlines() if line.strip()]
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("persistent_serialized_artifact_invalid") from None
    for value in values:
        serialize_safe_persistent_json(
            value,
            indent=None,
            separators=(",", ":"),
            trailing_newline=False,
        )
    return encoded


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("persistent_json_duplicate_key")
        value[key] = item
    return value


def parse_safe_persistent_json(text: str) -> object:
    assert_safe_persistent_text(text)
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except (TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("persistent_serialized_artifact_invalid") from None
    serialize_safe_persistent_json(
        value,
        indent=None,
        separators=(",", ":"),
        trailing_newline=False,
    )
    return value


def _assert_safe_persistent_json_value(value: object, *, depth: int = 0) -> None:
    if depth > 256:
        raise ValueError("persistent_json_nesting_too_deep")
    if depth == 0:
        findings = _structured_credential_findings(value)
        if findings:
            raise ValueError(f"persistent_artifact_secret_rejected={','.join(findings)}")
    if isinstance(value, str):
        assert_safe_persistent_text(value)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str):
                assert_safe_persistent_text(key)
                if key.strip().lower() in {"authorization", "proxy-authorization"} and isinstance(item, str):
                    assert_safe_persistent_text(f"Authorization: {item}")
            _assert_safe_persistent_json_value(item, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _assert_safe_persistent_json_value(item, depth=depth + 1)


def assert_safe_embedded_content_bytes(encoded: bytes) -> bytes:
    """Scan raw content before it is hidden inside a text encoding such as base64."""

    if not isinstance(encoded, bytes):
        raise TypeError("embedded artifact content must be bytes")
    if len(encoded) > MAX_SECRET_SCAN_CHARACTERS:
        raise ValueError("embedded_artifact_scan_input_too_large")
    candidates = {
        encoded.decode("utf-8", errors="ignore"),
        encoded.decode("latin-1", errors="ignore"),
        encoded.decode("latin-1", errors="ignore").replace("\x00", ""),
    }
    findings = sorted({name for text in candidates for name in secret_findings(text)})
    if findings:
        raise ValueError(f"embedded_artifact_secret_rejected={','.join(findings)}")
    return encoded


def serialize_safe_persistent_json(
    payload: object,
    *,
    indent: int | None = 2,
    sort_keys: bool = True,
    separators: tuple[str, str] | None = None,
    trailing_newline: bool = True,
) -> str:
    _assert_safe_persistent_json_value(payload)
    try:
        text = json.dumps(
            payload,
            indent=indent,
            sort_keys=sort_keys,
            separators=separators,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        raise ValueError("persistent_json_serialization_failed") from None
    if trailing_newline:
        text += "\n"
    return assert_safe_persistent_text(text)


def redact_secret_like(text: str) -> str:
    """Redact bounded diagnostic text without ever returning a matched value."""

    if not isinstance(text, str):
        raise TypeError("secret redaction input must be text")
    if len(text) > MAX_SECRET_SCAN_CHARACTERS:
        raise ValueError("secret_redaction_input_too_large")
    spans: list[tuple[int, int, str]] = []
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            if len(spans) >= MAX_SECRET_MATCH_LOCATIONS:
                raise ValueError("secret_redaction_match_limit_exceeded")
            end = match.end()
            if name == "private_key" and "-----END " not in text[match.start():end].upper():
                end = len(text)
            while end < len(text) and text[end] in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-./+=":
                end += 1
            spans.append((match.start(), end, name))
    for name, start, end in _credential_assignment_matches(text):
        if len(spans) >= MAX_SECRET_MATCH_LOCATIONS:
            raise ValueError("secret_redaction_match_limit_exceeded")
        spans.append((start, len(text), name))
    for name, start, end in _uri_credential_matches(text):
        if len(spans) >= MAX_SECRET_MATCH_LOCATIONS:
            raise ValueError("secret_redaction_match_limit_exceeded")
        spans.append((start, end, name))
    if not spans:
        return "<redacted:unsafe-diagnostic>" if secret_findings(text) else text
    spans.sort(key=lambda item: (item[0], -item[1], item[2]))
    merged: list[tuple[int, int, str]] = []
    for start, end, name in spans:
        if merged and start < merged[-1][1]:
            old_start, old_end, old_name = merged[-1]
            merged[-1] = (old_start, max(old_end, end), old_name)
        else:
            merged.append((start, end, name))
    pieces: list[str] = []
    cursor = 0
    for start, end, name in merged:
        pieces.append(text[cursor:start])
        pieces.append(f"<redacted:{name}>")
        cursor = end
    pieces.append(text[cursor:])
    redacted = "".join(pieces)
    if secret_findings(redacted):
        return "<redacted:unsafe-diagnostic>"
    return redacted


def safe_log_text(value: object, *, max_characters: int = MAX_SAFE_LOG_CHARACTERS) -> str:
    """Return a single-line, bounded, redacted representation for console/log output."""

    if not isinstance(max_characters, int) or isinstance(max_characters, bool) or max_characters < 32:
        raise ValueError("invalid_safe_log_character_limit")
    try:
        raw = str(value)
        terminal_safe = _remove_invisible_control_characters(_strip_terminal_escape_sequences(raw))
        redacted = redact_secret_like(terminal_safe)
    except Exception:
        return "<redacted:unsafe-diagnostic>"
    normalized = redacted.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    normalized = "".join(
        character
        if unicodedata.category(character) not in {"Cc", "Cf"}
        else f"\\u{ord(character):04x}"
        for character in normalized
    )
    if len(normalized) > max_characters:
        return normalized[: max_characters - 20] + "<truncated:safe-log>"
    return normalized


def path_is_inside(parent: Path, child: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical_json(value: object) -> object:
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":")))


def canonical_json_digest(value: object) -> str:
    return sha256_bytes(json.dumps(canonical_json(value), sort_keys=True, separators=(",", ":")).encode("utf-8"))


def default_budget_contract() -> dict[str, object]:
    return canonical_json(DEFAULT_BUDGET_CONTRACT)


def token_usage_not_observed() -> dict[str, object]:
    return canonical_json(TOKEN_USAGE_NOT_OBSERVED)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def budget_limit(contract: object, key: str, fallback: int | None = None) -> int:
    if isinstance(contract, dict) and _is_int(contract.get(key)):
        return int(contract[key])
    default = DEFAULT_BUDGET_CONTRACT.get(key)
    if _is_int(default):
        return int(default)
    if fallback is None:
        raise KeyError(key)
    return fallback


def validate_budget_contract(value: object, prefix: str = "budget_contract") -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{prefix}_missing"]
    if value.get("budget_schema_version") != BUDGET_SCHEMA_VERSION:
        errors.append(f"invalid_{prefix}_schema_version")
    for key, (minimum, maximum) in BUDGET_INT_LIMITS.items():
        current = value.get(key)
        if not _is_int(current) or not minimum <= int(current) <= maximum:
            errors.append(f"invalid_{prefix}={key}")
    if (
        _is_int(value.get("hard_total_token_limit"))
        and _is_int(value.get("soft_input_token_limit"))
        and int(value["hard_total_token_limit"]) < int(value["soft_input_token_limit"])
    ):
        errors.append(f"{prefix}_hard_below_soft")
    if (
        _is_int(value.get("hard_total_token_limit"))
        and _is_int(value.get("max_subagent_total_tokens"))
        and int(value["max_subagent_total_tokens"]) > int(value["hard_total_token_limit"])
    ):
        errors.append(f"{prefix}_subagent_tokens_exceed_hard_limit")
    if (
        _is_int(value.get("checkpoint_after_tasks"))
        and _is_int(value.get("max_selected_tasks"))
        and int(value["max_selected_tasks"]) > 0
        and int(value["checkpoint_after_tasks"]) > int(value["max_selected_tasks"])
    ):
        errors.append(f"{prefix}_checkpoint_exceeds_selected_task_cap")
    if value.get("pause_on_soft_limit") is not True:
        errors.append(f"{prefix}_must_pause_on_soft_limit")
    if value.get("enforcement_mode") != "advisory_or_runtime_supported":
        errors.append(f"invalid_{prefix}_enforcement_mode")
    return errors


def validate_token_usage(value: object, prefix: str = "token_usage") -> list[str]:
    if value == TOKEN_USAGE_NOT_OBSERVED:
        return []
    errors: list[str] = []
    if not isinstance(value, dict):
        return [f"{prefix}_missing"]
    if value.get("status") not in {"observed", "not_observed"}:
        errors.append(f"invalid_{prefix}_status")
    if value.get("status") == "not_observed" and value != TOKEN_USAGE_NOT_OBSERVED:
        errors.append(f"{prefix}_not_observed_must_be_explicit")
    if value.get("status") == "observed":
        for key in ("input_tokens", "output_tokens", "total_tokens"):
            current = value.get(key)
            if not _is_int(current) or int(current) < 0:
                errors.append(f"invalid_{prefix}={key}")
        if (
            _is_int(value.get("input_tokens"))
            and _is_int(value.get("output_tokens"))
            and _is_int(value.get("total_tokens"))
            and int(value["input_tokens"]) + int(value["output_tokens"]) != int(value["total_tokens"])
        ):
            errors.append(f"{prefix}_total_mismatch")
    return errors


def _list_of_strings(value: object) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item.strip() for item in value if isinstance(item, str) and item.strip()]


def implementation_contract_validation_command_ids(contract: dict[str, object]) -> list[str]:
    commands = contract.get("validation_commands")
    if not isinstance(commands, list):
        return []
    ids: list[str] = []
    for command in commands:
        if not isinstance(command, dict):
            continue
        command_id = command.get("id")
        if isinstance(command_id, str) and command_id.strip():
            ids.append(command_id.strip())
    return ids


def implementation_contract_paths(contract: dict[str, object]) -> list[str]:
    paths = contract.get("implementation_paths")
    if not isinstance(paths, list):
        return []
    normalized: list[str] = []
    for item in paths:
        if not isinstance(item, dict):
            continue
        path = item.get("path")
        if isinstance(path, str) and path.strip():
            normalized.append(path.strip())
    return normalized


def implementation_contract_source_binding(root: Path, source_subplan_path: str) -> dict[str, object]:
    errors: list[str] = []
    if not is_safe_repo_path(source_subplan_path):
        return {"errors": [f"unsafe_source_subplan_path={source_subplan_path or 'missing'}"]}
    path = (root / source_subplan_path).resolve()
    if not path_is_inside(root, path):
        return {"errors": [f"unsafe_source_subplan_path={source_subplan_path}"]}
    if not path.is_file():
        return {"errors": [f"missing_source_subplan={source_subplan_path}"]}

    text = path.read_text(encoding="utf-8", errors="replace")
    section_matches = list(IMPLEMENTATION_CONTRACT_SECTION_RE.finditer(text))
    if len(section_matches) != 1:
        errors.append(f"implementation_contract_section_count={source_subplan_path}:{len(section_matches)}")
        contract: dict[str, object] = {}
    else:
        json_matches = list(IMPLEMENTATION_CONTRACT_JSON_RE.finditer(section_matches[0].group("body")))
        if len(json_matches) != 1:
            errors.append(f"implementation_contract_json_block_count={source_subplan_path}:{len(json_matches)}")
            contract = {}
        else:
            try:
                parsed = json.loads(json_matches[0].group("json"))
            except json.JSONDecodeError:
                errors.append(f"implementation_contract_json_invalid={source_subplan_path}")
                parsed = {}
            contract = canonical_json(parsed) if isinstance(parsed, dict) else {}
            if not isinstance(parsed, dict):
                errors.append(f"implementation_contract_must_be_object={source_subplan_path}")

    digest = canonical_json_digest(contract) if contract else None
    return {
        "errors": errors,
        "source_subplan_path": source_subplan_path,
        "source_subplan_sha256": sha256_bytes(path.read_bytes()),
        "implementation_contract": contract,
        "implementation_contract_digest": digest,
        "validation_command_ids": implementation_contract_validation_command_ids(contract),
        "parent_acceptance_signal_ids": _list_of_strings(contract.get("parent_signals")),
        "security_review_required": contract.get("security_review_required") if isinstance(contract.get("security_review_required"), bool) else False,
        "risk_class": contract.get("risk_class") if isinstance(contract.get("risk_class"), str) else "",
        "risk_domains": _list_of_strings(contract.get("risk_domains")),
        "dependencies": canonical_json(contract.get("dependencies", {})),
        "outputs": _list_of_strings(contract.get("outputs")),
        "implementation_paths": implementation_contract_paths(contract),
    }


def _strip_value(value: str) -> str:
    return value.strip().strip("`").strip("'\"")


def _path_parts(value: str) -> tuple[str, ...]:
    return Path(value).parts


def is_safe_repo_path(value: str, *, allow_glob: bool = False, allow_home: bool = False) -> bool:
    target = _strip_value(value)
    if not target:
        return False
    if target.startswith("~"):
        return allow_home and not any(part == ".." for part in _path_parts(target))
    path = Path(target)
    if path.is_absolute():
        return False
    if any(part == ".." for part in path.parts):
        return False
    if not allow_glob and any(char in target for char in "*?[]"):
        return False
    return True


def unsafe_path_in_arg(value: str) -> bool:
    raw = _strip_value(value)
    candidates = [raw]
    if "=" in raw:
        candidates.append(raw.split("=", 1)[1])
    for candidate in candidates:
        if not candidate or candidate in {".", "./", "./..."}:
            continue
        if candidate.startswith(("http://", "https://")):
            return True
        if candidate.startswith("~"):
            return True
        path = Path(candidate)
        if path.is_absolute():
            return True
        if any(part == ".." for part in path.parts):
            return True
    return False


def _sensitive_validation_path(value: str) -> bool:
    candidate = _strip_value(value).replace("\\", "/")
    if "=" in candidate:
        candidate = candidate.split("=", 1)[1]
    candidate = candidate.split("::", 1)[0]
    for raw_part in candidate.split("/"):
        part = raw_part.strip().lower()
        if not part or part in {".", ".."}:
            continue
        if part in SENSITIVE_VALIDATION_PATH_PARTS or part.startswith(".env."):
            return True
        if Path(part).stem in {"credential", "credentials", "secret", "secrets"}:
            return True
    return False


def _safe_validation_target(
    value: str,
    *,
    root: Path | None = None,
    cwd: str | None = None,
) -> bool:
    if not value or value != value.strip() or "\\" in value or value.startswith("@"):
        return False
    if unsafe_path_in_arg(value) or _sensitive_validation_path(value):
        return False
    target = value.split("::", 1)[0]
    if not target:
        return False
    path = Path(target)
    if path.is_absolute() or ".." in path.parts:
        return False
    if root is None:
        return True
    try:
        canonical_root = root.resolve(strict=True)
        relative_cwd = cwd if isinstance(cwd, str) else "."
        if not safe_validation_cwd(relative_cwd, root=canonical_root):
            return False
        base = (canonical_root / relative_cwd).resolve(strict=True)
        cursor = base
        for part in path.parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                return False
        (base / path).resolve(strict=False).relative_to(canonical_root)
        return True
    except (OSError, RuntimeError, ValueError):
        return False


def safe_validation_cwd(value: object, *, root: Path | None = None) -> bool:
    if not isinstance(value, str) or not value or value != value.strip() or "\\" in value:
        return False
    if not is_safe_repo_path(value) or _sensitive_validation_path(value):
        return False
    if root is None:
        return True
    try:
        canonical_root = root.resolve(strict=True)
        lexical = canonical_root / value
        relative_parts = Path(value).parts
        cursor = canonical_root
        for part in relative_parts:
            if part in {"", "."}:
                continue
            cursor = cursor / part
            if cursor.is_symlink():
                return False
        canonical_cwd = lexical.resolve(strict=True)
        canonical_cwd.relative_to(canonical_root)
        return canonical_cwd.is_dir()
    except (OSError, RuntimeError, ValueError):
        return False


def _python_module_shadowed(root: Path | None, cwd: str | None, module: str) -> bool:
    if root is None:
        return False
    try:
        canonical_root = root.resolve(strict=True)
    except OSError:
        return True
    candidates = [canonical_root]
    if isinstance(cwd, str) and safe_validation_cwd(cwd, root=canonical_root):
        try:
            candidates.append((canonical_root / cwd).resolve(strict=True))
        except OSError:
            return True
    for base in candidates:
        module_file = base / f"{module}.py"
        module_dir = base / module
        if module_file.exists() or module_file.is_symlink() or module_dir.exists() or module_dir.is_symlink():
            return True
    return False


def _executable_shadowed(root: Path | None, cwd: str | None, executable: str) -> bool:
    if root is None:
        return False
    try:
        canonical_root = root.resolve(strict=True)
    except OSError:
        return True
    candidates = [canonical_root]
    if isinstance(cwd, str) and safe_validation_cwd(cwd, root=canonical_root):
        try:
            candidates.append((canonical_root / cwd).resolve(strict=True))
        except OSError:
            return True
    for base in candidates:
        for name in (executable, f"{executable}.exe"):
            candidate = base / name
            if candidate.exists() or candidate.is_symlink():
                return True
    return False


def _safe_pytest_args(args: list[str], *, root: Path | None, cwd: str | None) -> bool:
    if "-p" not in args:
        return False
    cache_disabled = False
    index = 0
    no_value_flags = {
        "--collect-only",
        "--continue-on-collection-errors",
        "--disable-warnings",
        "--exitfirst",
        "--fixtures",
        "--no-header",
        "--no-summary",
        "--setup-show",
        "--strict-config",
        "--strict-markers",
        "-s",
        "-x",
    }
    while index < len(args):
        arg = args[index]
        if re.fullmatch(r"-(?:q+|v+)", arg) or arg in no_value_flags:
            index += 1
            continue
        if arg == "-p":
            if index + 1 >= len(args) or args[index + 1] != "no:cacheprovider":
                return False
            cache_disabled = True
            index += 2
            continue
        if arg in {"-k", "-m"}:
            if index + 1 >= len(args) or not args[index + 1]:
                return False
            index += 2
            continue
        if arg.startswith("--maxfail="):
            if not arg.removeprefix("--maxfail=").isdigit():
                return False
            index += 1
            continue
        if arg.startswith("--tb="):
            if arg.removeprefix("--tb=") not in {"auto", "long", "short", "line", "native", "no"}:
                return False
            index += 1
            continue
        if arg.startswith("--color="):
            if arg.removeprefix("--color=") not in {"yes", "no", "auto"}:
                return False
            index += 1
            continue
        if arg.startswith("-"):
            return False
        if not _safe_validation_target(arg, root=root, cwd=cwd):
            return False
        index += 1
    return cache_disabled


def _safe_unittest_args(args: list[str], *, root: Path | None, cwd: str | None) -> bool:
    if not args:
        return True
    index = 1 if args[0] == "discover" else 0
    while index < len(args):
        arg = args[index]
        if arg in {"-b", "--buffer", "-f", "--failfast", "-q", "--quiet", "-v", "--verbose"}:
            index += 1
            continue
        if arg in {"-k", "-s", "--start-directory", "-t", "--top-level-directory"}:
            if index + 1 >= len(args) or not _safe_validation_target(args[index + 1], root=root, cwd=cwd):
                return False
            index += 2
            continue
        if arg in {"-p", "--pattern"}:
            if index + 1 >= len(args):
                return False
            pattern = args[index + 1]
            if not pattern or pattern != pattern.strip() or SHELL_METACHAR_RE.search(pattern) or _sensitive_validation_path(pattern):
                return False
            index += 2
            continue
        if arg.startswith("-") or not _safe_validation_target(arg, root=root, cwd=cwd):
            return False
        index += 1
    return True


def _safe_ruff_args(args: list[str], *, root: Path | None, cwd: str | None) -> bool:
    if not args or args[0] != "check":
        return False
    remainder = args[1:]
    if "--no-fix" not in remainder or "--no-cache" not in remainder:
        return False
    allowed_flags = {
        "--diff",
        "--no-cache",
        "--no-fix",
        "--show-files",
        "--show-settings",
        "--statistics",
        "-q",
        "--quiet",
        "-v",
        "--verbose",
    }
    for arg in remainder:
        if arg in allowed_flags:
            continue
        if arg.startswith("-") or not _safe_validation_target(arg, root=root, cwd=cwd):
            return False
    return True


def glob_patterns_overlap(left: str, right: str) -> bool:
    left = _strip_value(left)
    right = _strip_value(right)
    if left == right:
        return True
    if fnmatch.fnmatch(left, right) or fnmatch.fnmatch(right, left):
        return True
    left_prefix = re.split(r"[*?\[]", left, maxsplit=1)[0].rstrip("/")
    right_prefix = re.split(r"[*?\[]", right, maxsplit=1)[0].rstrip("/")
    if left_prefix and right.startswith(left_prefix + "/"):
        return True
    if right_prefix and left.startswith(right_prefix + "/"):
        return True
    return False


def parse_legacy_command(command: str) -> list[str] | None:
    command = command.strip().strip("`")
    if len(command.split()) < 2:
        return None
    if SHELL_METACHAR_RE.search(command):
        return None
    try:
        return shlex.split(command)
    except ValueError:
        return None


def safe_validation_argv(
    argv: object,
    *,
    root: Path | None = None,
    cwd: str | None = None,
) -> bool:
    if not isinstance(argv, list) or len(argv) < 2:
        return False
    normalized: list[str] = []
    for item in argv:
        if not isinstance(item, str):
            return False
        if not item or item != item.strip() or SHELL_METACHAR_RE.search(item):
            return False
        if item.startswith("@") or has_secret_like(item):
            return False
        if unsafe_path_in_arg(item) or _sensitive_validation_path(item):
            return False
        normalized.append(item)

    executable = normalized[0]
    if "/" in executable or "\\" in executable or Path(executable).name != executable:
        return False
    if executable in MUTATING_EXECUTABLES:
        return False

    if executable == "python3":
        if _executable_shadowed(root, cwd, executable):
            return False
        index = 1
        if index >= len(normalized) or normalized[index] != "-B":
            return False
        index += 1
        if index + 1 >= len(normalized) or normalized[index] != "-m":
            return False
        module = normalized[index + 1]
        startup_modules = ("sitecustomize", "usercustomize")
        if module not in SAFE_PYTHON_MODULES or any(
            _python_module_shadowed(root, cwd, candidate) for candidate in (module, *startup_modules)
        ):
            return False
        args = normalized[index + 2 :]
        if module == "pytest":
            return _safe_pytest_args(args, root=root, cwd=cwd)
        return _safe_unittest_args(args, root=root, cwd=cwd)
    if executable == "ruff":
        if _executable_shadowed(root, cwd, executable):
            return False
        return _safe_ruff_args(normalized[1:], root=root, cwd=cwd)
    return False


def exact_validation_command(command: str) -> bool:
    argv = parse_legacy_command(command)
    return bool(argv and safe_validation_argv(argv))


def safe_validation_command_item(
    item: object,
    *,
    root: Path | None = None,
    allow_legacy: bool = False,
    evidence: bool = False,
) -> bool:
    if not isinstance(item, dict):
        return False
    argv = item.get("argv")
    if argv is not None:
        keys = set(item)
        allowed_fields = VALIDATION_EVIDENCE_FIELDS if evidence else VALIDATION_COMMAND_REQUIRED_FIELDS
        if keys - allowed_fields or not VALIDATION_COMMAND_REQUIRED_FIELDS.issubset(keys):
            return False
        if not evidence and keys != VALIDATION_COMMAND_REQUIRED_FIELDS:
            return False
        command_id = item.get("id")
        expected_exit = item.get("expected_exit_code")
        timeout = item.get("timeout_seconds")
        probe_tier = item.get("probe_tier")
        cwd = item.get("cwd")
        if not isinstance(command_id, str) or VALIDATION_ID_RE.fullmatch(command_id) is None:
            return False
        if not _is_int(expected_exit) or expected_exit != 0:
            return False
        if not _is_int(timeout) or not 1 <= int(timeout) <= 3600:
            return False
        if item.get("network") != "deny":
            return False
        if not _is_int(probe_tier) or probe_tier != 1:
            return False
        if not safe_validation_cwd(cwd, root=root):
            return False
        if evidence:
            if item.get("exit_code") != 0 or isinstance(item.get("exit_code"), bool):
                return False
            present_hashes = keys & VALIDATION_EVIDENCE_HASH_FIELDS
            if not present_hashes:
                return False
            if any(not isinstance(item.get(field), str) or SHA256_RE.fullmatch(str(item[field])) is None for field in present_hashes):
                return False
        return safe_validation_argv(argv, root=root, cwd=str(cwd))
    command = item.get("command")
    if evidence or not allow_legacy or set(item) != LEGACY_VALIDATION_COMMAND_FIELDS:
        return False
    command_id = item.get("id")
    expected_result = item.get("expected_result")
    return (
        isinstance(command_id, str)
        and VALIDATION_ID_RE.fullmatch(command_id) is not None
        and isinstance(command, str)
        and exact_validation_command(command)
        and isinstance(expected_result, str)
        and bool(expected_result.strip())
    )
