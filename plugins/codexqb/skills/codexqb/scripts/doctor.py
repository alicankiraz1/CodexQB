#!/usr/bin/env python3
"""Dependency-free, path-safe CodexQB capability diagnostics.

The doctor intentionally reports capability *classes*, never mount identities or
provider diagnostics.  Those values can contain host-specific filesystem data
and are not part of the public diagnostic contract.
"""

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
        "reason=requires_python_-I_-S_-B_first_process\n"
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

if __name__ == "__main__" and not _launcher_admission_is_valid("doctor.py"):
    sys.stderr.write(
        "codexqb_controller=unsupported reason=launcher_admission_required\n"
    )
    raise SystemExit(2)


import importlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence, TextIO


REPORT_SCHEMA = "codexqb.doctor.capability-report"
REPORT_VERSION = 1
EXTERNAL_MOUNT_ERROR = "secure_repository_mount_identity_unavailable"
SAFE_FAILURE_CODE_RE = re.compile(r"[a-z][a-z0-9_]{0,127}")

ASSURANCE_UNAVAILABLE = "unavailable"
ASSURANCE_FILESYSTEM_ONLY = "filesystem_identity_only"
ASSURANCE_MOUNT_UNIQUE = "mount_unique_descriptor_bound"
ASSURANCE_RECONCILED = "mount_reconciled"
HIGH_ASSURANCE = frozenset((ASSURANCE_MOUNT_UNIQUE, ASSURANCE_RECONCILED))
KNOWN_ASSURANCE = frozenset(
    (
        ASSURANCE_UNAVAILABLE,
        ASSURANCE_FILESYSTEM_ONLY,
        ASSURANCE_MOUNT_UNIQUE,
        ASSURANCE_RECONCILED,
    )
)

OPERATIONS = (
    "read_only_evidence",
    "non_destructive_artifact_package_creation",
    "apply_run_mutation",
    "run_replace_quarantine_delete",
)

# Provider names are part of the diagnostic schema.  Unknown names are not
# echoed: a future provider must be deliberately added to this public surface.
KNOWN_PROVIDERS = frozenset(
    (
        "linux_fdinfo",
        "linux_fdinfo_mnt_id",
        "linux_statx",
        "linux_statx_mnt_id",
        "linux_name_to_handle_at",
        "darwin_fstatfs",
        "posix_fstat",
        "filesystem_fstat",
        "mount_identity_module",
        "mount_identity_resolver",
    )
)
HIGH_ASSURANCE_PROVIDERS = frozenset(
    (
        "linux_fdinfo",
        "linux_fdinfo_mnt_id",
        "linux_statx",
        "linux_statx_mnt_id",
        "linux_name_to_handle_at",
        "darwin_fstatfs",
    )
)

# Only failures that prove absence of a platform capability are expected.  A
# malformed response, permission change, backend bug, or provider disagreement
# is an operational failure even though MountProviderResult.supported is false.
EXPECTED_UNSUPPORTED_FAILURE_CODES = frozenset(
    (
        "mount_provider_platform_unsupported",
        "mount_provider_statx_symbol_unavailable",
        "mount_provider_statx_syscall_unavailable",
        "mount_provider_statx_request_unsupported",
        "mount_provider_statx_mnt_id_missing",
        "mount_provider_name_to_handle_symbol_unavailable",
        "mount_provider_name_to_handle_syscall_unavailable",
        "mount_provider_name_to_handle_request_unsupported",
        "mount_provider_name_to_handle_filesystem_unsupported",
        "mount_provider_fstatfs_symbol_unavailable",
        "mount_provider_fdinfo_mnt_id_missing",
    )
)
EXPECTED_FDINFO_ERRNOS = frozenset(("errno=enoent", "errno=enotdir", "errno=enosys"))

READY_REMEDIATION = "No action required."
UNSUPPORTED_REMEDIATION = (
    "Use a supported Linux or macOS host, or enable a descriptor-bound "
    "mount-identity provider."
)
FAILED_REMEDIATION = (
    "Restore the advertised mount-identity capability, then rerun CodexQB doctor."
)


@dataclass(frozen=True)
class _ProviderResult:
    provider: str
    supported: bool
    identity: object | None
    assurance: str
    failure_code: str | None = None
    diagnostics: object | None = None


@dataclass(frozen=True)
class _MountResolution:
    selected_provider: str | None
    identity: object | None
    assurance: str
    providers: tuple[_ProviderResult, ...]
    failure_code: str | None = None


def _enum_value(value: object) -> object:
    return getattr(value, "value", value)


def _normalise_assurance(value: object) -> str:
    candidate = _enum_value(value)
    if isinstance(candidate, str) and candidate in KNOWN_ASSURANCE:
        return candidate
    return ASSURANCE_UNAVAILABLE


def _normalise_provider(value: object) -> str:
    candidate = _enum_value(value)
    if isinstance(candidate, str) and candidate in KNOWN_PROVIDERS:
        return candidate
    return "unknown_provider"


def _normalise_selected_provider(value: object) -> str | None:
    if value is None:
        return None
    return _normalise_provider(value)


def _normalise_os_family(value: str) -> str:
    lowered = value.lower()
    if lowered.startswith("linux"):
        return "linux"
    if lowered == "darwin":
        return "darwin"
    if lowered.startswith(("win", "cygwin", "msys")):
        return "windows"
    return "other"


def _is_expected_unsupported_failure(result: object) -> bool:
    failure_code = getattr(result, "failure_code", None)
    if failure_code in EXPECTED_UNSUPPORTED_FAILURE_CODES:
        return True
    if failure_code != "mount_provider_fdinfo_unavailable":
        return False
    diagnostics = getattr(result, "diagnostics", ())
    if isinstance(diagnostics, (str, bytes, bytearray)):
        return False
    try:
        return any(value in EXPECTED_FDINFO_ERRNOS for value in diagnostics)
    except TypeError:
        return False


def _public_failure_code(result: object, fallback: str) -> str:
    """Expose only stable code-shaped diagnostics, never exception text."""

    candidate = _enum_value(getattr(result, "failure_code", None))
    if (
        isinstance(candidate, str)
        and SAFE_FAILURE_CODE_RE.fullmatch(candidate) is not None
        and candidate.startswith(("mount_provider_", "mount_identity_"))
    ):
        return candidate
    return fallback


def _public_resolution_failure_code(resolution: object) -> str | None:
    candidate = _enum_value(getattr(resolution, "failure_code", None))
    if candidate == EXTERNAL_MOUNT_ERROR:
        return EXTERNAL_MOUNT_ERROR
    if (
        isinstance(candidate, str)
        and SAFE_FAILURE_CODE_RE.fullmatch(candidate) is not None
        and candidate.startswith("mount_identity_")
    ):
        return candidate
    return None


def _provider_public_result(result: object) -> dict[str, object]:
    raw_provider = _enum_value(getattr(result, "provider", None))
    provider = _normalise_provider(raw_provider)
    supported = getattr(result, "supported", False) is True
    assurance = _normalise_assurance(getattr(result, "assurance", None))
    identity_available = getattr(result, "identity", None) is not None

    if supported and identity_available and assurance in HIGH_ASSURANCE:
        status = "available"
        failure_code = None
    elif identity_available and assurance == ASSURANCE_FILESYSTEM_ONLY:
        status = "diagnostic_only"
        failure_code = "insufficient_mount_assurance"
    elif supported or raw_provider not in KNOWN_PROVIDERS:
        status = "probe_failed"
        failure_code = _public_failure_code(result, "provider_probe_failed")
    elif _is_expected_unsupported_failure(result):
        status = "expected_unsupported"
        failure_code = _public_failure_code(result, "provider_unsupported")
    else:
        status = "probe_failed"
        failure_code = _public_failure_code(result, "provider_probe_failed")

    # Do not add identity or diagnostics here.  Both are deliberately private.
    return {
        "provider": provider,
        "supported": supported,
        "status": status,
        "assurance": assurance,
        "failure_code": failure_code,
    }


def _python_major_minor(version: object) -> tuple[int, int]:
    try:
        major = int(getattr(version, "major"))
        minor = int(getattr(version, "minor"))
    except (AttributeError, TypeError, ValueError):
        try:
            major = int(version[0])  # type: ignore[index]
            minor = int(version[1])  # type: ignore[index]
        except (IndexError, KeyError, TypeError, ValueError) as exc:
            raise ValueError("invalid_python_version") from exc
    return major, minor


def build_report(
    resolution: object,
    *,
    platform_name: str | None = None,
    python_version: object | None = None,
    probe_error_code: str | None = None,
) -> dict[str, object]:
    """Build the public report without serializing host-specific probe data."""

    if platform_name is None:
        platform_name = sys.platform
    if python_version is None:
        python_version = sys.version_info
    major, minor = _python_major_minor(python_version)

    raw_providers = getattr(resolution, "providers", ())
    try:
        provider_results = [_provider_public_result(item) for item in raw_providers]
    except TypeError:
        provider_results = []

    assurance = _normalise_assurance(getattr(resolution, "assurance", None))
    selected_identity_available = getattr(resolution, "identity", None) is not None
    ready = (
        assurance in HIGH_ASSURANCE
        and selected_identity_available
        and any(item["status"] == "available" for item in provider_results)
    )

    provider_failure = any(item["status"] == "probe_failed" for item in provider_results)
    resolution_failure_code = getattr(resolution, "failure_code", None)
    unexpected_resolution_failure = resolution_failure_code not in (
        None,
        EXTERNAL_MOUNT_ERROR,
    )
    if probe_error_code is not None or provider_failure or unexpected_resolution_failure:
        status = "probe_failed"
    elif ready:
        status = "ready"
    else:
        status = "expected_unsupported"

    supported_operations = list(OPERATIONS) if status == "ready" else []
    blocked_operations = [] if status == "ready" else list(OPERATIONS)
    if status == "ready":
        remediation = READY_REMEDIATION
        error_code = None
    elif status == "expected_unsupported":
        remediation = UNSUPPORTED_REMEDIATION
        error_code = EXTERNAL_MOUNT_ERROR
    else:
        remediation = FAILED_REMEDIATION
        error_code = EXTERNAL_MOUNT_ERROR

    return {
        "schema": REPORT_SCHEMA,
        "version": REPORT_VERSION,
        "status": status,
        "runtime": {
            "os_family": _normalise_os_family(platform_name),
            "python": {"major": major, "minor": minor},
        },
        "mount_identity": {
            "providers": provider_results,
            "selected_provider": _normalise_selected_provider(
                getattr(resolution, "selected_provider", None)
            ),
            "selected_assurance": assurance,
            "failure_code": _public_resolution_failure_code(resolution),
        },
        "operations": {
            "supported": supported_operations,
            "blocked": blocked_operations,
        },
        "error_code": error_code,
        "remediation": remediation,
    }


def _load_mount_identity_module() -> Any:
    script_directory = Path(__file__).resolve().parent
    script_directory_text = os.fspath(script_directory)
    if script_directory_text not in sys.path:
        sys.path.insert(0, script_directory_text)
    return importlib.import_module("mount_identity")


def _error_resolution(provider: str, *, supported: bool) -> _MountResolution:
    result = _ProviderResult(
        provider=provider,
        supported=supported,
        identity=None,
        assurance=ASSURANCE_UNAVAILABLE,
        failure_code="provider_probe_failed" if supported else "provider_unsupported",
    )
    return _MountResolution(
        selected_provider=None,
        identity=None,
        assurance=ASSURANCE_UNAVAILABLE,
        providers=(result,),
        failure_code=EXTERNAL_MOUNT_ERROR,
    )


def build_live_report(
    *,
    mount_identity_module: object | None = None,
    platform_name: str | None = None,
    python_version: object | None = None,
) -> dict[str, object]:
    """Probe the current descriptor and return a traceback-free report."""

    if mount_identity_module is None:
        try:
            mount_identity_module = _load_mount_identity_module()
        except Exception:
            return build_report(
                _error_resolution("mount_identity_module", supported=False),
                platform_name=platform_name,
                python_version=python_version,
                probe_error_code="mount_identity_module_unavailable",
            )

    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        root_fd = os.open(".", flags)
    except (OSError, ValueError):
        return build_report(
            _error_resolution("mount_identity_resolver", supported=True),
            platform_name=platform_name,
            python_version=python_version,
            probe_error_code="descriptor_open_failed",
        )

    try:
        resolver = getattr(mount_identity_module, "resolve_mount_identity")
        resolution = resolver(root_fd, reconcile=True)
    except Exception:
        return build_report(
            _error_resolution("mount_identity_resolver", supported=True),
            platform_name=platform_name,
            python_version=python_version,
            probe_error_code="mount_identity_probe_failed",
        )
    finally:
        os.close(root_fd)

    return build_report(
        resolution,
        platform_name=platform_name,
        python_version=python_version,
    )


def render_json(report: dict[str, object]) -> str:
    return json.dumps(report, indent=2, sort_keys=True, ensure_ascii=True)


def _join_operations(values: Iterable[object]) -> str:
    rendered = [value for value in values if isinstance(value, str)]
    return ", ".join(rendered) if rendered else "none"


def render_human(report: dict[str, object]) -> str:
    runtime = report["runtime"]
    mount_identity = report["mount_identity"]
    operations = report["operations"]
    assert isinstance(runtime, dict)
    assert isinstance(mount_identity, dict)
    assert isinstance(operations, dict)
    python = runtime["python"]
    assert isinstance(python, dict)
    providers = mount_identity["providers"]
    assert isinstance(providers, list)

    lines = [
        "CodexQB doctor",
        f"Schema: {report['schema']} v{report['version']}",
        f"Status: {report['status']}",
        (
            "Runtime: "
            f"{runtime['os_family']}, Python {python['major']}.{python['minor']}"
        ),
        "Mount identity providers:",
    ]
    if providers:
        for provider in providers:
            assert isinstance(provider, dict)
            lines.append(
                "  - "
                f"{provider['provider']}: {provider['status']} "
                f"(supported={str(provider['supported']).lower()}, "
                f"assurance={provider['assurance']}, "
                f"failure_code={provider['failure_code'] or 'none'})"
            )
    else:
        lines.append("  - none")
    lines.extend(
        (
            f"Selected provider: {mount_identity['selected_provider'] or 'none'}",
            f"Selected assurance: {mount_identity['selected_assurance']}",
            f"Resolution failure code: {mount_identity['failure_code'] or 'none'}",
            f"Supported operations: {_join_operations(operations['supported'])}",
            f"Blocked operations: {_join_operations(operations['blocked'])}",
            f"Error code: {report['error_code'] or 'none'}",
            f"Remediation: {report['remediation']}",
        )
    )
    return "\n".join(lines)


def _usage() -> str:
    return "Usage: codexqb-doctor [--json]\n"


def main(
    argv: Sequence[str] | None = None,
    *,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if stdout is None:
        stdout = sys.stdout
    if stderr is None:
        stderr = sys.stderr

    arguments = list(argv)
    if arguments in (["-h"], ["--help"]):
        stdout.write(_usage())
        return 0
    if arguments not in ([], ["--json"]):
        # Do not echo an unknown argument: it may itself contain a secret/path.
        stderr.write("codexqb-doctor: error: unsupported_argument\n")
        return 2

    report = build_live_report()
    output = render_json(report) if arguments == ["--json"] else render_human(report)
    stdout.write(output + "\n")
    return 1 if report["status"] == "probe_failed" else 0


if __name__ == "__main__":
    raise SystemExit(main())
