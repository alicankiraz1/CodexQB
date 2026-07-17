#!/usr/bin/env python3
"""Descriptor-bound mount capability providers for CodexQB.

The public reports produced here intentionally omit raw mount identities.  In
particular, Darwin ``fstatfs`` identities can contain mount source and mount
point names.  Callers may compare the opaque identities in memory, but must
use :func:`safe_resolution_report` for diagnostics intended for users.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import ctypes
from dataclasses import dataclass
from enum import Enum
import errno
import os
import re
import sys
from types import MappingProxyType
from typing import Protocol


AT_EMPTY_PATH = 0x1000
STATX_MNT_ID = 0x00001000
MAX_FDINFO_BYTES = 64 * 1024
SECURE_MOUNT_IDENTITY_UNAVAILABLE = "secure_repository_mount_identity_unavailable"

LINUX_FDINFO_PROVIDER = "linux_fdinfo_mnt_id"
LINUX_STATX_PROVIDER = "linux_statx"
LINUX_NAME_TO_HANDLE_PROVIDER = "linux_name_to_handle_at"
DARWIN_FSTATFS_PROVIDER = "darwin_fstatfs"
FILESYSTEM_FSTAT_PROVIDER = "filesystem_fstat"
DARWIN_MNT_LOCAL = 0x00001000

READ_ONLY_EVIDENCE = "read_only_evidence"
NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION = "non_destructive_artifact_package_creation"
# Transitional constant name for callers developed against the checkpoint draft.
NON_DESTRUCTIVE_ARTIFACT_CREATION = NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION
APPLY_RUN_MUTATION = "apply_run_mutation"
RUN_REPLACE_QUARANTINE_DELETE = "run_replace_quarantine_delete"

_SAFE_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,127}")
_SAFE_DIAGNOSTIC_RE = re.compile(r"[a-z0-9][a-z0-9_.=-]{0,127}")


class MountAssurance(str, Enum):
    """Strength of one descriptor-bound filesystem/mount observation."""

    UNAVAILABLE = "unavailable"
    FILESYSTEM_IDENTITY_ONLY = "filesystem_identity_only"
    MOUNT_UNIQUE_DESCRIPTOR_BOUND = "mount_unique_descriptor_bound"
    MOUNT_RECONCILED = "mount_reconciled"


ASSURANCE_RANK = MappingProxyType(
    {
        MountAssurance.UNAVAILABLE: 0,
        MountAssurance.FILESYSTEM_IDENTITY_ONLY: 1,
        MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND: 2,
        MountAssurance.MOUNT_RECONCILED: 3,
    }
)

OPERATION_MINIMUM_ASSURANCE = MappingProxyType(
    {
        READ_ONLY_EVIDENCE: MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
        NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION: MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
        APPLY_RUN_MUTATION: MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
        RUN_REPLACE_QUARANTINE_DELETE: MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
    }
)


def _valid_fd(fd: object) -> bool:
    return isinstance(fd, int) and not isinstance(fd, bool) and fd >= 0


def _require_safe_name(value: str, label: str) -> None:
    if _SAFE_NAME_RE.fullmatch(value) is None:
        raise ValueError(f"invalid_{label}")


def _safe_diagnostics(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes, bytearray)):
        raise TypeError("mount_diagnostics_must_be_sequence")
    result = tuple(values)
    if any(
        not isinstance(value, str) or _SAFE_DIAGNOSTIC_RE.fullmatch(value) is None
        for value in result
    ):
        raise ValueError("unsafe_mount_diagnostic")
    return result


@dataclass(frozen=True)
class MountIdentity:
    """Opaque, in-memory-only identity in a provider-independent namespace."""

    namespace: str
    parts: tuple[object, ...]

    def __post_init__(self) -> None:
        _require_safe_name(self.namespace, "mount_identity_namespace")
        if not isinstance(self.parts, tuple) or not self.parts:
            raise ValueError("invalid_mount_identity_parts")


@dataclass(frozen=True)
class MountProviderResult:
    provider: str
    supported: bool
    identity: MountIdentity | None
    assurance: MountAssurance
    failure_code: str | None
    diagnostics: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_safe_name(self.provider, "mount_provider_name")
        if not isinstance(self.supported, bool):
            raise TypeError("mount_provider_supported_must_be_bool")
        if not isinstance(self.assurance, MountAssurance):
            raise TypeError("mount_provider_assurance_invalid")
        object.__setattr__(self, "diagnostics", _safe_diagnostics(self.diagnostics))
        if self.failure_code is not None:
            _require_safe_name(self.failure_code, "mount_failure_code")
        if self.identity is not None:
            if (
                not self.supported
                or self.assurance is MountAssurance.UNAVAILABLE
                or self.failure_code is not None
            ):
                raise ValueError("invalid_available_mount_provider_result")
        elif self.assurance is not MountAssurance.UNAVAILABLE or self.failure_code is None:
            raise ValueError("invalid_failed_mount_provider_result")


@dataclass(frozen=True)
class MountResolution:
    selected_provider: str | None
    identity: MountIdentity | None
    assurance: MountAssurance
    providers: tuple[MountProviderResult, ...]
    failure_code: str | None

    def __post_init__(self) -> None:
        if self.selected_provider is not None:
            _require_safe_name(self.selected_provider, "selected_mount_provider")
        if not isinstance(self.assurance, MountAssurance):
            raise TypeError("mount_resolution_assurance_invalid")
        if not isinstance(self.providers, tuple) or any(
            not isinstance(item, MountProviderResult) for item in self.providers
        ):
            raise TypeError("mount_resolution_providers_invalid")
        if self.failure_code is not None:
            _require_safe_name(self.failure_code, "mount_failure_code")
        if self.identity is None:
            if self.selected_provider is not None or self.assurance is not MountAssurance.UNAVAILABLE:
                raise ValueError("invalid_unavailable_mount_resolution")
        elif self.selected_provider is None or self.assurance is MountAssurance.UNAVAILABLE:
            raise ValueError("invalid_available_mount_resolution")


class MountProvider(Protocol):
    def __call__(self, fd: int) -> MountProviderResult: ...


class MountIdentityError(ValueError):
    """Stable external error with structured, non-stringified diagnostics."""

    def __init__(self, code: str, resolution: MountResolution):
        _require_safe_name(code, "mount_failure_code")
        super().__init__(code)
        self.code = code
        self.resolution = resolution


def _failure(
    provider: str,
    failure_code: str,
    *diagnostics: str,
    supported: bool = False,
) -> MountProviderResult:
    return MountProviderResult(
        provider=provider,
        supported=supported,
        identity=None,
        assurance=MountAssurance.UNAVAILABLE,
        failure_code=failure_code,
        diagnostics=tuple(diagnostics),
    )


def _success(
    provider: str,
    identity: MountIdentity,
    assurance: MountAssurance = MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
) -> MountProviderResult:
    return MountProviderResult(
        provider=provider,
        supported=True,
        identity=identity,
        assurance=assurance,
        failure_code=None,
        diagnostics=(),
    )


def _errno_token(number: int | None) -> str:
    name = errno.errorcode.get(number or 0, "unknown").lower()
    return f"errno={name}"


def _platform_name(value: str | None) -> str:
    return sys.platform if value is None else value


def _read_fdinfo(fd: int) -> bytes:
    with open(f"/proc/self/fdinfo/{fd}", "rb", buffering=0) as handle:
        return handle.read(MAX_FDINFO_BYTES + 1)


def probe_linux_fdinfo(
    fd: int,
    *,
    reader: Callable[[int], bytes] | None = None,
    platform: str | None = None,
) -> MountProviderResult:
    provider = LINUX_FDINFO_PROVIDER
    if not _valid_fd(fd):
        return _failure(provider, "mount_provider_invalid_descriptor", supported=True)
    if not _platform_name(platform).startswith("linux"):
        return _failure(provider, "mount_provider_platform_unsupported")
    try:
        payload = (reader or _read_fdinfo)(fd)
    except OSError as exc:
        unavailable = exc.errno in {errno.ENOENT, errno.ENOTDIR, errno.ENOSYS}
        return _failure(
            provider,
            "mount_provider_fdinfo_unavailable",
            _errno_token(exc.errno),
            supported=not unavailable,
        )
    except Exception:
        return _failure(
            provider,
            "mount_provider_backend_failed",
            "reason=reader_exception",
            supported=True,
        )
    if not isinstance(payload, bytes):
        return _failure(
            provider,
            "mount_provider_response_invalid",
            "reason=non_bytes",
            supported=True,
        )
    if len(payload) > MAX_FDINFO_BYTES:
        return _failure(provider, "mount_provider_fdinfo_oversized", supported=True)
    values: list[bytes] = []
    for line in payload.splitlines():
        if line.startswith(b"mnt_id:"):
            values.append(line.partition(b":")[2].strip())
    if not values:
        return _failure(provider, "mount_provider_fdinfo_mnt_id_missing", supported=True)
    if len(values) != 1:
        return _failure(provider, "mount_provider_fdinfo_mnt_id_duplicate", supported=True)
    raw = values[0]
    if not raw or not raw.isdigit():
        return _failure(provider, "mount_provider_fdinfo_mnt_id_malformed", supported=True)
    mount_id = int(raw)
    if mount_id <= 0:
        return _failure(provider, "mount_provider_fdinfo_mnt_id_malformed", supported=True)
    return _success(provider, MountIdentity("linux_mount_id", (mount_id,)))


class _LinuxStatxTimestamp(ctypes.Structure):
    _fields_ = [
        ("tv_sec", ctypes.c_int64),
        ("tv_nsec", ctypes.c_uint32),
        ("reserved", ctypes.c_int32),
    ]


class _LinuxStatx(ctypes.Structure):
    # The mount ID offset is stable in the Linux UAPI.  The tail remains
    # opaque so this definition stays 256 bytes across older/newer headers.
    _fields_ = [
        ("stx_mask", ctypes.c_uint32),
        ("stx_blksize", ctypes.c_uint32),
        ("stx_attributes", ctypes.c_uint64),
        ("stx_nlink", ctypes.c_uint32),
        ("stx_uid", ctypes.c_uint32),
        ("stx_gid", ctypes.c_uint32),
        ("stx_mode", ctypes.c_uint16),
        ("spare0", ctypes.c_uint16),
        ("stx_ino", ctypes.c_uint64),
        ("stx_size", ctypes.c_uint64),
        ("stx_blocks", ctypes.c_uint64),
        ("stx_attributes_mask", ctypes.c_uint64),
        ("stx_atime", _LinuxStatxTimestamp),
        ("stx_btime", _LinuxStatxTimestamp),
        ("stx_ctime", _LinuxStatxTimestamp),
        ("stx_mtime", _LinuxStatxTimestamp),
        ("stx_rdev_major", ctypes.c_uint32),
        ("stx_rdev_minor", ctypes.c_uint32),
        ("stx_dev_major", ctypes.c_uint32),
        ("stx_dev_minor", ctypes.c_uint32),
        ("stx_mnt_id", ctypes.c_uint64),
        ("reserved_tail", ctypes.c_ubyte * 104),
    ]


StatxBackend = Callable[[int, bytes, int, int, _LinuxStatx], int]


def _load_statx_backend() -> StatxBackend | None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.statx
    except (AttributeError, OSError):
        return None
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_uint,
        ctypes.POINTER(_LinuxStatx),
    ]
    function.restype = ctypes.c_int

    def call(fd: int, path: bytes, flags: int, mask: int, payload: _LinuxStatx) -> int:
        return int(function(fd, path, flags, mask, ctypes.byref(payload)))

    return call


def probe_linux_statx(
    fd: int,
    *,
    backend: StatxBackend | None = None,
    platform: str | None = None,
) -> MountProviderResult:
    provider = LINUX_STATX_PROVIDER
    if not _valid_fd(fd):
        return _failure(provider, "mount_provider_invalid_descriptor", supported=True)
    if not _platform_name(platform).startswith("linux"):
        return _failure(provider, "mount_provider_platform_unsupported")
    selected = backend or _load_statx_backend()
    if selected is None:
        return _failure(provider, "mount_provider_statx_symbol_unavailable")
    payload = _LinuxStatx()
    try:
        ctypes.set_errno(0)
        result = selected(fd, b"", AT_EMPTY_PATH, STATX_MNT_ID, payload)
        error_number = ctypes.get_errno()
    except OSError as exc:
        result = -1
        error_number = exc.errno or 0
    except Exception:
        return _failure(
            provider,
            "mount_provider_backend_failed",
            "reason=statx_exception",
            supported=True,
        )
    if not isinstance(result, int) or isinstance(result, bool):
        return _failure(
            provider,
            "mount_provider_response_invalid",
            "reason=non_integer_status",
            supported=True,
        )
    if result != 0:
        if error_number == errno.ENOSYS:
            code = "mount_provider_statx_syscall_unavailable"
        elif error_number == errno.EINVAL:
            code = "mount_provider_statx_request_unsupported"
        elif error_number in {errno.EACCES, errno.EPERM}:
            code = "mount_provider_statx_permission_denied"
        elif error_number == errno.EBADF:
            code = "mount_provider_invalid_descriptor"
        else:
            code = "mount_provider_statx_call_failed"
        unsupported = error_number in {errno.ENOSYS, errno.EINVAL}
        return _failure(
            provider,
            code,
            _errno_token(error_number),
            supported=not unsupported,
        )
    if payload.stx_mask & STATX_MNT_ID == 0:
        return _failure(provider, "mount_provider_statx_mnt_id_missing", supported=True)
    mount_id = int(payload.stx_mnt_id)
    if mount_id <= 0:
        return _failure(provider, "mount_provider_statx_mnt_id_malformed", supported=True)
    return _success(provider, MountIdentity("linux_mount_id", (mount_id,)))


class _LinuxFileHandleHeader(ctypes.Structure):
    _fields_ = [
        ("handle_bytes", ctypes.c_uint),
        ("handle_type", ctypes.c_int),
    ]


NameToHandleBackend = Callable[
    [int, bytes, _LinuxFileHandleHeader, ctypes.c_int, int],
    int,
]


def _load_name_to_handle_backend() -> NameToHandleBackend | None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.name_to_handle_at
    except (AttributeError, OSError):
        return None
    function.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.POINTER(_LinuxFileHandleHeader),
        ctypes.POINTER(ctypes.c_int),
        ctypes.c_int,
    ]
    function.restype = ctypes.c_int

    def call(
        fd: int,
        path: bytes,
        handle: _LinuxFileHandleHeader,
        mount_id: ctypes.c_int,
        flags: int,
    ) -> int:
        return int(function(fd, path, ctypes.byref(handle), ctypes.byref(mount_id), flags))

    return call


def probe_linux_name_to_handle_at(
    fd: int,
    *,
    backend: NameToHandleBackend | None = None,
    platform: str | None = None,
) -> MountProviderResult:
    provider = LINUX_NAME_TO_HANDLE_PROVIDER
    if not _valid_fd(fd):
        return _failure(provider, "mount_provider_invalid_descriptor", supported=True)
    if not _platform_name(platform).startswith("linux"):
        return _failure(provider, "mount_provider_platform_unsupported")
    selected = backend or _load_name_to_handle_backend()
    if selected is None:
        return _failure(provider, "mount_provider_name_to_handle_symbol_unavailable")
    handle = _LinuxFileHandleHeader()
    handle.handle_bytes = 0
    mount_id = ctypes.c_int(-1)
    try:
        ctypes.set_errno(0)
        result = selected(fd, b"", handle, mount_id, AT_EMPTY_PATH)
        error_number = ctypes.get_errno()
    except OSError as exc:
        result = -1
        error_number = exc.errno or 0
    except Exception:
        return _failure(
            provider,
            "mount_provider_backend_failed",
            "reason=name_to_handle_exception",
            supported=True,
        )
    if not isinstance(result, int) or isinstance(result, bool):
        return _failure(
            provider,
            "mount_provider_response_invalid",
            "reason=non_integer_status",
            supported=True,
        )
    usable = result == 0 or (result == -1 and error_number == errno.EOVERFLOW)
    if usable:
        value = int(mount_id.value)
        if value <= 0:
            return _failure(
                provider,
                "mount_provider_name_to_handle_mnt_id_malformed",
                supported=True,
            )
        return _success(provider, MountIdentity("linux_mount_id", (value,)))
    unsupported = {getattr(errno, "ENOTSUP", errno.EOPNOTSUPP), errno.EOPNOTSUPP}
    if error_number in unsupported:
        code = "mount_provider_name_to_handle_filesystem_unsupported"
    elif error_number in {errno.EACCES, errno.EPERM}:
        code = "mount_provider_name_to_handle_permission_denied"
    elif error_number in {errno.EINVAL, errno.ENOENT}:
        code = "mount_provider_name_to_handle_request_unsupported"
    elif error_number == errno.ENOSYS:
        code = "mount_provider_name_to_handle_syscall_unavailable"
    elif error_number == errno.EBADF:
        code = "mount_provider_invalid_descriptor"
    else:
        code = "mount_provider_name_to_handle_call_failed"
    is_unsupported = error_number in unsupported | {errno.EINVAL, errno.ENOENT, errno.ENOSYS}
    return _failure(
        provider,
        code,
        _errno_token(error_number),
        supported=not is_unsupported,
    )


class _DarwinFsid(ctypes.Structure):
    _fields_ = [("value", ctypes.c_int32 * 2)]


class _DarwinStatfs(ctypes.Structure):
    _fields_ = [
        ("f_bsize", ctypes.c_uint32),
        ("f_iosize", ctypes.c_int32),
        ("f_blocks", ctypes.c_uint64),
        ("f_bfree", ctypes.c_uint64),
        ("f_bavail", ctypes.c_uint64),
        ("f_files", ctypes.c_uint64),
        ("f_ffree", ctypes.c_uint64),
        ("f_fsid", _DarwinFsid),
        ("f_owner", ctypes.c_uint32),
        ("f_type", ctypes.c_uint32),
        ("f_flags", ctypes.c_uint32),
        ("f_fssubtype", ctypes.c_uint32),
        ("f_fstypename", ctypes.c_char * 16),
        ("f_mntonname", ctypes.c_char * 1024),
        ("f_mntfromname", ctypes.c_char * 1024),
        ("f_flags_ext", ctypes.c_uint32),
        ("f_reserved", ctypes.c_uint32 * 7),
    ]


DarwinFstatfsBackend = Callable[[int, _DarwinStatfs], int]


def _load_darwin_fstatfs_backend() -> DarwinFstatfsBackend | None:
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        function = libc.fstatfs
    except (AttributeError, OSError):
        return None
    function.argtypes = [ctypes.c_int, ctypes.POINTER(_DarwinStatfs)]
    function.restype = ctypes.c_int

    def call(fd: int, payload: _DarwinStatfs) -> int:
        return int(function(fd, ctypes.byref(payload)))

    return call


def _nul_terminated(value: object) -> bytes:
    return bytes(value).split(b"\0", 1)[0]


def probe_darwin_fstatfs(
    fd: int,
    *,
    backend: DarwinFstatfsBackend | None = None,
    platform: str | None = None,
) -> MountProviderResult:
    provider = DARWIN_FSTATFS_PROVIDER
    if not _valid_fd(fd):
        return _failure(provider, "mount_provider_invalid_descriptor", supported=True)
    if _platform_name(platform) != "darwin":
        return _failure(provider, "mount_provider_platform_unsupported")
    selected = backend or _load_darwin_fstatfs_backend()
    if selected is None:
        return _failure(provider, "mount_provider_fstatfs_symbol_unavailable")
    payload = _DarwinStatfs()
    try:
        ctypes.set_errno(0)
        result = selected(fd, payload)
        error_number = ctypes.get_errno()
    except OSError as exc:
        result = -1
        error_number = exc.errno or 0
    except Exception:
        return _failure(
            provider,
            "mount_provider_backend_failed",
            "reason=fstatfs_exception",
            supported=True,
        )
    if not isinstance(result, int) or isinstance(result, bool):
        return _failure(
            provider,
            "mount_provider_response_invalid",
            "reason=non_integer_status",
            supported=True,
        )
    if result != 0:
        code = (
            "mount_provider_invalid_descriptor"
            if error_number == errno.EBADF
            else "mount_provider_fstatfs_call_failed"
        )
        return _failure(provider, code, _errno_token(error_number), supported=True)
    filesystem_type = _nul_terminated(payload.f_fstypename)
    mount_on = _nul_terminated(payload.f_mntonname)
    mount_from = _nul_terminated(payload.f_mntfromname)
    if not filesystem_type or not mount_on or not mount_from:
        return _failure(provider, "mount_provider_fstatfs_response_invalid", supported=True)
    identity = MountIdentity(
        "darwin_fstatfs",
        (
            int(payload.f_fsid.value[0]),
            int(payload.f_fsid.value[1]),
            int(payload.f_type),
            filesystem_type,
            int(payload.f_flags),
            mount_on,
            mount_from,
        ),
    )
    return _success(provider, identity)


def probe_filesystem_fstat(fd: int) -> MountProviderResult:
    provider = FILESYSTEM_FSTAT_PROVIDER
    if not _valid_fd(fd):
        return _failure(provider, "mount_provider_invalid_descriptor", supported=True)
    try:
        metadata = os.fstat(fd)
    except OSError as exc:
        return _failure(
            provider,
            "mount_provider_fstat_unavailable",
            _errno_token(exc.errno),
            supported=True,
        )
    return _success(
        provider,
        MountIdentity("filesystem_device", (int(metadata.st_dev),)),
        MountAssurance.FILESYSTEM_IDENTITY_ONLY,
    )


DEFAULT_PROVIDERS: tuple[MountProvider, ...] = (
    probe_linux_fdinfo,
    probe_linux_statx,
    probe_linux_name_to_handle_at,
    probe_darwin_fstatfs,
    probe_filesystem_fstat,
)

KNOWN_PROVIDER_NAMES = (
    LINUX_FDINFO_PROVIDER,
    LINUX_STATX_PROVIDER,
    LINUX_NAME_TO_HANDLE_PROVIDER,
    DARWIN_FSTATFS_PROVIDER,
    FILESYSTEM_FSTAT_PROVIDER,
)


def _callable_name(provider: MountProvider) -> str:
    value = getattr(provider, "provider_name", None) or getattr(provider, "__name__", "provider")
    normalized = str(value).lower().removeprefix("probe_")
    normalized = re.sub(r"[^a-z0-9_]+", "_", normalized).strip("_")
    if not normalized or not normalized[0].isalpha():
        return "provider"
    return normalized[:128]


def _invoke_provider(provider: MountProvider, fd: int) -> MountProviderResult:
    name = _callable_name(provider)
    try:
        result = provider(fd)
    except Exception:
        return _failure(
            name,
            "mount_provider_backend_failed",
            "reason=provider_exception",
            supported=True,
        )
    if not isinstance(result, MountProviderResult):
        return _failure(name, "mount_provider_contract_invalid", supported=True)
    return result


def _ordered_providers(
    providers: Sequence[MountProvider] | None,
    preferred_provider: str | None,
) -> tuple[MountProvider, ...]:
    selected = DEFAULT_PROVIDERS if providers is None else tuple(providers)
    if any(not callable(provider) for provider in selected):
        raise TypeError("mount_providers_must_be_callable")
    if preferred_provider is None or providers is not None:
        return selected
    _require_safe_name(preferred_provider, "preferred_mount_provider")
    by_name = dict(zip(KNOWN_PROVIDER_NAMES, DEFAULT_PROVIDERS, strict=True))
    preferred = by_name.get(preferred_provider)
    if preferred is None:
        return selected
    return (preferred, *(provider for provider in selected if provider is not preferred))


def resolve_mount_identity(
    fd: int,
    *,
    providers: Sequence[MountProvider] | None = None,
    reconcile: bool = True,
    preferred_provider: str | None = None,
) -> MountResolution:
    """Resolve a descriptor without weakening to ``st_dev`` silently."""

    if not _valid_fd(fd):
        failure = _failure("resolver", "mount_provider_invalid_descriptor")
        return MountResolution(None, None, MountAssurance.UNAVAILABLE, (failure,), SECURE_MOUNT_IDENTITY_UNAVAILABLE)
    if not isinstance(reconcile, bool):
        raise TypeError("mount_reconcile_must_be_bool")
    results: list[MountProviderResult] = []
    high: list[MountProviderResult] = []
    low: list[MountProviderResult] = []
    seen_names: set[str] = set()
    for provider in _ordered_providers(providers, preferred_provider):
        result = _invoke_provider(provider, fd)
        results.append(result)
        if result.provider in seen_names:
            return MountResolution(
                None,
                None,
                MountAssurance.UNAVAILABLE,
                tuple(results),
                "mount_identity_provider_contract_invalid",
            )
        seen_names.add(result.provider)
        if result.identity is None:
            continue
        if ASSURANCE_RANK[result.assurance] >= ASSURANCE_RANK[MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND]:
            high.append(result)
            if not reconcile:
                return MountResolution(
                    result.provider,
                    result.identity,
                    MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND,
                    tuple(results),
                    None,
                )
        else:
            low.append(result)
    if high:
        identities = {result.identity for result in high}
        if len(identities) != 1:
            return MountResolution(
                None,
                None,
                MountAssurance.UNAVAILABLE,
                tuple(results),
                "mount_identity_provider_conflict",
            )
        selected = high[0]
        assurance = (
            MountAssurance.MOUNT_RECONCILED
            if len(high) >= 2
            else MountAssurance.MOUNT_UNIQUE_DESCRIPTOR_BOUND
        )
        return MountResolution(
            selected.provider,
            selected.identity,
            assurance,
            tuple(results),
            None,
        )
    if low:
        selected = low[0]
        return MountResolution(
            selected.provider,
            selected.identity,
            selected.assurance,
            tuple(results),
            SECURE_MOUNT_IDENTITY_UNAVAILABLE,
        )
    supported_failures = [
        result for result in results if result.supported and result.identity is None
    ]
    return MountResolution(
        None,
        None,
        MountAssurance.UNAVAILABLE,
        tuple(results),
        (
            "mount_identity_provider_probe_failed"
            if supported_failures
            else SECURE_MOUNT_IDENTITY_UNAVAILABLE
        ),
    )


def require_mount_assurance(resolution: MountResolution, operation: str) -> None:
    if not isinstance(resolution, MountResolution):
        raise TypeError("mount_resolution_required")
    minimum = OPERATION_MINIMUM_ASSURANCE.get(operation)
    if minimum is None:
        raise ValueError("unknown_mount_operation")
    if ASSURANCE_RANK[resolution.assurance] < ASSURANCE_RANK[minimum]:
        raise MountIdentityError(SECURE_MOUNT_IDENTITY_UNAVAILABLE, resolution)


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value or "\n" in value or "\r" in value:
        raise ValueError("invalid_repository_relative_path")
    if value == ".":
        return value
    if value.startswith(("/", "\\")) or "\\" in value:
        raise ValueError("invalid_repository_relative_path")
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise ValueError("invalid_repository_relative_path")
    return value


def require_same_mount(
    root_resolution: MountResolution,
    child_fd: int,
    relative_path: object,
    *,
    providers: Sequence[MountProvider] | None = None,
) -> MountResolution:
    """Require one child descriptor to share the root's canonical mount."""

    path = _safe_relative_path(relative_path)
    require_mount_assurance(root_resolution, READ_ONLY_EVIDENCE)
    child = resolve_mount_identity(
        child_fd,
        providers=providers,
        reconcile=False,
        preferred_provider=root_resolution.selected_provider,
    )
    require_mount_assurance(child, READ_ONLY_EVIDENCE)
    if child.identity != root_resolution.identity:
        raise ValueError(f"repository_nested_mount_rejected={path}")
    return child


def safe_provider_result_report(result: MountProviderResult) -> dict[str, object]:
    if not isinstance(result, MountProviderResult):
        raise TypeError("mount_provider_result_required")
    return {
        "provider": result.provider,
        "supported": result.supported,
        "identity_present": result.identity is not None,
        "assurance": result.assurance.value,
        "failure_code": result.failure_code,
        "diagnostics": list(result.diagnostics),
    }


def safe_resolution_report(resolution: MountResolution) -> dict[str, object]:
    if not isinstance(resolution, MountResolution):
        raise TypeError("mount_resolution_required")
    return {
        "selected_provider": resolution.selected_provider,
        "identity_present": resolution.identity is not None,
        "assurance": resolution.assurance.value,
        "failure_code": resolution.failure_code,
        "providers": [safe_provider_result_report(item) for item in resolution.providers],
    }


__all__ = [
    "APPLY_RUN_MUTATION",
    "ASSURANCE_RANK",
    "AT_EMPTY_PATH",
    "DARWIN_FSTATFS_PROVIDER",
    "DARWIN_MNT_LOCAL",
    "DEFAULT_PROVIDERS",
    "FILESYSTEM_FSTAT_PROVIDER",
    "KNOWN_PROVIDER_NAMES",
    "LINUX_FDINFO_PROVIDER",
    "LINUX_NAME_TO_HANDLE_PROVIDER",
    "LINUX_STATX_PROVIDER",
    "MountAssurance",
    "MountIdentity",
    "MountIdentityError",
    "MountProviderResult",
    "MountResolution",
    "NON_DESTRUCTIVE_ARTIFACT_CREATION",
    "NON_DESTRUCTIVE_ARTIFACT_PACKAGE_CREATION",
    "OPERATION_MINIMUM_ASSURANCE",
    "READ_ONLY_EVIDENCE",
    "RUN_REPLACE_QUARANTINE_DELETE",
    "SECURE_MOUNT_IDENTITY_UNAVAILABLE",
    "STATX_MNT_ID",
    "probe_darwin_fstatfs",
    "probe_filesystem_fstat",
    "probe_linux_fdinfo",
    "probe_linux_name_to_handle_at",
    "probe_linux_statx",
    "require_mount_assurance",
    "require_same_mount",
    "resolve_mount_identity",
    "safe_provider_result_report",
    "safe_resolution_report",
]
