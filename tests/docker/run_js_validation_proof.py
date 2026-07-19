#!/usr/bin/env python3
"""Linux/Docker proof for the js_validation containment profile.

1. Confirms the container has real outbound network (a raw Node socket connects
   to a public resolver *without* containment).
2. Confirms Landlock is ACTIVE in the container.  The js_validation profile
   PERMITS spawning, so repo-write prevention relies on Landlock; on Linux the
   validation now FAILS CLOSED when Landlock is unavailable (see C-B), so the
   real-exec receipt tests below require it.  Docker's default seccomp profile
   returns EPERM for the ``landlock_*`` syscalls, so run this container with
   ``--security-opt seccomp=unconfined`` (the kernel must be >= 5.13; 6.x shows
   ABI 3+).  The seccomp *classic-BPF* filter the profile installs itself needs
   only NO_NEW_PRIVS and works regardless.
3. Runs the real JavaScript-validation behavior tests (no mocks); the outbound
   cases must be denied by the inherited seccomp filter even though the network
   is up, which is exactly what proves the kernel-level enforcement, and the
   git/worktree/submodule writes must be prevented (Landlock) or caught (digest).

Set ``CODEXQB_JS_REAL_VITEST=1`` to additionally run the real upstream Vitest
smoke (B2) under the profile (needs npm + network to install vitest).
"""

from __future__ import annotations

import os
import platform
import subprocess
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

JS_TESTS = [
    "tests.test_apply_run.ApplyRunTests.test_js_seccomp_denies_iouring_afunix_and_inet_egress",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_detects_git_writes",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_resolves_worktree_gitfile",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_resolves_submodule_gitfile",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_uses_authoritative_commondir",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_falls_back_when_commondir_absent",
    "tests.test_apply_run.ApplyRunTests.test_validation_control_surface_digest_fails_closed_when_walk_exceeds_cap",
    "tests.test_apply_run.ApplyRunTests.test_control_surface_entry_fails_closed_before_reading_oversized_file",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_pure_run_passes_and_records_network_enforcement",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_permits_bounded_child_process_spawning",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_denies_outbound_inet_socket",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_denies_afunix_egress",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_denies_iouring_egress",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_network_denial_is_inherited_by_spawned_children",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_rejects_nonexistent_and_swapped_runner",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_rejects_symlinked_runner",
    "tests.test_apply_run.ApplyRunTests.test_js_validation_prelaunch_inode_swap_is_detected",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_pure_run_records_enforced_receipt",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_spawned_git_child_succeeds",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_outbound_socket_is_denied",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_repo_write_is_denied_or_caught",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_git_hook_write_is_prevented_or_caught",
    "tests.test_apply_run.ApplyRunTests.test_execute_planned_validation_js_fails_closed_when_landlock_unavailable",
]

REAL_VITEST_TEST = (
    "tests.test_apply_run.ApplyRunTests.test_js_validation_real_upstream_vitest_runs_under_profile"
)

BASELINE_SCRIPT = (
    "const net=require('net');"
    "const s=net.connect({host:'1.1.1.1',port:53});"
    "s.setTimeout(5000);"
    "s.on('connect',()=>{console.log('BASELINE_NETWORK_CONNECTED');s.destroy();process.exit(0)});"
    "s.on('timeout',()=>{console.log('BASELINE_NETWORK_TIMEOUT');process.exit(2)});"
    "s.on('error',e=>{console.log('BASELINE_NETWORK_ERROR:'+(e&&e.code));process.exit(3)});"
)


def main() -> int:
    print("=== js_validation Linux proof ===", flush=True)
    print(f"platform: {platform.platform()} machine={platform.machine()}", flush=True)
    print(f"python: {sys.version.split()[0]}", flush=True)
    try:
        node_version = subprocess.check_output(["node", "--version"], text=True).strip()
        print(f"node: {node_version}", flush=True)
    except Exception as exc:  # pragma: no cover - environment guard
        print(f"node unavailable: {exc}", flush=True)
        return 10

    os.chdir(REPO_ROOT)
    sys.path.insert(0, REPO_ROOT)
    sys.path.insert(0, os.path.join(REPO_ROOT, "plugins/codexqb/skills/codexqb/scripts"))
    import apply_run  # noqa: E402  (import after sys.path setup)

    abi = apply_run._linux_landlock_abi()
    print(f"--- Landlock ABI probe: {abi} ---", flush=True)
    if abi < 1:
        print(
            "FAIL: Landlock is not available in this container.  The js_validation "
            "profile now FAILS CLOSED without it (C-B), so the real-exec receipt "
            "tests cannot pass here.  Re-run the container with "
            "`--security-opt seccomp=unconfined` so the landlock_* syscalls are "
            "permitted (kernel must be >= 5.13).",
            flush=True,
        )
        return 11
    print("Landlock is ACTIVE: repo-write prevention is kernel-enforced.", flush=True)

    print("--- baseline outbound network (NO containment) ---", flush=True)
    baseline = subprocess.run(["node", "-e", BASELINE_SCRIPT], text=True, capture_output=True)
    print((baseline.stdout + baseline.stderr).strip(), flush=True)
    if "BASELINE_NETWORK_CONNECTED" not in baseline.stdout:
        print(
            "WARNING: container could not open a real outbound socket; the seccomp "
            "denial below is still syscall-level (EACCES) and valid, but the "
            "network-reachability contrast is weaker.",
            flush=True,
        )
    else:
        print("container is normally networked; the js_validation profile must still deny INET.", flush=True)

    tests = list(JS_TESTS)
    if os.environ.get("CODEXQB_JS_REAL_VITEST") == "1":
        print("--- B2 real upstream Vitest smoke ENABLED ---", flush=True)
        tests.append(REAL_VITEST_TEST)

    print("--- running real JavaScript-validation behavior tests ---", flush=True)
    loader = unittest.defaultTestLoader
    suite = loader.loadTestsFromNames(tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
