"""Isolation policies for the namespace sandbox.

A policy is the full set of knobs `abx_init` understands -- one per isolation
dimension. Two presets matter for the attack-model story: `hardened()` turns
every dimension on (the containment claim); `weak()` turns them all off except
the user namespace (needed to run unprivileged), so the same benign canary
CROSSES on weak and is CONTAINED on hardened -- the probe-validity requirement
in PRD §7. `custom()` lets a probe isolate exactly one dimension to show that
dimension is the thing doing the containing.
"""
from __future__ import annotations

from dataclasses import dataclass, replace


@dataclass(frozen=True)
class Policy:
    name: str
    # --- namespaces (True = isolate / new namespace) ---
    userns: bool = True       # unprivileged user namespace + uid/gid map
    pidns: bool = True        # new PID namespace (+ fresh /proc)
    ipcns: bool = True        # new IPC namespace
    utsns: bool = True        # new UTS namespace (+ hostname)
    cgroupns: bool = True     # new cgroup namespace
    netns: bool = True        # new, empty network namespace (no connectivity)
    # --- behaviour ---
    pivot: bool = True        # pivot_root into a clean rootfs
    ro_root: bool = True      # remount the new root read-only
    limits: bool = True       # apply rlimits
    cgroup: bool = True        # best-effort cgroup v2 memory.max/pids.max
    seccomp: bool = True       # seccomp-bpf deny filter over dangerous syscalls
    allow_ptrace: bool = False # keep ptrace allowed under seccomp (tracing mode)
    hostname: str = "agentbox"
    # --- resource values (0 = leave unset) ---
    cpu_s: int = 10
    mem_mb: int = 512
    nproc: int = 64
    fsize_mb: int = 64
    nofile: int = 64
    pids_max: int = 64

    def to_args(self, rootfs: str | None) -> list[str]:
        """Render as abx_init CLI flags (the program argv is appended by the
        caller after a `--`)."""
        def tog(flag: str, on: bool) -> list[str]:
            return [f"--{flag}"] if on else [f"--no-{flag}"]

        args: list[str] = []
        if rootfs:
            args += ["--rootfs", rootfs]
        args += tog("userns", self.userns)
        args += tog("pidns", self.pidns)
        args += tog("ipcns", self.ipcns)
        args += tog("utsns", self.utsns)
        args += tog("cgroupns", self.cgroupns)
        args += tog("netns", self.netns)
        args += tog("pivot", self.pivot)
        args += tog("ro-root", self.ro_root)
        args += tog("limits", self.limits)
        args += tog("cgroup", self.cgroup)
        args += tog("seccomp", self.seccomp)
        args += tog("allow-ptrace", self.allow_ptrace)
        args += ["--hostname", self.hostname]
        args += ["--cpu", str(self.cpu_s), "--mem-mb", str(self.mem_mb),
                 "--nproc", str(self.nproc), "--fsize-mb", str(self.fsize_mb),
                 "--nofile", str(self.nofile), "--pids-max", str(self.pids_max)]
        return args


def hardened() -> Policy:
    """Every isolation dimension on: user+mount+pid+ipc+uts+cgroup+net
    namespaces, clean pivot_root, read-only root, dropped capabilities,
    NO_NEW_PRIVS, rlimits, best-effort cgroup limits, and a seccomp deny filter.
    This is the containment claim."""
    return Policy(name="hardened")


def traced() -> Policy:
    """Hardened, but with ptrace permitted under seccomp so an in-sandbox tracer
    (gdb) can observe the target. This is the isolation<->observability trade-off
    made explicit: the knob that blocks the target's anti-debug is the same knob
    that blocks our tracer, so tracing mode relaxes exactly that one restriction.
    Everything else (filesystem, network, pid, memory, caps, other syscalls)
    stays fully contained."""
    return Policy(name="traced", allow_ptrace=True)


def weak() -> Policy:
    """Everything off except the user namespace (kept so the sandbox still runs
    unprivileged). Shares the host filesystem, network, PID/IPC/UTS namespaces;
    no read-only root, no limits, no cgroup, no seccomp. Every probe CROSSES.
    For probe-validity demonstrations on BENIGN probes only."""
    return Policy(
        name="weak",
        pidns=False, ipcns=False, utsns=False, cgroupns=False, netns=False,
        pivot=False, ro_root=False, limits=False, cgroup=False, seccomp=False,
    )


def custom(name: str, **overrides) -> Policy:
    """A weak baseline with specific dimensions turned back on, to show that one
    dimension is responsible for containing one probe (used by the test suite)."""
    return replace(weak(), name=name, **overrides)
