# Each dimension's benign probe CROSSES on weak, is CONTAINED on hardened, and
# is CONTAINED when only its own knob is enabled (proving that knob contains it).
# "Contained" = did not report CROSSED. Linux only (needs unprivileged userns).
"""Isolation tests for NsSandbox across every dimension."""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="NsSandbox needs Linux namespaces; run in the VM/Docker",
)

HERE = os.path.dirname(__file__)
PROBES = os.path.join(HERE, "..", "examples", "probes")


def _read(name):
    with open(os.path.join(PROBES, name)) as fh:
        return fh.read()


def _run(policy, src_name, timeout=20.0):
    from agentbox.sandbox import CodeObject, RunSpec
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox

    sb = NsSandbox(policy=policy)
    res = sb.run(RunSpec(
        code=CodeObject(language=Language.C, source=_read(src_name)),
        tracer="none", timeout_s=timeout,
    ))
    return res, (res.stdout + "\n" + res.stderr)


def _crossed(output):
    return "CROSSED" in output


def _host_has_egress():
    """Can the host reach the internet? (Weak net-crossing can't be shown without it.)"""
    import socket
    try:
        s = socket.socket()
        s.settimeout(3)
        s.connect(("1.1.1.1", 53))
        s.close()
        return True
    except OSError:
        return False


# dimension label -> (probe source, kwargs that enable ONLY that dimension).
# fork uses both limit mechanisms: cgroup pids.max (root) and RLIMIT_NPROC
# (non-root) cover each other across environments.
DIMENSIONS = {
    "fs-read":   ("host_file.c",       dict(pivot=True)),
    "fs-write":  ("fs_write.c",        dict(pivot=True, ro_root=True)),
    "network":   ("net_egress.c",      dict(netns=True)),
    "pid":       ("proc_vis.c",        dict(pidns=True)),
    "fork":      ("fork_limit.c",      dict(limits=True, cgroup=True)),
    "memory":    ("mem_limit.c",       dict(limits=True)),
    "uts":       ("uts_host.c",        dict(utsns=True)),
    "syscalls":  ("seccomp_ptrace.c",  dict(seccomp=True)),
}


@pytest.mark.parametrize("label", list(DIMENSIONS))
def test_weak_crosses(label):
    """Under weak, every probe must CROSS (probe validity); two are host-dependent."""
    if label == "fs-write" and os.geteuid() != 0:
        pytest.skip("weak root-write needs root; userns maps to a non-root uid here")
    if label == "network" and not _host_has_egress():
        pytest.skip("host has no outbound network; cannot show egress crossing")
    from agentbox.sandbox import weak
    src, _ = DIMENSIONS[label]
    res, out = _run(weak(), src)
    assert _crossed(out), f"{label}: expected CROSSED on weak, got:\n{out}"


@pytest.mark.parametrize("label", list(DIMENSIONS))
def test_hardened_contains(label):
    """Under the hardened policy, no probe may CROSS."""
    from agentbox.sandbox import hardened
    src, _ = DIMENSIONS[label]
    res, out = _run(hardened(), src)
    assert not _crossed(out), f"{label}: expected CONTAINED on hardened, got:\n{out}"


@pytest.mark.parametrize("label", list(DIMENSIONS))
def test_single_dimension_contains(label):
    """Enabling only the relevant knob (weak + it) must contain the probe."""
    from agentbox.sandbox import custom
    src, enable = DIMENSIONS[label]
    res, out = _run(custom(label, **enable), src)
    assert not _crossed(out), (
        f"{label}: enabling {enable} should contain it, got:\n{out}")


# ---- backend mechanics (not dimension probes) -----------------------------

def test_normal_program_runs_and_exits_zero():
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    sb = NsSandbox(policy=hardened())
    res = sb.run(RunSpec(
        code=CodeObject(language=Language.C, source='#include <stdio.h>\nint main(int c,char**v){printf("hi %d\\n",c);return 0;}'),
        argv=["a", "b"], tracer="none"))
    assert res.exit_code == 0 and "hi 3" in res.stdout


def test_nonzero_exit_is_reported():
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    sb = NsSandbox(policy=hardened())
    res = sb.run(RunSpec(
        code=CodeObject(language=Language.C, source="int main(){return 7;}"), tracer="none"))
    assert res.exit_code == 7


def test_timeout_enforced():
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    sb = NsSandbox(policy=hardened())
    res = sb.run(RunSpec(
        code=CodeObject(language=Language.C, source="int main(){for(;;);}"),
        tracer="none", timeout_s=1.5))
    assert res.timed_out is True


def test_ro_root_leaves_tmp_writable():
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    sb = NsSandbox(policy=hardened())
    src = ('#include <stdio.h>\nint main(){FILE*f=fopen("/tmp/x","w");'
           'if(f){fputs("x",f);fclose(f);printf("OK\\n");}else printf("FAIL\\n");return 0;}')
    res = sb.run(RunSpec(code=CodeObject(language=Language.C, source=src), tracer="none"))
    assert "OK" in res.stdout


def test_teardown_leaves_no_rundir():
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    sb = NsSandbox(policy=hardened())
    res = sb.run(RunSpec(
        code=CodeObject(language=Language.C, source="int main(){return 0;}"), tracer="none"))
    assert not os.path.exists(res.meta["rundir"])
    assert res.containment_level == "namespaces"


# ---- one-way tracing --------------------------------------------------------

def test_strace_exports_target_syscalls():
    """Host-side strace observes the target inside the hardened sandbox."""
    import shutil
    if not shutil.which("strace"):
        pytest.skip("strace not installed")
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    src = open(os.path.join(HERE, "..", "examples", "hello.c")).read()
    sb = NsSandbox(policy=hardened())
    r = sb.run(RunSpec(code=CodeObject(language=Language.C, source=src),
                       argv=["X"], tracer="strace"))
    assert r.trace.tracer == "strace"
    assert 'execve("/app/target"' in r.trace.summary
    assert "write(" in r.trace.summary  # the target's own output syscall


def test_gdb_exports_crash_backtrace():
    """In-sandbox gdb exports a fault-localizing crash backtrace one-way via /out."""
    import shutil
    if not shutil.which("gdb"):
        pytest.skip("gdb not installed")
    from agentbox.sandbox import CodeObject, RunSpec, hardened
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    src = open(os.path.join(HERE, "..", "examples", "crash.c")).read()
    sb = NsSandbox(policy=hardened())
    r = sb.trace_gdb(RunSpec(code=CodeObject(language=Language.C, source=src)))
    assert r.trace.tracer == "gdb"
    assert "SIGSEGV" in r.trace.summary
    assert "clobber" in r.trace.summary  # the faulting function is localized


def test_interactive_gdb_session_driven_externally():
    """External caller drives gdb: break -> run -> inspect -> continue to the crash."""
    import shutil
    if not shutil.which("gdb"):
        pytest.skip("gdb not installed")
    from agentbox.sandbox import CodeObject, RunSpec
    from agentbox.sandbox.base import Language
    from agentbox.sandbox.ns import NsSandbox
    src = open(os.path.join(HERE, "..", "examples", "crash.c")).read()
    sb = NsSandbox()
    with sb.open_gdb(RunSpec(code=CodeObject(language=Language.C, source=src))) as g:
        assert "Breakpoint" in g.brk("clobber")
        out = g.run()
        assert "clobber" in out                    # stopped at the breakpoint
        assert g.print_("depth").strip().endswith("3")  # recursion starts at 3
        g.command("delete")
        crash = g.cont()
        assert "SIGSEGV" in crash                   # continued into the fault
        assert "0x0" in g.print_("p")               # the NULL pointer


@pytest.mark.parametrize("src", ["host_file.c", "net_egress.c", "proc_vis.c", "uts_host.c"])
def test_isolation_holds_under_traced_policy(src):
    """traced() permits ptrace but must keep every other dimension contained."""
    from agentbox.sandbox import traced
    res, out = _run(traced(), src)
    assert not _crossed(out), f"traced() must still contain {src}:\n{out}"
