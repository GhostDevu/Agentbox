"""Tests for the agent's sandbox tools against the real NsSandbox (Linux, no LLM)."""
import os
import sys

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux"),
    reason="agent tools run against NsSandbox; needs Linux namespaces",
)

CRASH = os.path.join(os.path.dirname(__file__), "..", "examples", "crash.c")


def _src():
    with open(CRASH) as fh:
        return fh.read()


def _hello():
    with open(os.path.join(os.path.dirname(CRASH), "hello.c")) as fh:
        return fh.read()


def test_backend_is_real_sandbox_on_linux():
    from agentbox.agent import tools
    assert tools._sandbox().containment_level == "namespaces"


def test_run_in_sandbox_gdb_tracer_reports_crash():
    from agentbox.agent.tools import run_in_sandbox
    out = run_in_sandbox(_src(), tracer="gdb")
    assert "SIGSEGV" in out and "clobber" in out
    assert "untrusted data" in out


def test_run_in_sandbox_strace_tracer():
    from agentbox.agent.tools import run_in_sandbox
    # hello.c, not crash.c: a crashing pid-1 target spins forever under host strace.
    out = run_in_sandbox(_hello(), tracer="strace")
    assert "write(" in out


def test_gdb_tools_drive_a_session():
    from agentbox.agent import tools
    assert "no gdb session" in tools.gdb_command("bt")
    tools.gdb_open(_src())
    try:
        assert "Breakpoint 1" in tools.gdb_command("break clobber")
        assert "clobber" in tools.gdb_command("run")
        assert "= 3" in tools.gdb_command("print depth")
        tools.gdb_command("delete")
        assert "SIGSEGV" in tools.gdb_command("continue")
        assert "0x0" in tools.gdb_command("print p")
    finally:
        assert "closed" in tools.gdb_close()
    assert "no gdb session" in tools.gdb_command("bt")


def test_gdb_command_refuses_escapes():
    from agentbox.agent import tools
    tools.gdb_open(_src())
    try:
        for bad in ("shell id", "python print(1)", "source /etc/passwd",
                    "set logging file /x", "print 1\nshell id", "!id"):
            assert tools.gdb_command(bad).startswith("refused"), bad
        assert not tools.gdb_command("set var $x = 1").startswith("refused")
    finally:
        tools.gdb_close()


def test_gdb_open_replaces_previous_session_and_cleans_up():
    from agentbox.agent import tools
    from agentbox.config import CONFIG
    tools.gdb_open(_src())
    tools.gdb_open(_src())      # must close the first
    tools.gdb_close()
    leftover = [d for d in os.listdir(CONFIG.work_root) if d.startswith("gdbses-")]
    assert leftover == []
