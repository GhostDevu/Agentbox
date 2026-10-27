"""Tests for the mock sandbox and tracer plumbing (no LLM; skip when tools absent)."""
import os
import shutil

import pytest

from agentbox.sandbox import CodeObject, MockSandbox, RunSpec
from agentbox.sandbox.base import Language
from agentbox.tracing import available_tracers

HAS_CC = any(shutil.which(c) for c in ("cc", "gcc", "clang"))


def test_python_hello_no_tracer():
    sb = MockSandbox()
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="print('hi'); print('there')"),
        tracer="none",
    )
    res = sb.run(spec)
    assert res.exit_code == 0
    assert "hi" in res.stdout
    assert res.containment_level == "none"
    assert res.timed_out is False


def test_python_nonzero_exit_is_reported_not_raised():
    sb = MockSandbox()
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="import sys; sys.exit(3)"),
        tracer="none",
    )
    res = sb.run(spec)
    assert res.exit_code == 3


def test_timeout_is_enforced():
    sb = MockSandbox()
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="import time; time.sleep(30)"),
        tracer="none",
        timeout_s=1.0,
    )
    res = sb.run(spec)
    assert res.timed_out is True
    assert res.exit_code is None


def test_argv_is_passed_through():
    sb = MockSandbox()
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="import sys; print(sys.argv[1:])"),
        argv=["alpha", "beta"],
        tracer="none",
    )
    res = sb.run(spec)
    assert "alpha" in res.stdout and "beta" in res.stdout


def test_teardown_leaves_no_workdir():
    sb = MockSandbox()
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="print('x')"),
        tracer="none",
    )
    res = sb.run(spec)
    assert not os.path.exists(res.meta["workdir"]), "workdir must be removed after run"


def test_output_is_bounded():
    from agentbox.config import Limits

    sb = MockSandbox(limits=Limits(max_output_bytes=100))
    spec = RunSpec(
        code=CodeObject(language=Language.PYTHON, source="print('A'*5000)"),
        tracer="none",
    )
    res = sb.run(spec)
    assert "truncated" in res.stdout
    assert len(res.stdout.encode()) < 300


@pytest.mark.skipif(not HAS_CC, reason="no C compiler available")
def test_c_hello_compiles_and_runs():
    sb = MockSandbox()
    src = os.path.join(os.path.dirname(__file__), "..", "examples", "hello.c")
    with open(src) as fh:
        code = fh.read()
    spec = RunSpec(code=CodeObject(language=Language.C, source=code), argv=["x"], tracer="none")
    res = sb.run(spec)
    assert res.exit_code == 0
    assert "hello from agentbox" in res.stdout


def test_tracer_registry_reports_availability():
    avail = available_tracers()
    assert set(avail) >= {"strace", "gdb", "dtrace"}
    assert all(isinstance(v, bool) for v in avail.values())
