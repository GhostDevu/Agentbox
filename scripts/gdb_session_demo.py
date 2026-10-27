"""Demonstrate an EXTERNAL AGENT driving an interactive gdb session (Linux).

gdb runs inside the sandbox (its symbol/DWARF parser stays contained); this
script -- standing in for ARCTIC's agent, outside the sandbox -- drives it over a
host pseudo-terminal: set a breakpoint, run, inspect variables, continue, and
localize the crash. This is the iterative tracing loop the agent uses.

    python3 scripts/gdb_session_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentbox.sandbox import CodeObject, RunSpec  # noqa: E402
from agentbox.sandbox.base import Language  # noqa: E402
from agentbox.sandbox.ns import NsSandbox  # noqa: E402


def step(label, output):
    print(f"\n>>> agent: {label}")
    print("\n".join("    " + ln for ln in output.splitlines()))


def main():
    sb = NsSandbox()
    src = open(os.path.join(os.path.dirname(__file__), "..", "examples", "crash.c")).read()
    spec = RunSpec(code=CodeObject(language=Language.C, source=src))

    print("External agent opens an interactive gdb session on the sandboxed program.")
    with sb.open_gdb(spec) as g:
        step("break clobber", g.brk("clobber"))
        step("run (stop at breakpoint)", g.run())
        step("print depth", g.print_("depth"))
        step("backtrace", g.backtrace())
        step("continue (next recursion)", g.cont())
        step("print depth again", g.print_("depth"))
        g.command("delete")
        step("continue to the crash", g.cont())
        step("backtrace at the fault", g.backtrace())
        step("value of the faulting pointer p", g.print_("p"))
    print("\nSession closed; sandbox torn down.")


if __name__ == "__main__":
    main()
