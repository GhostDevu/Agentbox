"""Demonstrate ONE-WAY tracing out of the sandbox (Linux).

Two modes, both export runtime info to the host while the target stays contained:

  1. strace (syscalls)  -- host-side tracer follows into the HARDENED sandbox;
     works even though the target's own ptrace is denied by seccomp. The trace
     file lives on the host, outside the sandbox: one-way by construction.
  2. gdb (crash state)  -- in-sandbox tracer (host gdb hangs across namespaces),
     runs the target as its child, writes the backtrace to an exported /out.
     Uses the `traced` policy: ptrace permitted, every other dimension contained.

Run inside the Linux VM / native Linux:
    python3 scripts/trace_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentbox.sandbox import CodeObject, RunSpec, hardened  # noqa: E402
from agentbox.sandbox.base import Language  # noqa: E402
from agentbox.sandbox.ns import NsSandbox  # noqa: E402

EX = os.path.join(os.path.dirname(__file__), "..", "examples")


def main():
    sb = NsSandbox(policy=hardened())

    print("=" * 70)
    print("MODE 1: strace syscall trace (host-side) through the HARDENED sandbox")
    print("=" * 70)
    hello = open(os.path.join(EX, "hello.c")).read()
    r = sb.run(RunSpec(code=CodeObject(language=Language.C, source=hello),
                       argv=["ARCTIC"], tracer="strace"))
    print(f"[{r.trace.note}]  containment={r.containment_level}")
    print("target output:", r.stdout.strip().replace("\n", " | "))
    print("--- target syscalls (exported one-way) ---")
    print("\n".join(r.trace.summary.splitlines()[:12]))

    print()
    print("=" * 70)
    print("MODE 2: gdb crash backtrace (in-sandbox tracer -> exported /out)")
    print("=" * 70)
    crash = open(os.path.join(EX, "crash.c")).read()
    r2 = sb.trace_gdb(RunSpec(code=CodeObject(language=Language.C, source=crash)))
    print(f"[{r2.trace.note}]")
    print("--- crash backtrace (exported one-way) ---")
    print("\n".join(r2.trace.summary.splitlines()[:14]))


if __name__ == "__main__":
    main()
