"""Smoke test: exercise the sandbox + tracer data flow WITHOUT the LLM.

Run:  python scripts/smoke.py
Shows, for a benign target: build -> run -> host tracer observes -> bounded
result. No API key required. This is the fastest way to see the baseline work.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentbox.sandbox import CodeObject, MockSandbox, RunSpec  # noqa: E402
from agentbox.sandbox.base import Language  # noqa: E402
from agentbox.tracing import available_tracers  # noqa: E402

print("Tracers available on this host:", available_tracers())
print()

sb = MockSandbox()

HELLO = r'''
#include <stdio.h>
int main(int argc, char **argv){ printf("hello (argc=%d)\n", argc); return 0; }
'''

spec = RunSpec(code=CodeObject(language=Language.C, source=HELLO), argv=["a", "b"], tracer="auto")
res = sb.run(spec)

print("sandbox         :", res.sandbox, f"(containment={res.containment_level})")
print("exit_code       :", res.exit_code, "| signal:", res.signal, "| timed_out:", res.timed_out)
print("duration_s      :", res.duration_s)
print("stdout          :", res.stdout.strip())
if res.trace:
    print("tracer          :", res.trace.tracer, "| note:", res.trace.note or "-")
    print("trace (first 400 chars):")
    print(res.trace.summary[:400] or "(none)")
