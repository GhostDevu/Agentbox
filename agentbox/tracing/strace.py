"""strace connector (Linux). ARCTIC's primary syscall-level signal.

`strace -f` follows forks so a target that spawns children is still observed.
This is launch-as-child: strace is the parent, so there is no attach race and
the first syscall is captured. Note the observer effect -- strace uses ptrace,
which serializes the target and can mask timing-sensitive bugs (RESEARCH.md
Q15-Q16); that caveat is a property of this tracer, recorded here on purpose.
"""
from __future__ import annotations

from .base import Tracer


class StraceTracer(Tracer):
    name = "strace"

    def available(self) -> bool:
        return self._on_path("strace") is not None

    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        strace = self._on_path("strace") or "strace"
        return [
            strace,
            "-f",                 # follow children
            "-tt",                # microsecond timestamps
            "-T",                 # time spent in each syscall
            "-y",                 # decode fds to paths
            "-s", "256",          # string arg length
            "-o", trace_out,
            "--",
            *target_argv,
        ]
