# strace -f follows forks and captures the first syscall (launch-as-child).
# Observer effect: ptrace serializes the target and can mask timing-sensitive bugs.
"""strace connector (Linux): syscall-level tracing."""
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
