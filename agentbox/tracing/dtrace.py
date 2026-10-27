# dtrace -c launches the target and records syscall entries for its pid. Kernel-
# side and read-mostly, so lower observer effect than ptrace. On macOS, SIP
# restricts it: usually needs sudo and may refuse SIP/hardened binaries.
"""dtrace connector (macOS / Solaris / *BSD)."""
from __future__ import annotations

from .base import Tracer


class DtraceTracer(Tracer):
    name = "dtrace"

    # Trace syscall entries for the launched process and its children.
    _SCRIPT = (
        "syscall:::entry /pid == $target || ppid == $target/ "
        "{ printf(\"%d %s(%s)\\n\", pid, probefunc, copyinstr(0)); }"
    )

    def available(self) -> bool:
        return self._on_path("dtrace") is not None

    def auto_ok(self) -> bool:
        # dtrace needs root, so never auto-pick it; request it by name under sudo.
        import os as _os

        return self.available() and getattr(_os, "geteuid", lambda: 1)() == 0

    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        dtrace = self._on_path("dtrace") or "dtrace"
        # -c runs the command (quoted as one target), -n the probe, -o the output.
        cmd = " ".join(_shquote(a) for a in target_argv)
        return [
            dtrace,
            "-q",
            "-c", cmd,
            "-o", trace_out,
            "-n", "syscall:::entry /pid == $target/ { printf(\"%s\\n\", probefunc); }",
        ]


def _shquote(arg: str) -> str:
    if arg and all(c.isalnum() or c in "._-/" for c in arg):
        return arg
    return "'" + arg.replace("'", "'\\''") + "'"
