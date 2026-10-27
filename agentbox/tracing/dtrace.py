"""dtrace connector (macOS / Solaris / *BSD).

dtrace with `-c` launches the target and traces it. We record syscall entries
scoped to the launched pid. dtrace is kernel-side and read-mostly, so its
observer effect is lower than ptrace -- which is exactly why it is interesting
for ARCTIC fidelity (RESEARCH.md Q34).

Reality check, recorded on purpose: on macOS, System Integrity Protection
restricts dtrace. It typically needs `sudo` and may refuse to trace
SIP-protected or hardened-runtime binaries. `available()` only checks that the
binary exists; a run may still fail with a privileges note, which `collect`
surfaces honestly rather than hiding.
"""
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
        # On macOS, dtrace needs root (and SIP still restricts targets), so it
        # must not be auto-picked -- only used when explicitly requested, ideally
        # under sudo. geteuid may be absent on some platforms; treat as not-ok.
        import os as _os

        return self.available() and getattr(_os, "geteuid", lambda: 1)() == 0

    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        dtrace = self._on_path("dtrace") or "dtrace"
        # -c runs the command; -n is the probe script; -o the output file.
        # Quote the command so dtrace runs the full argv as one target.
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
