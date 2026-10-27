"""gdb connector: crash state and backtraces, run in batch mode.

gdb launches the target, lets it run, and on a fault prints a backtrace and
registers -- exactly the crash-localization signal ARCTIC wants for memory-
safety bugs. Batch mode keeps it non-interactive so it fits the agent loop.

Caveats recorded on purpose: a debugger changes ASLR and the environment, so
crash addresses can differ from an untraced run (RESEARCH.md Q17); and on macOS
arm64 gdb needs code-signing/entitlements and often does not work out of the box
(prefer lldb or the Linux VM there).
"""
from __future__ import annotations

from .base import Tracer


class GdbTracer(Tracer):
    name = "gdb"

    def available(self) -> bool:
        return self._on_path("gdb") is not None

    def auto_ok(self) -> bool:
        # On macOS, gdb needs code-signing/entitlements to control a target and
        # usually fails to launch one, so keep it out of "auto" there. It stays
        # usable when requested by name (and works on Linux).
        import sys as _sys

        return self.available() and not _sys.platform.startswith("darwin")

    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        gdb = self._on_path("gdb") or "gdb"
        return [
            gdb,
            "-nx",                               # ignore .gdbinit
            "-batch",                            # non-interactive, exit at end
            "-ex", f"set logging file {trace_out}",
            "-ex", "set logging enabled on",
            "-ex", "set pagination off",
            "-ex", "run",
            "-ex", "echo \\n==== backtrace ====\\n",
            "-ex", "bt full",
            "-ex", "echo \\n==== registers ====\\n",
            "-ex", "info registers",
            "-ex", "quit",
            "--args",
            *target_argv,
        ]
