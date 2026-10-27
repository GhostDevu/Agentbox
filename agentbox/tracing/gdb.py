# Launches the target in batch mode and, on a fault, prints a backtrace and
# registers. Caveat: a debugger changes ASLR/env, so crash addresses can shift.
"""gdb connector: crash state and backtraces in batch mode."""
from __future__ import annotations

from .base import Tracer


class GdbTracer(Tracer):
    name = "gdb"

    def available(self) -> bool:
        return self._on_path("gdb") is not None

    def auto_ok(self) -> bool:
        # Keep gdb out of "auto" on macOS (needs entitlements); usable by name.
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
