"""The Tracer abstract data type.

Every tracer answers two questions: can it run here (`available`), and how does
it launch the target so the run is observed (`wrap`). After the run, `collect`
turns the on-disk trace into a bounded `TraceArtifact`.

The `wrap` contract is the load-bearing one for the isolation<->observability
study: it decides whether the tracer is the *parent* of the target (host-side,
launch model) or something else. The mock uses the parent/launch model because
it is the simplest honest realization of "host tool traces the inner program".
Real backends may instead place an in-guest agent; they implement the same ADT.
"""
from __future__ import annotations

import abc
import os
import shutil

from ..sandbox.base import TraceArtifact


class Tracer(abc.ABC):
    name: str = "tracer"

    @abc.abstractmethod
    def available(self) -> bool:
        """True if this tracer's binary exists and can be invoked here. Used
        when the caller asks for this tracer by name."""

    def auto_ok(self) -> bool:
        """True if "auto" may pick this tracer *unprivileged on this OS*. This
        is stricter than `available`: a tracer that needs root (dtrace) or extra
        entitlements (gdb on macOS) is available on request but not auto-picked,
        so `auto` never silently kills a run on a tracer that can't launch it."""
        return self.available()

    @abc.abstractmethod
    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        """Return the argv that launches `target_argv` under this tracer,
        directing trace data to `trace_out`."""

    def collect(self, trace_out: str, max_bytes: int) -> TraceArtifact:
        """Read `trace_out` and return a bounded artifact. Default reads the
        whole file; tracers with structured output can override to summarize."""
        if not os.path.exists(trace_out):
            return TraceArtifact(
                tracer=self.name, raw_path=None, summary="",
                note="no trace file produced",
            )
        with open(trace_out, "rb") as fh:
            data = fh.read()
        truncated = len(data) > max_bytes
        text = data[:max_bytes].decode("utf-8", "replace")
        if truncated:
            text += f"\n...[trace truncated, {len(data)} bytes total]"
        return TraceArtifact(
            tracer=self.name, raw_path=trace_out, summary=text, truncated=truncated,
        )

    @staticmethod
    def _on_path(*names: str) -> str | None:
        for n in names:
            found = shutil.which(n)
            if found:
                return found
        return None


class NullTracer(Tracer):
    """Runs the target with no tracing. Used for "none" and as the fallback
    when a requested tracer is unavailable."""

    name = "none"

    def __init__(self, note: str = "") -> None:
        self._note = note

    def available(self) -> bool:
        return True

    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        return list(target_argv)

    def collect(self, trace_out: str, max_bytes: int) -> TraceArtifact:
        return TraceArtifact(
            tracer=self.name, raw_path=None, summary="",
            note=self._note or "no tracer",
        )
