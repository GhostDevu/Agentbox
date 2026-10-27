# A tracer answers: can it run here (available), how does it launch the target
# so the run is observed (wrap), and collect() bounds the on-disk trace.
"""The Tracer abstract data type."""
from __future__ import annotations

import abc
import os
import shutil

from ..sandbox.base import TraceArtifact


class Tracer(abc.ABC):
    name: str = "tracer"

    @abc.abstractmethod
    def available(self) -> bool:
        """True if this tracer's binary exists and can be invoked here."""

    def auto_ok(self) -> bool:
        """True if "auto" may pick this tracer unprivileged here (stricter than available)."""
        return self.available()

    @abc.abstractmethod
    def wrap(self, target_argv: list[str], trace_out: str) -> list[str]:
        """Return the argv that launches `target_argv` under this tracer into `trace_out`."""

    def collect(self, trace_out: str, max_bytes: int) -> TraceArtifact:
        """Read `trace_out` into a bounded artifact (override to summarize structured output)."""
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
    """Runs the target with no tracing ("none" and the unavailable-tracer fallback)."""

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
