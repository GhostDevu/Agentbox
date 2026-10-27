"""Tracer ADT and registry.

A tracer's job is to *launch the target as its child* and record what the target
does, then hand back a bounded summary. Launch-as-child (not attach-to-running)
is deliberate: it closes the attach TOCTTOU window and captures the target from
its very first instruction (see RESEARCH.md Q8).

`get_tracer(name)` resolves a name ("strace", "gdb", "dtrace", "none", or
"auto") to an instance, falling back to the NullTracer when the requested tool
is not available on this host.
"""
from __future__ import annotations

from .base import NullTracer, Tracer
from .dtrace import DtraceTracer
from .gdb import GdbTracer
from .strace import StraceTracer

# Order matters for "auto": prefer syscall-level tracing (ARCTIC's primary
# signal), then a crash/backtrace tracer, then macOS dtrace.
_REGISTRY: dict[str, type[Tracer]] = {
    "strace": StraceTracer,
    "gdb": GdbTracer,
    "dtrace": DtraceTracer,
    "none": NullTracer,
}

_AUTO_ORDER = ["strace", "dtrace", "gdb"]


def get_tracer(name: str) -> Tracer:
    name = (name or "auto").lower()
    if name == "auto":
        for candidate in _AUTO_ORDER:
            inst = _REGISTRY[candidate]()
            if inst.auto_ok():
                return inst
        return NullTracer(note="no unprivileged tracer available; ran untraced")
    cls = _REGISTRY.get(name)
    if cls is None:
        raise ValueError(f"unknown tracer: {name!r}; known: {sorted(_REGISTRY)}")
    inst = cls()
    if not inst.available():
        # Fall back but record why, so the agent sees an honest note.
        return NullTracer(note=f"requested tracer {name!r} unavailable on this host")
    return inst


def available_tracers() -> dict[str, bool]:
    """Diagnostics helper: which tracers can actually run here."""
    return {name: cls().available() for name, cls in _REGISTRY.items() if name != "none"}


__all__ = [
    "Tracer",
    "NullTracer",
    "StraceTracer",
    "GdbTracer",
    "DtraceTracer",
    "get_tracer",
    "available_tracers",
]
