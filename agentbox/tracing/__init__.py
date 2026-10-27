# A tracer launches the target as its child (not attach), so it captures the
# target from its first instruction. get_tracer() resolves a name, falling back
# to NullTracer when the requested tool is unavailable.
"""Tracer ADT and registry."""
from __future__ import annotations

from .base import NullTracer, Tracer
from .dtrace import DtraceTracer
from .gdb import GdbTracer
from .strace import StraceTracer

# "auto" order: syscall tracing first, then crash/backtrace, then dtrace.
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
