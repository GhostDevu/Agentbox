"""Sandbox ADT and implementations (mock + Linux namespaces)."""
from .base import CodeObject, RunResult, RunSpec, Sandbox, TraceArtifact
from .mock import MockSandbox
from .policy import Policy, custom, hardened, traced, weak

__all__ = [
    "CodeObject",
    "RunSpec",
    "RunResult",
    "TraceArtifact",
    "Sandbox",
    "MockSandbox",
    "Policy",
    "hardened",
    "weak",
    "custom",
    "traced",
]


def __getattr__(name):
    # Lazy import so the package stays importable off Linux.
    if name == "NsSandbox":
        from .ns import NsSandbox
        return NsSandbox
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
