"""Sandbox ADT and implementations.

`base` defines the interface every sandbox must satisfy. `mock` is the baseline
stand-in with NO containment. Future backends (bubblewrap, gVisor, Firecracker)
implement the same `Sandbox` interface so the agent never changes.
"""
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
    # Lazy import so the package stays importable on macOS, where NsSandbox
    # refuses to construct but the module itself pulls in Linux-only ideas only
    # at call time.
    if name == "NsSandbox":
        from .ns import NsSandbox
        return NsSandbox
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
