# A sandbox takes a RunSpec and returns a RunResult + bounded trace; containment
# strength is a property of the implementation (containment_level), not this ADT.
"""The Sandbox abstract data type."""
from __future__ import annotations

import abc
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Language(str, Enum):
    """How the target is expressed. Drives build/launch in a backend."""

    C = "c"
    PYTHON = "python"
    BINARY = "binary"  # a pre-built executable referenced by path


@dataclass
class CodeObject:
    """The thing to run: inline `source` (C/Python) or a `path` to a built binary."""

    language: Language
    source: Optional[str] = None
    path: Optional[str] = None
    name: str = "target"          # label used in logs and trace file names

    def __post_init__(self) -> None:
        if self.language == Language.BINARY and not self.path:
            raise ValueError("BINARY CodeObject requires a path")
        if self.language != Language.BINARY and not self.source and not self.path:
            raise ValueError("source or path is required")


@dataclass
class RunSpec:
    """A single sandbox invocation request."""

    code: CodeObject
    argv: list[str] = field(default_factory=list)   # args passed to the target
    stdin: Optional[str] = None
    tracer: str = "auto"      # tracer name, "auto", or "none"
    timeout_s: Optional[float] = None  # None -> use Config.limits
    env: dict[str, str] = field(default_factory=dict)


@dataclass
class TraceArtifact:
    """One run's trace: full `raw_path` on disk; bounded `summary` is the only part
    safe to forward to an LLM (the raw trace is attacker-influenced and unbounded)."""

    tracer: str
    raw_path: Optional[str]
    summary: str
    truncated: bool = False
    note: str = ""                # e.g. "tracer unavailable", "needs privileges"


@dataclass
class RunResult:
    """A run's outcome; host-trusted except stdout/stderr/trace.summary (untrusted)."""

    exit_code: Optional[int]        # None if killed by timeout/signal pre-exit
    stdout: str
    stderr: str
    duration_s: float
    timed_out: bool
    trace: Optional[TraceArtifact]
    sandbox: str                    # implementation name
    containment_level: str          # see Sandbox.containment_level
    signal: Optional[int] = None    # terminating signal, if any
    meta: dict = field(default_factory=dict)


class Sandbox(abc.ABC):
    """Runs a target and returns a traced result; the agent talks to this alone."""

    #: Short implementation name, surfaced in results and logs.
    name: str = "sandbox"

    #: What this backend actually contains ("none", "namespaces", ...); cite this,
    #: never the interface, in evaluation claims.
    containment_level: str = "none"

    @abc.abstractmethod
    def run(self, spec: RunSpec) -> RunResult:
        """Run `spec`; report target failure in the result, raise only on caller error."""
        raise NotImplementedError
