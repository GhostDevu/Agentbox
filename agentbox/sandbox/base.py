"""The Sandbox abstract data type.

This is the contract the rest of ARCTIC depends on. A sandbox takes a
`RunSpec` (what to run, how long, under which tracer) and returns a `RunResult`
(what happened, plus a bounded trace artifact). Containment strength is a
property of the *implementation*, reported via `containment_level`, not of this
interface -- that is the whole point of piecing the boundary together behind a
stable ADT.
"""
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
    """The thing to run: either inline source, or a path to a built artifact.

    Exactly one of `source` / `path` is meaningful. For C, `source` is compiled
    by the backend; for PYTHON it is run by the interpreter; for BINARY, `path`
    points at an existing executable and `source` is ignored.
    """

    language: Language
    source: Optional[str] = None
    path: Optional[str] = None
    # Human label used in logs and trace file names.
    name: str = "target"

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
    """What a tracer produced for one run.

    `raw_path` is the full on-disk trace (kept for the pipeline / evaluation);
    `summary` is the bounded, caller-facing excerpt. `summary` is the only part
    that should ever be forwarded to an LLM, because the raw trace is attacker-
    influenced and unbounded.
    """

    tracer: str
    raw_path: Optional[str]
    summary: str
    truncated: bool = False
    note: str = ""  # e.g. "tracer unavailable", "needs privileges"


@dataclass
class RunResult:
    """Outcome of a sandbox run. All fields are host-trusted except the three
    captured from the target: `stdout`, `stderr`, and `trace.summary`. Callers
    must treat those as untrusted data, never as instructions.
    """

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
    """Runs a target and returns a traced result.

    Implementations differ only in how strongly they isolate the target and how
    the tracer reaches inside. The agent talks to this interface alone.
    """

    #: Short implementation name, surfaced in results and logs.
    name: str = "sandbox"

    #: Honest statement of what this backend contains. One of:
    #:   "none"         -- runs on the host, no isolation (the mock)
    #:   "namespaces"   -- Linux namespaces + seccomp (bubblewrap-class)
    #:   "userspace-kernel" -- gVisor-class syscall interposition
    #:   "microvm"      -- Firecracker-class hardware-virtualised
    #: Evaluation claims must cite this, never the interface.
    containment_level: str = "none"

    @abc.abstractmethod
    def run(self, spec: RunSpec) -> RunResult:
        """Execute `spec` and return a `RunResult`. Must not raise on target
        failure (nonzero exit, crash, timeout); those are reported in the
        result. May raise on caller error (bad spec, missing toolchain)."""
        raise NotImplementedError
