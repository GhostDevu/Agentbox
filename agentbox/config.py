"""Central configuration, overridable from the environment."""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Bounds per run: cap the host damage and the data fed back to the agent."""

    wall_timeout_s: float = 20.0          # hard kill after this many seconds
    max_output_bytes: int = 64 * 1024     # stdout/stderr captured per stream
    max_trace_summary_bytes: int = 16 * 1024  # trace text handed to the agent
    max_argv: int = 64


@dataclass(frozen=True)
class Config:
    # LLM that drives the agent (override with AGENTBOX_MODEL).
    model: str = os.environ.get("AGENTBOX_MODEL", "claude-opus-5-5")

    # Tracer the agent's tool uses when none is requested.
    default_tracer: str = os.environ.get("AGENTBOX_TRACER", "auto")

    # Root for per-run build/trace artifacts (each run's subdir is removed after).
    work_root: str = os.environ.get(
        "AGENTBOX_WORK_ROOT", os.path.join(os.path.expanduser("~"), ".agentbox", "runs")
    )

    limits: Limits = Limits()


CONFIG = Config()
