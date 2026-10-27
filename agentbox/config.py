"""Central configuration for Agentbox.

Everything tunable lives here so the agent, the sandbox and the tracers read one
source of truth. Values can be overridden from the environment, which keeps
secrets (the API key) and host-specific choices (the model) out of the code.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Limits:
    """Bounds applied to a single sandbox run.

    These exist for two reasons: they stop a runaway or hostile target from
    exhausting the host, and they bound the *channel* back to the agent so a
    target cannot flood the LLM context (an RQ4 / prompt-injection concern).
    """

    wall_timeout_s: float = 20.0          # hard kill after this many seconds
    max_output_bytes: int = 64 * 1024     # stdout/stderr captured per stream
    max_trace_summary_bytes: int = 16 * 1024  # trace text handed to the agent
    max_argv: int = 64                    # guard against absurd argument lists


@dataclass(frozen=True)
class Config:
    # LLM that drives the agent. Default follows the Anthropic skill guidance;
    # override with AGENTBOX_MODEL. Opus is the right default for tool-driven
    # agentic work; swap to a cheaper model for cost-sensitive batch runs.
    model: str = os.environ.get("AGENTBOX_MODEL", "claude-opus-5-5")

    # Which tracer the agent's tool uses by default when none is requested.
    default_tracer: str = os.environ.get("AGENTBOX_TRACER", "auto")

    # Where temp build/run artifacts and trace files are written. A per-run
    # subdirectory is created under this and removed afterwards.
    work_root: str = os.environ.get(
        "AGENTBOX_WORK_ROOT", os.path.join(os.path.expanduser("~"), ".agentbox", "runs")
    )

    limits: Limits = Limits()


CONFIG = Config()
