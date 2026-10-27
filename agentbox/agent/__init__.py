"""The LangChain agent that invokes Agentbox.

`tools` exposes the sandbox to the LLM as a single structured tool. `agent`
builds the tool-calling agent around it. The agent is intentionally thin: the
research lives in the sandbox and tracer layers, not here.
"""
from .tools import build_sandbox_tool, run_in_sandbox

__all__ = ["build_sandbox_tool", "run_in_sandbox"]
