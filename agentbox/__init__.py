"""Agentbox: a traced sandbox for ARCTIC.

Agentbox runs a target program inside a sandbox while keeping it observable to
the host machine's tracing tools (dtrace, gdb, strace, ...). This is the
isolation-vs-observability boundary that ARCTIC's runtime-context pipeline is
built on.

This package currently ships the *baseline*: a LangChain agent that invokes a
**mock** sandbox (no real containment yet). The mock exists to pin down the
interfaces -- the Sandbox ADT, the Tracer ADT, and the one-way result channel
back to the agent -- so the containment layers (namespaces, seccomp, microVM)
can be slotted in behind the same interface later.
"""

__version__ = "0.1.0"
