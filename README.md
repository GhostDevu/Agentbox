# Agentbox

ARCTIC's sandbox: run a target under isolation while a trusted tracer observes it,
so coding agents get **runtime context** (syscalls, crash state) for bug
localization.

```
agent (LLM) ──run_in_sandbox──▶  sandbox  ──runs──▶  target
     ▲                              │                   │
     └──── bounded trace summary ◀──┴── tracer observes ┘
```

> **Baseline status.** What's here is the baseline: a LangChain agent calling a
> **mock sandbox with no containment**, to pin the interfaces. Real isolation
> (bubblewrap → gVisor → Firecracker) is the roadmap in [PRD.md](PRD.md). The
> mock must only run **benign** code. See [CLAUDE.md](CLAUDE.md) for the rules.

## Layout

- `agentbox/sandbox/` — the `Sandbox` ADT (`base.py`) and the `MockSandbox` baseline.
- `agentbox/tracing/` — the `Tracer` ADT and strace/gdb/dtrace connectors.
- `agentbox/agent/` — the LangChain agent and the `run_in_sandbox` tool (the
  one-way, bounded channel back to the LLM).
- `examples/`, `scripts/smoke.py`, `tests/` — a benign canary + crasher, a no-LLM
  demo, and tests.

Design: [PRD.md](PRD.md). Sandbox survey + research questions: [RESEARCH.md](RESEARCH.md).

## Quickstart

**1. See the sandbox + tracer work, no API key:**

```sh
cd Agentbox
python scripts/smoke.py
```

On macOS this runs the target and `auto`-selects a tracer; since dtrace needs
root and gdb needs entitlements, it honestly falls back to *untraced*. Real
tracing (strace/gdb) runs in the Linux VM, or run dtrace explicitly under sudo.

**2. Run the tests:**

```sh
pip install pytest
python -m pytest -q
```

**2b. Run the REAL namespace sandbox** (Linux only — in the VM/Docker):

```sh
docker/run.sh                        # weak-vs-hardened gradient, all dimensions
docker/run.sh python3 -m pytest -q   # full suite (37 tests)
```

`NsSandbox` isolates every dimension — filesystem, network, process/PID, fork &
memory limits, IPC, UTS, privilege, and the syscall surface (seccomp) — each
CROSSING on the `weak()` policy and CONTAINED on `hardened()`. On a real Linux VM
run `python3 scripts/ns_demo.py` directly; `run.sh` only uses `--privileged` on
the outer container to emulate that environment (the sandbox stays unprivileged).

**2c. One-way tracing** (export runtime info while the target stays contained):

```sh
python3 scripts/trace_demo.py        # Linux
```

- **strace (syscalls)** — host-side tracer follows into the *hardened* sandbox and
  records the target's syscalls (works even though the target's own ptrace is
  seccomp-denied); the trace file is on the host, one-way by construction.
  `NsSandbox.run(spec, tracer="strace")`.
- **gdb (crash backtrace)** — in-sandbox tracer (host gdb hangs across namespaces)
  runs the target and writes its backtrace to an exported `/out`.
  `NsSandbox.trace_gdb(spec)`, using the `traced()` policy (ptrace permitted,
  every other dimension still contained).
- **gdb (interactive)** — an external agent drives gdb on the sandboxed program:
  `NsSandbox.open_gdb(spec)` returns a `GdbSession` with `brk/run/step/print_/
  backtrace/cont`, for ARCTIC's iterative tracing loop. Demo:
  `python3 scripts/gdb_session_demo.py`.

**3. Run the agent** (needs an Anthropic credential — `ANTHROPIC_API_KEY` or
`ant auth login`):

```sh
pip install -e '.[agent]'
python -m agentbox.agent.agent "find and explain the bug" --code examples/crash.c
```

The agent compiles and runs the program in the sandbox, reads the trace/backtrace,
and concludes with a bug location. Default model: `claude-opus-5-5` (override with
`AGENTBOX_MODEL` or `--model`).

## Using the sandbox directly

```python
from agentbox.sandbox import CodeObject, MockSandbox, RunSpec
from agentbox.sandbox.base import Language

sb = MockSandbox()
res = sb.run(RunSpec(
    code=CodeObject(language=Language.C, source=open("examples/crash.c").read()),
    tracer="gdb",          # "auto" | "strace" | "gdb" | "dtrace" | "none"
))
print(res.exit_code, res.signal, res.timed_out)
print(res.trace.summary if res.trace else "(no trace)")
```

## Safety

The mock provides **zero isolation**. Run only benign canary/probe code through
it, never untrusted or malicious samples. That is what the real backends are for.
