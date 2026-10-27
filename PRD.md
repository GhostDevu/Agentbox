# Agentbox PRD (v0.1 — for supervisor review)

**Status:** draft, 2026-10-23. **Owner:** Devanshu Agrawal. **Reviewer:** Prof.
Mainack Mondal (and the Professor-MM persona, `../MM/`).

Agentbox is ARCTIC's **sandbox**: it runs a potentially hostile target under
isolation while keeping it observable to a tracer, so the Tracing Module can
extract runtime context for bug localization. This PRD covers what Agentbox is,
the baseline that exists today, the directory layout, the intended design, and
the open decisions needing sign-off. The research backing it is in
[RESEARCH.md](RESEARCH.md); the central tension and the 35 driving questions live
there.

---

## 1. Problem & goal

Coding agents see prompts and static code; ARCTIC adds **runtime context**.
Targets may be vulnerable or malicious, so execution must be **isolated**. But
ARCTIC's whole value is **observing** that execution. Agentbox must therefore be
**strongly isolating against the target yet transparently observable by a trusted
tracer** — an asymmetric-trust, one-way-observability problem (RESEARCH.md §1).

**One-sentence contribution (sandbox side):** *a sandbox design and attack-model
evaluation for running untrusted targets under isolation while a trusted tracer
extracts true-behavior runtime context, quantified for containment and fidelity.*

### Goals

- **G1 Containment.** Contain host-FS, host-network, cross-run, and control-plane
  access per the threat model (§4).
- **G2 Observability.** Produce a true-behavior trace (syscalls / crash state) of
  the target via a trusted tracer.
- **G3 Fidelity.** The trace reflects the untraced run; measure the divergence.
- **G4 Pluggable boundary.** One `Sandbox` ADT; swap mock → bubblewrap → gVisor →
  Firecracker without touching the agent.
- **G5 Hygiene & cost.** No leftovers after a run; startup/overhead fit an agent
  loop.

### Non-goals (Part-1)

Kernel 0-days as defended-against, Spectre-class side channels, DoS resistance,
exploits *within* the workload's own sandbox allocation, and APR. These are
stated as out of scope (RESEARCH.md Q12), not ignored.

---

## 2. What exists today (the baseline)

A **LangChain agent → mock sandbox → host tracer** loop, end-to-end:

```
agent (LLM)  ──run_in_sandbox──▶  MockSandbox  ──wrap(argv)──▶  tracer
     ▲                                 │                           │
     └──── bounded result summary ◀────┴──── stdout/stderr/trace ◀─┘
```

- The **MockSandbox** compiles/launches a benign target **on the host with NO
  containment** and runs it under a host tracer (strace/gdb/dtrace) in a
  launch-as-child model, then returns a bounded, normalized result.
- Its purpose is to **pin the interfaces** (Sandbox ADT, Tracer ADT, the one-way
  result channel) so the containment layers slot in behind them. It is **not** a
  security boundary and must only run benign canary/probe code.
- Verified: `scripts/smoke.py` and `tests/` (8 passing). On macoS, `auto` honestly
  falls back to *untraced* because dtrace needs root and gdb needs entitlements;
  real tracing runs in the Linux VM (RESEARCH.md Q22).

This directly realizes the requested picture: *agent invokes program → sandbox
runs it → system tools can still trace the inner program.* What it does **not**
yet do is isolate — that is the roadmap (§6).

---

## 3. Directory structure

```
Agentbox/
├── PRD.md                      This document.
├── RESEARCH.md                 Sandbox survey + the 35 driving questions + findings.
├── CLAUDE.md                   Working rules for agents/humans editing this package.
├── README.md                   Quickstart: install, smoke test, run the agent.
├── pyproject.toml              Package metadata; `[agent]` and `[dev]` extras.
├── .env.example                Template for ANTHROPIC_API_KEY / overrides.
├── .gitignore
│
├── agentbox/                   The Python package.
│   ├── __init__.py             Package docstring + version.
│   ├── config.py               Single source of truth: model, tracer default,
│   │                           work dir, and the Limits (timeout, output/trace
│   │                           byte caps) that bound an untrusted run.
│   │
│   ├── sandbox/                The Sandbox ADT and its backends.
│   │   ├── __init__.py         Re-exports public types; lazy `NsSandbox` import.
│   │   ├── base.py             CodeObject / RunSpec / RunResult / TraceArtifact
│   │   │                       dataclasses, the Language enum, and the abstract
│   │   │                       `Sandbox` (with `containment_level`). THE CONTRACT
│   │   │                       the rest of ARCTIC depends on.
│   │   ├── mock.py             MockSandbox: dev-host stand-in, NO containment.
│   │   │                       Builds C / runs Python / binary; bounds output;
│   │   │                       guarantees teardown. (macOS-friendly.)
│   │   ├── policy.py           Policy dataclass + hardened()/weak() presets =
│   │   │                       the abx_init flag sets for the containment gradient.
│   │   └── ns.py               NsSandbox: the first REAL backend (Linux). Builds
│   │                           a minimal rootfs, compiles the target static, and
│   │                           drives abx_init. containment_level="namespaces".
│   │
│   ├── runtime/                Our own low-level container runtime (not bwrap).
│   │   └── abx_init.c          C init: clone() namespaces + userns map +
│   │                           pivot_root + ro-root + caps drop + NO_NEW_PRIVS +
│   │                           rlimits, then execv. Compiled on first use.
│   │
│   ├── tracing/                The Tracer ADT and connectors.
│   │   ├── __init__.py         Registry + `get_tracer("auto"|name)` with honest
│   │   │                       fallback; `available_tracers()` diagnostics.
│   │   ├── base.py             Abstract `Tracer` (available / auto_ok / wrap /
│   │   │                       collect) and `NullTracer`.
│   │   ├── strace.py           strace connector (syscalls; ARCTIC's primary signal).
│   │   ├── gdb.py              gdb connector (crash state / backtraces, batch mode).
│   │   └── dtrace.py           dtrace connector (macOS; low observer effect; needs root).
│   │
│   └── agent/                  The LangChain agent.
│       ├── __init__.py
│       ├── tools.py            `run_in_sandbox` tool = THE ONE-WAY CHANNEL. Bounds
│       │                       and frames all target-influenced output as data.
│       └── agent.py            build_agent / run_agent + CLI (tool-calling agent).
│
├── examples/
│   ├── hello.c                 Benign canary (syscalls to show in a trace).
│   ├── crash.c                 Benign NULL-deref (SIGSEGV; gdb backtrace target).
│   └── probes/                 Canary escape probes, one per dimension (benign).
│       ├── host_file.c         filesystem read     net_egress.c   network egress
│       ├── fs_write.c          filesystem write    proc_vis.c     PID namespace
│       ├── fork_limit.c        fork/PID limit      mem_limit.c    memory limit
│       ├── uts_host.c          UTS/hostname        seccomp_ptrace.c  syscall filter
│
├── scripts/
│   ├── smoke.py                Exercise mock sandbox WITHOUT the LLM (no API key).
│   ├── ns_demo.py              Run all probes under weak vs hardened (Linux).
│   ├── trace_demo.py           Show one-way tracing: strace syscalls + gdb crash (Linux).
│   ├── gdb_session_demo.py     External agent driving an interactive gdb session (Linux).
│   └── run_tests.py            Run the suite without pytest (minimal shim).
│
├── docker/
│   ├── Dockerfile              Debian + gcc + python3 + pytest; entrypoint delegates cgroups.
│   ├── entrypoint.sh           Sets up a delegated cgroup v2 parent, then runs the cmd.
│   └── run.sh                  Build the image and run a command with the tree mounted.
│
└── tests/
    ├── test_mock_sandbox.py    Mock backend: build/run/trace/teardown/bounds (skip-aware).
    └── test_ns_sandbox.py      NS backend: every dimension CROSS-on-weak/CONTAIN-on-hardened
                                + single-dimension attribution + mechanics (Linux only).
```

**Why this shape.** The three layers mirror the ARCTIC components: `sandbox/` is
the containment boundary, `tracing/` is the Tracing-Module ADT, `agent/` is the
Agent-Module entry point. The two ADTs (`sandbox/base.py`, `tracing/base.py`) are
the stable seams — every roadmap step (§6) is a new file behind an existing ADT,
never a change to the agent.

---

## 4. Threat model (draft — needs sign-off)

Stated adversarially per RESEARCH.md Q9–Q14.

- **Adversary (R-A).** Part-1: a **malicious or vulnerable native target** run at
  runtime. Supply-chain install scripts (`npm install` postinstall, `make`) are
  flagged as a *separate* entry point and deferred, not silently covered.
- **Capabilities assumed.** Arbitrary syscalls, fork/persistence attempts,
  network egress attempts, anti-trace/anti-debug, attempts to read/poison other
  runs.
- **Must contain, ranked.** (1) host FS integrity+secrecy, (2) host network,
  (3) **other concurrent/sequential runs** (no cross-run contamination of traces),
  (4) the tracer/agent control plane.
- **Explicit non-goals.** Host-kernel 0-days (namespace class assumes a trusted,
  patched kernel), hardware/Spectre side channels, DoS/resource-exhaustion as a
  security property (bounded, not defended), and manipulation of the LLM by trace
  content beyond the bounding/framing in `agent/tools.py`.
- **Agent position.** **Outside** the trust boundary; every byte the target can
  influence is untrusted data (one-way channel).

---

## 5. Design

### 5.1 The two ADTs

- **`Sandbox.run(RunSpec) -> RunResult`.** Backends differ only in
  `containment_level` (`none` → `namespaces` → `userspace-kernel` → `microvm`)
  and in *where the tracer attaches*. The agent never sees the difference.
- **`Tracer`.** `available()` (can it be requested), `auto_ok()` (may `auto` pick
  it unprivileged on this OS — stricter), `wrap(argv, out)` (launch-as-child,
  closing the attach race, RESEARCH.md Q8), `collect(out, cap)` (bounded artifact).

### 5.1a Isolation dimensions (NsSandbox / abx_init)

Every dimension is covered and independently toggleable, so a policy can be a
full gradient. Verified in the test suite (`tests/test_ns_sandbox.py`, 29 tests):
each dimension CROSSES on `weak`, is CONTAINED on `hardened`, and is contained
by enabling only its own knob.

| Dimension | Mechanism | Probe | hardened result |
|---|---|---|---|
| Filesystem (read) | mount ns + `pivot_root` into clean rootfs, detach old root | `host_file.c` | host files invisible |
| Filesystem (write) | read-only root remount (non-recursive; `/tmp` stays rw) | `fs_write.c` | write to `/` fails |
| Network | new network namespace (loopback down, no routes) | `net_egress.c` | connect fails |
| Process (visibility) | new PID namespace (target is pid 1) + fresh `/proc` | `proc_vis.c` | can't see host pids |
| Process (fork/count) | cgroup v2 `pids.max` (RLIMIT_NPROC is a bypassed-for-root fallback) | `fork_limit.c` | fork capped (~64) |
| Memory | `RLIMIT_AS` (+ best-effort cgroup `memory.max`) | `mem_limit.c` | alloc fails at cap |
| IPC | new IPC namespace | — | isolated |
| UTS / hostname | new UTS namespace + hostname | `uts_host.c` | own hostname |
| Privilege | user namespace + uid/gid map, drop all caps, `NO_NEW_PRIVS` | (implicit) | unprivileged |
| Syscall surface | seccomp-bpf deny filter (ptrace, bpf, mount, setns, kexec, …) | `seccomp_ptrace.c` | ptrace denied |
| CPU / time | `RLIMIT_CPU` + Python wall-clock timeout | (timeout test) | killed at limit |
| Files / FDs / cores | `RLIMIT_FSIZE`, `RLIMIT_NOFILE`, `RLIMIT_CORE=0` | — | bounded |

Resource limits use **two layers**: rlimits (portable, unprivileged) and cgroup
v2 (robust, needs a delegated writable cgroup — present on a normal VM; the
Docker harness prepares one via its entrypoint). Fork containment specifically
requires cgroups because `RLIMIT_NPROC` is not enforced for the root user.

### 5.2 Where the tracer sits (the load-bearing decision)

Per RESEARCH.md §4/§6, this is **per-backend**, abstracted by the Tracer ADT:

| Backend | Containment | Tracer position | True-behavior trace via |
|---|---|---|---|
| mock | none | host (parent) | strace/gdb/dtrace on the child |
| bubblewrap | namespaces | **host, parent ns** | host strace/gdb — target syscalls *are* host syscalls |
| gVisor | userspace-kernel | **inside the Sentry** | `runsc --strace` / seccheck (read-only, target-semantic) |
| Firecracker | microVM | **in-guest agent** | in-VM eBPF/strace streamed over vsock |

Design principle: **make the boundary the tracer** rather than pointing a two-way
host primitive (ptrace) at the target. Read-mostly observation (strace of genuine
host syscalls, gVisor seccheck, eBPF) is preferred; gdb/ptrace is an opt-in
crash-state path carrying a documented observer-effect caveat.

### 5.2b One-way runtime tracing (the ARCTIC export path)

Isolation is half the job; the sandbox must also export the target's runtime
behavior one-way to a trusted tracer. Two modes, both verified (RESEARCH.md §6.1):

- **strace (syscalls) — host-side.** The tracer runs *outside* the sandbox as the
  parent of `abx_init`; `strace -f` follows the clone into the fully **hardened**
  sandbox and records the target's own syscalls. It works even though the hardened
  seccomp denies the *target's* ptrace, because the filter restricts the target,
  not an external tracer. The trace file lives on the host — one-way by
  construction. `NsSandbox.run(spec, tracer="strace")`.
- **gdb (crash state) — in-sandbox, one-shot.** Host gdb hangs following a fork
  across new user/PID namespaces, so the tracer runs *inside*: `abx_init` execs
  gdb (made runnable by binding the host toolchain read-only), gdb runs the
  target as its child in the same namespaces, and writes the backtrace to `/out`,
  a host dir bound rw only for the trace. `NsSandbox.trace_gdb(spec)`.
- **gdb (interactive) — external agent control.** `NsSandbox.open_gdb(spec)`
  returns a live `GdbSession`: gdb runs in-sandbox with its terminal wired to a
  host pseudo-terminal, and an external caller (ARCTIC's agent) drives it --
  `brk()`, `run()`, `step()`, `print_()`, `backtrace()`, `cont()`, … -- to set
  breakpoints, inspect variables and memory, and localize iteratively. Keeping
  gdb in-sandbox means its symbol/DWARF parser (attacker-influenced data) stays
  contained; the agent is entirely external and the target is gdb's inferior.

**The trade-off, made explicit.** Tracing uses the `traced` policy, which differs
from `hardened` by **exactly one restriction**: seccomp permits `ptrace` (the knob
that blocks the target's anti-debug is the same one that blocks our tracer). Every
other dimension stays contained (tested). gdb mode additionally binds the host
toolchain read-only — never `/etc`, `/home`, `/root`, `/var` — a narrowed,
documented filesystem relaxation that applies only while crash-tracing.

Export channel (`abx_init`): `--out-dir HOSTDIR` (bind rw at `/out`), `--bind-ro
SRC[:DST]` (tooled rootfs), `--allow-ptrace` (seccomp keeps ptrace).

### 5.3 The one-way channel

`agent/tools.py` renders every result into framed sections that label
`metadata (host-trusted)` vs `stdout/stderr/trace (untrusted data)`, each byte-
bounded by `config.Limits`. The raw trace is retained on disk for the pipeline;
only the bounded summary is ever handed to the LLM. This is the concrete defense
for RQ4 / prompt-injection-via-trace.

### 5.4 Hygiene

Every run uses a fresh per-run work dir removed in a `finally` (verified by
`test_teardown_leaves_no_workdir`). Real backends extend this to namespaces,
mounts, cgroups and network state, with a leak check in the probe suite.

---

## 6. Roadmap & milestones

| # | Milestone | Containment | Exit criterion |
|---|---|---|---|
| M0 | **Baseline (done)** | none | LangChain agent → mock → tracer loop; smoke + tests green |
| M1 | **our NS runtime (done, verified)** | namespaces | `NsSandbox` + `abx_init.c`: own clone/userns/pivot_root/ro-root/caps/seccomp/rlimits/cgroup runtime (not a bwrap wrapper). All isolation dimensions (fs/net/pid/ipc/uts/mem/fork/syscalls/priv) CROSS on weak, CONTAINED on hardened. |
| M1t | **one-way tracing (done, verified)** | namespaces | Export the target's runtime behavior while contained: host-side **strace** (syscalls, through the hardened sandbox) and in-sandbox **gdb** (crash backtrace via `/out`, `traced` policy). Isolation preserved under tracing. 41 tests green on native x86_64 Linux. |
| M2 | **Attack-model probe suite** | — | each probe CROSSED-on-weak / CONTAINED-on-hardened, incl. probes *through the tracing channel* (Q24–Q25) |
| M3 | **Fidelity harness** | — | numeric divergence traced-vs-untraced; crash-address stability; repro rate ±tracing (Q26) |
| M4 | **gVisor backend (systrap)** | userspace-kernel | `runsc --strace`/seccheck normalized through the Tracer ADT |
| M5 | **Firecracker backend** | microVM | **Stage B, KVM host only** — in-guest agent over vsock |

M1–M3 are the credible Part-1 scope (RESEARCH.md §4.4). M5 is gated on a KVM host.

---

## 7. Evaluation plan

- **Isolation (G1).** Canary/escape probe suite (host-file R/W, net egress, mount
  escape, `/proc`+`/sys` reach, PID-ns escape, **tracer-handle abuse**), each with
  a weak-vs-hardened verdict. Comparator: naked Docker and nsjail-default (Q30).
- **Fidelity (G3).** Differential syscall-sequence divergence, crash-address
  stability, bug-reproduction rate ±tracing, dropped-event rate (Q26).
- **Cost (G5).** Startup latency, per-syscall overhead, memory, scaling with
  syscall rate (Q27). Leftover check after N runs (Q28).
- **Reproducibility (Q29).** Same binary+input → same trace/verdict across repeats
  and machines; record ASLR/timing/scheduling nondeterminism.

---

## 8. Open decisions (need supervisor sign-off)

Carried from RESEARCH.md §5; proposed answers in **bold**.

| ID | Question | Proposed |
|---|---|---|
| R1 | First real backend | **bubblewrap** |
| R2 | Primary tracer | **strace** (syscalls) + **gdb** (crash); evaluate **eBPF** |
| R3 | Tracer position | per-backend via the Tracer ADT (§5.2) |
| R4 | Kernel-trust assumption | **trusted+patched** for Part-1 (namespace class) |
| R5 | Agent trust position | **outside**; all trace content untrusted |
| R6 | arm64 sample validity | **open** — choose aarch64-reproducible bugs, defer x86 to a KVM x86 host |
| R7 | KVM host for Stage B | **open** — raise with Prof. Mondal (gates M5) |

### Questions for the supervisor

1. Is the Part-1 scope (M1–M3: bubblewrap + probe suite + fidelity harness, no
   microVM) the right line, or should gVisor-systrap (M4) be pulled into Part-1?
2. Accept "host kernel trusted and patched" as the Part-1 residual risk (R4)?
3. Which KVM host will exist for Stage B (R7), and when?
4. Does the sandbox get its own native benchmark for isolation+fidelity, kept
   separate from the npm/Defects4J localization evaluation?
