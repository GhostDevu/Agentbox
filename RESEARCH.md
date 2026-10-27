# Agentbox Sandbox Research

Research notes for building **Agentbox**, ARCTIC's sandbox. The job is unusual:
run a potentially hostile target under **strong isolation**, yet keep it
**transparently observable** to a tracer so ARCTIC can extract runtime context
(syscalls, backtraces, crash state). That is an asymmetric-trust,
one-way-observability problem, and it is the axis this survey is organized
around.

> Scope note: this is the Part-1 "survey + attack-model" background. It studies
> existing sandboxes *through the tracing lens* and extracts the design
> constraints for Agentbox. Reference source trees live beside this repo:
> `../bubblewrap/` (v0.13.0) and `../gvisor/` (shallow clone). Deeper bubblewrap
> mechanism notes are in `../BUBBLEWRAP.md`.

**Conventions**

- **Fact:** stated by the tool's own code/docs, with a citation.
- **Inference:** our conclusion, not stated directly by the source.
- Citations like `../gvisor/g3doc/...:N` point at the cloned trees.

---

## 1. The central tension, stated precisely

```
   LLM agent ──invoke──▶  ┌─────────────────────────────┐
                          │   SANDBOX                    │
                          │   ┌───────────────────────┐  │
   bounded result  ◀──────│   │  target program       │  │
   (trace summary)        │   │  (untrusted/hostile)  │  │
                          │   └──────────▲────────────┘  │
                          └──────────────┼───────────────┘
                                         │ observes
                                  ┌──────┴───────┐
                                  │  TRACER      │  dtrace / gdb / strace / eBPF
                                  └──────────────┘
```

Two properties must hold at once:

1. **Containment (against the target).** The target cannot reach the host FS,
   host network, host kernel integrity, other runs, or the agent control plane.
2. **Observability (for the tracer).** A trusted tracer sees the target's *true*
   runtime behavior — the syscalls and crashes it would exhibit un-sandboxed.

The hard part is that the mechanisms that grant observability (ptrace,
`/proc/<pid>/mem`, loose `ptrace_scope`, `CAP_SYS_PTRACE`) are the same
mechanisms that *weaken* containment, and some isolation mechanisms (gVisor's
syscall interposition, a microVM boundary) make a naive host tracer observe the
**wrong layer**. Resolving this — not writing agent plumbing — is the research.

---

## 2. Driving questions (from the research critic)

These were produced by the Opus-high research-critic subagent on 2026-10-23 to
drive this survey. They are the bar each design claim must clear. Reproduced in
full; the top 5 gate everything else.

### Theme 1 — The isolation ↔ observability contradiction (the core problem)

1. **Where does the tracer physically sit** — host, trusted in-guest supervisor,
   or sibling in the sandbox namespace — and is that constant or per-tracer
   (ptrace vs eBPF vs perf)? *The isolation argument changes entirely with this.*
2. **If the tracer needs `CAP_SYS_PTRACE` / `PTRACE_ATTACH` / `/proc/<pid>/mem`,
   does that capability live outside the sandbox and reach in, or inside it?** If
   inside, what stops the target from stealing/abusing it? *A ptrace-capable
   process co-resident with a hostile target is itself an escalation surface.*
3. **What is the tracer's own TCB, and why can't a hostile target subvert it**
   (parser bugs in strace/gdb on attacker-chosen syscall args, malformed core
   dumps, crafted DWARF/symbols)? *Tracers parse adversary-controlled data.*
4. **Does observability create a *bidirectional* hole?** ptrace can write
   registers/memory and continue execution. How do you guarantee one-way
   observability when the primitive is inherently two-way? *"One-way" may be
   physically unachievable with ptrace.*
5. **For gVisor:** the guest's syscalls are serviced by the Sentry in user space
   and never reach the host kernel. What does a *host* `strace`/`gdb` observe —
   the target's syscalls or the Sentry's? How do you recover target semantics?
   *Naive tracing yields the sandbox's syscalls, not the program's.*
6. **For Firecracker/microVM:** ptrace and `/proc/<pid>/mem` don't cross the VM
   boundary. What is the in-guest tracing agent, how is output exfiltrated
   (vsock? serial? shmem?), and what is that channel's TCB? *"Just use a VM"
   hides a whole in-guest subsystem.*
7. **How do Yama `ptrace_scope` and seccomp interact with the plan?** The knobs
   that enable tracing are the same ones that weaken isolation — map the coupling.
8. **Is tracing "attach to running" or "launch under the tracer"?** Different
   race windows (attach TOCTTOU, the fork/execve→attach gap) the target can
   exploit to run un-traced or detect tracing.

### Theme 2 — Threat model (write it down, adversarially)

9. **What *exactly* is the adversary:** malicious prebuilt ELF, benign-but-
   vulnerable code given an exploit input, or a hostile build/install script
   (supply chain) that runs *before* the program? *Different entry points.*
10. **Adversary capabilities:** arbitrary syscalls? kernel-LPE attempts? network
    egress? fork/persistence? ability to detect it's traced? *Without this list
    every "contained" claim is unfalsifiable.*
11. **What must be contained, ranked:** host FS, host kernel integrity, host
    network, **other concurrent runs**, the tracer/agent control plane. Is
    cross-run isolation in scope? *Run-to-run contamination silently corrupts the
    dataset.*
12. **What is explicitly OUT of scope** — kernel 0-days, HW side channels,
    Spectre, DoS, the agent being tricked by trace contents? *State the non-goals.*
13. **Is the LLM agent inside or outside the trust boundary**, and can the target
    craft trace output to manipulate it (prompt injection via `write()` buffers,
    filenames, argv)? *The sandbox contains the binary but not its influence.*
14. **Is the host kernel assumed trusted and current?** If one kernel 0-day
    defeats namespaces+seccomp, is that accepted residual risk or a reason to
    prefer a VM boundary? *This decides container-vs-VM.*

### Theme 3 — Fidelity and the observer effect

15. **Does tracing change whether the bug manifests at all?** ptrace serializes
    execution and perturbs timing/scheduling — for a race/TOCTTOU/heap-grooming
    bug, do you capture the real failure or a Heisenbug? *Fidelity is the
    project's existence condition.*
16. **How does the target detect tracing** (`TracerPid` in `/proc/self/status`,
    `PTRACE_TRACEME` failure, `getppid` timing, SIGTRAP, `0xCC` scanning) and
    alter behavior — threat-model item or fidelity caveat?
17. **Do breakpoints/SIGTRAP, ASLR-under-tracer, and env differences shift crash
    addresses?** Are backtraces stable enough to hand the agent?
18. **What is the ground-truth oracle that "the trace reflects real behavior"?**
    Is there a differential method (traced vs untraced vs in-VM) and a divergence
    metric? *Fidelity needs a measurement, not an assertion.*
19. **At what granularity is the trace, and is it enough** — syscall entry/exit
    with decoded args, register/memory snapshots, full backtraces, sampled? What
    is dropped under load, and does dropping bias toward or away from the bug?

### Theme 4 — Platform reality (arm64 / macOS / Docker-no-KVM)

20. **What can you measure *today*** on Docker Desktop's aarch64 VM with no KVM
    vs. what is strictly deferred to a bare-metal/KVM host? *Draw the line.*
21. **Architecture-mismatch risk:** targets/exploits/CVEs are often x86-64; you
    are on arm64. Do the bugs even reproduce on aarch64? *May invalidate samples.*
22. **macOS tracers are crippled** (dtrace SIP-restricted, no strace, gdb arm64
    painful). Is macOS purely orchestration, with all tracing in Linux? Then how
    does the host-side agent reach the in-VM tracer? *That split is an
    unspecified, security-relevant interface.*
23. **Docker Desktop's VM is shared and long-lived.** If the sandbox runs inside
    it, is the VM the real boundary, and what contaminates across runs there?

### Theme 5 — Evaluation and rigor (how do you *prove* it)

24. **Prove, don't assert, isolation:** a battery of canary/escape probes
    (network egress, host-file R/W, mount escape, `/proc`+`/sys` reach, PID-ns
    escape, abusing the tracer handle) each **CROSSED-on-weak / CONTAINED-on-
    hardened**. *Otherwise you've tested nothing.*
25. **Does the probe suite attack *through the observability channel*** (hijack
    the ptrace relationship, write memory via a tracer bug, escape via the trace
    transport)? *A generic escape suite won't exercise ARCTIC's novel hole.*
26. **Fidelity metric, numerically:** syscall-sequence divergence traced-vs-
    untraced, crash-address stability, bug-reproduction rate ±tracing, dropped-
    event rate.
27. **Cost numbers:** startup latency, per-syscall overhead, memory, scaling with
    syscall rate. Compatible with an interactive agent loop?
28. **Teardown/cleanup guarantee and how it's verified:** no leftover processes,
    mounts, loop devices, network state, temp files, kernel objects. How is a
    leak detected?
29. **Reproducibility:** same binary+input → same trace/crash/verdict across
    repeats and machines? Which nondeterminism (ASLR, timing, scheduling) is
    controlled or recorded?
30. **Baseline comparator:** against what do you claim the sandbox adds value —
    naked throwaway Docker? plain nsjail? *No control, no measurable contribution.*

### Theme 6 — Scope discipline (don't boil the ocean)

31. **Minimum credible milestone 1:** one sandbox + one tracer + one probe suite
    + one fidelity metric — and does the current LangChain+mock stub exercise the
    hard problem (the tracing hole) or just the plumbing? *The mock tests
    orchestration, not the research question.*
32. **Which single sandbox first,** given the platform? bubblewrap/nsjail
    (unprivileged, no KVM, runs today, shares host kernel) is tractable now;
    gVisor/Firecracker need KVM and add the interposition / VM-boundary tracing
    problems. Sequence: harden namespaces first, escalate to VM later?
33. **Which ONE tracer is primary, and why?** strace (syscalls — ARCTIC's main
    signal) vs gdb (crash/backtrace) vs eBPF (low observer effect, no ptrace) vs
    perf. Each answers a different question with a different security profile.
34. **Is eBPF a better primary than ptrace** — kernel-side, read-mostly, lower
    perturbation, harder to detect, no co-resident ptrace handle to steal? *This
    choice may dissolve or sharpen the central contradiction.*
35. **Is APR in scope for the thesis at all, or deferred?** Pulling it forward
    now starves the sandbox work that is the stated current focus.

### The 5 to answer FIRST

1. **Where does the tracer sit and what is its privilege/TCB vs the target?**
   (Q1–Q3) — nothing else can be reasoned about until this is fixed.
2. **Write the threat model adversarially**, with explicit non-goals and the
   kernel-trust assumption. (Q9–Q14) — decides container-vs-VM.
3. **Does tracing change whether the bug manifests, and what differential method
   proves it doesn't?** (Q15, Q18) — ARCTIC's existence condition.
4. **Pick the minimum credible stack** (bubblewrap/nsjail + one tracer + CROSSED-
   on-weak/CONTAINED-on-hardened probe suite) and make the mock replaceable with
   it. (Q24, Q31–Q33).
5. **Resolve platform reality:** what runs on today's KVM-less aarch64 Docker VM
   vs a KVM host, and does arm64 invalidate x86-centric bug samples? (Q20–Q23).

> Critic's sharpest note: **Q4 + Q5 are the load-bearing risk.** ptrace is not a
> one-way mirror, and gVisor/Firecracker make a host tracer see the wrong layer.
> If we cannot say how the tracer observes the target's *true* behavior without
> handing it a two-way channel or a wrong-layer trace, the "strongly isolating
> yet transparently observable" thesis is not yet defensible. Resolve before
> writing design prose. (§6 is our first answer.)

---

## 3. Sandbox survey, through the tracing lens

### 3.1 bubblewrap (`bwrap`) — unprivileged namespaces

- **Mechanism (Fact).** One command in fresh Linux namespaces; root is a tmpfs
  invisible to the host, built only from caller-requested binds; always a new
  mount ns and `NO_NEW_PRIVS`; PID/net/IPC/UTS/cgroup unshare, seccomp, and env
  cleanup are opt-in (`../BUBBLEWRAP.md` §1, `../bubblewrap/bubblewrap.c:3058,
  2928-2930`).
- **Isolation boundary.** Shares the **host kernel**. Security is "only as good
  as the arguments passed"; it is explicitly *not* a privilege boundary between
  user and OS (`../bubblewrap/SECURITY.md:7-9,27-29`). One kernel 0-day defeats
  it (answers Q14 for this class).
- **Tracing fit.** Because the target runs as an ordinary host process (just
  namespaced), a **host-side tracer in the same or a parent namespace can
  ptrace/strace it directly** — the target's syscalls *are* host syscalls. This
  is the cleanest match for "host tool traces the inner program." Caveats: the
  tracer must sit outside the target's seccomp/ptrace restrictions; if the
  sandbox blocks `ptrace` for the target (good: stops anti-debug) the external
  tracer can still attach because the filter applies to the target, not the
  parent. Yama `ptrace_scope` governs cross-process attach (Q7).
- **Verdict.** Best *baseline-real* backend: runs unprivileged today on the
  aarch64 VM, and the tracer story is simplest. Weakest containment (shared
  kernel). This is the milestone-1 target (Q32).

### 3.2 gVisor (`runsc`) — user-space application kernel

- **Mechanism (Fact).** An application kernel (the **Sentry**) reimplements the
  Linux syscall interface in memory-safe Go and runs in user space. **gVisor
  never passes a syscall through to the host**; `getpid` etc. are serviced inside
  the Sentry (`../gvisor/g3doc/architecture_guide/intro_to_gvisor.md:100-133`).
  Interception uses the **systrap** platform (`seccomp` `SECCOMP_RET_TRAP` →
  `SIGSYS` → Sentry), default since mid-2023; **KVM** platform on bare metal;
  legacy **ptrace** platform (`PTRACE_SYSEMU`) deprecated
  (`../gvisor/g3doc/architecture_guide/platforms.md:51-77`).
- **Isolation boundary.** Dual-kernel: to escape, an attacker must break the
  Sentry *and* the host kernel, which share no code
  (`intro_to_gvisor.md:149-151`). Does **not** protect against Spectre-class side
  channels or exploits *within* the workload (`:183-202`).
- **Tracing fit — the Q5 answer.** A **host `strace` on the `runsc` process sees
  the Sentry's host syscalls, not the target's** — semantically wrong for ARCTIC.
  The right source is **gVisor's own introspection**, which is a first-class
  feature:
  - `runsc --strace` logs the sandboxed app's syscalls *from inside the Sentry*
    (`../gvisor/runsc/config/config.go:227-240`: `strace`, `strace-syscalls`,
    `strace-log-size`, `strace-event`).
  - The **`seccheck` / runtime-monitoring** trace-point API streams structured
    syscall/lifecycle events to an external monitor
    (`../gvisor/pkg/sentry/seccheck/`, `g3doc/user_guide/runtime_monitoring.md`).
  - **Inference.** For gVisor the Sentry *is* the tracer, and it is the trust
    boundary: observation is read-only, target-semantic, and needs no co-resident
    ptrace handle to steal (directly favorable for Q2–Q4, Q34). The cost is that
    the trace format is gVisor's, not a drop-in `strace`/`gdb` artifact, so the
    Tracing-Module ADT must normalize it.
- **Platform reality.** systrap needs no virtualization → **can run inside Docker
  Desktop's aarch64 VM** (unlike KVM). Promising for Part-1 if `runsc` installs
  there (Q20).

### 3.3 Firecracker — microVM (KVM)

- **Mechanism (Fact/Inference).** A minimal VMM over KVM; a real guest kernel in
  a hardware-isolated VM; boots in ~100 ms with a tiny device model. Strongest
  of the three boundaries (true VM exit).
- **Tracing fit — the Q6 answer.** **ptrace and `/proc/<pid>/mem` do not cross
  the VM boundary.** Observability requires an **in-guest agent** (an in-VM
  strace/gdb/eBPF, or a kernel-side tracer) whose output is exfiltrated over
  **vsock / serial / shared memory**. That transport and the in-guest agent are a
  whole subsystem with their own TCB — "use a VM" is not free observability.
- **Platform reality.** Needs **KVM**, which Docker Desktop on Apple Silicon does
  **not** expose → **deferred to a real KVM host** (Stage B). Do not claim it now.

### 3.4 nsjail — hardened namespace launcher

- **Mechanism (Inference/known).** Like bubblewrap but policy-forward: namespaces
  + seccomp-bpf + rlimits + cgroups with a declarative config, built for running
  untrusted code (CTF/judge systems). Shares the host kernel like bwrap.
- **Tracing fit.** Same as bubblewrap — host-side ptrace/strace works because the
  target is a namespaced host process. Useful as the **weak-vs-hardened
  comparator** (Q30): nsjail-default vs nsjail-hardened gives a clean probe
  gradient.

### 3.5 runc / Docker — OCI container runtime

- **Mechanism.** namespaces + cgroups + seccomp + capabilities, orchestrated. The
  current evidence set (`../BUBBLEWRAP.md` era) was gathered in the Docker
  stand-in. Shares the host kernel.
- **Tracing fit.** `docker run --cap-add=SYS_PTRACE --security-opt seccomp=...`
  lets a tracer inside the container work; from outside, the container is host
  processes in namespaces, so host-side tracing works given `ptrace_scope` and
  caps. Docker is the natural **Stage-A stand-in** (no containment *claim*), and
  the Docker Desktop VM is itself a boundary to audit (Q23).

### 3.6 Comparison on the tracing axis

| Sandbox | Boundary | Shares host kernel | Where the tracer sits | Target's real syscalls visible to a *host* tracer? | Runs on KVM-less aarch64 VM today |
|---|---|---|---|---|---|
| bubblewrap | namespaces+seccomp | **yes** | host, parent ns (ptrace/strace) | **yes**, directly | **yes** |
| nsjail | namespaces+seccomp | **yes** | host, parent ns | **yes**, directly | **yes** |
| runc/Docker | namespaces+seccomp+caps | **yes** | host ns, or in-container | yes (with caps/`ptrace_scope`) | **yes** (Stage-A stand-in) |
| gVisor | user-space kernel | no (dual-kernel) | **inside the Sentry** (`--strace`/seccheck) | **no** — host sees the Sentry; use Sentry introspection | **yes** (systrap) — if `runsc` installs |
| Firecracker | microVM (KVM) | no (guest kernel) | **in-guest agent** → vsock/serial | **no** — needs in-guest tracing + transport | **no** (needs KVM) → Stage B |

---

## 4. Key findings → design implications for Agentbox

1. **The tracer's position is per-mechanism, not global (Q1).** Namespace
   sandboxes allow a host-side tracer (clean ARCTIC match); gVisor and microVMs
   force the tracer *inward* (Sentry introspection / in-guest agent). The Tracing
   Module ADT must therefore abstract over "where the trace comes from" and
   normalize formats — the agent must not care.
2. **"One-way observability" is only truly clean when the tracer is read-only and
   lives at or above the boundary (Q4).** ptrace is two-way; gVisor's seccheck
   and eBPF are read-mostly. This argues for **eBPF/gVisor-introspection as the
   primary fidelity path** and ptrace/gdb as an opt-in crash-state path with a
   stated observer-effect caveat.
3. **Container-vs-VM is decided by the kernel-trust assumption (Q14).** If we
   accept "host kernel trusted and patched" as residual risk, namespace sandboxes
   suffice for Part-1; malicious-ELF-with-kernel-LPE in scope ⇒ microVM (Stage B).
4. **Milestone 1 is bubblewrap + one tracer + a probe suite (Q31–Q33).** The mock
   here tests plumbing only; the first *real* backend must deliberately hit the
   tracing hole. Primary tracer: **strace** (ARCTIC's core syscall signal) with
   **gdb** for crash state; evaluate **eBPF** as the lower-observer-effect option.
5. **Platform line (Q20).** Today on aarch64 Docker-no-KVM: bubblewrap/nsjail/
   Docker + strace/gdb, and possibly gVisor-systrap. Deferred to a KVM host:
   Firecracker, gVisor-KVM, and any claim needing hardware virtualization.

---

## 5. Open decisions (carried into PRD §Decisions)

| ID | Question | Leaning |
|---|---|---|
| R1 | First real backend | **bubblewrap** (unprivileged, host-side tracing, runs today) |
| R2 | Primary tracer | **strace** for syscalls; **gdb** for crash state; **eBPF** evaluated for fidelity |
| R3 | Tracer position | host-side for namespace backends; **Sentry introspection** for gVisor; in-guest agent for microVM |
| R4 | Kernel-trust assumption | trusted+patched for Part-1 (namespace class); revisit for Stage B |
| R5 | Agent in/out of trust boundary | **out**; all trace content is untrusted data, bounded in `agent/tools.py` |
| R6 | arm64 sample validity | open — pick bug samples that reproduce on aarch64, or defer x86 bugs to a KVM x86 host |

---

## 6. First answer to the load-bearing risk (Q4+Q5)

**Claim.** The clean way to get a *true-behavior, one-way* trace is to make the
**boundary itself the tracer**, not to point a two-way host primitive at the
target:

- **Namespace backend (bubblewrap):** the target's syscalls are genuine host
  syscalls, so a host-side, parent-namespace **strace** observes true behavior.
  ptrace is two-way, so we (a) run launch-as-child to avoid the attach race
  (Q8 — implemented in `agentbox/tracing/`), (b) never expose the ptrace handle
  to the target (tracer is the parent, outside the target's seccomp domain), and
  (c) treat the recorded trace as untrusted data (Q3, Q13).
- **gVisor backend:** do **not** host-strace. Use `runsc --strace` / seccheck,
  where the Sentry reports the target's *own* syscalls read-only — target-
  semantic and one-way by construction.
- **microVM backend:** an in-guest read-only agent (eBPF/strace) streams over
  vsock; the host never ptraces across the boundary.

This is a hypothesis to be *measured* by the fidelity method (Q18, Q26):
differential syscall-sequence divergence traced-vs-untraced-vs-in-VM, crash-
address stability, and bug-reproduction rate ±tracing. The attack-model suite
(Q24–Q25) must include probes **through the observability channel**, not only
generic escapes.

### 6.1 Verified on our own NsSandbox (native x86_64 Linux, 2026-10-26)

The hypothesis above was tested against our namespace backend (`abx_init`), and
the implementation now in `agentbox/sandbox/ns.py` follows what worked:

| Approach | Result | Decision |
|---|---|---|
| **host-side `strace -f`** following the clone into the **fully hardened** sandbox | **WORKS** — captured the target's own syscalls (`execve("/app/target")` → … → `write`), even though the hardened seccomp denies the *target's* ptrace. The host tracer's ptrace is a host-side call, unaffected by the target's filter. | **strace = host-side**, hardened policy unchanged. Trace file lives on the host, outside the sandbox → one-way by construction. |
| **host-side `gdb`** with `follow-fork-mode child` across the user+PID-namespace clone | **HANGS** (tracee stuck in `t`/traced state). gdb cannot cleanly follow a fork that creates new user/PID namespaces. | **Do not** host-gdb a namespace sandbox. |
| **in-sandbox `gdb`** (tracer runs as the target's parent *inside* the sandbox, tooled rootfs of read-only host `/usr`,`/lib`,…) writing to an exported `/out` | **WORKS** — produced the exact crash localization (`SIGSEGV in clobber() at :13`, full backtrace to `main`, `p = 0x0`). ptrace within the same namespace needs no cross-ns follow. | **gdb = in-sandbox**, `traced` policy (ptrace permitted under seccomp), backtrace exported one-way via `/out`. |

**The isolation↔observability trade-off, quantified.** The `traced` policy differs
from `hardened` by **exactly one restriction**: seccomp permits `ptrace`. Every
other dimension (filesystem, network, PID, memory, fork, UTS, IPC, capabilities,
the rest of the syscall surface) stays contained — verified by
`test_isolation_holds_under_traced_policy`. gdb mode additionally binds the host
toolchain **read-only** (not `/etc`, `/home`, `/root`, `/var`), a narrowed,
documented filesystem relaxation that applies only while tracing a crash.

**One-way guarantees achieved:** the trace flows *out* (host strace file, or the
`/out` bind for gdb); the target cannot read the host's analysis copy or tamper
with it; and for strace the tracer lives entirely outside the sandbox. This is
ARCTIC's runtime-context channel, working on a contained target.

---

## 7. References

- `../bubblewrap/` (v0.13.0) and `../BUBBLEWRAP.md` — bubblewrap mechanism.
- `../gvisor/g3doc/architecture_guide/{intro_to_gvisor,platforms,security}.md` —
  gVisor architecture and security model.
- `../gvisor/runsc/config/config.go`, `../gvisor/pkg/sentry/seccheck/`,
  `../gvisor/g3doc/user_guide/runtime_monitoring.md` — gVisor native tracing.
- Firecracker (NSDI'20), gVisor architecture docs, Yama LSM, rr (ATC'17) — to be
  cited precisely as used (see `../MM/THESIS_CONTEXT.md` §8 reading list).
