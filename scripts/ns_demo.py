"""Demonstrate the NsSandbox containment gradient across every dimension (Linux).

Runs each canary probe under the WEAK policy (expect CROSSED) and the HARDENED
policy (expect CONTAINED). This is the probe-validity check from PRD §7: a probe
is only meaningful if it crosses on weak and is contained on hardened.

Run inside the Linux VM / Docker:
    python scripts/ns_demo.py
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agentbox.sandbox import CodeObject, RunSpec, hardened, weak  # noqa: E402
from agentbox.sandbox.base import Language  # noqa: E402
from agentbox.sandbox.ns import NsSandbox  # noqa: E402

PROBES = [
    ("filesystem: host-file read", "examples/probes/host_file.c"),
    ("filesystem: root write    ", "examples/probes/fs_write.c"),
    ("network: egress           ", "examples/probes/net_egress.c"),
    ("process: PID namespace     ", "examples/probes/proc_vis.c"),
    ("process: fork limit        ", "examples/probes/fork_limit.c"),
    ("memory: allocation limit   ", "examples/probes/mem_limit.c"),
    ("uts: hostname              ", "examples/probes/uts_host.c"),
    ("syscalls: seccomp (ptrace) ", "examples/probes/seccomp_ptrace.c"),
]


def run_one(policy, src_path):
    sb = NsSandbox(policy=policy)
    with open(src_path) as fh:
        code = fh.read()
    res = sb.run(RunSpec(code=CodeObject(language=Language.C, source=code), tracer="none"))
    out = (res.stdout or res.stderr or "(no output)").strip().splitlines()
    return res, (out[-1] if out else "(no output)")


def main():
    print("NsSandbox containment gradient (containment_level=namespaces)\n")
    for label, src in PROBES:
        print(f"### {label.strip()}")
        for policy in (weak(), hardened()):
            res, out = run_one(policy, src)
            sig = f" sig={res.signal}" if res.signal else ""
            print(f"  [{policy.name:8}] rc={res.exit_code}{sig}  {out}")
        print()


if __name__ == "__main__":
    main()
