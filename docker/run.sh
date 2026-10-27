#!/usr/bin/env bash
# Build the dev image and run a command inside it with the Agentbox tree mounted.
#
#   docker/run.sh                      # -> runs scripts/ns_demo.py
#   docker/run.sh python scripts/smoke.py
#   docker/run.sh bash                 # interactive shell
#
# Notes on the flags:
# Why --privileged for the OUTER container (the sandbox stays unprivileged):
#   * Docker's default seccomp profile blocks clone(CLONE_NEWUSER) and its
#     masked /proc trips the kernel's mount_too_revealing check on a nested
#     procfs; and its cgroup v2 fs is mounted read-only, so cgroup pids.max /
#     memory.max cannot be delegated.
#   * --privileged lifts all three, emulating an ordinary Linux VM where the
#     sandbox launcher can set up namespaces and delegate cgroups. abx_init
#     itself still runs unprivileged: user namespace, all capabilities dropped,
#     NO_NEW_PRIVS and a seccomp filter. On a real VM none of these flags are
#     needed. (For a namespaces-only demo without cgroup limits, the lighter
#     "--security-opt seccomp=unconfined,systempaths=unconfined" suffices.)
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"   # Agentbox/
img="agentbox-dev"

docker build -t "$img" -f "$here/docker/Dockerfile" "$here/docker" >/dev/null

cmd=("$@")
if [ ${#cmd[@]} -eq 0 ]; then
    cmd=(python3 scripts/ns_demo.py)
fi

exec docker run --rm -it \
    --privileged \
    -v "$here":/work \
    -w /work \
    "$img" "${cmd[@]}"
