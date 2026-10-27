#!/usr/bin/env bash
# Build the dev image and run a command with the Agentbox tree mounted.
#   docker/run.sh                      # -> scripts/ns_demo.py
#   docker/run.sh python scripts/smoke.py
#   docker/run.sh bash                 # interactive shell
#
# --privileged is for the OUTER container only (to emulate a Linux VM with
# writable cgroups and an unmasked /proc); abx_init itself always runs
# unprivileged. On a real VM no flags are needed.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"   # repo root
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
