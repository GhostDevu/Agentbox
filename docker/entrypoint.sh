#!/usr/bin/env bash
# Best-effort cgroup v2 delegation so abx_init can set pids.max/memory.max, then
# run the command. Move this shell to a leaf, enable +pids/+memory in the now
# process-free root, and make an "abx" parent for per-run children. Must run in
# the main shell (a subshell PID would block the subtree_control write); no-ops
# on a read-only cgroup fs, where abx_init falls back to rlimits.
CG=/sys/fs/cgroup
if mkdir "$CG/.wt" 2>/dev/null; then
    rmdir "$CG/.wt" 2>/dev/null
    mkdir -p "$CG/init"
    # move every root process (this shell included) into the leaf; no forks.
    while read -r p; do echo "$p" > "$CG/init/cgroup.procs" 2>/dev/null; done < "$CG/cgroup.procs"
    if echo "+pids +memory" > "$CG/cgroup.subtree_control" 2>/dev/null; then
        mkdir -p "$CG/abx"
        echo "+pids +memory" > "$CG/abx/cgroup.subtree_control" 2>/dev/null
        export AGENTBOX_CGROUP_PARENT="$CG/abx"
        echo "[entrypoint] cgroup parent delegated: $CG/abx" >&2
    fi
fi
[ -z "${AGENTBOX_CGROUP_PARENT:-}" ] && \
    echo "[entrypoint] no writable/delegable cgroup; sandbox uses rlimits only" >&2

exec "$@"
