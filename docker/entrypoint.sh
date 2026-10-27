#!/usr/bin/env bash
# Container entrypoint: set up a delegated, controller-enabled cgroup v2 parent
# for the sandbox (best-effort), then run the requested command.
#
# cgroup v2 forbids a non-root cgroup from having both member processes and
# enabled subtree controllers. A container's cgroup is non-root, so to let
# abx_init create per-run child cgroups with pids.max/memory.max we must move
# this shell out of the cgroup root into a leaf, enable +pids/+memory in the now
# process-free root, and create an "abx" parent with controllers for ITS
# children. This MUST run in the main shell (no command substitution): a
# subshell's own PID would linger in the root and block the subtree_control
# write. On a read-only cgroup fs this just no-ops and abx_init uses rlimits.
CG=/sys/fs/cgroup
if mkdir "$CG/.wt" 2>/dev/null; then
    rmdir "$CG/.wt" 2>/dev/null
    mkdir -p "$CG/init"
    # move every process in the cgroup root (this shell included) into the leaf;
    # the loop body is a builtin, so it forks nothing into the root.
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
