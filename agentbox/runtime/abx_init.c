/*
 * abx_init: Agentbox's minimal container-init (Linux only).
 *
 * Runs a target under namespaces + pivot_root + read-only root + no network +
 * dropped caps + NO_NEW_PRIVS + rlimits + best-effort cgroup v2 + a seccomp-bpf
 * deny filter. Each dimension toggles independently (--X / --no-X) so the
 * presets can build a weak-vs-hardened gradient. Compiled by sandbox/ns.py.
 *
 * Usage: abx_init [flags] -- PROG [ARG...]   (flags: see the parser in main())
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#if defined(__x86_64__)
#define ABX_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define ABX_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#define ABX_AUDIT_ARCH 0
#endif

/* ---- options ---------------------------------------------------------- */
#define ABX_MAX_BINDS 32
struct opts {
    const char *rootfs, *hostname, *cgroup_parent, *out_dir;
    int userns, pidns, ipcns, utsns, cgroupns, netns; /* 1 = isolate */
    int pivot, ro_root, limits, cgroup, seccomp, allow_ptrace;
    const char *bind_src[ABX_MAX_BINDS], *bind_dst[ABX_MAX_BINDS];
    int nbinds;
    long cpu_s, mem_mb, nproc, fsize_mb, nofile, pids_max;
    char **prog_argv;
};

static void die(const char *msg) {
    fprintf(stderr, "abx_init: %s: %s\n", msg, strerror(errno));
    exit(127);
}
static void warnf(const char *msg) {
    fprintf(stderr, "abx_init: warning: %s: %s (continuing)\n", msg, strerror(errno));
}

static int write_file_soft(const char *path, const char *data) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int rc = (write(fd, data, strlen(data)) < 0) ? -1 : 0;
    close(fd);
    return rc;
}
static void write_file(const char *path, const char *data) {
    if (write_file_soft(path, data) < 0) die(path);
}

/* ---- mkdir -p (create a directory and all parents) -------------------- */
static void mkdir_p(const char *path) {
    char tmp[512];
    snprintf(tmp, sizeof tmp, "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') { *p = 0; mkdir(tmp, 0755); *p = '/'; }
    }
    mkdir(tmp, 0755);
}

/* ---- seccomp: deny the dangerous syscall surface ---------------------- */
/* Built at runtime so tracing mode can keep ptrace: check arch, then one
 * (JEQ -> RET EPERM) pair per denied nr, else fall through to RET ALLOW. */
static void install_seccomp(int allow_ptrace) {
#if ABX_AUDIT_ARCH == 0
    (void)allow_ptrace;
    return; /* unknown build arch: skip rather than risk killing everything */
#else
    int deny[] = {
#ifdef __NR_ptrace
        __NR_ptrace,  /* index 0: dropped when allow_ptrace */
#endif
#ifdef __NR_bpf
        __NR_bpf,
#endif
#ifdef __NR_perf_event_open
        __NR_perf_event_open,
#endif
#ifdef __NR_kexec_load
        __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
        __NR_kexec_file_load,
#endif
#ifdef __NR_init_module
        __NR_init_module,
#endif
#ifdef __NR_finit_module
        __NR_finit_module,
#endif
#ifdef __NR_delete_module
        __NR_delete_module,
#endif
#ifdef __NR_add_key
        __NR_add_key,
#endif
#ifdef __NR_keyctl
        __NR_keyctl,
#endif
#ifdef __NR_request_key
        __NR_request_key,
#endif
#ifdef __NR_mount
        __NR_mount,
#endif
#ifdef __NR_umount2
        __NR_umount2,
#endif
#ifdef __NR_pivot_root
        __NR_pivot_root,
#endif
#ifdef __NR_setns
        __NR_setns,
#endif
#ifdef __NR_unshare
        __NR_unshare,
#endif
#ifdef __NR_reboot
        __NR_reboot,
#endif
#ifdef __NR_swapon
        __NR_swapon,
#endif
#ifdef __NR_swapoff
        __NR_swapoff,
#endif
#ifdef __NR_settimeofday
        __NR_settimeofday,
#endif
#ifdef __NR_clock_settime
        __NR_clock_settime,
#endif
#ifdef __NR_mknodat
        __NR_mknodat,
#endif
    };
    int ndeny = (int)(sizeof deny / sizeof deny[0]);

    struct sock_filter f[128];
    int n = 0;
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ABX_AUDIT_ARCH, 1, 0);
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    f[n++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    for (int i = 0; i < ndeny; i++) {
#ifdef __NR_ptrace
        if (allow_ptrace && deny[i] == __NR_ptrace) continue; /* tracing mode */
#endif
        f[n++] = (struct sock_filter)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, deny[i], 0, 1);
        f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA));
    }
    f[n++] = (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);

    struct sock_fprog prog = {.len = (unsigned short)n, .filter = f};
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0) < 0)
        warnf("seccomp");
#endif
}

/* ---- child: becomes the sandbox init ---------------------------------- */
struct child_ctx {
    struct opts *o;
    int sync_rfd;
};

static void setup_dev(void) {
    if (mount("dev", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755") < 0) {
        warnf("mount /dev tmpfs");
        return;
    }
    const char *nodes[] = {"null", "zero", "full", "random", "urandom", "tty", NULL};
    for (int i = 0; nodes[i]; i++) {
        char dst[256], src[256];
        snprintf(dst, sizeof dst, "/dev/%s", nodes[i]);
        snprintf(src, sizeof src, "/.oldroot/dev/%s", nodes[i]);
        int fd = open(dst, O_CREAT | O_WRONLY, 0666);
        if (fd >= 0) close(fd);
        mount(src, dst, NULL, MS_BIND, NULL); /* best-effort */
    }
}

static void do_mounts(struct opts *o) {
    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0)
        die("make-rprivate");
    if (!o->pivot)
        return; /* weak: keep the host filesystem view */

    if (mount(o->rootfs, o->rootfs, NULL, MS_BIND | MS_REC, NULL) < 0)
        die("bind rootfs");
    if (chdir(o->rootfs) < 0) die("chdir rootfs");
    mkdir(".oldroot", 0777);
    if (syscall(SYS_pivot_root, ".", ".oldroot") < 0) die("pivot_root");
    if (chdir("/") < 0) die("chdir /");

    /* fresh procfs for the pid-ns view; best-effort (a masked /proc can refuse). */
    if (o->pidns &&
        mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) < 0)
        warnf("mount /proc");
    if (mount("tmp", "/tmp", "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=64m") < 0)
        warnf("mount /tmp");
    setup_dev();

    /* read-only binds of host paths (a "tooled" rootfs so in-sandbox gdb can run);
     * sources live under /.oldroot until the old root is detached below. */
    for (int i = 0; i < o->nbinds; i++) {
        char src[600], dst[600];
        snprintf(src, sizeof src, "/.oldroot%s", o->bind_src[i]);
        snprintf(dst, sizeof dst, "%s", o->bind_dst[i]);
        mkdir_p(dst);
        if (mount(src, dst, NULL, MS_BIND | MS_REC, NULL) == 0)
            mount(NULL, dst, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
        else
            warnf("bind-ro");
    }
    /* one-way export channel: a host dir mounted rw at /out for the tracer. */
    if (o->out_dir) {
        char src[600];
        snprintf(src, sizeof src, "/.oldroot%s", o->out_dir);
        mkdir_p("/out");
        if (mount(src, "/out", NULL, MS_BIND | MS_REC, NULL) < 0)
            warnf("out-dir bind");
    }

    if (umount2("/.oldroot", MNT_DETACH) < 0) die("umount oldroot");
    rmdir("/.oldroot");

    if (o->ro_root) {
        /* non-recursive: root becomes read-only, /proc,/tmp,/dev stay writable */
        if (mount(NULL, "/", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) < 0)
            die("remount ro");
    }
}

static void set_limits(struct opts *o) {
    struct rlimit r;
    if (o->cpu_s > 0)    { r.rlim_cur = r.rlim_max = o->cpu_s;               setrlimit(RLIMIT_CPU, &r); }
    if (o->mem_mb > 0)   { r.rlim_cur = r.rlim_max = o->mem_mb * 1024L*1024; setrlimit(RLIMIT_AS, &r); }
    if (o->nproc > 0)    { r.rlim_cur = r.rlim_max = o->nproc;               setrlimit(RLIMIT_NPROC, &r); }
    if (o->fsize_mb > 0) { r.rlim_cur = r.rlim_max = o->fsize_mb * 1024L*1024;setrlimit(RLIMIT_FSIZE, &r); }
    if (o->nofile > 0)   { r.rlim_cur = r.rlim_max = o->nofile;              setrlimit(RLIMIT_NOFILE, &r); }
    r.rlim_cur = r.rlim_max = 0; setrlimit(RLIMIT_CORE, &r);
}

static void drop_caps(void) {
    for (int cap = 0; cap <= CAP_LAST_CAP; cap++)
        prctl(PR_CAPBSET_DROP, cap, 0, 0, 0);
    struct __user_cap_header_struct hdr = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2];
    memset(data, 0, sizeof data);
    syscall(SYS_capset, &hdr, data);
}

static int child_main(void *arg) {
    struct child_ctx *ctx = arg;
    struct opts *o = ctx->o;
    char b;
    if (read(ctx->sync_rfd, &b, 1) != 1) _exit(126);
    close(ctx->sync_rfd);

    if (o->utsns && o->hostname && sethostname(o->hostname, strlen(o->hostname)) < 0)
        warnf("sethostname");

    do_mounts(o);
    if (o->limits) set_limits(o);
    drop_caps();
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) die("no_new_privs");

    clearenv();
    setenv("PATH", "/bin:/usr/bin", 1);
    setenv("HOME", "/tmp", 1);

    if (o->seccomp) install_seccomp(o->allow_ptrace); /* last, so setup isn't filtered */

    execv(o->prog_argv[0], o->prog_argv);
    die("execv");
    return 127;
}

/* ---- parent: maps, cgroup, monitor ------------------------------------ */
static void write_maps(pid_t pid) {
    char path[256], line[128];
    snprintf(path, sizeof path, "/proc/%d/setgroups", pid);
    int fd = open(path, O_WRONLY);
    if (fd >= 0) { (void)!write(fd, "deny", 4); close(fd); }
    snprintf(path, sizeof path, "/proc/%d/uid_map", pid);
    snprintf(line, sizeof line, "0 %d 1", getuid());
    write_file(path, line);
    snprintf(path, sizeof path, "/proc/%d/gid_map", pid);
    snprintf(line, sizeof line, "0 %d 1", getgid());
    write_file(path, line);
}

static char g_cgroup[512];

static void setup_cgroup(pid_t pid, struct opts *o) {
    /* Best-effort cgroup v2: make a child cgroup under a controller-enabled
     * parent, set memory.max/pids.max, move the pid in. Fails silently without
     * a writable delegated cgroup; rlimits are the fallback. */
    char base[480] = "";
    if (o->cgroup_parent && o->cgroup_parent[0]) {
        snprintf(base, sizeof base, "%s", o->cgroup_parent);
    } else {
        char sub[400] = "";
        FILE *f = fopen("/proc/self/cgroup", "r");
        if (!f) return;
        char line[400];
        while (fgets(line, sizeof line, f)) {
            if (strncmp(line, "0::", 3) == 0) { strncpy(sub, line + 3, sizeof sub - 1); break; }
        }
        fclose(f);
        sub[strcspn(sub, "\n")] = 0;
        snprintf(base, sizeof base, "/sys/fs/cgroup%s",
                 (sub[0] && strcmp(sub, "/")) ? sub : "");
    }
    snprintf(g_cgroup, sizeof g_cgroup, "%s/abx-%d", base, pid);
    if (mkdir(g_cgroup, 0755) != 0) { g_cgroup[0] = 0; return; }

    char p[600], v[64];
    if (o->mem_mb > 0) {
        snprintf(p, sizeof p, "%s/memory.max", g_cgroup);
        snprintf(v, sizeof v, "%ld", o->mem_mb * 1024L * 1024);
        write_file_soft(p, v);
    }
    if (o->pids_max > 0) {
        snprintf(p, sizeof p, "%s/pids.max", g_cgroup);
        snprintf(v, sizeof v, "%ld", o->pids_max);
        write_file_soft(p, v);
    }
    snprintf(p, sizeof p, "%s/cgroup.procs", g_cgroup);
    snprintf(v, sizeof v, "%d", pid);
    write_file_soft(p, v);
}

static void cleanup_cgroup(void) {
    if (g_cgroup[0]) rmdir(g_cgroup); /* best-effort */
}

static long argl(const char *s) { return strtol(s, NULL, 10); }

int main(int argc, char **argv) {
    struct opts o = {
        .rootfs = NULL, .hostname = "agentbox",
        .userns = 1, .pidns = 1, .ipcns = 1, .utsns = 1, .cgroupns = 1, .netns = 1,
        .pivot = 1, .ro_root = 1, .limits = 1, .cgroup = 1, .seccomp = 1,
        .cpu_s = 10, .mem_mb = 512, .nproc = 64, .fsize_mb = 64, .nofile = 64,
        .pids_max = 64, .prog_argv = NULL,
    };

    int i = 1;
    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
#define TOGGLE(flag, field) \
        else if (!strcmp(a, "--" flag)) o.field = 1; \
        else if (!strcmp(a, "--no-" flag)) o.field = 0;
        TOGGLE("userns", userns)
        TOGGLE("pidns", pidns)
        TOGGLE("ipcns", ipcns)
        TOGGLE("utsns", utsns)
        TOGGLE("cgroupns", cgroupns)
        TOGGLE("netns", netns)
        TOGGLE("pivot", pivot)
        TOGGLE("ro-root", ro_root)
        TOGGLE("limits", limits)
        TOGGLE("cgroup", cgroup)
        TOGGLE("seccomp", seccomp)
        TOGGLE("allow-ptrace", allow_ptrace)
#undef TOGGLE
        else if (!strcmp(a, "--rootfs")) o.rootfs = argv[++i];
        else if (!strcmp(a, "--hostname")) o.hostname = argv[++i];
        else if (!strcmp(a, "--cgroup-parent")) o.cgroup_parent = argv[++i];
        else if (!strcmp(a, "--out-dir")) o.out_dir = argv[++i];
        else if (!strcmp(a, "--bind-ro")) {
            if (o.nbinds >= ABX_MAX_BINDS) { fprintf(stderr, "abx_init: too many --bind-ro\n"); return 2; }
            char *spec = argv[++i];
            char *colon = strchr(spec, ':');
            if (colon) { *colon = 0; o.bind_src[o.nbinds] = spec; o.bind_dst[o.nbinds] = colon + 1; }
            else { o.bind_src[o.nbinds] = spec; o.bind_dst[o.nbinds] = spec; }
            o.nbinds++;
        }
        else if (!strcmp(a, "--cpu")) o.cpu_s = argl(argv[++i]);
        else if (!strcmp(a, "--mem-mb")) o.mem_mb = argl(argv[++i]);
        else if (!strcmp(a, "--nproc")) o.nproc = argl(argv[++i]);
        else if (!strcmp(a, "--fsize-mb")) o.fsize_mb = argl(argv[++i]);
        else if (!strcmp(a, "--nofile")) o.nofile = argl(argv[++i]);
        else if (!strcmp(a, "--pids-max")) o.pids_max = argl(argv[++i]);
        else { fprintf(stderr, "abx_init: unknown option %s\n", a); return 2; }
    }
    if (i >= argc) { fprintf(stderr, "abx_init: no program after --\n"); return 2; }
    o.prog_argv = &argv[i];
    if (o.pivot && !o.rootfs) { fprintf(stderr, "abx_init: --pivot needs --rootfs\n"); return 2; }

    int sync_pipe[2];
    if (pipe(sync_pipe) < 0) die("pipe");

    int flags = SIGCHLD | CLONE_NEWNS; /* mount ns is always ours */
    if (o.userns)   flags |= CLONE_NEWUSER;
    if (o.pidns)    flags |= CLONE_NEWPID;
    if (o.ipcns)    flags |= CLONE_NEWIPC;
    if (o.utsns)    flags |= CLONE_NEWUTS;
    if (o.netns)    flags |= CLONE_NEWNET;
#ifdef CLONE_NEWCGROUP
    if (o.cgroupns) flags |= CLONE_NEWCGROUP;
#endif

    const size_t STACK = 1 << 20;
    char *stack = malloc(STACK);
    if (!stack) die("malloc stack");

    struct child_ctx ctx = {.o = &o, .sync_rfd = sync_pipe[0]};
    pid_t pid = clone(child_main, stack + STACK, flags, &ctx);
    if (pid < 0) {
        fprintf(stderr, "abx_init: clone failed: %s\n", strerror(errno));
        if (errno == EPERM)
            fprintf(stderr, "  (unprivileged user namespaces may be disabled; "
                            "enable them or run with --no-userns as root)\n");
        return 127;
    }

    if (o.userns) write_maps(pid);
    if (o.cgroup) setup_cgroup(pid, &o);
    if (write(sync_pipe[1], "x", 1) != 1) die("sync write");
    close(sync_pipe[1]);
    close(sync_pipe[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) die("waitpid");
    cleanup_cgroup();
    free(stack);

    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}
