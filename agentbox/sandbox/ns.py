# Drives abx_init (compiled on first use) to run a target inside Linux namespaces
# with a pivoted read-only root, no network, dropped caps and rlimits. Linux only;
# C targets are compiled static so the rootfs needs only the binary + mountpoints.
"""NsSandbox: the namespace-based sandbox backend."""
from __future__ import annotations

import hashlib
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

from ..config import CONFIG, Limits
from .base import CodeObject, Language, RunResult, RunSpec, Sandbox, TraceArtifact
from .policy import Policy, hardened, traced

_RUNTIME_SRC = os.path.join(os.path.dirname(__file__), "..", "runtime", "abx_init.c")


class NsSandbox(Sandbox):
    name = "ns"
    containment_level = "namespaces"

    def __init__(self, policy: Policy | None = None, limits: Limits | None = None) -> None:
        if not sys.platform.startswith("linux"):
            raise RuntimeError(
                "NsSandbox is Linux-only (needs namespaces/pivot_root). "
                f"This host is {platform.system()}. Run it in the Linux VM/Docker; "
                "use MockSandbox on the dev host."
            )
        self.policy = policy or hardened()
        self.limits = limits or CONFIG.limits
        self._init_bin: str | None = None

    # ---- build the runtime (once, cached by source hash) ------------------
    def _ensure_init(self) -> str:
        if self._init_bin and os.path.exists(self._init_bin):
            return self._init_bin
        src = os.path.abspath(_RUNTIME_SRC)
        with open(src, "rb") as fh:
            digest = hashlib.sha256(fh.read()).hexdigest()[:12]
        os.makedirs(CONFIG.work_root, exist_ok=True)
        out = os.path.join(CONFIG.work_root, f"abx_init-{digest}")
        if not os.path.exists(out):
            cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
            if not cc:
                raise RuntimeError("no C compiler (cc/gcc/clang) to build abx_init")
            proc = subprocess.run(
                [cc, "-O2", "-Wall", "-o", out, src],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"abx_init build failed:\n{proc.stderr}")
        self._init_bin = out
        return out

    # ---- assemble a minimal rootfs for one run ----------------------------
    def _build_rootfs(self, code: CodeObject, rundir: str) -> tuple[str, str, str]:
        """Return (rootfs_dir, in_sandbox_prog_path, host_prog_path)."""
        rootfs = os.path.join(rundir, "rootfs")
        # /app holds the target; gdb mode never binds the host toolchain over it,
        # so the target stays visible even with a tooled rootfs.
        for d in ("proc", "tmp", "dev", "app"):
            os.makedirs(os.path.join(rootfs, d), exist_ok=True)
        prog_in = "/app/target"
        dst = os.path.join(rootfs, "app", "target")

        if code.language == Language.C:
            src = os.path.join(rundir, "target.c")
            self._write(code, src)
            cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
            if not cc:
                raise RuntimeError("no C compiler to build the target")
            proc = subprocess.run(
                [cc, "-static", "-O0", "-g", "-o", dst, src],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"target compile failed:\n{proc.stderr}")
        elif code.language == Language.BINARY:
            if not code.path or not os.path.exists(code.path):
                raise FileNotFoundError(f"binary not found: {code.path}")
            shutil.copyfile(code.path, dst)
            os.chmod(dst, 0o755)
            # A dynamically-linked binary fails in the pivoted rootfs; link static.
        else:
            raise ValueError(
                f"NsSandbox supports C and static BINARY, not {code.language}"
            )
        return rootfs, prog_in, os.path.abspath(dst)

    @staticmethod
    def _write(code: CodeObject, dst: str) -> None:
        if code.source is not None:
            with open(dst, "w") as fh:
                fh.write(code.source)
        elif code.path is not None:
            shutil.copyfile(code.path, dst)
        else:
            raise ValueError("CodeObject has neither source nor path")

    # ---- run --------------------------------------------------------------
    def run(self, spec: RunSpec) -> RunResult:
        init_bin = self._ensure_init()
        os.makedirs(CONFIG.work_root, exist_ok=True)
        rundir = tempfile.mkdtemp(prefix=f"ns-{uuid.uuid4().hex[:8]}-", dir=CONFIG.work_root)
        timeout = spec.timeout_s or self.limits.wall_timeout_s
        try:
            rootfs, prog_in, prog_host = self._build_rootfs(spec.code, rundir)
            # In-rootfs path under pivot; host path when weak policy keeps the host FS.
            prog = prog_in if self.policy.pivot else prog_host
            policy_args = list(self.policy.to_args(rootfs))
            # Optional cgroup v2 parent for pids.max/memory.max; abx_init falls
            # back to rlimits when it is absent or not writable.
            cg_parent = os.environ.get("AGENTBOX_CGROUP_PARENT")
            if cg_parent:
                policy_args += ["--cgroup-parent", cg_parent]
            sandbox_argv = [init_bin, *policy_args, "--", prog, *spec.argv]

            # One-way tracing: the host-side tracer is abx_init's parent, so its
            # trace file is on the host and strace -f still records the target's
            # syscalls (seccomp restricts the target, not an external tracer).
            tracer = (spec.tracer or "none").lower()
            trace_file = None
            trace_note = ""
            launch = sandbox_argv
            if tracer in ("strace", "auto"):
                straceb = shutil.which("strace")
                if straceb:
                    trace_file = os.path.join(rundir, "trace.strace")
                    launch = [straceb, "-f", "-tt", "-T", "-s", "256",
                              "-o", trace_file, "--", *sandbox_argv]
                elif tracer == "strace":
                    trace_note = "strace requested but not installed; ran untraced"
            elif tracer == "gdb":
                trace_note = ("gdb crash-tracing uses the in-sandbox tracer path "
                              "(run via NsSandbox.trace_gdb); not wired into run()")
            elif tracer not in ("none",):
                trace_note = f"tracer {tracer!r} not supported; ran untraced"

            start = time.monotonic()
            timed_out = False
            try:
                proc = subprocess.run(
                    launch, input=spec.stdin, capture_output=True, text=True,
                    timeout=timeout, env={"PATH": os.environ.get("PATH", "")},
                )
                rc = proc.returncode
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                rc = None
                stdout = _text(exc.stdout)
                stderr = _text(exc.stderr)
            duration = time.monotonic() - start

            # abx_init maps a signalled target to 128+signo; recover the signal.
            exit_code: int | None = rc
            term_signal: int | None = None
            if rc is not None and rc > 128:
                term_signal = rc - 128
                exit_code = None

            if trace_file and os.path.exists(trace_file):
                trace = self._collect_strace(trace_file, prog)
            else:
                trace = TraceArtifact(
                    tracer="none", raw_path=None, summary="",
                    note=trace_note or "no tracer (containment-only run)")

            return RunResult(
                exit_code=exit_code,
                stdout=_bound(stdout, self.limits.max_output_bytes),
                stderr=_bound(stderr, self.limits.max_output_bytes),
                duration_s=round(duration, 4),
                timed_out=timed_out,
                trace=trace,
                sandbox=self.name,
                containment_level=self.containment_level,
                signal=term_signal,
                meta={"policy": self.policy.name, "rundir": rundir, "argv": sandbox_argv},
            )
        finally:
            shutil.rmtree(rundir, ignore_errors=True)

    # ---- trace collection -------------------------------------------------
    def _collect_strace(self, path: str, prog: str) -> TraceArtifact:
        """Keep only the target pid's syscalls from a `strace -f` log, bounded."""
        with open(path, errors="replace") as fh:
            lines = fh.readlines()
        # Match the execve whose program is the target, not abx_init's own execve
        # line (which merely lists the path among its arguments).
        needle = f'execve("{prog}"'
        target_pid = None
        start = 0
        for i, ln in enumerate(lines):
            if needle in ln:
                head = ln.split(None, 1)
                if head and head[0].isdigit():
                    target_pid = head[0]
                    start = i  # drop abx_init's setup syscalls before the exec
                    break
        if target_pid:
            # The pid survives execve, so the target's syscalls are this pid's
            # lines from the target execve onward.
            kept = [ln for ln in lines[start:]
                    if (ln.split(None, 1)[:1] or [""])[0] == target_pid]
            note = f"target pid {target_pid}; {len(kept)} syscall lines from execve"
        else:
            kept = lines
            note = "target execve not found; full trace"
        data = "".join(kept).encode("utf-8", "replace")
        cap = self.limits.max_trace_summary_bytes
        truncated = len(data) > cap
        summary = data[:cap].decode("utf-8", "replace")
        if truncated:
            summary += f"\n...[trace truncated, {len(data)} bytes total]"
        return TraceArtifact(tracer="strace", raw_path=None, summary=summary,
                             truncated=truncated, note=note)

    # Read-only host paths that make gdb runnable in-sandbox; deliberately not
    # /etc, /home, /root, /var. A narrowed FS relaxation for gdb mode only.
    DEFAULT_TOOL_BINDS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")

    def trace_gdb(self, spec: RunSpec, tool_binds=None) -> RunResult:
        """Run the target under in-sandbox gdb and export its crash backtrace via /out.

        Host gdb hangs following a fork across new user/PID namespaces, so gdb runs
        in-guest under the `traced` policy with the host toolchain bound read-only."""
        init_bin = self._ensure_init()
        os.makedirs(CONFIG.work_root, exist_ok=True)
        rundir = tempfile.mkdtemp(prefix=f"gdb-{uuid.uuid4().hex[:8]}-", dir=CONFIG.work_root)
        timeout = spec.timeout_s or self.limits.wall_timeout_s
        try:
            rootfs, prog_in, _ = self._build_rootfs(spec.code, rundir)
            outdir = os.path.join(rundir, "out")
            os.makedirs(outdir, exist_ok=True)

            args = list(traced().to_args(rootfs))
            cg_parent = os.environ.get("AGENTBOX_CGROUP_PARENT")
            if cg_parent:
                args += ["--cgroup-parent", cg_parent]
            for b in (tool_binds or self.DEFAULT_TOOL_BINDS):
                if os.path.exists(b):
                    args += ["--bind-ro", b]
            args += ["--out-dir", os.path.abspath(outdir)]

            gdb_path = shutil.which("gdb") or "/usr/bin/gdb"
            gdb_cmd = [
                gdb_path, "-q", "-batch", "-nx",
                "-ex", "set pagination off",
                "-ex", "set logging file /out/gdb.txt",
                "-ex", "set logging enabled on",
                "-ex", "run",
                "-ex", "echo \\n==BACKTRACE==\\n",
                "-ex", "bt full",
                "-ex", "echo \\n==REGISTERS==\\n",
                "-ex", "info registers",
                "-ex", "quit",
                "--args", prog_in, *spec.argv,
            ]
            argv = [init_bin, *args, "--", *gdb_cmd]

            start = time.monotonic()
            timed_out = False
            try:
                proc = subprocess.run(
                    argv, input=spec.stdin, capture_output=True, text=True,
                    timeout=timeout, env={"PATH": os.environ.get("PATH", "")},
                )
                rc = proc.returncode
                stdout, stderr = proc.stdout, proc.stderr
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                rc = None
                stdout = _text(exc.stdout)
                stderr = _text(exc.stderr)
            duration = time.monotonic() - start

            gdb_out = os.path.join(outdir, "gdb.txt")
            if os.path.exists(gdb_out) and os.path.getsize(gdb_out) > 0:
                with open(gdb_out, errors="replace") as fh:
                    raw = fh.read()
                note = "in-sandbox gdb backtrace exported via /out"
            else:
                raw = stdout
                note = "no /out/gdb.txt; falling back to gdb stdout"
            data = raw.encode("utf-8", "replace")
            cap = self.limits.max_trace_summary_bytes
            trunc = len(data) > cap
            summary = data[:cap].decode("utf-8", "replace") + (
                f"\n...[truncated, {len(data)} bytes]" if trunc else "")

            return RunResult(
                exit_code=(None if (rc is not None and rc > 128) else rc),
                stdout=_bound(stdout, self.limits.max_output_bytes),
                stderr=_bound(stderr, self.limits.max_output_bytes),
                duration_s=round(duration, 4),
                timed_out=timed_out,
                trace=TraceArtifact(tracer="gdb", raw_path=None, summary=summary,
                                    truncated=trunc, note=note),
                sandbox=self.name,
                containment_level=self.containment_level,
                signal=None,
                meta={"policy": "traced", "rundir": rundir},
            )
        finally:
            shutil.rmtree(rundir, ignore_errors=True)

    def open_gdb(self, spec: RunSpec, tool_binds=None, default_timeout: float = 10.0):
        """Open an interactive gdb session an external agent drives over a host pty.

        gdb runs in the sandbox (its DWARF parser stays contained); the returned
        GdbSession lives on the host. Caller owns it: context manager or .close()."""
        import pty

        init_bin = self._ensure_init()
        os.makedirs(CONFIG.work_root, exist_ok=True)
        rundir = tempfile.mkdtemp(prefix=f"gdbses-{uuid.uuid4().hex[:8]}-", dir=CONFIG.work_root)
        try:
            rootfs, prog_in, _ = self._build_rootfs(spec.code, rundir)
            outdir = os.path.join(rundir, "out")
            os.makedirs(outdir, exist_ok=True)

            args = list(traced().to_args(rootfs))
            cg_parent = os.environ.get("AGENTBOX_CGROUP_PARENT")
            if cg_parent:
                args += ["--cgroup-parent", cg_parent]
            for b in (tool_binds or self.DEFAULT_TOOL_BINDS):
                if os.path.exists(b):
                    args += ["--bind-ro", b]
            args += ["--out-dir", os.path.abspath(outdir)]

            gdb_path = shutil.which("gdb") or "/usr/bin/gdb"
            gdb_cmd = [gdb_path, "-q", "-nx", "--args", prog_in, *spec.argv]
            argv = [init_bin, *args, "--", *gdb_cmd]

            master, slave = pty.openpty()
            proc = subprocess.Popen(
                argv, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                env={"PATH": os.environ.get("PATH", ""), "TERM": "dumb"},
            )
            os.close(slave)
            sess = GdbSession(proc, master, rundir, default_timeout)
            sess._read_until_prompt(default_timeout)   # consume banner + prompt
            sess.command("set pagination off")          # or long output blocks
            sess.command("set confirm off")
            return sess
        except Exception:
            shutil.rmtree(rundir, ignore_errors=True)
            raise


class GdbSession:
    """A live gdb session driven over a host pty; the sandboxed gdb is at the slave end."""

    PROMPT = b"(gdb)"

    def __init__(self, proc, master_fd, rundir, default_timeout=10.0):
        self._p = proc
        self._fd = master_fd
        self._rundir = rundir
        self._timeout = default_timeout
        self._closed = False

    def _read_until_prompt(self, timeout):
        import select
        import time
        buf = b""
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            r, _, _ = select.select([self._fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(self._fd, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if buf.rstrip().endswith(self.PROMPT):
                    break
        return buf.decode("utf-8", "replace")

    def command(self, cmd: str, timeout: float | None = None) -> str:
        """Send one gdb command and return its output (echo and trailing prompt stripped)."""
        if self._closed:
            raise RuntimeError("gdb session is closed")
        os.write(self._fd, (cmd + "\n").encode())
        out = self._read_until_prompt(timeout or self._timeout)
        lines = out.splitlines()
        if lines and lines[0].strip() == cmd.strip():
            lines = lines[1:]                       # drop the terminal echo
        text = "\n".join(lines)
        idx = text.rfind("(gdb)")
        if idx != -1:
            text = text[:idx]
        return text.strip("\r\n")

    # convenience wrappers an agent can call directly
    def brk(self, loc: str) -> str: return self.command(f"break {loc}")
    def run(self, timeout: float | None = None) -> str: return self.command("run", timeout)
    def cont(self, timeout: float | None = None) -> str: return self.command("continue", timeout)
    def step(self) -> str: return self.command("step")
    def next(self) -> str: return self.command("next")
    def finish(self) -> str: return self.command("finish")
    def backtrace(self) -> str: return self.command("bt")
    def print_(self, expr: str) -> str: return self.command(f"print {expr}")
    def examine(self, expr: str) -> str: return self.command(f"x {expr}")
    def info_registers(self) -> str: return self.command("info registers")
    def info_locals(self) -> str: return self.command("info locals")

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            os.write(self._fd, b"quit\n")
        except OSError:
            pass
        try:
            self._p.wait(timeout=5)
        except Exception:
            self._p.kill()
        try:
            os.close(self._fd)
        except OSError:
            pass
        shutil.rmtree(self._rundir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def _text(x) -> str:
    if x is None:
        return ""
    return x.decode("utf-8", "replace") if isinstance(x, bytes) else x


def _bound(text: str, limit: int) -> str:
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", "replace") + f"\n...[truncated, {len(data)} bytes total]"
