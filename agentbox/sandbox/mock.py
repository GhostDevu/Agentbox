"""MockSandbox: the baseline stand-in. NO CONTAINMENT.

It builds (if needed) and runs the target *as a child process on the host*,
optionally under a host tracer, then returns a bounded result. It exists to pin
the interfaces and prove the data flow

    agent -> invoke -> [ run target ] <- host tracer observes -> bounded result

end to end, so the containment layers can be slotted in behind `Sandbox` later.

SAFETY: because this backend provides zero isolation, it must only ever run
*benign* programs: the canary/probe suite and hello-world fidelity targets. Do
NOT feed it untrusted or malicious samples -- that is what the real backends
(bubblewrap/gVisor/Firecracker) are for. The repo rule stands: never run
untrusted samples directly on the macOS host.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid

from ..config import CONFIG, Limits
from ..tracing import get_tracer
from .base import CodeObject, Language, RunResult, RunSpec, Sandbox, TraceArtifact


class MockSandbox(Sandbox):
    name = "mock"
    containment_level = "none"

    def __init__(self, limits: Limits | None = None) -> None:
        self.limits = limits or CONFIG.limits

    # ---- build -----------------------------------------------------------
    def _materialize(self, code: CodeObject, workdir: str) -> list[str]:
        """Return the base argv (program + no target args) for `code`, building
        from source into `workdir` when necessary."""
        if code.language == Language.BINARY:
            if not code.path or not os.path.exists(code.path):
                raise FileNotFoundError(f"binary not found: {code.path}")
            return [os.path.abspath(code.path)]

        if code.language == Language.PYTHON:
            src = os.path.join(workdir, f"{code.name}.py")
            self._write_source(code, src)
            # -I: isolated mode, so the target can't import from the cwd/env.
            return [sys.executable, "-I", src]

        if code.language == Language.C:
            src = os.path.join(workdir, f"{code.name}.c")
            out = os.path.join(workdir, code.name)
            self._write_source(code, src)
            cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
            if not cc:
                raise RuntimeError("no C compiler (cc/gcc/clang) on PATH")
            # -g for symbols (gdb backtraces); -O0 to keep the trace readable.
            proc = subprocess.run(
                [cc, "-g", "-O0", "-o", out, src],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"compile failed:\n{proc.stderr}")
            return [out]

        raise ValueError(f"unsupported language: {code.language}")

    @staticmethod
    def _write_source(code: CodeObject, dst: str) -> None:
        if code.source is not None:
            with open(dst, "w") as fh:
                fh.write(code.source)
        elif code.path is not None:
            shutil.copyfile(code.path, dst)
        else:  # pragma: no cover - guarded by CodeObject.__post_init__
            raise ValueError("CodeObject has neither source nor path")

    # ---- run -------------------------------------------------------------
    def run(self, spec: RunSpec) -> RunResult:
        if len(spec.argv) > self.limits.max_argv:
            raise ValueError("argv too long")

        os.makedirs(CONFIG.work_root, exist_ok=True)
        workdir = tempfile.mkdtemp(prefix=f"run-{uuid.uuid4().hex[:8]}-", dir=CONFIG.work_root)
        timeout = spec.timeout_s or self.limits.wall_timeout_s

        try:
            base_argv = self._materialize(spec.code, workdir)
            target_argv = base_argv + list(spec.argv)

            tracer = get_tracer(spec.tracer)
            trace_out = os.path.join(workdir, "trace.out")
            launch_argv = tracer.wrap(target_argv, trace_out)

            env = {**os.environ, **spec.env}
            start = time.monotonic()
            timed_out = False
            term_signal: int | None = None
            try:
                proc = subprocess.run(
                    launch_argv,
                    input=spec.stdin,
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                    env=env,
                    cwd=workdir,
                )
                exit_code = proc.returncode
                stdout, stderr = proc.stdout, proc.stderr
                # subprocess reports a signal death as a negative returncode.
                if exit_code is not None and exit_code < 0:
                    term_signal = -exit_code
            except subprocess.TimeoutExpired as exc:
                timed_out = True
                exit_code = None
                term_signal = signal.SIGKILL
                stdout = exc.stdout or ""
                stderr = exc.stderr or ""
                if isinstance(stdout, bytes):
                    stdout = stdout.decode("utf-8", "replace")
                if isinstance(stderr, bytes):
                    stderr = stderr.decode("utf-8", "replace")
            duration = time.monotonic() - start

            trace = tracer.collect(trace_out, self.limits.max_trace_summary_bytes)

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
                meta={"workdir": workdir, "launch_argv": launch_argv},
            )
        finally:
            # Teardown is a first-class guarantee even for the mock, so the
            # "no leftovers" invariant is exercised from day one.
            shutil.rmtree(workdir, ignore_errors=True)


def _bound(text: str, limit: int) -> str:
    """Bound an untrusted stream, marking truncation visibly."""
    data = text.encode("utf-8", "replace")
    if len(data) <= limit:
        return text
    return data[:limit].decode("utf-8", "replace") + f"\n...[truncated, {len(data)} bytes total]"
