"""Run the test suite WITHOUT installing pytest.

Debian/Ubuntu strip pip/ensurepip, and installing python3-pytest needs sudo.
This provides a minimal pytest-compatible shim (skip, mark.parametrize,
mark.skipif) so tests/*.py run unchanged, and reports pass/fail/skip counts.

    python3 scripts/run_tests.py
"""
import importlib.util
import os
import sys
import traceback
import types

ROOT = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.abspath(ROOT))


# ---- minimal pytest shim --------------------------------------------------
class Skipped(Exception):
    pass


class SkipIf:
    def __init__(self, cond, reason=""):
        self.cond, self.reason = cond, reason

    def __call__(self, fn):
        fn._skipif = (self.cond, self.reason)
        return fn


class _Mark:
    def parametrize(self, argnames, argvalues):
        def deco(fn):
            fn._params = (argnames, argvalues)
            return fn
        return deco

    def skipif(self, cond, reason=""):
        return SkipIf(cond, reason)


pytest = types.ModuleType("pytest")
pytest.skip = lambda reason="": (_ for _ in ()).throw(Skipped(reason))
pytest.mark = _Mark()
sys.modules["pytest"] = pytest


def _bind(argnames, value):
    names = [n.strip() for n in argnames.split(",")]
    if len(names) == 1:
        return {names[0]: value}
    return dict(zip(names, value))


def run_file(path):
    spec = importlib.util.spec_from_file_location(os.path.basename(path)[:-3], path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)

    pm = getattr(mod, "pytestmark", None)
    if isinstance(pm, SkipIf) and pm.cond:
        print(f"  SKIP (module): {pm.reason}")
        return (0, 0, 1)

    passed = failed = skipped = 0
    for name in sorted(dir(mod)):
        if not name.startswith("test_"):
            continue
        fn = getattr(mod, name)
        if not callable(fn):
            continue
        skipif = getattr(fn, "_skipif", None)
        if skipif and skipif[0]:
            print(f"  skip {name}: {skipif[1]}")
            skipped += 1
            continue
        params = getattr(fn, "_params", None)
        cases = ([(name, {})] if not params
                 else [(f"{name}[{v}]", _bind(params[0], v)) for v in params[1]])
        for case_name, kwargs in cases:
            try:
                fn(**kwargs)
                passed += 1
            except Skipped as s:
                print(f"  skip {case_name}: {s}")
                skipped += 1
            except Exception:
                failed += 1
                print(f"  FAIL {case_name}")
                print("    " + traceback.format_exc().replace("\n", "\n    ").strip())
    return (passed, failed, skipped)


def main():
    tests_dir = os.path.join(ROOT, "tests")
    files = sorted(f for f in os.listdir(tests_dir) if f.startswith("test_") and f.endswith(".py"))
    tp = tf = ts = 0
    for f in files:
        print(f"== {f} ==")
        p, fail, s = run_file(os.path.join(tests_dir, f))
        tp += p; tf += fail; ts += s
    print(f"\nTOTAL: {tp} passed, {tf} failed, {ts} skipped")
    return 1 if tf else 0


if __name__ == "__main__":
    raise SystemExit(main())
