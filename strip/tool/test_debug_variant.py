"""Tests for the DEBUG build of issue #58: the variant set derived in defines.py, its builds and DLL
placement in build.py, and strip.sh's DEBUG smoke call (fake tools, no dotnet)."""

import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build  # noqa: E402
import defines  # noqa: E402
import test_build  # noqa: E402
import test_strip_sh  # noqa: E402

STRIP = os.path.dirname(HERE)
CAPTURED = os.path.join(STRIP, "unity-defines.txt")


class DebugVariantDefinesTest(unittest.TestCase):
    def test_variant_is_the_captured_set_plus_debug_and_trace(self):
        sets = defines.load_unity_defines(CAPTURED)
        variants = defines.debug_variants(sets)
        self.assertEqual(list(variants), ["netstandard21_debug"])
        v = variants["netstandard21_debug"]
        self.assertEqual(v[: len(sets["netstandard21"])], sets["netstandard21"])
        self.assertEqual(set(v) - set(sets["netstandard21"]), {"DEBUG", "TRACE"})
        self.assertEqual(len(v), len(set(v)))
        self.assertEqual(defines.tfm_for_set("netstandard21_debug"), "netstandard2.1")
        # The assertion accepts exactly the variant: DEBUG is no leak here, but still one for the captured set.
        self.assertEqual(defines.check_defines("netstandard21_debug", v, v), [])
        self.assertIn("leakage", defines.check_defines("netstandard21", sets["netstandard21"], v)[0])

    def test_captured_file_stays_the_player_capture(self):
        # The variant is not a set of unity-defines.txt, so closure.py (which reads only the file) never sees it.
        sets = defines.load_unity_defines(CAPTURED)
        self.assertNotIn("netstandard21_debug", sets)
        for name, symbols in sets.items():
            self.assertNotIn("DEBUG", symbols, name)

    def test_no_variant_without_its_captured_set(self):
        self.assertEqual(defines.debug_variants({"netframework": ["NET471"]}), {})
        self.assertEqual(defines.debug_variants({"netstandard21": ["A", "DEBUG"]}),
                         {"netstandard21_debug": ["A", "DEBUG", "TRACE"]})


class DebugVariantBuildTest(test_build.BuildLoopTest):
    SETS = {"netstandard21": ["NETSTANDARD"], "netframework": ["NET471"]}

    def test_select_sets_adds_the_variant_last(self):
        sets = build.select_sets(self.SETS, [])
        self.assertEqual(list(sets), ["netstandard21", "netframework", "netstandard21_debug"])
        self.assertEqual(sets["netstandard21_debug"], ["NETSTANDARD", "DEBUG", "TRACE"])
        self.assertEqual(list(build.select_sets(self.SETS, ["netstandard21"])), ["netstandard21", "netstandard21_debug"])
        self.assertEqual(list(build.select_sets(self.SETS, ["netframework"])), ["netframework"])
        with self.assertRaises(build.StageError):
            build.select_sets(self.SETS, ["netstandard21_debug"])

    def test_variant_builds_3a_3c_consumer_and_lands_in_dll_debug(self):
        b = test_build.FakeBuilder(self.work, {})
        plan = build.plan_builds(b, build.select_sets(self.SETS, []), self.work, self.src)
        results = build.run_builds(b, plan, self.work, log=lambda *_: None)
        self.assertEqual(build.failure_lines(results), [])
        self.assertEqual([k for k, _, _ in b.built][-3:],
                         ["3a-netstandard21_debug", "3c-netstandard21_debug", "3c-consumer-netstandard21_debug"])
        self.assertTrue(all(a for _, _, a in b.built))
        self.assertEqual(b.targets["3c-netstandard21_debug"][1], "TurboBC.ns21-debug")
        self.assertEqual(b.sets["3c-netstandard21_debug"], ["NETSTANDARD", "DEBUG", "TRACE"])
        self.assertEqual(sorted(os.listdir(os.path.join(self.work, build.DLL_DIR))),
                         ["TurboBC.netfx.dll", "TurboBC.ns21.dll", "debug"])
        self.assertEqual(os.listdir(os.path.join(self.work, build.DEBUG_DLL_DIR)), ["TurboBC.ns21-debug.dll"])

    def test_failing_variant_fails_the_builds(self):
        b = test_build.FakeBuilder(self.work, {"3a-netstandard21_debug": ["CS0103 under DEBUG"]})
        plan = build.plan_builds(b, build.select_sets(self.SETS, []), self.work, self.src)
        results = build.run_builds(b, plan, self.work, log=lambda *_: None)
        self.assertIn("build [3a-netstandard21_debug]: 1 compile error(s)", build.failure_lines(results))


# The fake build.py also writes the DEBUG DLL; the fake run.sh writes the DLL names it got as results and
# fails the DEBUG call (the one with --filter) when FAKE_RC_debug_smoke is set.
FAKE_PYTHON_DEBUG = test_strip_sh.FAKE_PYTHON.replace(
    'touch "$work/dll/TurboBC.min.dll"',
    'touch "$work/dll/TurboBC.min.dll"; mkdir -p "$work/dll/debug"; touch "$work/dll/debug/TurboBC.ns21-debug.dll"')
SMOKE = r"""#!/usr/bin/env bash
echo "run.sh $*" >> "$FAKE_LOG"
res=""; prev=""; filtered=0; dlls=""
for a in "$@"; do
  [ "$prev" = --results ] && res=$a
  [ "$a" = --filter ] && filtered=1
  case $a in *.dll) dlls="$dlls $(basename "$a")" ;; esac
  prev=$a
done
echo "rows ran on$dlls" > "$res"
[ "$filtered" = 1 ] && exit "${FAKE_RC_debug_smoke:-0}"
exit 0
"""


class DebugSmokeStripShTest(test_strip_sh.StripShTest):
    def setUp(self):
        super().setUp()
        test_strip_sh.executable(self.fake / "python3", FAKE_PYTHON_DEBUG)
        test_strip_sh.executable(self.repo / "strip" / "smoke" / "run.sh", SMOKE)

    def smoke_calls(self):
        return [c for c in self.calls() if c.startswith("run.sh")]

    def test_debug_dll_gets_its_own_filtered_smoke_run(self):
        r = self.run_sh()
        self.assertEqual(r.returncode, 0, r.stderr)
        main, debug = self.smoke_calls()
        self.assertNotIn("ns21-debug", main)
        self.assertNotIn("--filter", main)
        self.assertIn("--filter curves/ --filter kat- --filter registries/", debug)
        self.assertTrue(debug.endswith(f"{self.work}/dll/debug/TurboBC.ns21-debug.dll"), debug)
        self.assertNotIn("--slow", debug)
        self.assertIn("smoke passed (DEBUG build)", r.stdout)
        # Both results go into the one file package.py puts into STRIP_INFO.md.
        self.assertIn(f"--smoke {self.work}/smoke-results.md", self.calls()[-1])
        text = (self.work / "smoke-results.md").read_text()
        self.assertIn("rows ran on TurboBC.min.dll", text)
        self.assertIn("DEBUG build (#58): [netstandard21] + DEBUG TRACE", text)
        self.assertIn("rows ran on TurboBC.ns21-debug.dll", text)
        self.assertLess(text.index("TurboBC.min.dll"), text.index("DEBUG build"))

    def test_debug_smoke_failure_fails_enforce_and_is_reported(self):
        r = self.run_sh(FAKE_RC_debug_smoke="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL strip.sh: smoke suite failed (DEBUG build)", r.stderr)
        self.log.unlink()
        r = self.run_sh("--report", FAKE_RC_debug_smoke="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REPORT strip.sh: smoke suite failed (DEBUG build)", r.stdout)
        note = (self.work / "report-note.md").read_text()
        self.assertIn("smoke suite failed (DEBUG build)", note)
        self.assertIn("rows ran on TurboBC.ns21-debug.dll", note)

    def test_no_debug_dll_no_debug_run(self):
        test_strip_sh.executable(self.fake / "python3", test_strip_sh.FAKE_PYTHON)
        self.assertEqual(self.run_sh().returncode, 0)
        self.assertEqual(len(self.smoke_calls()), 1)


# Only the tests defined here: the inherited ones already run from test_build and test_strip_sh.
for _cls in (DebugVariantBuildTest, DebugSmokeStripShTest):
    for _name in [n for n in dir(_cls) if n.startswith("test_") and n not in _cls.__dict__]:
        setattr(_cls, _name, None)
del _cls, _name

if __name__ == "__main__":
    unittest.main()
