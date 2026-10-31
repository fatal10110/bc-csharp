"""Tests for build.py (issue #10): staging from closure_report.json, the build plan and the
3a/3c build loop with a fake builder (no dotnet)."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import build  # noqa: E402
import closure  # noqa: E402

SETS = {"min": ["NETSTANDARD"], "netframework": ["NET471"]}


def write(path, text=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = self.tmp.name
        self.work = os.path.join(base, "work")
        self.src = os.path.join(base, "src")
        self.roots = os.path.join(base, "roots")
        for f in ("a/Kept.cs", "b/Denied.cs", "turbo/T.cs"):
            write(os.path.join(self.src, f), "class X { }\n")
        write(os.path.join(self.roots, "Consumer.cs"))
        write(os.path.join(self.roots, "sub", "RootStubs.cs"))
        write(os.path.join(self.roots, "notes.txt"))

    def report(self, **over):
        rep = {
            "files": ["a/Kept.cs", "b/Denied.cs", "turbo/T.cs"],
            "denied": {"b/Denied.cs": "b/**"},
            "stubs": ["Org.Fix"],
            "swept": True,
            "sweep_stubs": ["Org.Fix", "Org.Sweep"],
        }
        rep.update(over)
        write(os.path.join(self.work, build.REPORT_FILE), json.dumps(rep))


class StageTest(Fixture):
    def test_kept_list_excludes_denied_and_roots_are_listed(self):
        self.report()
        build.stage(self.work, self.roots)
        self.assertEqual(build.read_list(os.path.join(self.work, build.KEPT_LIST)), ["a/Kept.cs", "turbo/T.cs"])
        self.assertEqual(
            build.read_list(os.path.join(self.work, build.ROOTS_LIST)), ["Consumer.cs", "sub/RootStubs.cs"]
        )
        self.assertEqual(
            build.read_list(os.path.join(self.work, build.STAGE_DIR, build.STUBS_LIST)), [closure.SHIPPED_STUBS]
        )

    def test_ships_sweep_stubs_when_swept(self):
        self.report()
        _, stubs, _ = build.stage(self.work, self.roots)
        self.assertEqual(stubs, ["Org.Fix", "Org.Sweep"])
        with open(os.path.join(self.work, build.STAGE_DIR, closure.SHIPPED_STUBS), encoding="utf-8") as f:
            self.assertEqual(f.read(), closure.render_stubs(["Org.Fix", "Org.Sweep"]))

    def test_ships_fixpoint_stubs_without_sweep(self):
        self.report(swept=False, denied={}, sweep_stubs=[])
        kept, stubs, _ = build.stage(self.work, self.roots)
        self.assertEqual(stubs, ["Org.Fix"])
        self.assertEqual(len(kept), 3)

    def test_stage_dir_starts_empty(self):
        write(os.path.join(self.work, build.STAGE_DIR, "stale.cs"))
        self.report()
        build.stage(self.work, self.roots)
        self.assertEqual(
            sorted(os.listdir(os.path.join(self.work, build.STAGE_DIR))), [closure.SHIPPED_STUBS, build.STUBS_LIST]
        )

    def test_missing_report_or_roots_is_an_error(self):
        with self.assertRaises(build.StageError):
            build.stage(self.work, self.roots)
        self.report()
        with self.assertRaises(build.StageError):
            build.stage(self.work, os.path.join(self.tmp.name, "empty"))

    def test_cli_stage(self):
        self.report()
        self.assertEqual(build.main(["stage", "--work", self.work, "--roots", self.roots]), 0)
        self.assertEqual(build.main(["stage", "--work", os.path.join(self.tmp.name, "nowork")]), 2)


class NamingTest(unittest.TestCase):
    def test_dll_names(self):
        self.assertEqual(build.lib_assembly("netstandard21"), "TurboBC.ns21")
        self.assertEqual(build.lib_assembly("netframework"), "TurboBC.netfx")
        self.assertEqual(build.lib_assembly("partial"), "TurboBC.partial")
        with self.assertRaises(build.StageError):
            build.dll_suffix("bad name")


class FakeBuilder(build.StageBuilder):
    """Errors per build key; a clean build writes its output dll."""

    def __init__(self, work, errors):
        super().__init__(work, "unused.csproj")
        self.errors = errors
        self.built = []

    def build(self, key, files, assert_defines=False):
        self.built.append((key, len(files), assert_defines))
        errs = {closure.BuildError("f.cs", 1, 1, "CS0246", m) for m in self.errors.get(key, [])}
        if not errs:
            write(self.output(key), "dll")
        return errs


class BuildLoopTest(Fixture):
    def setUp(self):
        super().setUp()
        self.report()
        build.stage(self.work, self.roots)
        write(os.path.join(self.work, build.REWRITTEN_LIB, "a", "Kept.cs"))
        write(os.path.join(self.work, build.REWRITTEN_LIB, closure.SHIPPED_STUBS))
        write(os.path.join(self.work, build.REWRITTEN_ROOTS, "Consumer.cs"))

    def run_loop(self, errors):
        b = FakeBuilder(self.work, errors)
        plan = build.plan_builds(b, SETS, self.work, self.src)
        return b, plan, build.run_builds(b, plan, self.work, log=lambda *_: None)

    def test_plan_inputs_and_consumer_reference(self):
        b, plan, _ = self.run_loop({})
        s, k3a, k3c, kcon, f3a, f3c, fcon = plan[1]
        self.assertEqual((s, k3a, k3c, kcon), ("netframework", "3a-netframework", "3c-netframework",
                                                "3c-consumer-netframework"))
        self.assertEqual(f3a, [os.path.join(self.src, "a/Kept.cs"), os.path.join(self.src, "turbo/T.cs"),
                               os.path.join(self.work, build.STAGE_DIR, closure.SHIPPED_STUBS)])
        self.assertEqual(len(f3c), 2)
        self.assertEqual(fcon, [os.path.join(self.work, build.REWRITTEN_ROOTS, "Consumer.cs")])
        self.assertEqual(b.targets[kcon], ("netframework", "TurboBC.Consumer.netfx", [b.output(k3c)]))
        self.assertTrue(b.output(k3c).endswith(os.path.join("net471", "TurboBC.netfx.dll")))

    def test_props_carry_assembly_name_and_reference(self):
        b, plan, _ = self.run_loop({})
        os.makedirs(b.set_dir("3c-consumer-min"), exist_ok=True)
        b._write_props("3c-consumer-min", ["/x/A.cs"])
        with open(os.path.join(b.set_dir("3c-consumer-min"), "Closure.props"), encoding="utf-8") as f:
            props = f.read()
        self.assertIn("<AssemblyName>TurboBC.Consumer.min</AssemblyName>", props)
        self.assertIn(f'<Reference Include="TurboBC.min"><HintPath>{b.output("3c-min")}</HintPath></Reference>', props)
        self.assertIn("<DefineConstants>NETSTANDARD</DefineConstants>", props)
        self.assertIn("<TargetFramework>netstandard2.1</TargetFramework>", props)

    def test_clean_builds_copy_dlls_and_assert_defines(self):
        b, _, results = self.run_loop({})
        self.assertEqual(build.failure_lines(results), [])
        self.assertEqual(sorted(os.listdir(os.path.join(self.work, build.DLL_DIR))),
                         ["TurboBC.min.dll", "TurboBC.netfx.dll"])
        self.assertEqual(len(b.built), 6)
        self.assertTrue(all(a for _, _, a in b.built))

    def test_failed_lib_skips_its_consumer_and_dll(self):
        b, _, results = self.run_loop({"3c-min": ["missing type"], "3a-min": ["missing type"]})
        self.assertIsNone(results["3c-consumer-min"])
        self.assertNotIn("3c-consumer-min", [k for k, _, _ in b.built])
        self.assertEqual(results["3c-consumer-netframework"], [])
        self.assertEqual(os.listdir(os.path.join(self.work, build.DLL_DIR)), ["TurboBC.netfx.dll"])
        lines = build.failure_lines(results)
        self.assertIn("build [3a-min]: 1 compile error(s)", lines)
        self.assertIn("build [3c-consumer-min]: skipped (its TurboBC dll did not build)", lines)

    def test_consumer_errors_fail(self):
        _, _, results = self.run_loop({"3c-consumer-netframework": ["a", "b"]})
        self.assertEqual(build.failure_lines(results)[0], "build [3c-consumer-netframework]: 2 compile error(s)")

    def test_console_shows_at_most_ten_errors(self):
        _, _, results = self.run_loop({"3a-min": [f"e{i:02}" for i in range(12)]})
        lines = build.failure_lines(results)
        self.assertEqual(len(lines), 1 + build.SHOWN_ERRORS + 1)
        self.assertIn("2 more", lines[-1])

    def test_missing_rewrite_output_is_an_error(self):
        import shutil

        shutil.rmtree(os.path.join(self.work, build.REWRITTEN_ROOTS))
        with self.assertRaises(build.StageError):
            build.plan_builds(FakeBuilder(self.work, {}), SETS, self.work, self.src)


if __name__ == "__main__":
    unittest.main()
