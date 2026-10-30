"""Exclusion list of strip/tool/upstream_tests.py (issue #42): parsing, MSBuild output, stale base, report."""

import hashlib
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
import xml.etree.ElementTree as ET
from pathlib import Path

SCRIPT = Path(__file__).with_name("upstream_tests.py")
sys.path.insert(0, str(SCRIPT.parent))
import upstream_tests as ut  # noqa: E402

BASE_SHA = "7c9c8d5a12b6342529936f08899cdb752280d538"
FILTER = "Org.BouncyCastle.Tls.Tests.\nOrg.BouncyCastle.Crypto.Tests.GcmTest.\n"
PROBE = "crypto/test/src/tls/test/ExclusionProbeTest.cs"
PROBE_SOURCE = """using NUnit.Framework;

namespace Org.BouncyCastle.Tls.Tests
{
    [TestFixture]
    public class ExclusionProbeTest
    {
        private sealed class Helper { }
    }
}
"""
OTHER = "crypto/test/src/x509/test/OtherTest.cs"
OTHER_SOURCE = "namespace Org.BouncyCastle.X509.Tests;\n\npublic class OtherTest { }\n"


def make_tree(root, exclude_text):
    (root / "strip").mkdir(parents=True)
    (root / "strip" / "BASE").write_text(BASE_SHA + "\n", encoding="utf-8")
    (root / "strip" / "upstream-tests.txt").write_text(FILTER, encoding="utf-8")
    (root / "strip" / "upstream-expected-failures.txt").write_text("", encoding="utf-8")
    (root / "strip" / "upstream-tests-exclude.txt").write_text(exclude_text, encoding="utf-8")
    for path, text in ((PROBE, PROBE_SOURCE), (OTHER, OTHER_SOURCE)):
        (root / path).parent.mkdir(parents=True, exist_ok=True)
        (root / path).write_text(text, encoding="utf-8")


def write_base(root, exclusions):
    base = {"Org.BouncyCastle.Crypto.Tests.GcmTest.TestFunction": "pass"}
    digest = ut.filter_digest(ut.parse_filter(FILTER))
    text = ut.format_base(BASE_SHA, digest, ut.exclude_digest(exclusions), base)
    (root / "strip" / "upstream-base-results.txt").write_text(text, encoding="utf-8")


class ParseExclusionsTest(unittest.TestCase):
    def test_tagged_paths_with_comments_and_blank_lines(self):
        text = f"# comment\n\nE9 {PROBE}\n  E1/B\t{OTHER}  \n"
        self.assertEqual(ut.parse_exclusions(text), {PROBE: "E9", OTHER: "E1/B"})
        self.assertEqual(ut.parse_exclusions("# nothing excluded yet\n\n"), {})

    def test_untagged_or_badly_tagged_lines_are_refused(self):
        for line in (PROBE, f"B {PROBE}", f"E {PROBE}", f"E9/H {PROBE}", f"e9 {PROBE}", f"E123 {PROBE}"):
            with self.subTest(line=line), self.assertRaisesRegex(ut.ToolError, r"exclude\.txt:1: "):
                ut.parse_exclusions(line)

    def test_paths_must_be_test_sources(self):
        bad = (
            "crypto/src/x509/X509ExtensionUtil.cs", "crypto/test/src/tls/test/A.txt", "crypto/test/src/A.cs extra",
            "crypto/test/src/../../src/A.cs", "crypto/test/src/./A.cs", "crypto/test/src/**/A.cs",
            "crypto/test/src/a;b.cs", "crypto/test/src/a$(X).cs", "crypto\\test\\src\\A.cs", "/crypto/test/src/A.cs",
            "crypto/test/src//A.cs", 'crypto/test/src/a"b.cs',
        )
        for path in bad:
            with self.subTest(path=path), self.assertRaises(ut.ToolError):
                ut.parse_exclusions(f"E9 {path}")

    def test_duplicate_path_is_refused(self):
        with self.assertRaisesRegex(ut.ToolError, "duplicate path"):
            ut.parse_exclusions(f"E9 {PROBE}\nE10 {PROBE}\n")

    def test_digest_covers_the_paths_not_their_order_or_tags(self):
        self.assertEqual(ut.exclude_digest({}), hashlib.sha256(b"").hexdigest())
        one = ut.exclude_digest({PROBE: "E9", OTHER: "E10"})
        self.assertEqual(one, ut.exclude_digest({OTHER: "E1/B", PROBE: "E9"}))
        self.assertNotEqual(one, ut.exclude_digest({PROBE: "E9"}))
        self.assertNotEqual(ut.exclude_digest({}), ut.exclude_digest({PROBE: "E9"}))

    def test_committed_list_parses(self):
        repo = SCRIPT.parents[2]
        exclusions = ut.parse_exclusions((repo / ut.EXCLUDE_FILE).read_text(encoding="utf-8"))
        ut.check_exclusions_exist(repo, exclusions)


class MsBuildTest(unittest.TestCase):
    def test_compile_remove_items_for_the_test_project_only(self):
        text = ut.exclusion_targets({PROBE: "E9", OTHER: "E10"})
        project = ET.fromstring(text)
        group = project.find("ItemGroup")
        self.assertEqual(group.get("Condition"), "'$(MSBuildProjectName)' == 'BouncyCastle.Crypto.Tests'")
        self.assertEqual(
            [item.get("Remove") for item in group.findall("Compile")],
            ["$(MSBuildProjectDirectory)/src/tls/test/ExclusionProbeTest.cs",
             "$(MSBuildProjectDirectory)/src/x509/test/OtherTest.cs"],
        )
        self.assertEqual([item.get("Include") for item in group.findall("Compile")], [None, None])

    def test_empty_list_removes_nothing(self):
        project = ET.fromstring(ut.exclusion_targets({}))
        self.assertEqual(project.findall(".//Compile"), [])

    def test_command_passes_the_targets_file(self):
        command = ut.dotnet_test_command("dotnet", "FullyQualifiedName~X.", Path("/r/exclude.targets"), "t.trx",
                                         Path("/r"), "net6.0")
        self.assertIn("-p:CustomAfterMicrosoftCommonTargets=/r/exclude.targets", command)
        self.assertEqual(command[:3], ["dotnet", "test", str(ut.TEST_PROJECT)])

    def test_run_tests_writes_the_list_and_keeps_an_unchanged_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            tree, results_dir = Path(tmp) / "tree", Path(tmp) / "results"
            tree.mkdir()
            commands = []

            def fake_run(command, cwd, env, stdout, stderr):
                commands.append((command, cwd))
                (results_dir / "t.trx").write_text(
                    '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results/></TestRun>',
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0)

            with unittest.mock.patch.object(ut.subprocess, "run", fake_run), \
                    unittest.mock.patch.object(ut, "find_dotnet", return_value="dotnet"):
                ut.run_tests(tree, ["Org.X."], {PROBE: "E9"}, results_dir, "t.trx", "net6.0")
                targets = results_dir / "exclude.targets"
                stamp = targets.stat().st_mtime_ns
                ut.run_tests(tree, ["Org.X."], {PROBE: "E9"}, results_dir, "t.trx", "net6.0")
                self.assertEqual(targets.stat().st_mtime_ns, stamp)
                ut.run_tests(tree, ["Org.X."], {}, results_dir, "t.trx", "net6.0")
            self.assertEqual(targets.read_text(encoding="utf-8"), ut.exclusion_targets({}))
            self.assertEqual(commands[0][1], tree)
            self.assertIn(f"-p:CustomAfterMicrosoftCommonTargets={targets}", commands[0][0])

    def test_base_run_uses_the_same_exclusions(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            make_tree(root, f"E9 {PROBE}\n")
            (Path(tmp) / "bc-test-data").mkdir()
            exclusions = {PROBE: "E9"}
            seen = []

            def fake_run_tests(tree, entries, excl, results_dir, trx_name, framework):
                seen.append((tree.name, excl))
                return {"Org.BouncyCastle.Tls.Tests.T.A": "pass", "Org.BouncyCastle.Crypto.Tests.GcmTest.B": "pass"}

            with unittest.mock.patch.object(ut, "run_tests", fake_run_tests), \
                    unittest.mock.patch.object(ut, "git", return_value=""), unittest.mock.patch("sys.stdout"):
                ut.update_base(root, ut.parse_filter(FILTER), exclusions, Path(tmp) / "results", "net6.0", False)
            self.assertEqual(seen, [(f".upstream-base-{BASE_SHA[:12]}", exclusions)])
            meta, _ = ut.parse_base((root / ut.BASE_RESULTS_FILE).read_text(encoding="utf-8"))
            self.assertEqual(meta["exclude-sha256"], ut.exclude_digest(exclusions))


class ReportTest(unittest.TestCase):
    def test_type_names_skip_comments_literals_and_nested_types(self):
        source = """// The class Prose under test; /* class Block */ is a comment too.
namespace Org.X.Tests
{
    /* class Hidden */
    [TestFixture]
    public class Kept
    {
        private const string Url = "http://h/ class InString";
        private const char Quote = '"';
        private sealed class Nested { }
        private static void M<T>() where T : class { }
    }

    public struct Also { }
}
"""
        self.assertEqual(ut.top_level_types(source), ["Kept", "Also"])
        self.assertEqual(ut.top_level_types("namespace Org.X;\npublic class A { class B { } }\nrecord C;\n"),
                         ["A", "C"])
        self.assertEqual(ut.top_level_types("// class Only in a comment\n"), [])

    def test_type_level_and_deeper_entries_select_the_type(self):
        name = "Org.X.Tests.Kept"
        for entry in ("Org.X.", "Org.X.Tests.Kept.", "X.Tests.", "Org.X.Tests.Kept.Method."):
            with self.subTest(entry=entry):
                self.assertTrue(ut.entry_selects_type(entry, name))
        for entry in ("Org.X.Tests.KeptFoo.", "Org.X.Tests.Other.", "Org.Y."):
            with self.subTest(entry=entry):
                self.assertFalse(ut.entry_selects_type(entry, name))

    def test_method_level_entry_reports_its_type(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_tree(root, "")
            entries = ["Org.BouncyCastle.Tls.Tests.ExclusionProbeTest.Probe."]
            self.assertEqual(ut.excluded_kept_tests(root, {PROBE: "E9", OTHER: "E10"}, entries),
                             [("E9", PROBE, ["Org.BouncyCastle.Tls.Tests.ExclusionProbeTest"])])

    def test_excluded_sources_in_the_kept_surface_are_reported(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_tree(root, "")
            rows = ut.excluded_kept_tests(root, {PROBE: "E9", OTHER: "E10"}, ut.parse_filter(FILTER))
            self.assertEqual(
                rows,
                [("E9", PROBE, ["Org.BouncyCastle.Tls.Tests.ExclusionProbeTest"])],
            )
            entries = ["Org.BouncyCastle.X509.Tests.OtherTest."]
            self.assertEqual(ut.excluded_kept_tests(root, {OTHER: "E10"}, entries),
                             [("E10", OTHER, ["Org.BouncyCastle.X509.Tests.OtherTest"])])
            text = ut.format_report(ut.diff({}, {}, {}), BASE_SHA, {}, {}, rows)
            self.assertIn("Excluded sources with kept-surface tests", text)
            self.assertIn(f"E9 {PROBE}: Org.BouncyCastle.Tls.Tests.ExclusionProbeTest", text)


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        make_tree(self.root, "# none\n")
        write_base(self.root, {})
        self.trx = Path(self.tmp.name) / "current.trx"
        self.trx.write_text(
            '<TestRun xmlns="http://microsoft.com/schemas/VisualStudio/TeamTest/2010"><Results>'
            '<UnitTestResult testId="1" testName="TestFunction" outcome="Passed" /></Results><TestDefinitions>'
            '<UnitTest id="1"><TestMethod className="Org.BouncyCastle.Crypto.Tests.GcmTest" name="TestFunction" />'
            "</UnitTest></TestDefinitions></TestRun>",
            encoding="utf-8",
        )

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args], capture_output=True, text=True
        )

    def write_exclude(self, text):
        (self.root / "strip" / "upstream-tests-exclude.txt").write_text(text, encoding="utf-8")

    def test_changed_list_needs_update_base(self):
        self.assertEqual(self.run_script("--trx", str(self.trx)).returncode, 0)
        self.write_exclude(f"E9 {PROBE}\n")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 2)
        self.assertIn("upstream-tests-exclude.txt changed since", result.stderr)
        self.assertIn("--update-base", result.stderr)
        write_base(self.root, {PROBE: "E9"})
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"E9 {PROBE}: Org.BouncyCastle.Tls.Tests.ExclusionProbeTest", result.stdout)

    def test_base_results_without_exclusion_digest_are_stale(self):
        path = self.root / "strip" / "upstream-base-results.txt"
        text = "".join(line for line in path.read_text(encoding="utf-8").splitlines(True)
                       if not line.startswith("# exclude-sha256:"))
        path.write_text(text, encoding="utf-8")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 2)
        self.assertIn("--update-base", result.stderr)

    def test_bad_list_is_refused_in_every_mode(self):
        cases = ((PROBE, "E-number of the cut"), ("E9 crypto/test/src/tls/test/Gone.cs", "do not exist"))
        for text, message in cases:
            self.write_exclude(text + "\n")
            for args in (("--print-filter",), ("--trx", str(self.trx))):
                with self.subTest(text=text, args=args):
                    result = self.run_script(*args)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(message, result.stderr)

    def test_missing_list_is_refused(self):
        (self.root / "strip" / "upstream-tests-exclude.txt").unlink()
        result = self.run_script("--print-filter")
        self.assertEqual(result.returncode, 2)
        self.assertIn("upstream-tests-exclude.txt not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
