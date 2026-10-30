import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

SCRIPT = Path(__file__).with_name("upstream_tests.py")
REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SCRIPT.parent))
import upstream_tests as ut  # noqa: E402

NS = "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"
BASE_SHA = "7c9c8d5a12b6342529936f08899cdb752280d538"
FILTER = "# kept surface\nOrg.BouncyCastle.Tls.Tests.\n\nOrg.BouncyCastle.Crypto.Tests.GcmTest.\n"


def trx(results):
    """A TRX as the NUnit adapter writes it; results: (className, testName, outcome)."""
    tests, rows = [], []
    for index, (class_name, test_name, outcome) in enumerate(results):
        test_id = f"00000000-0000-0000-0000-{index:012d}"
        tests.append(
            f'<UnitTest name="{test_name}" storage="/x/BouncyCastle.Crypto.Tests.dll" id="{test_id}">'
            f'<Execution id="e{index}" /><TestMethod codeBase="/x/BouncyCastle.Crypto.Tests.dll" '
            f'adapterTypeName="executor://NUnit3TestExecutor" className="{class_name}" name="{test_name}" />'
            "</UnitTest>"
        )
        rows.append(
            f'<UnitTestResult executionId="e{index}" testId="{test_id}" testName="{test_name}" '
            f'computerName="h" duration="00:00:00.01" outcome="{outcome}" testListId="l" />'
        )
    return (
        f'<?xml version="1.0" encoding="utf-8"?><TestRun id="r" name="n" xmlns="{NS}">'
        f"<Results>{''.join(rows)}</Results><TestDefinitions>{''.join(tests)}</TestDefinitions></TestRun>"
    )


class ParseTrxTest(unittest.TestCase):
    def parse(self, results):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "t.trx"
            path.write_text(trx(results), encoding="utf-8")
            return ut.parse_trx(path)

    def test_outcomes_and_full_names(self):
        parsed = self.parse(
            [
                ("Org.BouncyCastle.Tls.Tests.TlsTestSuite", "RunTest(&quot;TLS12 client&quot;, 2)", "Passed"),
                ("Org.BouncyCastle.Tls.Tests.TlsSrpProtocolTest", "TestClientServer", "Failed"),
                ("Org.BouncyCastle.Crypto.Tests.GcmTest", "TestFunction", "NotExecuted"),
                ("Org.BouncyCastle.Crypto.Tests.GcmTest", "Org.BouncyCastle.Crypto.Tests.GcmTest.Qualified", "Passed"),
                ("Org.BouncyCastle.Crypto.Tests.GcmTest", "Odd", "Timeout"),
            ]
        )
        self.assertEqual(
            parsed,
            {
                'Org.BouncyCastle.Tls.Tests.TlsTestSuite.RunTest("TLS12 client", 2)': "pass",
                "Org.BouncyCastle.Tls.Tests.TlsSrpProtocolTest.TestClientServer": "fail",
                "Org.BouncyCastle.Crypto.Tests.GcmTest.TestFunction": "skip",
                "Org.BouncyCastle.Crypto.Tests.GcmTest.Qualified": "pass",
                "Org.BouncyCastle.Crypto.Tests.GcmTest.Odd": "fail",
            },
        )

    def test_duplicate_name_keeps_worst_outcome(self):
        parsed = self.parse([("A.B", "T", "Passed"), ("A.B", "T", "Failed"), ("A.B", "T", "Passed")])
        self.assertEqual(parsed, {"A.B.T": "fail"})

    def test_unreadable_trx_is_a_tool_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.trx"
            path.write_text("<TestRun", encoding="utf-8")
            with self.assertRaises(ut.ToolError):
                ut.parse_trx(path)


class DiffTest(unittest.TestCase):
    def test_categories(self):
        base = {"T.pass_now_fail": "pass", "T.expected": "pass", "T.stale": "pass", "T.gone": "pass",
                "T.skipped": "pass", "T.base_fail": "fail", "T.fixed": "fail", "T.ok": "pass"}
        current = {"T.pass_now_fail": "fail", "T.expected": "fail", "T.stale": "pass", "T.skipped": "skip",
                   "T.base_fail": "fail", "T.fixed": "pass", "T.ok": "pass", "T.new_fail": "fail",
                   "T.new_pass": "pass"}
        expected = {"T.expected": "E1/B", "T.stale": "E5", "T.unknown": "A/E8"}
        report = ut.diff(base, current, expected)
        self.assertEqual(
            report.regressions,
            [("T.gone", "pass", "missing"), ("T.new_fail", "missing", "fail"),
             ("T.pass_now_fail", "pass", "fail"), ("T.skipped", "pass", "skip")],
        )
        self.assertEqual(report.expected_hits, {"T.expected": "E1/B"})
        self.assertEqual(report.expected_passing, [("T.stale", "E5")])
        self.assertEqual(report.expected_unknown, [("T.unknown", "A/E8")])
        self.assertEqual(report.base_failures, [("T.base_fail", "fail", "fail")])
        self.assertEqual(report.new_tests, [("T.new_fail", "fail"), ("T.new_pass", "pass")])
        self.assertEqual(report.fixed, ["T.fixed"])

    def test_expected_entry_suppresses_regression_and_missing(self):
        base = {"T.a": "pass", "T.b": "pass"}
        current = {"T.a": "fail"}
        self.assertEqual(len(ut.diff(base, current, {}).regressions), 2)
        report = ut.diff(base, current, {"T.a": "E1/B", "T.b": "E8"})
        self.assertEqual(report.regressions, [])
        self.assertEqual(report.expected_hits, {"T.a": "E1/B", "T.b": "E8"})

    def test_identical_results_report_nothing(self):
        results = {"T.a": "pass", "T.b": "skip"}
        report = ut.diff(results, dict(results), {})
        self.assertEqual((report.regressions, report.new_tests, report.base_failures), ([], [], []))


class ListFilesTest(unittest.TestCase):
    def test_expected_failures_parsing(self):
        text = "# comment\n\nE1/B  Org.X.T.RunTest(\"a b\", 1)\nE/E5\tOrg.X.Ed\nE1 Org.X.Srp\nA/E8 Org.X.Pkix\n"
        self.assertEqual(
            ut.parse_expected(text),
            {'Org.X.T.RunTest("a b", 1)': "E1/B", "Org.X.Ed": "E/E5", "Org.X.Srp": "E1", "Org.X.Pkix": "A/E8"},
        )

    def test_expected_failures_need_an_e_number(self):
        for line in ("B Org.X.T", "E Org.X.T", "E1/H Org.X.T", "E1/b Org.X.T", "E123 Org.X.T", "Org.X.T"):
            with self.subTest(line=line), self.assertRaises(ut.ToolError):
                ut.parse_expected(line)
        with self.assertRaises(ut.ToolError):
            ut.parse_expected("E1 Org.X.T\nE2 Org.X.T\n")

    def test_filter_expression(self):
        entries = ut.parse_filter(FILTER)
        self.assertEqual(entries, ["Org.BouncyCastle.Tls.Tests.", "Org.BouncyCastle.Crypto.Tests.GcmTest."])
        self.assertEqual(
            ut.filter_expression(entries),
            "FullyQualifiedName~Org.BouncyCastle.Tls.Tests.|FullyQualifiedName~Org.BouncyCastle.Crypto.Tests.GcmTest.",
        )

    def test_empty_filter_is_refused(self):
        with self.assertRaisesRegex(ut.ToolError, "unfiltered"):
            ut.filter_expression(ut.parse_filter("# nothing kept\n\n"))

    def test_filter_entries_are_dotted_names(self):
        for line in ("Org.BouncyCastle.Tls.Tests", "Org.X.|FullyQualifiedName~Y.", "Org.X.T!.", "Org", "Org.X.T.(a)."):
            with self.subTest(line=line), self.assertRaises(ut.ToolError):
                ut.parse_filter(line)
        with self.assertRaises(ut.ToolError):
            ut.parse_filter("Org.X.\nOrg.X.\n")

    def test_unmatched_filter_entries(self):
        entries = ["Org.X.Tests.", "Org.X.Tests.Gone.", "Org.Y."]
        results = {"Org.X.Tests.Kept.T": "pass", "Org.Y.Z.T(1)": "fail"}
        self.assertEqual(ut.unmatched_entries(entries, results), ["Org.X.Tests.Gone."])

    def test_base_results_round_trip(self):
        results = {"T.b": "fail", 'T.a("x y")': "pass", "T.c": "skip"}
        text = ut.format_base(BASE_SHA, "abc", "def", results)
        self.assertEqual(
            ut.parse_base(text), ({"base": BASE_SHA, "filter-sha256": "abc", "exclude-sha256": "def"}, results)
        )
        with self.assertRaises(ut.ToolError):
            ut.parse_base("passed\tT.a\n")


class CliTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        (self.root / "strip").mkdir(parents=True)
        (self.root / "strip" / "BASE").write_text(BASE_SHA + "\n", encoding="utf-8")
        (self.root / "strip" / "upstream-tests.txt").write_text(FILTER, encoding="utf-8")
        (self.root / "strip" / "upstream-expected-failures.txt").write_text("# none yet\n", encoding="utf-8")
        (self.root / "strip" / "upstream-tests-exclude.txt").write_text("# none yet\n", encoding="utf-8")
        entries = ut.parse_filter(FILTER)
        base = {"Org.BouncyCastle.Tls.Tests.TlsTestSuite.RunTest(TLS12)": "pass",
                "Org.BouncyCastle.Crypto.Tests.GcmTest.TestFunction": "pass"}
        (self.root / "strip" / "upstream-base-results.txt").write_text(
            ut.format_base(BASE_SHA, ut.filter_digest(entries), ut.exclude_digest({}), base), encoding="utf-8"
        )
        self.trx = Path(self.tmp.name) / "current.trx"

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--root", str(self.root), *args], capture_output=True, text=True
        )

    def write_trx(self, gcm_outcome):
        self.trx.write_text(
            trx([("Org.BouncyCastle.Tls.Tests.TlsTestSuite", "RunTest(TLS12)", "Passed"),
                 ("Org.BouncyCastle.Crypto.Tests.GcmTest", "TestFunction", gcm_outcome)]),
            encoding="utf-8",
        )

    def test_clean_run_reports_zero_regressions(self):
        self.write_trx("Passed")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Result: 0 regression(s)", result.stdout)

    def test_broken_test_is_a_regression_until_listed(self):
        self.write_trx("Failed")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("[pass -> fail] Org.BouncyCastle.Crypto.Tests.GcmTest.TestFunction", result.stdout)
        (self.root / "strip" / "upstream-expected-failures.txt").write_text(
            "E14/G Org.BouncyCastle.Crypto.Tests.GcmTest.TestFunction\n", encoding="utf-8"
        )
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Expected failures hit (1): E14/G x1", result.stdout)

    def test_stale_base_results_are_refused(self):
        self.write_trx("Passed")
        (self.root / "strip" / "BASE").write_text("0" * 40 + "\n", encoding="utf-8")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 2)
        self.assertIn("--update-base", result.stderr)
        (self.root / "strip" / "BASE").write_text(BASE_SHA + "\n", encoding="utf-8")
        (self.root / "strip" / "upstream-tests.txt").write_text(FILTER + "Org.X.Y.\n", encoding="utf-8")
        result = self.run_script("--trx", str(self.trx))
        self.assertEqual(result.returncode, 2)
        self.assertIn("changed since", result.stderr)

    def test_empty_filter_refused_before_running(self):
        (self.root / "strip" / "upstream-tests.txt").write_text("# empty\n", encoding="utf-8")
        result = self.run_script("--print-filter")
        self.assertEqual(result.returncode, 2)
        self.assertIn("refusing an unfiltered upstream run", result.stderr)

    def test_missing_test_data_gives_clone_command(self):
        if ut.find_test_data(self.root) is not None:
            self.skipTest("a bc-test-data directory exists above the temporary directory")
        result = self.run_script()
        self.assertEqual(result.returncode, 2)
        self.assertIn("bc-test-data not found", result.stderr)
        self.assertIn("git clone --depth 1 https://github.com/bcgit/bc-test-data.git", result.stderr)

    def test_find_test_data_walks_up(self):
        data = Path(self.tmp.name) / "bc-test-data"
        data.mkdir()
        self.assertEqual(ut.find_test_data(self.root / "crypto" / "test"), data)


class ErrorPathTest(unittest.TestCase):
    def test_git_failure_is_a_tool_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ut.ToolError, "git rev-parse HEAD failed"):
                ut.git(Path(tmp) / "missing", "rev-parse", "HEAD")

    def test_no_trx_names_a_test_compile_failure(self):
        log = "Build started\nPKCS12Example.cs(121,5): error CS1729: no constructor\nBuild FAILED.\n"
        message = str(ut.no_trx_error(1, log))
        self.assertIn("crypto/test does not compile on this tree", message)
        self.assertIn("error CS1729", message)
        self.assertNotIn("does not compile", str(ut.no_trx_error(1, "Test host crashed\n")))

    def test_relative_results_dir_is_resolved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "repo"
            (root / "strip").mkdir(parents=True)
            (root / "strip" / "BASE").write_text(BASE_SHA + "\n", encoding="utf-8")
            (root / "strip" / "upstream-tests.txt").write_text(FILTER, encoding="utf-8")
            (root / "strip" / "upstream-tests-exclude.txt").write_text("", encoding="utf-8")
            seen = []

            def fake_update_base(root_arg, entries, exclusions, results_dir, framework, keep_tree):
                seen.append(results_dir)
                return 0

            with mock.patch.object(ut, "update_base", fake_update_base):
                code = ut.main(["--root", str(root), "--results-dir", "rel", "--update-base"])
            self.assertEqual(code, 0)
            self.assertTrue(seen[0].is_absolute(), seen[0])


class RepoFilesTest(unittest.TestCase):
    """The committed list files parse and the BASE results match strip/BASE and the filter."""

    def test_committed_files_are_consistent(self):
        entries = ut.parse_filter((REPO / ut.FILTER_FILE).read_text(encoding="utf-8"))
        self.assertTrue(entries)
        self.assertFalse([e for e in entries if ".Turbo." in e], "fork-owned tests have no BASE result")
        ut.parse_expected((REPO / ut.EXPECTED_FILE).read_text(encoding="utf-8"))
        exclusions = ut.parse_exclusions((REPO / ut.EXCLUDE_FILE).read_text(encoding="utf-8"))
        ut.check_exclusions_exist(REPO, exclusions)
        base_sha, base = ut.load_base(REPO, entries, exclusions)
        self.assertEqual(base_sha, (REPO / "strip" / "BASE").read_text(encoding="utf-8").strip())
        self.assertTrue(base)


if __name__ == "__main__":
    unittest.main()
