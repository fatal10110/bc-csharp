"""Tests for strip/strip.sh (issue #10): argument handling, prerequisites and the step order and
report/enforce semantics. strip.sh is copied into a temporary repository layout and run with fake
python3, dotnet and openssl on a PATH that holds nothing else, so no dotnet build runs."""

import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "strip.sh"
REPO = Path(__file__).resolve().parents[2]
SYSTEM_TOOLS = ("bash", "env", "dirname", "basename", "tr", "cp", "rm", "cat", "mkdir", "touch", "git")

# Logs every call; emulates the tools' exit codes (FAKE_RC_<tool>) and the files strip.sh relies on.
FAKE_PYTHON = r"""#!/usr/bin/env bash
case ${1:-} in
  -c) exit 0 ;;
  --version) echo "Python 3.12.3"; exit 0 ;;
esac
tool=$(basename "$1"); shift
echo "$tool $*" >> "$FAKE_LOG"
args=" $* "
out=""; files=""; work=""; sub=${1:-}
while [ $# -gt 0 ]; do
  case $1 in --out) out=$2 ;; --files) files=$2 ;; --work) work=$2 ;; esac
  shift
done
case $tool in
  closure.py)
    # Real contract: fail checks exit 1, but exit 0 under --report (only the line prefix changes).
    if [ -n "${FAKE_CLOSURE_FAILS:-}" ]; then
      case $args in *" --report "*) echo "REPORT deny hit"; exit 0 ;; *) echo "FAIL deny hit"; exit 1 ;; esac
    fi
    exit "${FAKE_RC_closure:-0}" ;;
  rewrite.py)
    mkdir -p "$out"
    while read -r f; do case $f in '#'*|'') ;; *) touch "$out/$f" ;; esac; done < "$files" ;;
  build.py)
    if [ "$sub" = stage ]; then
      mkdir -p "$work/stage"
      echo "a/Kept.cs" > "$work/kept.txt"; echo "_TurboNamespaceStubs.cs" > "$work/stage/stubs.txt"
      echo "Consumer.cs" > "$work/roots.txt"
      exit "${FAKE_RC_stage:-0}"
    fi
    mkdir -p "$work/dll"; touch "$work/dll/TurboBC.min.dll"
    exit "${FAKE_RC_build:-0}" ;;
  package.py) exit "${FAKE_RC_package:-0}" ;;
esac
exit 0
"""
FAKE_DOTNET = '#!/usr/bin/env bash\necho "${FAKE_SDK:-8.0.427}"\n'
FAKE_OPENSSL = '#!/usr/bin/env bash\necho "${FAKE_SSL:-OpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)}"\n'
SMOKE = '#!/usr/bin/env bash\necho "run.sh $*" >> "$FAKE_LOG"\nwhile [ $# -gt 0 ]; do [ "$1" = --results ] && echo ok > "$2"; shift; done\nexit "${FAKE_RC_smoke:-0}"\n'


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


class StripShTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.repo = t / "repo"
        (self.repo / "strip" / "roots").mkdir(parents=True)
        (self.repo / "crypto" / "src").mkdir(parents=True)
        shutil.copy(SCRIPT, self.repo / "strip" / "strip.sh")
        (self.repo / "strip" / "BASE").write_text("7c9c8d5a12b6342529936f08899cdb752280d538\n")
        (self.repo / "strip" / "ROOTS_SHA").write_text("3856398f548d1c41158567148647df1317e12740\n")
        self.home = t / "home"
        self.home.mkdir()
        self.fake = t / "fakebin"
        executable(self.fake / "python3", FAKE_PYTHON)
        executable(self.fake / "dotnet", FAKE_DOTNET)
        executable(self.fake / "openssl", FAKE_OPENSSL)
        self.sysbin = t / "sysbin"
        self.sysbin.mkdir()
        for name in SYSTEM_TOOLS:
            (self.sysbin / name).symlink_to(shutil.which(name))
        self.log = t / "calls.log"
        self.work = t / "work"

    def run_sh(self, *args, **env):
        e = {"PATH": f"{self.fake}:{self.sysbin}", "HOME": str(self.home), "FAKE_LOG": str(self.log)}
        e.update(env)
        return subprocess.run(
            [str(self.sysbin / "bash"), str(self.repo / "strip" / "strip.sh"), "--work", str(self.work), *args],
            capture_output=True, text=True, env=e, cwd=self.tmp.name,
        )

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def tools(self):
        return [c.split(" ", 2)[0] + ("" if not c.startswith("build.py") else " " + c.split(" ")[1])
                for c in self.calls()]

    # --- arguments and prerequisites ---

    def test_help(self):
        r = self.run_sh("--help")
        self.assertEqual(r.returncode, 0)
        self.assertIn("--refresh-roots", r.stdout)

    def test_usage_errors_exit_2_before_any_tool(self):
        for args in (["--bogus"], ["--refresh-roots"], ["--turbohttp", "/x"], ["--set"], ["--work"]):
            with self.subTest(args=args):
                r = self.run_sh(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("usage:", r.stderr)
        self.assertEqual(self.calls(), [])

    def test_dotnet_missing(self):
        (self.fake / "dotnet").unlink()
        r = self.run_sh("--report")
        self.assertEqual(r.returncode, 3)
        self.assertIn("export PATH=$HOME/.dotnet:$PATH", r.stderr)
        self.assertEqual(self.calls(), [])

    def test_dotnet_found_in_home(self):
        (self.fake / "dotnet").rename(self.home / "dotnet")
        executable(self.home / ".dotnet" / "dotnet", FAKE_DOTNET)
        r = self.run_sh("--report")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("dotnet 8.0.427", r.stdout)

    def test_old_sdk_rejected(self):
        r = self.run_sh("--report", FAKE_SDK="6.0.400")
        self.assertEqual(r.returncode, 3)
        self.assertIn(".NET SDK 8", r.stderr)

    def test_openssl_3_system_accepted_and_others_warn(self):
        r = self.run_sh("--report")
        self.assertNotIn("warning: OpenSSL", r.stdout)
        self.assertIn("OpenSSL 3.0.13", r.stdout)
        r = self.run_sh("--report", FAKE_SSL="OpenSSL 1.1.1w  11 Sep 2023")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("warning: OpenSSL 3.x not found", r.stdout)

    # --- step order, report and enforce ---

    def test_report_runs_every_step_in_order(self):
        r = self.run_sh("--report", "--set", "min")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tools(), ["closure.py", "build.py stage", "rewrite.py", "rewrite.py", "rewrite.py",
                                        "build.py build", "package.py"])
        calls = self.calls()
        self.assertNotIn("--report", calls[0].split())
        self.assertIn("--set min", calls[0])
        self.assertIn("--set min", calls[5])
        self.assertIn("--report", calls[5].split())
        self.assertIn("--base 7c9c8d5a12b6342529936f08899cdb752280d538", calls[6])
        self.assertIn("--roots-sha 3856398f548d1c41158567148647df1317e12740", calls[6])
        self.assertNotIn("--smoke", calls[6])
        self.assertTrue((self.work / "rewritten" / "lib" / "_TurboNamespaceStubs.cs").is_file())
        self.assertIn("no strip/smoke/run.sh yet", r.stdout)

    def test_enforce_clean_passes(self):
        r = self.run_sh()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("--report", " ".join(self.calls()))
        self.assertIn("clean", r.stdout)

    def test_enforce_stops_on_closure_fail_checks(self):
        r = self.run_sh(FAKE_CLOSURE_FAILS="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL strip.sh: closure fail checks", r.stderr)
        self.assertEqual(self.tools(), ["closure.py"])

    def test_report_goes_on_after_closure_and_build_failures(self):
        r = self.run_sh("--report", FAKE_CLOSURE_FAILS="1", FAKE_RC_build="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tools()[-1], "package.py")
        self.assertIn("report: 2 failing step(s)", r.stdout)
        # The package says it is not for handover (package.py --smoke embeds the note).
        note = self.work / "report-note.md"
        self.assertIn(f"--smoke {note}", self.calls()[-1])
        text = note.read_text()
        self.assertTrue(text.startswith("Not for handover"))
        self.assertIn("- closure fail checks", text)
        self.assertIn("Smoke: not run.", text)

    def test_report_logs_closure_fail_checks_and_marks_package(self):
        # closure.py exits 0 under its own --report: strip.sh must not rely on that flag (round 1).
        r = self.run_sh("--report", FAKE_CLOSURE_FAILS="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("REPORT strip.sh: closure fail checks", r.stdout)
        self.assertIn("report: 1 failing step(s)", r.stdout)
        self.assertTrue((self.work / "report-note.md").read_text().startswith("Not for handover"))

    def test_enforce_stops_on_compile_errors(self):
        r = self.run_sh(FAKE_RC_build="1")
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("package.py", self.tools())

    def test_tool_errors_are_fatal_in_report(self):
        for env, tools in (({"FAKE_RC_closure": "3"}, 1), ({"FAKE_RC_closure": "2"}, 1),
                           ({"FAKE_RC_build": "3"}, 6), ({"FAKE_RC_stage": "2"}, 2), ({"FAKE_RC_package": "1"}, 7)):
            with self.subTest(env=env):
                self.log.unlink(missing_ok=True)
                r = self.run_sh("--report", **env)
                self.assertEqual(r.returncode, 3, r.stdout)
                self.assertEqual(len(self.calls()), tools)

    def test_refresh_roots_runs_first(self):
        r = self.run_sh("--refresh-roots", "--turbohttp", "th", "--report")
        self.assertEqual(r.returncode, 0, r.stderr)
        first = self.calls()[0].split()
        self.assertEqual(first[0], "refresh_roots.py")
        # strip.sh resolves from bash $PWD, the realpath (/private/var/... on macOS, where TMPDIR is /var/...).
        self.assertEqual(first[first.index("--turbohttp") + 1], os.path.join(os.path.realpath(self.tmp.name), "th"))
        self.assertEqual(first[first.index("--strip-dir") + 1], "strip")

    # --- smoke hook ---

    def test_smoke_hook_runs_when_builds_clean_and_feeds_package(self):
        executable(self.repo / "strip" / "smoke" / "run.sh", SMOKE)
        r = self.run_sh()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = self.calls()
        smoke = next(c for c in calls if c.startswith("run.sh"))
        self.assertIn(f"--results {self.work}/smoke-results.md", smoke)
        self.assertIn(f"{self.work}/dll/TurboBC.min.dll", smoke)
        self.assertIn(f"--smoke {self.work}/smoke-results.md", calls[-1])

    def test_smoke_slow_is_opt_in(self):
        executable(self.repo / "strip" / "smoke" / "run.sh", SMOKE)
        self.assertEqual(self.run_sh().returncode, 0)
        smoke = next(c for c in self.calls() if c.startswith("run.sh"))
        self.assertNotIn("--slow", smoke)
        self.log.unlink()
        r = self.run_sh("--smoke-slow")
        self.assertEqual(r.returncode, 0, r.stderr)
        smoke = next(c for c in self.calls() if c.startswith("run.sh"))
        self.assertIn(f"--slow {self.work}/dll/TurboBC.min.dll", smoke)

    def test_smoke_failure_and_skip(self):
        executable(self.repo / "strip" / "smoke" / "run.sh", SMOKE)
        r = self.run_sh(FAKE_RC_smoke="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("FAIL strip.sh: smoke suite failed", r.stderr)
        self.log.unlink()
        r = self.run_sh("--report", FAKE_RC_build="1")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(any(c.startswith("run.sh") for c in self.calls()))
        self.assertIn("REPORT strip.sh: smoke skipped", r.stdout)

    def test_smoke_needs_openssl_3(self):
        executable(self.repo / "strip" / "smoke" / "run.sh", SMOKE)
        r = self.run_sh(FAKE_SSL="LibreSSL 3.3.6")
        self.assertEqual(r.returncode, 3)
        self.assertIn("needs OpenSSL 3.x", r.stderr)


class ModeBitTest(unittest.TestCase):
    def test_strip_sh_is_executable_in_git(self):
        r = subprocess.run(["git", "-C", str(REPO), "ls-files", "-s", "strip/strip.sh"],
                           capture_output=True, text=True)
        if r.returncode != 0 or not r.stdout:
            self.skipTest("not a git checkout")
        self.assertTrue(r.stdout.startswith("100755 "), r.stdout)
        self.assertTrue(os.stat(SCRIPT).st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
