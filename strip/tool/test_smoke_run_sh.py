"""Tests for strip/smoke/run.sh (issue #23), the smoke hook strip.sh calls: arguments, the upstream BASE
build and its reuse, one harness build and run per TurboBC DLL, the results file and the exit codes. run.sh
is copied into a temporary repository layout and run with fake dotnet and git on a PATH that holds nothing
else, so no dotnet build runs (the harness itself proves its row isolation with TurboSmoke --self-test)."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "smoke" / "run.sh"
BASE = "7c9c8d5a12b6342529936f08899cdb752280d538"
SYSTEM_TOOLS = ("bash", "env", "dirname", "basename", "tr", "cp", "rm", "cat", "mkdir", "touch")

# dotnet: `build <csproj> ... -o <dir>` creates the output (FAKE_RC_base fails the BASE build, FAKE_BUILD_FAIL
# names a TurboBcDll whose harness build fails); `<dir>/TurboSmoke.dll ...` runs the harness (FAKE_RC_selftest,
# FAKE_RC_run_<label>) and writes its --results file.
FAKE_DOTNET = r"""#!/usr/bin/env bash
echo "dotnet $*" >> "$FAKE_LOG"
if [ "${1:-}" = build ]; then
  proj=$2; out=""; dll=""
  while [ $# -gt 0 ]; do
    case $1 in -o) out=$2 ;; -p:TurboBcDll=*) dll=${1#-p:TurboBcDll=} ;; esac
    shift
  done
  case $proj in
    */BouncyCastle.Crypto.csproj)
      [ "${FAKE_RC_base:-0}" = 0 ] || exit "$FAKE_RC_base"
      mkdir -p "$out"; touch "$out/BouncyCastle.Cryptography.dll" ;;
    *)
      if [ -n "${FAKE_BUILD_FAIL:-}" ] && [ "$dll" = "$FAKE_BUILD_FAIL" ]; then echo "error CS0246"; exit 1; fi
      mkdir -p "$out"; touch "$out/TurboSmoke.dll" ;;
  esac
  exit 0
fi
shift
label=""; results=""
while [ $# -gt 0 ]; do
  case $1 in
    --self-test) exit "${FAKE_RC_selftest:-0}" ;;
    --label) label=$2 ;;
    --results) results=$2 ;;
  esac
  shift
done
var=FAKE_RC_run_$label
rc=${!var:-0}
if [ "$rc" = 0 ]; then r="1 rows, 1 passed, 0 failed"; else r="1 rows, 0 passed, 1 failed"; fi
printf 'TurboBC.%s.dll: %s\n' "$label" "$r" > "$results"
exit "$rc"
"""
FAKE_GIT = r"""#!/usr/bin/env bash
echo "git $*" >> "$FAKE_LOG"
[ "${1:-}" = -C ] && shift 2
if [ "${1:-} ${2:-}" = "worktree add" ]; then mkdir -p "$4/crypto/src"; fi
exit 0
"""


def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)


class SmokeRunShTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        t = Path(self.tmp.name)
        self.repo = t / "repo"
        (self.repo / "strip" / "smoke").mkdir(parents=True)
        shutil.copy(SCRIPT, self.repo / "strip" / "smoke" / "run.sh")
        (self.repo / "strip" / "BASE").write_text(BASE + "\n")
        self.fake = t / "fakebin"
        executable(self.fake / "dotnet", FAKE_DOTNET)
        executable(self.fake / "git", FAKE_GIT)
        self.sysbin = t / "sysbin"
        self.sysbin.mkdir()
        for name in SYSTEM_TOOLS:
            (self.sysbin / name).symlink_to(shutil.which(name))
        self.home = t / "home"
        self.home.mkdir()
        self.log = t / "calls.log"
        self.work = t / "work"
        self.results = self.work / "smoke-results.md"
        dll_dir = self.work / "dll"
        dll_dir.mkdir(parents=True)
        self.dlls = []
        for label in ("min", "partial"):
            p = dll_dir / f"TurboBC.{label}.dll"
            p.touch()
            self.dlls.append(str(p))

    def run_sh(self, *args, **env):
        e = {"PATH": f"{self.fake}:{self.sysbin}", "HOME": str(self.home), "FAKE_LOG": str(self.log)}
        e.update(env)
        return subprocess.run(
            [str(self.sysbin / "bash"), str(self.repo / "strip" / "smoke" / "run.sh"), *args],
            capture_output=True, text=True, env=e, cwd=self.tmp.name,
        )

    def run_hook(self, *extra, **env):
        """The call strip.sh makes: --work <work> --results <work>/smoke-results.md <dll>..."""
        return self.run_sh("--work", str(self.work), "--results", str(self.results), *extra, *self.dlls, **env)

    def calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def harness_builds(self):
        return [c for c in self.calls() if c.startswith("dotnet build") and "TurboSmoke.csproj" in c]

    def base_builds(self):
        return [c for c in self.calls() if c.startswith("dotnet build") and "BouncyCastle.Crypto.csproj" in c]

    # --- arguments ---

    def test_usage_errors_exit_2(self):
        cases = [
            (),
            ("--results", str(self.results), *self.dlls),
            ("--work", str(self.work), *self.dlls),
            ("--work", str(self.work), "--results", str(self.results)),
            ("--work", str(self.work), "--results", str(self.results), str(self.work / "TurboBC.none.dll")),
            ("--work", str(self.work), "--results", str(self.results), "--bogus", *self.dlls),
            ("--work", str(self.work), "--results", str(self.results), "--base-dll", str(self.work / "x.dll"),
             *self.dlls),
        ]
        other = self.work / "dll" / "Other.dll"
        other.touch()
        cases.append(("--work", str(self.work), "--results", str(self.results), str(other)))
        for args in cases:
            with self.subTest(args=args):
                r = self.run_sh(*args)
                self.assertEqual(r.returncode, 2, r.stderr)
                self.assertIn("usage:", r.stderr)
        self.assertEqual(self.calls(), [])

    # --- upstream BASE build ---

    def test_base_built_from_a_temporary_worktree_once_then_reused(self):
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        src = self.work / "smoke" / "base-src"
        git = [c for c in self.calls() if c.startswith("git")]
        self.assertIn(f"git -C {self.repo} worktree add --detach {src} {BASE}", git)
        self.assertIn(f"git -C {self.repo} worktree remove --force {src}", git[-1])
        self.assertEqual(len(self.base_builds()), 1)
        self.assertIn(f"-o {self.work}/smoke/base/bin", self.base_builds()[0])
        self.assertIn("-f net6.0", self.base_builds()[0])
        self.assertEqual((self.work / "smoke" / "base" / "BASE").read_text().strip(), BASE)

        self.log.unlink()
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("reusing", r.stdout)
        self.assertEqual([c for c in self.calls() if c.startswith("git")], [])
        self.assertEqual(self.base_builds(), [])

    def test_base_rebuilt_when_base_changes(self):
        self.assertEqual(self.run_hook().returncode, 0)
        (self.work / "smoke" / "base" / "BASE").write_text("0" * 40 + "\n")
        self.log.unlink()
        self.assertEqual(self.run_hook().returncode, 0)
        self.assertEqual(len(self.base_builds()), 1)

    def test_base_dll_option_skips_the_base_build(self):
        base_dll = self.work / "BouncyCastle.Cryptography.dll"
        base_dll.touch()
        r = self.run_hook("--base-dll", str(base_dll))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual([c for c in self.calls() if c.startswith("git")], [])
        self.assertEqual(self.base_builds(), [])
        for c in self.harness_builds():
            self.assertIn(f"-p:UpstreamBcDll={base_dll}", c)

    def test_base_build_failure_exits_3_and_removes_the_worktree(self):
        r = self.run_hook(FAKE_RC_base="1")
        self.assertEqual(r.returncode, 3)
        self.assertIn("upstream BASE build failed", r.stderr)
        self.assertIn("worktree remove --force", self.calls()[-1])
        self.assertEqual(self.harness_builds(), [])

    # --- per DLL ---

    def test_one_build_and_run_per_dll_and_results(self):
        r = self.run_hook()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        builds = self.harness_builds()
        self.assertEqual(len(builds), 2)
        for build, dll, label in zip(builds, self.dlls, ("min", "partial")):
            self.assertIn(f"-p:TurboBcDll={dll}", build)
            self.assertIn(f"-p:UpstreamBcDll={self.work}/smoke/base/bin/BouncyCastle.Cryptography.dll", build)
            self.assertIn(f"-o {self.work}/smoke/build/{label}/bin", build)
            self.assertIn(f"-p:BaseIntermediateOutputPath={self.work}/smoke/build/{label}/obj/", build)
        runs = [c for c in self.calls() if c.startswith("dotnet ") and "TurboSmoke.dll" in c]
        self.assertEqual(len([c for c in runs if "--self-test" in c]), 1)
        labelled = [c for c in runs if "--label" in c]
        self.assertEqual(len(labelled), 2)
        self.assertIn(f"--label min --dll {self.dlls[0]}", labelled[0])
        self.assertIn(f"--label partial --dll {self.dlls[1]}", labelled[1])
        text = self.results.read_text()
        self.assertEqual(text.splitlines()[0], f"Smoke suite (strip/smoke), BASE build: {BASE}")
        self.assertLess(text.index("TurboBC.min.dll: 1 rows"), text.index("TurboBC.partial.dll: 1 rows"))

    def test_filter_is_passed_to_every_run(self):
        self.assertEqual(self.run_hook("--filter", "curves").returncode, 0)
        labelled = [c for c in self.calls() if "--label" in c]
        self.assertTrue(labelled and all(c.endswith("--filter curves") for c in labelled), labelled)

    def test_failing_row_exits_1_and_keeps_every_block(self):
        r = self.run_hook(FAKE_RC_run_min="1")
        self.assertEqual(r.returncode, 1)
        text = self.results.read_text()
        self.assertIn("TurboBC.min.dll: 1 rows, 0 passed, 1 failed", text)
        self.assertIn("TurboBC.partial.dll: 1 rows, 1 passed, 0 failed", text)

    def test_harness_build_failure_exits_1_and_runs_the_other_dlls(self):
        r = self.run_hook(FAKE_BUILD_FAIL=self.dlls[0])
        self.assertEqual(r.returncode, 1)
        text = self.results.read_text()
        self.assertIn("TurboBC.min.dll: harness build failed", text)
        self.assertIn("TurboBC.partial.dll: 1 rows, 1 passed", text)

    def test_self_test_failure_exits_1(self):
        r = self.run_hook(FAKE_RC_selftest="1")
        self.assertEqual(r.returncode, 1)
        self.assertIn("harness self-test: FAILED", self.results.read_text())


if __name__ == "__main__":
    unittest.main()
