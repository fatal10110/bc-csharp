# 2026-10 strip.sh orchestration (#10)

## What

`strip/strip.sh` runs `STRIP_PLAN_V2.md` §5 steps 1–7 with the merged tools: prerequisites and
`--refresh-roots --turbohttp <path>` (refresh_roots.py), closure + deny + sweep + budget (closure.py),
staging, the namespace rewrite (rewrite.py), builds 3a/3c (new `strip/tool/build.py`), the smoke hook
for #23 and packaging (package.py). Enforce mode (default) stops with exit 1 at the first failing
step; `--report` logs those failures and still packages. `tools/ci/check.sh` already runs
`strip/strip.sh --report` once it is executable, so from this PR on the gate runs the pipeline instead
of the netstandard2.0/net6.0 library builds.

## Files

- `strip/strip.sh` (mode 100755): argument parsing (`--report`, `--refresh-roots`, `--turbohttp`,
  `--set`, `--work`, `--out`, `--old-base`; usage errors exit 2), prerequisites (python3 ≥ 3.8, git,
  dotnet SDK ≥ 8 with a `~/.dotnet` fallback, `openssl version` 3.x as a warning), the step sequence,
  the smoke hook and the report note. bash-3.2 portable, shellcheck clean.
- `strip/tool/build.py`: `stage` (kept list = closure files − denied, roots list, the kept tree's
  namespace stubs) and `build` (per define set: 3a stripped tree → `TurboBC.Strip.<x>.dll`; 3c
  rewritten tree → `TurboBC.<x>.dll`; the rewritten roots — consumer files, `RootStubs.cs`,
  `roots-extra.cs` — as a separate assembly referencing it → `TurboBC.Consumer.<x>.dll`).
  `StageBuilder` subclasses closure.py's `DotnetBuilder` (Closure.csproj copy, CS3021 suppressed,
  restore once per project, binlog define assertion on every build), adding an `AssemblyName` and a
  `Reference` to the generated props.
- `strip/tool/test_build.py`: staging, DLL naming, props, the build loop with a fake builder.
- `strip/tool/test_strip_sh.py`: strip.sh in a temporary repository layout with fake python3, dotnet
  and openssl on a PATH that holds nothing else: usage errors, prerequisites, step order, report vs
  enforce, tool errors, refresh-roots, the smoke hook; the git mode bit.

## Decisions

- **Builds in `--report`:** compile errors are logged (`REPORT build [<key>]: N compile error(s)`,
  the first 10 per build, all of them in `<work>/build_report.json`) and the run goes on to package.
  Enforce fails on them. The 3c consumer compile is skipped when its `TurboBC.<x>.dll` did not build
  (it cannot reference a missing DLL); that is reported too. Infrastructure errors (restore, build
  failure without compile errors, a tool error) exit 3 in both modes.
- **Shipped stubs:** the stubs of the kept tree: closure.py's `sweep_stubs` (closure − denied + roots)
  when the sweep ran, else the fixpoint stubs. Identical today
  (`Org.BouncyCastle.Crypto.Agreement.Srp`); they would diverge once a denied file is the only
  declarer of a namespace a kept using names.
- **DLL names:** `TurboBC.ns21` for `[netstandard21]`, `TurboBC.netfx` for `[netframework]`, else
  `TurboBC.<set>` (the provisional `[min]`/`[partial]`/`[sdk]`, all netstandard2.1).
- **Step order:** the rewrite (4) runs before the builds (3) because 3c compiles its output; the
  3a build of the unrewritten tree is library-only (the consumer check is 3c's).
- **build.py exit 1 also under `--report`** (unlike closure.py): `--report` only changes the line
  prefix, strip.sh owns report/enforce for builds and needs the signal to skip the smoke hook.
- **closure.py runs without its `--report` in both modes:** its `--report` exits 0 on fail checks,
  which would hide deny hits, budget overrun and unresolved errors from strip.sh's report summary
  and the package note. Without it closure.py prints every `FAIL` line and exits 1; strip.sh logs
  that as a failing step (report) or stops (enforce).
- **Smoke hook contract (#23):** `strip/smoke/run.sh --work <work> --results <file> <TurboBC dll>...`,
  run only when it is executable and every build is clean; exit 0 = pass; the results file feeds
  `package.py --smoke`. Without the hook STRIP_INFO.md says "Not run.". The hook requires OpenSSL 3.x
  (system OpenSSL accepted); without the hook OpenSSL is only a warning.
- **Report packages are marked:** when `--report` packages with failing steps, STRIP_INFO.md's smoke
  section starts with "Not for handover: ..." and lists them, so a report package cannot pass for a
  release.
- **CI:** no workflow change. ubuntu-latest ships python3; the net471 reference pack comes from NuGet
  through Closure.csproj when a `[netframework]` set exists (none of the provisional sets), and the
  NuGet cache key already covers `strip/**/*.csproj`.
- **check.sh keeps the library builds:** `strip.sh --report` never fails on compile errors of the
  stripped builds (all of them have errors until #19/#20), so the gate still builds `crypto/src`
  for netstandard2.0 and net6.0 after it. Without that a cut that breaks kept code would pass the
  gate. #30 switches the gate to enforce (and adds `strip/budget.txt`) and can drop the loop.

## Deferred

- Enforce mode in check.sh/CI and `strip/budget.txt` → #30. The smoke suite behind the hook → #23–#27.
- A clean cut tree (deny referrers E9–E12 → #19; [partial]/[sdk] guard errors E13 → #20); until then
  every build of the kept tree fails and the consumer compile is skipped in the gate.

## How verified

- `strip/strip.sh --report` on b886b9d8: exit 0 in ~100 s (closure 86 s, rewrite + 9 builds/skips
  14 s, package); 713 kept files, 1 stub; builds [min] 10 errors (the 7 #19 referrers), [partial]
  189, [sdk] 6; consumers skipped; `strip/out` packaged (714 files).
- `strip/strip.sh --refresh-roots --turbohttp /home/zorg/workspace/turboHTTP` (enforce): roots and
  ROOTS_SHA unchanged, exit 1 at the closure fail checks (deny hits, unresolved errors).
- Consumer compile and net471: with `closure.py --no-deny --set min` in a scratch work dir, then
  `build.py stage`, the three rewrites and `build.py build`: 3a, 3c and the consumer assembly against
  `TurboBC.min.dll` build clean; the same kept tree with a scratch `[netframework]` set
  (`NETFRAMEWORK;NET471`) builds `TurboBC.netfx.dll` and its consumer clean (reference pack restored).
- `git status --porcelain` clean under `crypto/src` and `strip/roots` after every run.
- `test_strip_sh.py`'s fake closure.py follows the real exit contract (0 under `--report`, 1
  without); the report tests fail on a strip.sh that passes `--report` to closure.py.
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`, `shellcheck strip/strip.sh`,
  `./tools/ci/check.sh`.
