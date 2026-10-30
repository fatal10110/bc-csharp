# 2026-10 — Closure engine: Closure.csproj, define sets, closure.py (#6, #7)

## What

The closure step of STRIP_PLAN_V2.md §5 step 2 with the build setup of §4: a template
`Closure.csproj`, generated per-set props carrying exactly the captured defines, a binlog assertion
that csc received exactly those defines, and a rewritten closure resolver (C# lookup order, arity,
partial units, extension index, namespace stubs outside `crypto/src`, union fixpoint over define
sets, fail checks at the fixpoint). Replaces the prototype `index.py`/`closure.py`.

## Files

- `strip/Closure.csproj` — template; explicit `Sdk.props`/`Sdk.targets` imports so
  `ImportDirectoryBuild*=false` takes effect; `EnableDefaultCompileItems=false`, LangVersion 9,
  `AllowUnsafeBlocks=false`, `DisableImplicitFrameworkDefines`/`DisableImplicitConfigurationDefines`;
  imports the generated `Closure.props` after `Sdk.props` (so its `<DefineConstants>` replaces TRACE);
  `Microsoft.NETFramework.ReferenceAssemblies` only when the TFM is net471.
- `strip/unity-defines.txt` — provisional `[min]`, `[partial]`, `[sdk]` sets (plan §4); #29 swaps in
  `[netstandard21]`/`[netframework]` without code changes (section names are generic; only
  `netframework` maps to net471, every other set to netstandard2.1).
- `strip/tool/defines.py` — parser, TFM mapping, props rendering (MSBuild/XML escaping), csc
  `/define:` extraction from the replayed binlog, set comparison with leakage reporting.
- `strip/tool/index.py` — light C# scanner (comments/literals blanked, brace frames, all `#if`
  branches with the frame stack restored per branch) and `Index`: (namespace, name, arity) → files,
  nested types as `Outer.Inner` in the outer file, partial units, extension methods, namespaces.
- `strip/tool/closure.py` — `Resolver` (lookup levels, CS0246/0103/0305/0308/0426/0234/1061/1501),
  `run_closure` (fixpoint over all sets, stubs every iteration, prune + rebuild at the fixpoint),
  `DotnetBuilder` (per-set project dir, `dotnet restore` once, `--no-restore` loop, binlog assertion
  on the first and final build), `CHECKS` (fail checks), CLI.
- `strip/tool/test_defines.py`, `test_index.py`, `test_closure.py` — 48 tests, no dotnet/network.
- `.gitignore` — `/strip/work/` (default work directory).

## Decisions

- **Roots input:** `--roots DIR|FILE` (repeatable, outside `crypto/src`) plus `--seed` for
  `crypto/src` paths; `crypto/src/turbo/` is seeded automatically when it exists. `strip/roots/` is
  #5's; `strip.sh` (#10) will pass it.
- **"Converges"** = the fixpoint is reached (no set adds a file or namespace). Errors left at the
  fixpoint are unresolved and fail the run unless `--report`; for the provisional sets these are
  the E13 guard errors (#20), which adding files cannot fix.
- **Lookup continues outward past compiled candidates:** if the winning level's files are already
  compiled and the error persists, the type is not declared under this define set, so C# itself
  would look further out. Keeps `#if`-only declarations from stalling the loop.
- **Stubs** are written to `<work>/_nsstubs.cs` every iteration (every `crypto/src` namespace a kept
  using names, plus namespace hits from qualified names). Non-BC namespaces (System, UnityEngine,
  TurboHTTP) are never stubbed: references or the root stubs provide them. At the fixpoint the
  survivors (named by a kept using, declared by no kept file, ancestors of other survivors dropped)
  go to `<work>/_TurboNamespaceStubs.cs`; packaging it as `Lib/_TurboNamespaceStubs.cs` is #9.
- **Define assertion** replays the binlog to a text log (`dotnet msbuild x.binlog -noConsoleLogger
  -fl`), no extra tools; the assertion build uses `--no-incremental` so CoreCompile always runs, and a
  log without a csc line is an error, not a pass.
- **Output shapes kept:** `closure_files.json` (sorted `crypto/src`-relative paths; roots are no
  longer listed) and `prov.json` (`{file: ["referrer:Name"]}`; root referrers are repo-relative), so
  `deny.py` and #8 consume them unchanged.
- **Hooks for #8:** `closure.CHECKS` is the list of fixpoint checks (`ClosureResult` → failure lines);
  deny hits, the referrer sweep and the budget are added there. `deny.py` is untouched.

## Deferred

- Deny list, referrer sweep, budget → #8. `strip.sh` → #10. Packaging of the stubs → #9.
- net471 (`[netframework]`) needs `Microsoft.NETFramework.ReferenceAssemblies.net471` from NuGet;
  not cached on the dev box, so only exercised once #29 delivers the real set.

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py'` — 48 tests OK.
- Acceptance run on unpatched `crypto/src` (BASE 7c9c8d5a + strip-v2 tooling commits), all three
  provisional sets, roots = the three turboHTTP consumer files with the rewrite reversed plus a
  scratch stand-in for `RootStubs.cs` (#5 owns the real one):
  `python3 strip/tool/closure.py --roots <scratch roots> --work <scratch> --report`
  → define assertion ok for `[min]`, `[partial]`, `[sdk]` (first and final build); fixpoint after
  27 iterations, 930 files, 1 surviving stub (`Org.BouncyCastle.Asn1.Cmp`), 0 same-level ties;
  `[min]` clean; `[partial]` 192 unresolved errors in the 11 E13 files (`Pack.cs`, `Streams.cs`,
  `TlsStream.cs`, `Base{Input,Output}Stream.cs`, `FilterStream.cs`, `Poly1305.cs`,
  `ChaCha7539Engine.cs`, `DigestSink.cs`, `SignerSink.cs`, `X448Field.cs`); `[sdk]` 6, all in
  `Poly1305.cs:254,257` — matching plan §4. ~85 s for the whole run.
- `X509Certificate.cs`'s `X509Utilities` binds to `x509/X509Utilities.cs` (prov
  `x509/X509Certificate.cs:X509Utilities`; real-tree test). `Asn1Signature.cs` is still in the
  closure, but only via `Asn1VerifierFactory`/`Asn1VerifierFactoryProvider` (E8's territory).
- `git status` after the run: no file under `crypto/src` changed.
- `./tools/ci/check.sh` (see the PR's Local gates).
