# Real Unity define sets and the enforce run (#29 part, #30, #20)

## What

- `strip/unity-defines.txt` holds the two captured Unity 2021.3.45f2 sets: `[netstandard21]` (104
  symbols) and `[netframework]` (101 symbols). Each is the unedited `/define:` list csc got for
  `TurboHTTP.Transport.BouncyCastle` in an Android IL2CPP player build (Library/Bee `.rsp`) of
  the probe project. The provisional `[min]`/`[partial]`/`[sdk]` sets are gone.
- `strip/budget.txt` = 748: the first enforced kept count (680) + 10%.
- `tools/ci/check.sh` (and so CI) runs `strip/strip.sh` in enforce mode. The `--report` run and
  the whole-library builds (netstandard2.0, net6.0) that existed only until #30 are gone.
- No E13 guard edit was needed for the real sets. #20 closes with this change.

## Files

- `strip/unity-defines.txt`: the two real sets, with a header recording the Unity version, the
  capture method and what BC sees.
- `strip/budget.txt`: the cap, with N, the formula and the rounding in the comment.
- `tools/ci/check.sh`: the strip step is `strip/strip.sh` (enforce); it fails when `strip.sh` is
  missing. The library-build loop is removed and the header is updated.
- `.github/workflows/ci.yml`: the comment describing the job.
- `strip/tool/test_defines.py`: `test_file_has_the_captured_unity_sets` replaces the provisional
  test. It pins the two sets, their sizes and differences, and that neither set has a
  `*_OR_GREATER`, `NETFRAMEWORK`, `NETCOREAPP` or LEAK_SUSPECTS symbol.
- `strip/tool/test_enforce_gate.py` (new): `budget.txt` is present and equals N + 10% rounded up,
  `check.sh` calls `strip/strip.sh` without `--report`/`--smoke-slow`, and it no longer builds
  `BouncyCastle.Crypto.csproj`. All 3 tests fail on strip-v2 4f5c5913.
- `strip/tool/defines.py`, `deny.py`, `build.py` and `strip/Closure.csproj`: comment and docstring
  wording only (no provisional sets any more).

## Decisions

- **Drop the provisional sets.** Evidence:
  - The kept files use 15 distinct `#if` symbols: `DEBUG`, `NET40/45_OR_GREATER`,
    `NET5_0/6_0/8_0/9_0_OR_GREATER`, `NETCOREAPP1_0/1_1/2_0/2_1/3_0_OR_GREATER` and
    `NETSTANDARD1_0/2_0/2_1_OR_GREATER`. Neither real set defines any of them. So for BC,
    `[netstandard21]` is exactly the old `[min]`, and every `#if` in the shipped code takes its
    legacy (non-Span, non-intrinsics) branch.
  - `[partial]` and `[sdk]` model configurations Unity 2021.3 never produces. In the union closure
    they only added two Span-only files to the shipped Lib: `util/Spans.cs` and
    `util/collections/ReadOnlySet.cs`. The closure over the old 3-set file keeps 682 files; over
    the real sets it keeps 680.
  - Only `test_defines.py` pinned the provisional sets. Other tests use `min` and `sdk` as fake
    set names only.
  - The E13 edits from #51 stay. They are inert under the real sets, because nothing defines
    `NETSTANDARD2_1_OR_GREATER`. They are no longer compiled by any strip build. They matter
    again only if a later Unity version starts defining `*_OR_GREATER`, and then a new capture
    and enforce run would show it.
- **No new E13 fix.** Builds 3a and 3c (stripped tree, rewritten tree and consumer) have
  0 compile errors for both sets. `[netframework]` against the net471 reference assemblies was
  built here for the first time and is clean. #20's rule leaves nothing to fix: `Closes #20`.
- **Budget:** N = 680 kept files (first enforced run, both sets). Cap = 680 × 1.1 = 748 exactly.
  A fractional result would have been rounded up; the test computes `ceil(N * 1.1)`.
- **check.sh:** enforce without `--smoke-slow`, so CI keeps only the fast smoke rows (about
  2 min 15 s for the strip step locally). `strip.sh` missing is now a gate failure rather than a
  silent skip.
- **`[partial]` CopyToAsync note (#51, w1030 journal):** under both real sets none of
  `NETCOREAPP1_0_OR_GREATER || NET45_OR_GREATER || NETSTANDARD1_0_OR_GREATER` is defined. The
  `CopyToAsync` overrides (`util/io/FilterStream.cs:38`, `tls/TlsStream.cs`,
  `BaseInput/OutputStream`) are therefore not compiled, and `System.IO.Stream.CopyToAsync` (the
  base implementation over `Read`/`Write`) is used, as under the old `[min]`. The trees compile
  either way (3a/3c clean). `Streams.CopyToAsync` is still compiled.
- **Smoke on the `[netframework]` DLL:** the net8 harness (`strip/smoke/TurboSmoke.csproj`)
  compiles against `TurboBC.netfx.dll` and loads it. It references mscorlib 4.0.0.0, which
  .NET 8 serves through its facade forwarding. All rows pass, so both real sets' DLLs are
  smoke-tested here. What this does not cover is Mono/IL2CPP at Unity's .NET Framework API level.
  The Unity compile check (CompilePlayerScripts at both levels) covers that; see below.

## How verified

- `strip/strip.sh --report --work <tmp>` (first run with the real sets): kept 680, 0 denied,
  0 unresolved, builds 3a/3c 0 errors for both sets, smoke 214/214 per DLL.
- `strip/strip.sh --smoke-slow` (enforce, all sets): `kept: 680 files, budget: 748`, CLEAN,
  0 deny hits, 0 unresolved, 6 builds 0 errors. Smoke: TurboBC.netfx.dll 215/215 and
  TurboBC.ns21.dll 215/215, including `timeout/trickle-handshake-timeout-30s`. Total 2 min 46 s.
- Per directory (kept 680): asn1 177, crypto 135, math 120, runtime 1, security 14, tls 193,
  turbo 2, util 33, x509 5.
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: OK. The new
  `test_enforce_gate.py` tests (3) fail on the old `check.sh` without `budget.txt`.
- `./tools/ci/check.sh --full`: see the PR's Local gates section.
- Unity 2021.3.45f2 probe (Lib from this `strip/out`): see below.

## Unity validation

Unity 2021.3.45f2, Windows host, probe project `E:\turbo-strip-probe\proj` consuming a copy of
turboHTTP@3856398f. Its `Runtime/Transport/BouncyCastle/Lib` was replaced (rsync `--delete`) by
`strip/out/Lib` from the enforce run above (681 `.cs` files: 680 kept files and the namespace
stubs).

- `TurboStripProbe.Capture`, `CompilePlayerScripts` for StandaloneWindows64, Android and iOS:
  OK (23 assemblies each) at both API levels, ".NET Standard 2.1" and ".NET Framework"
  (NET_Unity_4_8). The player define lists recorded by the capture have the same BC-relevant
  symbols as the committed sets: `NETSTANDARD NETSTANDARD2_1 NET_STANDARD NET_STANDARD_2_0
  NET_STANDARD_2_1`, and `NET_4_6 NET_UNITY_4_8`. Neither has a `*_OR_GREATER` symbol.
- turboHTTP TLS PlayMode tests at NS2.1 with `TURBOHTTP_INTEGRATION_TESTS` (filter
  `TurboHTTP\.Tests\.Transport\.(Tls|Http1\.RawSocketTransportProxyTunnel)`, real handshakes
  through BC): 92 total, 87 passed, 0 failed, 5 skipped. Of the skips, 4 need local self-signed
  certificate generation and 1 needs BC to be absent. This matches the capture run on the
  683-file Lib from 69c22288.
- The probe's scripting defines were reset to empty afterwards.
