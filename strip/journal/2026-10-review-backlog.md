# 2026-10 Review-thread backlog on merged PRs #39-#64 (#71)

## What

Settled the 38 unresolved review threads (31 CodeQL, 7 review) left on the merged PRs #39, #40, #41,
#43, #53, #55, #56, #59 and #64, plus open CodeQL alert 48 (no thread). Each CodeQL alert has one of
two outcomes: a code fix, which the next analysis closes, or a dismissal with a written reason when the
code is deliberate. Each review nit is fixed in this PR or answered with evidence.

## Files

- `.github/workflows/codeql.yml`: `paths-ignore: ["strip/roots"]` in the inline config. The roots
  consumer copies are mirrored turboHTTP code, and `refresh_roots.py` checks that they stay
  byte-identical, so an alert in them could only ever be dismissed.
- `strip/smoke/harness/Program.cs`: `Path.Join` for the work directory (alert 28); the row loop
  iterates `selected.Select(SmokeRunner.Run)` (alert 48).
- `strip/smoke/harness/SmokeSelfTest.cs`: the "timeout" row's never-set event sits in a `using`
  block (alert 29). The wait still blocks until the runner's 1000 ms timeout, so the row order, names
  and the timeout check are unchanged.
- `strip/smoke/harness/SmokeAssert.cs`: `SmokeHex.Decode` filters whitespace with `Where` (alert 30).
- `strip/smoke/server/OpenSslServer.cs`: `Path.Join` (alerts 39-43); `string.Concat(_stdout,
  _stderr)` instead of two `ToString()` calls (37, 38). The best-effort `Kill` at exit now catches
  `InvalidOperationException` and `Win32Exception` instead of `Exception` (47).
- `strip/smoke/rows/InteropRows.cs` (`NewCertificates` via `ToDictionary`, 50),
  `HostileKeyRows.cs` (dropped the per-iteration copy, 51) and `OpenSslSigAlgReport.cs`
  (`Select(raw => raw.TrimEnd('\r'))`, 52).
- `strip/tool/test_upstream_tests.py`, `test_upstream_exclusions.py`: `import unittest.mock` in
  place of `from unittest import mock` (27, 53).
- Review nits:
  - `strip/roots/roots-extra.cs` (#43): the leaf check tests `DigitalSignature` alone. `KeyCertSign`
    is the CA bit (RFC 5280 4.2.1.3). The file is hand-maintained and compile-only; `refresh_roots.py`
    never touches it.
  - `strip/smoke/run.sh` (#53): the results header prints `base_label`, which each branch of step 1
    sets: the `--base-dll` path, or the BASE sha. Before, a stale `smoke/base/BASE` file was printed
    even when `--base-dll` was passed. Test:
    `test_smoke_run_sh.py::test_base_dll_option_names_the_dll_in_the_results_header`.
  - `strip/smoke/rows/LoopbackRows.cs` (#53): `Throws<TlsFatalAlert>` and an `AlertDescription`
    comparison replace the type-name and message match.
  - `strip/smoke/rows/KatAeadRows.cs` (#53): the ChaCha20 tamper row asserts
    `bad_record_mac`, which is what `BcChaCha20Poly1305.DoFinal` throws at
    `crypto/src/tls/crypto/impl/bc/BcChaCha20Poly1305.cs:65`. `Check` takes the tamper assertion as
    a delegate.
  - `strip/tool/upstream_tests.py` (#64):
    - `top_level_types` blanks comments and string/char literals (`CODE_NOISE`) before `TYPE_DECL`,
      and keeps only the outermost type level, so nested types are no longer reported under the
      namespace.
    - `entry_selects_type` also matches entries below the type (`Ns.Type.Method.`).
    - The tests are in `test_upstream_exclusions.py::ReportTest`.
- `strip/journal/2026-10-review-backlog.md`: this file.

## Decisions

- **CodeQL exclusion inline.** `paths-ignore` sits in the existing inline `config:` block, so the
  workflow stays a single file. The python and actions legs read it too, which is harmless.
- **Alert 47 narrowed, not dismissed.** `Process.Kill()` on a process this harness started locally
  fails with `InvalidOperationException` (no process, or disposed) or `Win32Exception` (could not
  terminate). `NotSupportedException` applies only to remote processes.
- **Dismissed, won't fix (roots mirrors):** 21, 22, 24, 25 (`BouncyCastleTlsProvider.cs`), 23 and 26
  (`TurboTlsAuthentication.cs`).
- **Dismissed, won't fix (E5 contract):** 19 (`TurboKeyFactory.cs` catch-all). E5 maps every SPKI
  parse failure to `ArgumentException`. A narrower catch would have to list every
  Asn1/IO/Cast/Arithmetic/Format exception the parser can throw, and missing one would leak another
  type to turboHTTP.
- **Dismissed, used in tests:** the smoke catch-alls that turn any exception into a failed row or a
  rethrown error, so a row never crashes the run: 31, 32, 33, 34, 35, 45, 46, 49.
- **#53 SmokeRowGroup stack-size note, no code change.** The #26 hostile rows already run on a 256 KB
  thread:
  - `HostileRows.cs:27` sets `StackBytes = 256 * 1024`.
  - `HostileRows.cs:128`: `Add` wraps every body in `OnSmallStack`.
  - `HostileRows.cs:132-148`: `OnSmallStack` starts `new Thread(..., StackBytes)`.
  - `HostileKeyRows.cs` registers through the same `Add`.
  - This matches STRIP_PLAN_V2.md:248.
- **Doc follow-up for the main session.** `strip/docs/agents/tooling.md:21-22` describes the CodeQL
  paths. It should mention that `strip/roots` is excluded. Waves lanes do not edit
  strip/docs/agents/.

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: OK.
- The new tests fail on the old `upstream_tests.py` and `run.sh`, and pass on the new ones.
- `./tools/ci/check.sh`: strip enforce build plus the fast smoke rows, including loopback, kat-aead,
  hostile and the self-test.
- After the PR's CodeQL run, `gh api 'repos/fatal10110/bc-csharp/code-scanning/alerts?state=open'`
  must be empty, and `wave_mail.py threads --pr N` must report 0 unresolved for N in 37..70.
