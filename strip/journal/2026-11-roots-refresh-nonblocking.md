# 2026-11 — roots refreshed to turboHTTP main (BouncyCastleTlsStream), non-blocking smoke rows (#75)

## What

The closure roots now mirror the turboHTTP glue that actually consumes `Lib/`: the rewritten
`BouncyCastleTlsProvider.cs`, the new non-blocking `BouncyCastleTlsStream.cs`, and the current
`TurboTlsClient.cs` / `TurboTlsAuthentication.cs`, copied from turboHTTP `main`
`5b92ce86c7fa646cf0f55c12c53b161edcea0f99` (`ROOTS_SHA`, was `3856398f`). A smoke row group drives
the non-blocking `TlsClientProtocol` API the stream relies on.

## Files

- `strip/roots/BouncyCastleTlsStream.cs` (new), `BouncyCastleTlsProvider.cs`, `TurboTlsClient.cs`,
  `TurboTlsAuthentication.cs`, `strip/ROOTS_SHA` — written by `refresh_roots.py --rev origin/main`.
- `strip/roots/RootStubs.cs` — stand-ins the current glue needs beyond `ITlsProvider`/`TlsResult`/
  `PreserveAttribute`: `CertificateVerificationStatus`, `CertificateVerificationResult`,
  `ServerCertificateVerifier` (`MaxChainLength`, `Verify`), `TlsHostName` (`ToSniHostName`,
  `ToTargetHost`), `TlsCertificateNameMatcher.Matches`, and `AndroidTrustManagerVerifier.EnsureRegistered`
  (called under `UNITY_ANDROID && !UNITY_EDITOR`, which both captured sets define). Signatures mirror
  turboHTTP; the verifier, matcher and host-name stubs throw `NotSupportedException`.
- `strip/tool/refresh_roots.py` — `CONSUMER_FILES` has four entries.
- `strip/roots/BouncyCastleTlsStream.net471.cs` (new, hand-maintained) — the `[netframework]` stand-in for
  the stream: the constructor and `HandshakeAsync(TlsClient, CancellationToken)` the provider uses plus the
  abstract `Stream` members, all throwing.
- `strip/tool/defines.py` — `NET471_EXCLUDED_ROOTS = {BouncyCastleTlsStream.cs}`,
  `NET471_ONLY_ROOTS = {BouncyCastleTlsStream.net471.cs}` and `roots_for_set`, which swaps them for the
  net471 set.
- `strip/tool/closure.py` — the fixpoint and the sweep compile `roots_for_set(set, roots)` per set.
- `strip/tool/build.py` — the 3c consumer build of each set gets `roots_for_set`.
- `strip/smoke/client/SmokeNonBlockingConnection.cs` (new) — the consumer's engine loop in the
  harness: `Connect`, `OfferInput`, `ReadOutput`, `GetAvailableInputBytes`, `GetAvailableOutputBytes`,
  `ReadInput`, `WriteApplicationData`, `CloseInput`, blocking socket I/O.
- `strip/smoke/rows/NonBlockingRows.cs` (new) — group `nonblocking`, order 55: TLS 1.3 and 1.2 echo,
  the locally raised `bad_certificate` alert reaching the server through `ReadOutput`, and a transport
  close without close_notify surfacing as `TlsNoCloseNotifyException` from `CloseInput`.
- `tools/ci/check.sh` — the format step skips the files `refresh_roots.py` writes (read from its
  `CONSUMER_FILES`): they are turboHTTP-formatted (`csharp_indent_switch_labels` differs) and must stay
  byte-identical, as CodeQL already assumes. The hand-maintained roots files are still formatted.
- `strip/smoke/client/SmokeTlsClient.cs` — re-aligned with the refreshed `TurboTlsClient` (crypto-security
  review): SNI through `GetSniServerNames` (ASCII host, none for an IP literal) instead of a direct
  `AddServerNameExtensionClient`, and the consumer's explicit `OfferedCipherSuites` list through
  `TlsUtilities.GetSupportedCipherSuites`, so the exact-ClientHello rows assert the consumer's code path.
- Tests: `test_refresh_roots.py` (four consumer files), `test_defines.py` (`roots_for_set`; the swapped
  names exist and are consumer files), `test_closure.py` (the net471 set compiles one root fewer),
  `test_deny.py` (the sweep compiles the set's roots), `test_build.py` (the net471 consumer build leaves
  the stream out). `refresh_roots.py` prints a reminder to re-check the stand-in when the stream copy changes.
- Docs: `STRIP_PLAN_V2.md` §4 tree comment (4 consumer files), `strip/docs/agents/architecture.md`,
  `strip/docs/agents/testing.md`.

## Decisions

- **`BouncyCastleTlsStream.cs` is a root for the netstandard2.1 sets only.** It overrides
  `Stream.ReadAsync(Memory<byte>, …)` / `WriteAsync(ReadOnlyMemory<byte>, …)` and uses `ValueTask` and
  `MemoryMarshal`. Unity's Mono BCL has them at the .NET Framework API level (turboHTTP ships it there),
  the `Microsoft.NETFramework.ReferenceAssemblies` net471 surface the `[netframework]` set builds against
  does not (probe: CS0246 `Memory<>`, `ValueTask`). Its Bouncy Castle surface is `TlsClientProtocol`'s
  non-blocking members, which carry no `#if`, so the `[netstandard21]` set (and its DEBUG variant) checks
  them for every DLL. The provider references the stream, so the net471 set compiles a throwing stand-in
  (`BouncyCastleTlsStream.net471.cs`) in its place; without it the first enforce run failed with
  `[netframework] unresolved: BouncyCastleTlsProvider.cs(166,36): CS0246 BouncyCastleTlsStream`.
  Alternative rejected: an API-contract copy in `roots-extra.cs`, which would drift from turboHTTP the way
  the issue describes.
- **The swap is two constants in `defines.py`, keyed by TFM**, not a data file: one file pair today, and
  the reason is a compiler fact about the reference assemblies, not a policy.
- **Stubs throw.** `ServerCertificateVerifier.Verify`, `TlsCertificateNameMatcher.Matches` and
  `TlsHostName` are decision-A code that lives in turboHTTP; a permissive stub could one day stand in for
  the real check, a throwing one cannot.
- **Only the four BC-referencing glue files are roots.** `AndroidTrustManagerVerifier.cs`,
  `BouncyCastleModuleRegistration.cs` and `AssemblyInfo.cs` reference UnityEngine only.
- **The format gate never touches the copies.** The first `check.sh --full` failed with 56 WHITESPACE
  errors in `BouncyCastleTlsProvider.cs` and `TurboTlsAuthentication.cs` (switch-label indentation);
  reformatting would break the refresh round-trip, so the copies are excluded, not fixed.
- **Smoke keeps a mirror, not the consumer file.** The harness compiles against `TurboBC.*.dll` on
  net8; `SmokeNonBlockingConnection` mirrors the stream's engine loop (plan §5: the client mirrors
  `TurboTlsClient` the same way). The stream itself is compile-checked by the 3c consumer build.

- **Review fixes (strip-build-reviewer, no blockers):** sweep-path test for the root swap, the consistency
  test and refresh reminder above, plan §5 step 3c and the `build.py` docstring say the roots are per set.
  Noted, not changed: the swap keys on `tfm_for_set`, so a future `netframework_debug` variant would need
  `tfm_for_set` to know it (pre-existing coupling).
- **Review fixes (crypto-security-reviewer, no blockers):** the smoke connection throws `IOException` on a
  closed-and-failed engine like the consumer (`IsFailed` is now exercised on both DLLs; the truncation row
  asserts it and a failing follow-up read); the post-failure output flush swallows every exception as the
  consumer does; the handshake-EOF divergence (`TlsFatalAlert(handshake_failure)` here, `IOException` in the
  consumer) is documented; `AndroidTrustManagerVerifier.EnsureRegistered` throws like the other stubs.

- **Review round 2 (PR 76 threads):**
  - `nonblocking/pinned-mismatch-alert-reaches-server` raced the server's flight and failed CI on Linux
    (`Broken pipe`: BC's TLS 1.3 server writes its flight as separate records and signs CertificateVerify
    between them; the client rejects at Certificate, sends the alert and closes; the server's next write
    hits the closed socket). Replaced by `pinned-mismatch-alert-via-readoutput`: TLS 1.2 (plaintext alert),
    the engine driven by hand, and the output queue after the failing `OfferInput` asserted byte for byte
    (`15 03 03 00 02 02 2A`); the server's outcome is accepted either way, as long as it never completed.
  - `nonblocking/truncation-mid-record`: a `TruncatingStream` drops the last 5 bytes of the echo record
    before the socket closes, so `CloseInput` takes its `EndOfStreamException` path (input buffered); the
    row asserts the exact type on two consecutive reads, never 0.
  - `strip/roots.sha256`, written by `refresh_roots.py`, pins the copies the format step and CodeQL skip;
    `test_refresh_roots.CommittedRootsTest` checks the committed copies against it, so a hand edit fails a
    unit test. `check.sh` exits 2 if the copies list cannot be derived (never formats the copies by accident).
  - CodeQL: `assertLessEqual`, and specific `IOException`/`ObjectDisposedException` catches in the smoke
    connection's post-failure flush.

## Deferred

- None. The hand-over comment on turboHTTP (acceptance item 3) is posted by the owner once the PR is
  merged: whether `Lib/` changed is recorded below.

## How verified

- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: 201 tests (the new ones failed before
  the change, pass after).
- After review round 2: `./tools/ci/check.sh --full` OK again; smoke 277/277 fast rows on both DLLs (the five
  `nonblocking/*` rows included), 27/27 DEBUG, 126 NUnit, 41 + 201 tool tests.
- `strip/strip.sh --smoke-slow` (enforce, 133 s): fixpoint 680 files, 1 namespace stub, 0 ties; 0 deny hits,
  budget 748; 0 unresolved names in both sets (the first run, without the net471 stand-in, failed on
  `BouncyCastleTlsProvider.cs: CS0246 BouncyCastleTlsStream` in `[netframework]`); builds 3a/3c/consumer
  clean for `netstandard21`, `netframework` and `netstandard21_debug`; smoke 277/277 on `TurboBC.ns21` and
  `TurboBC.netfx` (273 before, plus the four `nonblocking/*` rows), 27/27 on `TurboBC.ns21-debug`.
- `./tools/ci/check.sh --full`: OK (format of the hand-maintained files, enforce strip, smoke, actionlint,
  shellcheck, 126/126 turbo NUnit tests, 41 + 199 Python tool tests, waves simulation). The first run
  failed only on the format step over the turboHTTP copies (see Decisions).
- `Lib/` unchanged: `strip/out/Lib` is byte-identical to turboHTTP `main` 5b92ce86's
  `Runtime/Transport/BouncyCastle/Lib` (synced from hand-over commit `4df803aa`), `.meta` files included;
  only turboHTTP's own `TurboHTTP.SecureProtocol.asmdef` exists there and not here. `STRIP_INFO.md` records
  the new `ROOTS_SHA`. No re-sync is needed; the hand-over note on turboHTTP states that.
