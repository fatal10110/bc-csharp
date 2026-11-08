# 2026-11 — roots refreshed after turboHTTP#344, AbandonableTask root stub (#79)

## What

- `strip.sh --refresh-roots` against turboHTTP `main` failed: turboHTTP#354 (the fix for turboHTTP#344)
  made `BouncyCastleTlsProvider.WrapAsync` await `TurboHTTP.Transport.Internal.AbandonableTask.WaitAsync`,
  which `RootStubs.cs` did not stub. Both sets failed with CS0234 on `TurboHTTP.Transport.Internal`
  and the closure collapsed to 186 files.
- The closure roots now mirror turboHTTP `main` `c4f3eb8aadf6194ff9a2e99df064eba3b556c75a` (`ROOTS_SHA`,
  was `957a9ad`). The provider races the handshake against the token and the deadline and abandons it.
  The stream gains `[UnityEngine.Scripting.Preserve]` on `MaxPendingOutputBytes` and its setter. The glue
  uses no new Bouncy Castle API.
- An unresolved name in a `strip/roots/` file whose message does not name `Org.BouncyCastle` now
  carries a hint pointing at `RootStubs.cs`.

## Files

- `strip/roots/BouncyCastleTlsProvider.cs`, `BouncyCastleTlsStream.cs`, `strip/ROOTS_SHA`,
  `strip/roots.sha256`: written by `refresh_roots.py --turbohttp <turboHTTP worktree at c4f3eb8>`.
- `strip/roots/RootStubs.cs`: `TurboHTTP.Transport.Internal.AbandonableTask` with the two `WaitAsync`
  overloads of turboHTTP `Runtime/Transport/Internal/AbandonableTask.cs`, both throwing. The header
  lists the file among the mirrored ones.
- `strip/tool/closure.py`: `unresolved_hint`, used by `check_unresolved`.
- `strip/tool/test_closure.py`: `test_unresolved_name_in_a_root_points_at_root_stubs`.

## Decisions

- **Only the members the glue uses.** `Observe` is left out, like the other stubs.
- **The hint is conditional.** Roots name Bouncy Castle types through `using`, so a removed or denied
  BC type gives an unqualified CS0246 that cannot be told apart from a missing turboHTTP type by the
  message alone. The hint reads "if this is a turboHTTP or Unity type, ..." (both specialist rubrics).
  A CS0234 that names `Org.BouncyCastle` gets no hint.
- `BouncyCastleTlsStream.net471.cs` is unchanged: the provider still uses only the constructor and
  `HandshakeAsync`.

## Deferred

- None. turboHTTP's `Runtime/Transport/BouncyCastle/README.md` Provenance table is turboHTTP's to update
  on its next re-sync (issue #79, "turboHTTP side").

## How verified

- The new test fails on the old `closure.py` (no hint) and passes now. `strip/tool`: 215 OK;
  `tools/agent-tools`: 41 OK.
- `./tools/ci/check.sh --full` exits 0 (`check.sh: OK`). Its enforce run reported:
  - closure: fixpoint 680 files, 1 namespace stub, 0 same-level ties, 0 unresolved names in both sets;
  - deny: 0 hits; budget: 680 of 748; reflection scan: 681 files, 0 hits;
  - smoke: 277/277 on `TurboBC.ns21` and `TurboBC.netfx`, and 27/27 DEBUG.
  The rest of `--full` passed: turbo NUnit tests, Python tool tests, actionlint, shellcheck, waves simulation.
  `./tools/ci/check.sh` passed again after the hint wording change.
- `Lib/` is unchanged: `diff -rq strip/out/Lib <turboHTTP c4f3eb8>/Runtime/Transport/BouncyCastle/Lib`
  (asmdef and its `.meta` excluded) shows no difference.
- Not run: Unity 2021.3 / IL2CPP and the slow smoke rows. Nothing in `Lib/` changed.
