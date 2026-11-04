# 2026-11 — roots refreshed after turboHTTP#287, no reflection in the stripped Lib (#77)

## What

- The closure roots mirror turboHTTP `main` `957a9adebe1cda8df5b4b2aef52ec0029b3c62bf` (`ROOTS_SHA`,
  was `5b92ce86`). turboHTTP#287 (`5fc7659`) changed `TurboTlsAuthentication.cs`: `VerifyPath` now goes
  through `ToBuiltPath(CertificateVerificationResult)`, which accepts only `result.IsTrusted`.
  `BouncyCastleTlsProvider.cs` gained a doc-comment change. The stream and the client are unchanged.
  The glue uses no new Bouncy Castle API.
- The strip now fails on reflection in its output. `strip.sh` step 4b runs `strip/tool/reflection.py`
  over `<work>/rewritten/lib`, the tree `package.py` copies to `strip/out/Lib`. Any hit is a fail check:
  enforce stops with exit 1, and `--report` logs it and marks the package "Not for handover".
  turboHTTP's narrowed BouncyCastle `link.xml` (turboHTTP#196) and IL2CPP High stripping rely on this
  (turboHTTP#249).

## Files

- `strip/roots/TurboTlsAuthentication.cs`, `BouncyCastleTlsProvider.cs`, `strip/ROOTS_SHA`,
  `strip/roots.sha256`: written by `refresh_roots.py --turbohttp /home/zorg/workspace/turboHTTP`.
- `strip/roots/RootStubs.cs`: `CertificateVerificationStatus` gets `NotVerified = 0` and the explicit
  values turboHTTP uses. `CertificateVerificationResult.IsTrusted` mirrors turboHTTP
  `Runtime/Transport/Tls/ServerCertificateVerifier.cs`.
- `strip/tool/reflection.py` (new): blanks comments and the text of string and char literals,
  keeping interpolation holes as code, then matches the following:
  - `System.Reflection` and `System.Linq.Expressions`;
  - `Type.GetType(` and the other by-name `Type` lookups, and `GetType` with an argument on any
    receiver (`asm.GetType("X")`, `module.GetType("X")`);
  - `.Assembly` / `.Module` (the reflection objects behind by-name lookups), `CreateInstance(` on any
    receiver and `GetUninitializedObject` (review on PR #78);
  - `Activator`, `Assembly.Load*` and `Assembly.Get*Assembly`, and assembly enumeration;
  - `Make{GenericType,GenericMethod,ArrayType,...}`;
  - member lookups with a receiver (`.GetMethod(`, `.GetProperty(`, `.GetFields(`, `.GetTypeInfo(`,
    `.InvokeMember(`, ...);
  - `CreateDelegate` and `.DynamicInvoke(`;
  - the `System.Reflection` info types, `TypeDescriptor` and `dynamic`.

  Exit codes: 0 clean, 1 hits (`FAIL reflection: path:line: label: text`), 2 usage, 3 I/O.
- `strip/strip.sh`: step 4b (after the rewrite, before the builds). The header and `--help` are updated.
- `strip/tool/test_reflection.py` (new, 11 tests). `strip/tool/test_strip_sh.py`: the step order includes
  `reflection.py --lib <work>/rewritten/lib`. Enforce stops on hits, `--report` logs them, and exits
  2 and 3 are fatal.
- `strip/docs/agents/architecture.md`: tool list and pipeline step 3.

## Decisions

- **The scan runs on the produced Lib, not as a deny glob.** `deny.txt` denies files. Reflection is a
  property of the code, and a kept file can gain it through an upstream bump or an edge cut. The scan
  covers exactly what turboHTTP vendors, including `crypto/src/turbo/` and `_TurboNamespaceStubs.cs`.
- **Code only, and conservative.** Comments, doc comments and literal text are blanked, so messages
  and crefs that name an API are not hits. `#if`-inactive code is still scanned. A hit there is a false
  positive in the safe direction.
- **Not hits, by design.** `obj.GetType()` and `typeof(T)` give type identity and names for exception
  messages, which work under the linker. Today's Lib uses them in `AbstractTlsCrypto.cs`,
  `BcTlsSecret.cs`, `Platform.GetTypeName` and `TurboKeyFactory`. `Properties.GetProperty` is
  Bouncy Castle's environment-variable lookup. Unqualified calls are not hits either, because a
  reflection member lookup always has a receiver. The only allowed (receiver, member) pair is
  (`Properties`, `GetProperty`), and `props.GetProperty(` is a hit.
- **Step 4b runs before the builds.** It needs only the rewritten tree and costs well under a second,
  so a hit fails before the slow builds and smoke run.
- **No allowlist file.** The output has no reflection today. A future need is a plan-level decision
  (turboHTTP's `link.xml` would have to preserve the target), not a line in a data file.

## Deferred

- None. The hand-over note goes on turboHTTP#249 (see How verified for whether `Lib/` changed).

## How verified

- Calibration: `reflection.py --lib crypto/src` (all 2299 upstream files) reports exactly the 2 real
  uses: `bcpg/ArmoredOutputStream.cs` `using System.Reflection` and `Assembly.GetExecutingAssembly`,
  both outside the closure. A raw-text pass of the same regexes adds 11 `dynamic` hits, all in comments.
  So blanking removes no code, and there is no false positive across upstream.
  `reflection.py --lib <turboHTTP>/Runtime/Transport/BouncyCastle/Lib`: 681 files, 0 hits.
  The PR #78 review patterns (`GetType` with an argument, `.Assembly`/`.Module`, `CreateInstance`,
  `GetUninitializedObject`) leave both calibrations unchanged: the same 2 upstream hits, 0 in turboHTTP's Lib.
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`: 214 OK. `tools/agent-tools`: 41 OK.
  The new tests fail on the old tree (no `reflection.py`, no step 4b).
- `./tools/ci/check.sh --full` exits 0 (`check.sh: OK`). Its `strip.sh` enforce run reported:
  - closure: fixpoint 680 files, 1 namespace stub, 0 same-level ties, 0 errors (0 unresolved names) in
    both sets;
  - deny: 0 hits; budget: 680 of 748;
  - step 4b: `reflection scan: 681 files, 0 hit(s)`;
  - builds 3a/3c/consumer: clean for `netstandard21`, `netframework` and `netstandard21_debug`;
  - smoke: 277/277 on `TurboBC.ns21` and `TurboBC.netfx`, and 27/27 DEBUG.

  The rest of `--full` also passed: actionlint, shellcheck, 126/126 turbo NUnit tests, 41 + 214 Python
  tool tests and the waves simulation.
- `Lib/` is unchanged. `diff -rq strip/out/Lib <turboHTTP 957a9ad>/Runtime/Transport/BouncyCastle/Lib`
  shows no difference, `.meta` files included. The only extras are turboHTTP's own
  `TurboHTTP.SecureProtocol.asmdef` and its `.meta`. `STRIP_INFO.md` records the new `ROOTS_SHA`, and
  turboHTTP needs no re-sync.
- Not run: Unity 2021.3 / IL2CPP, which is turboHTTP's sync gate, and the slow smoke rows
  (`--smoke-slow`). This change does not touch the handshake-timeout path they cover.
