# Architecture

Load when touching the strip pipeline, the `strip/` layout, edge cuts, turbo-owned code, decisions
A–G or key limits. The contract is [`STRIP_PLAN_V2.md`](../../../STRIP_PLAN_V2.md). This guide is a
map of it, not a replacement.

## Upstream tree (unchanged layout)

- **Library:** `crypto/src/BouncyCastle.Crypto.csproj`.
  - Multi-targets `net6.0;netstandard2.0;net461` and is signed with `BouncyCastle.NET.snk`.
  - It is versioned by Nerdbank.GitVersioning from `version.json`, so it needs git history.
  - Sources are grouped by domain: `tls/`, `crypto/`, `math/`, `asn1/`, `x509/`, `security/`, `util/`,
    `pqc/`, …
- **Tests:** `crypto/test/BouncyCastle.Crypto.Tests.csproj` (NUnit 3). The bulk vectors live in the
  separate `bc-test-data` repo, found by `SimpleTest.FindTestDataPath`.
- **Upstream's place:** it is the input. The strip is computed from it; edge cuts change it as
  little as possible.

## strip-v2 additions

- **Edge cuts E1–E14** (plan §3) are small commits on `strip-v2`, one per E-number or per issue
  E-range (#14 E2–E4, #19 E9–E12). Every hunk is marked `// turbo-strip:`.
- **Turbo-owned code** lives in `crypto/src/turbo/` (`Org.BouncyCastle.Turbo`, MIT header).
  - `TurboKeyFactory` (E5) builds every peer key, from TLS and from `X509Certificate.GetPublicKey` (E8).
  - Its NUnit fixtures and those of the cuts live in `crypto/test/src/turbo/`.
- **`strip/` contents:**

| Path | Role |
| --- | --- |
| `BASE`, `ROOTS_SHA` | pinned upstream commit; turboHTTP commit the roots were copied from |
| `roots/` | consumer copies (`BouncyCastleTlsProvider`, `TurboTlsClient`, `TurboTlsAuthentication`), `RootStubs.cs`, `roots-extra.cs` (BC API contract) |
| `unity-defines.txt` | define sets the closure builds with: `[netstandard21]`, `[netframework]`, captured from Unity 2021.3.45f2 |
| `deny.txt` | denied subsystems (globs relative to `crypto/src`) |
| `budget.txt` | total cap on kept files |
| `Closure.csproj` | single-TFM build template; defines come from a generated `.props` |
| `tool/` | `index.py`, `closure.py`, `defines.py`, `deny.py`, `build.py`, `rewrite.py`, `package.py`, `refresh_roots.py`, `upstream_tests.py` (+ `test_*.py`) |
| `smoke/` | net8 smoke harness (`run.sh`, `client/`, `server/`, `harness/`, `rows/`) |
| `strip.sh` | the pipeline |
| `upstream-*.txt` | upstream-test diff: filter, BASE results, expected failures |
| `unity-probe/` | `DefineProbe.cs`, an Editor cross-check of defines |
| `journal/` | implementation journal |
| `docs/agents/` | these guides |
| `out/`, `work/` | generated, git-ignored |

## Pipeline (`strip/strip.sh`, plan §5)

1. **Prepare.** Checks prerequisites. With `--refresh-roots --turbohttp <path>`, it re-copies
   `roots/` and updates `ROOTS_SHA`.
2. **Closure.** Runs a fixpoint over the union of the define sets.
   - Names resolve in C# lookup order, with an extension-method index, and partial types count as one unit.
   - Namespace stubs are written outside `crypto/src` and pruned at the fixpoint.
   - Then come the deny list, the referrer sweep (the complete list of kept files that reference a
     denied one) and the budget check.
3. **Rewrite.** Replaces the whole token `Org.BouncyCastle` with
   `TurboHTTP.SecureProtocol.Org.BouncyCastle`. It covers usings, aliases, crefs and string keys.
4. **Builds,** per define set:
   - 3a: the stripped tree;
   - 3c: the rewritten tree → `TurboBC.ns21.dll` / `TurboBC.netfx.dll`, then the consumer files +
     `RootStubs` + `roots-extra` compiled against it.
5. **Smoke.** `strip/smoke/run.sh` runs on every 3c DLL; `--smoke-slow` adds the slow rows.
6. **Package.** Writes `strip/out/`: `Lib/` with a `.meta` per file and folder
   (GUID = `md5("turbohttp-bc:"+relpath)`), `LICENSE.md`, `THIRD-PARTY-NOTICES.txt`, and
   `STRIP_INFO.md` (BASE, ROOTS_SHA, cut list, counts, smoke results, shadow diff).
7. **Hand-over.** turboHTTP#141 syncs `Lib/`; the script never writes into turboHTTP.

Enforce mode (the default, and the gate) stops at the first failing step. `--report` logs and continues.

## Decisions (plan §2; all confirmed on turboHTTP#141)

- **A:** chain validation is outside BC (native verifier on mobile, `X509Chain` on desktop).
  `X509Certificate.Verify` and `IsSignatureValid` throw.
- **B:** no TLS 1.2 CBC.
- **C:** no X25519MLKEM768 in v1 (#60).
- **D:** no OCSP request, so must-staple is not enforced, in v1 (#61).
- **E:** no Ed25519/Ed448 certificates.
- **F:** no TLS 1.3 resumption.
- **G:** `BasicGcmMultiplier` always (constant-time GHASH), and `AesLightEngine` without AES-NI (the leak is reduced, not removed). ChaCha20 goes first.
- **Groups:** x25519, secp256r1, secp384r1, secp521r1.
- **Suites:**
  - TLS 1.3: CHACHA20, AES_128_GCM, AES_256_GCM.
  - TLS 1.2: ECDHE_{ECDSA,RSA} with the same AEADs.
  - `signature_algorithms` is the exact 12-entry list of plan §5 step 5.
- **Key limits** (TurboKeyFactory + E7):
  - RSA 2048–8192 bits, public exponent ≤ 64 bits, Miller-Rabin off for peer keys.
  - EC only on named P-256/384/521; explicit parameters are rejected before parsing.

## Risk areas

1. **Runtime-only breakage:** static initializers, registries and string-keyed lookups that throw
   when an entry is removed (E6 `DefineCurveAlias`). Only smoke rows catch these.
2. **Hostile-server DoS:** key sizes, exponents, ASN.1 nesting, PSS parameters. Every bound must sit
   before allocation or modexp.
3. **Unity define sets:** Unity 2021.3 defines no `*_OR_GREATER` symbol, so the legacy non-Span paths ship.
   - Editor and Development builds add `DEBUG` (#58).
   - A Unity upgrade needs a new capture and enforce run (see `testing.md`).
4. **Rebase surface:** cuts in churny upstream files (`TlsUtilities`, factories) turn bumps into
   conflict work. The reserve alternative is the official DLL with a Cecil rename (plan §7).
