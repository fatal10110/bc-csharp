# 2026-10 — E8: X509Certificate key via TurboKeyFactory, Verify throws, SigAlgName map (#18)

## What

Edge cut E8 (STRIP_PLAN_V2.md §3 E8, decision A) in `crypto/src/x509/X509Certificate.cs`:

- `CreatePublicKey` (behind the cached `GetPublicKey()`) calls `TurboKeyFactory.CreateKey(SubjectPublicKeyInfo)`
  instead of `PublicKeyFactory.CreateKey`. A rejected key (RSA outside 2048–8192 bits or exponent over 64 bits,
  EC off P-256/384/521 or with explicit parameters, DSA, Ed25519/Ed448, malformed SPKI) surfaces as
  TurboKeyFactory's plain `ArgumentException`, unwrapped. A rejection is not cached; the next call re-runs the
  (early, cheap) rejection.
- `IsSignatureValid` (both), `IsAlternativeSignatureValid` (both), `Verify` (both), `VerifyAltSignature` and the
  protected `CheckSignature`/`CheckSignatureValid` throw `NotSupportedException` (decision A: chains are
  validated by the platform, never by BC).
- `SigAlgName` uses the new turbo map `TurboSignatureNames.GetName`: RSA PKCS#1 v1.5 with SHA-1/224/256/384/512,
  RSASSA-PSS and ECDSA with SHA-1/224/256/384/512, spelled as upstream's `SignerUtilities` names them
  (`SHA-256withRSA`, `PSSwithRSA`, `SHA-256withECDSA`); any other OID returns its dotted string.
- `ToString()` prints `Public Key: <unsupported key>` when `GetPublicKey()` throws `ArgumentException`.

## Files

- `crypto/src/x509/X509Certificate.cs` — the cut; every hunk marked `// turbo-strip: E8`. Usings
  `Org.BouncyCastle.Crypto.Operators` and `Org.BouncyCastle.Security` dropped (no longer used), `Org.BouncyCastle.Turbo`
  added. Private helpers `GetPublicKeyForDisplay` and `VerificationNotSupported` at the end of the class.
- `crypto/src/turbo/TurboSignatureNames.cs` — new turbo-owned internal static OID->name map (MIT header).
- `crypto/test/src/turbo/X509CertificateE8Test.cs` — 18 NUnit regression checks (all but the accepted-key,
  RSA/ECDSA name and accepted-key ToString rows fail on the pre-cut code).
- `strip/upstream-expected-failures.txt` — `E8/A Org.BouncyCastle.Tests.CertTest.TestFunction`, the one
  kept-surface upstream test E8 breaks on purpose.

## Decisions

- **Protected `CheckSignature`/`CheckSignatureValid` throw too**, instead of being left intact: they were the last
  path to BC certificate-signature verification (a subclass can call them with its own verifier), and keeping them
  would keep the `X509Utilities.VerifySignature`/`AreEquivalentAlgorithms` calls and the RFC 5280 TBS/outer
  algorithm comparison in a code path nothing may reach. Signatures stay (public/protected API is kept, only the
  bodies change), so subclasses and callers still compile.
- **Method signatures kept**, including the `IVerifierFactoryProvider` overloads: `IVerifierFactoryProvider` and
  `IVerifierFactory` live in `Org.BouncyCastle.Crypto` (interfaces), not in the denied `crypto/operators/`.
- **SigAlgName keyed by OID only.** Upstream decoded RSASSA-PSS and ecdsa-with-SHA2 parameters to print
  `SHA256withRSAandMGF1`; the map prints `PSSwithRSA` (upstream's name for the bare OID) and never parses
  parameters. No kept caller depends on the name; only `ToString()` prints it. Ed25519/Ed448 OIDs are not mapped
  (decision E) and print as OIDs.
- **ToString catches `ArgumentException` only** (TurboKeyFactory's whole failure contract); any other exception
  from an overriding `GetPublicKey` still propagates.
- **X509Crl.cs untouched** (lane scope: X509Certificate only); see "Closure" below for whether it keeps
  `X509SignatureUtil.cs` and `Asn1Signature.cs` in.

## Closure

`strip/tool/closure.py --roots strip/roots --report` after the cut: fixpoint 838 files. Out of the closure:
`x509/X509SignatureUtil.cs`, `crypto/operators/Asn1Signature.cs`, `security/SignerUtilities.cs`,
`security/PublicKeyFactory.cs`, `x509/X509Crl.cs`, `x509/X509CrlParser.cs`. In: `x509/X509Certificate.cs`,
`x509/X509Utilities.cs`, `turbo/TurboSignatureNames.cs`. No report line names an `x509/` or `turbo/` file. So
X509Crl.cs (which still uses `X509SignatureUtilities` and `Asn1VerifierFactory`) needs no cut: no kept file
reaches it. Rebase surface: `X509Certificate.cs` changed in 3 upstream commits between the previous strip base
5200dfdf and BASE.

## Deferred

- Hostile-certificate smoke rows for this path belong to the smoke suite (#26).
- BC-side verification (`TurboVerifierFactory`) stays plan Appendix A.

## How verified

- `./tools/ci/check.sh`: OK (format, netstandard2.0 and net6.0 library builds).
- `dotnet test --framework net6.0 --filter "FullyQualifiedName~X509CertificateE8Test|FullyQualifiedName~TurboKeyFactoryTest"`:
  71/71 pass; the E8 fixture on the pre-cut code: 10 of 17 failed (the malformed-SPKI row was added after).
- `strip/tool/upstream_tests.py`: 505 run, 429 pass, 76 fail, all expected; 0 regressions. Before the
  expected-failure row it reported exactly one regression, `CertTest.TestFunction` ("RSA modulus size out of
  range": its 1024-bit RSA certificates; later sub-tests call `Verify`).
- `python3 -m unittest discover -s strip/tool -p 'test_upstream_tests.py'`: 23 OK (list-file consistency).
- `strip/tool/closure.py --report`: as above.
