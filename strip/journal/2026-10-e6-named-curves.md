# 2026-10 — E6: CustomNamedCurves / ECNamedCurveTable deny-forced trims (#16)

## What

Edge cut E6 (STRIP_PLAN_V2.md §3 E6): only what `strip/deny.txt` forces (`math/ec/custom/sec/SecT*`, `**/*sm2*`,
`**/*gost*`).

- `CustomNamedCurves`: the 18 `SecT*` holders and `SM2P256V1Holder` are gone, and so are their `DefineCurve`
  lines in the static constructor and the `B-163…B-571` / `K-163…K-571` `DefineCurveAlias` lines.
  `DefineCurveAlias` throws `InvalidOperationException` for an OID that is not defined. Any alias left behind
  would make the static constructor throw, which would break every EC lookup, P-256/384/521 included
  (`BcTlsECDomain` → `ECDomainParameters.LookupName` → `ECUtilities.FindECCurveOid`).
- `ECNamedCurveTable`: the `ECGost3410NamedCurves` lookups are dropped from all six lookups and from `Names`.
- The SEC, NIST, X962, TeleTrusT, ANSSI and GM tables are untouched.

## Files

- `crypto/src/crypto/ec/CustomNamedCurves.cs`: three `// turbo-strip: E6` hunks:
  - the usings (`Asn1.GM` and `Math.EC.Custom.GM` dropped);
  - the holder block;
  - the static-constructor block.
- `crypto/src/asn1/x9/ECNamedCurveTable.cs`: eight `// turbo-strip: E6` hunks:
  - the `Asn1.CryptoPro` using;
  - six lookup if-blocks;
  - `Names`.
- `crypto/test/src/turbo/NamedCurvesE6Test.cs`: a new plain-NUnit fixture,
  `Org.BouncyCastle.Turbo.Tests.NamedCurvesE6Test`. It is the E6 regression check until the smoke harness
  (#23/#24) exists. It covers:
  - secp256r1/384r1/521r1 by name, by `P-` alias and by OID through `CustomNamedCurves.GetOid/GetName/GetByOid/GetByName`
    (custom `SecP*Curve` type), `ECDomainParameters.LookupName` and `ECNamedDomainParameters.LookupOid`;
  - no `sect*`/`B-`/`K-`/`sm2p256v1` entry left in `CustomNamedCurves`;
  - no GOST entry left in `ECNamedCurveTable` (`LookupOid` of a GOST OID throws `ArgumentException`);
  - `sect163k1` still resolves through the SEC table as a generic `F2mCurve`.

  Three of its nine cases fail on the pre-E6 code.

## Decisions

- **Usings.** The now-unused usings (`Asn1.GM`, `Math.EC.Custom.GM`, `Asn1.CryptoPro`) are dropped under a marker
  instead of being left to the closure's namespace stubs. This follows E5 (`BcTlsRawKeyCertificate.cs:11`).
  `Math.EC.Custom.GM` is empty after the deny, and `Asn1.CryptoPro` would otherwise need a stub only for this file.
- **Marker style.** Each removed block becomes one `// turbo-strip: E6 …` comment line at the place of the cut.
  `DefineCurve`/`DefineCurveAlias` themselves are unchanged.
- **Kept fallback.** `sect*`, `B-`/`K-` and `sm2p256v1` still resolve through `ECNamedCurveTable`, because the SEC and
  GM tables have their own generic curves. The plan keeps these tables, and TurboKeyFactory (E5) limits peer keys to
  named P-256/384/521. Nothing is cut there.

## How verified

- `NamedCurvesE6Test` (net6.0):
  - before the cut: 3 failed and 6 passed (the lookups of the kept curves pass, the removal assertions fail);
  - after the cut: 9 of 9 pass.
- Scoped upstream fixtures (`Org.BouncyCastle.Math.EC.Tests`, `Crypto.Tests.ECTest`, `Crypto.Tests.NistEccTest`,
  `Tests.NamedCurveTest`, `Crypto.Tests.ECGost3410Test`, `Tests.ECDsa5Test`): 38 passed and 1 failed.
  - The failure is `Org.BouncyCastle.Tests.NamedCurveTest.TestFunction`. It is expected: `doTestECGost` iterates
    `ECGost3410NamedCurves.Names` through `ECNamedCurveTable.GetByName`.
  - That test is not in `strip/upstream-tests.txt`, so no line goes into `strip/upstream-expected-failures.txt`.
- `./tools/ci/check.sh`: OK. It builds the library for netstandard2.0 and net6.0 because `strip/strip.sh` (#10) does
  not exist yet.
