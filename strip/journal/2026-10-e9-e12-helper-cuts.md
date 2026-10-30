# 2026-10 — E9–E12: deny-forced helper cuts (#19)

## What

The four helper cuts the deny list forces (STRIP_PLAN_V2.md §3 E9–E12). Each removes the last kept reference to a
denied file, so the [min] referrer sweep is empty and the stripped tree builds.

- **E9** `X509ExtensionUtilities.CalculateKeyIdentifier(AsymmetricKeyParameter)` throws `NotSupportedException`
  instead of calling the denied `SubjectPublicKeyInfoFactory`. The `SubjectPublicKeyInfo` and `X509Certificate`
  overloads are unchanged.
- **E10** `ECKeyPairGenerator.Init` loses the `ECGost3410Utilities` branch (GOST parameter rewrite and the
  "requires ECKeyGenerationParameters" check).
- **E11** `DigestUtilities.GetDigestForMechanism` returns null for DSTU7564-256/384/512, GOST3411 and
  GOST3411-2012-256/512, so `GetDigest` (by name or OID) throws its usual `SecurityUtilityException` ("not
  recognised").
- **E12** `BcTlsHmac.CalculateMac()` inlines `MacUtilities.DoFinal` (allocate `GetMacSize()` bytes, `DoFinal`).

## Files

- `crypto/src/x509/extension/X509ExtensionUtil.cs`: one `// turbo-strip: E9` hunk (method body).
- `crypto/src/crypto/generators/ECKeyPairGenerator.cs`: two `// turbo-strip: E10` hunks. One is the branch; the
  other drops the `Crypto.Utilities` using, which only `ECGost3410Utilities` needed.
- `crypto/src/security/DigestUtilities.cs`: one `// turbo-strip: E11` hunk. The six case labels share
  `return null;`.
- `crypto/src/tls/crypto/impl/bc/BcTlsHmac.cs`: two `// turbo-strip: E12` hunks. One is the inlined
  `CalculateMac()`; the other drops the `Security` using, which only `MacUtilities` needed.
- `crypto/test/src/turbo/HelperCutsE9E12Test.cs`: a new plain-NUnit fixture with 22 cases. On the pre-cut code,
  14 of them fail: the E9 throw, the E10 GOST branch, and E11 by name and OID.

## Decisions

- **E9 throws instead of removing the overload.** Plan E9 says "remove". Three public members call the overload:
  `CreateAuthorityKeyIdentifier(AsymmetricKeyParameter)`, `CreateAuthorityKeyIdentifier(AsymmetricKeyParameter,
  GeneralNames, BigInteger)` and `CreateSubjectKeyIdentifier(AsymmetricKeyParameter)`. Two constructors, outside the
  closure, call it too: `SubjectKeyIdentifierStructure(AsymmetricKeyParameter)` and
  `AuthorityKeyIdentifierStructure(AsymmetricKeyParameter)`. Seventeen `crypto/test` call sites use those
  members.
  - Removing the overload means cutting five more members, and `crypto/test` stops compiling, so
    `strip/tool/upstream_tests.py` can only exit 2 until #42 lands.
  - Throwing in the body is one hunk with the same effect on the closure: no `SubjectPublicKeyInfoFactory`
    reference is left. Every signature is kept, which follows the E8 precedent (bodies throw, signatures stay).
    The upstream-test diff keeps working, and #19 does not depend on #42.
  - The `*Structure` classes are not in the closure (`closure_files.json`), so they are not touched.
- **E11 maps the denied cases to `return null`** instead of deleting them. A deleted case falls through to the
  switch's `default: throw new NotImplementedException()`, because the enum members and OID maps stay. With
  `return null`, a denied digest fails like any unknown digest (`SecurityUtilityException`), and `SecureRandom`'s
  `CreatePrng` contract is unchanged. The enum members and the `AlgorithmOidMap`/`Oids` entries stay; they only
  reference OIDs from non-denied `asn1/` classes.
- **E10 leaves `ECKeyParameters.VerifyAlgorithmName` alone.** It still accepts "ECGOST3410", and
  `ECKeyPairGenerator("ECGOST3410")` now generates ordinary EC keys on the given curve. No kept caller uses that
  name: `BcTlsECDomain` and `ECNRSigner` use "EC".
- **Usings.** The usings that became unused are dropped under a marker, as E5, E6 and E8 did.
- **`DefaultMacResult.cs:17` is not edited** (plan E12). It is outside the closure, and the sweep would report
  `MacUtilities` again if it ever came back in.

## Closure

`strip/strip.sh --report --set min`:

- Before, on e5f71b70: `fixpoint: 777 files`, `deny: 65 denied, 7 with kept referrers, swept=True`,
  `kept: 712 files`. The seven `FAIL deny hit` lines name DigestUtilities ×4, MacUtilities, ECKeyPairGenerator
  and X509ExtensionUtil. Builds 3a/3c for [min] had 10 compile errors, and the consumer build was skipped.
- After: `fixpoint: 680 files`, `deny: 0 denied, 0 with kept referrers, swept=False`, `kept: 680 files`, `CLEAN`.
  For [min], `TurboBC.Strip.min.dll`, `TurboBC.min.dll` and `TurboBC.Consumer.min.dll` all have 0 compile
  errors.
- 32 kept files left the closure. They include `security/MacUtilities.cs` (so `GOST28147Mac.cs` is no longer
  reached), and the DSA/ElGamal parameters, `Mgf1BytesGenerator`, `CMac`, `SipHash`, the VMPC/RC2/RC5/IDEA/Skipjack
  engines, `Nat448`/`Scalar448` and `X25519PublicKeyParameters`. All of them were reached only through the
  denied-file chains. None entered.
- [partial] (189 errors) and [sdk] (6, `Poly1305.cs:254,257` `MethodImpl`) are the E13 guard mismatches, owned by
  #20.

Rebase surface (upstream commits between 5200dfdf and BASE 7c9c8d5a): X509ExtensionUtil.cs 3,
ECKeyPairGenerator.cs 1, DigestUtilities.cs 3, BcTlsHmac.cs 0.

## Deferred

- The smoke suite (#23) should carry the HMAC KAT and the denied-digest rows. Until then, they are in
  `HelperCutsE9E12Test`.

## How verified

- `./tools/ci/check.sh`: OK. It runs `strip/strip.sh --report`, which is clean for [min]; [partial]/[sdk] show
  E13 only. It also builds the netstandard2.0 and net6.0 library with 0 errors.
- `strip/strip.sh --report --set min`, before and after, as above.
- `dotnet test --framework net6.0 --filter "FullyQualifiedName~Org.BouncyCastle.Turbo.Tests"`: 126/126 pass.
  `HelperCutsE9E12Test` on the pre-cut code: 14 of 22 fail.
- `python3 strip/tool/upstream_tests.py`: 505 run, 429 pass, 76 fail, all of them expected; 0 regressions. No new
  expected-failure lines.
