# 2026-10 — E5: TurboKeyFactory for BcTlsRawKeyCertificate (#15)

## What

Edge cut E5 (STRIP_PLAN_V2.md §3): the TLS client builds every peer public key (raw-key and X.509 leaf/CA keys,
since `BcTlsCertificate` derives from `BcTlsRawKeyCertificate`) through a new whitelisting factory instead of
`PublicKeyFactory.CreateKey`.

- `TurboKeyFactory.CreateKey(SubjectPublicKeyInfo)` (and a `byte[]` overload for a DER SPKI):
  - rsaEncryption and id-RSASSA-PSS only; modulus 2048–8192 bits and public exponent 2–64 bits (3 ≤ e < 2^64),
    checked on the parsed `RsaPublicKeyStructure` before `new RsaKeyParameters(false, n, e)`, so master's
    even-modulus and small-factor checks (and, until E7, Miller-Rabin) only ever run on in-range keys.
  - id-ecPublicKey only with namedCurve parameters P-256/P-384/P-521; explicit (specifiedCurve), implicitlyCA and
    missing parameters are rejected on the raw ASN.1 parameter (it must be an OBJECT IDENTIFIER) before any
    `X962Parameters`/`X9ECParameters` parsing, so a specifiedCurve never gets its field primality-tested or its
    curve built (review round 1). The point octet string must start with 0x02,
    0x03 or 0x04 (infinity, hybrid and empty encodings rejected), then `Curve.DecodePoint` and
    `new ECPublicKeyParameters("EC", q, ECNamedDomainParameters)` run master's `ValidatePublicPoint`.
  - Every failure is exactly `ArgumentException` (other exception types are wrapped, inner exception kept); a null
    argument gives `ArgumentNullException`.
- `BcTlsRawKeyCertificate.GetPublicKey` calls `TurboKeyFactory.CreateKey`; its existing catch maps the
  `ArgumentException` to `TlsFatalAlert(unsupported_certificate)`.
- `BcTlsRawKeyCertificate` cuts: Ed25519/Ed448 (fields, legacy TLS 1.2 verifier, TLS 1.3 verifiers, getters,
  `SupportsSignatureAlgorithm` cases; decision E), DSA (verifier, getter, legacy mapping, support case), sm2sig_sm3
  verifier, ML-DSA/SLH-DSA verifiers and their `Supports*`/`Validate*`/getter helpers; dropped the `Asn1.Cmp`,
  `Security` and `Utilities` usings (unused after the cuts). Every hunk is marked `// turbo-strip: E5 ...`.

## Files

- `crypto/src/turbo/TurboKeyFactory.cs` (new, MIT header, `Org.BouncyCastle.Turbo`): the factory. Picked up by the
  library's SDK default globbing; no csproj change needed.
- `crypto/src/tls/crypto/impl/bc/BcTlsRawKeyCertificate.cs`: E5 call-site reroute and branch cuts.
- `crypto/test/src/turbo/TurboKeyFactoryTest.cs` (new): 53-row accept/reject table plus routing rows through
  `BcTlsRawKeyCertificate`.

## Decisions

- Public API `CreateKey(SubjectPublicKeyInfo)` so E8 (#18, `X509Certificate.CreatePublicKey(c.SubjectPublicKeyInfo)`)
  can call it without a shape change. The `byte[]` overload exists for callers holding a DER SPKI.
- The 2048–8192 modulus window is enforced in TurboKeyFactory itself, not left to E7's `RsaMaxSize`, so the bound
  sits before `RsaKeyParameters` (small-factor test, Miller-Rabin) and holds even when E7's default is overridden.
  The 2048 floor applies to id-RSASSA-PSS too (plan: "rsaEncryption and id-RSASSA-PSS keys of ≥ 2048 bits").
- e = 1 is rejected (RFC 8017 §3.1: 3 ≤ e), a stricter reading than master's positive-and-odd check; even e still
  falls to master's check.
- IdEARsa and id-RSAES-OAEP (accepted by `PublicKeyFactory`) are rejected: the plan whitelists only rsaEncryption and
  id-RSASSA-PSS.
- X9.62 hybrid point encodings are rejected (RFC 5480 §2.2: compressed or uncompressed only); compressed points are
  accepted (RFC 5480 MAY). `DerBitString.GetOctets` (non-zero pad bits rejected) instead of master's `GetBytes`.
- Exact `ArgumentException` contract (subclasses wrapped) so callers and tests can rely on one type; a plain
  `catch`/`throw;` instead of an exception filter to stay away from IL2CPP filter questions.
- `GetPubKeyDH` and the DH certificate role are left untouched (plan does not cut DH); with E5 a DH SPKI is rejected,
  so `GetPubKeyDH` now always fails with `unsupported_certificate`.
- The commented-out `TODO[gmssl]` SM2 encryptor block is left as is (comment only, no closure effect, smaller hunk).
- RFC 8446 §4.2.3 scheme↔curve binding not enforced (plan: accepted, low impact).

## Deferred

- Hostile-input smoke rows (#26, the issue's acceptance item): the NUnit table here is the regression check until
  the smoke harness (#23) exists; #26 ports the rows.
- Miller-Rabin still runs on in-range peer RSA keys (about 1 s on 8192-bit n, repeated per `GetPublicKey` call)
  until E7 (#17) sets `RsaMaxMRTests` = 0.

## How verified

- `./tools/ci/check.sh`: OK (format, netstandard2.0 and net6.0 library builds); strip.sh not present yet.
- `dotnet test --framework net6.0 --filter "FullyQualifiedName~TurboKeyFactoryTest|FullyQualifiedName~BcTlsCryptoE1Test"`:
  61/61 pass (round 1: the Miller-Rabin-dependent prime-modulus row was dropped because E7 turns peer-key
  Miller-Rabin off; a specifiedCurve row with a composite 1100-bit field was added, which fails on the round-0 code). Before the call-site reroute the 4 routing rows (1024-bit RSA, 65-bit e, secp256k1, Ed25519) failed.
- `--filter "FullyQualifiedName~Org.BouncyCastle.Tls.Tests"`: 57 failed / 128 passed vs 56 / 129 on strip-v2
  with the E5 call site reverted; the only new failure is `SM2Tls13Test.SM2SignerAndVerifier_BC_BC` (sm2sig_sm3
  verifier cut by E5).
