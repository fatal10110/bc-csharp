# 2026-10 — E1: BcTlsCrypto algorithm, group and signature_algorithms support (#13)

## What

Edge cut E1 (STRIP_PLAN_V2.md §3) in `crypto/src/tls/crypto/impl/bc/BcTlsCrypto.cs`; every hunk is marked
`// turbo-strip: E1 ...`.

- `HasEncryptionAlgorithm`: AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305 only (decision B; the NULL_HMAC_* branches
  are gone with the rest).
- `HasNamedGroup`: x25519, secp256r1, secp384r1, secp521r1 only (decision C: no KEM/hybrid groups; no ffdhe).
- `HasRsaEncryption`, `HasDHAgreement`, `HasKemAgreement` return false; `CreateDHDomain`, `CreateKemDomain` and the
  abstract `CreateSrp6Client/Server/VerifierGenerator` throw `TlsFatalAlert(internal_error)`. The `BcTlsMLKemDomain`
  and `BcX448Domain` references are removed (the x448 case in `CreateECDomain`).
- `HasSignatureAndHashAlgorithm`: hash whitelist {Intrinsic, SHA-256, SHA-384, SHA-512} before the ML-DSA/SLH-DSA
  early return.
- `HasSignatureAlgorithm` and `HasCryptoSignatureAlgorithm`: rsa, ecdsa, rsa_pss_rsae_*, rsa_pss_pss_* only
  (dsa, ed25519/ed448 (decision E), ecdsa_brainpool*tls13, sm2 removed). `HasSignatureScheme`: false for ML-DSA,
  SLH-DSA and sm2sig_sm3.
- `Gost3411_2012_256Digest` removed from `CloneDigest`/`CreateDigest`, `gostr3411_2012_256` from
  `HasCryptoHashAlgorithm`.
- `HasSrpAuthentication` returns false (see Decisions).

Resulting default `signature_algorithms` (TlsUtilities.CreateDefaultSupportedSigAlgs filtered by E1), exactly plan §5
step 5: ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512, rsa_pss_pss_sha256/384/512,
rsa_pss_rsae_sha256/384/512, rsa_pkcs1_sha256/384/512.

## Files

- `crypto/src/tls/crypto/impl/bc/BcTlsCrypto.cs` — the E1 hunks above.
- `crypto/test/src/turbo/BcTlsCryptoE1Test.cs` — new plain-NUnit fixture (`Org.BouncyCastle.Turbo.Tests`), the E1
  regression check until the smoke harness (#23/#24) exists: filtered default list = the 12-entry plan list; a real
  ClientHello captured from a non-blocking `TlsClientProtocol` + `DefaultTlsClient` carries exactly that
  `signature_algorithms` and only allowed groups; Has*/Create* capability assertions; gost digest gone.

## Decisions

- Exceptions: the throwing `Create*` methods use `TlsFatalAlert(AlertDescription.internal_error)`, the same as the
  file's existing unsupported-cipher path (`CreateCipher` default), so a misuse surfaces as a TLS alert.
- `HasSrpAuthentication` → false: not named in the plan row, but `CreateSrp6*` throw by E1, and
  `TlsUtilities.IsSupportedKeyExchange` (SRP, SRP_DSS, SRP_RSA) would otherwise still report SRP suites as usable
  (advertised ≠ processable). One-line hunk, same file, same E-number.
- `HasSignatureScheme` keeps its default branch (it has no TLS caller); only the ML-DSA/SLH-DSA/sm2sig_sm3 cases flip
  to false, as the plan states. The md5 special cases are now unreachable on the `HasSignatureAndHashAlgorithm` path
  and are left in place (smaller diff).
- `CreateECDomain` keeps its default `BcTlsECDomain` branch; only the x448 case is removed. `HasHkdfAlgorithm`,
  `HasMacAlgorithm`, `HasCryptoHashAlgorithm` (except gost) and `CreateAesEngine` (E14) are untouched.
- The fixture asserts `supported_groups` as a subset of the four allowed groups (DefaultTlsClient offers x25519,
  secp256r1, secp384r1 today; secp521r1 is added to the offer by E4, #14).

## Deferred

- The ClientHello row of the smoke suite (#24) takes over the exact `signature_algorithms`/groups assertions.

## How verified

- `./tools/ci/check.sh` (format of added upstream lines, library build netstandard2.0 + net6.0): OK.
- strip/strip.sh: n/a (not present yet).
- `dotnet test --framework net6.0 --filter FullyQualifiedName~BcTlsCryptoE1`: 8/8 pass; 8/8 fail on the unmodified
  library.
- `--filter FullyQualifiedName~Org.BouncyCastle.Tls.Crypto.Tests`: 9/9 pass.
- `--filter FullyQualifiedName~Org.BouncyCastle.Tls.Tests`: 129/185 pass (baseline 185/185); the 56 failures are all
  expected:
  - 26 × decision B: TlsTestSuite/DtlsTestSuite SSL30/TLS10/TLS11/DTLS10 cases (6 each) and FallbackNone (×2) —
    pre-TLS 1.2 versions have only CBC suites ("No selectable cipher suite").
  - 1 × decision B: DtlsInvalidRecordTest.BlockCipherInvalidRecordsDiscarded (ECDHE_PSK AES_128_CBC).
  - 7 × decision C: TlsProtocolKemTest/TlsProtocolHybridTest (MLKEM512/768/1024, X25519MLKEM768,
    SecP256r1MLKEM768, SecP384r1MLKEM1024, CurveSM2MLKEM768).
  - 21 × decision E: TlsRawKeysProtocolTest (TLS 1.2 + 1.3) and DtlsRawKeysProtocolTest — the mock peers sign with
    Ed25519 raw keys.
  - 1 × E1 SRP: TlsSrpProtocolTest.TestClientServer (`CreateSrp6VerifierGenerator` throws).
