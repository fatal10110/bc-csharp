# 2026-10 Smoke: hostile inputs (#26)

## What

The `hostile` row group of the smoke suite (STRIP_PLAN_V2.md §5 step 5, "Hostile inputs"): ASN.1 depth over
TLS and straight into `Asn1InputStream`, RSA modulus size and public-exponent bounds, explicit EC parameters,
each through `X509Certificate.GetPublicKey` (E8) and through a TLS 1.3 and a TLS 1.2 handshake against a custom
BASE server. Plus the E5 key table (review round 1, owner comment on #26): every case of
`crypto/test/src/turbo/TurboKeyFactoryTest.cs` against each stripped DLL. 67 rows; no library change.

## Files

- `strip/smoke/server/SmokeHostileServer.cs` (BASE side):
  - `SmokeHostileCertificates`: nested definite-length (DER) and indefinite-length (BER) SEQUENCEs; the deepest
    nesting that fits a byte budget; hand-built certificates with an RSA SubjectPublicKeyInfo of any modulus size
    and exponent (odd modulus without prime factors below 2000, deterministic from a seed), or with the explicit
    P-256 parameters around a real certificate's point; garbage signature (decision A: the client never checks
    certificate signatures); real RSA keys with a chosen exponent (e = 3).
  - `SmokeHostileTlsServer : SmokeTlsServer`: sends arbitrary bytes as the end-entity certificate (TLS 1.3 or
    1.2) through a `BcTlsCertificate` subclass whose `GetEncoded` returns them, and signs with the given real key.
- `strip/smoke/server/SmokeHostileKeys.cs` (BASE side): `SmokeKeyCase` (id, expected reason or accept values,
  lazily built SPKI DER and certificate) and the `SmokeHostileKeys.Cases` table; secp256k1 and Ed25519
  certificates for the TLS rows. `SmokeHostileCertificates.Certificate`/`OddModulus` became internal for it.
- `strip/smoke/rows/HostileRows.cs` (TurboBC side): the rows; every body runs on `new Thread(body, 256 KB)`,
  joined and rethrown (the runner's own thread has the default stack).
- `strip/smoke/rows/HostileKeyRows.cs` (TurboBC side, `partial HostileRows`): one `key-<case>` row per table
  entry and four TLS rows.

## Rows

| Row | Checks |
|---|---|
| `asn1-depth-16k-definite`, `asn1-depth-16k-indefinite` | 16385 levels into `Asn1InputStream` -> `Asn1Exception` "maximum nested construction level reached" |
| `asn1-depth-tls13-certificate-32k`, `asn1-depth-tls12-certificate-32k` | deepest nesting whose Certificate body fits 32768 bytes (one more level would not; > 8000 levels) -> `TlsFatalAlert(bad_certificate)` with the depth exception as cause |
| `rsa-8192-accepted-under-50ms` | fastest of up to 5 `new X509Certificate(der).GetPublicKey()` on an 8192-bit n, e = 65537, after a warm-up on another modulus: < 50 ms |
| `rsa-8192-e3-getpublickey-accepted`, `rsa-8192-e64bit-getpublickey-accepted` | 8192-bit n with e = 3 and e = 2^64 - 1 accepted |
| `rsa-e3-tls{13,12}-accepted`, `rsa-e65537-tls{13,12}-accepted` | real 2048-bit keys with e = 3 / 65537 complete the handshake |
| `rsa-8193-{getpublickey,tls13,tls12}-rejected` | 8193-bit n |
| `rsa-1024-{getpublickey,tls13,tls12}-rejected` | real 1024-bit key (it signs, so an accept would complete the handshake) |
| `rsa-8192-e65bit-{getpublickey,tls13,tls12}-rejected` | 8192-bit n with e = 2^64 + 1 (and, for GetPublicKey, an 8191-bit e) |
| `ec-explicit-params-{getpublickey,tls13,tls12}-rejected` | the server's real P-256 point with specifiedCurve parameters |

| `key-rsa-{2048,4096,pss-oid-2048,pss-oid-4096}-accepted` | accepted via `TurboKeyFactory.CreateKey` and `GetPublicKey`, modulus bits and e checked |
| `key-rsa-prime-modulus-accepted-e7` | RFC 3526 group 14 prime as n is accepted: pins E7 (`RsaMaxMRTests` = 0) |
| `key-rsa-{2047,pss-oid-1024,pss-oid-e65bit,e1,even-e,even-n,small-factor-n,oaep-oid,idearsa-oid,malformed-key,wrong-shape-key}-rejected` | exactly `ArgumentException` from both, reason pinned where the factory has one |
| `key-ec-p{256,384,521}[-compressed]-accepted` | named domain parameters with the curve OID, Q equals the encoded point |
| `key-ec-{secp256k1,p224,brainpoolp256r1,implicitlyca,missing-parameters,explicit-composite-field}-rejected` | curve / parameter form |
| `key-ec-{off-curve,infinity,empty,hybrid-06,hybrid-07,truncated,p384-point-as-p256}-...-rejected` | point checks |
| `key-{ed25519,dsa,dh}-rejected` | other algorithms |
| `key-{garbage-der,trailing-data}-rejected` | `TurboKeyFactory.CreateKey(byte[])` only |
| `key-ec-secp256k1-tls{13,12}-rejected`, `key-ed25519-tls{13,12}-rejected` | unsupported_certificate over TLS (P-256 signer) |

GetPublicKey rejects must throw exactly `ArgumentException`, twice (no cached success). TLS rejects must end in
`TlsFatalAlert(unsupported_certificate)` with `ArgumentException` (TurboKeyFactory) in the cause chain: a
mismatched hand-built key that got through would fail later with `decrypt_error` instead, so the row shows the
bound sits before any signature verification (modexp).

## Decisions

- Hostile bytes never pass through BASE's parser: BASE also caps depth at 64 and would build the hostile keys
  (Miller-Rabin on 8192 bits). The server's own certificate stands behind the raw bytes for everything else.
- Deep nesting goes in the certificate itself (not a valid certificate) and is measured against the Certificate
  handshake body (RFC 8446 4.4.2: 1 + 3 + 3 + 2 bytes around one entry; RFC 5246 7.4.2: 3 + 3), the length the
  client compares with its 32768-byte cap (`TlsProtocol`, `AbstractTlsPeer.GetMaxHandshakeMessageSize`). The
  alert must be bad_certificate: the cap's own failure is internal_error.
- 16385 levels (> 16K) in both DER and BER forms (upstream `ASN1SequenceParserTest` covers both forms too).
- The 50 ms bound times certificate parse plus GetPublicKey, best of up to five runs, after a warm-up (same
  pattern as `RsaKeyParametersE7Test.Modulus8192AcceptedFast`; the host is shared).
- Two new files; no shared harness file edited; nothing from interop (#25) or timeouts (#27).
- Key table (round 1): built in BASE as bytes, so the TurboBC side never needs the OID/curve tables the strip
  may have dropped; only `TurboKeyFactory`, `X509Certificate` and the key parameter types. #26's owner comment
  lists "prime n" as a reject; E7 turns Miller-Rabin off for peer keys (plan §3 E7), so a prime n without small
  factors is accepted. The row asserts the accept and names E7. "P-256 under both OIDs": `secp256r1` and
  `prime256v1` are the same OID (1.2.840.10045.3.1.7), one row per point form. Added the composite 1100-bit
  specifiedCurve row from the E5 fixture (rejected before curve construction).

## How verified

- `strip/strip.sh --set min --work <lane>/work --out <lane>/out`: smoke passed, all rows incl. 23 `hostile/*`.
- Mutation checks on TurboBC.min (reverted): `RsaMinModulusBits = 1024` and `RsaMaxExponentBits = 8192` in
  `TurboKeyFactory` fail the 6 rows `rsa-1024-*` and `rsa-8192-e65bit-*` (the TLS ones with
  `decrypt_error`); lifting `Asn1InputStream.FindDepth`'s default from 64 to 1000000 makes
  `asn1-depth-16k-definite` overflow the 256 KB stack and abort the smoke run.
- Round 1 mutation (reverted): `TurboKeyFactory.IsSupportedCurve` also accepting secp256k1 fails
  `key-ec-secp256k1-rejected` and both `key-ec-secp256k1-tls*` rows (`decrypt_error`); 90/93 otherwise.
- `./tools/ci/check.sh`.
