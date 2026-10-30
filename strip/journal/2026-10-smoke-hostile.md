# 2026-10 Smoke: hostile inputs (#26)

## What

The `hostile` row group of the smoke suite (STRIP_PLAN_V2.md §5 step 5, "Hostile inputs"): ASN.1 depth over
TLS and straight into `Asn1InputStream`, RSA modulus size and public-exponent bounds, explicit EC parameters,
each through `X509Certificate.GetPublicKey` (E8) and through a TLS 1.3 and a TLS 1.2 handshake against a custom
BASE server. 23 rows; no library change.

## Files

- `strip/smoke/server/SmokeHostileServer.cs` (BASE side):
  - `SmokeHostileCertificates`: nested definite-length (DER) and indefinite-length (BER) SEQUENCEs; the deepest
    nesting that fits a byte budget; hand-built certificates with an RSA SubjectPublicKeyInfo of any modulus size
    and exponent (odd modulus without prime factors below 2000, deterministic from a seed), or with the explicit
    P-256 parameters around a real certificate's point; garbage signature (decision A: the client never checks
    certificate signatures); real RSA keys with a chosen exponent (e = 3).
  - `SmokeHostileTlsServer : SmokeTlsServer`: sends arbitrary bytes as the end-entity certificate (TLS 1.3 or
    1.2) through a `BcTlsCertificate` subclass whose `GetEncoded` returns them, and signs with the given real key.
- `strip/smoke/rows/HostileRows.cs` (TurboBC side): the rows; every body runs on `new Thread(body, 256 KB)`,
  joined and rethrown (the runner's own thread has the default stack).

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

## How verified

- `strip/strip.sh --set min --work <lane>/work --out <lane>/out`: smoke passed, all rows incl. 23 `hostile/*`.
- Mutation checks on TurboBC.min (reverted): `RsaMinModulusBits = 1024` and `RsaMaxExponentBits = 8192` in
  `TurboKeyFactory` fail the 6 rows `rsa-1024-*` and `rsa-8192-e65bit-*` (the TLS ones with
  `decrypt_error`); lifting `Asn1InputStream.FindDepth`'s default from 64 to 1000000 makes
  `asn1-depth-16k-definite` overflow the 256 KB stack and abort the smoke run.
- `./tools/ci/check.sh`.
