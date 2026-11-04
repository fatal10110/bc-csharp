# 2026-10 Smoke: extra hostile negotiation rows (#66)

## What

Smoke group `hostile-negotiation` (45 fast rows, about 1.2 s per define-set DLL), the follow-ups of the
PR #33 review. Every row pins a rejection the client already performs on `strip-v2` 195dd500, so a later
cut or bump cannot drop it silently. No library code changes.

| #66 box | Rows (`hostile-negotiation/...`) | Pinned outcome |
| --- | --- | --- |
| 1 CertificateVerify, scheme not offered | `cv-tls13-{ed25519-0x0807,ecdsa-sha1-0x0203,rsa-pkcs1-sha1-0x0201}-rejected` | `illegal_parameter` |
| 2 TLS 1.2 SKE sha1/sha224 | `ske-tls12-{ecdsa-sha1-0x0203,ecdsa-sha224-0x0303,rsa-sha1-0x0201,rsa-sha224-0x0301}-rejected` | `illegal_parameter` |
| 3 ServerHello suite not offered / wrong version | `serverhello-tls12-{rsa-kx-0x009c,dhe-0x009e,dhe-chacha-0xccaa,cbc-0xc013,cbc-sha256-0xc027,scsv-0x00ff,tls13-suite-0x1301}-rejected`, `serverhello-tls13-{rsa-kx-0x009c,cbc-0xc013,tls12-suite-0xc02b}-rejected`; control `serverhello-tls12-offered-suite-control` | `illegal_parameter` (TLS 1.2 with "ServerHello selected invalid cipher suite") |
| 4 x448 / ffdhe2048 | `ske-tls12-group-{x448,ffdhe2048}-rejected`, `hrr-group-{x448,ffdhe2048,x25519-already-shared}-rejected`, `serverhello-tls13-keyshare-x448-rejected`; control `hrr-group-secp256r1-control` | `illegal_parameter` (HRR with "invalid key_share selected") |
| 5 PSS key/scheme mismatch | `pss-oid-leaf-rsae-tls{13,12}-rejected`, `rsaencryption-leaf-pss-pss-tls{13,12}-rejected` | `certificate_unknown` |
| 6 EC SPKI pad bits | `spki-ec-padbits-{1-der,7-der,1-ber}-rejected` (CreateKey + GetPublicKey twice), `spki-ec-padbits-1-tls{13,12}-rejected` | exactly `ArgumentException`; over TLS `unsupported_certificate` with it in the cause chain |
| 7 low-order X25519 | `x25519-low-order-{zero,one,order8a,order8b,p-minus-1,p,p-plus-1}-tls13-rejected`, `x25519-low-order-{zero,order8a}-tls12-rejected`; controls `x25519-valid-share-tls{13,12}-control` | `handshake_failure` |

## Files

- `strip/smoke/rows/HostileNegotiationRows.cs` (new): the row group (client side, TurboBC namespaces).
  A separate class, not a partial of `HostileRows` (owned by the parallel #65 lane).
- `strip/smoke/server/SmokeNegotiationServers.cs` (new, BASE side):
  - `StartSigningWith(keyKind, scheme, tls13)`: a `SmokeTlsServer` whose credential signs with any scheme
    (BASE checks neither the scheme against the client's `signature_algorithms` nor the key against the
    certificate); `ed25519` signs with an Ed25519 key behind the P-256 certificate, because the client
    refuses Ed25519 certificates first (decision E).
  - `StartPssMismatch`: the real RSA key under id-RSASSA-PSS signing `rsa_pss_rsae_sha256`, and the real
    rsaEncryption certificate signing `rsa_pss_pss_sha256` (`SmokeHostileTlsServer`).
  - `PadBitsSpki` / `PadBitsCertificate` / `StartPadBitsLeaf`: P-256 SPKI whose BIT STRING has 1 or 7
    unused bits over a real point. BASE's DER encoder clears unused bits, so the BER case restores the
    point's last octet after encoding; the TLS leaf uses a server key whose point ends in an even octet.
  - Raw handlers on `SmokeServerHost.Start` for what BASE refuses to send (it throws `internal_error` on a
    suite the client did not offer, only sends HRR for offered groups, and cannot write ffdhe2048 as
    ECDHE parameters): TLS 1.2 ServerHello, TLS 1.3 ServerHello with key share, HelloRetryRequest, and a
    TLS 1.2 ECDHE_ECDSA flight with a really signed ServerKeyExchange (so the low-order point gets past
    the signature check).
- `strip/journal/2026-10-smoke-extra-hostile-rows.md` (this file).

## Decisions

- **Tripwires instead of stalls.** The client turns end-of-stream during a handshake into
  `handshake_failure`, the alert box 7 pins. A raw server that just waited would let a client that
  wrongly accepted a low-order share pass the row after the socket timeout. So every raw handler follows
  the hostile message with something a client that accepted it fails on at once with another alert: an
  undecryptable application_data record (TLS 1.3 ServerHello, `bad_record_mac`), a ChangeCipherSpec plus
  undecryptable Finished after the client's Finished (TLS 1.2 SKE, `bad_record_mac`), an empty Certificate
  after a second ClientHello (HRR, `unexpected_message`), a Finished after the ServerHello (TLS 1.2,
  `unexpected_message`). The four control rows send the same flight with a valid value and pin the
  tripwire alert, with the server handler finishing cleanly.
- **Box 5 alert.** The issue leaves the alert open; the client raises `certificate_unknown`
  (`BcTlsRawKeyCertificate.ValidateRsa_Pss_Rsae` / `ValidateRsa_Pss_Pss`) on TLS 1.3 and 1.2 alike, and the
  rows pin it.
- **Extra rows** beyond the boxes, same checks: SCSV selected, wrong-version suites, the HRR group already
  in key_share (RFC 8446 4.2.8), a TLS 1.3 key share for x448, rsa sha1/sha224 SKE.
- No row found a missing rejection: no follow-up issue.

## How verified

- `strip/smoke/run.sh --filter hostile-negotiation` on `TurboBC.ns21.dll` and `TurboBC.netfx.dll`: 45/45 each.
- Mutation check (scratch strip `--report --set netstandard21`, never committed): with the offered-scheme
  check, suite selection, version-for-suite, key-share selection, ECDH config group check, X25519 all-zero
  check, `DerBitString.GetOctets` alignment check and both `RsaUtilities.SupportsPss_*` disabled, 37 of the
  41 hostile rows fail (completed handshake, another alert, or no exception). The three TLS 1.3 ServerHello
  suite rows still see `illegal_parameter` from the independent `GetPrfAlgorithm` check (suite vs. TLS 1.3),
  and the check behind `serverhello-tls13-keyshare-x448` (`m_clientAgreements` lookup) was not mutated. The
  controls pass on both builds. (The first mutation run found that the BER pad-bit row passed because BASE's
  encoder had cleared the bit; fixed by restoring the octet, and the row fails on the mutated build.)
- `./tools/ci/check.sh` (strip.sh enforce, all fast smoke rows, budget 748 clean).
