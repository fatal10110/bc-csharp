# 2026-10 — E2–E4: key-exchange factory, default suites, AbstractTlsClient defaults (#14)

## What

Edge cuts E2, E3 and E4 (STRIP_PLAN_V2.md §3), one commit; every hunk is marked `// turbo-strip: E2|E3|E4 ...`.

- **E2** `crypto/src/tls/DefaultTlsKeyExchangeFactory.cs`: `CreateDHKeyExchange`, `CreateDHanonKeyExchange{Client,Server}`,
  `CreateDheKeyExchange{Client,Server}`, `CreateECDHKeyExchange` (static ECDH),
  `CreateECDHanonKeyExchange{Client,Server}`, `CreatePskKeyExchange{Client,Server}`, `CreateRsaKeyExchange` and
  `CreateSrpKeyExchange{Client,Server}` throw `TlsFatalAlert(internal_error)`. `CreateECDheKeyExchange{Client,Server}`
  are kept.
- **E3** `crypto/src/tls/DefaultTlsClient.cs`: the default suite list is the nine plan suites, in plan order:
  TLS 1.3 CHACHA20_POLY1305_SHA256, AES_128_GCM_SHA256, AES_256_GCM_SHA384; TLS 1.2 ECDHE_ECDSA then ECDHE_RSA, each
  with CHACHA20_POLY1305_SHA256, AES_128_GCM_SHA256, AES_256_GCM_SHA384.
- **E4** `crypto/src/tls/AbstractTlsClient.cs`: `GetDHGroupVerifier` and `GetSrpConfigVerifier` return null;
  `GetCertificateStatusRequest` returns null (decision D; `GetMultiCertStatusRequest` was already null);
  `GetSupportedGroups` adds secp521r1 to the secp256r1/secp384r1 array.

Resulting ClientHello from a `DefaultTlsClient` on `BcTlsCrypto`: cipher_suites = the nine E3 suites followed by
`TLS_EMPTY_RENEGOTIATION_INFO_SCSV`; supported_groups = x25519, secp256r1, secp384r1, secp521r1; no status_request,
no status_request_v2.

## Files

- `crypto/src/tls/DefaultTlsKeyExchangeFactory.cs` — E2 hunks (13 methods).
- `crypto/src/tls/DefaultTlsClient.cs` — E3 default suite list.
- `crypto/src/tls/AbstractTlsClient.cs` — E4 hunks (two verifiers, status request, secp521r1).
- `crypto/test/src/turbo/DefaultTlsClientE2E4Test.cs` — new plain-NUnit fixture (`Org.BouncyCastle.Turbo.Tests`):
  exact offered suites + SCSV, exact supported_groups, no status_request(_v2) on a captured ClientHello; null
  verifiers; every non-ECDHE factory method throws internal_error; ECDHE client/server still constructed.
- `strip/upstream-expected-failures.txt` — `E2` (7) and `E4/D` (11) groups, plus one `E5` line (see Decisions).

## Decisions

- "anon" in the plan row covers both DH_anon and ECDH_anon: all four anon methods throw (nothing in the strip offers
  an anon suite; conservative).
- Server-side factory methods throw too: the plan row lists key-exchange kinds without a client/server split; the
  ECDHE server stays because the upstream mock servers use it for the kept suites.
- Suite order follows the plan text (ChaCha20 first, decision G) and is pinned by the fixture.
- Not cut (plan does not name them; deny/closure is #8): the unreachable `TlsUtilities.CreateKeyExchange{Client,Server}`
  branches, `PskTlsClient`, `SrpTlsClient`, `DefaultTlsDHGroupVerifier`, the ffdhe branch of `GetSupportedGroups`
  (cannot fire: no DHE suite is offered and E1 `HasNamedGroup` rejects ffdhe).
- `SM2Tls13Test.SM2SignerAndVerifier_BC_BC` already fails on strip-v2 at 631d82a3: the E5 cut (#40) removed the
  sm2sig_sm3 verifier from `BcTlsRawKeyCertificate.CreateVerifier`, and #41 (expected-failures list) merged in
  parallel without it. Listed under `E5` so `upstream_tests.py` reports zero regressions.

## Deferred

- The ClientHello row of the smoke suite (#24) takes over the exact suites/groups/status_request assertions.

## How verified

- `./tools/ci/check.sh` (format of added upstream lines, library build netstandard2.0 + net6.0): OK.
- strip/strip.sh: n/a (not present yet).
- `dotnet test --framework net6.0 --filter "FullyQualifiedName~DefaultTlsClientE2E4Test|FullyQualifiedName~BcTlsCryptoE1"`:
  14/14 pass. On the unmodified library 5/6 of the new fixture fail (the sixth, ECDHE kept, is a preservation check).
- `strip/tool/upstream_tests.py` (kept surface, 505 tests): 430 pass, 75 fail, all 75 listed (E1 ×56, E2 ×7,
  E4/D ×11, E5 ×1), 0 regressions. New failures from this change: 7 PSK tests (E2: the PSK factory methods throw)
  and 11 status-request tests (E4/D: the mock clients rely on `base.GetCertificateStatusRequest()`). E3 broke no
  upstream test.
- `python3 -m unittest discover -s strip/tool -p 'test_upstream_tests.py'`: 23/23 OK.
