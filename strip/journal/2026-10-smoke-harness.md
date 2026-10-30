# 2026-10 Smoke harness, curve lookup and primitive KATs (#23, #24)

## What

`strip/smoke/` holds the strip's smoke suite (`STRIP_PLAN_V2.md` §5 step 5): a net8 console
(`TurboSmoke`) built once per `TurboBC.<x>.dll`. The client side references that DLL (namespaces
`TurboHTTP.SecureProtocol.Org.BouncyCastle.*`), the server and tooling side a full upstream build of
`strip/BASE` (`BouncyCastle.Cryptography`, `Org.BouncyCastle.*`); the two share no types and meet only
over byte streams. `strip/smoke/run.sh` is strip.sh's step 5 hook (contract unchanged:
`--work <work> --results <file> <TurboBC dll>...`, exit 0 = pass) and runs standalone too. Rows here:
curve lookup (first), KATs, and a loopback self-check of the harness. #25 (OpenSSL interop, ClientHello),
#26 (hostile servers) and #27 (timeouts) add row groups as new files under `strip/smoke/rows/`.

## Files

- `strip/smoke/run.sh` (100755): argument checks (usage errors exit 2); step 1 builds BASE
  (`git worktree add --detach <work>/smoke/base-src <BASE>`, `dotnet build crypto/src/BouncyCastle.Crypto.csproj
  -f net6.0 -c Release -o <work>/smoke/base/bin`, worktree removed again, stamp `<work>/smoke/base/BASE`;
  reused while the stamp matches; `--base-dll` skips it; failure exits 3); step 2 the runner self-test
  (once); step 3 per DLL: harness build into `<work>/smoke/build/<x>/` (`-p:TurboBcDll`,
  `-p:UpstreamBcDll`, own obj dir), run with `--label <x>`; the results file gets a header (BASE) and one
  block per DLL. A harness that does not compile against a DLL fails that DLL only. `--filter` passes
  through. bash-3.2 portable, shellcheck clean.
- `strip/smoke/TurboSmoke.csproj`: net8.0 Exe, C# 9, nullable/implicit usings off, no NuGet packages; two
  `Reference`s by HintPath; an MSBuild error when either path is missing.
- `strip/smoke/harness/`: `SmokeRowGroup` (abstract: `Name`, `Order`, `AddRows(SmokeRows)`), `SmokeRows.Add(name,
  body, timeoutMillis = 60000)`, `SmokeContext` (label, DLL, scratch work dir); `SmokeRunner` (reflection
  discovery of every non-abstract `SmokeRowGroup`, ordered by `Order` then `Name`; duplicate group or row
  ids and throwing registrations become failed rows; each row on its own background thread with a join
  timeout, exceptions caught per row, one-line exception chains; results text without timings);
  `SmokeAssert`/`SmokeHex` (byte diffs report the first differing offset); `SmokeSelfTest`
  (`--self-test`: failing check, exception, throwing static initializer, hanging row, broken and
  duplicate registration each fail alone and the next row still runs); `Program` (CLI, exit 0/1/2).
- `strip/smoke/client/`: `SmokeTlsClient : DefaultTlsClient` mirrors `strip/roots/TurboTlsClient.cs`
  (ALPN, SNI, TLS 1.3 + 1.2, default suites, negotiated version/ALPN/suite capture) plus an injected
  `TlsAuthentication` and `GetHandshakeTimeoutMillis()` = `HandshakeTimeoutMillis` (default 30000);
  `SmokeTlsAuthentication` (pins the end-entity DER, or explicit `AcceptAny()`; records the presented
  certificate); `SmokeClient` (BcTlsCrypto over SecureRandom, `TlsClientProtocol.Connect` like
  BouncyCastleTlsProvider, `Connect(host, port, client, receiveTimeoutMillis = 30000)` sets the socket
  timeouts) and `SmokeConnection`.
- `strip/smoke/server/` (upstream BASE): `SmokeServerKey` (chain DER + private key + signature scheme;
  `CreateEcdsa(curve)` / `CreateRsa(bits)` self-sign a fresh certificate; hostile rows pass their own),
  `SmokeTlsServer : DefaultTlsServer` (versions, ALPN and suites as knobs; strip AEAD suites by key type;
  records the SNI it received; one credential for 1.3 and 1.2), `SmokeServerHost` (one connection on
  127.0.0.1, ephemeral port, handler thread: raw `Start(Action<Stream>)` for trickle/malformed servers or
  `StartTls(server, afterHandshake)`, default echo; `Join` returns the handler's exception).
- `strip/smoke/rows/`: `CurveLookupRows` (curves, order 0), `KatAeadRows`, `KatDigestRows`, `KatEcRows`,
  `KatRsaRows`, `KatTlsHkdfRows` (order 10), `LoopbackRows` (order 50).
- `strip/tool/test_smoke_run_sh.py`: run.sh in a temporary repository layout with fake dotnet and git:
  usage errors, BASE build from a temporary worktree and its reuse/rebuild, `--base-dll`, BASE build
  failure (exit 3, worktree removed), one build and run per DLL with distinct output dirs, self-test once,
  results order, `--filter`, a failing row, a harness build failure, a self-test failure.

## Rows (26 on TurboBC.min.dll)

- `curves/registry`, `curves/secp{256,384,521}r1`: `CustomNamedCurves.Names/GetOid/GetName/GetByName/
  GetByOid` (names, OIDs and the P-256/384/521 aliases agree; custom `SecP*R1Curve` implementation; field
  size; G on the curve), `ECDomainParameters.LookupName` (name and alias → `ECNamedDomainParameters` with
  the SEC OID), `ECNamedDomainParameters.LookupOid`. Public API only; runs first.
- `kat-aead`: AES-128/256-GCM (GCM spec test cases 4 and 16, crypto/test GCMTest.cs) on `AesLightEngine`
  with `BasicGcmMultiplier` passed explicitly and with `GcmBlockCipher(engine)` as BcTlsCrypto builds it
  (E14 default); ChaCha20-Poly1305 RFC 8439 §2.8.2 through `BcChaCha20Poly1305`. Encrypt, decrypt, flipped
  tag rejected (`InvalidCipherTextException` / `TlsFatalAlert`).
- `kat-digest`: SHA-256 (two vectors), SHA-384, SHA-512 (FIPS 180), HMAC-SHA-256/384/512 (RFC 4231 case 2).
- `kat-ec`: X25519 RFC 7748 §5.2 vectors 1 and 2 and the §6.1 ECDH; ECDSA verify P-256/SHA-256,
  P-384/SHA-384, P-521/SHA-512 (RFC 6979 A.2.5–A.2.7 "sample"): public key decoded from its uncompressed
  encoding equals d·G, the RFC signature verifies, s+1 and another message do not.
- `kat-rsa`: RSASSA-PSS example 1 key (crypto/test PSSTest.cs): PSS SHA-1 example 1.2; PSS SHA-256 salt 32
  and PKCS#1 v1.5 SHA-256 over the same message, signed by OpenSSL 3.0.13 (key built from the vector's CRT
  components with `openssl asn1parse -genconf`); flipped bit rejected.
- `kat-tls13-hkdf/rfc8448-key-schedule`: BcTlsCrypto HkdfInit/HkdfExtract/HkdfExpandLabel through early,
  handshake, c/s hs traffic, master and the server handshake key/iv (RFC 8448 §3; BcTlsCryptoTest.TestHkdf).
- `loopback`: TLS 1.3 with an ECDSA P-256 certificate (h2, a 1.3 suite, SNI seen by the server, timeout
  30000), TLS 1.2 ECDHE_RSA with RSA 2048 (rsa_pss_rsae_sha256; http/1.1; ECDHE_RSA AEAD suite), and a
  pinned-certificate mismatch refused with bad_certificate; application data echoed.

## Decisions

- One harness build per DLL (`-p:TurboBcDll`): the TurboBC DLLs share namespaces and type names, so one
  compilation can reference only one; building per DLL also proves the rows compile against each set. A
  row naming a type outside a set's closure fails that DLL's build, reported as such.
- BASE comes from a temporary `git worktree` (Nerdbank.GitVersioning needs history; same pattern as
  upstream_tests.py), built for net6.0 into `<work>/smoke/base/bin`, the worktree removed, the build
  reused while the stamp names the same BASE (strip.sh keeps `<work>`).
- Registration by reflection over `SmokeRowGroup` subclasses: a new row group is a new file, no shared
  edit. The harness is not shipped, so reflection there is no IL2CPP concern.
- Results: plain text, no timings (deterministic for STRIP_INFO.md); per-row timings go to the console.
- KAT vectors inlined (no bc-test-data dependency), taken from upstream crypto/test sources; where
  crypto/test has no fixed known answer for the strip's scheme (PKCS#1 v1.5 SHA-256, PSS SHA-256) the
  signature comes from OpenSSL over the PSS example key.
- `Crypto.Modes.ChaCha20Poly1305` is outside the closure; the TLS implementation `BcChaCha20Poly1305` is
  what the strip ships, so the KAT runs through it.
- `BasicGcmMultiplier` and `GcmBlockCipher(IBlockCipher, IGcmMultiplier)` are `[Obsolete]` upstream: the
  explicit construction sits in a `#pragma warning disable CS0618` scope.
- `SmokeTlsClient` stays C# 9 like the consumer it mirrors (the project is LangVersion 9).
- Authentication: pinned end-entity certificate by default (decision A: no BC chain validation);
  `AcceptAny()` only explicitly.
- Per-row timeout 60 s by default (a hung row is abandoned on a background thread and failed);
  `SmokeClient.Connect` sets the socket receive/send timeout (30 s default) as the plan asks.

## Deferred

- The hook runs end to end in strip.sh only once every 3c build is clean (#19 E9–E12, #20 E13); until
  then strip.sh logs "smoke skipped" and STRIP_INFO.md says the smoke did not run.
- OpenSSL interop and exact ClientHello lists: #25. Hostile inputs: #26. Timeout rows: #27.

## How verified

- TurboBC.min.dll built by hand from this tree (`closure.py --no-deny --set min --report`, `build.py stage`,
  the three rewrites, `build.py build --set min`): `strip/smoke/run.sh --work <scratch> --results <file>
  <scratch>/dll/TurboBC.min.dll` exit 0, BASE built in ~6 s on a warm NuGet cache, self-test OK, 26/26 rows
  pass; a rerun reuses the BASE build.
- A mutated GCM tag byte in `KatAeadRows.cs`: `kat-aead/aes128-gcm-light-basic` FAIL, run.sh exit 1,
  the other rows still run (reverted).
- `python3 -m unittest discover -s strip/tool -p 'test_*.py'`; `shellcheck strip/smoke/run.sh`;
  `./tools/ci/check.sh` (strip.sh --report: builds not clean yet, so the hook is skipped and logged).
