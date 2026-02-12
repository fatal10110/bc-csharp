# BouncyCastle Stripping Plan (Unity TLS Fallback)

## Scope
Minimal BouncyCastle subset for Unity TLS client fallback on Android and iOS.
Provider selection happens once before the first TLS attempt. TLS is used for ALPN with `h2` and `http/1.1`.

## Requirements
- TLS 1.2 and TLS 1.3 only
- ALPN for `h2` and `http/1.1`
- X.509 parsing for SAN and DN only
- No RFC 5280 PKIX chain validation inside BouncyCastle
- No TLS retry logic; provider chosen once before first connection

## Entry Points (Observed Usage)
- `SecureRandom..ctor()`
- `BcTlsCrypto..ctor(SecureRandom)`
- `TlsClientProtocol..ctor(Stream)`
- `TlsClientProtocol.Connect(TlsClient)`
- `TlsClientProtocol.Stream`
- `TlsClientProtocol.Close()`
- `DefaultTlsClient..ctor(TlsCrypto)`
- `TlsExtensionsUtilities.AddAlpnExtensionClient(...)`
- `ProtocolName.AsUtf8Encoding(string)`
- `TlsExtensionsUtilities.AddServerNameExtension(...)`
- `ServerName..ctor(NameType.host_name, string)`
- `ProtocolName.GetUtf8Decoding()`
- `ProtocolVersion.TLSv12`
- `ProtocolVersion.TLSv13`
- `TlsClientContext.ServerVersion`
- `SecurityParameters.CipherSuite`
- `DefaultTlsClient.GetClientExtensions()`
- `DefaultTlsClient.GetSupportedCipherSuites()`
- `TlsAuthentication.GetClientCredentials(CertificateRequest)`
- `TlsAuthentication.NotifyServerCertificate(TlsServerCertificate)`
- `TlsServerCertificate.Certificate`
- `Certificate.IsEmpty`
- `Certificate.Length`
- `Certificate.GetCertificateAt(int)`
- `TlsCertificate.GetX509Certificate()`
- `X509Certificate.GetSubjectAlternativeNames()`
- `X509Certificate.SubjectDN`
- `X509Certificate.NotBefore`
- `X509Certificate.NotAfter`
- `TlsFatalAlert(AlertDescription.*)`

## Minimal Keep Set (Option A)
Keep these source roots from `crypto/src` in this repo:
- `tls`
- `tls/crypto`
- `tls/crypto/impl/bc`
- `crypto`
- `math`
- `runtime` (keep `runtime/intrinsics` for hardware intrinsics helpers)
- `security`
- `util`
- `x509`
- `asn1`
- `asn1/x509`
- `asn1/x500`

Drop early (unless compilation shows a hard dependency):
- `pgp`
- `cms`
- `smime`
- `ocsp`
- `pkcs`
- `crmf`
- `eac`
- `tsp`
- `dvcs`
- `openpgp`
- `ess`
- `est`

## Cipher Suites to Pin (Recommended)
Update your TLS client to return a fixed list so unused crypto can be removed:
- TLS 1.3
  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`
  - `TLS_CHACHA20_POLY1305_SHA256`
- TLS 1.2
  - `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
  - `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
  - `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
  - Optional: `TLS_ECDHE_*_WITH_CHACHA20_POLY1305_SHA256`

## Stripping Steps (In-Place)
1. Freeze the bc-csharp version you will strip (2.2.1+ for TLS 1.3).
2. Create a working copy of `crypto/src` and delete everything outside the Minimal Keep Set.
3. Build the stripping project and re-add only the specific files that fail compilation.
4. If size is still too large, trim `BcTlsCrypto` to only construct algorithms used by the pinned cipher suites.
5. Re-run the build until it compiles cleanly with only TLS 1.2/1.3 + ALPN paths and X.509 parsing.

## Deferred (For Later)
- Unity 2021.3 LTS compatibility pass (asmdef, IL2CPP/Mono conditionals, `link.xml` preserves)
- Android/iOS validation (handshake, ALPN, perf, memory)
