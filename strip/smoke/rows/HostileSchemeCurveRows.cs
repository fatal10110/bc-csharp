using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using BaseTls = Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #65: TLS 1.3 binds each ecdsa_secp* signature scheme to its curve and hash (RFC 8446 section 4.2.3). A server
    /// (BASE, which does not check the binding when signing) signs CertificateVerify with a scheme whose curve is not
    /// its key's curve; the client must refuse it with illegal_parameter (E5, BcTlsRawKeyCertificate.CreateVerifier)
    /// although the signature itself verifies under the certificate's key. Matching schemes still complete over TLS
    /// 1.3, and TLS 1.2, where ecdsa binds neither curve nor hash (RFC 8422 section 5.4), still accepts a P-384 key
    /// signing ServerKeyExchange with SHA-256.
    /// </summary>
    public sealed class HostileSchemeCurveRows : SmokeRowGroup
    {
        private static readonly string[] Alpn = { "http/1.1" };

        private static readonly Lazy<SmokeServerKey> P256 =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp256r1"));

        private static readonly Lazy<SmokeServerKey> P384 =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp384r1"));

        private static readonly Lazy<SmokeServerKey> P521 =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp521r1"));

        public override string Name => "hostile-scheme-curve";

        public override void AddRows(SmokeRows rows)
        {
            // Mismatch: one row per ecdsa_secp* case of the verifier.
            rows.Add("scheme-curve-p384-signs-0403-tls13-illegal-parameter",
                () => AssertRejected(SignAs(P384.Value, BaseTls.HashAlgorithm.sha256)));
            rows.Add("scheme-curve-p521-signs-0403-tls13-illegal-parameter",
                () => AssertRejected(SignAs(P521.Value, BaseTls.HashAlgorithm.sha256)));
            rows.Add("scheme-curve-p256-signs-0503-tls13-illegal-parameter",
                () => AssertRejected(SignAs(P256.Value, BaseTls.HashAlgorithm.sha384)));
            rows.Add("scheme-curve-p256-signs-0603-tls13-illegal-parameter",
                () => AssertRejected(SignAs(P256.Value, BaseTls.HashAlgorithm.sha512)));

            // Match: each curve with its own scheme (CreateEcdsa's default) completes over TLS 1.3.
            rows.Add("scheme-curve-p256-signs-0403-tls13-accepted", () => AssertHandshake(P256.Value, true));
            rows.Add("scheme-curve-p384-signs-0503-tls13-accepted", () => AssertHandshake(P384.Value, true));
            rows.Add("scheme-curve-p521-signs-0603-tls13-accepted", () => AssertHandshake(P521.Value, true));

            // TLS 1.2: (sha256, ecdsa) with a P-384 key is legal and stays accepted.
            rows.Add("scheme-curve-p384-signs-sha256-tls12-accepted",
                () => AssertHandshake(SignAs(P384.Value, BaseTls.HashAlgorithm.sha256), false));
        }

        /// <summary>The same certificate and key, signing with (hash, ecdsa) instead of the curve's own hash.</summary>
        private static SmokeServerKey SignAs(SmokeServerKey key, short hash) =>
            new SmokeServerKey(key.Kind + "-hash" + hash, key.ChainDer, key.PrivateKey,
                BaseTls.SignatureAndHashAlgorithm.GetInstance(hash, BaseTls.SignatureAlgorithm.ecdsa), true);

        private static void AssertRejected(SmokeServerKey signer)
        {
            var server = new SmokeHostileTlsServer(signer, signer.CertificateDer, true);
            using (SmokeServerHost host = SmokeServerHost.StartTls(server))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                    SmokeTlsAuthentication.Pinned(signer.CertificateDer));
                TlsFatalAlert alert = SmokeAssert.Throws<TlsFatalAlert>(
                    () => SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose(),
                    "TLS 1.3 handshake with a scheme naming another curve");
                // The server only sees the client's alert; its outcome is not part of the row.
                host.Join();
                SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.illegal_parameter),
                    AlertDescription.GetText(alert.AlertDescription), "alert (" + SmokeRunner.Describe(alert) + ")");
            }
        }

        private static void AssertHandshake(SmokeServerKey key, bool tls13)
        {
            var server = new SmokeHostileTlsServer(key, key.CertificateDer, tls13);
            using (SmokeServerHost host = SmokeServerHost.StartTls(server))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                    SmokeTlsAuthentication.Pinned(key.CertificateDer));
                SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose();
                SmokeAssert.Equal(tls13 ? "1.3" : "1.2", client.NegotiatedVersion, "version");
                Exception serverError = host.Join();
                SmokeAssert.True(serverError == null, "server failed: "
                    + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
            }
        }
    }
}
