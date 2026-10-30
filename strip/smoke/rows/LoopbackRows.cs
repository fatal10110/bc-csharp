using System;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #23: the harness end to end. SmokeTlsClient (TurboBC) handshakes over loopback TCP with a SmokeTlsServer on
    /// the upstream BASE library, then exchanges application data: TLS 1.3 with an ECDSA P-256 certificate, TLS
    /// 1.2 ECDHE_RSA with an RSA 2048 certificate (rsa_pss_rsae_sha256), and a pinned-certificate mismatch the
    /// client must refuse. Interop with OpenSSL is #25; hostile servers #26; timeouts #27.
    /// </summary>
    public sealed class LoopbackRows : SmokeRowGroup
    {
        private static readonly string[] Alpn = { "h2", "http/1.1" };

        private static readonly Lazy<SmokeServerKey> EcdsaKey =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp256r1"));

        private static readonly Lazy<SmokeServerKey> RsaKey = new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateRsa());

        public override string Name => "loopback";
        public override int Order => 50;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("tls13-ecdsa-p256", () =>
            {
                SmokeTlsClient client = Exchange(new SmokeTlsServer(EcdsaKey.Value), EcdsaKey.Value, Alpn,
                    out SmokeTlsServer server);
                SmokeAssert.Equal("1.3", client.NegotiatedVersion, "version");
                SmokeAssert.Equal("h2", client.NegotiatedAlpn, "ALPN");
                SmokeAssert.True(Array.IndexOf(new[] { "0x1301", "0x1302", "0x1303" }, client.NegotiatedCipherSuite) >= 0,
                    "TLS 1.3 suite " + client.NegotiatedCipherSuite);
                SmokeAssert.Equal("localhost", server.ReceivedServerName, "SNI seen by the server");
                SmokeAssert.Equal(30000, client.GetHandshakeTimeoutMillis(), "handshake timeout");
            });
            rows.Add("tls12-ecdhe-rsa-2048", () =>
            {
                var tls12 = new SmokeTlsServer(RsaKey.Value);
                tls12.Versions = SmokeTlsServer.Tls12Only;
                SmokeTlsClient client = Exchange(tls12, RsaKey.Value, new[] { "http/1.1" }, out SmokeTlsServer server);
                SmokeAssert.Equal("1.2", client.NegotiatedVersion, "version");
                SmokeAssert.Equal("http/1.1", client.NegotiatedAlpn, "ALPN");
                SmokeAssert.True(Array.IndexOf(new[] { "0xC02F", "0xC030", "0xCCA8" }, client.NegotiatedCipherSuite) >= 0,
                    "ECDHE_RSA AEAD suite " + client.NegotiatedCipherSuite);
                SmokeAssert.Equal("localhost", server.ReceivedServerName, "SNI seen by the server");
            });
            rows.Add("pinned-certificate-mismatch", () =>
            {
                var server = new SmokeTlsServer(EcdsaKey.Value);
                using (SmokeServerHost host = SmokeServerHost.StartTls(server))
                {
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                        SmokeTlsAuthentication.Pinned(RsaKey.Value.CertificateDer));
                    TlsFatalAlert e = SmokeAssert.Throws<TlsFatalAlert>(
                        () => SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose(),
                        "handshake with an unpinned certificate");
                    SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.bad_certificate),
                        AlertDescription.GetText(e.AlertDescription), "alert for an unpinned certificate");
                    host.Join();
                }
            });
        }

        private static SmokeTlsClient Exchange(SmokeTlsServer tlsServer, SmokeServerKey key, string[] alpn,
            out SmokeTlsServer server)
        {
            server = tlsServer;
            using (SmokeServerHost host = SmokeServerHost.StartTls(tlsServer))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", alpn,
                    SmokeTlsAuthentication.Pinned(key.CertificateDer));
                using (SmokeConnection connection = SmokeClient.Connect(SmokeServerHost.Address, host.Port, client))
                {
                    byte[] ping = Encoding.ASCII.GetBytes("smoke ping");
                    connection.Stream.Write(ping, 0, ping.Length);
                    byte[] echo = new byte[ping.Length];
                    int read = 0;
                    while (read < echo.Length)
                    {
                        int n = connection.Stream.Read(echo, read, echo.Length - read);
                        SmokeAssert.True(n > 0, "connection closed before the echo");
                        read += n;
                    }
                    SmokeAssert.Equal(ping, echo, "echoed application data");
                }
                Exception serverError = host.Join();
                SmokeAssert.True(serverError == null, "server failed: "
                    + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
                return client;
            }
        }
    }
}
