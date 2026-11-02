using System;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using UpstreamAlertDescription = Org.BouncyCastle.Tls.AlertDescription;
using UpstreamTlsFatalAlertReceived = Org.BouncyCastle.Tls.TlsFatalAlertReceived;
using UpstreamTlsServerProtocol = Org.BouncyCastle.Tls.TlsServerProtocol;

namespace TurboSmoke
{
    /// <summary>
    /// #75: the non-blocking TlsClientProtocol API that turboHTTP's BouncyCastleTlsStream drives (strip/roots):
    /// OfferInput, ReadOutput, GetAvailableInputBytes, GetAvailableOutputBytes, ReadInput, WriteApplicationData and
    /// CloseInput, through <see cref="SmokeNonBlockingConnection"/>. A handshake and an echo over loopback on TLS 1.3
    /// and 1.2; the alert a failing OfferInput leaves in the output queue reaching the server through ReadOutput; and
    /// a transport close without close_notify surfacing from CloseInput as TlsNoCloseNotifyException, the type the
    /// consumer relies on (RFC 8446 section 6.1: truncation, never a clean end of data), with IsFailed set and later
    /// reads failing.
    /// </summary>
    public sealed class NonBlockingRows : SmokeRowGroup
    {
        private static readonly string[] Alpn = { "h2", "http/1.1" };

        private static readonly byte[] Ping = Encoding.ASCII.GetBytes("smoke ping");

        private static readonly Lazy<SmokeServerKey> EcdsaKey =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp256r1"));

        private static readonly Lazy<SmokeServerKey> RsaKey = new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateRsa());

        public override string Name => "nonblocking";
        public override int Order => 55;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("tls13-ecdsa-p256-echo", () =>
            {
                SmokeTlsClient client = Echo(new SmokeTlsServer(EcdsaKey.Value), EcdsaKey.Value, Alpn);
                SmokeAssert.Equal("1.3", client.NegotiatedVersion, "version");
                SmokeAssert.Equal("h2", client.NegotiatedAlpn, "ALPN");
            });
            rows.Add("tls12-ecdhe-rsa-2048-echo", () =>
            {
                var tls12 = new SmokeTlsServer(RsaKey.Value);
                tls12.Versions = SmokeTlsServer.Tls12Only;
                SmokeTlsClient client = Echo(tls12, RsaKey.Value, new[] { "http/1.1" });
                SmokeAssert.Equal("1.2", client.NegotiatedVersion, "version");
                SmokeAssert.Equal("http/1.1", client.NegotiatedAlpn, "ALPN");
            });
            rows.Add("pinned-mismatch-alert-reaches-server", () =>
            {
                using (SmokeServerHost host = SmokeServerHost.StartTls(new SmokeTlsServer(EcdsaKey.Value)))
                {
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                        SmokeTlsAuthentication.Pinned(RsaKey.Value.CertificateDer));
                    TlsFatalAlert e = SmokeAssert.Throws<TlsFatalAlert>(
                        () => SmokeNonBlockingConnection.Connect(SmokeServerHost.Address, host.Port, client).Dispose(),
                        "OfferInput of an unpinned certificate");
                    SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.bad_certificate),
                        AlertDescription.GetText(e.AlertDescription), "alert raised by the client");
                    // The alert the engine queued was taken with ReadOutput and sent before the failure propagated.
                    Exception serverError = host.Join();
                    var received = serverError as UpstreamTlsFatalAlertReceived;
                    SmokeAssert.True(received != null, "server saw: "
                        + (serverError == null ? "no error" : SmokeRunner.Describe(serverError)));
                    SmokeAssert.Equal(UpstreamAlertDescription.GetText(UpstreamAlertDescription.bad_certificate),
                        UpstreamAlertDescription.GetText(received.AlertDescription), "alert received by the server");
                }
            });
            rows.Add("truncation-without-close-notify", () =>
            {
                var server = new SmokeTlsServer(EcdsaKey.Value);
                using (SmokeServerHost host = SmokeServerHost.Start(stream =>
                {
                    // Handshake, echo one message, then close the socket without close_notify (TlsServerProtocol.Close
                    // would send one).
                    var protocol = new UpstreamTlsServerProtocol(stream);
                    protocol.Accept(server);
                    byte[] buffer = new byte[Ping.Length];
                    int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                    protocol.Stream.Write(buffer, 0, n);
                    protocol.Stream.Flush();
                    stream.Dispose();
                }))
                {
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                        SmokeTlsAuthentication.Pinned(EcdsaKey.Value.CertificateDer));
                    using (var connection = SmokeNonBlockingConnection.Connect(SmokeServerHost.Address, host.Port, client))
                    {
                        connection.Write(Ping);
                        SmokeAssert.Equal(Ping, ReadExactly(connection, Ping.Length), "echoed application data");
                        byte[] more = new byte[16];
                        SmokeAssert.Throws<TlsNoCloseNotifyException>(() => connection.Read(more, 0, more.Length),
                            "CloseInput after end of stream without close_notify");
                        SmokeAssert.True(connection.Protocol.IsClosed && connection.Protocol.IsFailed,
                            "engine closed and failed after the truncation");
                        SmokeAssert.Throws<System.IO.IOException>(() => connection.Read(more, 0, more.Length),
                            "read on the failed connection");
                    }
                    Exception serverError = host.Join();
                    SmokeAssert.True(serverError == null, "server failed: "
                        + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
                }
            });
        }

        private static SmokeTlsClient Echo(SmokeTlsServer tlsServer, SmokeServerKey key, string[] alpn)
        {
            using (SmokeServerHost host = SmokeServerHost.StartTls(tlsServer))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", alpn,
                    SmokeTlsAuthentication.Pinned(key.CertificateDer));
                using (var connection = SmokeNonBlockingConnection.Connect(SmokeServerHost.Address, host.Port, client))
                {
                    SmokeAssert.True(connection.Protocol.IsConnected && !connection.Protocol.IsHandshaking,
                        "engine state after the handshake");
                    connection.Write(Ping);
                    SmokeAssert.Equal(0, connection.Protocol.GetAvailableOutputBytes(), "output queue drained by ReadOutput");
                    SmokeAssert.Equal(Ping, ReadExactly(connection, Ping.Length), "echoed application data");
                    SmokeAssert.Equal(0, connection.Protocol.GetAvailableInputBytes(), "input queue drained by ReadInput");
                }
                Exception serverError = host.Join();
                SmokeAssert.True(serverError == null, "server failed: "
                    + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
                return client;
            }
        }

        private static byte[] ReadExactly(SmokeNonBlockingConnection connection, int count)
        {
            byte[] data = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = connection.Read(data, read, count - read);
                SmokeAssert.True(n > 0, "connection closed before " + count + " bytes arrived");
                read += n;
            }
            return data;
        }
    }
}
