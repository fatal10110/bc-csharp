using System;
using System.IO;
using System.Net.Sockets;
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
    /// and 1.2; the alert a failing OfferInput leaves in the output queue (read back with ReadOutput, asserted byte for
    /// byte over TLS 1.2 where it is plaintext); a transport close without close_notify at a record boundary
    /// surfacing from CloseInput as TlsNoCloseNotifyException, the type the consumer relies on (RFC 8446 section 6.1:
    /// truncation, never a clean end of data), with IsFailed set and later reads failing; and a transport close inside
    /// a record, CloseInput's other path (EndOfStreamException while input is buffered), which must also never read as
    /// end of data.
    /// </summary>
    public sealed class NonBlockingRows : SmokeRowGroup
    {
        private static readonly string[] Alpn = { "h2", "http/1.1" };

        private static readonly byte[] Ping = Encoding.ASCII.GetBytes("smoke ping");

        /// <summary>One maximum TLS record, the consumer's staging size.</summary>
        private const int BufferSize = 16 * 1024 + 2048 + 5;

        /// <summary>RFC 5246 7.2: an alert record, version TLS 1.2, length 2, level fatal(2), bad_certificate(42).</summary>
        private static readonly byte[] BadCertificateAlertRecord = { 0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x2A };

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
            rows.Add("pinned-mismatch-alert-via-readoutput", () =>
            {
                // TLS 1.2, so the alert the client raises on the server's Certificate is plaintext on the wire. The
                // engine is driven by hand here (as ClientHelloRows.Capture does) to read the output queue after the
                // failing OfferInput. The server's view is a race (it may still be writing its flight when the client
                // closes), so only the client side is asserted byte for byte.
                var tls12 = new SmokeTlsServer(EcdsaKey.Value);
                tls12.Versions = SmokeTlsServer.Tls12Only;
                using (SmokeServerHost host = SmokeServerHost.StartTls(tls12))
                using (var tcp = new TcpClient())
                {
                    tcp.ReceiveTimeout = SmokeClient.DefaultReceiveTimeoutMillis;
                    tcp.SendTimeout = SmokeClient.DefaultReceiveTimeoutMillis;
                    tcp.Connect(SmokeServerHost.Address, host.Port);
                    NetworkStream net = tcp.GetStream();
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                        SmokeTlsAuthentication.Pinned(RsaKey.Value.CertificateDer));
                    var protocol = new TlsClientProtocol();
                    byte[] buffer = new byte[BufferSize];
                    protocol.Connect(client);
                    Drain(protocol, net, buffer);
                    TlsFatalAlert e = SmokeAssert.Throws<TlsFatalAlert>(() =>
                    {
                        while (protocol.IsHandshaking)
                        {
                            int n = net.Read(buffer, 0, buffer.Length);
                            SmokeAssert.True(n > 0, "server closed before its certificate arrived");
                            protocol.OfferInput(buffer, 0, n);
                            Drain(protocol, net, buffer);
                        }
                    }, "OfferInput of an unpinned certificate");
                    SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.bad_certificate),
                        AlertDescription.GetText(e.AlertDescription), "alert raised by the client");
                    // What the failing OfferInput left in the output queue: exactly the fatal alert record.
                    byte[] queued = new byte[protocol.GetAvailableOutputBytes()];
                    protocol.ReadOutput(queued, 0, queued.Length);
                    SmokeAssert.Equal(BadCertificateAlertRecord, queued, "alert record from ReadOutput after the failure");
                    SmokeAssert.True(protocol.IsClosed && protocol.IsFailed, "engine closed and failed");
                    SmokeAssert.Equal(0, protocol.GetAvailableOutputBytes(), "nothing else queued");
                    net.Write(queued, 0, queued.Length);
                    tcp.Close();
                    // The server either read the alert or failed writing the rest of its flight to the closed socket;
                    // it never completed the handshake.
                    Exception serverError = host.Join();
                    SmokeAssert.True(serverError is UpstreamTlsFatalAlertReceived || serverError is IOException,
                        "server saw: " + (serverError == null ? "a completed handshake" : SmokeRunner.Describe(serverError)));
                    if (serverError is UpstreamTlsFatalAlertReceived received)
                    {
                        SmokeAssert.Equal(UpstreamAlertDescription.GetText(UpstreamAlertDescription.bad_certificate),
                            UpstreamAlertDescription.GetText(received.AlertDescription), "alert received by the server");
                    }
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
                        SmokeAssert.Throws<IOException>(() => connection.Read(more, 0, more.Length),
                            "read on the failed connection");
                    }
                    Exception serverError = host.Join();
                    SmokeAssert.True(serverError == null, "server failed: "
                        + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
                }
            });
            rows.Add("truncation-mid-record", () =>
            {
                // The server's echo record leaves without its last 5 bytes, then the socket closes: CloseInput sees
                // buffered input and takes its EndOfStreamException path (TlsProtocol.CloseInput), which must never
                // read as end of data, on this read or the next.
                var server = new SmokeTlsServer(EcdsaKey.Value);
                using (SmokeServerHost host = SmokeServerHost.Start(stream =>
                {
                    var truncating = new TruncatingStream(stream);
                    var protocol = new UpstreamTlsServerProtocol(truncating);
                    protocol.Accept(server);
                    byte[] buffer = new byte[Ping.Length];
                    int n = protocol.Stream.Read(buffer, 0, buffer.Length);
                    truncating.DropTail = 5;
                    protocol.Stream.Write(buffer, 0, n);
                    protocol.Stream.Flush();
                    SmokeAssert.True(truncating.Truncated, "the echo record was written to the transport");
                    stream.Dispose();
                }))
                {
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn,
                        SmokeTlsAuthentication.Pinned(EcdsaKey.Value.CertificateDer));
                    using (var connection = SmokeNonBlockingConnection.Connect(SmokeServerHost.Address, host.Port, client))
                    {
                        connection.Write(Ping);
                        byte[] more = new byte[Ping.Length];
                        IOException first = SmokeAssert.Throws<IOException>(() => connection.Read(more, 0, more.Length),
                            "CloseInput with a partial record buffered");
                        SmokeAssert.True(first.GetType() == typeof(EndOfStreamException),
                            "EndOfStreamException for a partial record, got " + first.GetType().Name);
                        IOException second = SmokeAssert.Throws<IOException>(() => connection.Read(more, 0, more.Length),
                            "second read after a partial record");
                        SmokeAssert.True(second.GetType() == typeof(EndOfStreamException),
                            "EndOfStreamException again, got " + second.GetType().Name);
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

        /// <summary>Every record the engine queued, to the socket.</summary>
        private static void Drain(TlsClientProtocol protocol, Stream net, byte[] buffer)
        {
            int n;
            while ((n = protocol.ReadOutput(buffer, 0, buffer.Length)) > 0)
            {
                net.Write(buffer, 0, n);
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

        /// <summary>
        /// A server transport that, once <see cref="DropTail"/> is set, writes the next record without its last
        /// <see cref="DropTail"/> bytes and discards everything after it: a peer that dies in the middle of a record.
        /// The upstream record layer writes one record per Write call.
        /// </summary>
        private sealed class TruncatingStream : Stream
        {
            private readonly Stream _inner;

            internal TruncatingStream(Stream inner)
            {
                _inner = inner;
            }

            internal int DropTail { get; set; }

            internal bool Truncated { get; private set; }

            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => true;
            public override long Length => throw new NotSupportedException();

            public override long Position
            {
                get => throw new NotSupportedException();
                set => throw new NotSupportedException();
            }

            public override void Flush() => _inner.Flush();

            public override int Read(byte[] buffer, int offset, int count) => _inner.Read(buffer, offset, count);

            public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();

            public override void SetLength(long value) => throw new NotSupportedException();

            public override void Write(byte[] buffer, int offset, int count)
            {
                if (DropTail <= 0)
                {
                    _inner.Write(buffer, offset, count);
                    return;
                }
                if (!Truncated)
                {
                    _inner.Write(buffer, offset, Math.Max(0, count - DropTail));
                    Truncated = true;
                }
            }

            protected override void Dispose(bool disposing)
            {
                if (disposing)
                {
                    _inner.Dispose();
                }
                base.Dispose(disposing);
            }
        }
    }
}
