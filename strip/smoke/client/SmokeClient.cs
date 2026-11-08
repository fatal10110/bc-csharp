using System;
using System.IO;
using System.Net.Sockets;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace TurboSmoke
{
    /// <summary>
    /// Client-side plumbing shaped like turboHTTP's BouncyCastleTlsProvider (strip/roots): BcTlsCrypto over a
    /// SecureRandom, TlsClientProtocol over the transport stream, Connect(client). Over TCP the harness sets the
    /// socket ReceiveTimeout (plan section 5 step 5), so a silent server cannot block a row past it.
    /// </summary>
    public static class SmokeClient
    {
        public const int DefaultReceiveTimeoutMillis = 30000;

        public static TlsCrypto CreateCrypto() => new BcTlsCrypto(new SecureRandom());

        /// <summary>A <see cref="SmokeTlsClient"/> on a fresh BcTlsCrypto.</summary>
        public static SmokeTlsClient CreateClient(string targetHost, string[] alpnProtocols,
            TlsAuthentication authentication) =>
            new SmokeTlsClient(CreateCrypto(), targetHost, alpnProtocols, authentication);

        /// <summary>Handshakes over an existing transport; throws whatever the handshake throws.</summary>
        public static TlsClientProtocol Handshake(Stream transport, SmokeTlsClient client)
        {
            var protocol = new TlsClientProtocol(transport);
            protocol.Connect(client);
            return protocol;
        }

        /// <summary>Connects over TCP and handshakes; the connection is closed again if the handshake throws.</summary>
        public static SmokeConnection Connect(string host, int port, SmokeTlsClient client,
            int receiveTimeoutMillis = DefaultReceiveTimeoutMillis)
        {
            var tcp = new TcpClient();
            try
            {
                tcp.ReceiveTimeout = receiveTimeoutMillis;
                tcp.SendTimeout = receiveTimeoutMillis;
                tcp.Connect(host, port);
                TlsClientProtocol protocol = Handshake(tcp.GetStream(), client);
                return new SmokeConnection(tcp, protocol);
            }
            catch
            {
                tcp.Dispose();
                throw;
            }
        }
    }

    /// <summary>An established client connection; Dispose closes TLS (close_notify) and the socket.</summary>
    public sealed class SmokeConnection : IDisposable
    {
        private readonly TcpClient _tcp;

        internal SmokeConnection(TcpClient tcp, TlsClientProtocol protocol)
        {
            _tcp = tcp;
            Protocol = protocol;
        }

        public TlsClientProtocol Protocol { get; }

        /// <summary>The application data stream.</summary>
        public Stream Stream => Protocol.Stream;

        public void Dispose()
        {
            try
            {
                Protocol.Close();
            }
            catch (IOException)
            {
                // The peer may already be gone; the socket is closed below either way.
            }
            _tcp.Dispose();
        }
    }
}
