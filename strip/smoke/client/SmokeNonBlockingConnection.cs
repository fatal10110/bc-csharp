using System;
using System.IO;
using System.Net.Sockets;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// Drives <see cref="TlsClientProtocol"/> in non-blocking mode the way turboHTTP's BouncyCastleTlsStream does
    /// (strip/roots, #75): Connect queues the ClientHello, the socket's bytes go in with OfferInput, the engine's
    /// records come out with ReadOutput, application data moves through WriteApplicationData and ReadInput, and end
    /// of stream is CloseInput. The engine never touches the socket; the socket I/O here is blocking (the harness has
    /// no async need). A locally raised alert is flushed to the wire before the failure propagates (RFC 8446 6.2),
    /// as the consumer does.
    /// </summary>
    public sealed class SmokeNonBlockingConnection : IDisposable
    {
        /// <summary>One maximum TLS record (2^14 + 2048 + header), the consumer's staging size.</summary>
        private const int BufferSize = 16 * 1024 + 2048 + 5;

        private readonly TcpClient _tcp;
        private readonly Stream _net;
        private readonly byte[] _in = new byte[BufferSize];
        private readonly byte[] _out = new byte[BufferSize];

        private SmokeNonBlockingConnection(TcpClient tcp)
        {
            _tcp = tcp;
            _net = tcp.GetStream();
            Protocol = new TlsClientProtocol();
        }

        /// <summary>The engine, for state assertions (IsHandshaking, IsConnected, IsClosed, queue sizes).</summary>
        public TlsClientProtocol Protocol { get; }

        /// <summary>Connects over TCP and handshakes; the socket is closed again if the handshake throws.</summary>
        public static SmokeNonBlockingConnection Connect(string host, int port, SmokeTlsClient client,
            int receiveTimeoutMillis = SmokeClient.DefaultReceiveTimeoutMillis)
        {
            var tcp = new TcpClient();
            try
            {
                tcp.ReceiveTimeout = receiveTimeoutMillis;
                tcp.SendTimeout = receiveTimeoutMillis;
                tcp.Connect(host, port);
                var connection = new SmokeNonBlockingConnection(tcp);
                connection.Handshake(client);
                return connection;
            }
            catch
            {
                tcp.Dispose();
                throw;
            }
        }

        private void Handshake(TlsClient client)
        {
            Protocol.Connect(client); // queues the ClientHello; never blocks in this mode
            FlushOutput();
            while (Protocol.IsHandshaking)
            {
                Pump();
            }
            if (!Protocol.IsConnected)
            {
                throw new IOException("the handshake ended without a connection");
            }
        }

        /// <summary>One socket read into the engine, then every record the engine queued back to the socket; also
        /// when the input made the engine fail, so the alert it queued reaches the peer. End of stream during the
        /// handshake surfaces as the engine's TlsFatalAlert(handshake_failure) from CloseInput; the consumer throws its
        /// own IOException there instead.</summary>
        private void Pump()
        {
            int n = _net.Read(_in, 0, _in.Length);
            try
            {
                if (n <= 0)
                {
                    Protocol.CloseInput();
                }
                else
                {
                    Protocol.OfferInput(_in, 0, n);
                }
            }
            finally
            {
                try
                {
                    FlushOutput();
                }
                catch (Exception)
                {
                    // Best effort: the peer may already be gone; the engine's failure is what the caller needs.
                }
            }
        }

        private void FlushOutput()
        {
            int n;
            while ((n = Protocol.ReadOutput(_out, 0, _out.Length)) > 0)
            {
                _net.Write(_out, 0, n);
            }
        }

        public void Write(byte[] data)
        {
            Protocol.WriteApplicationData(data, 0, data.Length);
            FlushOutput();
        }

        /// <summary>Blocks until plaintext is available; 0 once the peer's close_notify was processed. Throws what
        /// the engine throws (TlsNoCloseNotifyException on a transport close without close_notify), and IOException
        /// on a connection the engine has failed, as the consumer does.</summary>
        public int Read(byte[] buffer, int offset, int count)
        {
            while (Protocol.GetAvailableInputBytes() == 0)
            {
                if (Protocol.IsClosed)
                {
                    if (Protocol.IsFailed)
                    {
                        throw new IOException("the TLS connection has failed");
                    }
                    return 0;
                }
                Pump();
            }
            return Protocol.ReadInput(buffer, offset, count);
        }

        /// <summary>Sends close_notify (if the engine is still open) and closes the socket.</summary>
        public void Dispose()
        {
            try
            {
                Protocol.Close();
                FlushOutput();
            }
            catch (IOException)
            {
                // The peer may already be gone; the socket is closed below either way.
            }
            _tcp.Dispose();
        }
    }
}
