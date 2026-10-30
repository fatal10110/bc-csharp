using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// A one-connection server on 127.0.0.1 (ephemeral port) running a handler on its own thread: a TLS server
    /// (<see cref="StartTls"/>) or raw bytes (<see cref="Start"/>, for trickle and malformed-record servers). No
    /// external network. Whatever the handler throws is kept for <see cref="Join"/>.
    /// </summary>
    public sealed class SmokeServerHost : IDisposable
    {
        public const string Address = "127.0.0.1";

        private readonly TcpListener _listener;
        private readonly Thread _thread;
        private Exception _error;

        private SmokeServerHost(Action<Stream> handler, int ioTimeoutMillis)
        {
            _listener = new TcpListener(IPAddress.Loopback, 0);
            _listener.Start(1);
            Port = ((IPEndPoint)_listener.LocalEndpoint).Port;
            _thread = new Thread(() =>
            {
                try
                {
                    using (TcpClient peer = _listener.AcceptTcpClient())
                    {
                        peer.ReceiveTimeout = ioTimeoutMillis;
                        peer.SendTimeout = ioTimeoutMillis;
                        handler(peer.GetStream());
                    }
                }
                catch (Exception e)
                {
                    _error = e;
                }
                finally
                {
                    _listener.Stop();
                }
            });
            _thread.IsBackground = true;
            _thread.Name = "smoke server";
            _thread.Start();
        }

        public int Port { get; }

        /// <summary>Accepts one connection and runs <paramref name="handler"/> on its stream (raw bytes).</summary>
        public static SmokeServerHost Start(Action<Stream> handler, int ioTimeoutMillis = 30000) =>
            new SmokeServerHost(handler ?? throw new ArgumentNullException(nameof(handler)), ioTimeoutMillis);

        /// <summary>Accepts one connection, runs the TLS handshake for <paramref name="server"/>, then
        /// <paramref name="afterHandshake"/> (default <see cref="EchoUntilClosed"/>).</summary>
        public static SmokeServerHost StartTls(TlsServer server, Action<TlsServerProtocol> afterHandshake = null,
            int ioTimeoutMillis = 30000)
        {
            if (server == null)
            {
                throw new ArgumentNullException(nameof(server));
            }
            Action<TlsServerProtocol> after = afterHandshake ?? EchoUntilClosed;
            return new SmokeServerHost(stream =>
            {
                var protocol = new TlsServerProtocol(stream);
                try
                {
                    protocol.Accept(server);
                    after(protocol);
                }
                finally
                {
                    protocol.Close();
                }
            }, ioTimeoutMillis);
        }

        /// <summary>Echoes application data until the client closes.</summary>
        public static void EchoUntilClosed(TlsServerProtocol protocol)
        {
            var buffer = new byte[4096];
            int n;
            while ((n = protocol.Stream.Read(buffer, 0, buffer.Length)) > 0)
            {
                protocol.Stream.Write(buffer, 0, n);
            }
        }

        /// <summary>Waits for the handler; returns what it threw (null if nothing). Throws TimeoutException if it
        /// is still running after <paramref name="timeoutMillis"/>.</summary>
        public Exception Join(int timeoutMillis = 30000)
        {
            if (!_thread.Join(timeoutMillis))
            {
                throw new TimeoutException("smoke server still running after " + timeoutMillis + " ms");
            }
            return _error;
        }

        public void Dispose()
        {
            _listener.Stop();
        }
    }
}
