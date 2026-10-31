using System;
using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
using System.Threading;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #27: handshake timeout behaviour (plan section 5 step 5 "Timeout"; upstream ab4eb3d2, in BASE). The client
    /// checks its handshake timeout only between records (TlsProtocol.BlockForHandshake, CheckHandshakeTimeout), so:
    /// a trickle server (one accepted handshake record every few seconds) is aborted by the handshake timeout, with
    /// TlsTimeoutException "Handshake timed out", at the first record after it expires: about 30 s with the harness
    /// default (slow row: run.sh --slow, strip.sh --smoke-slow) and 2 s in the variant every run has. A silent peer
    /// sends no record, so the handshake timeout never gets checked and only the socket ReceiveTimeout the harness
    /// sets aborts it (turboHTTP must set it too: turboHTTP#142). The servers are raw-byte handlers: no TLS server
    /// produces these cases.
    /// </summary>
    public sealed class TimeoutRows : SmokeRowGroup
    {
        // How late after the expected abort a row still passes (a loaded machine, thread start-up).
        private const int SlackMillis = 5000;

        // Lower-bound tolerance: the library measures wall-clock time, the row a Stopwatch.
        private const int EarlyMillis = 100;

        private const int SilentReceiveTimeoutMillis = 1500;

        public override string Name => "timeout";
        public override int Order => 120;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("trickle-handshake-timeout-2s", () => Trickle(2000, 500), 20000);
            rows.Add("silent-peer-receive-timeout", SilentPeer, 20000);
            rows.AddSlow("trickle-handshake-timeout-30s",
                () => Trickle(SmokeTlsClient.DefaultHandshakeTimeoutMillis, 3000), 90000);
        }

        /// <summary>The server sends a ServerHello one byte per handshake record, a record every
        /// <paramref name="intervalMillis"/>; the client must abort with TlsTimeoutException at the first record
        /// boundary after <paramref name="handshakeTimeoutMillis"/>.</summary>
        private static void Trickle(int handshakeTimeoutMillis, int intervalMillis)
        {
            int sent = 0;
            using (var stop = new ManualResetEventSlim(false))
            using (SmokeServerHost host = SmokeServerHost.Start(stream =>
            {
                // The header promises 256 body bytes: the client queues every 1-byte fragment
                // (TlsProtocol.ProcessHandshakeQueue: recognized type, length under the maximum) and never gets the
                // whole message, so each record is accepted and only the timeout can end the handshake.
                var message = new byte[4 + 256];
                message[0] = 2; // server_hello
                message[2] = 1; // uint24 length 0x000100
                for (int i = 0; i < message.Length && !stop.Wait(intervalMillis); i++)
                {
                    // TLSPlaintext: handshake(22), legacy_record_version 0x0303, length 1, one fragment byte.
                    byte[] record = { 22, 3, 3, 0, 1, message[i] };
                    try
                    {
                        stream.Write(record, 0, record.Length);
                    }
                    catch (IOException)
                    {
                        return; // the client has gone
                    }
                    Interlocked.Increment(ref sent);
                }
            }))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", new[] { "http/1.1" },
                    SmokeTlsAuthentication.AcceptAny());
                client.HandshakeTimeoutMillis = handshakeTimeoutMillis;
                var watch = Stopwatch.StartNew();
                Exception e = SmokeAssert.Throws<Exception>(
                    () => SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose(),
                    "handshake with a trickle server");
                long elapsed = watch.ElapsedMilliseconds;
                stop.Set();
                Exception serverError = host.Join();

                SmokeAssert.True(e is TlsTimeoutException && e.Message == "Handshake timed out",
                    "expected TlsTimeoutException: Handshake timed out, got " + SmokeRunner.Describe(e));
                SmokeAssert.True(elapsed >= handshakeTimeoutMillis - EarlyMillis
                    && elapsed <= handshakeTimeoutMillis + intervalMillis + SlackMillis,
                    "aborted after " + elapsed + " ms, expected " + handshakeTimeoutMillis + ".."
                    + (handshakeTimeoutMillis + intervalMillis) + " ms");
                int records = Volatile.Read(ref sent);
                SmokeAssert.True(records >= handshakeTimeoutMillis / intervalMillis - 1,
                    "the server sent only " + records + " records before the abort");
                SmokeAssert.True(serverError == null, "server failed: "
                    + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
            }
        }

        /// <summary>The server reads nothing and sends nothing. A 500 ms handshake timeout cannot fire inside the
        /// blocked record read; the 1500 ms socket ReceiveTimeout ends the handshake with the transport's
        /// IOException (SocketError.TimedOut), not TlsTimeoutException.</summary>
        private static void SilentPeer()
        {
            using (var stop = new ManualResetEventSlim(false))
            using (SmokeServerHost host = SmokeServerHost.Start(stream => stop.Wait(30000)))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", new[] { "http/1.1" },
                    SmokeTlsAuthentication.AcceptAny());
                client.HandshakeTimeoutMillis = 500;
                var watch = Stopwatch.StartNew();
                Exception e = SmokeAssert.Throws<Exception>(
                    () => SmokeClient.Connect(SmokeServerHost.Address, host.Port, client, SilentReceiveTimeoutMillis)
                        .Dispose(),
                    "handshake with a silent peer");
                long elapsed = watch.ElapsedMilliseconds;
                stop.Set();
                Exception serverError = host.Join();

                SocketException socket = null;
                for (Exception x = e; x != null && socket == null; x = x.InnerException)
                {
                    socket = x as SocketException;
                }
                SmokeAssert.True(e is IOException && !(e is TlsTimeoutException) && socket != null
                    && socket.SocketErrorCode == SocketError.TimedOut,
                    "expected the socket receive timeout (IOException -> SocketException TimedOut), got "
                    + SmokeRunner.Describe(e));
                SmokeAssert.True(elapsed >= SilentReceiveTimeoutMillis - EarlyMillis
                    && elapsed <= SilentReceiveTimeoutMillis + SlackMillis,
                    "aborted after " + elapsed + " ms, expected about " + SilentReceiveTimeoutMillis + " ms");
                SmokeAssert.True(serverError == null, "server failed: "
                    + (serverError == null ? "" : SmokeRunner.Describe(serverError)));
            }
        }
    }
}
