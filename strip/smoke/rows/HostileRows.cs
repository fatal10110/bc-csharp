using System;
using System.Diagnostics;
using System.Runtime.ExceptionServices;
using System.Threading;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// #26: hostile inputs (STRIP_PLAN_V2.md section 5 step 5). Every row body runs on a worker thread with a
    /// 256 KB stack, so unbounded recursion would overflow there instead of passing on a default 8 MB stack.
    /// ASN.1 depth: the deepest SEQUENCE nesting that fits the client's 32 KB handshake-message cap, sent as the
    /// server certificate over TLS 1.3 and 1.2, and more than 16K levels fed straight to Asn1InputStream, must hit
    /// the depth limit. Keys (E5 TurboKeyFactory, E7, E8): an 8192-bit RSA key is accepted in under 50 ms;
    /// 8193-bit and 1024-bit moduli, a 65-bit or larger public exponent and explicit EC parameters are rejected
    /// via X509Certificate.GetPublicKey (exactly ArgumentException) and via TLS (unsupported_certificate);
    /// e = 3 and e = 65537 are accepted. Hostile certificates come from SmokeHostileTlsServer (BASE), which
    /// OpenSSL cannot be made to send.
    /// </summary>
    public sealed partial class HostileRows : SmokeRowGroup
    {
        /// <summary>Worker-thread stack for every row (plan section 5 step 5).</summary>
        public const int StackBytes = 256 * 1024;

        /// <summary>The client's handshake-message cap (AbstractTlsPeer.GetMaxHandshakeMessageSize default; the
        /// smoke client keeps it).</summary>
        private const int MaxHandshakeMessage = 32768;

        private const string DepthMessage = "maximum nested construction level reached";

        private const string E65537 = "010001";
        private const string E3 = "03";

        /// <summary>2^64 + 1: 65 bits, odd.</summary>
        private const string E65Bits = "010000000000000001";

        /// <summary>2^64 - 1: the largest accepted exponent (64 bits).</summary>
        private const string E64Bits = "ffffffffffffffff";

        private static readonly string[] Alpn = { "http/1.1" };

        private static readonly Lazy<SmokeServerKey> RsaSigner =
            new Lazy<SmokeServerKey>(() => SmokeHostileCertificates.CreateRsa(2048, 65537));

        private static readonly Lazy<SmokeServerKey> RsaE3 =
            new Lazy<SmokeServerKey>(() => SmokeHostileCertificates.CreateRsa(2048, 3));

        private static readonly Lazy<SmokeServerKey> Rsa1024 =
            new Lazy<SmokeServerKey>(() => SmokeHostileCertificates.CreateRsa(1024, 65537));

        private static readonly Lazy<SmokeServerKey> P256 =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp256r1"));

        public override string Name => "hostile";

        public override void AddRows(SmokeRows rows)
        {
            // --- ASN.1 depth ---
            Add(rows, "asn1-depth-16k-definite",
                () => AssertDepthLimit(SmokeHostileCertificates.NestedSequences(16385)));
            Add(rows, "asn1-depth-16k-indefinite",
                () => AssertDepthLimit(SmokeHostileCertificates.NestedSequencesIndefinite(16385)));
            Add(rows, "asn1-depth-tls13-certificate-32k",
                () => AssertDeepCertificateRejected(SmokeHostileCertificates.Tls13CertificateOverhead, true));
            Add(rows, "asn1-depth-tls12-certificate-32k",
                () => AssertDeepCertificateRejected(SmokeHostileCertificates.Tls12CertificateOverhead, false));

            // --- RSA accepted ---
            Add(rows, "rsa-8192-accepted-under-50ms", Rsa8192AcceptedFast);
            Add(rows, "rsa-8192-e3-getpublickey-accepted", () => AssertRsaAccepted(8192, E3));
            Add(rows, "rsa-8192-e64bit-getpublickey-accepted", () => AssertRsaAccepted(8192, E64Bits));
            Add(rows, "rsa-e3-tls13-accepted", () => AssertHandshake(RsaE3.Value, true));
            Add(rows, "rsa-e3-tls12-accepted", () => AssertHandshake(RsaE3.Value, false));
            Add(rows, "rsa-e65537-tls13-accepted", () => AssertHandshake(RsaSigner.Value, true));
            Add(rows, "rsa-e65537-tls12-accepted", () => AssertHandshake(RsaSigner.Value, false));

            // --- RSA rejected: modulus size ---
            Add(rows, "rsa-8193-getpublickey-rejected",
                () => AssertGetPublicKeyRejected(RsaCert(8193, E65537)));
            Add(rows, "rsa-8193-tls13-rejected",
                () => AssertKeyRejectedOverTls(RsaSigner.Value, RsaCert(8193, E65537), true));
            Add(rows, "rsa-8193-tls12-rejected",
                () => AssertKeyRejectedOverTls(RsaSigner.Value, RsaCert(8193, E65537), false));
            Add(rows, "rsa-1024-getpublickey-rejected", () => AssertGetPublicKeyRejected(Rsa1024.Value.CertificateDer));
            // A real 1024-bit key signs: accepting it would complete the handshake.
            Add(rows, "rsa-1024-tls13-rejected",
                () => AssertKeyRejectedOverTls(Rsa1024.Value, Rsa1024.Value.CertificateDer, true));
            Add(rows, "rsa-1024-tls12-rejected",
                () => AssertKeyRejectedOverTls(Rsa1024.Value, Rsa1024.Value.CertificateDer, false));

            // --- RSA rejected: public exponent ---
            Add(rows, "rsa-8192-e65bit-getpublickey-rejected", () =>
            {
                AssertGetPublicKeyRejected(RsaCert(8192, E65Bits));
                // e about as large as n (8191 bits).
                AssertGetPublicKeyRejected(RsaCert(8192, "7" + new string('f', 2047)));
            });
            Add(rows, "rsa-8192-e65bit-tls13-rejected",
                () => AssertKeyRejectedOverTls(RsaSigner.Value, RsaCert(8192, E65Bits), true));
            Add(rows, "rsa-8192-e65bit-tls12-rejected",
                () => AssertKeyRejectedOverTls(RsaSigner.Value, RsaCert(8192, E65Bits), false));

            // --- explicit EC parameters ---
            Add(rows, "ec-explicit-params-getpublickey-rejected",
                () => AssertGetPublicKeyRejected(ExplicitP256Cert()));
            Add(rows, "ec-explicit-params-tls13-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, ExplicitP256Cert(), true));
            Add(rows, "ec-explicit-params-tls12-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, ExplicitP256Cert(), false));

            // --- E5 key table (HostileKeyRows.cs) ---
            AddKeyRows(rows);
        }

        private static byte[] RsaCert(int modulusBits, string exponentHex) =>
            SmokeHostileCertificates.RsaCertificate(modulusBits, exponentHex);

        /// <summary>The signer's real P-256 point with explicit curve parameters: accepting it would complete the
        /// handshake.</summary>
        private static byte[] ExplicitP256Cert() =>
            SmokeHostileCertificates.ExplicitP256Certificate(P256.Value.CertificateDer);

        /// <summary>Registers <paramref name="body"/> to run on a <see cref="StackBytes"/> worker thread.</summary>
        private static void Add(SmokeRows rows, string name, Action body) => rows.Add(name, () => OnSmallStack(body));

        /// <summary>Runs <paramref name="body"/> on a new thread with a 256 KB stack, waits, rethrows what it threw.
        /// The runner's per-row timeout still applies (it abandons the calling thread).</summary>
        private static void OnSmallStack(Action body)
        {
            Exception error = null;
            var thread = new Thread(() =>
            {
                try
                {
                    body();
                }
                catch (Exception e)
                {
                    error = e;
                }
            }, StackBytes);
            thread.IsBackground = true;
            thread.Name = "smoke hostile (256 KB stack)";
            thread.Start();
            thread.Join();
            if (error != null)
            {
                ExceptionDispatchInfo.Capture(error).Throw();
            }
        }

        private static void AssertDepthLimit(byte[] encoding)
        {
            Asn1Exception e = SmokeAssert.Throws<Asn1Exception>(() =>
            {
                using (var input = new Asn1InputStream(encoding))
                {
                    input.ReadObject();
                }
            }, "Asn1InputStream on " + encoding.Length + " bytes of nesting");
            SmokeAssert.Equal(DepthMessage, e.Message, "Asn1InputStream depth exception");
        }

        /// <summary>The deepest nesting whose Certificate handshake body still fits the 32 KB cap: the client
        /// must reach the parser (bad_certificate, not the size cap's internal_error) and stop at the depth limit.
        /// </summary>
        private static void AssertDeepCertificateRejected(int overhead, bool tls13)
        {
            int depth = SmokeHostileCertificates.DeepestNestingFitting(MaxHandshakeMessage - overhead);
            byte[] nesting = SmokeHostileCertificates.NestedSequences(depth);
            SmokeAssert.True(nesting.Length + overhead <= MaxHandshakeMessage,
                "Certificate body " + (nesting.Length + overhead) + " fits " + MaxHandshakeMessage);
            SmokeAssert.True(SmokeHostileCertificates.NestedSequencesLength(depth + 1) + overhead > MaxHandshakeMessage,
                "one more level would not fit");
            SmokeAssert.True(depth > 8000, "nesting depth " + depth);
            TlsFatalAlert alert = ConnectExpectingAlert(new SmokeHostileTlsServer(RsaSigner.Value, nesting, tls13));
            SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.bad_certificate),
                AlertDescription.GetText(alert.AlertDescription), "alert for " + depth + " nested levels");
            Exception cause = FindCause(alert, x => x is Asn1Exception && x.Message == DepthMessage);
            SmokeAssert.True(cause != null, "depth exception in the cause chain, got " + SmokeRunner.Describe(alert));
        }

        private static void Rsa8192AcceptedFast()
        {
            byte[] der = SmokeHostileCertificates.RsaCertificate(8192, E65537);
            // Warm-up outside the measurement: JIT and first-call costs (another modulus, same code paths).
            AssertRsaKey(new X509Certificate(SmokeHostileCertificates.RsaCertificate(8192, E65537, seed: 2))
                .GetPublicKey(), 8192, E65537);
            const int bound = 50;
            long best = long.MaxValue;
            for (int i = 0; i < 5 && best >= bound; i++)
            {
                var watch = Stopwatch.StartNew();
                var key = new X509Certificate(der).GetPublicKey();
                watch.Stop();
                AssertRsaKey(key, 8192, E65537);
                best = Math.Min(best, watch.ElapsedMilliseconds);
            }
            SmokeAssert.True(best < bound,
                "fastest 8192-bit certificate parse + GetPublicKey: " + best + " ms (bound " + bound + " ms)");
        }

        private static void AssertRsaAccepted(int modulusBits, string exponentHex)
        {
            byte[] der = SmokeHostileCertificates.RsaCertificate(modulusBits, exponentHex);
            AssertRsaKey(new X509Certificate(der).GetPublicKey(), modulusBits, exponentHex);
        }

        private static void AssertRsaKey(object key, int modulusBits, string exponentHex)
        {
            var rsa = key as RsaKeyParameters;
            SmokeAssert.True(rsa != null && !rsa.IsPrivate, "RSA public key, got " + key?.GetType().Name);
            SmokeAssert.Equal(modulusBits, rsa.Modulus.BitLength, "modulus bits");
            SmokeAssert.True(rsa.Exponent.Equals(new BigInteger(exponentHex, 16)), "exponent " + exponentHex);
        }

        /// <summary>E8: GetPublicKey goes through TurboKeyFactory, whose rejection is exactly ArgumentException,
        /// and a rejection is not cached as a success.</summary>
        private static void AssertGetPublicKeyRejected(byte[] der)
        {
            var cert = new X509Certificate(der);
            for (int i = 0; i < 2; i++)
            {
                ArgumentException e = SmokeAssert.Throws<ArgumentException>(() => cert.GetPublicKey(),
                    "GetPublicKey, call " + (i + 1));
                SmokeAssert.Equal(typeof(ArgumentException).FullName, e.GetType().FullName, "exception type");
            }
        }

        /// <summary>The client must refuse the key with unsupported_certificate (BcTlsRawKeyCertificate wraps
        /// TurboKeyFactory's ArgumentException), before any signature with it is checked.</summary>
        private static void AssertKeyRejectedOverTls(SmokeServerKey signer, byte[] leafOnWire, bool tls13)
        {
            TlsFatalAlert alert = ConnectExpectingAlert(new SmokeHostileTlsServer(signer, leafOnWire, tls13));
            SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.unsupported_certificate),
                AlertDescription.GetText(alert.AlertDescription), "alert (" + SmokeRunner.Describe(alert) + ")");
            Exception cause = FindCause(alert, x => x.GetType() == typeof(ArgumentException));
            SmokeAssert.True(cause != null,
                "TurboKeyFactory ArgumentException in the cause chain, got " + SmokeRunner.Describe(alert));
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

        private static TlsFatalAlert ConnectExpectingAlert(SmokeHostileTlsServer server)
        {
            using (SmokeServerHost host = SmokeServerHost.StartTls(server))
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn, SmokeTlsAuthentication.AcceptAny());
                TlsFatalAlert alert = SmokeAssert.Throws<TlsFatalAlert>(
                    () => SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose(),
                    "handshake with a hostile certificate");
                // The server only sees the client's alert; its outcome is not part of the row.
                host.Join();
                return alert;
            }
        }

        private static Exception FindCause(Exception e, Func<Exception, bool> match)
        {
            for (Exception x = e; x != null; x = x.InnerException)
            {
                if (match(x))
                {
                    return x;
                }
            }
            return null;
        }
    }
}
