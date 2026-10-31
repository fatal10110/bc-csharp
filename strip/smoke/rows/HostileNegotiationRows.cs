using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Turbo;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// #66: hostile negotiation rows. Each row pins a rejection the client already performs, so a later cut or
    /// bump cannot drop it silently: a CertificateVerify or ServerKeyExchange signed with a scheme the client did not
    /// offer, a ServerHello with a suite it did not offer (or one invalid for the version), x448/ffdhe2048 selected
    /// in a ServerKeyExchange, HelloRetryRequest or key share, an RSA-PSS key/scheme mismatch, an EC SPKI whose BIT
    /// STRING has pad bits, and low-order X25519 shares. Servers: BASE TlsServerProtocol where it will send the case
    /// (SmokeNegotiationServers), hand-built records where it will not. Control rows send the same raw flight with a
    /// valid value and require the client to get past the step the hostile row stops at.
    /// </summary>
    public sealed class HostileNegotiationRows : SmokeRowGroup
    {
        private const string InvalidSuite = "ServerHello selected invalid cipher suite";
        private const string InvalidKeyShare = "invalid key_share selected";

        private static readonly string[] Alpn = { "http/1.1" };

        public override string Name => "hostile-negotiation";

        public override void AddRows(SmokeRows rows)
        {
            // 1. TLS 1.3 CertificateVerify with a scheme the client did not offer (RFC 8446 4.4.3).
            AddSigning(rows, "cv-tls13-ed25519-0x0807-rejected", "ed25519", 0x0807, true);
            AddSigning(rows, "cv-tls13-ecdsa-sha1-0x0203-rejected", "p256", 0x0203, true);
            AddSigning(rows, "cv-tls13-rsa-pkcs1-sha1-0x0201-rejected", "rsa", 0x0201, true);

            // 2. TLS 1.2 ServerKeyExchange signed with sha1/sha224 (RFC 5246 7.4.1.4.1, 7.4.3).
            AddSigning(rows, "ske-tls12-ecdsa-sha1-0x0203-rejected", "p256", 0x0203, false);
            AddSigning(rows, "ske-tls12-ecdsa-sha224-0x0303-rejected", "p256", 0x0303, false);
            AddSigning(rows, "ske-tls12-rsa-sha1-0x0201-rejected", "rsa", 0x0201, false);
            AddSigning(rows, "ske-tls12-rsa-sha224-0x0301-rejected", "rsa", 0x0301, false);

            // 3. ServerHello with a suite the client did not offer, or one invalid for the version (RFC 8446 4.1.3,
            // RFC 5246 7.4.1.3): rejected before any E2 factory throw (internal_error) is reachable.
            AddTls12Suite(rows, "rsa-kx", 0x009C);
            AddTls12Suite(rows, "dhe", 0x009E);
            AddTls12Suite(rows, "dhe-chacha", 0xCCAA);
            AddTls12Suite(rows, "cbc", 0xC013);
            AddTls12Suite(rows, "cbc-sha256", 0xC027);
            AddTls12Suite(rows, "scsv", 0x00FF);
            AddTls12Suite(rows, "tls13-suite", SmokeNegotiationServers.TlsAes128GcmSha256);
            AddControl(rows, "serverhello-tls12-offered-suite-control", () =>
                SmokeNegotiationServers.StartTls12ServerHello(SmokeNegotiationServers.TlsEcdheEcdsaAes128GcmSha256),
                AlertDescription.unexpected_message);
            AddTls13Suite(rows, "rsa-kx", 0x009C);
            AddTls13Suite(rows, "cbc", 0xC013);
            AddTls13Suite(rows, "tls12-suite", SmokeNegotiationServers.TlsEcdheEcdsaAes128GcmSha256);

            // 4. Groups the client did not offer (RFC 8422 5.4, RFC 8446 4.1.4, 4.2.8; RFC 7919: ffdhe is DHE only).
            AddAlert(rows, "ske-tls12-group-x448-rejected", () => SmokeNegotiationServers.StartTls12KeyExchange(
                SmokeNegotiationServers.X448, new byte[56]), AlertDescription.illegal_parameter);
            AddAlert(rows, "ske-tls12-group-ffdhe2048-rejected", () => SmokeNegotiationServers.StartTls12KeyExchange(
                SmokeNegotiationServers.Ffdhe2048, new byte[255]), AlertDescription.illegal_parameter);
            AddAlert(rows, "hrr-group-x448-rejected",
                () => SmokeNegotiationServers.StartHelloRetryRequest(SmokeNegotiationServers.X448),
                AlertDescription.illegal_parameter, InvalidKeyShare);
            AddAlert(rows, "hrr-group-ffdhe2048-rejected",
                () => SmokeNegotiationServers.StartHelloRetryRequest(SmokeNegotiationServers.Ffdhe2048),
                AlertDescription.illegal_parameter, InvalidKeyShare);
            AddAlert(rows, "hrr-group-x25519-already-shared-rejected",
                () => SmokeNegotiationServers.StartHelloRetryRequest(SmokeNegotiationServers.X25519),
                AlertDescription.illegal_parameter, InvalidKeyShare);
            AddAlert(rows, "serverhello-tls13-keyshare-x448-rejected",
                () => SmokeNegotiationServers.StartTls13ServerHello(SmokeNegotiationServers.TlsAes128GcmSha256,
                    SmokeNegotiationServers.X448, new byte[56]),
                AlertDescription.illegal_parameter);
            AddControl(rows, "hrr-group-secp256r1-control",
                () => SmokeNegotiationServers.StartHelloRetryRequest(SmokeNegotiationServers.Secp256r1),
                AlertDescription.unexpected_message);

            // 5. RSA-PSS key/scheme mismatch (RFC 8446 4.2.3): the scheme is offered, the key type does not match it.
            AddAlert(rows, "pss-oid-leaf-rsae-tls13-rejected",
                () => SmokeNegotiationServers.StartPssMismatch(true, true), AlertDescription.certificate_unknown);
            AddAlert(rows, "pss-oid-leaf-rsae-tls12-rejected",
                () => SmokeNegotiationServers.StartPssMismatch(true, false), AlertDescription.certificate_unknown);
            AddAlert(rows, "rsaencryption-leaf-pss-pss-tls13-rejected",
                () => SmokeNegotiationServers.StartPssMismatch(false, true), AlertDescription.certificate_unknown);
            AddAlert(rows, "rsaencryption-leaf-pss-pss-tls12-rejected",
                () => SmokeNegotiationServers.StartPssMismatch(false, false), AlertDescription.certificate_unknown);

            // 6. EC SPKI with non-zero BIT STRING pad bits (RFC 5480 2.2): exactly ArgumentException (E5, E8).
            rows.Add("spki-ec-padbits-1-der-rejected", () => AssertPadBitsRejected(1, false));
            rows.Add("spki-ec-padbits-7-der-rejected", () => AssertPadBitsRejected(7, false));
            rows.Add("spki-ec-padbits-1-ber-rejected", () => AssertPadBitsRejected(1, true));
            rows.Add("spki-ec-padbits-1-tls13-rejected", () => AssertPadBitsRejectedOverTls(true));
            rows.Add("spki-ec-padbits-1-tls12-rejected", () => AssertPadBitsRejectedOverTls(false));

            // 7. Low-order X25519 shares (RFC 7748 6.1, RFC 8446 7.4.2): the all-zero secret aborts the handshake.
            AddLowOrder(rows, "zero", "0000000000000000000000000000000000000000000000000000000000000000", true);
            AddLowOrder(rows, "one", "0100000000000000000000000000000000000000000000000000000000000000", false);
            AddLowOrder(rows, "order8a", "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800", true);
            AddLowOrder(rows, "order8b", "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157", false);
            AddLowOrder(rows, "p-minus-1", "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false);
            AddLowOrder(rows, "p", "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false);
            AddLowOrder(rows, "p-plus-1", "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f", false);
            AddControl(rows, "x25519-valid-share-tls13-control",
                () => SmokeNegotiationServers.StartTls13ServerHello(SmokeNegotiationServers.TlsAes128GcmSha256,
                    SmokeNegotiationServers.X25519, SmokeNegotiationServers.ValidX25519Share()),
                AlertDescription.bad_record_mac);
            AddControl(rows, "x25519-valid-share-tls12-control",
                () => SmokeNegotiationServers.StartTls12KeyExchange(SmokeNegotiationServers.X25519,
                    SmokeNegotiationServers.ValidX25519Share()),
                AlertDescription.bad_record_mac);
        }

        /// <summary>A BASE server signing with <paramref name="scheme"/>, which the client did not offer: the
        /// offered-list check (TlsUtilities.VerifySupportedSignatureAlgorithm) runs before any verifier exists.
        /// </summary>
        private static void AddSigning(SmokeRows rows, string name, string keyKind, int scheme, bool tls13) =>
            AddAlert(rows, name, () => SmokeNegotiationServers.StartSigningWith(keyKind, scheme, tls13),
                AlertDescription.illegal_parameter);

        private static void AddTls12Suite(SmokeRows rows, string name, int suite) =>
            AddAlert(rows, "serverhello-tls12-" + name + "-0x" + suite.ToString("x4") + "-rejected",
                () => SmokeNegotiationServers.StartTls12ServerHello(suite), AlertDescription.illegal_parameter,
                InvalidSuite);

        private static void AddTls13Suite(SmokeRows rows, string name, int suite) =>
            AddAlert(rows, "serverhello-tls13-" + name + "-0x" + suite.ToString("x4") + "-rejected",
                () => SmokeNegotiationServers.StartTls13ServerHello(suite, SmokeNegotiationServers.X25519,
                    SmokeNegotiationServers.ValidX25519Share()), AlertDescription.illegal_parameter);

        private static void AddLowOrder(SmokeRows rows, string name, string hex, bool tls12Too)
        {
            byte[] share = SmokeHex.Decode(hex);
            AddAlert(rows, "x25519-low-order-" + name + "-tls13-rejected",
                () => SmokeNegotiationServers.StartTls13ServerHello(SmokeNegotiationServers.TlsAes128GcmSha256,
                    SmokeNegotiationServers.X25519, share), AlertDescription.handshake_failure);
            if (tls12Too)
            {
                AddAlert(rows, "x25519-low-order-" + name + "-tls12-rejected",
                    () => SmokeNegotiationServers.StartTls12KeyExchange(SmokeNegotiationServers.X25519, share),
                    AlertDescription.handshake_failure);
            }
        }

        /// <summary>The client must abort with <paramref name="expected"/> (and <paramref name="detail"/> in the
        /// message when given).</summary>
        private static void AddAlert(SmokeRows rows, string name, Func<SmokeServerHost> start, short expected,
            string detail = null) => rows.Add(name, () =>
        {
            Exception serverError;
            Exception clientError = Connect(start, out serverError);
            string context = "client: " + Describe(clientError) + "; server: " + Describe(serverError);
            var alert = clientError as TlsFatalAlert;
            SmokeAssert.True(alert != null, "TlsFatalAlert from the client, got " + context);
            SmokeAssert.Equal(AlertDescription.GetText(expected), AlertDescription.GetText(alert.AlertDescription),
                "alert (" + context + ")");
            if (detail != null)
            {
                SmokeAssert.True(alert.Message.Contains(detail, StringComparison.Ordinal),
                    "alert detail '" + detail + "' (" + context + ")");
            }
        }, 30000);

        /// <summary>The same raw flight with a valid value: the client must get past the step the hostile rows stop
        /// at and fail on the handler's tripwire with <paramref name="expected"/>, the handler finishing cleanly.
        /// This is what keeps a hostile row from passing on a stalled handshake.</summary>
        private static void AddControl(SmokeRows rows, string name, Func<SmokeServerHost> start, short expected) =>
            rows.Add(name, () =>
            {
                Exception serverError;
                Exception clientError = Connect(start, out serverError);
                string context = "client: " + Describe(clientError) + "; server: " + Describe(serverError);
                var alert = clientError as TlsFatalAlert;
                SmokeAssert.True(alert != null, "TlsFatalAlert from the client, got " + context);
                SmokeAssert.Equal(AlertDescription.GetText(expected), AlertDescription.GetText(alert.AlertDescription),
                    "tripwire alert (" + context + ")");
                SmokeAssert.True(serverError == null, "server handler finished (" + context + ")");
            }, 30000);

        private static Exception Connect(Func<SmokeServerHost> start, out Exception serverError)
        {
            using (SmokeServerHost host = start())
            {
                SmokeTlsClient client = SmokeClient.CreateClient("localhost", Alpn, SmokeTlsAuthentication.AcceptAny());
                Exception clientError = null;
                try
                {
                    SmokeClient.Connect(SmokeServerHost.Address, host.Port, client).Dispose();
                }
                catch (Exception e)
                {
                    clientError = e;
                }
                serverError = host.Join();
                SmokeAssert.True(clientError != null, "the handshake must fail; it completed as "
                    + client.NegotiatedVersion + " " + client.NegotiatedCipherSuite);
                return clientError;
            }
        }

        private static string Describe(Exception e) => e == null ? "none" : SmokeRunner.Describe(e);

        /// <summary>TurboKeyFactory.CreateKey and X509Certificate.GetPublicKey (twice: a rejection is not cached)
        /// must throw exactly ArgumentException.</summary>
        private static void AssertPadBitsRejected(int padBits, bool trailingBitsSet)
        {
            byte[] spki = SmokeNegotiationServers.PadBitsSpki(padBits, trailingBitsSet);
            AssertExactlyArgumentException(() => TurboKeyFactory.CreateKey(spki), "TurboKeyFactory.CreateKey");
            var cert = new X509Certificate(SmokeNegotiationServers.PadBitsCertificate(padBits, trailingBitsSet));
            for (int i = 0; i < 2; i++)
            {
                AssertExactlyArgumentException(() => cert.GetPublicKey(), "GetPublicKey, call " + (i + 1));
            }
        }

        private static void AssertExactlyArgumentException(Action body, string what)
        {
            ArgumentException e = SmokeAssert.Throws<ArgumentException>(body, what);
            SmokeAssert.Equal(typeof(ArgumentException).FullName, e.GetType().FullName, what + ": exception type");
        }

        /// <summary>The signer's real point behind one pad bit: the client must refuse the key with
        /// unsupported_certificate and TurboKeyFactory's ArgumentException in the cause chain.</summary>
        private static void AssertPadBitsRejectedOverTls(bool tls13)
        {
            Exception serverError;
            Exception clientError = Connect(() => SmokeNegotiationServers.StartPadBitsLeaf(tls13), out serverError);
            var alert = clientError as TlsFatalAlert;
            string context = "client: " + Describe(clientError) + "; server: " + Describe(serverError);
            SmokeAssert.True(alert != null, "TlsFatalAlert from the client, got " + context);
            SmokeAssert.Equal(AlertDescription.GetText(AlertDescription.unsupported_certificate),
                AlertDescription.GetText(alert.AlertDescription), "alert (" + context + ")");
            bool found = false;
            for (Exception x = alert; x != null && !found; x = x.InnerException)
            {
                found = x.GetType() == typeof(ArgumentException);
            }
            SmokeAssert.True(found, "TurboKeyFactory ArgumentException in the cause chain (" + context + ")");
        }
    }
}
