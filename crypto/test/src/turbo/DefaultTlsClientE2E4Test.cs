// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cuts E2-E4 (STRIP_PLAN_V2.md §3 E2-E4, §5 step 5) until the smoke suite exists.

using System;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class DefaultTlsClientE2E4Test
    {
        // STRIP_PLAN_V2.md §3 E3 in plan order, then the RFC 5746 SCSV (§5 step 5).
        private static readonly int[] ExpectedOfferedSuites =
        {
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            CipherSuite.TLS_EMPTY_RENEGOTIATION_INFO_SCSV,
        };

        private static readonly int[] ExpectedGroups =
        {
            NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1,
        };

        private sealed class E2E4Client
            : DefaultTlsClient
        {
            internal E2E4Client(TlsCrypto crypto)
                : base(crypto)
            {
            }

            public override TlsAuthentication GetAuthentication() => throw new NotSupportedException();
        }

        private static ClientHello CaptureClientHello()
        {
            TlsClientProtocol protocol = new TlsClientProtocol();
            protocol.Connect(new E2E4Client(new BcTlsCrypto()));

            byte[] output = new byte[protocol.GetAvailableOutputBytes()];
            protocol.ReadOutput(output, 0, output.Length);

            // One handshake record: record header (5), handshake header (4), ClientHello body.
            Assert.AreEqual(ContentType.handshake, output[0]);
            Assert.AreEqual(HandshakeType.client_hello, output[5]);
            int bodyLength = (output[6] << 16) | (output[7] << 8) | output[8];
            byte[] body = Arrays.CopyOfRange(output, 9, 9 + bodyLength);

            return ClientHello.Parse(new MemoryStream(body, false), null);
        }

        private static void AssertInternalError(TestDelegate code, string name)
        {
            TlsFatalAlert alert = Assert.Throws<TlsFatalAlert>(code, name);
            Assert.AreEqual(AlertDescription.internal_error, alert.AlertDescription, name);
        }

        [Test]
        public void ClientHelloCipherSuites()
        {
            CollectionAssert.AreEqual(ExpectedOfferedSuites, CaptureClientHello().CipherSuites);
        }

        [Test]
        public void ClientHelloSupportedGroups()
        {
            int[] groups = TlsExtensionsUtilities.GetSupportedGroupsExtension(CaptureClientHello().Extensions);
            CollectionAssert.AreEqual(ExpectedGroups, groups);
        }

        [Test]
        public void ClientHelloNoStatusRequest()
        {
            var extensions = CaptureClientHello().Extensions;
            Assert.IsFalse(TlsUtilities.HasExtension(extensions, ExtensionType.status_request));
            Assert.IsFalse(TlsUtilities.HasExtension(extensions, ExtensionType.status_request_v2));
        }

        [Test]
        public void ClientVerifiersAreNull()
        {
            E2E4Client client = new E2E4Client(new BcTlsCrypto());
            Assert.IsNull(client.GetDHGroupVerifier());
            Assert.IsNull(client.GetSrpConfigVerifier());
        }

        [Test]
        public void KeyExchangeFactoryDeniesNonEcdhe()
        {
            DefaultTlsKeyExchangeFactory f = new DefaultTlsKeyExchangeFactory();

            AssertInternalError(() => f.CreateDHKeyExchange(KeyExchangeAlgorithm.DH_RSA), "DH");
            AssertInternalError(() => f.CreateDHanonKeyExchangeClient(KeyExchangeAlgorithm.DH_anon, null),
                "DHanon client");
            AssertInternalError(() => f.CreateDHanonKeyExchangeServer(KeyExchangeAlgorithm.DH_anon, null),
                "DHanon server");
            AssertInternalError(() => f.CreateDheKeyExchangeClient(KeyExchangeAlgorithm.DHE_RSA, null), "DHE client");
            AssertInternalError(() => f.CreateDheKeyExchangeServer(KeyExchangeAlgorithm.DHE_RSA, null), "DHE server");
            AssertInternalError(() => f.CreateECDHKeyExchange(KeyExchangeAlgorithm.ECDH_RSA), "static ECDH");
            AssertInternalError(() => f.CreateECDHanonKeyExchangeClient(KeyExchangeAlgorithm.ECDH_anon),
                "ECDHanon client");
            AssertInternalError(() => f.CreateECDHanonKeyExchangeServer(KeyExchangeAlgorithm.ECDH_anon, null),
                "ECDHanon server");
            AssertInternalError(() => f.CreatePskKeyExchangeClient(KeyExchangeAlgorithm.PSK, null, null),
                "PSK client");
            AssertInternalError(() => f.CreatePskKeyExchangeServer(KeyExchangeAlgorithm.PSK, null, null, null),
                "PSK server");
            AssertInternalError(() => f.CreateRsaKeyExchange(KeyExchangeAlgorithm.RSA), "RSA");
            AssertInternalError(() => f.CreateSrpKeyExchangeClient(KeyExchangeAlgorithm.SRP, null, null),
                "SRP client");
            AssertInternalError(() => f.CreateSrpKeyExchangeServer(KeyExchangeAlgorithm.SRP, null), "SRP server");
        }

        [Test]
        public void KeyExchangeFactoryKeepsEcdhe()
        {
            DefaultTlsKeyExchangeFactory f = new DefaultTlsKeyExchangeFactory();

            Assert.IsNotNull(f.CreateECDheKeyExchangeClient(KeyExchangeAlgorithm.ECDHE_RSA));
            Assert.IsNotNull(f.CreateECDheKeyExchangeClient(KeyExchangeAlgorithm.ECDHE_ECDSA));
            Assert.IsNotNull(f.CreateECDheKeyExchangeServer(KeyExchangeAlgorithm.ECDHE_RSA, null));
        }
    }
}
