using System.Collections.Generic;
using System.Text;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace TurboSmoke
{
    /// <summary>
    /// Custom test server on the upstream BASE library (TlsServerProtocol), for cases OpenSSL cannot produce
    /// (#26 hostile certificates, #27 trickle): subclass it, or replace the knobs before the handshake. Defaults:
    /// TLS 1.3 + 1.2, the strip's AEAD suites for the key type, ALPN h2 then http/1.1, the given credential.
    /// </summary>
    public class SmokeTlsServer : DefaultTlsServer
    {
        private static readonly int[] Tls13Suites =
        {
            CipherSuite.TLS_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_AES_128_GCM_SHA256,
            CipherSuite.TLS_AES_256_GCM_SHA384,
        };

        private static readonly int[] EcdsaSuites =
        {
            CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        };

        private static readonly int[] RsaSuites =
        {
            CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        };

        /// <summary>For <see cref="Versions"/>: TLS 1.2 only.</summary>
        public static readonly ProtocolVersion[] Tls12Only = { ProtocolVersion.TLSv12 };

        /// <summary>For <see cref="Versions"/>: TLS 1.3 only.</summary>
        public static readonly ProtocolVersion[] Tls13Only = { ProtocolVersion.TLSv13 };

        public SmokeTlsServer(SmokeServerKey key)
            : base(new BcTlsCrypto(new SecureRandom()))
        {
            Key = key;
        }

        public SmokeServerKey Key { get; set; }

        public ProtocolVersion[] Versions { get; set; } = { ProtocolVersion.TLSv13, ProtocolVersion.TLSv12 };

        /// <summary>Server ALPN preference; null sends no ALPN.</summary>
        public IList<ProtocolName> Alpn { get; set; } =
            new List<ProtocolName> { ProtocolName.Http_2_Tls, ProtocolName.Http_1_1 };

        /// <summary>The SNI host name the client sent, null if none.</summary>
        public string ReceivedServerName { get; private set; }

        protected override ProtocolVersion[] GetSupportedVersions() => Versions;

        protected override IList<ProtocolName> GetProtocolNames() => Alpn;

        protected override int[] GetSupportedCipherSuites()
        {
            var suites = new List<int>(Tls13Suites);
            suites.AddRange(Key.IsEcdsa ? EcdsaSuites : RsaSuites);
            return TlsUtilities.GetSupportedCipherSuites(Crypto, suites.ToArray());
        }

        public override void ProcessClientExtensions(IDictionary<int, byte[]> clientExtensions)
        {
            base.ProcessClientExtensions(clientExtensions);
            IList<ServerName> names = TlsExtensionsUtilities.GetServerNameExtensionClient(clientExtensions);
            if (names != null && names.Count > 0)
            {
                ReceivedServerName = Encoding.UTF8.GetString(names[0].NameData);
            }
        }

        /// <summary>The signer credential for <see cref="Key"/>, for TLS 1.3 and 1.2 alike (the suites match the
        /// key type).</summary>
        public override TlsCredentials GetCredentials()
        {
            TlsCrypto crypto = m_context.Crypto;
            Certificate certificate;
            if (TlsUtilities.IsTlsV13(m_context))
            {
                var entries = new CertificateEntry[Key.ChainDer.Count];
                for (int i = 0; i < entries.Length; i++)
                {
                    entries[i] = new CertificateEntry(crypto.CreateCertificate(Key.ChainDer[i]), null);
                }
                certificate = new Certificate(TlsUtilities.EmptyBytes, entries);
            }
            else
            {
                var certs = new TlsCertificate[Key.ChainDer.Count];
                for (int i = 0; i < certs.Length; i++)
                {
                    certs[i] = crypto.CreateCertificate(Key.ChainDer[i]);
                }
                certificate = new Certificate(certs);
            }
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), (BcTlsCrypto)crypto,
                Key.PrivateKey, certificate, Key.SignatureAlgorithm);
        }
    }
}
