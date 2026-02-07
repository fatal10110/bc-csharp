using System;
using System.IO;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.IO;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls
{
    /// <summary>(D)TLS SRP key exchange (RFC 5054).</summary>
    // TODO[api] Make sealed
    public class TlsSrpKeyExchange
        : AbstractTlsKeyExchange
    {
        private static int CheckKeyExchange(int keyExchange)
        {
            switch (keyExchange)
            {
            case KeyExchangeAlgorithm.SRP:
            case KeyExchangeAlgorithm.SRP_DSS:
            case KeyExchangeAlgorithm.SRP_RSA:
                return keyExchange;
            default:
                throw new ArgumentException("unsupported key exchange algorithm", "keyExchange");
            }
        }

        protected TlsSrpIdentity m_srpIdentity;
        protected TlsSrpConfigVerifier m_srpConfigVerifier;
        protected TlsCertificate m_serverCertificate = null;
        protected byte[] m_srpSalt = null;
        protected TlsSrp6Client m_srpClient = null;



        protected TlsCredentials m_serverCredentials = null;
        protected BigInteger m_srpPeerCredentials = null;

        public TlsSrpKeyExchange(int keyExchange, TlsSrpIdentity srpIdentity, TlsSrpConfigVerifier srpConfigVerifier)
            : base(CheckKeyExchange(keyExchange))
        {
            m_srpIdentity = srpIdentity;
            m_srpConfigVerifier = srpConfigVerifier;
        }



        public override void SkipServerCredentials()
        {
            if (m_keyExchange != KeyExchangeAlgorithm.SRP)
                throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public override void ProcessServerCredentials(TlsCredentials serverCredentials)
        {
            if (m_keyExchange == KeyExchangeAlgorithm.SRP)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_serverCredentials = TlsUtilities.RequireSignerCredentials(serverCredentials);
        }

        public override void ProcessServerCertificate(Certificate serverCertificate)
        {
            if (m_keyExchange == KeyExchangeAlgorithm.SRP)
                throw new TlsFatalAlert(AlertDescription.internal_error);

            m_serverCertificate = serverCertificate.GetCertificateAt(0);
        }

        public override bool RequiresServerKeyExchange => true;



        public override void ProcessServerKeyExchange(Stream input)
        {
            DigestInputBuffer digestBuffer = null;
            Stream teeIn = input;

            if (m_keyExchange != KeyExchangeAlgorithm.SRP)
            {
                digestBuffer = new DigestInputBuffer();
                teeIn = new TeeInputStream(input, digestBuffer);
            }

            ServerSrpParams srpParams = ServerSrpParams.Parse(teeIn);

            if (digestBuffer != null)
            {
                TlsUtilities.VerifyServerKeyExchangeSignature(m_context, input, m_serverCertificate, null,
                    digestBuffer);
            }

            TlsSrpConfig config = new TlsSrpConfig();
            config.SetExplicitNG(new BigInteger[]{ srpParams.N, srpParams.G });

            if (!m_srpConfigVerifier.Accept(config))
                throw new TlsFatalAlert(AlertDescription.insufficient_security);

            m_srpSalt = srpParams.S;

            /*
             * RFC 5054 2.5.3: The client MUST abort the handshake with an "illegal_parameter" alert if
             * B % N = 0.
             */
            m_srpPeerCredentials = ValidatePublicValue(srpParams.N, srpParams.B);
            m_srpClient = m_context.Crypto.CreateSrp6Client(config);
        }

        public override void ProcessClientCredentials(TlsCredentials clientCredentials) =>
            throw new TlsFatalAlert(AlertDescription.internal_error);

        public override void GenerateClientKeyExchange(Stream output)
        {
            byte[] identity = m_srpIdentity.GetSrpIdentity();
            byte[] password = m_srpIdentity.GetSrpPassword();

            BigInteger A = m_srpClient.GenerateClientCredentials(m_srpSalt, identity, password);
            TlsSrpUtilities.WriteSrpParameter(A, output);

            m_context.SecurityParameters.m_srpIdentity = Arrays.Clone(identity);
        }



        public override TlsSecret GeneratePreMasterSecret()
        {
            BigInteger S = m_srpClient.CalculateSecret(m_srpPeerCredentials);

            // TODO Check if this needs to be a fixed size
            return m_context.Crypto.CreateSecret(BigIntegers.AsUnsignedByteArray(S));
        }

        protected static BigInteger ValidatePublicValue(BigInteger N, BigInteger val)
        {
            val = val.Mod(N);

            // Check that val % N != 0
            if (val.Equals(BigInteger.Zero))
                throw new TlsFatalAlert(AlertDescription.illegal_parameter);

            return val;
        }
    }
}
