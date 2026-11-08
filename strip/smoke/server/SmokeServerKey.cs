using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// A server credential for the custom test servers: certificate chain (DER, end-entity first), private key and
    /// the signature scheme the server signs with. Built with the upstream BASE library (server side, namespaces
    /// Org.BouncyCastle). The factories make a fresh self-signed certificate; hostile-certificate rows (#26) pass
    /// their own chain and key to the constructor.
    /// </summary>
    public sealed class SmokeServerKey
    {
        public SmokeServerKey(string kind, IList<byte[]> chainDer, AsymmetricKeyParameter privateKey,
            SignatureAndHashAlgorithm signatureAlgorithm, bool isEcdsa)
        {
            if (chainDer == null || chainDer.Count == 0)
            {
                throw new ArgumentException("empty certificate chain", nameof(chainDer));
            }
            Kind = kind;
            ChainDer = chainDer;
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            SignatureAlgorithm = signatureAlgorithm ?? throw new ArgumentNullException(nameof(signatureAlgorithm));
            IsEcdsa = isEcdsa;
        }

        public string Kind { get; }

        /// <summary>Certificate chain, DER, end-entity first.</summary>
        public IList<byte[]> ChainDer { get; }

        /// <summary>DER of the end-entity certificate (what <see cref="SmokeTlsAuthentication.Pinned"/> takes).
        /// </summary>
        public byte[] CertificateDer => ChainDer[0];

        public AsymmetricKeyParameter PrivateKey { get; }

        public SignatureAndHashAlgorithm SignatureAlgorithm { get; }

        /// <summary>ECDSA key (TLS 1.2 ECDHE_ECDSA suites) rather than RSA (ECDHE_RSA).</summary>
        public bool IsEcdsa { get; }

        /// <summary>Self-signed ECDSA certificate on a named curve (secp256r1, secp384r1, secp521r1).</summary>
        public static SmokeServerKey CreateEcdsa(string curveName, string subjectCn = "localhost")
        {
            DerObjectIdentifier oid;
            string sigAlg;
            short hash;
            switch (curveName)
            {
            case "secp256r1":
                oid = SecObjectIdentifiers.SecP256r1;
                sigAlg = "SHA256WITHECDSA";
                hash = HashAlgorithm.sha256;
                break;
            case "secp384r1":
                oid = SecObjectIdentifiers.SecP384r1;
                sigAlg = "SHA384WITHECDSA";
                hash = HashAlgorithm.sha384;
                break;
            case "secp521r1":
                oid = SecObjectIdentifiers.SecP521r1;
                sigAlg = "SHA512WITHECDSA";
                hash = HashAlgorithm.sha512;
                break;
            default:
                throw new ArgumentException("unsupported curve " + curveName, nameof(curveName));
            }
            var random = new SecureRandom();
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(oid, random));
            AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
            byte[] cert = SelfSign(pair, sigAlg, subjectCn, random);
            return new SmokeServerKey("ecdsa-" + curveName, new[] { cert }, pair.Private,
                SignatureAndHashAlgorithm.GetInstance(hash, Org.BouncyCastle.Tls.SignatureAlgorithm.ecdsa), true);
        }

        /// <summary>Self-signed RSA certificate; the server signs with rsa_pss_rsae_sha256 (TLS 1.3 and 1.2).
        /// </summary>
        public static SmokeServerKey CreateRsa(int bits = 2048, string subjectCn = "localhost")
        {
            var random = new SecureRandom();
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(65537), random, bits, 80));
            AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
            byte[] cert = SelfSign(pair, "SHA256WITHRSA", subjectCn, random);
            return new SmokeServerKey("rsa-" + bits, new[] { cert }, pair.Private,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256, false);
        }

        private static byte[] SelfSign(AsymmetricCipherKeyPair pair, string sigAlg, string subjectCn,
            SecureRandom random)
        {
            var name = new X509Name("CN=" + subjectCn);
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(new BigInteger(63, random).Add(BigInteger.One));
            gen.SetIssuerDN(name);
            gen.SetSubjectDN(name);
            gen.SetNotBefore(DateTime.UtcNow.AddHours(-1));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(pair.Public);
            gen.AddExtension(X509Extensions.SubjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.DnsName, subjectCn)));
            return gen.Generate(new Asn1SignatureFactory(sigAlg, pair.Private, random)).GetEncoded();
        }
    }
}
