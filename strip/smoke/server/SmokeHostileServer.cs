using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// #26: hostile certificate encodings, built with the upstream BASE library (server side). Keys the strip must
    /// reject are hand-built as SubjectPublicKeyInfo inside a TBSCertificate with a garbage signature: BASE never
    /// builds them as key objects (its RsaKeyParameters would run Miller-Rabin on an 8192-bit modulus, or refuse
    /// the key), and the client never verifies certificate signatures (decision A). Everything leaves here as bytes.
    /// </summary>
    public static class SmokeHostileCertificates
    {
        /// <summary>Overhead of a TLS 1.3 Certificate handshake body around one certificate: request context
        /// length (1), certificate_list length (3), cert_data length (3), extensions length (2); RFC 8446 4.4.2.
        /// </summary>
        public const int Tls13CertificateOverhead = 1 + 3 + 3 + 2;

        /// <summary>Overhead of a TLS 1.2 Certificate handshake body around one certificate: certificate_list
        /// length (3), ASN.1Cert length (3); RFC 5246 7.4.2.</summary>
        public const int Tls12CertificateOverhead = 3 + 3;

        private static readonly AlgorithmIdentifier Sha256WithRsa =
            new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance);

        private static readonly AlgorithmIdentifier EcdsaWithSha256 =
            new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256);

        /// <summary>DER length of <paramref name="depth"/> nested definite-length SEQUENCEs around an empty
        /// innermost SEQUENCE (X.690 8.1.3: short form below 128, then 0x81, 0x82, 0x83 long forms).</summary>
        public static int NestedSequencesLength(int depth)
        {
            if (depth < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(depth));
            }
            int length = 2;
            for (int i = 1; i < depth; i++)
            {
                length = checked(1 + LengthOfLength(length) + length);
            }
            return length;
        }

        /// <summary>The largest nesting depth whose encoding is at most <paramref name="maxLength"/> bytes.
        /// </summary>
        public static int DeepestNestingFitting(int maxLength)
        {
            if (maxLength < 2)
            {
                throw new ArgumentOutOfRangeException(nameof(maxLength));
            }
            int depth = 1;
            int length = 2;
            while (true)
            {
                int next = 1 + LengthOfLength(length) + length;
                if (next > maxLength)
                {
                    return depth;
                }
                length = next;
                depth++;
            }
        }

        /// <summary><paramref name="depth"/> nested definite-length SEQUENCEs (DER), the innermost one empty.
        /// </summary>
        public static byte[] NestedSequences(int depth)
        {
            int total = NestedSequencesLength(depth);
            // Content length of each level, outermost first.
            var contents = new int[depth];
            int inner = 0;
            for (int level = depth - 1; level >= 0; level--)
            {
                contents[level] = inner;
                inner = 1 + LengthOfLength(inner) + inner;
            }
            var encoding = new byte[total];
            int at = 0;
            for (int level = 0; level < depth; level++)
            {
                encoding[at++] = 0x30;
                int content = contents[level];
                int lengthOctets = LengthOfLength(content) - 1;
                if (lengthOctets == 0)
                {
                    encoding[at++] = (byte)content;
                    continue;
                }
                encoding[at++] = (byte)(0x80 | lengthOctets);
                for (int shift = (lengthOctets - 1) * 8; shift >= 0; shift -= 8)
                {
                    encoding[at++] = (byte)(content >> shift);
                }
            }
            if (at != total)
            {
                throw new InvalidOperationException("nested encoding is " + at + " bytes, expected " + total);
            }
            return encoding;
        }

        /// <summary><paramref name="depth"/> nested indefinite-length SEQUENCEs (BER, X.690 8.1.3.6): 30 80
        /// repeated, then the end-of-contents octets 00 00 repeated.</summary>
        public static byte[] NestedSequencesIndefinite(int depth)
        {
            if (depth < 1)
            {
                throw new ArgumentOutOfRangeException(nameof(depth));
            }
            var encoding = new byte[checked(depth * 4)];
            for (int i = 0; i < depth; i++)
            {
                encoding[2 * i] = 0x30;
                encoding[2 * i + 1] = 0x80;
            }
            return encoding;
        }

        /// <summary>A certificate whose RSA SubjectPublicKeyInfo carries an odd <paramref name="modulusBits"/>-bit
        /// modulus without small factors (deterministic from <paramref name="seed"/>) and the public exponent
        /// <paramref name="exponentHex"/> (big-endian hex); RFC 8017 A.1.1 RSAPublicKey.</summary>
        public static byte[] RsaCertificate(int modulusBits, string exponentHex, int seed = 1)
        {
            BigInteger n = OddModulus(modulusBits, seed);
            var e = new BigInteger(exponentHex, 16);
            var spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
                new DerSequence(new DerInteger(n), new DerInteger(e)));
            return Certificate(spki, Sha256WithRsa);
        }

        /// <summary>The certificate of <paramref name="namedCurveCertificateDer"/>'s P-256 point with the curve
        /// given as explicit specifiedCurve parameters (X9.62 ECParameters) instead of the namedCurve OID that
        /// RFC 5480 2.1.1 requires.</summary>
        public static byte[] ExplicitP256Certificate(byte[] namedCurveCertificateDer)
        {
            SubjectPublicKeyInfo named =
                X509CertificateStructure.GetInstance(namedCurveCertificateDer).SubjectPublicKeyInfo;
            if (!SecObjectIdentifiers.SecP256r1.Equals(named.Algorithm.Parameters))
            {
                throw new ArgumentException("not a P-256 certificate", nameof(namedCurveCertificateDer));
            }
            X9ECParameters p256 = ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1);
            var spki = new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new X962Parameters(p256)),
                named.PublicKey.GetOctets());
            return Certificate(spki, EcdsaWithSha256);
        }

        /// <summary>A real RSA key with public exponent <paramref name="exponent"/> and a self-signed certificate
        /// for it (signs rsa_pss_rsae_sha256), for rows where the client must accept the key.</summary>
        public static SmokeServerKey CreateRsa(int bits, int exponent, string subjectCn = "localhost")
        {
            var random = new SecureRandom();
            var generator = new RsaKeyPairGenerator();
            generator.Init(new RsaKeyGenerationParameters(BigInteger.ValueOf(exponent), random, bits, 80));
            AsymmetricCipherKeyPair pair = generator.GenerateKeyPair();
            var name = new X509Name("CN=" + subjectCn);
            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(new BigInteger(63, random).Add(BigInteger.One));
            gen.SetIssuerDN(name);
            gen.SetSubjectDN(name);
            gen.SetNotBefore(DateTime.UtcNow.AddHours(-1));
            gen.SetNotAfter(DateTime.UtcNow.AddDays(1));
            gen.SetPublicKey(pair.Public);
            byte[] cert = gen.Generate(new Asn1SignatureFactory("SHA256WITHRSA", pair.Private, random)).GetEncoded();
            return new SmokeServerKey("rsa-" + bits + "-e" + exponent, new[] { cert }, pair.Private,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256, false);
        }

        /// <summary>An odd modulus of exactly <paramref name="bits"/> bits with no prime factor below 2000 (a
        /// superset of the small-factor test RsaKeyParameters runs), deterministic from the seed.</summary>
        internal static BigInteger OddModulus(int bits, int seed)
        {
            BigInteger smallPrimes = BigInteger.One;
            for (int p = 3; p < 2000; p += 2)
            {
                bool prime = true;
                for (int d = 3; d * d <= p && prime; d += 2)
                {
                    prime = p % d != 0;
                }
                if (prime)
                {
                    smallPrimes = smallPrimes.Multiply(BigInteger.ValueOf(p));
                }
            }
            BigInteger n = new BigInteger(bits, new Random(seed)).SetBit(bits - 1).SetBit(0);
            while (!n.Gcd(smallPrimes).Equals(BigInteger.One))
            {
                n = n.Add(BigInteger.Two);
            }
            if (n.BitLength != bits)
            {
                throw new InvalidOperationException("modulus overflowed to " + n.BitLength + " bits");
            }
            return n;
        }

        internal static byte[] Certificate(SubjectPublicKeyInfo spki, AlgorithmIdentifier signatureAlgorithm)
        {
            var name = new X509Name("CN=localhost");
            var tbs = new V3TbsCertificateGenerator();
            tbs.SetSerialNumber(new DerInteger(BigInteger.ValueOf(26)));
            tbs.SetSignature(signatureAlgorithm);
            tbs.SetIssuer(name);
            tbs.SetSubject(name);
            tbs.SetStartDate(new Time(DateTime.UtcNow.AddHours(-1)));
            tbs.SetEndDate(new Time(DateTime.UtcNow.AddDays(1)));
            tbs.SetSubjectPublicKeyInfo(spki);
            // Garbage signature: nothing on the client verifies certificate signatures (decision A).
            var signature = new DerBitString(new byte[64]);
            return new X509CertificateStructure(tbs.GenerateTbsCertificate(), signatureAlgorithm, signature)
                .GetEncoded(Asn1Encodable.Der);
        }

        private static int LengthOfLength(int length) =>
            length < 0x80 ? 1 : length < 0x100 ? 2 : length < 0x10000 ? 3 : length < 0x1000000 ? 4 : 5;
    }

    /// <summary>
    /// #26: a test server that puts arbitrary bytes on the wire as its end-entity certificate (TLS 1.3 or 1.2) and
    /// signs the handshake with <see cref="SmokeServerKey"/>'s real key. BASE never parses the bytes: they may be a
    /// deep ASN.1 nesting (BASE caps depth at 64 too) or a certificate whose key BASE would refuse.
    /// </summary>
    public sealed class SmokeHostileTlsServer : SmokeTlsServer
    {
        private readonly byte[] _leafOnWire;

        public SmokeHostileTlsServer(SmokeServerKey signer, byte[] leafOnWire, bool tls13)
            : base(signer)
        {
            _leafOnWire = leafOnWire ?? throw new ArgumentNullException(nameof(leafOnWire));
            Versions = tls13 ? Tls13Only : Tls12Only;
        }

        public override TlsCredentials GetCredentials()
        {
            var crypto = (BcTlsCrypto)m_context.Crypto;
            // The signer's own certificate stands behind the raw bytes for everything but the encoding.
            TlsCertificate leaf = new RawWireCertificate(crypto,
                X509CertificateStructure.GetInstance(Key.CertificateDer), _leafOnWire);
            Certificate certificate = TlsUtilities.IsTlsV13(m_context)
                ? new Certificate(TlsUtilities.EmptyBytes, new[] { new CertificateEntry(leaf, null) })
                : new Certificate(new[] { leaf });
            return new BcDefaultTlsCredentialedSigner(new TlsCryptoParameters(m_context), crypto, Key.PrivateKey,
                certificate, Key.SignatureAlgorithm);
        }

        private sealed class RawWireCertificate : BcTlsCertificate
        {
            private readonly byte[] _wire;

            internal RawWireCertificate(BcTlsCrypto crypto, X509CertificateStructure standIn, byte[] wire)
                : base(crypto, standIn)
            {
                _wire = wire;
            }

            public override byte[] GetEncoded() => (byte[])_wire.Clone();
        }
    }
}
