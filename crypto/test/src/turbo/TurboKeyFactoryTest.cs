// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E5 (STRIP_PLAN_V2.md §3 E5) until the smoke suite (#26) exists.

using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class TurboKeyFactoryTest
    {
        private static readonly BigInteger E3 = BigInteger.Three;
        private static readonly BigInteger E65537 = BigInteger.ValueOf(65537);

        // Largest accepted exponent: 64 bits, odd.
        private static readonly BigInteger E64Bits = BigInteger.One.ShiftLeft(63).Add(BigInteger.One);

        // Smallest rejected exponent size: 65 bits, odd.
        private static readonly BigInteger E65Bits = BigInteger.One.ShiftLeft(64).Add(BigInteger.One);

        private static readonly BigInteger N1024 = MakeModulus(1024, 1);
        private static readonly BigInteger N2047 = MakeModulus(2047, 2);
        private static readonly BigInteger N2048 = MakeModulus(2048, 3);
        private static readonly BigInteger N4096 = MakeModulus(4096, 4);
        private static readonly BigInteger N8192 = MakeModulus(8192, 5);
        private static readonly BigInteger N8193 = MakeModulus(8193, 6);

        // ---- RSA: accepted ----

        [Test]
        public void RsaEncryption2048E65537Accepted() => AssertRsaAccepted(PkcsObjectIdentifiers.RsaEncryption, N2048,
            E65537);

        [Test]
        public void RsaEncryption2048E3Accepted() => AssertRsaAccepted(PkcsObjectIdentifiers.RsaEncryption, N2048, E3);

        [Test]
        public void RsaEncryption4096Accepted() => AssertRsaAccepted(PkcsObjectIdentifiers.RsaEncryption, N4096,
            E65537);

        [Test]
        public void RsaEncryption8192Accepted() => AssertRsaAccepted(PkcsObjectIdentifiers.RsaEncryption, N8192,
            E65537);

        [Test]
        public void RsaEncryption64BitExponentAccepted() => AssertRsaAccepted(PkcsObjectIdentifiers.RsaEncryption,
            N2048, E64Bits);

        [Test]
        public void RsassaPssAccepted() => AssertRsaAccepted(PkcsObjectIdentifiers.IdRsassaPss, N2048, E65537);

        [Test]
        public void RsassaPss4096Accepted() => AssertRsaAccepted(PkcsObjectIdentifiers.IdRsassaPss, N4096, E65537);

        // ---- RSA: rejected by the TurboKeyFactory bounds (before RsaKeyParameters runs) ----

        [Test]
        public void Rsa8193BitRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N8193,
            E65537), "modulus");

        [Test]
        public void Rsa1024BitRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N1024,
            E65537), "modulus");

        [Test]
        public void Rsa2047BitRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2047,
            E65537), "modulus");

        [Test]
        public void RsassaPss1024BitRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.IdRsassaPss, N1024,
            E65537), "modulus");

        [Test]
        public void Rsa65BitExponentRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N8192,
            E65Bits), "exponent");

        [Test]
        public void RsassaPss65BitExponentRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.IdRsassaPss,
            N2048, E65Bits), "exponent");

        [Test]
        public void RsaModulusSizedExponentRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption,
            N8192, N8192.Subtract(BigInteger.Two)), "exponent");

        [Test]
        public void RsaExponentOneRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048,
            BigInteger.One), "exponent");

        // ---- RSA: rejected by master's validation in the public RsaKeyParameters constructor ----

        [Test]
        public void RsaEvenExponentRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048,
            BigInteger.ValueOf(65536)), "even");

        [Test]
        public void RsaEvenModulusRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption,
            N2048.ClearBit(0), E65537), "even");

        [Test]
        public void RsaSmallFactorModulusRejected()
        {
            // 3 * (odd 2046-bit value with the top two bits set) is an odd 2048-bit modulus.
            BigInteger n = BigInteger.Three.Multiply(MakeModulus(2046, 8));
            Assert.AreEqual(2048, n.BitLength);
            AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, n, E65537), "small");
        }

        [Test]
        public void RsaPrimeModulusRejected()
        {
            // A prime "modulus" passes the size and small-factor checks; master's Miller-Rabin rejects it.
            BigInteger prime = BigInteger.ProbablePrime(2048, new Random(7));
            AssertRejected(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, prime, E65537), "composite");
        }

        // ---- RSA: other OIDs that PublicKeyFactory accepts ----

        [Test]
        public void RsaesOaepRejected() => AssertRejected(RsaSpki(PkcsObjectIdentifiers.IdRsaesOaep, N2048, E65537),
            "algorithm");

        [Test]
        public void IdEARsaRejected() => AssertRejected(RsaSpki(X509ObjectIdentifiers.IdEARsa, N2048, E65537),
            "algorithm");

        [Test]
        public void RsaMalformedKeyRejected()
        {
            var spki = new SubjectPublicKeyInfo(RsaAlgID(PkcsObjectIdentifiers.RsaEncryption),
                new byte[] { 0x30, 0x03, 0x02, 0x01 });
            AssertRejected(spki, null);
        }

        [Test]
        public void RsaWrongStructureRejected()
        {
            var spki = new SubjectPublicKeyInfo(RsaAlgID(PkcsObjectIdentifiers.RsaEncryption),
                new DerSequence(new DerInteger(N2048)));
            AssertRejected(spki, null);
        }

        // ---- EC: accepted ----

        [Test]
        public void ECP256Accepted() => AssertECAccepted(SecObjectIdentifiers.SecP256r1, compressed: false);

        [Test]
        public void ECP384Accepted() => AssertECAccepted(SecObjectIdentifiers.SecP384r1, compressed: false);

        [Test]
        public void ECP521Accepted() => AssertECAccepted(SecObjectIdentifiers.SecP521r1, compressed: false);

        [Test]
        public void ECP256X9OidAccepted() => AssertECAccepted(X9ObjectIdentifiers.Prime256v1, compressed: false);

        [Test]
        public void ECP256CompressedAccepted() => AssertECAccepted(SecObjectIdentifiers.SecP256r1, compressed: true);

        [Test]
        public void ECP521CompressedAccepted() => AssertECAccepted(SecObjectIdentifiers.SecP521r1, compressed: true);

        // ---- EC: rejected ----

        [Test]
        public void ECSecp256k1Rejected() => AssertRejected(ECSpki(SecObjectIdentifiers.SecP256k1,
            NamedPoint(SecObjectIdentifiers.SecP256k1).GetEncoded(false)), "curve");

        [Test]
        public void ECP224Rejected() => AssertRejected(ECSpki(SecObjectIdentifiers.SecP224r1,
            NamedPoint(SecObjectIdentifiers.SecP224r1).GetEncoded(false)), "curve");

        [Test]
        public void ECBrainpoolP256Rejected() => AssertRejected(ECSpki(TeleTrusTObjectIdentifiers.BrainpoolP256R1,
            NamedPoint(TeleTrusTObjectIdentifiers.BrainpoolP256R1).GetEncoded(false)), "curve");

        [Test]
        public void ECExplicitParametersRejected()
        {
            // The explicit form of P-256 itself: rejected because it is not a namedCurve (RFC 5480 §2.1.1).
            X9ECParameters x9 = ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1);
            var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new X962Parameters(x9));
            var spki = new SubjectPublicKeyInfo(algID, NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false));
            AssertRejected(spki, "named");
        }

        [Test]
        public void ECImplicitlyCARejected()
        {
            var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new X962Parameters(DerNull.Instance));
            var spki = new SubjectPublicKeyInfo(algID, NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false));
            AssertRejected(spki, "named");
        }

        [Test]
        public void ECMissingParametersRejected()
        {
            var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey);
            var spki = new SubjectPublicKeyInfo(algID, NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false));
            AssertRejected(spki, null);
        }

        [Test]
        public void ECOffCurvePointRejected()
        {
            byte[] encoding = NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false);
            encoding[encoding.Length - 1] ^= 1;
            AssertRejected(ECSpki(SecObjectIdentifiers.SecP256r1, encoding), null);
        }

        [Test]
        public void ECInfinityRejected() => AssertRejected(ECSpki(SecObjectIdentifiers.SecP256r1, new byte[] { 0x00 }),
            "encoding");

        [Test]
        public void ECEmptyPointRejected() => AssertRejected(ECSpki(SecObjectIdentifiers.SecP256r1, new byte[0]),
            "encoding");

        [Test]
        public void ECHybridPointRejected()
        {
            // X9.62 hybrid form (0x06/0x07): MUST NOT be used (RFC 5480 §2.2).
            ECPoint q = NamedPoint(SecObjectIdentifiers.SecP256r1);
            byte[] encoding = q.GetEncoded(false);
            encoding[0] = (byte)(q.AffineYCoord.TestBitZero() ? 0x07 : 0x06);
            AssertRejected(ECSpki(SecObjectIdentifiers.SecP256r1, encoding), "encoding");
        }

        [Test]
        public void ECTruncatedPointRejected()
        {
            byte[] encoding = NamedPoint(SecObjectIdentifiers.SecP384r1).GetEncoded(false);
            AssertRejected(ECSpki(SecObjectIdentifiers.SecP384r1, Arrays.CopyOf(encoding, encoding.Length - 1)), null);
        }

        [Test]
        public void ECPointFromOtherCurveRejected()
        {
            // A valid P-384 point labelled as P-256.
            AssertRejected(ECSpki(SecObjectIdentifiers.SecP256r1,
                NamedPoint(SecObjectIdentifiers.SecP384r1).GetEncoded(false)), null);
        }

        // ---- Everything else ----

        [Test]
        public void Ed25519Rejected() => AssertRejected(Ed25519Spki(), "algorithm");

        [Test]
        public void DsaRejected() => AssertRejected(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa), new DerInteger(N2048)), "algorithm");

        [Test]
        public void DHRejected() => AssertRejected(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.DhKeyAgreement), new DerInteger(N2048)), "algorithm");

        [Test]
        public void GarbageBytesRejected()
        {
            var ex = Assert.Throws<ArgumentException>(
                () => TurboKeyFactory.CreateKey(new byte[] { 0x30, 0x82, 0xFF, 0xFF, 0x00 }));
            Assert.IsNotNull(ex.InnerException);
        }

        [Test]
        public void TrailingDataRejected()
        {
            byte[] encoding = RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048, E65537).GetEncoded(Asn1Encodable.Der);
            Assert.Throws<ArgumentException>(() => TurboKeyFactory.CreateKey(Arrays.Append(encoding, 0x00)));
        }

        [Test]
        public void EncodedSpkiAccepted()
        {
            byte[] encoding = RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048, E65537).GetEncoded(Asn1Encodable.Der);
            Assert.IsInstanceOf<RsaKeyParameters>(TurboKeyFactory.CreateKey(encoding));
        }

        [Test]
        public void NullInputRejected()
        {
            Assert.Throws<ArgumentNullException>(() => TurboKeyFactory.CreateKey((SubjectPublicKeyInfo)null));
            Assert.Throws<ArgumentNullException>(() => TurboKeyFactory.CreateKey((byte[])null));
        }

        // ---- Routing: BcTlsRawKeyCertificate.GetPublicKey goes through TurboKeyFactory ----

        [Test]
        public void RawKeyCertificateRejects1024BitRsa() => AssertUnsupportedCertificate(
            () => RawKeyCert(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N1024, E65537)).GetPubKeyRsa());

        [Test]
        public void RawKeyCertificateRejects65BitExponent() => AssertUnsupportedCertificate(
            () => RawKeyCert(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048, E65Bits)).GetPubKeyRsa());

        [Test]
        public void RawKeyCertificateRejectsSecp256k1() => AssertUnsupportedCertificate(
            () => RawKeyCert(ECSpki(SecObjectIdentifiers.SecP256k1,
                NamedPoint(SecObjectIdentifiers.SecP256k1).GetEncoded(false))).GetPubKeyEC());

        [Test]
        public void RawKeyCertificateRejectsEd25519() => AssertUnsupportedCertificate(
            () => RawKeyCert(Ed25519Spki()).SupportsSignatureAlgorithm(SignatureAlgorithm.ed25519));

        [Test]
        public void RawKeyCertificateAcceptsAllowedKeys()
        {
            Assert.IsNotNull(RawKeyCert(RsaSpki(PkcsObjectIdentifiers.RsaEncryption, N2048, E65537)).GetPubKeyRsa());
            Assert.IsNotNull(RawKeyCert(ECSpki(SecObjectIdentifiers.SecP384r1,
                NamedPoint(SecObjectIdentifiers.SecP384r1).GetEncoded(true))).GetPubKeyEC());
        }

        // ---- Helpers ----

        private static void AssertRsaAccepted(DerObjectIdentifier oid, BigInteger n, BigInteger e)
        {
            AsymmetricKeyParameter key = TurboKeyFactory.CreateKey(RsaSpki(oid, n, e));

            Assert.IsInstanceOf<RsaKeyParameters>(key);
            Assert.IsFalse(key.IsPrivate);
            RsaKeyParameters rsa = (RsaKeyParameters)key;
            Assert.AreEqual(n, rsa.Modulus);
            Assert.AreEqual(e, rsa.Exponent);
        }

        private static void AssertECAccepted(DerObjectIdentifier curveOid, bool compressed)
        {
            ECPoint q = NamedPoint(curveOid);
            AsymmetricKeyParameter key = TurboKeyFactory.CreateKey(ECSpki(curveOid, q.GetEncoded(compressed)));

            Assert.IsInstanceOf<ECPublicKeyParameters>(key);
            ECPublicKeyParameters ec = (ECPublicKeyParameters)key;
            Assert.AreEqual(q, ec.Q);
            Assert.IsInstanceOf<ECNamedDomainParameters>(ec.Parameters);
            Assert.AreEqual(curveOid, ((ECNamedDomainParameters)ec.Parameters).Name);
        }

        // Exactly ArgumentException (not a subclass); 'reason' is a substring of the message when given.
        private static void AssertRejected(SubjectPublicKeyInfo spki, string reason)
        {
            var ex = Assert.Throws<ArgumentException>(() => TurboKeyFactory.CreateKey(spki));
            if (reason != null)
            {
                StringAssert.Contains(reason, ex.Message);
            }
        }

        private static void AssertUnsupportedCertificate(TestDelegate code)
        {
            var alert = Assert.Throws<TlsFatalAlert>(code);
            Assert.AreEqual(AlertDescription.unsupported_certificate, alert.AlertDescription);
            Assert.IsInstanceOf<ArgumentException>(alert.InnerException);
        }

        private static BcTlsRawKeyCertificate RawKeyCert(SubjectPublicKeyInfo spki) =>
            new BcTlsRawKeyCertificate(new BcTlsCrypto(), spki);

        private static AlgorithmIdentifier RsaAlgID(DerObjectIdentifier oid) =>
            PkcsObjectIdentifiers.RsaEncryption.Equals(oid)
                ? new AlgorithmIdentifier(oid, DerNull.Instance)
                : new AlgorithmIdentifier(oid);

        private static SubjectPublicKeyInfo RsaSpki(DerObjectIdentifier oid, BigInteger n, BigInteger e) =>
            new SubjectPublicKeyInfo(RsaAlgID(oid), new RsaPublicKeyStructure(n, e));

        private static SubjectPublicKeyInfo ECSpki(DerObjectIdentifier curveOid, byte[] point) =>
            new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new X962Parameters(curveOid)), point);

        // A valid Ed25519 public key (from the all-zero seed); master's PublicKeyFactory accepts it.
        private static SubjectPublicKeyInfo Ed25519Spki() =>
            new SubjectPublicKeyInfo(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                new Ed25519PrivateKeyParameters(new byte[32]).GeneratePublicKey().GetEncoded());

        // A fixed, valid public point on the named curve: [12345]G.
        private static ECPoint NamedPoint(DerObjectIdentifier curveOid)
        {
            X9ECParameters x9 = ECNamedCurveTable.GetByOid(curveOid);
            return x9.G.Multiply(BigInteger.ValueOf(12345)).Normalize();
        }

        // Deterministic odd composite of exactly 'bits' bits with no small prime factors, so master's
        // RsaKeyParameters validation (even modulus, small factors, Miller-Rabin) accepts it.
        private static BigInteger MakeModulus(int bits, int seed)
        {
            var random = new Random(seed);
            BigInteger n = new BigInteger(bits, random).SetBit(bits - 1).SetBit(bits - 2).SetBit(0);
            while (BigIntegers.HasAnySmallFactors(n) || n.IsProbablePrime(8))
            {
                n = n.Add(BigInteger.Two);
            }
            Assert.AreEqual(bits, n.BitLength);
            return n;
        }
    }
}
