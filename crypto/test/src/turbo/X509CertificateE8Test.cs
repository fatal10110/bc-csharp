// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E8 (STRIP_PLAN_V2.md §3 E8, decision A) until the smoke suite (#23)
// exists.

using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class X509CertificateE8Test
    {
        private static readonly BigInteger E65537 = BigInteger.ValueOf(65537);
        private static readonly BigInteger N1024 = MakeModulus(1024, 1);
        private static readonly BigInteger N2048 = MakeModulus(2048, 3);

        private static readonly AlgorithmIdentifier Sha256WithRsa =
            new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance);

        // --- GetPublicKey goes through TurboKeyFactory ---

        [Test]
        public void GetPublicKeyRsa2048Accepted()
        {
            var key = Cert(RsaSpki(N2048)).GetPublicKey() as RsaKeyParameters;
            Assert.IsNotNull(key);
            Assert.AreEqual(N2048, key.Modulus);
            Assert.AreEqual(E65537, key.Exponent);
        }

        [Test]
        public void GetPublicKeyP256Accepted()
        {
            var key = Cert(P256Spki()).GetPublicKey() as ECPublicKeyParameters;
            Assert.IsNotNull(key);
            Assert.AreEqual(NamedPoint(SecObjectIdentifiers.SecP256r1), key.Q.Normalize());
        }

        [Test]
        public void GetPublicKeyRsa1024Rejected() => AssertKeyRejected(RsaSpki(N1024));

        [Test]
        public void GetPublicKeyECExplicitParametersRejected()
        {
            X9ECParameters x9 = ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1);
            var algID = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, new X962Parameters(x9));
            AssertKeyRejected(
                new SubjectPublicKeyInfo(algID, NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false)));
        }

        [Test]
        public void GetPublicKeyDsaRejected() => AssertKeyRejected(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa), new DerInteger(N2048)));

        [Test]
        public void GetPublicKeyEd25519Rejected() => AssertKeyRejected(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
            new Ed25519PrivateKeyParameters(new byte[32]).GeneratePublicKey().GetEncoded()));

        [Test]
        public void GetPublicKeyMalformedRsaKeyRejected() => AssertKeyRejected(new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
            new byte[] { 0x30, 0x03, 0x02 }));

        // --- No BC certificate-signature verification (decision A) ---

        [Test]
        public void VerificationThrowsForValidlySignedCertificate()
        {
            // A genuinely self-signed P-256 certificate: master verifies it; the strip refuses to.
            var kpg = new ECKeyPairGenerator();
            kpg.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
            AsymmetricCipherKeyPair kp = kpg.GenerateKeyPair();

            var gen = new X509V3CertificateGenerator();
            gen.SetSerialNumber(BigInteger.One);
            gen.SetIssuerDN(new X509Name("CN=E8"));
            gen.SetSubjectDN(new X509Name("CN=E8"));
            gen.SetNotBefore(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            gen.SetNotAfter(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc));
            gen.SetPublicKey(kp.Public);
            X509Certificate cert = gen.Generate(new Asn1SignatureFactory("SHA256withECDSA", kp.Private));

            AssertVerificationUnsupported(cert, kp.Public);
        }

        [Test]
        public void VerificationThrowsForRsaCertificate()
        {
            X509Certificate cert = Cert(RsaSpki(N2048));
            AssertVerificationUnsupported(cert, cert.GetPublicKey());
        }

        [Test]
        public void ProtectedCheckSignatureThrows()
        {
            var cert = new SubclassedCertificate(Cert(RsaSpki(N2048)).CertificateStructure);
            Assert.Throws<NotSupportedException>(() => cert.CallCheckSignature());
            Assert.Throws<NotSupportedException>(() => cert.CallCheckSignatureValid());
        }

        // --- SigAlgName from the turbo OID->name map ---

        [Test]
        public void SigAlgNameSha256WithRsa() => Assert.AreEqual("SHA-256withRSA", Cert(RsaSpki(N2048)).SigAlgName);

        [Test]
        public void SigAlgNameEcdsaWithSha256() => Assert.AreEqual("SHA-256withECDSA",
            Cert(P256Spki(), new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256)).SigAlgName);

        [Test]
        public void SigAlgNameEcdsaWithSha384() => Assert.AreEqual("SHA-384withECDSA",
            Cert(P256Spki(), new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha384)).SigAlgName);

        [Test]
        public void SigAlgNameRsassaPssIgnoresParameters()
        {
            // Keyed by OID only: the PSS parameters are not parsed (master printed "SHA256withRSAandMGF1").
            var hash = new AlgorithmIdentifier(NistObjectIdentifiers.IdSha256, DerNull.Instance);
            var pss = new RsassaPssParameters(hash,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.IdMgf1, hash), new DerInteger(32), new DerInteger(1));
            var sigAlg = new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsassaPss, pss);
            Assert.AreEqual("PSSwithRSA", Cert(RsaSpki(N2048), sigAlg).SigAlgName);
        }

        [Test]
        public void SigAlgNameUnknownOidIsOidString() => Assert.AreEqual("1.2.3.4.5",
            Cert(RsaSpki(N2048), new AlgorithmIdentifier(new DerObjectIdentifier("1.2.3.4.5"))).SigAlgName);

        [Test]
        public void SigAlgNameEd25519IsOidString() => Assert.AreEqual("1.3.101.112",
            Cert(RsaSpki(N2048), new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519)).SigAlgName);

        // --- ToString survives a rejected key ---

        [Test]
        public void ToStringPrintsUnsupportedKey()
        {
            string s = Cert(RsaSpki(N1024)).ToString();
            StringAssert.Contains("Public Key: <unsupported key>", s);
            StringAssert.Contains("Signature Algorithm: SHA-256withRSA", s);
        }

        [Test]
        public void ToStringPrintsAcceptedKey()
        {
            string s = Cert(RsaSpki(N2048)).ToString();
            StringAssert.DoesNotContain("<unsupported key>", s);
        }

        private static void AssertKeyRejected(SubjectPublicKeyInfo spki)
        {
            X509Certificate cert = Cert(spki);
            // Exactly ArgumentException (TurboKeyFactory's contract), not wrapped; and not cached as a success.
            Assert.Throws<ArgumentException>(() => cert.GetPublicKey());
            Assert.Throws<ArgumentException>(() => cert.GetPublicKey());
        }

        private static void AssertVerificationUnsupported(X509Certificate cert, AsymmetricKeyParameter key)
        {
            var provider = new Asn1VerifierFactoryProvider(key);
            Assert.Throws<NotSupportedException>(() => cert.Verify(key));
            Assert.Throws<NotSupportedException>(() => cert.Verify(provider));
            Assert.Throws<NotSupportedException>(() => cert.IsSignatureValid(key));
            Assert.Throws<NotSupportedException>(() => cert.IsSignatureValid(provider));
            Assert.Throws<NotSupportedException>(() => cert.IsAlternativeSignatureValid(key));
            Assert.Throws<NotSupportedException>(() => cert.IsAlternativeSignatureValid(provider));
            Assert.Throws<NotSupportedException>(() => cert.VerifyAltSignature(provider));
        }

        private static X509Certificate Cert(SubjectPublicKeyInfo spki) => Cert(spki, Sha256WithRsa);

        // A certificate around the given key and signature algorithm; the signature bytes are a dummy, which is
        // enough because the strip never verifies them.
        private static X509Certificate Cert(SubjectPublicKeyInfo spki, AlgorithmIdentifier sigAlg)
        {
            var tbsGen = new V3TbsCertificateGenerator();
            tbsGen.SetSerialNumber(new DerInteger(1));
            tbsGen.SetSignature(sigAlg);
            tbsGen.SetIssuer(new X509Name("CN=E8"));
            tbsGen.SetStartDate(new Time(new DateTime(2026, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbsGen.SetEndDate(new Time(new DateTime(2027, 1, 1, 0, 0, 0, DateTimeKind.Utc)));
            tbsGen.SetSubject(new X509Name("CN=E8"));
            tbsGen.SetSubjectPublicKeyInfo(spki);
            TbsCertificateStructure tbs = tbsGen.GenerateTbsCertificate();
            return new X509Certificate(new X509CertificateStructure(tbs, sigAlg, new DerBitString(new byte[64])));
        }

        private static SubjectPublicKeyInfo RsaSpki(BigInteger n) => new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(PkcsObjectIdentifiers.RsaEncryption, DerNull.Instance),
            new RsaPublicKeyStructure(n, E65537));

        private static SubjectPublicKeyInfo P256Spki()
        {
            var curve = new X962Parameters(SecObjectIdentifiers.SecP256r1);
            return new SubjectPublicKeyInfo(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, curve),
                NamedPoint(SecObjectIdentifiers.SecP256r1).GetEncoded(false));
        }

        // A fixed, valid public point on the named curve: [12345]G.
        private static ECPoint NamedPoint(DerObjectIdentifier curveOid)
        {
            X9ECParameters x9 = ECNamedCurveTable.GetByOid(curveOid);
            return x9.G.Multiply(BigInteger.ValueOf(12345)).Normalize();
        }

        // Deterministic odd composite of exactly 'bits' bits with no small prime factors (see TurboKeyFactoryTest).
        private static BigInteger MakeModulus(int bits, int seed)
        {
            var random = new Random(seed);
            BigInteger n = new BigInteger(bits, random).SetBit(bits - 1).SetBit(bits - 2).SetBit(0);
            while (BigIntegers.HasAnySmallFactors(n) || n.IsProbablePrime(8))
            {
                n = n.Add(BigInteger.Two);
            }
            return n;
        }

        private sealed class SubclassedCertificate
            : X509Certificate
        {
            internal SubclassedCertificate(X509CertificateStructure c)
                : base(c)
            {
            }

            internal void CallCheckSignature() =>
                CheckSignature(new Asn1VerifierFactory(SignatureAlgorithm, GetPublicKey()));

            internal bool CallCheckSignatureValid() =>
                CheckSignatureValid(new Asn1VerifierFactory(SignatureAlgorithm, GetPublicKey()));
        }
    }
}
