// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cuts E9-E12 (STRIP_PLAN_V2.md §3 E9-E12) until the smoke suite exists.

using System;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Rosstandart;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.UA;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.X509.Extension;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class HelperCutsE9E12Test
    {
        private static readonly SecureRandom Random = new SecureRandom();

        private static ECPublicKeyParameters GenerateP256PublicKey()
        {
            X9ECParameters x9 = CustomNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
            var domain = new ECNamedDomainParameters(SecObjectIdentifiers.SecP256r1, x9);
            var generator = new ECKeyPairGenerator();
            generator.Init(new ECKeyGenerationParameters(domain, Random));
            return (ECPublicKeyParameters)generator.GenerateKeyPair().Public;
        }

        private static SubjectPublicKeyInfo P256Spki(ECPublicKeyParameters publicKey) =>
            new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, SecObjectIdentifiers.SecP256r1),
                publicKey.Q.GetEncoded(false));

        // E9: key identifiers from a SubjectPublicKeyInfo stay (RFC 5280 §4.2.1.2 method 1: SHA-1 of the key bits).
        [Test]
        public void SubjectKeyIdentifierFromSpkiIsSha1OfKeyBits()
        {
            SubjectPublicKeyInfo spki = P256Spki(GenerateP256PublicKey());

            var sha1 = new Sha1Digest();
            byte[] keyBits = spki.PublicKey.GetBytes();
            sha1.BlockUpdate(keyBits, 0, keyBits.Length);
            byte[] expected = new byte[sha1.GetDigestSize()];
            sha1.DoFinal(expected, 0);

            SubjectKeyIdentifier ski = X509ExtensionUtilities.CreateSubjectKeyIdentifier(spki);
            Assert.AreEqual(Hex.ToHexString(expected), Hex.ToHexString(ski.GetKeyIdentifier()));

            AuthorityKeyIdentifier aki = X509ExtensionUtilities.CreateAuthorityKeyIdentifier(spki);
            Assert.AreEqual(Hex.ToHexString(expected), Hex.ToHexString(aki.GetKeyIdentifier()));
        }

        // E9: the AsymmetricKeyParameter overloads needed the denied SubjectPublicKeyInfoFactory; they now throw.
        [Test]
        public void KeyIdentifierFromKeyParameterThrows()
        {
            ECPublicKeyParameters publicKey = GenerateP256PublicKey();

            Assert.Throws<NotSupportedException>(() => X509ExtensionUtilities.CreateSubjectKeyIdentifier(publicKey));
            Assert.Throws<NotSupportedException>(
                () => X509ExtensionUtilities.CreateAuthorityKeyIdentifier(publicKey));
        }

        // E10: plain EC key generation on the TLS curves is unchanged.
        [Test]
        public void ECKeyPairGeneratorGeneratesOnP256()
        {
            ECPublicKeyParameters publicKey = GenerateP256PublicKey();

            Assert.AreEqual("EC", publicKey.AlgorithmName);
            Assert.IsTrue(publicKey.Q.IsValid());
        }

        // E10: the ECGost3410Utilities branch is gone, so "ECGOST3410" no longer insists on ECKeyGenerationParameters
        // (pre-cut: ArgumentException "ECGOST3410 key generation requires ECKeyGenerationParameters").
        [Test]
        public void ECKeyPairGeneratorHasNoGostBranch()
        {
            var generator = new ECKeyPairGenerator("ECGOST3410");
            generator.Init(new KeyGenerationParameters(Random, 256));

            var publicKey = (ECPublicKeyParameters)generator.GenerateKeyPair().Public;
            Assert.AreEqual("ECGOST3410", publicKey.AlgorithmName);
            Assert.AreEqual(256, publicKey.Parameters.Curve.FieldSize);
        }

        // E11: the GOST3411, GOST3411-2012 and DSTU7564 digests are no longer created by name or OID.
        [TestCase("GOST3411")]
        [TestCase("GOST3411-2012-256")]
        [TestCase("GOST3411-2012-512")]
        [TestCase("DSTU7564-256")]
        [TestCase("DSTU7564-384")]
        [TestCase("DSTU7564-512")]
        public void DeniedDigestNameNotRecognised(string name)
        {
            Assert.Throws<SecurityUtilityException>(() => DigestUtilities.GetDigest(name));
        }

        private static readonly object[] DeniedDigestOids =
        {
            new object[] { CryptoProObjectIdentifiers.GostR3411 },
            new object[] { RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256 },
            new object[] { RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512 },
            new object[] { UAObjectIdentifiers.dstu7564digest_256 },
            new object[] { UAObjectIdentifiers.dstu7564digest_384 },
            new object[] { UAObjectIdentifiers.dstu7564digest_512 },
        };

        [TestCaseSource(nameof(DeniedDigestOids))]
        public void DeniedDigestOidNotRecognised(DerObjectIdentifier oid)
        {
            Assert.Throws<SecurityUtilityException>(() => DigestUtilities.GetDigest(oid));
        }

        [TestCase("SHA-1", 20)]
        [TestCase("SHA-256", 32)]
        [TestCase("SHA-384", 48)]
        [TestCase("SHA-512", 64)]
        public void KeptDigestsResolve(string name, int size)
        {
            Assert.AreEqual(size, DigestUtilities.GetDigest(name).GetDigestSize());
        }

        // E11: SecureRandom's digest PRNGs still resolve their digests through DigestUtilities.
        [Test]
        public void SecureRandomPrngStillWorks()
        {
            SecureRandom random = SecureRandom.GetInstance("SHA256PRNG");
            byte[] bytes = new byte[32];
            random.NextBytes(bytes);
            Assert.AreEqual(32, bytes.Length);
        }

        // E12: BcTlsHmac.CalculateMac() no longer goes through MacUtilities; RFC 4231 test case 1 (HMAC-SHA-256).
        [Test]
        public void BcTlsHmacCalculateMacMatchesRfc4231()
        {
            var crypto = new BcTlsCrypto(Random);
            TlsHmac hmac = crypto.CreateHmac(MacAlgorithm.hmac_sha256);
            Assert.IsInstanceOf<BcTlsHmac>(hmac);

            byte[] key = Hex.Decode("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
            byte[] data = Hex.Decode("4869205468657265");
            const string Expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

            hmac.SetKey(key, 0, key.Length);
            hmac.Update(data, 0, data.Length);
            byte[] mac = hmac.CalculateMac();
            Assert.AreEqual(Expected, Hex.ToHexString(mac));

            // The mac resets after CalculateMac(); the (output, offset) overload gives the same value.
            hmac.Update(data, 0, data.Length);
            byte[] output = new byte[hmac.MacLength + 3];
            hmac.CalculateMac(output, 3);
            Assert.AreEqual(Expected, Hex.ToHexString(output, 3, hmac.MacLength));
        }
    }
}
