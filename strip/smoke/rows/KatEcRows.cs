using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X9;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.EC;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Signers;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math.EC;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math.EC.Multiplier;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math.EC.Rfc7748;

namespace TurboSmoke
{
    /// <summary>
    /// #24: X25519 (RFC 7748 section 5.2 vectors and section 6.1 ECDH; crypto/test math/ec/rfc7748 X25519Test.cs)
    /// and ECDSA verify on P-256/384/521 (RFC 6979 A.2.5-A.2.7, message "sample" with SHA-256/384/512, the TLS
    /// signature schemes; crypto/test DeterministicDSATest.cs). The ECDSA public keys are decoded from their
    /// uncompressed encoding (the path a server key takes) and must equal d*G.
    /// </summary>
    public sealed class KatEcRows : SmokeRowGroup
    {
        public override string Name => "kat-ec";
        public override int Order => 10;

        private delegate IDigest DigestFactory();

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("x25519-rfc7748-vector1", () => CheckScalarMult(
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"));
            rows.Add("x25519-rfc7748-vector2", () => CheckScalarMult(
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"));
            rows.Add("x25519-rfc7748-ecdh", CheckEcdh);

            rows.Add("ecdsa-p256-sha256-verify", () => CheckEcdsa("secp256r1", () => new Sha256Digest(),
                "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
                "04"
                + "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6"
                + "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299",
                "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716",
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8"));
            rows.Add("ecdsa-p384-sha384-verify", () => CheckEcdsa("secp384r1", () => new Sha384Digest(),
                "6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d8"
                + "96d5724e4c70a825f872c9ea60d2edf5",
                "04"
                + "ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64"
                + "def8f0ea9055866064a254515480bc13"
                + "8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1"
                + "288b231c3ae0d4fe7344fd2533264720",
                "94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c"
                + "81a648152e44acf96e36dd1e80fabe46",
                "99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94f"
                + "a329c145786e679e7b82c71a38628ac8"));
            rows.Add("ecdsa-p521-sha512-verify", () => CheckEcdsa("secp521r1", () => new Sha512Digest(),
                "0fad06daa62ba3b25d2fb40133da757205de67f5bb0018fee8c86e1b68c7e75"
                + "caa896eb32f1f47c70855836a6d16fcc1466f6d8fbec67db89ec0c08b0e996b8"
                + "3538",
                "04"
                + "01894550d0785932e00eaa23b694f213f8c3121f86dc97a04e5a7167db4e5bcd"
                + "371123d46e45db6b5d5370a7f20fb633155d38ffa16d2bd761dcac474b9a2f50"
                + "23a4"
                + "00493101c962cd4d2fddf782285e64584139c2f91b47f87ff82354d6630f746a"
                + "28a0db25741b5b34a828008b22acc23f924faafbd4d33f81ea66956dfeaa2bfd"
                + "fcf5",
                "0c328fafcbd79dd77850370c46325d987cb525569fb63c5d3bc53950e6d4c5f1"
                + "74e25a1ee9017b5d450606add152b534931d7d4e8455cc91f9b15bf05ec36e37"
                + "7fa",
                "0617cce7cf5064806c467f678d3b4080d6f1cc50af26ca209417308281b68af2"
                + "82623eaa63e5b5c0723d8b8c37ff0777b1a20f8ccb1dccc43997f1ee0e44da4a"
                + "67a"));
        }

        private static void CheckScalarMult(string k, string u, string expected)
        {
            byte[] r = new byte[X25519.PointSize];
            X25519.ScalarMult(SmokeHex.Decode(k), 0, SmokeHex.Decode(u), 0, r, 0);
            SmokeAssert.Equal(SmokeHex.Decode(expected), r, "X25519(k, u)");
        }

        private static void CheckEcdh()
        {
            byte[] a = SmokeHex.Decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
            byte[] aPub = SmokeHex.Decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
            byte[] b = SmokeHex.Decode("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
            byte[] bPub = SmokeHex.Decode("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
            byte[] k = SmokeHex.Decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

            byte[] pub = new byte[X25519.PointSize];
            X25519.GeneratePublicKey(a, 0, pub, 0);
            SmokeAssert.Equal(aPub, pub, "Alice public key");
            X25519.GeneratePublicKey(b, 0, pub, 0);
            SmokeAssert.Equal(bPub, pub, "Bob public key");

            byte[] shared = new byte[X25519.PointSize];
            SmokeAssert.True(X25519.CalculateAgreement(a, 0, bPub, 0, shared, 0), "Alice agreement rejected");
            SmokeAssert.Equal(k, shared, "Alice shared secret");
            SmokeAssert.True(X25519.CalculateAgreement(b, 0, aPub, 0, shared, 0), "Bob agreement rejected");
            SmokeAssert.Equal(k, shared, "Bob shared secret");
        }

        private static void CheckEcdsa(string curveName, DigestFactory digestFactory, string d, string q, string r,
            string s)
        {
            X9ECParameters x9 = CustomNamedCurves.GetByName(curveName);
            SmokeAssert.NotNull(x9, "CustomNamedCurves.GetByName(" + curveName + ")");
            var domain = new ECDomainParameters(x9);

            ECPoint decoded = x9.Curve.DecodePoint(SmokeHex.Decode(q));
            ECPoint derived = new FixedPointCombMultiplier().Multiply(x9.G, new BigInteger(d, 16)).Normalize();
            SmokeAssert.True(decoded.Equals(derived), curveName + ": public key != d*G");
            var publicKey = new ECPublicKeyParameters(decoded, domain);

            BigInteger rr = new BigInteger(r, 16), ss = new BigInteger(s, 16);
            SmokeAssert.True(Verify(publicKey, digestFactory, "sample", rr, ss), "RFC 6979 signature rejected");
            SmokeAssert.True(!Verify(publicKey, digestFactory, "sample", rr, ss.Add(BigInteger.One)),
                "signature with s+1 accepted");
            SmokeAssert.True(!Verify(publicKey, digestFactory, "test", rr, ss), "signature on another message accepted");
        }

        private static bool Verify(ECPublicKeyParameters publicKey, DigestFactory digestFactory, string message,
            BigInteger r, BigInteger s)
        {
            IDigest digest = digestFactory();
            byte[] m = Encoding.ASCII.GetBytes(message);
            digest.BlockUpdate(m, 0, m.Length);
            byte[] hash = new byte[digest.GetDigestSize()];
            digest.DoFinal(hash, 0);

            var signer = new ECDsaSigner();
            signer.Init(false, publicKey);
            return signer.VerifySignature(hash, r, s);
        }
    }
}
