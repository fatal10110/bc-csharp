using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Engines;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Signers;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Math;

namespace TurboSmoke
{
    /// <summary>
    /// #24: RSA signature verify with the RSASSA-PSS example 1 key (1024-bit, crypto/test crypto/test PSSTest.cs):
    /// PSS SHA-1 example 1.2 (signature from the test vectors), PSS SHA-256 salt 32 (rsa_pss_rsae_sha256) and
    /// PKCS#1 v1.5 SHA-256 (rsa_pkcs1_sha256), the last two signed over the same message by OpenSSL 3. A flipped
    /// signature bit must be rejected.
    /// </summary>
    public sealed class KatRsaRows : SmokeRowGroup
    {
        public override string Name => "kat-rsa";
        public override int Order => 10;

        private const string Modulus =
            "a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991"
            + "d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1df"
            + "d5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f1"
            + "05acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a2137";

        // PSS example 1.2 message.
        private const string Message =
            "851384cdfe819c22ed6c4ccb30daeb5cf059bc8e1166b7e3530c4c233e2b5f8f"
            + "71a1cca582d43ecc72b1bca16dfc7013226b9e";

        private delegate ISigner SignerFactory();

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("pss-sha1-verify", () => Check(() => new PssSigner(new RsaEngine(), new Sha1Digest(), 20),
                "3ef7f46e831bf92b32274142a585ffcefbdca7b32ae90d10fb0f0c729984f04e"
                + "f29a9df0780775ce43739b97838390db0a5505e63de927028d9d29b219ca2c45"
                + "17832558a55d694a6d25b9dab66003c4cccd907802193be5170d26147d37b935"
                + "90241be51c25055f47ef62752cfbe21418fafe98c22c4d4d47724fdb5669e843"));
            rows.Add("pss-sha256-verify", () => Check(() => new PssSigner(new RsaEngine(), new Sha256Digest(), 32),
                "65059ec46a69d5c6b22e5d9d1d7721710d171c5e5c6e06b7b449c812910a4400"
                + "ed7ca0543435101797850752f3e0a9e787d3603b3d16a0d93d079df761816cf0"
                + "46738a7b93f39c2bfef5047bb2c119edb2f52d3b2c0d0657356114b24d2a7ab6"
                + "7231c88c98d4357ff1a665e95bbc1325e1dc96bc86b00fbe1e9c7253659b14bb"));
            rows.Add("pkcs1-sha256-verify", () => Check(() => new RsaDigestSigner(new Sha256Digest()),
                "1c1e9fa522a25823a2eff921768ac3351b05c2085a173db8b2fa450aa434f9b0"
                + "2c98df9ba7be0eb7283bfc74fc9ef0c336c1f5417943972d44fcd4a50f30e001"
                + "7aecbe792222f83b5436b6303c09e4ecbebcbb4abf85bc94aa288ad2bcff83bd"
                + "4b15820b0f072171a68413bdce701862e20e1600a510b2d89896073337929716"));
        }

        private static void Check(SignerFactory factory, string signature)
        {
            var key = new RsaKeyParameters(false, new BigInteger(Modulus, 16), BigInteger.ValueOf(65537));
            byte[] message = SmokeHex.Decode(Message), sig = SmokeHex.Decode(signature);
            SmokeAssert.True(Verify(factory(), key, message, sig), "known signature rejected");

            byte[] tampered = (byte[])sig.Clone();
            tampered[tampered.Length / 2] ^= 0x01;
            SmokeAssert.True(!Verify(factory(), key, message, tampered), "flipped signature bit accepted");
        }

        private static bool Verify(ISigner signer, RsaKeyParameters key, byte[] message, byte[] signature)
        {
            signer.Init(false, key);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
    }
}
