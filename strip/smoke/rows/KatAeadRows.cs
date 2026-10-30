using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Engines;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Modes;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Modes.Gcm;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace TurboSmoke
{
    /// <summary>
    /// #24: AEAD known answers. AES-GCM on AesLightEngine + BasicGcmMultiplier (decision G / E14: the engine and
    /// multiplier the strip's TLS path uses), vectors GCM spec test cases 4 and 16 (crypto/test GCMTest.cs);
    /// ChaCha20-Poly1305 RFC 8439 section 2.8.2 (crypto/test ChaCha20Poly1305Test.cs) through BcChaCha20Poly1305, the
    /// TLS implementation (the generic Crypto.Modes.ChaCha20Poly1305 is outside the closure). Each row encrypts,
    /// decrypts and rejects a flipped tag bit.
    /// </summary>
    public sealed class KatAeadRows : SmokeRowGroup
    {
        public override string Name => "kat-aead";
        public override int Order => 10;

        private const string GcmPlain =
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
            + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39";
        private const string GcmAad = "feedfacedeadbeeffeedfacedeadbeefabaddad2";
        private const string GcmIv = "cafebabefacedbaddecaf888";

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("aes128-gcm-light-basic", () => CheckGcm(
                "feffe9928665731c6d6a8f9467308308", GcmIv, GcmAad, GcmPlain,
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091"
                + "5bc94fbc3221a5db94fae95ae7121a47"));
            rows.Add("aes256-gcm-light-basic", () => CheckGcm(
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308", GcmIv, GcmAad, GcmPlain,
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662"
                + "76fc6ece0f4e1768cddf8853bb2d551b"));
            rows.Add("chacha20-poly1305-tls", () => Check(ChaCha20Poly1305, typeof(TlsFatalAlert),
                "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
                "070000004041424344454647",
                "50515253c0c1c2c3c4c5c6c7",
                "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
                + "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
                + "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
                + "637265656e20776f756c642062652069742e",
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
                + "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
                + "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
                + "3ff4def08e4b7a9de576d26586cec64b6116"
                + "1ae10b594f09e26a7e902ecbd0600691"));
        }

        private delegate byte[] AeadProcess(bool encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input);

        private static void Check(AeadProcess process, Type tamperException, string key, string nonce, string aad,
            string plain, string sealedHex)
        {
            byte[] k = SmokeHex.Decode(key), n = SmokeHex.Decode(nonce), a = SmokeHex.Decode(aad);
            byte[] p = SmokeHex.Decode(plain), expected = SmokeHex.Decode(sealedHex);

            SmokeAssert.Equal(expected, process(true, k, n, a, p), "encrypt");
            SmokeAssert.Equal(p, process(false, k, n, a, expected), "decrypt");

            byte[] tampered = (byte[])expected.Clone();
            tampered[tampered.Length - 1] ^= 0x01;
            Exception e = SmokeAssert.Throws<Exception>(() => process(false, k, n, a, tampered), "flipped tag bit");
            SmokeAssert.True(tamperException.IsInstanceOfType(e), "flipped tag bit: expected "
                + tamperException.Name + ", got " + e.GetType().Name + ": " + e.Message);
        }

        // Both constructions: BasicGcmMultiplier passed explicitly (decision G), and GcmBlockCipher(engine) as
        // BcTlsCrypto builds it, whose default multiplier E14 makes BasicGcmMultiplier.
        private static void CheckGcm(string key, string nonce, string aad, string plain, string sealedHex)
        {
            Check(GcmBasic, typeof(InvalidCipherTextException), key, nonce, aad, plain, sealedHex);
            Check(GcmDefault, typeof(InvalidCipherTextException), key, nonce, aad, plain, sealedHex);
        }

#pragma warning disable CS0618 // BasicGcmMultiplier and this constructor are [Obsolete] upstream
        private static byte[] GcmBasic(bool encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) =>
            Gcm(new GcmBlockCipher(new AesLightEngine(), new BasicGcmMultiplier()), encrypt, key, nonce, aad, input);
#pragma warning restore CS0618

        private static byte[] GcmDefault(bool encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input) =>
            Gcm(new GcmBlockCipher(new AesLightEngine()), encrypt, key, nonce, aad, input);

        private static byte[] Gcm(GcmBlockCipher cipher, bool encrypt, byte[] key, byte[] nonce, byte[] aad,
            byte[] input)
        {
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce, aad));
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            len += cipher.DoFinal(output, len);
            SmokeAssert.Equal(output.Length, len, "output length");
            return output;
        }

        private static byte[] ChaCha20Poly1305(bool encrypt, byte[] key, byte[] nonce, byte[] aad, byte[] input)
        {
            var cipher = new BcChaCha20Poly1305(encrypt);
            cipher.SetKey(key, 0, key.Length);
            cipher.Init(nonce, 16, aad);
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int len = cipher.DoFinal(input, 0, input.Length, output, 0);
            SmokeAssert.Equal(output.Length, len, "output length");
            return output;
        }
    }
}
