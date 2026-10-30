// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E14 (STRIP_PLAN_V2.md §2 G, §3 E14) until the smoke suite exists.
// Run with DOTNET_EnableAES=0 DOTNET_EnablePCLMULQDQ=0 to exercise the non-accelerated branches on net6.0.

using System;
using System.Reflection;

using NUnit.Framework;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Modes.Gcm;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.Utilities.Encoders;

#pragma warning disable CS0618 // BasicGcmMultiplier is [Obsolete("Will be removed")] upstream

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class GcmAesE14Test
    {
        // McGrew-Viega GCM test cases (copied from crypto/test/src/crypto/test/GCMTest.cs):
        // name, key, plaintext, aad, iv, ciphertext, tag.
        private static readonly string[][] TestVectors =
        {
            new[]
            {
                "Test Case 1",
                "00000000000000000000000000000000",
                "",
                "",
                "000000000000000000000000",
                "",
                "58e2fccefa7e3061367f1d57a4e7455a",
            },
            new[]
            {
                "Test Case 2",
                "00000000000000000000000000000000",
                "00000000000000000000000000000000",
                "",
                "000000000000000000000000",
                "0388dace60b6a392f328c2b971b2fe78",
                "ab6e47d42cec13bdf53a67b21257bddf",
            },
            new[]
            {
                "Test Case 3",
                "feffe9928665731c6d6a8f9467308308",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255",
                "",
                "cafebabefacedbaddecaf888",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
                "4d5c2af327cd64a62cf35abd2ba6fab4",
            },
            new[]
            {
                "Test Case 4",
                "feffe9928665731c6d6a8f9467308308",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                "cafebabefacedbaddecaf888",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
                + "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            },
            new[]
            {
                "Test Case 16",
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
                + "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
                "feedfacedeadbeeffeedfacedeadbeefabaddad2",
                "cafebabefacedbaddecaf888",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
                + "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            },
        };

        private sealed class AesProbe : BcTlsCrypto
        {
            public IBlockCipher Aes() => CreateAesEngine();
        }

        [Test]
        public void CreateGcmMultiplierIsAlwaysBasic()
        {
            Assert.That(GcmBlockCipher.CreateGcmMultiplier(), Is.TypeOf<BasicGcmMultiplier>());
        }

        [Test]
        public void DefaultGcmBlockCipherUsesBasicMultiplier()
        {
            // BcTlsCrypto.CreateGcmMode builds GCM with the one-argument constructor.
            FieldInfo field = typeof(GcmBlockCipher).GetField("multiplier",
                BindingFlags.Instance | BindingFlags.NonPublic);
            Assert.That(field, Is.Not.Null);

            var gcm = new GcmBlockCipher(new AesLightEngine());
            Assert.That(field.GetValue(gcm), Is.TypeOf<BasicGcmMultiplier>());
        }

        [Test]
        public void TlsAesEngineIsLightWithoutHardwareAes()
        {
            IBlockCipher engine = new AesProbe().Aes();
            if (AesUtilities.IsHardwareAccelerated)
            {
                Assert.That(engine, Is.TypeOf(AesUtilities.CreateEngine().GetType()));
                Assert.That(engine, Is.Not.TypeOf<AesLightEngine>());
            }
            else
            {
                Assert.That(engine, Is.TypeOf<AesLightEngine>());
            }
        }

        [Test]
        public void GcmKatLightEngineBasicMultiplier()
        {
            foreach (string[] v in TestVectors)
            {
                RunKat(v, () => new GcmBlockCipher(new AesLightEngine()));
            }
        }

        [Test]
        public void GcmKatTlsAesEngineDefaultMultiplier()
        {
            var probe = new AesProbe();
            foreach (string[] v in TestVectors)
            {
                RunKat(v, () => new GcmBlockCipher(probe.Aes()));
            }
        }

        private static void RunKat(string[] v, Func<GcmBlockCipher> create)
        {
            string name = v[0];
            byte[] key = Hex.Decode(v[1]);
            byte[] pt = Hex.Decode(v[2]);
            byte[] aad = Hex.Decode(v[3]);
            byte[] iv = Hex.Decode(v[4]);
            byte[] expected = Arrays.Concatenate(Hex.Decode(v[5]), Hex.Decode(v[6]));
            var parameters = new AeadParameters(new KeyParameter(key), 128, iv, aad);

            byte[] ct = Process(create(), true, parameters, pt);
            Assert.That(Hex.ToHexString(ct), Is.EqualTo(Hex.ToHexString(expected)), name + " encrypt");

            byte[] decrypted = Process(create(), false, parameters, ct);
            Assert.That(Hex.ToHexString(decrypted), Is.EqualTo(v[2]), name + " decrypt");

            byte[] tampered = Arrays.Clone(ct);
            tampered[tampered.Length - 1] ^= 0x01;
            Assert.Throws<InvalidCipherTextException>(() => Process(create(), false, parameters, tampered),
                name + " tampered tag");
        }

        private static byte[] Process(GcmBlockCipher gcm, bool forEncryption, AeadParameters parameters,
            byte[] input)
        {
            gcm.Init(forEncryption, parameters);
            byte[] output = new byte[gcm.GetOutputSize(input.Length)];
            int len = gcm.ProcessBytes(input, 0, input.Length, output, 0);
            len += gcm.DoFinal(output, len);
            Assert.That(len, Is.EqualTo(output.Length));
            return output;
        }
    }
}
