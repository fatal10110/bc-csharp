// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E1 (STRIP_PLAN_V2.md §3 E1, §5 step 5) until the smoke suite exists.

using System;
using System.Collections.Generic;
using System.IO;

using NUnit.Framework;

using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class BcTlsCryptoE1Test
    {
        // STRIP_PLAN_V2.md §5 step 5: the exact, ordered signature_algorithms list.
        private static readonly SignatureAndHashAlgorithm[] ExpectedSigAlgs =
        {
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa),
            SignatureAndHashAlgorithm.rsa_pss_pss_sha256,
            SignatureAndHashAlgorithm.rsa_pss_pss_sha384,
            SignatureAndHashAlgorithm.rsa_pss_pss_sha512,
            SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
            SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
            SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.rsa),
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha384, SignatureAlgorithm.rsa),
            SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
        };

        private static readonly int[] AllowedGroups =
        {
            NamedGroup.x25519, NamedGroup.secp256r1, NamedGroup.secp384r1, NamedGroup.secp521r1,
        };

        // Copy of TlsUtilities.CreateDefaultSupportedSigAlgs (private) at BASE, in order.
        private static IList<SignatureAndHashAlgorithm> UpstreamDefaultSigAlgs()
        {
            return new List<SignatureAndHashAlgorithm>
            {
                SignatureAndHashAlgorithm.ed25519,
                SignatureAndHashAlgorithm.ed448,
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.ecdsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha384, SignatureAlgorithm.ecdsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha512, SignatureAlgorithm.ecdsa),
                SignatureAndHashAlgorithm.rsa_pss_pss_sha256,
                SignatureAndHashAlgorithm.rsa_pss_pss_sha384,
                SignatureAndHashAlgorithm.rsa_pss_pss_sha512,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha256,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha384,
                SignatureAndHashAlgorithm.rsa_pss_rsae_sha512,
                SignatureAndHashAlgorithm.mldsa44,
                SignatureAndHashAlgorithm.mldsa65,
                SignatureAndHashAlgorithm.mldsa87,
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.rsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha384, SignatureAlgorithm.rsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha512, SignatureAlgorithm.rsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.dsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha384, SignatureAlgorithm.dsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha512, SignatureAlgorithm.dsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha224, SignatureAlgorithm.ecdsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha224, SignatureAlgorithm.rsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha224, SignatureAlgorithm.dsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha1, SignatureAlgorithm.ecdsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha1, SignatureAlgorithm.rsa),
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha1, SignatureAlgorithm.dsa),
            };
        }

        private sealed class E1Client
            : DefaultTlsClient
        {
            internal E1Client(TlsCrypto crypto)
                : base(crypto)
            {
            }

            public override TlsAuthentication GetAuthentication() => throw new NotSupportedException();
        }

        private static ClientHello CaptureClientHello(TlsCrypto crypto)
        {
            TlsClientProtocol protocol = new TlsClientProtocol();
            protocol.Connect(new E1Client(crypto));

            byte[] output = new byte[protocol.GetAvailableOutputBytes()];
            protocol.ReadOutput(output, 0, output.Length);

            // One handshake record: record header (5), handshake header (4), ClientHello body.
            Assert.AreEqual(ContentType.handshake, output[0]);
            Assert.AreEqual(HandshakeType.client_hello, output[5]);
            int bodyLength = (output[6] << 16) | (output[7] << 8) | output[8];
            byte[] body = Arrays.CopyOfRange(output, 9, 9 + bodyLength);

            return ClientHello.Parse(new MemoryStream(body, false), null);
        }

        [Test]
        public void DefaultSigAlgsFilterToPlanList()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            var filtered = new List<SignatureAndHashAlgorithm>();
            foreach (SignatureAndHashAlgorithm alg in UpstreamDefaultSigAlgs())
            {
                TlsUtilities.AddIfSupported(filtered, crypto, alg);
            }

            CollectionAssert.AreEqual(ExpectedSigAlgs, filtered);
        }

        [Test]
        public void ClientHelloSignatureAlgorithmsAndGroups()
        {
            ClientHello clientHello = CaptureClientHello(new BcTlsCrypto());

            var sigAlgs = TlsExtensionsUtilities.GetSignatureAlgorithmsExtension(clientHello.Extensions);
            CollectionAssert.AreEqual(ExpectedSigAlgs, sigAlgs);

            int[] groups = TlsExtensionsUtilities.GetSupportedGroupsExtension(clientHello.Extensions);
            Assert.IsNotNull(groups);
            CollectionAssert.IsSubsetOf(groups, AllowedGroups);
            CollectionAssert.Contains(groups, NamedGroup.x25519);
            CollectionAssert.Contains(groups, NamedGroup.secp256r1);
        }

        [Test]
        public void SignatureAndHashWhitelist()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            short[] rejectedHashes = { HashAlgorithm.md5, HashAlgorithm.sha1, HashAlgorithm.sha224 };
            foreach (short hash in rejectedHashes)
            {
                Assert.IsFalse(crypto.HasSignatureAndHashAlgorithm(
                    SignatureAndHashAlgorithm.GetInstance(hash, SignatureAlgorithm.rsa)), "rsa hash " + hash);
                Assert.IsFalse(crypto.HasSignatureAndHashAlgorithm(
                    SignatureAndHashAlgorithm.GetInstance(hash, SignatureAlgorithm.ecdsa)), "ecdsa hash " + hash);
            }

            SignatureAndHashAlgorithm[] rejected =
            {
                SignatureAndHashAlgorithm.ed25519,
                SignatureAndHashAlgorithm.ed448,
                SignatureAndHashAlgorithm.mldsa44,
                SignatureAndHashAlgorithm.mldsa65,
                SignatureAndHashAlgorithm.mldsa87,
                SignatureAndHashAlgorithm.ecdsa_brainpoolP256r1tls13_sha256,
                SignatureAndHashAlgorithm.ecdsa_brainpoolP384r1tls13_sha384,
                SignatureAndHashAlgorithm.ecdsa_brainpoolP512r1tls13_sha512,
                SignatureAndHashAlgorithm.GetInstance(HashAlgorithm.sha256, SignatureAlgorithm.dsa),
                SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.slhdsa_sha2_128s),
                SignatureScheme.GetSignatureAndHashAlgorithm(SignatureScheme.sm2sig_sm3),
            };
            foreach (SignatureAndHashAlgorithm alg in rejected)
            {
                Assert.IsFalse(crypto.HasSignatureAndHashAlgorithm(alg), alg.ToString());
            }
        }

        [Test]
        public void SignatureAlgorithmsAndSchemes()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            short[] kept =
            {
                SignatureAlgorithm.rsa, SignatureAlgorithm.ecdsa,
                SignatureAlgorithm.rsa_pss_rsae_sha256, SignatureAlgorithm.rsa_pss_rsae_sha384,
                SignatureAlgorithm.rsa_pss_rsae_sha512, SignatureAlgorithm.rsa_pss_pss_sha256,
                SignatureAlgorithm.rsa_pss_pss_sha384, SignatureAlgorithm.rsa_pss_pss_sha512,
            };
            foreach (short alg in kept)
            {
                Assert.IsTrue(crypto.HasSignatureAlgorithm(alg), "kept " + alg);
            }

            short[] dropped =
            {
                SignatureAlgorithm.dsa, SignatureAlgorithm.ed25519, SignatureAlgorithm.ed448,
                SignatureAlgorithm.ecdsa_brainpoolP256r1tls13_sha256,
                SignatureAlgorithm.ecdsa_brainpoolP384r1tls13_sha384,
                SignatureAlgorithm.ecdsa_brainpoolP512r1tls13_sha512,
            };
            foreach (short alg in dropped)
            {
                Assert.IsFalse(crypto.HasSignatureAlgorithm(alg), "dropped " + alg);
            }

            int[] droppedSchemes =
            {
                SignatureScheme.mldsa44, SignatureScheme.mldsa65, SignatureScheme.mldsa87,
                SignatureScheme.slhdsa_sha2_128s, SignatureScheme.slhdsa_sha2_256f,
                SignatureScheme.slhdsa_shake_128s, SignatureScheme.slhdsa_shake_256f,
                SignatureScheme.sm2sig_sm3, SignatureScheme.ed25519, SignatureScheme.ed448,
            };
            foreach (int scheme in droppedSchemes)
            {
                Assert.IsFalse(crypto.HasSignatureScheme(scheme), "scheme " + scheme);
            }

            int[] keptSchemes =
            {
                SignatureScheme.ecdsa_secp256r1_sha256, SignatureScheme.rsa_pss_rsae_sha256,
                SignatureScheme.rsa_pss_pss_sha512, SignatureScheme.rsa_pkcs1_sha256,
            };
            foreach (int scheme in keptSchemes)
            {
                Assert.IsTrue(crypto.HasSignatureScheme(scheme), "scheme " + scheme);
            }

            int[] droppedCrypto =
            {
                CryptoSignatureAlgorithm.dsa, CryptoSignatureAlgorithm.ed25519, CryptoSignatureAlgorithm.ed448,
                CryptoSignatureAlgorithm.sm2,
            };
            foreach (int alg in droppedCrypto)
            {
                Assert.IsFalse(crypto.HasCryptoSignatureAlgorithm(alg), "crypto sig " + alg);
            }
            Assert.IsTrue(crypto.HasCryptoSignatureAlgorithm(CryptoSignatureAlgorithm.rsa));
            Assert.IsTrue(crypto.HasCryptoSignatureAlgorithm(CryptoSignatureAlgorithm.ecdsa));
            Assert.IsTrue(crypto.HasCryptoSignatureAlgorithm(CryptoSignatureAlgorithm.rsa_pss_pss_sha384));
        }

        [Test]
        public void EncryptionAlgorithms()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            Assert.IsTrue(crypto.HasEncryptionAlgorithm(EncryptionAlgorithm.AES_128_GCM));
            Assert.IsTrue(crypto.HasEncryptionAlgorithm(EncryptionAlgorithm.AES_256_GCM));
            Assert.IsTrue(crypto.HasEncryptionAlgorithm(EncryptionAlgorithm.CHACHA20_POLY1305));

            int[] dropped =
            {
                EncryptionAlgorithm.AES_128_CBC, EncryptionAlgorithm.AES_256_CBC, EncryptionAlgorithm.AES_128_CCM,
                EncryptionAlgorithm.AES_128_CCM_8, EncryptionAlgorithm.AES_256_CCM, EncryptionAlgorithm.AES_256_CCM_8,
                EncryptionAlgorithm.ARIA_128_CBC, EncryptionAlgorithm.ARIA_128_GCM, EncryptionAlgorithm.ARIA_256_GCM,
                EncryptionAlgorithm.CAMELLIA_128_CBC, EncryptionAlgorithm.CAMELLIA_256_GCM,
                EncryptionAlgorithm.cls_3DES_EDE_CBC, EncryptionAlgorithm.NULL, EncryptionAlgorithm.NULL_HMAC_SHA256,
                EncryptionAlgorithm.NULL_HMAC_SHA384, EncryptionAlgorithm.SEED_CBC, EncryptionAlgorithm.SM4_CBC,
                EncryptionAlgorithm.SM4_CCM, EncryptionAlgorithm.SM4_GCM, EncryptionAlgorithm.RC4_128,
            };
            foreach (int alg in dropped)
            {
                Assert.IsFalse(crypto.HasEncryptionAlgorithm(alg), "encryption " + alg);
            }
        }

        [Test]
        public void NamedGroups()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            foreach (int group in AllowedGroups)
            {
                Assert.IsTrue(crypto.HasNamedGroup(group), "group " + group);
            }

            int[] dropped =
            {
                NamedGroup.x448, NamedGroup.secp224r1, NamedGroup.secp256k1, NamedGroup.brainpoolP256r1,
                NamedGroup.brainpoolP256r1tls13, NamedGroup.curveSM2, NamedGroup.ffdhe2048, NamedGroup.ffdhe8192,
                NamedGroup.MLKEM512, NamedGroup.MLKEM768, NamedGroup.MLKEM1024, NamedGroup.X25519MLKEM768,
                NamedGroup.SecP256r1MLKEM768, NamedGroup.SecP384r1MLKEM1024,
            };
            foreach (int group in dropped)
            {
                Assert.IsFalse(crypto.HasNamedGroup(group), "group " + group);
                Assert.IsFalse(TlsUtilities.IsSupportedNamedGroup(crypto, group), "supported group " + group);
            }
        }

        [Test]
        public void KeyExchangeCapabilities()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            Assert.IsTrue(crypto.HasECDHAgreement());
            Assert.IsFalse(crypto.HasRsaEncryption());
            Assert.IsFalse(crypto.HasDHAgreement());
            Assert.IsFalse(crypto.HasKemAgreement());
            Assert.IsFalse(crypto.HasSrpAuthentication());

            Assert.Throws<TlsFatalAlert>(() => crypto.CreateDHDomain(null));
            Assert.Throws<TlsFatalAlert>(() => crypto.CreateKemDomain(null));
            Assert.Throws<TlsFatalAlert>(() => crypto.CreateSrp6Client(null));
            Assert.Throws<TlsFatalAlert>(() => crypto.CreateSrp6Server(null, null));
            Assert.Throws<TlsFatalAlert>(() => crypto.CreateSrp6VerifierGenerator(null));
        }

        [Test]
        public void GostDigestRemoved()
        {
            BcTlsCrypto crypto = new BcTlsCrypto();

            Assert.IsFalse(crypto.HasCryptoHashAlgorithm(CryptoHashAlgorithm.gostr3411_2012_256));
            Assert.Throws<ArgumentException>(() => crypto.CreateDigest(CryptoHashAlgorithm.gostr3411_2012_256));
            Assert.IsTrue(crypto.HasCryptoHashAlgorithm(CryptoHashAlgorithm.sha256));
        }
    }
}
