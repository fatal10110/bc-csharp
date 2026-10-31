using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto.Impl.BC;

namespace TurboSmoke
{
    /// <summary>
    /// #24: TLS 1.3 key schedule through BcTlsCrypto (HkdfInit, HkdfExtract, TlsCryptoUtilities.HkdfExpandLabel):
    /// the server-side secrets of the RFC 8448 section 3 trace (crypto/test tls/crypto/test BcTlsCryptoTest.cs
    /// TestHkdf), the transcript hashes taken from the trace.
    /// </summary>
    public sealed class KatTlsHkdfRows : SmokeRowGroup
    {
        public override string Name => "kat-tls13-hkdf";
        public override int Order => 10;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("rfc8448-key-schedule", KeySchedule);
        }

        private static void KeySchedule()
        {
            var crypto = new BcTlsCrypto(new SecureRandom());
            int hash = CryptoHashAlgorithm.sha256;
            int hashLen = TlsCryptoUtilities.GetHashOutputSize(hash);

            byte[] emptyHash = crypto.CreateHash(hash).CalculateHash();
            Expect(emptyHash, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "Hash(\"\")");

            TlsSecret early = crypto.HkdfInit(hash).HkdfExtract(hash, crypto.HkdfInit(hash));
            Expect(crypto, early, "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", "early secret");

            TlsSecret derived = TlsCryptoUtilities.HkdfExpandLabel(early, hash, "derived", emptyHash, hashLen);
            Expect(crypto, derived, "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
                "derived (handshake)");

            TlsSecret ecdhe = crypto.CreateSecret(
                SmokeHex.Decode("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"));
            TlsSecret handshake = derived.HkdfExtract(hash, ecdhe);
            Expect(crypto, handshake, "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
                "handshake secret");

            byte[] helloHash = SmokeHex.Decode("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
            TlsSecret cHs = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, "c hs traffic", helloHash, hashLen);
            Expect(crypto, cHs, "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
                "client handshake traffic secret");
            TlsSecret sHs = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, "s hs traffic", helloHash, hashLen);
            Expect(crypto, sHs, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
                "server handshake traffic secret");

            TlsSecret masterDerived = TlsCryptoUtilities.HkdfExpandLabel(handshake, hash, "derived", emptyHash,
                hashLen);
            Expect(crypto, masterDerived, "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4",
                "derived (master)");
            TlsSecret master = masterDerived.HkdfExtract(hash, crypto.HkdfInit(hash));
            Expect(crypto, master, "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
                "master secret");

            Expect(crypto, TlsCryptoUtilities.HkdfExpandLabel(sHs, hash, "key", TlsUtilities.EmptyBytes, 16),
                "3fce516009c21727d0f2e4e86ee403bc", "server handshake key");
            Expect(crypto, TlsCryptoUtilities.HkdfExpandLabel(sHs, hash, "iv", TlsUtilities.EmptyBytes, 12),
                "5d313eb2671276ee13000b30", "server handshake iv");
        }

        // AdoptSecret copies, so the original stays usable for the next derivation.
        private static void Expect(TlsCrypto crypto, TlsSecret secret, string hex, string what) =>
            Expect(crypto.AdoptSecret(secret).Extract(), hex, what);

        private static void Expect(byte[] actual, string hex, string what) =>
            SmokeAssert.Equal(SmokeHex.Decode(hex), actual, what);
    }
}
