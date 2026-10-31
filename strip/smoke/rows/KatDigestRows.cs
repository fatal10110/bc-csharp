using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Macs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;

namespace TurboSmoke
{
    /// <summary>
    /// #24: SHA-256/384/512 (FIPS 180 "abc" and two-block vectors; crypto/test SHA*DigestTest.cs) and HMAC-SHA-2
    /// (RFC 4231 test case 2; crypto/test SHA*HMacTest.cs).
    /// </summary>
    public sealed class KatDigestRows : SmokeRowGroup
    {
        public override string Name => "kat-digest";
        public override int Order => 10;

        private delegate IDigest DigestFactory();

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("sha256", () =>
            {
                CheckDigest(() => new Sha256Digest(), "abc",
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
                CheckDigest(() => new Sha256Digest(), "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                    "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
            });
            rows.Add("sha384", () => CheckDigest(() => new Sha384Digest(), "abc",
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed"
                + "8086072ba1e7cc2358baeca134c825a7"));
            rows.Add("sha512", () => CheckDigest(() => new Sha512Digest(), "abc",
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"));
            rows.Add("hmac-sha256", () => CheckHmac(() => new Sha256Digest(),
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"));
            rows.Add("hmac-sha384", () => CheckHmac(() => new Sha384Digest(),
                "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e"
                + "8e2240ca5e69e2c78b3239ecfab21649"));
            rows.Add("hmac-sha512", () => CheckHmac(() => new Sha512Digest(),
                "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                + "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"));
        }

        private static void CheckDigest(DigestFactory factory, string message, string expected)
        {
            IDigest digest = factory();
            byte[] input = Encoding.ASCII.GetBytes(message);
            digest.BlockUpdate(input, 0, input.Length);
            byte[] output = new byte[digest.GetDigestSize()];
            digest.DoFinal(output, 0);
            SmokeAssert.Equal(SmokeHex.Decode(expected), output, digest.AlgorithmName + "(\"" + message + "\")");
        }

        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        private static void CheckHmac(DigestFactory factory, string expected)
        {
            var mac = new HMac(factory());
            mac.Init(new KeyParameter(Encoding.ASCII.GetBytes("Jefe")));
            byte[] data = Encoding.ASCII.GetBytes("what do ya want for nothing?");
            mac.BlockUpdate(data, 0, data.Length);
            byte[] output = new byte[mac.GetMacSize()];
            mac.DoFinal(output, 0);
            SmokeAssert.Equal(SmokeHex.Decode(expected), output, mac.AlgorithmName);
        }
    }
}
