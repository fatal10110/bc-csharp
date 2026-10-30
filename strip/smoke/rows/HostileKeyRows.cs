using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Turbo;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// #26: the E5 key table (SmokeHostileKeys, ported from crypto/test/src/turbo/TurboKeyFactoryTest.cs) against
    /// the stripped DLL. An accepted key must come out of TurboKeyFactory.CreateKey and X509Certificate.GetPublicKey
    /// with the expected modulus/exponent or curve/point. A rejected key must throw exactly ArgumentException from
    /// both, with the factory's reason when pinned: a removed curve table or registry in the strip would surface as
    /// another exception type or reason. One TLS row per family that the key rows do not already cover over TLS
    /// (another curve, another algorithm) must end in unsupported_certificate.
    /// </summary>
    public sealed partial class HostileRows
    {
        private static void AddKeyRows(SmokeRows rows)
        {
            foreach (SmokeKeyCase key in SmokeHostileKeys.Cases)
            {
                SmokeKeyCase k = key;
                Add(rows, "key-" + k.Id, () => AssertKeyCase(k));
            }
            Add(rows, "key-ec-secp256k1-tls13-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, SmokeHostileKeys.Secp256k1Certificate(), true));
            Add(rows, "key-ec-secp256k1-tls12-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, SmokeHostileKeys.Secp256k1Certificate(), false));
            Add(rows, "key-ed25519-tls13-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, SmokeHostileKeys.Ed25519Certificate(), true));
            Add(rows, "key-ed25519-tls12-rejected",
                () => AssertKeyRejectedOverTls(P256.Value, SmokeHostileKeys.Ed25519Certificate(), false));
        }

        private static void AssertKeyCase(SmokeKeyCase k)
        {
            if (k.RejectReason != null)
            {
                ArgumentException e = SmokeAssert.Throws<ArgumentException>(
                    () => TurboKeyFactory.CreateKey(k.SpkiDer), "TurboKeyFactory.CreateKey");
                SmokeAssert.Equal(typeof(ArgumentException).FullName, e.GetType().FullName, "exception type");
                SmokeAssert.True(e.Message.Contains(k.RejectReason, StringComparison.Ordinal),
                    "reason '" + k.RejectReason + "', got '" + e.Message + "'");
                if (k.InCertificate)
                {
                    AssertGetPublicKeyRejected(k.CertificateDer);
                }
                return;
            }

            AssertAcceptedKey(TurboKeyFactory.CreateKey(k.SpkiDer), k, "TurboKeyFactory.CreateKey");
            AssertAcceptedKey(new X509Certificate(k.CertificateDer).GetPublicKey(), k, "GetPublicKey");
        }

        private static void AssertAcceptedKey(object key, SmokeKeyCase k, string via)
        {
            if (k.ModulusBits != 0)
            {
                AssertRsaKey(key, k.ModulusBits, k.ExponentHex);
                return;
            }
            var ec = key as ECPublicKeyParameters;
            SmokeAssert.True(ec != null && !ec.IsPrivate, via + ": EC public key, got " + key?.GetType().Name);
            var named = ec.Parameters as ECNamedDomainParameters;
            SmokeAssert.True(named != null, via + ": named domain parameters, got " + ec.Parameters.GetType().Name);
            SmokeAssert.Equal(k.CurveOid, named.Name.Id, via + ": curve");
            SmokeAssert.Equal(k.PublicKeyOctets, ec.Q.GetEncoded(k.Compressed), via + ": point");
        }
    }
}
