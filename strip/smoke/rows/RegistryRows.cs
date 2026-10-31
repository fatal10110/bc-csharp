using System;
using System.Linq;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X9;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.X509;

namespace TurboSmoke
{
    /// <summary>
    /// #58: the static constructors of the kept name/OID registries that no other row reaches through public API.
    /// DigestUtilities (reached on the client path through X509Utilities, SubjectKeyIdentifier and
    /// X509ExtensionUtil; E11 edited it) runs map self-checks under #if DEBUG that throw, so a cut that breaks its
    /// maps fails only in Unity Editor and Development builds: strip.sh runs this group against the DEBUG build
    /// (TurboBC.ns21-debug.dll) as well as every release build. ECNamedCurveTable is the other registry the
    /// client path consults by name. TurboSignatureNames (E8) is the static table behind X509Certificate.SigAlgName
    /// and ToString().
    /// </summary>
    public sealed class RegistryRows : SmokeRowGroup
    {
        public override string Name => "registries";
        public override int Order => 5;

        private const string Sha256Oid = "2.16.840.1.101.3.4.2.1";

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("digest-utilities", () =>
            {
                IDigest byName = DigestUtilities.GetDigest("SHA-256");
                SmokeAssert.Equal("SHA-256", byName.AlgorithmName, "DigestUtilities.GetDigest(\"SHA-256\")");
                DerObjectIdentifier oid = DigestUtilities.GetObjectIdentifier("SHA-256");
                SmokeAssert.NotNull(oid, "DigestUtilities.GetObjectIdentifier(\"SHA-256\")");
                SmokeAssert.Equal(Sha256Oid, oid.Id, "DigestUtilities.GetObjectIdentifier(\"SHA-256\")");
                SmokeAssert.Equal("SHA-256", DigestUtilities.GetAlgorithmName(oid), "DigestUtilities.GetAlgorithmName");
                // FIPS 180 "abc" vector through the OID path (the one X509Utilities.CalculateDigest takes).
                byte[] digest = DigestUtilities.CalculateDigest(new DerObjectIdentifier(Sha256Oid),
                    Encoding.ASCII.GetBytes("abc"));
                SmokeAssert.Equal(SmokeHex.Decode("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
                    digest, "DigestUtilities.CalculateDigest(SHA-256, \"abc\")");
            });
            rows.Add("x509-sig-alg-name", () =>
            {
                foreach (var (oid, name) in new[]
                {
                    ("1.2.840.113549.1.1.11", "SHA-256withRSA"),
                    ("1.2.840.10045.4.3.2", "SHA-256withECDSA"),
                    ("1.2.3.4", "1.2.3.4"), // unknown OID: dotted string
                })
                {
                    var cert = new X509Certificate(SmokeHostileKeys.P256CertificateSignedWith(oid));
                    SmokeAssert.Equal(name, cert.SigAlgName, "SigAlgName for " + oid);
                }
                // Rejected subject key: ToString prints a placeholder instead of throwing (E8).
                string text = new X509Certificate(SmokeHostileKeys.Secp256k1Certificate()).ToString();
                SmokeAssert.True(text.Contains("<unsupported key>"), "ToString lacks <unsupported key>: " + text);
                SmokeAssert.True(text.Contains("SHA-256withRSA"), "ToString lacks SHA-256withRSA: " + text);
                // A key TurboKeyFactory rejects by wrapping a parse failure (non-zero EC point pad bits) prints the
                // same placeholder.
                string padBits = new X509Certificate(SmokeNegotiationServers.PadBitsCertificate(1, false)).ToString();
                SmokeAssert.True(padBits.Contains("<unsupported key>"), "ToString lacks <unsupported key>: " + padBits);
            });
            // Decision A (E8): BC never verifies certificate signatures; chain validation is turboHTTP's (platform
            // verifiers). Pinned on the shipped DLL so a bump that restores verification fails here.
            rows.Add("x509-verify-not-supported", () =>
            {
                var cert = new X509Certificate(SmokeHostileKeys.P256CertificateSignedWith("1.2.840.10045.4.3.2"));
                AsymmetricKeyParameter key = cert.GetPublicKey();
                SmokeAssert.NotNull(key, "GetPublicKey of the P-256 certificate");
                SmokeAssert.Throws<NotSupportedException>(() => cert.Verify(key), "Verify(key)");
                SmokeAssert.Throws<NotSupportedException>(() => cert.IsSignatureValid(key), "IsSignatureValid(key)");
                SmokeAssert.Throws<NotSupportedException>(() => cert.Verify((IVerifierFactoryProvider)null),
                    "Verify(provider)");
                SmokeAssert.Throws<NotSupportedException>(() => cert.IsSignatureValid((IVerifierFactoryProvider)null),
                    "IsSignatureValid(provider)");
                SmokeAssert.Throws<NotSupportedException>(() => cert.VerifyAltSignature(null), "VerifyAltSignature");
            });
            rows.Add("ec-named-curve-table", () =>
            {
                var names = ECNamedCurveTable.Names.ToList();
                foreach (string name in new[] { "secp256r1", "secp384r1", "secp521r1" })
                {
                    SmokeAssert.True(names.Contains(name), "ECNamedCurveTable.Names lacks " + name);
                    DerObjectIdentifier oid = ECNamedCurveTable.GetOid(name);
                    SmokeAssert.NotNull(oid, "ECNamedCurveTable.GetOid(" + name + ")");
                    // GetName answers the first registry's name (X9.62 prime256v1 for secp256r1): round-trip it.
                    string registered = ECNamedCurveTable.GetName(oid);
                    SmokeAssert.NotNull(registered, "ECNamedCurveTable.GetName(" + oid.Id + ")");
                    SmokeAssert.Equal(oid.Id, ECNamedCurveTable.GetOid(registered).Id,
                        "ECNamedCurveTable.GetOid(" + registered + ")");
                    SmokeAssert.NotNull(ECNamedCurveTable.GetByOid(oid), "ECNamedCurveTable.GetByOid(" + name + ")");
                }
            });
        }
    }
}
