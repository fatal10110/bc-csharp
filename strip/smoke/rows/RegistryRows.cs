using System.Linq;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X9;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;

namespace TurboSmoke
{
    /// <summary>
    /// #58: the static constructors of the kept name/OID registries that no other row reaches through public API.
    /// DigestUtilities (reached on the client path through X509Utilities, SubjectKeyIdentifier and
    /// X509ExtensionUtil; E11 edited it) runs map self-checks under #if DEBUG that throw, so a cut that breaks its
    /// maps fails only in Unity Editor and Development builds: strip.sh runs this group against the DEBUG build
    /// (TurboBC.ns21-debug.dll) as well as every release build. ECNamedCurveTable is the other registry the
    /// client path consults by name.
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
