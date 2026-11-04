using System.Linq;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Sec;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X9;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.EC;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;

namespace TurboSmoke
{
    /// <summary>
    /// #24: curve lookup by name and OID through public API only, first of all rows. A registry whose static
    /// initializer throws after the E6 trims (CustomNamedCurves.DefineCurveAlias on a removed curve) fails here
    /// instead of at the first TLS handshake.
    /// </summary>
    public sealed class CurveLookupRows : SmokeRowGroup
    {
        public override string Name => "curves";
        public override int Order => 0;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("registry", () =>
            {
                var names = CustomNamedCurves.Names.ToList();
                foreach (string name in new[] { "secp256r1", "secp384r1", "secp521r1" })
                {
                    SmokeAssert.True(names.Contains(name), "CustomNamedCurves.Names lacks " + name);
                }
            });
            rows.Add("secp256r1", () => Check("secp256r1", "P-256", SecObjectIdentifiers.SecP256r1, 256,
                "SecP256R1Curve"));
            rows.Add("secp384r1", () => Check("secp384r1", "P-384", SecObjectIdentifiers.SecP384r1, 384,
                "SecP384R1Curve"));
            rows.Add("secp521r1", () => Check("secp521r1", "P-521", SecObjectIdentifiers.SecP521r1, 521,
                "SecP521R1Curve"));
        }

        private static void Check(string name, string nistName, DerObjectIdentifier expectedOid, int bits,
            string curveType)
        {
            DerObjectIdentifier oid = CustomNamedCurves.GetOid(name);
            SmokeAssert.NotNull(oid, "CustomNamedCurves.GetOid(" + name + ")");
            SmokeAssert.Equal(expectedOid.Id, oid.Id, "CustomNamedCurves.GetOid(" + name + ")");
            SmokeAssert.Equal(name, CustomNamedCurves.GetName(oid), "CustomNamedCurves.GetName");

            X9ECParameters byName = CustomNamedCurves.GetByName(name);
            SmokeAssert.NotNull(byName, "CustomNamedCurves.GetByName(" + name + ")");
            X9ECParameters byOid = CustomNamedCurves.GetByOid(oid);
            SmokeAssert.NotNull(byOid, "CustomNamedCurves.GetByOid");
            X9ECParameters byAlias = CustomNamedCurves.GetByName(nistName);
            SmokeAssert.NotNull(byAlias, "CustomNamedCurves.GetByName(" + nistName + ")");
            foreach (X9ECParameters x9 in new[] { byOid, byAlias })
            {
                SmokeAssert.True(x9.Curve.Equals(byName.Curve) && x9.G.Equals(byName.G) && x9.N.Equals(byName.N),
                    name + ": lookups by name, OID and alias disagree");
            }
            SmokeAssert.Equal(curveType, byName.Curve.GetType().Name, name + " curve implementation");
            SmokeAssert.Equal(bits, byName.Curve.FieldSize, name + " field size");
            SmokeAssert.True(byName.G.IsValid(), name + ": generator not on the curve");

            foreach (string lookup in new[] { name, nistName })
            {
                ECDomainParameters dp = ECDomainParameters.LookupName(lookup);
                var named = dp as ECNamedDomainParameters;
                SmokeAssert.True(named != null, "ECDomainParameters.LookupName(" + lookup + ") is not named");
                SmokeAssert.Equal(expectedOid.Id, named.Name.Id, "ECDomainParameters.LookupName(" + lookup + ")");
                SmokeAssert.True(dp.Curve.Equals(byName.Curve), "ECDomainParameters.LookupName(" + lookup + ") curve");
            }

            ECNamedDomainParameters byLookupOid = ECNamedDomainParameters.LookupOid(oid);
            SmokeAssert.True(byLookupOid.Curve.Equals(byName.Curve) && byLookupOid.N.Equals(byName.N),
                "ECNamedDomainParameters.LookupOid(" + oid.Id + ")");
        }
    }
}
