// Copyright (c) 2026 fatal10110 and contributors. Licensed under the MIT License.
// Regression checks for strip-v2 edge cut E6 (STRIP_PLAN_V2.md §3 E6, §5 step 5 curve lookup) until the smoke
// suite exists.

using System;
using System.Linq;

using NUnit.Framework;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.GM;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Math.EC.Custom.Sec;

namespace Org.BouncyCastle.Turbo.Tests
{
    [TestFixture]
    public class NamedCurvesE6Test
    {
        private static readonly object[] KeptCurves =
        {
            new object[] { "secp256r1", "P-256", SecObjectIdentifiers.SecP256r1, typeof(SecP256R1Curve), 256 },
            new object[] { "secp384r1", "P-384", SecObjectIdentifiers.SecP384r1, typeof(SecP384R1Curve), 384 },
            new object[] { "secp521r1", "P-521", SecObjectIdentifiers.SecP521r1, typeof(SecP521R1Curve), 521 },
        };

        // ECGost3410NamedCurves "GostR3410-2001-CryptoPro-A", CryptoProObjectIdentifiers.GostR3410x2001CryptoProA.
        private const string GostName = "GostR3410-2001-CryptoPro-A";
        private static readonly DerObjectIdentifier GostOid = new DerObjectIdentifier("1.2.643.2.2.35.1");

        [TestCaseSource(nameof(KeptCurves))]
        public void CustomNamedCurvesResolvesByNameAliasAndOid(
            string name, string alias, DerObjectIdentifier oid, Type curveType, int bits)
        {
            Assert.AreEqual(oid, CustomNamedCurves.GetOid(name));
            Assert.AreEqual(oid, CustomNamedCurves.GetOid(alias));
            Assert.AreEqual(name, CustomNamedCurves.GetName(oid));

            X9ECParameters byOid = CustomNamedCurves.GetByOid(oid);
            Assert.IsNotNull(byOid);
            Assert.IsInstanceOf(curveType, byOid.Curve);
            Assert.AreEqual(bits, byOid.Curve.FieldSize);

            X9ECParameters byName = CustomNamedCurves.GetByName(name);
            Assert.IsNotNull(byName);
            Assert.IsInstanceOf(curveType, byName.Curve);
        }

        [TestCaseSource(nameof(KeptCurves))]
        public void DomainParametersLookupResolvesCustomCurve(
            string name, string alias, DerObjectIdentifier oid, Type curveType, int bits)
        {
            foreach (string n in new[] { name, alias })
            {
                ECDomainParameters byName = ECDomainParameters.LookupName(n);
                Assert.IsInstanceOf<ECNamedDomainParameters>(byName, n);
                Assert.AreEqual(oid, ((ECNamedDomainParameters)byName).Name, n);
                Assert.IsInstanceOf(curveType, byName.Curve, n);
            }

            ECNamedDomainParameters byOid = ECNamedDomainParameters.LookupOid(oid);
            Assert.AreEqual(oid, byOid.Name);
            Assert.IsInstanceOf(curveType, byOid.Curve);
            Assert.AreEqual(bits, byOid.Curve.FieldSize);
            Assert.IsTrue(byOid.G.IsValid());
        }

        [Test]
        public void CustomNamedCurvesHasNoBinaryOrSm2Entries()
        {
            string[] names = CustomNamedCurves.Names.ToArray();
            CollectionAssert.Contains(names, "secp256r1");
            Assert.IsEmpty(names.Where(n => n.StartsWith("sect", StringComparison.OrdinalIgnoreCase)
                || n.StartsWith("B-", StringComparison.Ordinal) || n.StartsWith("K-", StringComparison.Ordinal)
                || n.Equals("sm2p256v1", StringComparison.OrdinalIgnoreCase)));

            foreach (string n in new[] { "sect163k1", "sect571r1", "B-163", "B-571", "K-163", "K-571", "sm2p256v1" })
            {
                Assert.IsNull(CustomNamedCurves.GetOid(n), n);
                Assert.IsNull(CustomNamedCurves.GetByName(n), n);
            }
            Assert.IsNull(CustomNamedCurves.GetByOid(SecObjectIdentifiers.SecT163k1));
            Assert.IsNull(CustomNamedCurves.GetByOid(SecObjectIdentifiers.SecT571r1));
            Assert.IsNull(CustomNamedCurves.GetByOid(GMObjectIdentifiers.sm2p256v1));
        }

        [Test]
        public void EcNamedCurveTableHasNoGostEntries()
        {
            Assert.IsNull(ECNamedCurveTable.GetByName(GostName));
            Assert.IsNull(ECNamedCurveTable.GetByNameLazy(GostName));
            Assert.IsNull(ECNamedCurveTable.GetOid(GostName));
            Assert.IsNull(ECNamedCurveTable.GetByOid(GostOid));
            Assert.IsNull(ECNamedCurveTable.GetByOidLazy(GostOid));
            Assert.IsNull(ECNamedCurveTable.GetName(GostOid));
            CollectionAssert.DoesNotContain(ECNamedCurveTable.Names.ToArray(), GostName);
            Assert.Throws<ArgumentException>(() => ECNamedDomainParameters.LookupOid(GostOid));
        }

        [Test]
        public void SecTableStillAnswersBinaryCurvesWithGenericF2m()
        {
            // E6 cuts only the custom SecT* implementations; the generic SEC table entry stays (TurboKeyFactory
            // restricts the curves a peer key may use).
            ECDomainParameters dp = ECDomainParameters.LookupName("sect163k1");
            Assert.IsInstanceOf<F2mCurve>(dp.Curve);
            Assert.AreEqual(SecObjectIdentifiers.SecT163k1, ((ECNamedDomainParameters)dp).Name);
        }
    }
}
