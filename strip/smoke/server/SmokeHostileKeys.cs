using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.EdEC;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.TeleTrust;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Utilities;

namespace TurboSmoke
{
    /// <summary>
    /// #26: one SubjectPublicKeyInfo the client's key factory (E5 TurboKeyFactory, reached through E8
    /// X509Certificate.GetPublicKey and E5 BcTlsRawKeyCertificate) must accept or reject. Built with the upstream
    /// BASE library on first use; only bytes and plain values leave here.
    /// </summary>
    public sealed class SmokeKeyCase
    {
        private readonly Lazy<byte[]> _spki;

        internal SmokeKeyCase(string id, string rejectReason, Func<byte[]> spki, bool inCertificate = true)
        {
            Id = id;
            RejectReason = rejectReason;
            InCertificate = inCertificate;
            _spki = new Lazy<byte[]>(spki);
        }

        /// <summary>Row id suffix.</summary>
        public string Id { get; }

        /// <summary>Null when the key must be accepted; else a substring of the factory's ArgumentException
        /// message ("" when the message is not pinned).</summary>
        public string RejectReason { get; }

        /// <summary>False for encodings that are not a SubjectPublicKeyInfo at all (garbage, trailing data): they
        /// cannot sit inside a certificate, so only TurboKeyFactory.CreateKey(byte[]) sees them.</summary>
        public bool InCertificate { get; }

        /// <summary>Expected modulus size of an accepted RSA key, else 0.</summary>
        public int ModulusBits { get; internal set; }

        /// <summary>Expected public exponent (hex) of an accepted RSA key.</summary>
        public string ExponentHex { get; internal set; }

        /// <summary>Expected named-curve OID of an accepted EC key, else null.</summary>
        public string CurveOid { get; internal set; }

        /// <summary>Whether the accepted EC point is in compressed form.</summary>
        public bool Compressed { get; internal set; }

        /// <summary>The DER (or deliberately broken) SubjectPublicKeyInfo.</summary>
        public byte[] SpkiDer => (byte[])_spki.Value.Clone();

        /// <summary>The subjectPublicKey BIT STRING contents (EC: the point encoding).</summary>
        public byte[] PublicKeyOctets =>
            SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(_spki.Value)).PublicKey.GetOctets();

        /// <summary>A certificate carrying <see cref="SpkiDer"/>, with a garbage signature (decision A).</summary>
        public byte[] CertificateDer => SmokeHostileCertificates.Certificate(
            SubjectPublicKeyInfo.GetInstance(Asn1Object.FromByteArray(_spki.Value)), SmokeHostileKeys.Sha256WithRsa);
    }

    /// <summary>
    /// #26: the key table ported from the E5 NUnit fixture (crypto/test/src/turbo/TurboKeyFactoryTest.cs, PR #40)
    /// as listed on #26: RSA size, exponent, structure and OID; EC curve, parameter form and point encoding; other
    /// algorithms and broken encodings. The fixture runs only against the full library; these run against every
    /// stripped TurboBC.&lt;set&gt;.dll.
    /// </summary>
    public static class SmokeHostileKeys
    {
        internal static readonly AlgorithmIdentifier Sha256WithRsa =
            new AlgorithmIdentifier(PkcsObjectIdentifiers.Sha256WithRsaEncryption, DerNull.Instance);

        private const string ModulusSize = "RSA modulus size out of range";
        private const string Exponent = "RSA public exponent out of range";
        private const string Algorithm = "Unsupported public key algorithm";
        private const string Curve = "Unsupported EC curve";
        private const string NamedCurve = "EC parameters must be a named curve";
        private const string PointEncoding = "Unsupported EC point encoding";
        private const string Unpinned = "";

        private static readonly BigInteger E65537 = BigInteger.ValueOf(65537);

        /// <summary>2^64 + 1: 65 bits, odd.</summary>
        private static readonly BigInteger E65Bits = BigInteger.One.ShiftLeft(64).Add(BigInteger.One);

        /// <summary>Every case, in row order.</summary>
        public static IReadOnlyList<SmokeKeyCase> Cases { get; } = Build();

        private static List<SmokeKeyCase> Build()
        {
            DerObjectIdentifier rsa = PkcsObjectIdentifiers.RsaEncryption;
            DerObjectIdentifier pss = PkcsObjectIdentifiers.IdRsassaPss;
            DerObjectIdentifier p256 = SecObjectIdentifiers.SecP256r1;
            DerObjectIdentifier p384 = SecObjectIdentifiers.SecP384r1;
            DerObjectIdentifier p521 = SecObjectIdentifiers.SecP521r1;
            var cases = new List<SmokeKeyCase>
            {
                // --- RSA accepted (8192, e = 3, 64-bit e and the TLS rows live in HostileRows) ---
                RsaAccepted("rsa-2048-accepted", rsa, 2048),
                RsaAccepted("rsa-4096-accepted", rsa, 4096),
                RsaAccepted("rsa-pss-oid-2048-accepted", pss, 2048),
                RsaAccepted("rsa-pss-oid-4096-accepted", pss, 4096),
                // E7 turns Miller-Rabin off for peer moduli (RsaMaxMRTests = 0), so a prime modulus without small
                // factors is accepted: this row pins that decision (RFC 3526 group 14 prime, 2048 bits).
                new SmokeKeyCase("rsa-prime-modulus-accepted-e7", null,
                    () => RsaSpki(rsa, DHStandardGroups.rfc3526_2048.P, E65537))
                {
                    ModulusBits = 2048,
                    ExponentHex = "010001",
                },

                // --- RSA rejected ---
                RsaRejected("rsa-2047-rejected", rsa, Odd(2047), E65537, ModulusSize),
                RsaRejected("rsa-pss-oid-1024-rejected", pss, Odd(1024), E65537, ModulusSize),
                RsaRejected("rsa-pss-oid-e65bit-rejected", pss, Odd(2048), E65Bits, Exponent),
                RsaRejected("rsa-e1-rejected", rsa, Odd(2048), BigInteger.One, Exponent),
                RsaRejected("rsa-even-e-rejected", rsa, Odd(2048), BigInteger.ValueOf(65536),
                    "RSA publicExponent is even"),
                RsaRejected("rsa-even-n-rejected", rsa, () => OddModulus(2048).ClearBit(0), E65537,
                    "RSA modulus is even"),
                // 3 * (odd 2046-bit value with the top two bits set): an odd 2048-bit modulus with the factor 3.
                RsaRejected("rsa-small-factor-n-rejected", rsa,
                    () => BigInteger.Three.Multiply(SmokeHostileCertificates.OddModulus(2046, 8).SetBit(2044)), E65537,
                    "RSA modulus has a small prime factor"),
                RsaRejected("rsa-oaep-oid-rejected", PkcsObjectIdentifiers.IdRsaesOaep, Odd(2048), E65537, Algorithm),
                RsaRejected("rsa-idearsa-oid-rejected", X509ObjectIdentifiers.IdEARsa, Odd(2048), E65537, Algorithm),
                new SmokeKeyCase("rsa-malformed-key-rejected", Unpinned,
                    () => Spki(RsaAlgID(rsa), new byte[] { 0x30, 0x03, 0x02, 0x01 })),
                new SmokeKeyCase("rsa-wrong-shape-key-rejected", Unpinned,
                    () => Spki(RsaAlgID(rsa), new DerSequence(new DerInteger(OddModulus(2048))).GetEncoded())),

                // --- EC accepted (SecP256r1 and X9 prime256v1 are the same OID, 1.2.840.10045.3.1.7) ---
                ECAccepted("ec-p256-accepted", p256, false),
                ECAccepted("ec-p256-compressed-accepted", p256, true),
                ECAccepted("ec-p384-accepted", p384, false),
                ECAccepted("ec-p384-compressed-accepted", p384, true),
                ECAccepted("ec-p521-accepted", p521, false),
                ECAccepted("ec-p521-compressed-accepted", p521, true),

                // --- EC rejected: curve and parameter form ---
                ECRejected("ec-secp256k1-rejected", SecObjectIdentifiers.SecP256k1,
                    () => Point(SecObjectIdentifiers.SecP256k1).GetEncoded(false), Curve),
                ECRejected("ec-p224-rejected", SecObjectIdentifiers.SecP224r1,
                    () => Point(SecObjectIdentifiers.SecP224r1).GetEncoded(false), Curve),
                ECRejected("ec-brainpoolp256r1-rejected", TeleTrusTObjectIdentifiers.BrainpoolP256R1,
                    () => Point(TeleTrusTObjectIdentifiers.BrainpoolP256R1).GetEncoded(false), Curve),
                new SmokeKeyCase("ec-implicitlyca-rejected", NamedCurve, () => Spki(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, DerNull.Instance), P256Point())),
                new SmokeKeyCase("ec-missing-parameters-rejected", "EC parameters missing", () => Spki(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey), P256Point())),
                // specifiedCurve over a composite 1100-bit "prime" field: rejected on the raw parameter, before any
                // curve construction or primality test on the attacker-chosen field.
                new SmokeKeyCase("ec-explicit-composite-field-rejected", NamedCurve, ExplicitCompositeFieldSpki),

                // --- EC rejected: point ---
                ECRejected("ec-off-curve-point-rejected", p256, () =>
                {
                    byte[] point = P256Point();
                    point[point.Length - 1] ^= 1;
                    return point;
                }, Unpinned),
                ECRejected("ec-infinity-point-rejected", p256, () => new byte[] { 0x00 }, PointEncoding),
                ECRejected("ec-empty-point-rejected", p256, () => new byte[0], PointEncoding),
                ECRejected("ec-hybrid-06-point-rejected", p256, () => Hybrid(0x06), PointEncoding),
                ECRejected("ec-hybrid-07-point-rejected", p256, () => Hybrid(0x07), PointEncoding),
                ECRejected("ec-truncated-point-rejected", p384,
                    () => Arrays.CopyOf(Point(p384).GetEncoded(false), 96), Unpinned),
                ECRejected("ec-p384-point-as-p256-rejected", p256, () => Point(p384).GetEncoded(false), Unpinned),

                // --- other algorithms and broken encodings ---
                new SmokeKeyCase("ed25519-rejected", Algorithm, Ed25519Spki),
                new SmokeKeyCase("dsa-rejected", Algorithm, () => Spki(
                    new AlgorithmIdentifier(X9ObjectIdentifiers.IdDsa), new DerInteger(OddModulus(2048)).GetEncoded())),
                new SmokeKeyCase("dh-rejected", Algorithm, () => Spki(
                    new AlgorithmIdentifier(PkcsObjectIdentifiers.DhKeyAgreement),
                    new DerInteger(OddModulus(2048)).GetEncoded())),
                new SmokeKeyCase("garbage-der-rejected", "Malformed SubjectPublicKeyInfo",
                    () => new byte[] { 0x30, 0x82, 0xFF, 0xFF, 0x00 }, inCertificate: false),
                new SmokeKeyCase("trailing-data-rejected", Unpinned,
                    () => Arrays.Append(RsaSpki(rsa, OddModulus(2048), E65537), 0x00), inCertificate: false),
            };
            return cases;
        }

        /// <summary>A certificate with the Ed25519 key of <see cref="Ed25519Spki"/>.</summary>
        public static byte[] Ed25519Certificate() => SmokeHostileCertificates.Certificate(
            SubjectPublicKeyInfo.GetInstance(Ed25519Spki()), Sha256WithRsa);

        /// <summary>A certificate with a valid secp256k1 point on its namedCurve OID.</summary>
        public static byte[] Secp256k1Certificate() => SmokeHostileCertificates.Certificate(
            SubjectPublicKeyInfo.GetInstance(ECSpki(SecObjectIdentifiers.SecP256k1,
                Point(SecObjectIdentifiers.SecP256k1).GetEncoded(false))), Sha256WithRsa);

        private static SmokeKeyCase RsaAccepted(string id, DerObjectIdentifier oid, int bits) =>
            new SmokeKeyCase(id, null, () => RsaSpki(oid, OddModulus(bits), E65537))
            {
                ModulusBits = bits,
                ExponentHex = "010001",
            };

        private static SmokeKeyCase RsaRejected(string id, DerObjectIdentifier oid, Func<BigInteger> n,
            BigInteger e, string reason) => new SmokeKeyCase(id, reason, () => RsaSpki(oid, n(), e));

        private static SmokeKeyCase ECAccepted(string id, DerObjectIdentifier curve, bool compressed) =>
            new SmokeKeyCase(id, null, () => ECSpki(curve, Point(curve).GetEncoded(compressed)))
            {
                CurveOid = curve.Id,
                Compressed = compressed,
            };

        private static SmokeKeyCase ECRejected(string id, DerObjectIdentifier curve, Func<byte[]> point,
            string reason) => new SmokeKeyCase(id, reason, () => ECSpki(curve, point()));

        private static Func<BigInteger> Odd(int bits) => () => OddModulus(bits);

        private static BigInteger OddModulus(int bits) => SmokeHostileCertificates.OddModulus(bits, 1);

        private static AlgorithmIdentifier RsaAlgID(DerObjectIdentifier oid) =>
            PkcsObjectIdentifiers.RsaEncryption.Equals(oid)
                ? new AlgorithmIdentifier(oid, DerNull.Instance)
                : new AlgorithmIdentifier(oid);

        private static byte[] RsaSpki(DerObjectIdentifier oid, BigInteger n, BigInteger e) =>
            Spki(RsaAlgID(oid), new DerSequence(new DerInteger(n), new DerInteger(e)).GetEncoded());

        private static byte[] ECSpki(DerObjectIdentifier curve, byte[] point) =>
            Spki(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, curve), point);

        private static byte[] Spki(AlgorithmIdentifier algorithm, byte[] publicKey) =>
            new SubjectPublicKeyInfo(algorithm, publicKey).GetEncoded(Asn1Encodable.Der);

        /// <summary>A fixed valid point on the named curve: [12345]G.</summary>
        private static ECPoint Point(DerObjectIdentifier curve) =>
            ECNamedCurveTable.GetByOid(curve).G.Multiply(BigInteger.ValueOf(12345)).Normalize();

        private static byte[] P256Point() => Point(SecObjectIdentifiers.SecP256r1).GetEncoded(false);

        /// <summary>X9.62 hybrid form (RFC 5480 2.2: MUST NOT be used) with the given type octet.</summary>
        private static byte[] Hybrid(byte type)
        {
            byte[] point = P256Point();
            point[0] = type;
            return point;
        }

        private static byte[] ExplicitCompositeFieldSpki()
        {
            BigInteger q = BigInteger.One.ShiftLeft(1100).Subtract(BigInteger.One);
            byte[] fe = new byte[(q.BitLength + 7) / 8];
            var specifiedCurve = new DerSequence(
                new DerInteger(1),
                new DerSequence(X9ObjectIdentifiers.PrimeField, new DerInteger(q)),
                new DerSequence(new DerOctetString(fe), new DerOctetString(fe)),
                new DerOctetString(Arrays.Prepend(fe, 0x02)),
                new DerInteger(q));
            return Spki(new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, specifiedCurve), P256Point());
        }

        /// <summary>A valid Ed25519 public key (from the all-zero seed).</summary>
        private static byte[] Ed25519Spki() =>
            Spki(new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                new Ed25519PrivateKeyParameters(new byte[32]).GeneratePublicKey().GetEncoded());
    }
}
