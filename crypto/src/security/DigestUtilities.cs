using System;
using System.Collections.Generic;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.CryptoPro;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.GM;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Rosstandart;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.TeleTrust;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.UA;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Collections;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating IDigest objects from their names/Oids
    /// </remarks>
    public static class DigestUtilities
    {
        private enum DigestAlgorithm {

        };

        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();
        private static readonly Dictionary<string, DerObjectIdentifier> Oids =
            new Dictionary<string, DerObjectIdentifier>(StringComparer.OrdinalIgnoreCase);

        static DigestUtilities()
        {
            // Signal to obfuscation tools not to change enum constants
            Enums.GetArbitraryValue<DigestAlgorithm>().ToString();

            AlgorithmOidMap[PkcsObjectIdentifiers.MD2] = "MD2";
            AlgorithmOidMap[PkcsObjectIdentifiers.MD4] = "MD4";
            AlgorithmOidMap[PkcsObjectIdentifiers.MD5] = "MD5";

            AlgorithmMap["SHA1"] = "SHA-1";
            AlgorithmOidMap[OiwObjectIdentifiers.IdSha1] = "SHA-1";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha1] = "SHA-1";

            AlgorithmMap["SHA224"] = "SHA-224";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha224] = "SHA-224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha224] = "SHA-224";
            AlgorithmMap["SHA256"] = "SHA-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha256] = "SHA-256";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha256] = "SHA-256";
            AlgorithmMap["SHA384"] = "SHA-384";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha384] = "SHA-384";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha384] = "SHA-384";
            AlgorithmMap["SHA512"] = "SHA-512";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha512] = "SHA-512";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512] = "SHA-512";

            AlgorithmMap["SHA512/224"] = "SHA-512/224";
            AlgorithmMap["SHA512-224"] = "SHA-512/224";
            AlgorithmMap["SHA512(224)"] = "SHA-512/224";
            AlgorithmMap["SHA-512(224)"] = "SHA-512/224";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha512_224] = "SHA-512/224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_224] = "SHA-512/224";
            AlgorithmMap["SHA512/256"] = "SHA-512/256";
            AlgorithmMap["SHA512-256"] = "SHA-512/256";
            AlgorithmMap["SHA512(256)"] = "SHA-512/256";
            AlgorithmMap["SHA-512(256)"] = "SHA-512/256";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha512_256] = "SHA-512/256";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_256] = "SHA-512/256";

            AlgorithmMap["RIPEMD-128"] = "RIPEMD128";
            AlgorithmOidMap[TeleTrusTObjectIdentifiers.RipeMD128] = "RIPEMD128";
            AlgorithmMap["RIPEMD-160"] = "RIPEMD160";
            AlgorithmOidMap[TeleTrusTObjectIdentifiers.RipeMD160] = "RIPEMD160";
            AlgorithmMap["RIPEMD-256"] = "RIPEMD256";
            AlgorithmOidMap[TeleTrusTObjectIdentifiers.RipeMD256] = "RIPEMD256";
            AlgorithmMap["RIPEMD-320"] = "RIPEMD320";
            //AlgorithmOidMap[TeleTrusTObjectIdentifiers.RipeMD320] = "RIPEMD320";

            AlgorithmOidMap[CryptoProObjectIdentifiers.GostR3411] = "GOST3411";

            AlgorithmMap["KECCAK224"] = "KECCAK-224";
            AlgorithmMap["KECCAK256"] = "KECCAK-256";
            AlgorithmMap["KECCAK288"] = "KECCAK-288";
            AlgorithmMap["KECCAK384"] = "KECCAK-384";
            AlgorithmMap["KECCAK512"] = "KECCAK-512";

            AlgorithmOidMap[NistObjectIdentifiers.IdSha3_224] = "SHA3-224";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_224] = "SHA3-224";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha3_256] = "SHA3-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_256] = "SHA3-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha3_384] = "SHA3-384";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_384] = "SHA3-384";
            AlgorithmOidMap[NistObjectIdentifiers.IdSha3_512] = "SHA3-512";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_512] = "SHA3-512";
            AlgorithmMap["SHAKE128"] = "SHAKE128-256";
            AlgorithmMap["SHAKE-128"] = "SHAKE128-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdShake128] = "SHAKE128-256";
            AlgorithmMap["SHAKE256"] = "SHAKE256-512";
            AlgorithmMap["SHAKE-256"] = "SHAKE256-512";
            AlgorithmOidMap[NistObjectIdentifiers.IdShake256] = "SHAKE256-512";

            AlgorithmOidMap[GMObjectIdentifiers.sm3] = "SM3";



            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256] = "GOST3411-2012-256";
            AlgorithmOidMap[RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512] = "GOST3411-2012-512";

            AlgorithmOidMap[UAObjectIdentifiers.dstu7564digest_256] = "DSTU7564-256";
            AlgorithmOidMap[UAObjectIdentifiers.dstu7564digest_384] = "DSTU7564-384";
            AlgorithmOidMap[UAObjectIdentifiers.dstu7564digest_512] = "DSTU7564-512";

            Oids["MD2"] = PkcsObjectIdentifiers.MD2;
            Oids["MD4"] = PkcsObjectIdentifiers.MD4;
            Oids["MD5"] = PkcsObjectIdentifiers.MD5;
            Oids["SHA-1"] = OiwObjectIdentifiers.IdSha1;
            Oids["SHA-224"] = NistObjectIdentifiers.IdSha224;
            Oids["SHA-256"] = NistObjectIdentifiers.IdSha256;
            Oids["SHA-384"] = NistObjectIdentifiers.IdSha384;
            Oids["SHA-512"] = NistObjectIdentifiers.IdSha512;
            Oids["SHA-512/224"] = NistObjectIdentifiers.IdSha512_224;
            Oids["SHA-512/256"] = NistObjectIdentifiers.IdSha512_256;
            Oids["SHA3-224"] = NistObjectIdentifiers.IdSha3_224;
            Oids["SHA3-256"] = NistObjectIdentifiers.IdSha3_256;
            Oids["SHA3-384"] = NistObjectIdentifiers.IdSha3_384;
            Oids["SHA3-512"] = NistObjectIdentifiers.IdSha3_512;
            Oids["SHAKE128-256"] = NistObjectIdentifiers.IdShake128;
            Oids["SHAKE256-512"] = NistObjectIdentifiers.IdShake256;
            Oids["RIPEMD128"] = TeleTrusTObjectIdentifiers.RipeMD128;
            Oids["RIPEMD160"] = TeleTrusTObjectIdentifiers.RipeMD160;
            Oids["RIPEMD256"] = TeleTrusTObjectIdentifiers.RipeMD256;
            Oids["GOST3411"] = CryptoProObjectIdentifiers.GostR3411;
            Oids["SM3"] = GMObjectIdentifiers.sm3;

            Oids["GOST3411-2012-256"] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_256;
            Oids["GOST3411-2012-512"] = RosstandartObjectIdentifiers.id_tc26_gost_3411_12_512;
            Oids["DSTU7564-256"] = UAObjectIdentifiers.dstu7564digest_256;
            Oids["DSTU7564-384"] = UAObjectIdentifiers.dstu7564digest_384;
            Oids["DSTU7564-512"] = UAObjectIdentifiers.dstu7564digest_512;

#if DEBUG
            foreach (var key in AlgorithmMap.Keys)
            {
                if (DerObjectIdentifier.TryFromID(key, out var ignore))
                    throw new Exception("OID mapping belongs in AlgorithmOidMap: " + key);
            }

            var mechanisms = new HashSet<string>(AlgorithmMap.Values);
            mechanisms.UnionWith(AlgorithmOidMap.Values);

            foreach (var mechanism in mechanisms)
            {
                if (AlgorithmMap.TryGetValue(mechanism, out var check))
                {
                    if (mechanism != check)
                        throw new Exception("Mechanism mapping MUST be to self: " + mechanism);
                }
                else
                {
                    if (!mechanism.Equals(mechanism.ToUpperInvariant()))
                        throw new Exception("Unmapped mechanism MUST be uppercase: " + mechanism);
                }
            }
#endif
        }

        // TODO[api] Change parameter name to 'oid'
        public static byte[] CalculateDigest(DerObjectIdentifier id, byte[] input)
        {
            return CalculateDigest(id.Id, input);
        }

        public static byte[] CalculateDigest(string algorithm, byte[] input)
        {
            IDigest digest = GetDigest(algorithm);
            return DoFinal(digest, input);
        }

        public static byte[] CalculateDigest(string algorithm, byte[] buf, int off, int len)
        {
            IDigest digest = GetDigest(algorithm);
            return DoFinal(digest, buf, off, len);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static byte[] CalculateDigest(DerObjectIdentifier oid, ReadOnlySpan<byte> buffer) =>
            CalculateDigest(oid.GetID(), buffer);

        public static byte[] CalculateDigest(string algorithm, ReadOnlySpan<byte> buffer)
        {
            IDigest digest = GetDigest(algorithm);
            return DoFinal(digest, buffer);
        }
#endif

        public static byte[] DoFinal(IDigest digest)
        {
            byte[] b = new byte[digest.GetDigestSize()];
            digest.DoFinal(b, 0);
            return b;
        }

        public static byte[] DoFinal(IDigest digest, byte[] input)
        {
            digest.BlockUpdate(input, 0, input.Length);
            return DoFinal(digest);
        }

        public static byte[] DoFinal(IDigest digest, byte[] buf, int off, int len)
        {
            digest.BlockUpdate(buf, off, len);
            return DoFinal(digest);
        }

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public static byte[] DoFinal(IDigest digest, ReadOnlySpan<byte> buffer)
        {
            digest.BlockUpdate(buffer);
            return DoFinal(digest);
        }
#endif

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

        // TODO[api] Change parameter name to 'oid'
        public static IDigest GetDigest(DerObjectIdentifier id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            if (AlgorithmOidMap.TryGetValue(id, out var mechanism))
            {
                var digest = GetDigestForMechanism(mechanism);
                if (digest != null)
                    return digest;
            }

            throw new SecurityUtilityException("Digest OID not recognised.");
        }

        public static IDigest GetDigest(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var digest = GetDigestForMechanism(mechanism);
            if (digest != null)
                return digest;

            throw new SecurityUtilityException("Digest " + algorithm + " not recognised.");
        }

        private static IDigest GetDigestForMechanism(string mechanism)
        {
            if (!Enums.TryGetEnumValue<DigestAlgorithm>(mechanism, out var digestAlgorithm))
                return null;

            switch (digestAlgorithm)
            {

            default:
                throw new NotImplementedException();
            }
        }

        private static string GetMechanism(string algorithm)
        {
            if (AlgorithmMap.TryGetValue(algorithm, out var mechanism1))
                return mechanism1;

            if (DerObjectIdentifier.TryFromID(algorithm, out var oid))
            {
                if (AlgorithmOidMap.TryGetValue(oid, out var mechanism2))
                    return mechanism2;
            }

            return null;
        }

        /// <summary>
        /// Returns an ObjectIdentifier for a given digest mechanism.
        /// </summary>
        /// <param name="mechanism">A string representation of the digest meanism.</param>
        /// <returns>A DerObjectIdentifier, null if the Oid is not available.</returns>
        public static DerObjectIdentifier GetObjectIdentifier(string mechanism)
        {
            if (mechanism == null)
                throw new ArgumentNullException(nameof(mechanism));

            mechanism = GetMechanism(mechanism) ?? mechanism;

            return CollectionUtilities.GetValueOrNull(Oids, mechanism);
        }
    }
}
