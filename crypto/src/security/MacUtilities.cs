using System;
using System.Collections.Generic;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Iana;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Rosstandart;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Engines;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Macs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Paddings;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Collections;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Utility class for creating HMac object from their names/Oids
    /// </remarks>
    public static class MacUtilities
    {
        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static MacUtilities()
        {
            AlgorithmOidMap[IanaObjectIdentifiers.HmacMD5] = "HMAC-MD5";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacRipeMD160] = "HMAC-RIPEMD160";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacSha1] = "HMAC-SHA1";
            AlgorithmOidMap[IanaObjectIdentifiers.HmacTiger] = "HMAC-TIGER";

            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha1] = "HMAC-SHA1";

            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha224] = "HMAC-SHA224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha256] = "HMAC-SHA256";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha384] = "HMAC-SHA384";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512] = "HMAC-SHA512";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_224] = "HMAC-SHA512-224";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdHmacWithSha512_256] = "HMAC-SHA512-256";

            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_224] = "HMAC-SHA3-224";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_256] = "HMAC-SHA3-256";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_384] = "HMAC-SHA3-384";
            AlgorithmOidMap[NistObjectIdentifiers.IdHMacWithSha3_512] = "HMAC-SHA3-512";



            // TODO AESMAC?








            AlgorithmMap["PBEWITHHMACSHA"] = "PBEWITHHMACSHA1";
            AlgorithmOidMap[OiwObjectIdentifiers.IdSha1] = "PBEWITHHMACSHA1";

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

        public static byte[] CalculateMac(string algorithm, ICipherParameters cp, byte[] input)
        {
            IMac mac = GetMac(algorithm);
            mac.Init(cp);
            mac.BlockUpdate(input, 0, input.Length);
            return DoFinal(mac);
        }

        public static byte[] DoFinal(IMac mac)
        {
            byte[] b = new byte[mac.GetMacSize()];
            mac.DoFinal(b, 0);
            return b;
        }

        public static byte[] DoFinal(IMac mac, byte[] input)
        {
            mac.BlockUpdate(input, 0, input.Length);
            return DoFinal(mac);
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

        // TODO[api] Change parameter name to 'oid'
        public static IMac GetMac(DerObjectIdentifier id)
        {
            if (id == null)
                throw new ArgumentNullException(nameof(id));

            if (AlgorithmOidMap.TryGetValue(id, out var mechanism))
            {
                var mac = GetMacForMechanism(mechanism);
                if (mac != null)
                    return mac;
            }

            throw new SecurityUtilityException("Mac OID not recognised.");
        }

        public static IMac GetMac(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var mac = GetMacForMechanism(mechanism);
            if (mac != null)
                return mac;

            throw new SecurityUtilityException("Mac " + algorithm + " not recognised.");
        }

        private static IMac GetMacForMechanism(string mechanism)
        {
            if (Platform.StartsWith(mechanism, "PBEWITH"))
            {
                mechanism = mechanism.Substring("PBEWITH".Length);
            }

            if (Platform.StartsWith(mechanism, "HMAC"))
            {
                string digestName;
                if (Platform.StartsWith(mechanism, "HMAC-") || Platform.StartsWith(mechanism, "HMAC/"))
                {
                    digestName = mechanism.Substring(5);
                }
                else
                {
                    digestName = mechanism.Substring(4);
                }

                return new HMac(DigestUtilities.GetDigest(digestName));
            }

            if (mechanism == "AESCMAC")
            {
                return new CMac(AesUtilities.CreateEngine());
            }


            return null;
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
    }
}
