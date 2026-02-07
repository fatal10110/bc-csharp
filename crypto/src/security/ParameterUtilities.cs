using System;
using System.Collections.Generic;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.CryptoPro;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Kisa;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nsri;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Ntt;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Collections;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Security
{
    public static class ParameterUtilities
    {
        private static readonly IDictionary<string, string> Algorithms =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly IDictionary<string, int> BasicIVSizes =
            new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        static ParameterUtilities()
        {
            AddAlgorithm("AES",
                "AESWRAP");
            AddAlgorithm("AES128",
                SecurityUtilities.WrongAes128,
                NistObjectIdentifiers.IdAes128Cbc,
                NistObjectIdentifiers.IdAes128Ccm,
                NistObjectIdentifiers.IdAes128Cfb,
                NistObjectIdentifiers.IdAes128Ecb,
                NistObjectIdentifiers.IdAes128Gcm,
                NistObjectIdentifiers.IdAes128Ofb,
                NistObjectIdentifiers.IdAes128Wrap,
                NistObjectIdentifiers.IdAes128WrapPad);
            AddAlgorithm("AES192",
                SecurityUtilities.WrongAes192,
                NistObjectIdentifiers.IdAes192Cbc,
                NistObjectIdentifiers.IdAes192Ccm,
                NistObjectIdentifiers.IdAes192Cfb,
                NistObjectIdentifiers.IdAes192Ecb,
                NistObjectIdentifiers.IdAes192Gcm,
                NistObjectIdentifiers.IdAes192Ofb,
                NistObjectIdentifiers.IdAes192Wrap,
                NistObjectIdentifiers.IdAes192WrapPad);
            AddAlgorithm("AES256",
                SecurityUtilities.WrongAes256,
                NistObjectIdentifiers.IdAes256Cbc,
                NistObjectIdentifiers.IdAes256Ccm,
                NistObjectIdentifiers.IdAes256Cfb,
                NistObjectIdentifiers.IdAes256Ecb,
                NistObjectIdentifiers.IdAes256Gcm,
                NistObjectIdentifiers.IdAes256Ofb,
                NistObjectIdentifiers.IdAes256Wrap,
                NistObjectIdentifiers.IdAes256WrapPad);


            AddBasicIVSizeEntries(8, "BLOWFISH", "CHACHA", "DES", "DESEDE", "DESEDE3", "SALSA20");
            AddBasicIVSizeEntries(12, "CHACHA7539");
            AddBasicIVSizeEntries(16, "AES", "AES128", "AES192", "AES256", "ARIA", "ARIA128", "ARIA192", "ARIA256",
                "CAMELLIA", "CAMELLIA128", "CAMELLIA192", "CAMELLIA256", "NOEKEON", "SEED", "SM4");

            // TODO These algorithms support an IV
            // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
            // "RIJNDAEL", "SKIPJACK", "TWOFISH"
        }

        private static void AddAlgorithm(string canonicalName, params object[] aliases)
        {
            Algorithms[canonicalName] = canonicalName;

            foreach (object alias in aliases)
            {
                Algorithms[alias.ToString()] = canonicalName;
            }
        }

        private static void AddBasicIVSizeEntries(int size, params string[] algorithms)
        {
            foreach (string algorithm in algorithms)
            {
                BasicIVSizes.Add(algorithm, size);
            }
        }

        public static string GetCanonicalAlgorithmName(string algorithm)
        {
            return CollectionUtilities.GetValueOrNull(Algorithms, algorithm);
        }

        public static KeyParameter CreateKeyParameter(DerObjectIdentifier algOid, byte[] keyBytes)
        {
            return CreateKeyParameter(algOid.Id, keyBytes, 0, keyBytes.Length);
        }

        public static KeyParameter CreateKeyParameter(string algorithm, byte[] keyBytes)
        {
            return CreateKeyParameter(algorithm, keyBytes, 0, keyBytes.Length);
        }

        public static KeyParameter CreateKeyParameter(
            DerObjectIdentifier algOid,
            byte[]				keyBytes,
            int					offset,
            int					length)
        {
            return CreateKeyParameter(algOid.Id, keyBytes, offset, length);
        }

        public static KeyParameter CreateKeyParameter(
            string	algorithm,
            byte[]	keyBytes,
            int		offset,
            int		length)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");



            return new KeyParameter(keyBytes, offset, length);
        }

        public static ICipherParameters GetCipherParameters(
            DerObjectIdentifier	algOid,
            ICipherParameters	key,
            Asn1Object			asn1Params)
        {
            return GetCipherParameters(algOid.Id, key, asn1Params);
        }

        public static ICipherParameters GetCipherParameters(
            string				algorithm,
            ICipherParameters	key,
            Asn1Object			asn1Params)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");



            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");

            Asn1OctetString iv = null;

            try
            {
                // TODO These algorithms support an IV
                // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
                // "RIJNDAEL", "SKIPJACK", "TWOFISH"

                int basicIVKeySize = FindBasicIVSize(canonical);
                if (basicIVKeySize != -1
                    || canonical == "RIJNDAEL" || canonical == "SKIPJACK" || canonical == "TWOFISH")
                {
                    iv = Asn1OctetString.GetInstance(asn1Params);
                }

            }
            catch (Exception e)
            {
                throw new ArgumentException("Could not process ASN.1 parameters", e);
            }

            if (iv != null)
            {
                return new ParametersWithIV(key, iv.GetOctets());
            }

            throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");
        }

        public static Asn1Encodable GenerateParameters(
            DerObjectIdentifier algID,
            SecureRandom		random)
        {
            return GenerateParameters(algID.Id, random);
        }

        public static Asn1Encodable GenerateParameters(
            string			algorithm,
            SecureRandom	random)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            string canonical = GetCanonicalAlgorithmName(algorithm);

            if (canonical == null)
                throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");

            // TODO These algorithms support an IV
            // but JCE doesn't seem to provide an AlgorithmParametersGenerator for them
            // "RIJNDAEL", "SKIPJACK", "TWOFISH"

            int basicIVKeySize = FindBasicIVSize(canonical);
            if (basicIVKeySize != -1)
                return CreateIVOctetString(random, basicIVKeySize);



            throw new SecurityUtilityException("Algorithm " + algorithm + " not recognised.");
        }

        public static ICipherParameters IgnoreRandom(ICipherParameters cipherParameters)
        {
            if (cipherParameters is ParametersWithRandom withRandom)
                return withRandom.Parameters;

            return cipherParameters;
        }

        public static ICipherParameters WithContext(ICipherParameters cp, byte[] context)
        {
            if (context != null)
            {
                cp = new ParametersWithContext(cp, context);
            }
            return cp;
        }

        public static ICipherParameters WithRandom(ICipherParameters cp, SecureRandom random)
        {
            if (random != null)
            {
                cp = new ParametersWithRandom(cp, random);
            }
            return cp;
        }

        private static Asn1OctetString CreateIVOctetString(SecureRandom random, int ivLength)
        {
            return new DerOctetString(CreateIV(random, ivLength));
        }

        private static byte[] CreateIV(SecureRandom random, int ivLength)
        {
            return SecureRandom.GetNextBytes(random, ivLength);
        }

        private static int FindBasicIVSize(string canonicalName)
        {
            return BasicIVSizes.TryGetValue(canonicalName, out int keySize) ? keySize : -1;
        }
    }
}
