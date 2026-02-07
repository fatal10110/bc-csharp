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
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Agreement;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Digests;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Encodings;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Engines;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Generators;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Macs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Modes;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Paddings;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Utilities.Collections;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Security
{
    /// <remarks>
    ///  Cipher Utility class contains methods that can not be specifically grouped into other classes.
    /// </remarks>
    public static class CipherUtilities
    {
        private enum CipherAlgorithm {
            AES,


        };

        private enum CipherMode { ECB, NONE, CBC, CCM, CFB, CTR, CTS, EAX, GCM, GOFB, OCB, OFB, OPENPGPCFB, SIC };
        private enum CipherPadding
        {
            NOPADDING,
            RAW,
            ISO10126PADDING,
            ISO10126D2PADDING,
            ISO10126_2PADDING,
            ISO7816_4PADDING,
            ISO9797_1PADDING,
            ISO9796_1,
            ISO9796_1PADDING,
            OAEP,
            OAEPPADDING,
            OAEPWITHMD5ANDMGF1PADDING,
            OAEPWITHSHA1ANDMGF1PADDING,
            OAEPWITHSHA_1ANDMGF1PADDING,
            OAEPWITHSHA224ANDMGF1PADDING,
            OAEPWITHSHA_224ANDMGF1PADDING,
            OAEPWITHSHA256ANDMGF1PADDING,
            OAEPWITHSHA_256ANDMGF1PADDING,
            OAEPWITHSHA256ANDMGF1WITHSHA256PADDING,
            OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING,
            OAEPWITHSHA256ANDMGF1WITHSHA1PADDING,
            OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING,
            OAEPWITHSHA384ANDMGF1PADDING,
            OAEPWITHSHA_384ANDMGF1PADDING,
            OAEPWITHSHA512ANDMGF1PADDING,
            OAEPWITHSHA_512ANDMGF1PADDING,
            PKCS1,
            PKCS1PADDING,
            PKCS5,
            PKCS5PADDING,
            PKCS7,
            PKCS7PADDING,
            TBCPADDING,
            WITHCTS,
            X923PADDING,
            ZEROBYTEPADDING,
        };

        private static readonly Dictionary<string, string> AlgorithmMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        private static readonly Dictionary<DerObjectIdentifier, string> AlgorithmOidMap =
            new Dictionary<DerObjectIdentifier, string>();

        static CipherUtilities()
        {
            // Signal to obfuscation tools not to change enum constants
            Enums.GetArbitraryValue<CipherAlgorithm>().ToString();
            Enums.GetArbitraryValue<CipherMode>().ToString();
            Enums.GetArbitraryValue<CipherPadding>().ToString();

            // TODO Flesh out the list of aliases

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Cbc] = "AES/CBC/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Cbc] = "AES/CBC/PKCS7PADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Cbc] = "AES/CBC/PKCS7PADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Ccm] = "AES/CCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Ccm] = "AES/CCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Ccm] = "AES/CCM/NOPADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Cfb] = "AES/CFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Cfb] = "AES/CFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Cfb] = "AES/CFB/NOPADDING";



            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Gcm] = "AES/GCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Gcm] = "AES/GCM/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Gcm] = "AES/GCM/NOPADDING";

            AlgorithmOidMap[NistObjectIdentifiers.IdAes128Ofb] = "AES/OFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes192Ofb] = "AES/OFB/NOPADDING";
            AlgorithmOidMap[NistObjectIdentifiers.IdAes256Ofb] = "AES/OFB/NOPADDING";



            AlgorithmMap["RSA/ECB/PKCS1"] = "RSA//PKCS1PADDING";
            AlgorithmMap["RSA/ECB/PKCS1PADDING"] = "RSA//PKCS1PADDING";
            AlgorithmOidMap[PkcsObjectIdentifiers.RsaEncryption] = "RSA//PKCS1PADDING";
            AlgorithmOidMap[PkcsObjectIdentifiers.IdRsaesOaep] = "RSA//OAEPPADDING";













            AlgorithmMap["PBEWITHSHA1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";

            AlgorithmMap["PBEWITHSHA-256AND128BITAES-CBC-BC"] = "PBEWITHSHA256AND128BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-256AND192BITAES-CBC-BC"] = "PBEWITHSHA256AND192BITAES-CBC-BC";
            AlgorithmMap["PBEWITHSHA-256AND256BITAES-CBC-BC"] = "PBEWITHSHA256AND256BITAES-CBC-BC";




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

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return CollectionUtilities.GetValueOrNull(AlgorithmOidMap, oid);
        }

        public static IBufferedCipher GetCipher(DerObjectIdentifier oid)
        {
            if (oid == null)
                throw new ArgumentNullException(nameof(oid));

            if (AlgorithmOidMap.TryGetValue(oid, out var mechanism))
            {
                var cipher = GetCipherForMechanism(mechanism);
                if (cipher != null)
                    return cipher;
            }

            throw new SecurityUtilityException("Cipher OID not recognised.");
        }

        public static IBufferedCipher GetCipher(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            string mechanism = GetMechanism(algorithm) ?? algorithm.ToUpperInvariant();

            var cipher = GetCipherForMechanism(mechanism);
            if (cipher != null)
                return cipher;

            throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
        }

        private static IBufferedCipher GetCipherForMechanism(string mechanism)
        {
            IBasicAgreement iesAgreement = null;
            if (mechanism == "IES")
            {
                iesAgreement = new DHBasicAgreement();
            }
            else if (mechanism == "ECIES")
            {
                iesAgreement = new ECDHBasicAgreement();
            }

            if (iesAgreement != null)
            {
                return new BufferedIesCipher(
                    new IesEngine(
                    iesAgreement,
                    new Kdf2BytesGenerator(
                    new Sha1Digest()),
                    new HMac(
                    new Sha1Digest())));
            }



            if (Platform.StartsWith(mechanism, "PBE"))
            {
                if (Platform.EndsWith(mechanism, "-CBC"))
                {

                }
                else if (Platform.EndsWith(mechanism, "-BC") || Platform.EndsWith(mechanism, "-OPENSSL"))
                {
                    if (Strings.IsOneOf(mechanism,
                        "PBEWITHSHAAND128BITAES-CBC-BC",
                        "PBEWITHSHAAND192BITAES-CBC-BC",
                        "PBEWITHSHAAND256BITAES-CBC-BC",
                        "PBEWITHSHA256AND128BITAES-CBC-BC",
                        "PBEWITHSHA256AND192BITAES-CBC-BC",
                        "PBEWITHSHA256AND256BITAES-CBC-BC",
                        "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
                        "PBEWITHMD5AND192BITAES-CBC-OPENSSL",
                        "PBEWITHMD5AND256BITAES-CBC-OPENSSL"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(AesUtilities.CreateEngine()));
                    }
                }
            }



            string[] parts = mechanism.Split('/');

            IAeadCipher aeadCipher = null;
            IBlockCipher blockCipher = null;
            IAsymmetricBlockCipher asymBlockCipher = null;
            IStreamCipher streamCipher = null;

            string algorithmName = CollectionUtilities.GetValueOrKey(AlgorithmMap, parts[0]).ToUpperInvariant();

            if (!Enums.TryGetEnumValue<CipherAlgorithm>(algorithmName, out var cipherAlgorithm))
                return null;

            switch (cipherAlgorithm)
            {
            case CipherAlgorithm.AES:
                blockCipher = AesUtilities.CreateEngine();
                break;


            default:
                return null;
            }

            if (aeadCipher != null)
            {
                if (parts.Length > 1)
                    throw new ArgumentException("Modes and paddings cannot be applied to AEAD ciphers");

                return new BufferedAeadCipher(aeadCipher);
            }

            if (streamCipher != null)
            {
                if (parts.Length > 1)
                    throw new ArgumentException("Modes and paddings not used for stream ciphers");

                return new BufferedStreamCipher(streamCipher);
            }


            bool cts = false;
            bool padded = true;
            IBlockCipherPadding padding = null;
            IAeadBlockCipher aeadBlockCipher = null;

            if (parts.Length > 2)
            {
                string paddingName = parts[2];

                CipherPadding cipherPadding;
                if (paddingName == "")
                {
                    cipherPadding = CipherPadding.RAW;
                }
                else if (paddingName == "X9.23PADDING")
                {
                    cipherPadding = CipherPadding.X923PADDING;
                }
                else if (!Enums.TryGetEnumValue<CipherPadding>(paddingName, out cipherPadding))
                {
                    return null;
                }

                switch (cipherPadding)
                {
                case CipherPadding.NOPADDING:
                    padded = false;
                    break;
                case CipherPadding.RAW:
                    break;
                case CipherPadding.ISO10126PADDING:
                case CipherPadding.ISO10126D2PADDING:
                case CipherPadding.ISO10126_2PADDING:
                    padding = new ISO10126d2Padding();
                    break;
                case CipherPadding.ISO7816_4PADDING:
                case CipherPadding.ISO9797_1PADDING:
                    padding = new ISO7816d4Padding();
                    break;
                case CipherPadding.ISO9796_1:
                case CipherPadding.ISO9796_1PADDING:
                    asymBlockCipher = new ISO9796d1Encoding(asymBlockCipher);
                    break;
                case CipherPadding.OAEP:
                case CipherPadding.OAEPPADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher);
                    break;
                case CipherPadding.OAEPWITHMD5ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new MD5Digest());
                    break;
                case CipherPadding.OAEPWITHSHA1ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha1Digest());
                    break;
                case CipherPadding.OAEPWITHSHA224ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_224ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha224Digest());
                    break;
                case CipherPadding.OAEPWITHSHA256ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA256PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_256PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha256Digest());
                    break;
                case CipherPadding.OAEPWITHSHA256ANDMGF1WITHSHA1PADDING:
                case CipherPadding.OAEPWITHSHA_256ANDMGF1WITHSHA_1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha256Digest(), new Sha1Digest(), null);
                    break;
                case CipherPadding.OAEPWITHSHA384ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_384ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha384Digest());
                    break;
                case CipherPadding.OAEPWITHSHA512ANDMGF1PADDING:
                case CipherPadding.OAEPWITHSHA_512ANDMGF1PADDING:
                    asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha512Digest());
                    break;
                case CipherPadding.PKCS1:
                case CipherPadding.PKCS1PADDING:
                    asymBlockCipher = new Pkcs1Encoding(asymBlockCipher);
                    break;
                case CipherPadding.PKCS5:
                case CipherPadding.PKCS5PADDING:
                case CipherPadding.PKCS7:
                case CipherPadding.PKCS7PADDING:
                    padding = new Pkcs7Padding();
                    break;
                case CipherPadding.TBCPADDING:
                    padding = new TbcPadding();
                    break;
                case CipherPadding.WITHCTS:
                    cts = true;
                    break;
                case CipherPadding.X923PADDING:
                    padding = new X923Padding();
                    break;
                case CipherPadding.ZEROBYTEPADDING:
                    padding = new ZeroBytePadding();
                    break;
                default:
                    return null;
                }
            }

            string mode = "";
            IBlockCipherMode blockCipherMode = null;
            if (parts.Length > 1)
            {
                mode = parts[1];

                int di = GetDigitIndex(mode);
                string modeName = di >= 0 ? mode.Substring(0, di) : mode;

                CipherMode cipherMode;
                if (modeName == "")
                {
                    cipherMode = CipherMode.NONE;
                }
                else if (!Enums.TryGetEnumValue<CipherMode>(modeName, out cipherMode))
                {
                    return null;
                }

                switch (cipherMode)
                {
                case CipherMode.ECB:
                case CipherMode.NONE:
                    break;
                case CipherMode.CBC:
                    blockCipherMode = new CbcBlockCipher(blockCipher);
                    break;
                case CipherMode.CCM:
                    aeadBlockCipher = new CcmBlockCipher(blockCipher);
                    break;
                case CipherMode.CFB:
                {
                    int bits = (di < 0)
                        ?	8 * blockCipher.GetBlockSize()
                        :	int.Parse(mode.Substring(di));
    
                    blockCipherMode = new CfbBlockCipher(blockCipher, bits);
                    break;
                }
                case CipherMode.CTR:
                    blockCipherMode = new SicBlockCipher(blockCipher);
                    break;
                case CipherMode.CTS:
                    cts = true;
                    blockCipherMode = new CbcBlockCipher(blockCipher);
                    break;
                case CipherMode.EAX:
                    aeadBlockCipher = new EaxBlockCipher(blockCipher);
                    break;
                case CipherMode.GCM:
                    aeadBlockCipher = new GcmBlockCipher(blockCipher);
                    break;
                case CipherMode.GOFB:
                    blockCipherMode = new GOfbBlockCipher(blockCipher);
                    break;
                case CipherMode.OCB:
                    aeadBlockCipher = new OcbBlockCipher(blockCipher, CreateBlockCipher(cipherAlgorithm));
                    break;
                case CipherMode.OFB:
                {
                    int bits = (di < 0)
                        ?	8 * blockCipher.GetBlockSize()
                        :	int.Parse(mode.Substring(di));
    
                    blockCipherMode = new OfbBlockCipher(blockCipher, bits);
                    break;
                }
                case CipherMode.OPENPGPCFB:
                    blockCipherMode = new OpenPgpCfbBlockCipher(blockCipher);
                    break;
                case CipherMode.SIC:
                {
                    if (blockCipher.GetBlockSize() < 16)
                        return null;

                    blockCipherMode = new SicBlockCipher(blockCipher);
                    break;
                }
                default:
                    return null;
                }
            }

            if (aeadBlockCipher != null)
            {
                if (cts)
                    throw new SecurityUtilityException("CTS mode not valid for AEAD ciphers.");
                if (padded && parts.Length > 2 && parts[2] != "")
                    throw new SecurityUtilityException("Bad padding specified for AEAD cipher.");

                return new BufferedAeadBlockCipher(aeadBlockCipher);
            }

            if (blockCipher != null)
            {
                    throw new SecurityUtilityException("ECB mode not supported");

                if (cts)
                    return new CtsBlockCipher(blockCipherMode);

                if (padding != null)
                    return new PaddedBufferedBlockCipher(blockCipherMode, padding);

                if (!padded || blockCipherMode.IsPartialBlockOkay)
                    return new BufferedBlockCipher(blockCipherMode);

                return new PaddedBufferedBlockCipher(blockCipherMode);
            }

            if (asymBlockCipher != null)
                return new BufferedAsymmetricBlockCipher(asymBlockCipher);

            return null;
        }

        private static int GetDigitIndex(string s)
        {
            for (int i = 0; i < s.Length; ++i)
            {
                if (char.IsDigit(s[i]))
                    return i;
            }

            return -1;
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

        private static IBlockCipher CreateBlockCipher(CipherAlgorithm cipherAlgorithm)
        {
            switch (cipherAlgorithm)
            {
            case CipherAlgorithm.AES: return AesUtilities.CreateEngine();

            default:
                throw new SecurityUtilityException("Cipher " + cipherAlgorithm + " not recognised or not a block cipher");
            }
        }
    }
}
