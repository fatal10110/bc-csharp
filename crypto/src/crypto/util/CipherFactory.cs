using System;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Kisa;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Ntt;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X509;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Engines;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Modes;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Paddings;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Parameters;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Utilities
{
    // TODO[api] Make static
    public class CipherFactory
    {
        private CipherFactory()
        {
        }





        public static object CreateContentCipher(bool forEncryption, ICipherParameters encKey,
            AlgorithmIdentifier encryptionAlgID)
        {
            DerObjectIdentifier encAlg = encryptionAlgID.Algorithm;



            BufferedBlockCipher cipher = CreateCipher(encryptionAlgID.Algorithm);
            Asn1Object sParams = encryptionAlgID.Parameters.ToAsn1Object();

            if (sParams != null && !(sParams is DerNull))
            {
                if (encAlg.Equals(NistObjectIdentifiers.IdAes128Cbc)
                    || encAlg.Equals(NistObjectIdentifiers.IdAes192Cbc)
                    || encAlg.Equals(NistObjectIdentifiers.IdAes256Cbc))
                {
                    cipher.Init(forEncryption, new ParametersWithIV(encKey,
                        Asn1OctetString.GetInstance(sParams).GetOctets()));
                }

                else
                {
                    throw new InvalidOperationException("cannot match parameters");
                }
            }
            else
            {
                cipher.Init(forEncryption, encKey);
            }

            return cipher;
        }

        private static BufferedBlockCipher CreateCipher(DerObjectIdentifier algorithm)
        {
            IBlockCipherMode cipher;

            if (NistObjectIdentifiers.IdAes128Cbc.Equals(algorithm)
                || NistObjectIdentifiers.IdAes192Cbc.Equals(algorithm)
                || NistObjectIdentifiers.IdAes256Cbc.Equals(algorithm))
            {
                cipher = new CbcBlockCipher(AesUtilities.CreateEngine());
            }


            else
            {
                throw new InvalidOperationException("cannot recognise cipher: " + algorithm);
            }

            return new PaddedBufferedBlockCipher(cipher, new Pkcs7Padding());
        }
    }
}
