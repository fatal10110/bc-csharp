using System;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Kisa;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Ntt;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.X509;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Utilities
{
    public class AlgorithmIdentifierFactory
    {





        /**
    * Create an AlgorithmIdentifier for the passed in encryption algorithm.
    *
    * @param encryptionOID OID for the encryption algorithm
    * @param keySize key size in bits (-1 if unknown)
    * @param random SecureRandom to use for parameter generation.
    * @return a full AlgorithmIdentifier including parameters
    * @throws IllegalArgumentException if encryptionOID cannot be matched
    */
        public static AlgorithmIdentifier GenerateEncryptionAlgID(DerObjectIdentifier encryptionOID, int keySize, SecureRandom random)

        {
            if (encryptionOID.Equals(NistObjectIdentifiers.IdAes128Cbc)
                    || encryptionOID.Equals(NistObjectIdentifiers.IdAes192Cbc)
                    || encryptionOID.Equals(NistObjectIdentifiers.IdAes256Cbc))
            {
                byte[] iv = new byte[16];

                random.NextBytes(iv);

                return new AlgorithmIdentifier(encryptionOID, new DerOctetString(iv));
            }
            else if (encryptionOID.Equals(PkcsObjectIdentifiers.DesEde3Cbc)
                    || encryptionOID.Equals(OiwObjectIdentifiers.DesCbc))
            {
                byte[] iv = new byte[8];

                random.NextBytes(iv);

                return new AlgorithmIdentifier(encryptionOID, new DerOctetString(iv));
            }

            else if (encryptionOID.Equals(PkcsObjectIdentifiers.rc4))
            {
                return new AlgorithmIdentifier(encryptionOID, DerNull.Instance);
            }

            else
            {
                throw new InvalidOperationException("unable to match algorithm");
            }
        }
    }
}