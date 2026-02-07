using System;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Kisa;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Nist;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Ntt;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Oiw;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Asn1.Pkcs;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Generators;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Security;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto.Utilities
{
    public static class CipherKeyGeneratorFactory
    {
        /**
         * Create a key generator for the passed in Object Identifier.
         *
         * @param algorithm the Object Identifier indicating the algorithn the generator is for.
         * @param random a source of random to initialise the generator with.
         * @return an initialised CipherKeyGenerator.
         * @throws IllegalArgumentException if the algorithm cannot be identified.
         */
        public static CipherKeyGenerator CreateKeyGenerator(DerObjectIdentifier algorithm, SecureRandom random)
        {
            if (NistObjectIdentifiers.IdAes128Cbc.Equals(algorithm))
            {
                return CreateCipherKeyGenerator(random, 128);
            }
            else if (NistObjectIdentifiers.IdAes192Cbc.Equals(algorithm))
            {
                return CreateCipherKeyGenerator(random, 192);
            }
            else if (NistObjectIdentifiers.IdAes256Cbc.Equals(algorithm))
            {
                return CreateCipherKeyGenerator(random, 256);
            }

            throw new InvalidOperationException("cannot recognise cipher: " + algorithm);

        }

        private static CipherKeyGenerator CreateCipherKeyGenerator(SecureRandom random, int keySize)
        {
            CipherKeyGenerator keyGen = new CipherKeyGenerator();
            keyGen.Init(new KeyGenerationParameters(random, keySize));
            return keyGen;
        }
    }
}