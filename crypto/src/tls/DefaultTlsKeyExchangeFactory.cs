using System;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls
{
    public class DefaultTlsKeyExchangeFactory
        : AbstractTlsKeyExchangeFactory
    {
        public override TlsKeyExchange CreateDHKeyExchange(int keyExchange)
        {
            return new TlsDHKeyExchange(keyExchange);
        }

        public override TlsKeyExchange CreateDHanonKeyExchangeClient(int keyExchange,
            TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsDHanonKeyExchange(keyExchange, dhGroupVerifier);
        }



        public override TlsKeyExchange CreateDheKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsDheKeyExchange(keyExchange, dhGroupVerifier);
        }



        public override TlsKeyExchange CreateECDHKeyExchange(int keyExchange)
        {
            return new TlsECDHKeyExchange(keyExchange);
        }

        public override TlsKeyExchange CreateECDHanonKeyExchangeClient(int keyExchange)
        {
            return new TlsECDHanonKeyExchange(keyExchange);
        }



        public override TlsKeyExchange CreateECDheKeyExchangeClient(int keyExchange)
        {
            return new TlsECDheKeyExchange(keyExchange);
        }



        public override TlsKeyExchange CreatePskKeyExchangeClient(int keyExchange, TlsPskIdentity pskIdentity,
            TlsDHGroupVerifier dhGroupVerifier)
        {
            return new TlsPskKeyExchange(keyExchange, pskIdentity, dhGroupVerifier);
        }



        public override TlsKeyExchange CreateRsaKeyExchange(int keyExchange)
        {
            return new TlsRsaKeyExchange(keyExchange);
        }

        public override TlsKeyExchange CreateSrpKeyExchangeClient(int keyExchange, TlsSrpIdentity srpIdentity,
            TlsSrpConfigVerifier srpConfigVerifier)
        {
            return new TlsSrpKeyExchange(keyExchange, srpIdentity, srpConfigVerifier);
        }


    }
}
