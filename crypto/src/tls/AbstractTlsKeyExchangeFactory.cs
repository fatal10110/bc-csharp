using System;

using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;

namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls
{
    /// <summary>Base class for supporting a TLS key exchange factory implementation.</summary>
    public abstract class AbstractTlsKeyExchangeFactory
        : TlsKeyExchangeFactory
    {
        public virtual TlsKeyExchange CreateDHKeyExchange(int keyExchange)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public virtual TlsKeyExchange CreateDHanonKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }



        public virtual TlsKeyExchange CreateDheKeyExchangeClient(int keyExchange, TlsDHGroupVerifier dhGroupVerifier)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }



        public virtual TlsKeyExchange CreateECDHKeyExchange(int keyExchange)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public virtual TlsKeyExchange CreateECDHanonKeyExchangeClient(int keyExchange)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }



        public virtual TlsKeyExchange CreateECDheKeyExchangeClient(int keyExchange)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }



        public virtual TlsKeyExchange CreatePskKeyExchangeClient(int keyExchange, TlsPskIdentity pskIdentity,
            TlsDHGroupVerifier dhGroupVerifier)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }



        public virtual TlsKeyExchange CreateRsaKeyExchange(int keyExchange)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }

        public virtual TlsKeyExchange CreateSrpKeyExchangeClient(int keyExchange, TlsSrpIdentity srpIdentity,
            TlsSrpConfigVerifier srpConfigVerifier)
        {
            throw new TlsFatalAlert(AlertDescription.internal_error);
        }


    }
}
