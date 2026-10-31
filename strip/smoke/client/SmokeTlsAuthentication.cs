using System;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// Server authentication for smoke rows. Decision A keeps chain validation outside BC, and turboHTTP's
    /// TurboTlsAuthentication checks only hostname and validity, so the harness either pins the exact end-entity
    /// certificate the test server presents (the default for rows) or, explicitly, accepts any certificate. Either
    /// way it records the presented end-entity certificate.
    /// </summary>
    public sealed class SmokeTlsAuthentication : TlsAuthentication
    {
        private readonly byte[] _pinned;

        private SmokeTlsAuthentication(byte[] pinned)
        {
            _pinned = pinned;
        }

        /// <summary>Accept only this end-entity certificate (DER); anything else is a bad_certificate alert.</summary>
        public static SmokeTlsAuthentication Pinned(byte[] certificateDer) =>
            new SmokeTlsAuthentication(certificateDer ?? throw new ArgumentNullException(nameof(certificateDer)));

        /// <summary>Accept any certificate the server presents (rows that test something else).</summary>
        public static SmokeTlsAuthentication AcceptAny() => new SmokeTlsAuthentication(null);

        /// <summary>DER of the end-entity certificate the server presented, null before the handshake.</summary>
        public byte[] ServerCertificate { get; private set; }

        public void NotifyServerCertificate(TlsServerCertificate serverCertificate)
        {
            Certificate chain = serverCertificate?.Certificate;
            if (chain == null || chain.IsEmpty)
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
            byte[] leaf = chain.GetCertificateAt(0).GetEncoded();
            ServerCertificate = leaf;
            if (_pinned != null && !_pinned.AsSpan().SequenceEqual(leaf))
            {
                throw new TlsFatalAlert(AlertDescription.bad_certificate);
            }
        }

        public TlsCredentials GetClientCredentials(CertificateRequest certificateRequest)
        {
            return null;
        }
    }
}
