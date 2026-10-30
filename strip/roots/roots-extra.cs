// The Bouncy Castle API contract of turboHTTP under decision A (STRIP_PLAN_V2.md section 3,
// "roots-extra.cs"): the APIs turboHTTP uses or will use (chain validation outside BC, turboHTTP
// #33) that the consumer files do not reach yet. Never executed; it only has to compile, unrewritten
// in the closure and namespace-rewritten against each separate-assembly DLL (section 5 step 3c).
// New entries come from turboHTTP #33 via #141.

using System;
using System.Collections.Generic;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto;
using Org.BouncyCastle.X509;

namespace TurboHTTP.Transport.BouncyCastle.Contract
{
    internal static class RootsExtraContract
    {
        // #33 wraps the DER of the platform-built path (trust anchor last, possibly with certificates the
        // server did not send) and checks its signature algorithms against the negotiated ones.
        internal static void CheckPlatformPath(TlsContext context, TlsCrypto crypto, byte[][] platformPath)
        {
            var path = new TlsCertificate[platformPath.Length];
            for (int i = 0; i < platformPath.Length; ++i)
            {
                path[i] = crypto.CreateCertificate(platformPath[i]);
            }
            TlsUtilities.CheckPeerSigAlgs(context, path);
        }

        // The server chain is handed to the platform verifier as DER.
        internal static byte[][] EncodeChain(Certificate chain)
        {
            var encoded = new byte[chain.Length][];
            for (int i = 0; i < chain.Length; ++i)
            {
                encoded[i] = chain.GetCertificateAt(i).GetEncoded();
            }
            return encoded;
        }

        internal static bool InspectCertificate(byte[] der, out string subject, out DateTime notBefore,
            out DateTime notAfter, out AsymmetricKeyParameter publicKey)
        {
            var cert = new X509Certificate(der);
            subject = cert.SubjectDN.ToString();
            notBefore = cert.NotBefore;
            notAfter = cert.NotAfter;
            publicKey = cert.GetPublicKey();

            // Entries are [tag, value]; host matching uses dNSName and iPAddress (RFC 6125, RFC 5280 4.2.1.6).
            int hostNames = 0;
            IList<IList<object>> altNames = cert.GetSubjectAlternativeNames();
            if (altNames != null)
            {
                foreach (IList<object> altName in altNames)
                {
                    int tag = (int)altName[0];
                    if (tag == GeneralName.DnsName || tag == GeneralName.IPAddress)
                    {
                        ++hostNames;
                    }
                }
            }

            ExtendedKeyUsage eku = ExtendedKeyUsage.GetInstance(
                cert.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));
            BasicConstraints basicConstraints = BasicConstraints.GetInstance(
                cert.GetExtensionParsedValue(X509Extensions.BasicConstraints));
            KeyUsage keyUsage = KeyUsage.GetInstance(cert.GetExtensionParsedValue(X509Extensions.KeyUsage));

            bool serverAuth = eku == null || eku.HasKeyPurposeId(KeyPurposeID.id_kp_serverAuth);
            bool isCA = basicConstraints != null && basicConstraints.IsCA();
            int usage = keyUsage == null ? 0 : keyUsage.IntValue;
            // digitalSignature is the bit a leaf needs to sign the handshake (RFC 8446 4.4.3, RFC 8422 5.4);
            // keyCertSign is the CA bit (RFC 5280 4.2.1.3) and does not make a leaf usable as a TLS server.
            bool signs = keyUsage == null || (usage & KeyUsage.DigitalSignature) != 0;
            return serverAuth && !isCA && signs && hostNames > 0;
        }
    }
}
