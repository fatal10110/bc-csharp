// Stand-ins for the turboHTTP and Unity types the consumer files in strip/roots use outside Bouncy
// Castle (STRIP_PLAN_V2.md section 4). They mirror turboHTTP Runtime/Transport/Tls/*.cs and
// Runtime/Transport/BouncyCastle/AndroidTrustManagerVerifier.cs at strip/ROOTS_SHA, signatures only,
// and compile both in the closure and as a separate assembly against each rewritten DLL (section 5
// step 3c). Nothing here runs: the certificate verifier, the name matcher, the host-name helpers and
// the Android bridge throw if called, so a stub can never stand in for the real check (decision A,
// chain validation outside BC).

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace TurboHTTP.Transport.Tls
{
    public interface ITlsProvider
    {
        Task<TlsResult> WrapAsync(Stream innerStream, string host, string[] alpnProtocols, CancellationToken ct);

        bool IsAlpnSupported();

        string ProviderName { get; }
    }

    public sealed class TlsResult
    {
        public Stream SecureStream { get; }

        public string NegotiatedAlpn { get; }

        public string TlsVersion { get; }

        public string CipherSuite { get; }

        public string ProviderName { get; }

        public TlsResult(
            Stream secureStream,
            string negotiatedAlpn,
            string tlsVersion,
            string cipherSuite = null,
            string providerName = null)
        {
            SecureStream = secureStream ?? throw new ArgumentNullException(nameof(secureStream));
            NegotiatedAlpn = negotiatedAlpn;
            TlsVersion = tlsVersion ?? throw new ArgumentNullException(nameof(tlsVersion));
            CipherSuite = cipherSuite;
            ProviderName = providerName ?? "Unknown";
        }
    }

    // Runtime/Transport/Tls/ServerCertificateVerifier.cs: the outcome types and the members
    // TurboTlsAuthentication uses (#75; NotVerified and IsTrusted since turboHTTP#287, #77).
    internal enum CertificateVerificationStatus
    {
        NotVerified = 0,
        Trusted = 1,
        UntrustedRoot = 2,
        NotTimeValid = 3,
        Invalid = 4,
        NoVerifier = 5,
    }

    internal readonly struct CertificateVerificationResult
    {
        internal CertificateVerificationResult(CertificateVerificationStatus status, string detail, byte[][] path)
        {
            Status = status;
            Detail = detail;
            Path = path;
        }

        internal CertificateVerificationStatus Status { get; }

        internal string Detail { get; }

        internal byte[][] Path { get; }

        internal bool IsTrusted
            => Status == CertificateVerificationStatus.Trusted && Path != null && Path.Length > 0;
    }

    internal static class ServerCertificateVerifier
    {
        internal const int MaxChainLength = 10;

        internal static CertificateVerificationResult Verify(
            IReadOnlyList<byte[]> chainDer, string host, DateTime verificationTimeUtc)
        {
            throw new NotSupportedException("RootStubs: ServerCertificateVerifier is a compile-time stand-in");
        }
    }

    // Runtime/Transport/Tls/TlsHostName.cs
    internal static class TlsHostName
    {
        internal static string ToSniHostName(string host)
        {
            throw new NotSupportedException("RootStubs: TlsHostName is a compile-time stand-in");
        }

        internal static string ToTargetHost(string host)
        {
            throw new NotSupportedException("RootStubs: TlsHostName is a compile-time stand-in");
        }
    }

    // Runtime/Transport/Tls/TlsCertificateNameMatcher.cs
    internal static class TlsCertificateNameMatcher
    {
        internal static bool Matches(
            string host,
            bool hasSubjectAltName,
            IReadOnlyList<string> dnsNames,
            IReadOnlyList<byte[]> ipAddresses,
            IReadOnlyList<string> commonNames)
        {
            throw new NotSupportedException("RootStubs: TlsCertificateNameMatcher is a compile-time stand-in");
        }
    }
}

namespace TurboHTTP.Transport.BouncyCastle
{
    // Runtime/Transport/BouncyCastle/AndroidTrustManagerVerifier.cs (UnityEngine JNI; not a root).
    // TurboTlsAuthentication calls it under UNITY_ANDROID && !UNITY_EDITOR, which both captured sets define.
    internal static class AndroidTrustManagerVerifier
    {
        internal static void EnsureRegistered()
        {
            throw new NotSupportedException("RootStubs: AndroidTrustManagerVerifier is a compile-time stand-in");
        }
    }
}

namespace UnityEngine.Scripting
{
    public class PreserveAttribute : Attribute
    {
    }
}
