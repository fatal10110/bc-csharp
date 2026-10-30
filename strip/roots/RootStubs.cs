// Stand-ins for the turboHTTP and Unity types the consumer files in strip/roots use outside Bouncy
// Castle (STRIP_PLAN_V2.md section 4). Only these three: ITlsProvider, TlsResult (5-argument
// constructor) and UnityEngine.Scripting.PreserveAttribute. They mirror turboHTTP
// Runtime/Transport/Tls/{ITlsProvider,TlsResult}.cs at strip/ROOTS_SHA and compile both in the
// closure and as a separate assembly against each rewritten DLL (section 5 step 3c).

using System;
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
}

namespace UnityEngine.Scripting
{
    public class PreserveAttribute : Attribute
    {
    }
}
