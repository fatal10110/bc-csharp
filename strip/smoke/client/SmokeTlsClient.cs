using System;
using System.Collections.Generic;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls.Crypto;

namespace TurboSmoke
{
    /// <summary>
    /// Mirror of turboHTTP's TurboTlsClient (strip/roots/TurboTlsClient.cs at ROOTS_SHA, internal sealed there):
    /// the same ALPN and SNI extensions, TLS 1.3 + 1.2, default cipher suites, and the same negotiated-result
    /// capture. Differences: the authentication is injected (decision A: chain validation lives outside BC, so the
    /// harness pins its test certificate, <see cref="SmokeTlsAuthentication"/>), and the handshake timeout is
    /// 30000 ms (plan section 5 step 5; turboHTTP#142), adjustable for the timeout rows. Client-side files use the
    /// rewritten namespaces only (TurboBC.x.dll); keep this file C# 9 like the consumer.
    /// </summary>
    public sealed class SmokeTlsClient : DefaultTlsClient
    {
        public const int DefaultHandshakeTimeoutMillis = 30000;

        private readonly string _targetHost;
        private readonly string[] _alpnProtocols;
        private readonly TlsAuthentication _authentication;

        public SmokeTlsClient(TlsCrypto crypto, string targetHost, string[] alpnProtocols,
            TlsAuthentication authentication)
            : base(crypto)
        {
            _targetHost = targetHost ?? throw new ArgumentNullException(nameof(targetHost));
            _alpnProtocols = alpnProtocols ?? Array.Empty<string>();
            _authentication = authentication ?? throw new ArgumentNullException(nameof(authentication));
        }

        /// <summary>ALPN protocol negotiated by the server, or null if no match.</summary>
        public string NegotiatedAlpn { get; private set; }

        /// <summary>TLS version negotiated ("1.2", "1.3").</summary>
        public string NegotiatedVersion { get; private set; }

        /// <summary>Cipher suite negotiated, "0xXXXX".</summary>
        public string NegotiatedCipherSuite { get; private set; }

        /// <summary>What <see cref="GetHandshakeTimeoutMillis"/> returns; 30000 unless a row changes it.</summary>
        public int HandshakeTimeoutMillis { get; set; } = DefaultHandshakeTimeoutMillis;

        public override TlsAuthentication GetAuthentication()
        {
            return _authentication;
        }

        public override int GetHandshakeTimeoutMillis()
        {
            return HandshakeTimeoutMillis;
        }

        public override IDictionary<int, byte[]> GetClientExtensions()
        {
            var extensions = base.GetClientExtensions() ?? new Dictionary<int, byte[]>();

            if (_alpnProtocols.Length > 0)
            {
                var protocols = new List<ProtocolName>();
                foreach (var protocol in _alpnProtocols)
                {
                    protocols.Add(ProtocolName.AsUtf8Encoding(protocol));
                }

                TlsExtensionsUtilities.AddAlpnExtensionClient(extensions, protocols);
            }

            var hostBytes = System.Text.Encoding.UTF8.GetBytes(_targetHost);
            var serverNames = new List<ServerName>
            {
                new ServerName(NameType.host_name, hostBytes)
            };
            TlsExtensionsUtilities.AddServerNameExtensionClient(extensions, serverNames);

            return extensions;
        }

        public override void NotifyHandshakeComplete()
        {
            base.NotifyHandshakeComplete();

            var context = m_context;
            if (context != null)
            {
                NegotiatedVersion = FormatTlsVersion(context.ServerVersion);

                var securityParams = context.SecurityParameters;
                if (securityParams != null)
                {
                    var alpnProtocol = securityParams.ApplicationProtocol;
                    if (alpnProtocol != null)
                    {
                        NegotiatedAlpn = alpnProtocol.GetUtf8Decoding();
                    }

                    NegotiatedCipherSuite = $"0x{securityParams.CipherSuite:X4}";
                }
            }
        }

        private static string FormatTlsVersion(ProtocolVersion version)
        {
            if (version == null)
            {
                return "Unknown";
            }
            if (version.Equals(ProtocolVersion.TLSv12))
            {
                return "1.2";
            }
            if (version.Equals(ProtocolVersion.TLSv13))
            {
                return "1.3";
            }
            return version.ToString();
        }

        protected override ProtocolVersion[] GetSupportedVersions()
        {
            return new[]
            {
                ProtocolVersion.TLSv13,
                ProtocolVersion.TLSv12
            };
        }

        protected override int[] GetSupportedCipherSuites()
        {
            return base.GetSupportedCipherSuites();
        }
    }
}
