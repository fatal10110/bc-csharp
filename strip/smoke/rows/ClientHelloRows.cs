using System;
using System.Collections.Generic;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #25: the exact ClientHello (STRIP_PLAN_V2.md section 5 step 5, "ClientHello assertion (exact allow-lists)").
    /// SmokeTlsClient, the consumer's shape (ALPN h2, SNI localhost), writes its first flight into an offline
    /// TlsClientProtocol; the record is parsed here byte by byte, without library types, and checked against the
    /// wire values of the RFC registries: cipher suites = E3 + TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 3.4),
    /// supported_groups = x25519, secp256r1, secp384r1, secp521r1 (decision C: no hybrid), signature_algorithms =
    /// the ordered 12-entry list (E1, decision E: no EdDSA), no status_request / status_request_v2 (decision D,
    /// RFC 6066 8, RFC 6961). The last row checks what OpenSSL 3 itself reports about the same ClientHello.
    /// </summary>
    public sealed class ClientHelloRows : SmokeRowGroup
    {
        // Wire values (IANA TLS registries); order is the client's preference order (DefaultTlsClient, E3).
        private static readonly int[] ExpectedCipherSuites =
        {
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0xCCA9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xC02C, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xCCA8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
            0xC02F, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xC030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            0x00FF, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        };

        private static readonly int[] ExpectedGroups =
        {
            0x001D, // x25519
            0x0017, // secp256r1
            0x0018, // secp384r1
            0x0019, // secp521r1
        };

        private static readonly int[] ExpectedSignatureAlgorithms =
        {
            0x0403, 0x0503, 0x0603, // ecdsa_secp256r1_sha256, ecdsa_secp384r1_sha384, ecdsa_secp521r1_sha512
            0x0809, 0x080A, 0x080B, // rsa_pss_pss_sha256, rsa_pss_pss_sha384, rsa_pss_pss_sha512
            0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha256, rsa_pss_rsae_sha384, rsa_pss_rsae_sha512
            0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512
        };

        // Extension types (IANA).
        private const int ServerName = 0, StatusRequest = 5, SupportedGroups = 10, EcPointFormats = 11,
            SignatureAlgorithms = 13, Alpn = 16, StatusRequestV2 = 17, EncryptThenMac = 22,
            ExtendedMasterSecret = 23, SupportedVersions = 43, SignatureAlgorithmsCert = 50, KeyShare = 51,
            RenegotiationInfo = 0xFF01;

        public override string Name => "clienthello";
        public override int Order => 45;

        public override void AddRows(SmokeRows rows)
        {
            rows.Add("cipher-suites", () =>
            {
                ParsedClientHello hello = Capture();
                SmokeAssert.Equal(Format(ExpectedCipherSuites), Format(hello.CipherSuites), "cipher_suites");
                SmokeAssert.True(!hello.Extensions.ContainsKey(RenegotiationInfo),
                    "renegotiation_info sent next to the SCSV (RFC 5746 3.4: one or the other)");
            });
            rows.Add("supported-groups", () =>
            {
                ParsedClientHello hello = Capture();
                SmokeAssert.Equal(Format(ExpectedGroups), Format(U16List(hello.Extension(SupportedGroups), 2)),
                    "supported_groups");
            });
            rows.Add("signature-algorithms", () =>
            {
                ParsedClientHello hello = Capture();
                SmokeAssert.Equal(Format(ExpectedSignatureAlgorithms),
                    Format(U16List(hello.Extension(SignatureAlgorithms), 2)), "signature_algorithms");
                SmokeAssert.True(!hello.Extensions.ContainsKey(SignatureAlgorithmsCert),
                    "signature_algorithms_cert sent (the client sets none)");
            });
            rows.Add("no-status-request", () =>
            {
                ParsedClientHello hello = Capture();
                SmokeAssert.True(!hello.Extensions.ContainsKey(StatusRequest), "status_request sent (decision D)");
                SmokeAssert.True(!hello.Extensions.ContainsKey(StatusRequestV2), "status_request_v2 sent (decision D)");
            });
            rows.Add("key-share-and-versions", () =>
            {
                ParsedClientHello hello = Capture();
                SmokeAssert.Equal("0x0304 0x0303", Format(U8List(hello.Extension(SupportedVersions))),
                    "supported_versions");
                // RFC 8446 4.2.8: KeyShareClientHello = client_shares<0..2^16-1> of (group, key_exchange<1..2^16-1>).
                byte[] shares = hello.Extension(KeyShare);
                var reader = new WireReader(shares, 0, shares.Length);
                var list = reader.Vector(2);
                var groups = new List<int>();
                while (!list.AtEnd)
                {
                    groups.Add(list.U16());
                    WireReader key = list.Vector(2);
                    SmokeAssert.Equal(32, key.Remaining, "x25519 key_exchange length");
                    key.Skip(key.Remaining);
                }
                reader.ExpectEnd("key_share");
                SmokeAssert.Equal("0x001D", Format(groups.ToArray()), "key_share groups (x25519 only, others by HRR)");
            });
            rows.Add("alpn-and-sni", () =>
            {
                ParsedClientHello hello = Capture();
                byte[] alpn = hello.Extension(Alpn);
                SmokeAssert.Equal(new byte[] { 0x00, 0x03, 0x02, (byte)'h', (byte)'2' }, alpn, "ALPN (RFC 7301: h2)");
                byte[] sni = hello.Extension(ServerName);
                byte[] expectedSni = new byte[] { 0x00, 0x0C, 0x00, 0x00, 0x09 };
                SmokeAssert.Equal(Concat(expectedSni, Encoding.ASCII.GetBytes("localhost")), sni,
                    "server_name (RFC 6066 3: host_name localhost)");
            });
            rows.Add("extension-types", () =>
            {
                ParsedClientHello hello = Capture();
                // Exact set: no session_ticket (35), psk_key_exchange_modes (45) or pre_shared_key (41) (decision F,
                // no resumption), no padding, early_data or anything else.
                int[] expected =
                {
                    ServerName, SupportedGroups, EcPointFormats, SignatureAlgorithms, Alpn, EncryptThenMac,
                    ExtendedMasterSecret, SupportedVersions, KeyShare,
                };
                var actual = new List<int>(hello.Extensions.Keys);
                actual.Sort();
                SmokeAssert.Equal(Format(expected), Format(actual.ToArray()), "extension types offered");

            });
            rows.Add("seen-by-openssl", () =>
            {
                OpenSslCertificate cert = InteropRows.Certificate("p256");
                using (OpenSslServer server = OpenSslServer.Start("clienthello-seen-by-openssl", Flags(cert,
                    "-tls1_3", "-groups", "X25519", "-alpn", "h2", "-rev")))
                {
                    InteropRows.Exchange(server, cert);
                    string report = server.WaitForExit();
                    ExpectLine(report, "Client cipher list: TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:"
                        + "TLS_AES_256_GCM_SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256:"
                        + "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:"
                        + "ECDHE-RSA-AES256-GCM-SHA384:TLS_EMPTY_RENEGOTIATION_INFO_SCSV", server);
                    ExpectLine(report, "Signature Algorithms: ECDSA+SHA256:ECDSA+SHA384:ECDSA+SHA512:"
                        + "RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:RSA-PSS+SHA256:RSA-PSS+SHA384:RSA-PSS+SHA512:"
                        + "RSA+SHA256:RSA+SHA384:RSA+SHA512", server);
                    ExpectLine(report, "Supported groups: x25519:secp256r1:secp384r1:secp521r1", server);
                }
            });
        }

        private static string[] Flags(OpenSslCertificate cert, params string[] flags)
        {
            var all = new List<string>(cert.Flags);
            all.AddRange(flags);
            return all.ToArray();
        }

        private static void ExpectLine(string report, string line, OpenSslServer server)
        {
            foreach (string actual in report.Split('\n'))
            {
                if (actual.TrimEnd('\r') == line)
                {
                    return;
                }
            }
            throw new SmokeCheckException("OpenSSL did not report '" + line + "'; " + server.Describe());
        }

        /// <summary>The first flight of a SmokeTlsClient (TLS 1.3 + 1.2, ALPN h2, SNI localhost), parsed.</summary>
        private static ParsedClientHello Capture()
        {
            SmokeTlsClient client = SmokeClient.CreateClient("localhost", new[] { "h2" },
                SmokeTlsAuthentication.AcceptAny());
            var protocol = new TlsClientProtocol();
            protocol.Connect(client);
            byte[] output = new byte[protocol.GetAvailableOutputBytes()];
            protocol.ReadOutput(output, 0, output.Length);
            return ParsedClientHello.Parse(output);
        }

        private static int[] U16List(byte[] extension, int lengthBytes)
        {
            var reader = new WireReader(extension, 0, extension.Length);
            WireReader list = reader.Vector(lengthBytes);
            reader.ExpectEnd("extension");
            var values = new List<int>();
            while (!list.AtEnd)
            {
                values.Add(list.U16());
            }
            return values.ToArray();
        }

        private static int[] U8List(byte[] extension) => U16List(extension, 1);

        private static string Format(int[] values)
        {
            var parts = new string[values.Length];
            for (int i = 0; i < values.Length; ++i)
            {
                parts[i] = "0x" + values[i].ToString("X4");
            }
            return string.Join(" ", parts);
        }

        private static byte[] Concat(byte[] a, byte[] b)
        {
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }

        /// <summary>RFC 8446 4.1.2 / RFC 5246 7.4.1.2 ClientHello in one handshake record.</summary>
        private sealed class ParsedClientHello
        {
            public int[] CipherSuites;
            public readonly Dictionary<int, byte[]> Extensions = new Dictionary<int, byte[]>();

            public byte[] Extension(int type)
            {
                if (!Extensions.TryGetValue(type, out byte[] data))
                {
                    throw new SmokeCheckException("extension " + type + " missing from the ClientHello");
                }
                return data;
            }

            public static ParsedClientHello Parse(byte[] flight)
            {
                var record = new WireReader(flight, 0, flight.Length);
                SmokeAssert.Equal(22, record.U8(), "record content type (handshake)");
                record.U16(); // legacy_record_version
                WireReader handshake = record.Vector(2);
                record.ExpectEnd("first flight (one record)");
                SmokeAssert.Equal(1, handshake.U8(), "handshake type (client_hello)");
                WireReader body = handshake.Vector(3);
                handshake.ExpectEnd("handshake record");

                SmokeAssert.Equal(0x0303, body.U16(), "legacy_version");
                body.Skip(32); // random
                body.Vector(1); // legacy_session_id
                WireReader suites = body.Vector(2);
                var list = new List<int>();
                while (!suites.AtEnd)
                {
                    list.Add(suites.U16());
                }
                WireReader compression = body.Vector(1);
                SmokeAssert.Equal(1, compression.Remaining, "compression methods length");
                SmokeAssert.Equal(0, compression.U8(), "compression method (null)");

                var hello = new ParsedClientHello { CipherSuites = list.ToArray() };
                WireReader extensions = body.Vector(2);
                body.ExpectEnd("ClientHello body");
                while (!extensions.AtEnd)
                {
                    int type = extensions.U16();
                    WireReader data = extensions.Vector(2);
                    SmokeAssert.True(!hello.Extensions.ContainsKey(type), "extension " + type + " sent twice");
                    hello.Extensions.Add(type, data.Bytes(data.Remaining));
                }
                return hello;
            }
        }

        /// <summary>Bounds-checked big-endian reader over a byte range.</summary>
        private sealed class WireReader
        {
            private readonly byte[] m_buf;
            private int m_pos;
            private readonly int m_end;

            public WireReader(byte[] buf, int offset, int length)
            {
                m_buf = buf;
                m_pos = offset;
                m_end = offset + length;
            }

            public int Remaining => m_end - m_pos;
            public bool AtEnd => m_pos == m_end;

            public void Skip(int n)
            {
                if (n < 0 || n > Remaining)
                {
                    throw new SmokeCheckException("ClientHello truncated: need " + n + " bytes, have " + Remaining);
                }
                m_pos += n;
            }

            public int U8()
            {
                Skip(1);
                return m_buf[m_pos - 1];
            }

            public int U16() => (U8() << 8) | U8();

            public WireReader Vector(int lengthBytes)
            {
                int length = 0;
                for (int i = 0; i < lengthBytes; ++i)
                {
                    length = (length << 8) | U8();
                }
                int start = m_pos;
                Skip(length);
                return new WireReader(m_buf, start, length);
            }

            public byte[] Bytes(int n)
            {
                int start = m_pos;
                Skip(n);
                byte[] result = new byte[n];
                Buffer.BlockCopy(m_buf, start, result, 0, n);
                return result;
            }

            public void ExpectEnd(string what)
            {
                if (!AtEnd)
                {
                    throw new SmokeCheckException(what + ": " + Remaining + " trailing bytes");
                }
            }
        }
    }
}
