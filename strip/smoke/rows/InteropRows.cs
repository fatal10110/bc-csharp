using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #25: interop with OpenSSL 3 <c>s_server</c> (STRIP_PLAN_V2.md section 5 step 5, "Interop"). Every E3 suite x
    /// {x25519, P-256, P-384, P-521} x every certificate the suite can use (TLS 1.3: RSA 2048 and ECDSA P-256/384/521;
    /// TLS 1.2 ECDHE_ECDSA: the three EC certificates; ECDHE_RSA: RSA 2048), ALPN h2, one row and one single-connection
    /// server per combination. The server is forced to exactly one suite and one group, so a handshake only succeeds
    /// on that pair (TLS 1.3 groups other than x25519 go through HelloRetryRequest, RFC 8446 4.1.4: the client's
    /// key_share is x25519 only). Each row checks version, suite and ALPN on the client, the version and suite
    /// OpenSSL reports, and an application-data round trip (<c>-rev</c> echoes a line reversed). The reject rows
    /// run servers with only RSA key exchange, only DHE or only CBC suites: the handshake must end in a fatal
    /// alert (RFC 5246 7.4.1.3 / 7.2.2: no shared suite, handshake_failure), never in a session or a hang.
    /// </summary>
    public sealed class InteropRows : SmokeRowGroup
    {
        private const int RowTimeoutMillis = 30000;
        private const int ReceiveTimeoutMillis = 10000;

        private sealed class Suite
        {
            public Suite(string name, string openSslName, int wireValue)
            {
                Name = name;
                OpenSslName = openSslName;
                WireValue = wireValue;
            }

            public string Name { get; }
            public string OpenSslName { get; }
            public int WireValue { get; }
        }

        private static readonly Suite[] Tls13Suites =
        {
            new Suite("chacha20", "TLS_CHACHA20_POLY1305_SHA256", CipherSuite.TLS_CHACHA20_POLY1305_SHA256),
            new Suite("aes128gcm", "TLS_AES_128_GCM_SHA256", CipherSuite.TLS_AES_128_GCM_SHA256),
            new Suite("aes256gcm", "TLS_AES_256_GCM_SHA384", CipherSuite.TLS_AES_256_GCM_SHA384),
        };

        private static readonly Suite[] Tls12EcdsaSuites =
        {
            new Suite("ecdsa-chacha20", "ECDHE-ECDSA-CHACHA20-POLY1305",
                CipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
            new Suite("ecdsa-aes128gcm", "ECDHE-ECDSA-AES128-GCM-SHA256",
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
            new Suite("ecdsa-aes256gcm", "ECDHE-ECDSA-AES256-GCM-SHA384",
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
        };

        private static readonly Suite[] Tls12RsaSuites =
        {
            new Suite("rsa-chacha20", "ECDHE-RSA-CHACHA20-POLY1305",
                CipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
            new Suite("rsa-aes128gcm", "ECDHE-RSA-AES128-GCM-SHA256",
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
            new Suite("rsa-aes256gcm", "ECDHE-RSA-AES256-GCM-SHA384",
                CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
        };

        // Row name part, OpenSSL -groups name.
        private static readonly string[][] Groups =
        {
            new[] { "x25519", "X25519" },
            new[] { "p256", "P-256" },
            new[] { "p384", "P-384" },
            new[] { "p521", "P-521" },
        };

        private static readonly string[] EcCertificates = { "p256", "p384", "p521" };
        private static readonly string[] AllCertificates = { "rsa2048", "p256", "p384", "p521" };

        // After AllCertificates: static initializers run in textual order.
        private static readonly Dictionary<string, Lazy<OpenSslCertificate>> s_certificates = NewCertificates();

        public override string Name => "interop";
        public override int Order => 60;

        public override void AddRows(SmokeRows rows)
        {
            AddMatrix(rows, "tls13", "-tls1_3", "-ciphersuites", Tls13Suites, AllCertificates);
            AddMatrix(rows, "tls12", "-tls1_2", "-cipher", Tls12EcdsaSuites, EcCertificates);
            AddMatrix(rows, "tls12", "-tls1_2", "-cipher", Tls12RsaSuites, new[] { "rsa2048" });

            AddReject(rows, "reject-rsa-kx", "AES128-GCM-SHA256:AES256-GCM-SHA384");
            AddReject(rows, "reject-dhe",
                "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305");
            AddReject(rows, "reject-cbc", "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA256:"
                + "ECDHE-RSA-AES256-SHA384");
        }

        /// <summary>The OpenSSL-generated certificate of this run ("rsa2048", "p256", "p384", "p521").</summary>
        public static OpenSslCertificate Certificate(string name) => s_certificates[name].Value;

        /// <summary>Connects a SmokeTlsClient (ALPN h2, pinned to <paramref name="cert"/>) to the server, sends one
        /// line and expects it back reversed (s_server -rev); returns the client after a clean close.</summary>
        public static SmokeTlsClient Exchange(OpenSslServer server, OpenSslCertificate cert)
        {
            SmokeTlsClient client = SmokeClient.CreateClient("localhost", new[] { "h2" },
                SmokeTlsAuthentication.Pinned(cert.Der));
            try
            {
                using (SmokeConnection connection = SmokeClient.Connect(SmokeServerHost.Address, server.Port, client,
                    ReceiveTimeoutMillis))
                {
                    const string Line = "turbo smoke interop";
                    byte[] ping = Encoding.ASCII.GetBytes(Line + "\n");
                    connection.Stream.Write(ping, 0, ping.Length);
                    connection.Stream.Flush();
                    string echo = ReadLine(connection.Stream);
                    char[] reversed = Line.ToCharArray();
                    Array.Reverse(reversed);
                    SmokeAssert.Equal(new string(reversed), echo, "application data reversed by s_server -rev");
                }
            }
            catch (SmokeCheckException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SmokeCheckException("exchange with OpenSSL failed: " + SmokeRunner.Describe(e) + "; "
                    + server.Describe());
            }
            return client;
        }

        private static void AddMatrix(SmokeRows rows, string version, string versionFlag, string suiteFlag,
            Suite[] suites, string[] certificates)
        {
            foreach (Suite suite in suites)
            {
                foreach (string[] group in Groups)
                {
                    foreach (string certName in certificates)
                    {
                        string expectedVersion = version == "tls13" ? "1.3" : "1.2";
                        string openSslVersion = version == "tls13" ? "TLSv1.3" : "TLSv1.2";
                        string groupFlag = group[1];
                        string rowName = version + "-" + suite.Name + "-" + group[0] + "-" + certName;
                        rows.Add(rowName, () =>
                        {
                            OpenSslCertificate cert = Certificate(certName);
                            var flags = new List<string>(cert.Flags)
                            {
                                versionFlag, suiteFlag, suite.OpenSslName, "-groups", groupFlag, "-alpn", "h2", "-rev",
                            };
                            using (OpenSslServer server = OpenSslServer.Start("interop-" + rowName, flags.ToArray()))
                            {
                                SmokeTlsClient client = Exchange(server, cert);
                                SmokeAssert.Equal(expectedVersion, client.NegotiatedVersion, "version");
                                SmokeAssert.Equal("0x" + suite.WireValue.ToString("X4"), client.NegotiatedCipherSuite,
                                    "cipher suite");
                                SmokeAssert.Equal("h2", client.NegotiatedAlpn, "ALPN");
                                string report = server.WaitForExit();
                                SmokeAssert.True(report.Contains("Protocol version: " + openSslVersion + "\n")
                                    && report.Contains("Ciphersuite: " + suite.OpenSslName + "\n"),
                                    "OpenSSL's view of the session; " + server.Describe());
                            }
                        }, RowTimeoutMillis);
                    }
                }
            }
        }

        private static void AddReject(SmokeRows rows, string name, string cipherList)
        {
            rows.Add(name, () =>
            {
                OpenSslCertificate cert = Certificate("rsa2048");
                var flags = new List<string>(cert.Flags) { "-tls1_2", "-cipher", cipherList, "-alpn", "h2", "-rev" };
                using (OpenSslServer server = OpenSslServer.Start("interop-" + name, flags.ToArray()))
                {
                    SmokeTlsClient client = SmokeClient.CreateClient("localhost", new[] { "h2" },
                        SmokeTlsAuthentication.Pinned(cert.Der));
                    TlsException e = SmokeAssert.Throws<TlsException>(
                        () => SmokeClient.Connect(SmokeServerHost.Address, server.Port, client, ReceiveTimeoutMillis)
                            .Dispose(),
                        "handshake with a server offering no client suite; " + server.Describe());
                    short alert = e is TlsFatalAlertReceived received ? received.AlertDescription
                        : e is TlsFatalAlert sent ? sent.AlertDescription : (short)-1;
                    SmokeAssert.True(alert == AlertDescription.handshake_failure,
                        "expected a fatal handshake_failure alert from either side, got " + SmokeRunner.Describe(e));
                    SmokeAssert.True(client.NegotiatedVersion == null, "handshake completed");
                    server.WaitForExit();
                    SmokeAssert.True(server.Describe().Contains("no shared cipher"),
                        "OpenSSL did not fail for lack of a shared suite; " + server.Describe());
                }
            }, RowTimeoutMillis);
        }

        private static string ReadLine(Stream stream)
        {
            var line = new StringBuilder();
            while (true)
            {
                int b = stream.ReadByte();
                SmokeAssert.True(b >= 0, "connection closed before the echoed line (got '" + line + "')");
                if (b == '\n')
                {
                    return line.ToString();
                }
                SmokeAssert.True(line.Length < 256, "echoed line too long");
                line.Append((char)b);
            }
        }

        private static Dictionary<string, Lazy<OpenSslCertificate>> NewCertificates()
        {
            var certificates = new Dictionary<string, Lazy<OpenSslCertificate>>();
            foreach (string name in AllCertificates)
            {
                string kind = name;
                certificates.Add(kind, new Lazy<OpenSslCertificate>(() => OpenSslCertificate.Create(kind)));
            }
            return certificates;
        }
    }
}
