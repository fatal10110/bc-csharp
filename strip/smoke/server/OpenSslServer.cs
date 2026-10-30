using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace TurboSmoke
{
    /// <summary>
    /// #25: one OpenSSL 3 <c>s_server</c> process serving exactly one connection (<c>-naccept 1</c>) on an
    /// ephemeral loopback port. The caller supplies the protocol flags (<c>-tls1_3</c>, <c>-ciphersuites</c>,
    /// <c>-cipher</c>, <c>-groups</c>, <c>-alpn</c>, <c>-rev</c>, ...); the port is read from the <c>ACCEPT</c> line
    /// s_server prints on stdout. Dispose kills a process that is still running; processes a row abandoned are
    /// killed at harness exit. The binary is <c>openssl</c> from PATH (system OpenSSL 3.x is fine, strip.sh checks
    /// the version), or <c>$TURBO_SMOKE_OPENSSL</c>. A missing or non-3.x OpenSSL fails the rows, never skips them.
    /// </summary>
    public sealed class OpenSslServer : IDisposable
    {
        public const int StartTimeoutMillis = 10000;
        public const int ExitTimeoutMillis = 10000;

        private static readonly object s_lock = new object();
        private static readonly List<Process> s_running = new List<Process>();
        private static bool s_exitHookInstalled;

        private readonly Process _process;
        private readonly StringBuilder _stdout = new StringBuilder();
        private readonly StringBuilder _stderr = new StringBuilder();
        private readonly ManualResetEventSlim _accepted = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _stdoutClosed = new ManualResetEventSlim(false);
        private readonly ManualResetEventSlim _stderrClosed = new ManualResetEventSlim(false);

        private readonly string _logName;

        private OpenSslServer(Process process, string logName)
        {
            _process = process;
            _logName = logName;
        }

        /// <summary>The OpenSSL binary the rows run.</summary>
        public static string Binary
        {
            get
            {
                string configured = Environment.GetEnvironmentVariable("TURBO_SMOKE_OPENSSL");
                return string.IsNullOrEmpty(configured) ? "openssl" : configured;
            }
        }

        private static readonly Lazy<string> s_version = new Lazy<string>(() =>
        {
            string version = Run(new[] { "version" }).Trim();
            if (!version.StartsWith("OpenSSL 3.", StringComparison.Ordinal))
            {
                throw new InvalidOperationException("the interop rows need OpenSSL 3.x, '" + Binary + " version' says: "
                    + version);
            }
            return version;
        });

        /// <summary>"OpenSSL 3.x.y ..." of <see cref="Binary"/>; throws when it is missing or not 3.x.</summary>
        public static string Version => s_version.Value;

        /// <summary>Loopback port the server accepts on.</summary>
        public int Port { get; private set; }

        /// <summary>Starts <c>openssl s_server -accept 127.0.0.1:0 -naccept 1</c> with the given flags and waits
        /// for its ACCEPT line. Dispose writes the command line, stdout and stderr to
        /// <c>&lt;WorkDir&gt;/openssl/&lt;logName&gt;.log</c>.</summary>
        public static OpenSslServer Start(string logName, params string[] flags)
        {
            _ = Version;
            var info = NewStartInfo();
            foreach (string arg in new[] { "s_server", "-accept", SmokeServerHost.Address + ":0", "-naccept", "1" })
            {
                info.ArgumentList.Add(arg);
            }
            foreach (string flag in flags)
            {
                info.ArgumentList.Add(flag);
            }

            var process = new Process { StartInfo = info };
            var server = new OpenSslServer(process, logName);
            process.OutputDataReceived += (sender, e) => server.OnStdout(e.Data);
            process.ErrorDataReceived += (sender, e) => server.OnStderr(e.Data);
            Track(process);
            try
            {
                process.Start();
                process.StandardInput.Close();
                process.BeginOutputReadLine();
                process.BeginErrorReadLine();
                if (!server._accepted.Wait(StartTimeoutMillis))
                {
                    throw new InvalidOperationException("openssl s_server printed no ACCEPT line within "
                        + StartTimeoutMillis + " ms; " + server.Describe());
                }
                return server;
            }
            catch
            {
                server.Dispose();
                throw;
            }
        }

        /// <summary>Waits for the process to exit after its one connection; returns its stdout followed by its
        /// stderr, where s_server prints the connection report (protocol, cipher suite, the client's cipher list,
        /// groups and signature algorithms) and its errors ("no shared cipher").</summary>
        public string WaitForExit()
        {
            // Exit alone is not enough: s_server flushes its buffered connection report at exit, and the
            // asynchronous readers may still be delivering it; wait for end of stream on both pipes too.
            if (!_process.WaitForExit(ExitTimeoutMillis) || !_stdoutClosed.Wait(ExitTimeoutMillis)
                || !_stderrClosed.Wait(ExitTimeoutMillis))
            {
                throw new InvalidOperationException("openssl s_server still running " + ExitTimeoutMillis
                    + " ms after its connection; " + Describe());
            }
            lock (_stdout)
            {
                lock (_stderr)
                {
                    return _stdout.ToString() + _stderr.ToString();
                }
            }
        }

        /// <summary>stdout and stderr so far, for failure messages.</summary>
        public string Describe()
        {
            string stdout, stderr;
            lock (_stdout)
            {
                stdout = _stdout.ToString();
            }
            lock (_stderr)
            {
                stderr = _stderr.ToString();
            }
            return "s_server stdout: [" + stdout.Trim() + "] stderr: [" + stderr.Trim() + "]";
        }

        public void Dispose()
        {
            try
            {
                if (!_process.HasExited)
                {
                    _process.Kill();
                    _process.WaitForExit(ExitTimeoutMillis);
                }
            }
            catch (InvalidOperationException)
            {
                // Never started, or already gone.
            }
            Untrack(_process);
            try
            {
                string dir = Path.Combine(SmokeContext.WorkDir, "openssl");
                Directory.CreateDirectory(dir);
                File.WriteAllText(Path.Combine(dir, _logName + ".log"), Binary + " "
                    + string.Join(" ", _process.StartInfo.ArgumentList) + "\n" + Describe() + "\n");
            }
            catch (IOException)
            {
                // The log is a convenience; the row's own checks decide.
            }
            _process.Dispose();
        }

        /// <summary>Runs <c>openssl &lt;args&gt;</c> to completion; returns stdout, throws on non-zero exit.</summary>
        public static string Run(string[] args)
        {
            var info = NewStartInfo();
            foreach (string arg in args)
            {
                info.ArgumentList.Add(arg);
            }
            Process process;
            try
            {
                process = Process.Start(info);
            }
            catch (Exception e)
            {
                throw new InvalidOperationException("cannot run '" + Binary + "' (the interop rows need OpenSSL 3.x): "
                    + e.Message, e);
            }
            using (process)
            {
                process.StandardInput.Close();
                var stderr = process.StandardError.ReadToEndAsync();
                string stdout = process.StandardOutput.ReadToEnd();
                process.WaitForExit();
                if (process.ExitCode != 0)
                {
                    throw new InvalidOperationException("'" + Binary + " " + string.Join(" ", args) + "' exited "
                        + process.ExitCode + ": " + stderr.Result.Trim());
                }
                return stdout;
            }
        }

        private static ProcessStartInfo NewStartInfo() => new ProcessStartInfo(Binary)
        {
            UseShellExecute = false,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };

        private void OnStdout(string line)
        {
            if (line == null)
            {
                _stdoutClosed.Set();
                return;
            }
            lock (_stdout)
            {
                _stdout.AppendLine(line);
            }
            if (Port == 0 && line.StartsWith("ACCEPT ", StringComparison.Ordinal))
            {
                int colon = line.LastIndexOf(':');
                if (colon > 0 && int.TryParse(line.Substring(colon + 1).Trim(), out int port) && port > 0)
                {
                    Port = port;
                    _accepted.Set();
                }
            }
        }

        private void OnStderr(string line)
        {
            if (line == null)
            {
                _stderrClosed.Set();
                return;
            }
            lock (_stderr)
            {
                _stderr.AppendLine(line);
            }
        }

        private static void Track(Process process)
        {
            lock (s_lock)
            {
                if (!s_exitHookInstalled)
                {
                    AppDomain.CurrentDomain.ProcessExit += (sender, e) => KillAll();
                    s_exitHookInstalled = true;
                }
                s_running.Add(process);
            }
        }

        private static void Untrack(Process process)
        {
            lock (s_lock)
            {
                s_running.Remove(process);
            }
        }

        private static void KillAll()
        {
            lock (s_lock)
            {
                foreach (Process process in s_running)
                {
                    try
                    {
                        process.Kill();
                    }
                    catch (Exception)
                    {
                        // Best effort at exit.
                    }
                }
                s_running.Clear();
            }
        }
    }

    /// <summary>
    /// A self-signed server certificate and key generated by OpenSSL itself (<c>openssl req -x509</c>, CN and
    /// subjectAltName localhost), once per run into <see cref="SmokeContext.WorkDir"/>. The client pins the DER.
    /// </summary>
    public sealed class OpenSslCertificate
    {
        private OpenSslCertificate(string name, string certificatePath, string keyPath, byte[] der)
        {
            Name = name;
            CertificatePath = certificatePath;
            KeyPath = keyPath;
            Der = der;
        }

        public string Name { get; }
        public string CertificatePath { get; }
        public string KeyPath { get; }

        /// <summary>DER of the certificate, what the client pins.</summary>
        public byte[] Der { get; }

        /// <summary>The s_server flags presenting this certificate.</summary>
        public string[] Flags => new[] { "-cert", CertificatePath, "-key", KeyPath };

        /// <summary>"rsa2048", "rsapss2048" (an id-RSASSA-PSS key without parameter restrictions) or "p256" /
        /// "p384" / "p521".</summary>
        public static OpenSslCertificate Create(string name)
        {
            string newKey;
            string[] keyOptions;
            switch (name)
            {
            case "rsa2048":
                newKey = "rsa:2048";
                keyOptions = Array.Empty<string>();
                break;
            case "rsapss2048":
                newKey = "rsa-pss";
                keyOptions = new[] { "-pkeyopt", "rsa_keygen_bits:2048" };
                break;
            case "p256":
                newKey = "ec";
                keyOptions = new[] { "-pkeyopt", "ec_paramgen_curve:prime256v1" };
                break;
            case "p384":
                newKey = "ec";
                keyOptions = new[] { "-pkeyopt", "ec_paramgen_curve:secp384r1" };
                break;
            case "p521":
                newKey = "ec";
                keyOptions = new[] { "-pkeyopt", "ec_paramgen_curve:secp521r1" };
                break;
            default:
                throw new ArgumentException("unknown certificate kind " + name, nameof(name));
            }

            string dir = Path.Combine(SmokeContext.WorkDir, "openssl");
            Directory.CreateDirectory(dir);
            string cert = Path.Combine(dir, name + ".crt.pem"), key = Path.Combine(dir, name + ".key.pem");
            var args = new List<string> { "req", "-x509", "-newkey", newKey };
            args.AddRange(keyOptions);
            args.AddRange(new[]
            {
                "-nodes", "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "2",
                "-addext", "subjectAltName=DNS:localhost",
            });
            OpenSslServer.Run(args.ToArray());
            return new OpenSslCertificate(name, cert, key, PemToDer(File.ReadAllText(cert)));
        }

        private static byte[] PemToDer(string pem)
        {
            const string Begin = "-----BEGIN CERTIFICATE-----", End = "-----END CERTIFICATE-----";
            int start = pem.IndexOf(Begin, StringComparison.Ordinal);
            int end = pem.IndexOf(End, StringComparison.Ordinal);
            if (start < 0 || end < start)
            {
                throw new InvalidDataException("no PEM certificate in openssl req output");
            }
            start += Begin.Length;
            return Convert.FromBase64String(pem.Substring(start, end - start).Replace("\r", "").Replace("\n", ""));
        }
    }
}
