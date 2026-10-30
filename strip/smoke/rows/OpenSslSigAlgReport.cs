using System;
using System.Collections.Generic;
using System.Linq;

namespace TurboSmoke
{
    /// <summary>
    /// Checks the "Signature Algorithms:" line that <c>openssl s_server</c> prints about a peer's ClientHello
    /// (apps/lib/s_cb.c, do_print_sigalgs) against the wire list the client advertises, entry by entry and in order.
    /// The spelling differs between OpenSSL 3 releases: 3.0 prints every RSASSA-PSS entry as "RSA-PSS+SHAn", newer
    /// releases (3.5.5 on the CI runner) print rsa_pss_pss_* (0x0809-0x080B) by their TLS name and keep
    /// "RSA-PSS+SHAn" for rsa_pss_rsae_*. Each wire value therefore accepts its known spellings, and nothing else.
    /// </summary>
    public static class OpenSslSigAlgReport
    {
        private const string Prefix = "Signature Algorithms: ";

        // Wire value (RFC 8446 4.2.3) -> spellings OpenSSL 3 prints for it.
        private static readonly Dictionary<int, string[]> Spellings = new Dictionary<int, string[]>
        {
            { 0x0403, new[] { "ECDSA+SHA256" } },
            { 0x0503, new[] { "ECDSA+SHA384" } },
            { 0x0603, new[] { "ECDSA+SHA512" } },
            { 0x0809, new[] { "RSA-PSS+SHA256", "rsa_pss_pss_sha256" } },
            { 0x080A, new[] { "RSA-PSS+SHA384", "rsa_pss_pss_sha384" } },
            { 0x080B, new[] { "RSA-PSS+SHA512", "rsa_pss_pss_sha512" } },
            { 0x0804, new[] { "RSA-PSS+SHA256" } },
            { 0x0805, new[] { "RSA-PSS+SHA384" } },
            { 0x0806, new[] { "RSA-PSS+SHA512" } },
            { 0x0401, new[] { "RSA+SHA256" } },
            { 0x0501, new[] { "RSA+SHA384" } },
            { 0x0601, new[] { "RSA+SHA512" } },
        };

        /// <summary>Null when the report holds exactly one "Signature Algorithms:" line (not the "Shared" one)
        /// whose entries match <paramref name="expected"/> in order; otherwise why not.</summary>
        public static string Mismatch(string report, int[] expected)
        {
            string found = null;
            foreach (string line in report.Split('\n').Select(raw => raw.TrimEnd('\r')))
            {
                if (!line.StartsWith(Prefix, StringComparison.Ordinal))
                {
                    continue;
                }
                if (found != null)
                {
                    return "more than one '" + Prefix.Trim() + "' line";
                }
                found = line.Substring(Prefix.Length);
            }
            if (found == null)
            {
                return "no '" + Prefix.Trim() + "' line";
            }

            string[] actual = found.Split(':');
            if (actual.Length != expected.Length)
            {
                return "expected " + expected.Length + " entries, got " + actual.Length + " (" + found + ")";
            }
            for (int i = 0; i < expected.Length; ++i)
            {
                if (!Spellings.TryGetValue(expected[i], out string[] names))
                {
                    return "no OpenSSL spelling known for 0x" + expected[i].ToString("X4");
                }
                if (Array.IndexOf(names, actual[i]) < 0)
                {
                    return "entry " + i + " is '" + actual[i] + "', expected 0x" + expected[i].ToString("X4") + " ("
                        + string.Join(" or ", names) + ") in " + found;
                }
            }
            return null;
        }
    }
}
