using System;
using System.Collections.Generic;
using System.IO;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;

namespace TurboSmoke
{
    /// <summary>
    /// #66: hostile negotiation servers, built with the upstream BASE library (server side). Two kinds:
    /// <list type="bullet">
    /// <item>BASE <see cref="TlsServerProtocol"/> servers whose credential signs with a scheme the client did not
    /// offer, or whose certificate key type does not match the RSA-PSS scheme (BASE checks neither).</item>
    /// <item>Raw handlers (<see cref="SmokeServerHost.Start"/>) writing hand-built records for what BASE refuses to
    /// send: a ServerHello with a suite the client did not offer, a HelloRetryRequest or key share for a group the
    /// client did not offer, a ServerKeyExchange for ffdhe2048 or x448, low-order X25519 shares.</item>
    /// </list>
    /// Everything leaves here as bytes or a started <see cref="SmokeServerHost"/>.
    /// </summary>
    public static class SmokeNegotiationServers
    {
        public const int X25519 = 0x001d;
        public const int X448 = 0x001e;
        public const int Secp256r1 = 0x0017;
        public const int Ffdhe2048 = 0x0100;

        public const int TlsAes128GcmSha256 = 0x1301;
        public const int TlsEcdheEcdsaAes128GcmSha256 = 0xC02B;

        /// <summary>Raw handlers: the socket timeout bounds a drain the client never ends.</summary>
        private const int RawIoTimeoutMillis = 10000;

        /// <summary>RFC 8446 4.1.3: SHA-256("HelloRetryRequest").</summary>
        private static readonly byte[] HelloRetryRequestRandom = Hex(
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");

        private static readonly Lazy<SmokeServerKey> P256 =
            new Lazy<SmokeServerKey>(() => SmokeServerKey.CreateEcdsa("secp256r1"));

        private static readonly Lazy<SmokeServerKey> Rsa =
            new Lazy<SmokeServerKey>(() => SmokeHostileCertificates.CreateRsa(2048, 65537));

        private static readonly Lazy<AsymmetricKeyParameter> Ed25519 = new Lazy<AsymmetricKeyParameter>(() =>
        {
            var generator = new Ed25519KeyPairGenerator();
            generator.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            return generator.GenerateKeyPair().Private;
        });

        /// <summary>A P-256 server key whose uncompressed point ends in an even octet, so the point in a BIT STRING
        /// with one pad bit is still valid DER (X.690 11.2.1: unused bits are zero).</summary>
        private static readonly Lazy<SmokeServerKey> P256EvenPoint = new Lazy<SmokeServerKey>(() =>
        {
            while (true)
            {
                SmokeServerKey key = SmokeServerKey.CreateEcdsa("secp256r1");
                byte[] point = SpkiOf(key.CertificateDer).PublicKey.GetOctets();
                if ((point[point.Length - 1] & 1) == 0)
                {
                    return key;
                }
            }
        });

        // --- BASE servers ---

        /// <summary>A BASE server that signs CertificateVerify (TLS 1.3) or ServerKeyExchange (TLS 1.2) with
        /// <paramref name="scheme"/> ((hash &lt;&lt; 8) | signature) using a real <paramref name="keyKind"/> key
        /// ("p256", "rsa", or "ed25519" behind the P-256 certificate). BASE does not check the scheme against the
        /// client's signature_algorithms.</summary>
        public static SmokeServerHost StartSigningWith(string keyKind, int scheme, bool tls13)
        {
            var algorithm = new SignatureAndHashAlgorithm((short)(scheme >> 8), (short)(scheme & 0xff));
            SmokeServerKey key;
            switch (keyKind)
            {
            case "p256":
                key = new SmokeServerKey("p256-" + scheme.ToString("x4"), P256.Value.ChainDer, P256.Value.PrivateKey,
                    algorithm, true);
                break;
            case "ed25519":
                key = new SmokeServerKey("ed25519-behind-p256", P256.Value.ChainDer, Ed25519.Value, algorithm, true);
                break;
            case "rsa":
                key = new SmokeServerKey("rsa-" + scheme.ToString("x4"), Rsa.Value.ChainDer, Rsa.Value.PrivateKey,
                    algorithm, false);
                break;
            default:
                throw new ArgumentException("unknown key kind " + keyKind, nameof(keyKind));
            }
            var server = new SmokeTlsServer(key)
            {
                Versions = tls13 ? SmokeTlsServer.Tls13Only : SmokeTlsServer.Tls12Only,
            };
            return SmokeServerHost.StartTls(server);
        }

        /// <summary>RSA-PSS key/scheme mismatch (RFC 8446 4.2.3): <paramref name="pssOidLeaf"/> sends the real RSA
        /// key under id-RSASSA-PSS and signs rsa_pss_rsae_sha256; otherwise the real rsaEncryption certificate and
        /// rsa_pss_pss_sha256. Either way the signature itself is valid for the key.</summary>
        public static SmokeServerHost StartPssMismatch(bool pssOidLeaf, bool tls13)
        {
            SmokeServerKey rsa = Rsa.Value;
            if (pssOidLeaf)
            {
                SubjectPublicKeyInfo real = SpkiOf(rsa.CertificateDer);
                var pssSpki = new SubjectPublicKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.IdRsassaPss),
                    real.PublicKey);
                byte[] leaf = SmokeHostileCertificates.Certificate(pssSpki, SmokeHostileKeys.Sha256WithRsa);
                return SmokeServerHost.StartTls(new SmokeHostileTlsServer(rsa, leaf, tls13));
            }
            var signer = new SmokeServerKey("rsa-pss-pss-on-rsaencryption", rsa.ChainDer, rsa.PrivateKey,
                SignatureAndHashAlgorithm.rsa_pss_pss_sha256, false);
            return SmokeServerHost.StartTls(new SmokeHostileTlsServer(signer, rsa.CertificateDer, tls13));
        }

        /// <summary>A BASE server whose leaf carries its real P-256 point in a BIT STRING with one pad bit (DER
        /// valid: the point ends in an even octet). Accepting the key would complete the handshake.</summary>
        public static SmokeServerHost StartPadBitsLeaf(bool tls13)
        {
            SmokeServerKey key = P256EvenPoint.Value;
            byte[] point = SpkiOf(key.CertificateDer).PublicKey.GetOctets();
            byte[] leaf = SmokeHostileCertificates.Certificate(EcSpki(point, 1),
                new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256));
            return SmokeServerHost.StartTls(new SmokeHostileTlsServer(key, leaf, tls13));
        }

        // --- SPKI with BIT STRING pad bits (RFC 5480 2.2, X.690 8.6.2) ---

        /// <summary>A P-256 ecPublicKey SPKI for k*G, with <paramref name="padBits"/> unused bits in the BIT STRING.
        /// <paramref name="trailingBitsSet"/> false: the smallest k >= 1 whose point's last octet has the pad bits
        /// clear (valid DER); true: the smallest k whose last octet has a pad bit set, encoded as is (BER only: the
        /// client keeps it as a DLBitString). Either way the octets are a real point, so a parser that ignored the
        /// pad bits would accept the key.</summary>
        public static byte[] PadBitsSpki(int padBits, bool trailingBitsSet) =>
            PadBits(padBits, trailingBitsSet, spki => spki.GetEncoded(Asn1Encodable.Der));

        /// <summary><see cref="PadBitsSpki"/> in a certificate (garbage signature, decision A).</summary>
        public static byte[] PadBitsCertificate(int padBits, bool trailingBitsSet) =>
            PadBits(padBits, trailingBitsSet, spki => SmokeHostileCertificates.Certificate(spki,
                new AlgorithmIdentifier(X9ObjectIdentifiers.ECDsaWithSha256)));

        /// <summary>Encodes with <paramref name="encode"/>, then restores the point's last octet: BASE's DER encoder
        /// clears the unused bits, and the BIT STRING's last octet is the last byte of the SPKI encoding.</summary>
        private static byte[] PadBits(int padBits, bool trailingBitsSet, Func<SubjectPublicKeyInfo, byte[]> encode)
        {
            X9ECParameters curve = ECNamedCurveTable.GetByOid(SecObjectIdentifiers.SecP256r1);
            int mask = (1 << padBits) - 1;
            for (int k = 1; k < 100000; k++)
            {
                byte[] point = curve.G.Multiply(Org.BouncyCastle.Math.BigInteger.ValueOf(k)).Normalize()
                    .GetEncoded(false);
                if (((point[point.Length - 1] & mask) != 0) != trailingBitsSet)
                {
                    continue;
                }
                SubjectPublicKeyInfo spki = EcSpki(point, padBits);
                byte[] spkiDer = spki.GetEncoded(Asn1Encodable.Der);
                byte[] encoded = encode(spki);
                int at = IndexOf(encoded, spkiDer);
                if (at < 0)
                {
                    throw new InvalidOperationException("SPKI not found in its encoding");
                }
                encoded[at + spkiDer.Length - 1] = point[point.Length - 1];
                return encoded;
            }
            throw new InvalidOperationException("no point found");
        }

        private static int IndexOf(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i + needle.Length <= haystack.Length; i++)
            {
                int j = 0;
                while (j < needle.Length && haystack[i + j] == needle[j])
                {
                    j++;
                }
                if (j == needle.Length)
                {
                    return i;
                }
            }
            return -1;
        }

        private static SubjectPublicKeyInfo EcSpki(byte[] point, int padBits) => new SubjectPublicKeyInfo(
            new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, SecObjectIdentifiers.SecP256r1),
            new DerBitString(point, padBits));

        private static SubjectPublicKeyInfo SpkiOf(byte[] certificateDer) =>
            X509CertificateStructure.GetInstance(certificateDer).SubjectPublicKeyInfo;

        // --- raw handlers ---
        //
        // Every raw handler ends with a tripwire: if the client wrongly accepted the hostile message, the next
        // thing it gets fails with a different alert at once (bad_record_mac or unexpected_message), instead of a
        // stalled handshake that would end in the EOF-during-handshake handshake_failure. The control rows send
        // the same flight with a valid value and pin that tripwire alert.

        /// <summary>A valid X25519 public key (for control rows).</summary>
        public static byte[] ValidX25519Share()
        {
            var key = new X25519PrivateKeyParameters(new SecureRandom());
            return key.GeneratePublicKey().GetEncoded();
        }

        /// <summary>TLS 1.2 ServerHello (legacy_version 0x0303, no supported_versions) selecting
        /// <paramref name="suite"/>. Tripwire: a Finished message right after it (unexpected_message for a client
        /// that accepted the suite and expects a Certificate).</summary>
        public static SmokeServerHost StartTls12ServerHello(int suite) => StartRaw((stream, hello) =>
        {
            WriteHandshake(stream, 2, Tls12ServerHelloBody(hello, suite));
            WriteHandshake(stream, 20, new byte[12]);
        });

        /// <summary>TLS 1.3 ServerHello selecting <paramref name="suite"/> with a key_share for
        /// <paramref name="group"/>. Tripwire: a 32-byte application_data record that cannot decrypt under the
        /// handshake keys (bad_record_mac for a client that computed them).</summary>
        public static SmokeServerHost StartTls13ServerHello(int suite, int group, byte[] keyExchange) => StartRaw(
            (stream, hello) =>
            {
                byte[] keyShare = Concat(U16(group), Vec(2, keyExchange));
                byte[] extensions = Concat(Extension(0x002b, U16(0x0304)), Extension(0x0033, keyShare));
                WriteHandshake(stream, 2, ServerHelloBody(Fill(32, 0x5a), hello.SessionId, suite, extensions));
                WriteRecord(stream, 23, new byte[32]);
            });

        /// <summary>TLS 1.3 HelloRetryRequest selecting <paramref name="group"/>. Tripwire: if the client sends a
        /// second ClientHello, answer it with an empty Certificate message (unexpected_message).</summary>
        public static SmokeServerHost StartHelloRetryRequest(int group) => StartRaw((stream, hello) =>
        {
            byte[] extensions = Concat(Extension(0x002b, U16(0x0304)), Extension(0x0033, U16(group)));
            WriteHandshake(stream, 2,
                ServerHelloBody(HelloRetryRequestRandom, hello.SessionId, TlsAes128GcmSha256, extensions));
            if (ReadUntil(stream, 22))
            {
                WriteHandshake(stream, 11, new byte[4]);
            }
        });

        /// <summary>TLS 1.2 ECDHE_ECDSA flight: ServerHello, Certificate (real P-256), ServerKeyExchange for
        /// <paramref name="group"/> with <paramref name="point"/>, signed ecdsa_secp256r1_sha256 over the real
        /// randoms (RFC 8422 5.4, RFC 5246 7.4.3), ServerHelloDone. Tripwire: after the client's ChangeCipherSpec
        /// and Finished, a ChangeCipherSpec and a Finished record that cannot decrypt (bad_record_mac).</summary>
        public static SmokeServerHost StartTls12KeyExchange(int group, byte[] point) => StartRaw((stream, hello) =>
        {
            SmokeServerKey key = P256.Value;
            byte[] parameters = Concat(new byte[] { 3 }, U16(group), Vec(1, point));
            ISigner signer = SignerUtilities.GetSigner("SHA256WITHECDSA");
            signer.Init(true, new ParametersWithRandom(key.PrivateKey, new SecureRandom()));
            byte[] signed = Concat(hello.Random, Tls12ServerRandom, parameters);
            signer.BlockUpdate(signed, 0, signed.Length);
            byte[] keyExchange = Concat(parameters, new byte[] { 4, 3 }, Vec(2, signer.GenerateSignature()));
            WriteHandshake(stream, 2, Tls12ServerHelloBody(hello, TlsEcdheEcdsaAes128GcmSha256));
            WriteHandshake(stream, 11, Vec(3, Vec(3, key.CertificateDer)));
            WriteHandshake(stream, 12, keyExchange);
            WriteHandshake(stream, 14, new byte[0]);
            if (ReadUntil(stream, 20) && ReadUntil(stream, 22))
            {
                WriteRecord(stream, 20, new byte[] { 1 });
                WriteRecord(stream, 22, new byte[40]);
            }
        });

        /// <summary>A TLS 1.2 server random without the RFC 8446 4.1.3 downgrade sentinel.</summary>
        private static readonly byte[] Tls12ServerRandom = Fill(32, 0x5a);

        private static byte[] Tls12ServerHelloBody(ClientHelloInfo hello, int suite)
        {
            // RFC 5746 3.6: renegotiation_info answers the SCSV; extended_master_secret only when offered.
            byte[] extensions = Extension(0xff01, new byte[] { 0 });
            if (hello.ExtensionTypes.Contains(0x0017))
            {
                extensions = Concat(extensions, Extension(0x0017, new byte[0]));
            }
            return ServerHelloBody(Tls12ServerRandom, new byte[0], suite, extensions);
        }

        private static byte[] ServerHelloBody(byte[] random, byte[] sessionId, int suite, byte[] extensions) =>
            Concat(U16(0x0303), random, Vec(1, sessionId), U16(suite), new byte[] { 0 }, Vec(2, extensions));

        /// <summary>Reads the ClientHello, runs <paramref name="respond"/>, then reads until the client closes, so
        /// the client's alert is not cut off by a reset. A client that has gone mid-response ends the handler
        /// quietly: only what the client raised matters to the rows.</summary>
        private static SmokeServerHost StartRaw(Action<Stream, ClientHelloInfo> respond) =>
            SmokeServerHost.Start(stream =>
            {
                ClientHelloInfo hello = ClientHelloInfo.Parse(ReadRecord(stream, out int type));
                if (type != 22)
                {
                    throw new InvalidDataException("first record type " + type);
                }
                try
                {
                    respond(stream, hello);
                    stream.Flush();
                }
                catch (IOException)
                {
                    return; // the client has gone (it rejected the flight)
                }
                Drain(stream);
            }, RawIoTimeoutMillis);

        /// <summary>Reads records until one of <paramref name="contentType"/> (true), or an alert or end of stream
        /// (false: the client rejected what came before).</summary>
        private static bool ReadUntil(Stream stream, int contentType)
        {
            while (true)
            {
                int type;
                try
                {
                    ReadRecord(stream, out type);
                }
                catch (EndOfStreamException)
                {
                    return false;
                }
                if (type == contentType)
                {
                    return true;
                }
                if (type == 21)
                {
                    return false;
                }
            }
        }

        private static void Drain(Stream stream)
        {
            var buffer = new byte[1024];
            try
            {
                while (stream.Read(buffer, 0, buffer.Length) > 0)
                {
                }
            }
            catch (IOException)
            {
                // the client has gone
            }
        }

        /// <summary>One TLSPlaintext record's fragment (RFC 8446 5.1).</summary>
        private static byte[] ReadRecord(Stream stream, out int contentType)
        {
            byte[] header = ReadExactly(stream, 5);
            contentType = header[0];
            return ReadExactly(stream, (header[3] << 8) | header[4]);
        }

        private static void WriteRecord(Stream stream, int contentType, byte[] fragment)
        {
            byte[] record = Concat(new byte[] { (byte)contentType, 3, 3 }, U16(fragment.Length), fragment);
            stream.Write(record, 0, record.Length);
        }

        private static byte[] ReadExactly(Stream stream, int length)
        {
            var buffer = new byte[length];
            int read = 0;
            while (read < length)
            {
                int n = stream.Read(buffer, read, length - read);
                if (n <= 0)
                {
                    throw new EndOfStreamException("client closed after " + read + " of " + length + " bytes");
                }
                read += n;
            }
            return buffer;
        }

        /// <summary>One handshake message in one handshake(22) record, legacy_record_version 0x0303.</summary>
        private static void WriteHandshake(Stream stream, int type, byte[] body) =>
            WriteRecord(stream, 22, Concat(new byte[] { (byte)type }, U24(body.Length), body));

        private static byte[] Extension(int type, byte[] data) => Concat(U16(type), Vec(2, data));

        private static byte[] Vec(int lengthBytes, byte[] data)
        {
            var length = new byte[lengthBytes];
            for (int i = 0; i < lengthBytes; i++)
            {
                length[i] = (byte)(data.Length >> (8 * (lengthBytes - 1 - i)));
            }
            return Concat(length, data);
        }

        private static byte[] U16(int value) => new[] { (byte)(value >> 8), (byte)value };

        private static byte[] U24(int value) => new[] { (byte)(value >> 16), (byte)(value >> 8), (byte)value };

        private static byte[] Fill(int length, byte value)
        {
            var result = new byte[length];
            for (int i = 0; i < length; i++)
            {
                result[i] = value;
            }
            return result;
        }

        private static byte[] Concat(params byte[][] parts)
        {
            var output = new MemoryStream();
            foreach (byte[] part in parts)
            {
                output.Write(part, 0, part.Length);
            }
            return output.ToArray();
        }

        private static byte[] Hex(string hex) => Convert.FromHexString(hex);

        /// <summary>What the raw handlers need from the client's first flight (RFC 8446 4.1.2, RFC 5246 7.4.1.2).
        /// </summary>
        private sealed class ClientHelloInfo
        {
            public byte[] Random;
            public byte[] SessionId;
            public readonly HashSet<int> ExtensionTypes = new HashSet<int>();

            /// <summary>Parses a ClientHello that fits one record (the smoke client's does).</summary>
            public static ClientHelloInfo Parse(byte[] fragment)
            {
                if (fragment.Length < 4 || fragment[0] != 1)
                {
                    throw new InvalidDataException("first record is not a ClientHello");
                }
                int end = 4 + ((fragment[1] << 16) | (fragment[2] << 8) | fragment[3]);
                if (end > fragment.Length)
                {
                    throw new InvalidDataException("ClientHello spans records");
                }
                var info = new ClientHelloInfo();
                int pos = 4 + 2; // legacy_version
                info.Random = Slice(fragment, pos, 32);
                pos += 32;
                info.SessionId = Slice(fragment, pos + 1, fragment[pos]);
                pos += 1 + fragment[pos];
                pos += 2 + ((fragment[pos] << 8) | fragment[pos + 1]); // cipher_suites
                pos += 1 + fragment[pos]; // legacy_compression_methods
                int extensionsEnd = pos + 2 + ((fragment[pos] << 8) | fragment[pos + 1]);
                pos += 2;
                while (pos < extensionsEnd)
                {
                    info.ExtensionTypes.Add((fragment[pos] << 8) | fragment[pos + 1]);
                    pos += 4 + ((fragment[pos + 2] << 8) | fragment[pos + 3]);
                }
                return info;
            }

            private static byte[] Slice(byte[] data, int offset, int length)
            {
                var result = new byte[length];
                Buffer.BlockCopy(data, offset, result, 0, length);
                return result;
            }
        }
    }
}
