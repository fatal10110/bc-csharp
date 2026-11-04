// The [netframework] set's stand-in for BouncyCastleTlsStream.cs (defines.NET471_ONLY_ROOTS, #75). The consumer
// file overrides Stream.ReadAsync(Memory<byte>, ..) and WriteAsync(ReadOnlyMemory<byte>, ..) and uses ValueTask,
// which Unity's Mono BCL has at the .NET Framework API level and the net471 reference assemblies that set builds
// against do not. This file gives BouncyCastleTlsProvider.cs the two members it uses, so the other consumer files
// still compile against TurboBC.netfx.dll; the real stream's Bouncy Castle surface (TlsClientProtocol's
// non-blocking members, which carry no #if) is compiled by the netstandard2.1 sets. Never executed, every member
// throws; hand-maintained with the consumer file.

using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Tls;

namespace TurboHTTP.Transport.BouncyCastle
{
    internal sealed class BouncyCastleTlsStream : Stream
    {
        private const string Message = "BouncyCastleTlsStream.net471.cs is a compile-time stand-in";

        internal BouncyCastleTlsStream(Stream inner)
        {
            throw new NotSupportedException(Message);
        }

        internal Task HandshakeAsync(TlsClient client, CancellationToken ct) => throw new NotSupportedException(Message);

        public override bool CanRead => throw new NotSupportedException(Message);
        public override bool CanSeek => throw new NotSupportedException(Message);
        public override bool CanWrite => throw new NotSupportedException(Message);
        public override long Length => throw new NotSupportedException(Message);

        public override long Position
        {
            get => throw new NotSupportedException(Message);
            set => throw new NotSupportedException(Message);
        }

        public override void Flush() => throw new NotSupportedException(Message);

        public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException(Message);

        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException(Message);

        public override void SetLength(long value) => throw new NotSupportedException(Message);

        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException(Message);
    }
}
