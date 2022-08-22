using System;
using System.Buffers;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecureBootPolicy
{
    internal static class StreamExtensions
    {
        internal static void Write(this Stream thisStream, ReadOnlySpan<byte> buffer)
        {
            byte[] sharedBuffer = ArrayPool<byte>.Shared.Rent(buffer.Length);
            try
            {
                buffer.CopyTo(sharedBuffer);
                thisStream.Write(sharedBuffer, 0, buffer.Length);
            }
            finally { ArrayPool<byte>.Shared.Return(sharedBuffer); }
        }
    }
}
