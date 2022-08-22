using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;

namespace SecureBootPolicy
{
    internal static class SpanExtensions
    {
        internal static Span<byte> AsSpan<T>(ref T val) where T : unmanaged
        {
            unsafe
            {
                void* valPtr = Unsafe.AsPointer(ref val);
                return new Span<byte>(valPtr, sizeof(T));
            }
        }
    }
}
