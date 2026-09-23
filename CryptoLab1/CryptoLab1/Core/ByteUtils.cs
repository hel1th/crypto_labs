using System;

namespace CryptoLab1.Core
{
    public static class ByteUtils
    {
        public static (byte[] Left, byte[] Right) SplitHalves(byte[] block)
        {
            ArgumentNullException.ThrowIfNull(block);
            if (block.Length % 2 != 0)
                throw new ArgumentException("Block size must be an even number of bytes.");

            var half = block.Length / 2;
            return (block[..half], block[half..]);
        }


        public static byte[] Combine(byte[] first, byte[] second)
        {
            ArgumentNullException.ThrowIfNull(first);
            ArgumentNullException.ThrowIfNull(second);

            var result = new byte[first.Length + second.Length];
            first.CopyTo(result, 0);
            second.CopyTo(result, first.Length);
            return result;
        }


        public static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
        {
            if (a.Length != b.Length)
                throw new ArgumentException($"Source spans must have equal length: {a.Length} and {b.Length}.");

            if (destination.Length < a.Length)
                throw new ArgumentException($"Destination span length ({destination.Length}) is too small for result ({a.Length}).");

            for (var i = 0; i < a.Length; i++)
                destination[i] = (byte)(a[i] ^ b[i]);
        }


        public static byte[] Xor(byte[] a, byte[] b)
        {
            ArgumentNullException.ThrowIfNull(a);
            ArgumentNullException.ThrowIfNull(b);

            var result = new byte[a.Length];
            Xor(a.AsSpan(), b.AsSpan(), result.AsSpan());
            return result;
        }
    }
}
