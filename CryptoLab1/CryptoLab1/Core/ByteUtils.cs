
namespace CryptoLab1.Core
{
    public static class ByteUtils
    {
        public static void Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b, Span<byte> destination)
        {
            if (a.Length != b.Length)
                throw new ArgumentException($"Source spans must have equal length: {a.Length} and {b.Length}.");

            if (destination.Length < a.Length)
                throw new ArgumentException($"Destination span length ({destination.Length}) is too small for result ({a.Length}).");

            for (var i = 0; i < a.Length; i++)
                destination[i] = (byte)(a[i] ^ b[i]);
        }

    }
}
