using CryptoLab1.Core;

namespace CryptoLab1.Des
{
    public class DesRoundFunction : IRoundFunction
    {
        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            var result = new byte[4];
            Transform(inputBlock, roundKey, result);
            return result;
        }

        public void Transform(ReadOnlySpan<byte> inputBlock, ReadOnlySpan<byte> roundKey, Span<byte> destination)
        {
            Span<byte> expanded = stackalloc byte[6];
            BitPermutation.Permute(inputBlock, DesConstants.E, BitNumbering.Msb1, expanded);

            Span<byte> xored = stackalloc byte[6];
            ByteUtils.Xor(expanded, roundKey, xored);

            Span<byte> substituted = stackalloc byte[4];
            SBoxSubstitute(xored, substituted);

            BitPermutation.Permute(substituted, DesConstants.P, BitNumbering.Msb1, destination);
        }

        private static void SBoxSubstitute(ReadOnlySpan<byte> input48, Span<byte> output32)
        {
            if (input48.Length != 6)
                throw new ArgumentException("Input must be 6 bytes (48 bits) for S-box substitution.");

            if (output32.Length < 4)
                throw new ArgumentException("Output must have at least 4 bytes (32 bits).");

            for (var b = 0; b < 4; b++)
            {
                var s1 = b * 2;
                var s2 = b * 2 + 1;

                var chunk1 = GetChunk(s1, input48);
                var val1 = DesConstants.SBoxes[s1, GetRow(chunk1), GetColumn(chunk1)];

                var chunk2 = GetChunk(s2, input48);
                var val2 = DesConstants.SBoxes[s2, GetRow(chunk2), GetColumn(chunk2)];

                output32[b] = (byte)((val1 << 4) | val2);
            }
        }

        private static byte GetChunk(int i, ReadOnlySpan<byte> input48)
        {
            var bitOffset = i * 6;
            var byteIndex = bitOffset / 8;
            var bitInByte = bitOffset % 8;

            var window = (input48[byteIndex] << 8) | (byteIndex + 1 < input48.Length ? input48[byteIndex + 1] : 0);
            var chunk = (window >> (10 - bitInByte)) & 0x3F;

            return (byte)chunk;
        }

        private static int GetRow(byte chunk)
        {
            return ((chunk & 0x20) >> 4) | (chunk & 0x01);
        }

        private static int GetColumn(byte chunk)
        {
            return (chunk >> 1) & 0x0F;
        }
    }
}
