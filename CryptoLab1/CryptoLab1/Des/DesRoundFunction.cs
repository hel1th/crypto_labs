using CryptoLab1.Core;

namespace CryptoLab1.Des
{
    public class DesRoundFunction : IRoundFunction
    {
        public byte[] Transform(byte[] inputBlock, byte[] roundKey)
        {
            var expanded = BitPermutation.Permute(inputBlock, DesConstants.E, BitNumbering.Msb1);
            var xored = ByteUtils.Xor(expanded, roundKey);
            var substituted = SBoxSubstitute(xored);

            return BitPermutation.Permute(substituted, DesConstants.P, BitNumbering.Msb1);
        }

        private static byte[] SBoxSubstitute(byte[] input48)
        {
            if (input48.Length != 6)
                throw new ArgumentException("Input must be 6 bytes (48 bits) for S-box substitution.");

            var output32 = new byte[4];

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

            return output32;
        }

        private static byte GetChunk(int i, byte[] input48)
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
