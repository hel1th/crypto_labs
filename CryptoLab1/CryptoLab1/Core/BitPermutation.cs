
namespace CryptoLab1.Core
{
    public static class BitPermutation
    {
        public static void Permute(
            ReadOnlySpan<byte> value,
            int[] pBlock,
            BitDirection direction,
            int startIndex,
            Span<byte> destination)
        {
            ArgumentNullException.ThrowIfNull(pBlock);

            var totalInputBits = value.Length * 8;
            var totalOutputBits = pBlock.Length;
            var requiredBytes = (totalOutputBits + 7) / 8;

            if (destination.Length < requiredBytes)
                throw new ArgumentException($"Destination span length ({destination.Length}) is less than required ({requiredBytes}).");

            destination[..requiredBytes].Clear();

            for (var outBitIndex = 0; outBitIndex < totalOutputBits; outBitIndex++)
            {
                var inBitIndex = pBlock[outBitIndex] - startIndex;

                if (inBitIndex < 0 || inBitIndex >= totalInputBits)
                    throw new ArgumentOutOfRangeException(
                        nameof(pBlock),
                        $"pBlock[{outBitIndex}] = {pBlock[outBitIndex]} with startIndex = {startIndex} " +
                        $"yields bit index {inBitIndex}, which is out of range [0, {totalInputBits - 1}].");

                var bit = GetBit(value, inBitIndex, direction);
                
                if (bit != 0)
                    SetBit(destination, outBitIndex, 1, direction);
            }
        }

        public static void Permute(
            ReadOnlySpan<byte> value,
            int[] pBlock,
            BitNumbering numbering,
            Span<byte> destination) =>
            Permute(value, pBlock, numbering.GetDirection(), numbering.GetStartIndex(), destination);

        public static byte[] Permute(
            byte[] value,
            int[] pBlock,
            BitDirection direction,
            int startIndex)
        {
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(pBlock);

            var totalOutputBits = pBlock.Length;
            var result = new byte[(totalOutputBits + 7) / 8];
            Permute(value.AsSpan(), pBlock, direction, startIndex, result.AsSpan());
            return result;
        }

        public static byte[] Permute(
            byte[] value,
            int[] pBlock,
            BitNumbering numbering) =>
            Permute(value, pBlock, numbering.GetDirection(), numbering.GetStartIndex());

        public static int GetBit(ReadOnlySpan<byte> data, int bitIndex, BitDirection direction)
        {
            var totalBits = data.Length * 8;
            if (bitIndex < 0 || bitIndex >= totalBits)
                throw new ArgumentOutOfRangeException(
                    nameof(bitIndex),
                    $"Bit index {bitIndex} is out of range [0, {totalBits - 1}].");

            var (byteIndex, bitShift) = GetIndexAndShift(direction, data.Length, bitIndex);

            return (data[byteIndex] >> bitShift) & 1;
        }

        public static void SetBit(Span<byte> data, int bitIndex, int bitValue, BitDirection direction)
        {
            var totalBits = data.Length * 8;
            if (bitIndex < 0 || bitIndex >= totalBits)
                throw new ArgumentOutOfRangeException(
                    nameof(bitIndex),
                    $"Bit index {bitIndex} is out of range [0, {totalBits - 1}].");

            var (byteIndex, bitShift) = GetIndexAndShift(direction, data.Length, bitIndex);

            if (bitValue == 1)
                data[byteIndex] |= (byte)(1 << bitShift);
            else
                data[byteIndex] &= (byte)~(1 << bitShift);
        }

        private static (int byteIndex, int bitShift) GetIndexAndShift(BitDirection direction, int dataLen, int bitIndex)
        {
            int byteIndex, bitShift;
            if (direction == BitDirection.MsbFirst)
            {
                byteIndex = bitIndex >> 3;
                bitShift = 7 - (bitIndex & 7);
            }
            else
            {
                byteIndex = dataLen - 1 - (bitIndex >> 3);
                bitShift = bitIndex & 7;
            }

            return (byteIndex, bitShift);
        }
    }
}
