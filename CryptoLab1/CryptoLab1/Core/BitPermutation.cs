using System;

namespace CryptoLab1.Core
{
    public static class BitPermutation
    {

        public static byte[] Permute(
            byte[] value,
            int[] pBlock,
            BitDirection direction,
            int startIndex)
        {
            ArgumentNullException.ThrowIfNull(value);
            ArgumentNullException.ThrowIfNull(pBlock);

            var totalInputBits = value.Length * 8;
            var totalOutputBits = pBlock.Length;

            byte[] result = new byte[(totalOutputBits + 7) / 8];

            for (var outBitIndex = 0; outBitIndex < totalOutputBits; outBitIndex++)
            {
                var inBitIndex = pBlock[outBitIndex] - startIndex;

                if (inBitIndex < 0 || inBitIndex >= totalInputBits)
                    throw new ArgumentOutOfRangeException(
                        nameof(pBlock),
                        $"pBlock[{outBitIndex}] = {pBlock[outBitIndex]} with startIndex = {startIndex} " +
                        $"yields bit index {inBitIndex}, which is out of range [0, {totalInputBits - 1}].");


                var bit = GetBit(value, inBitIndex, direction);
                SetBit(result, outBitIndex, bit, direction);
            }

            return result;
        }

        public static int GetBit(byte[] data, int bitIndex, BitDirection direction)
        {
            ArgumentNullException.ThrowIfNull(data);

            var totalBits = data.Length * 8;
            if (bitIndex < 0 || bitIndex >= totalBits)
                throw new ArgumentOutOfRangeException(
                    nameof(bitIndex),
                    $"Bit index {bitIndex} is out of range [0, {totalBits - 1}].");


            var (byteIndex, bitShift) = GetIndexAndShift(direction, data.Length, bitIndex);


            return (data[byteIndex] >> bitShift) & 1;
        }

        public static void SetBit(byte[] data, int bitIndex, int bitValue, BitDirection direction)
        {
            ArgumentNullException.ThrowIfNull(data);

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
                // totalBits = 24, bitIndex = 3
                // 10011100_00011101_00111011
                // 012345 Msb          | |  |
                //                 Lsb 543210
                //   ^ this bit
                byteIndex = bitIndex / 8;
                bitShift = 7 - (bitIndex % 8);
            }
            else
            {
                byteIndex = dataLen - 1 - bitIndex / 8;
                bitShift = bitIndex % 8;
            }
            return (byteIndex, bitShift);
        }
    }
}
