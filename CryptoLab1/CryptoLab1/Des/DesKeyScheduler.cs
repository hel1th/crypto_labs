using System;
using CryptoLab1.Core;

namespace CryptoLab1.Des
{
    public class DesKeyScheduler : IKeyScheduler
    {
        private const int KeySizeBytes = 8;
        private const int RoundsCount = 16;
        private const int RoundKeySizeBytes = 6;

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            ValidateKey(key);

            Span<byte> key56 = new byte[7];
            BitPermutation.Permute(key, DesConstants.PС1, BitNumbering.Msb1, key56);

            var (c, d) = Split56To28BitHalves(key56);

            var roundKeys = new byte[RoundsCount][];
            Span<byte> cd56 = new byte[7];

            for (var i = 0; i < RoundsCount; i++)
            {
                var shift = DesConstants.Shifts[i];
                c = RotateLeft28(c, shift);
                d = RotateLeft28(d, shift);

                Combine28BitHalvesTo56(c, d, cd56);

                var roundKey = new byte[RoundKeySizeBytes];
                BitPermutation.Permute(cd56, DesConstants.PС2, BitNumbering.Msb1, roundKey);

                roundKeys[i] = roundKey;
            }

            return roundKeys;
        }

        private static (uint C, uint D) Split56To28BitHalves(ReadOnlySpan<byte> key56)
        {
            var c = ((uint)key56[0] << 20) |
                     ((uint)key56[1] << 12) |
                     ((uint)key56[2] << 4) |
                     ((uint)key56[3] >> 4);

            var d = (((uint)key56[3] & 0x0F) << 24) |
                     ((uint)key56[4] << 16) |
                     ((uint)key56[5] << 8) |
                     key56[6];

            return (c, d);
        }

        private static uint RotateLeft28(uint value, int shift) =>
            ((value << shift) | (value >> (28 - shift))) & 0x0FFFFFFF;

        private static void Combine28BitHalvesTo56(uint c, uint d, Span<byte> destination)
        {
            destination[0] = (byte)(c >> 20);
            destination[1] = (byte)(c >> 12);
            destination[2] = (byte)(c >> 4);
            destination[3] = (byte)(((c & 0x0F) << 4) | ((d >> 24) & 0x0F));
            destination[4] = (byte)(d >> 16);
            destination[5] = (byte)(d >> 8);
            destination[6] = (byte)d;
        }

        private static void ValidateKey(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);
            if (key.Length != KeySizeBytes)
                throw new ArgumentException($"DES key must be exactly {KeySizeBytes} bytes (64 bits), but received {key.Length} bytes.");
        }
    }
}
