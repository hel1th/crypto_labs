using System.Security.Cryptography;

namespace CryptoLab1.Core
{
    public static class Padding
    {

        public static byte[] Apply(byte[] data, int blockSize, PaddingMode mode)
        {
            ArgumentNullException.ThrowIfNull(data);
            return Apply(data.AsSpan(), blockSize, mode);
        }


        public static byte[] Apply(ReadOnlySpan<byte> data, int blockSize, PaddingMode mode)
        {
            ValidateBlockSize(blockSize);

            var padLen = CalculatePaddingLength(data.Length, blockSize, mode);
            var result = new byte[data.Length + padLen];
            data.CopyTo(result);

            if (padLen == 0)
                return result;

            var padSpan = result.AsSpan(data.Length, padLen);

            switch (mode)
            {
                case PaddingMode.Zeros:
                    padSpan.Clear();
                    break;

                case PaddingMode.AnsiX923:
                    padSpan[..^1].Clear();
                    padSpan[^1] = (byte)padLen;
                    break;

                case PaddingMode.Pkcs7:
                    padSpan.Fill((byte)padLen);
                    break;

                case PaddingMode.Iso10126:
                    if (padLen > 1)
                        RandomNumberGenerator.Fill(padSpan[..^1]);
                    
                    padSpan[^1] = (byte)padLen;
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported padding mode.");
            }

            return result;
        }


        public static byte[] Remove(byte[] data, int blockSize, PaddingMode mode)
        {
            ArgumentNullException.ThrowIfNull(data);
            return Remove(data.AsSpan(), blockSize, mode);
        }

        public static byte[] Remove(ReadOnlySpan<byte> data, int blockSize, PaddingMode mode)
        {
            ValidateBlockSize(blockSize);

            if (data.Length == 0 || data.Length % blockSize != 0)
                throw new ArgumentException($"Data length ({data.Length}) must be a non-zero multiple of block size ({blockSize}).");

            if (mode == PaddingMode.Zeros)
            {
                var end = data.Length;
                while (end > 0 && data[end - 1] == 0)
                    end--;
                    
                return [.. data[..end]];
            }

            var padLen = GetAndValidatePaddingLength(data, blockSize, mode);
            var padStart = data.Length - padLen;

            switch (mode)
            {
                case PaddingMode.AnsiX923:
                    for (var i = padStart; i < data.Length - 1; i++)
                    {
                        if (data[i] != 0)
                            throw new ArgumentException("Invalid ANSI X.923 padding: non-zero byte found before length indicator.");
                    }
                    break;

                case PaddingMode.Pkcs7:
                    for (var i = padStart; i < data.Length; i++)
                    {
                        if (data[i] != padLen)
                            throw new ArgumentException($"Invalid PKCS#7 padding: expected byte {padLen}, found {data[i]}.");
                    }
                    break;

                case PaddingMode.Iso10126:
                    break;

                default:
                    throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unsupported padding mode.");
            }

            return [.. data[..padStart]];
        }

        private static int GetAndValidatePaddingLength(ReadOnlySpan<byte> data, int blockSize, PaddingMode mode)
        {
            int padLen = data[^1];
            if (padLen <= 0 || padLen > blockSize || padLen > data.Length)
                throw new ArgumentException($"Invalid {mode} padding length: {padLen}.");

            return padLen;
        }

        private static int CalculatePaddingLength(int dataLength, int blockSize, PaddingMode mode)
        {
            var remainder = dataLength % blockSize;

            if (mode != PaddingMode.Zeros) return remainder == 0 ? blockSize : blockSize - remainder;

            if (dataLength == 0)
                return blockSize;

            return remainder == 0 ? 0 : blockSize - remainder;
        }

        private static void ValidateBlockSize(int blockSize)
        {
            if (blockSize is <= 0 or > 256)
                throw new ArgumentOutOfRangeException(nameof(blockSize), blockSize, "Block size must be between 1 and 256 bytes.");
        }
    }
}
