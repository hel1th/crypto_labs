
using System.Security.Cryptography;

namespace CryptoLab1.Core.Modes
{
    internal class RandomDeltaModeHandler : ICipherModeHandler
    {
        public bool RequiresIv => true;
        public bool RequiresPadding => false;

        public void Encrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Validate(cipher, input, output, iv);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

            Span<byte> deltaBuffer = stackalloc byte[blockSize];
            var delta = GetOrGenerateDelta(blockSize, extraParams, deltaBuffer);

            Span<byte> counter = stackalloc byte[blockSize];
            iv!.CopyTo(counter);

            Span<byte> keystream = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                cipher.Encrypt(counter, keystream);
                ByteUtils.Xor(inputBlock, keystream, outputBlock);

                AddDelta(counter, delta);
            }

            if (remainder > 0)
            {
                var offset = blockCount * blockSize;

                cipher.Encrypt(counter, keystream);
                ByteUtils.Xor(
                    input.Slice(offset, remainder),
                    keystream[..remainder],
                    output.Slice(offset, remainder));
            }
        }

        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            ValidateDelta(extraParams, cipher.BlockSizeBytes);

            Encrypt(cipher, input, output, iv, extraParams);
        }

        private static ReadOnlySpan<byte> GetOrGenerateDelta(
            int blockSize,
            object[]? extraParams,
            Span<byte> fallbackBuffer)
        {
            if (
                extraParams is { Length: > 0 }
                && extraParams[0] is byte[] delta
                && delta.Length == blockSize
            )
                return delta;

            RandomNumberGenerator.Fill(fallbackBuffer);
            return fallbackBuffer;
        }

        private static void AddDelta(Span<byte> counter, ReadOnlySpan<byte> delta)
        {
            var carry = 0;
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                var sum = counter[i] + delta[i] + carry;
                counter[i] = (byte)sum;
                carry = sum >> 8;
            }
        }

        private static void ValidateDelta(
            object[]? extraParams,
            int blockSize)
        {
            if (extraParams == null || extraParams.Length == 0 || extraParams[0] is not byte[] delta || delta.Length != blockSize)
            {
                throw new ArgumentException(
                    $"Delta of length {blockSize} bytes must be provided in extraParams[0].",
                    nameof(extraParams));
            }
        }

        private static void Validate(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv)
        {
            ArgumentNullException.ThrowIfNull(cipher);

            if (iv is null || iv.Length != cipher.BlockSizeBytes)
                throw new ArgumentException($"IV must be {cipher.BlockSizeBytes} bytes long.", nameof(iv));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output length ({output.Length}) must be at least as long as input length ({input.Length}).", nameof(output));
        }
    }
}
