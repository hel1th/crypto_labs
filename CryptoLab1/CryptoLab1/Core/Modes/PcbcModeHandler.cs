
namespace CryptoLab1.Core.Modes
{
    internal class PcbcModeHandler : ICipherModeHandler
    {
        public bool RequiresIv => true;

        public bool RequiresPadding => true;

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

            Span<byte> feedback = stackalloc byte[blockSize];
            iv!.CopyTo(feedback);

            Span<byte> xorBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                ByteUtils.Xor(inputBlock, feedback, xorBlock);
                cipher.Encrypt(xorBlock, outputBlock);

                ByteUtils.Xor(inputBlock, outputBlock, feedback);
            }
        }


        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Validate(cipher, input, output, iv);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            Span<byte> feedback = stackalloc byte[blockSize];
            iv!.CopyTo(feedback);

            Span<byte> currentCipherBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;

                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                inputBlock.CopyTo(currentCipherBlock);

                cipher.Decrypt(currentCipherBlock, outputBlock);

                ByteUtils.Xor(outputBlock, feedback, outputBlock);

                ByteUtils.Xor(outputBlock, currentCipherBlock, feedback);
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

            if (input.Length % cipher.BlockSizeBytes != 0)
                throw new ArgumentException($"Input length ({input.Length}) must be a multiple of block size ({cipher.BlockSizeBytes}).", nameof(input));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output length ({output.Length}) must be at least as long as input length ({input.Length}).", nameof(output));
        }
    }
}

