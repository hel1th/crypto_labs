
namespace CryptoLab1.Core.Modes
{
    internal class CbcModeHandler : ICipherModeHandler
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

            Span<byte> prevBlock = stackalloc byte[blockSize];
            iv!.CopyTo(prevBlock);

            Span<byte> xorBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                ByteUtils.Xor(inputBlock, prevBlock, xorBlock);
                cipher.Encrypt(xorBlock, outputBlock);

                outputBlock.CopyTo(prevBlock);
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

            Span<byte> prevBlock = stackalloc byte[blockSize];
            iv!.CopyTo(prevBlock);

            Span<byte> currentCipherBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                inputBlock.CopyTo(currentCipherBlock);

                cipher.Decrypt(inputBlock, outputBlock);
                ByteUtils.Xor(outputBlock, prevBlock, outputBlock);

                currentCipherBlock.CopyTo(prevBlock);
            }
        }

        private static void Validate(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv)
        {
            ArgumentNullException.ThrowIfNull(cipher);

            var blockSize = cipher.BlockSizeBytes;
            if (iv == null || iv.Length != blockSize)
                throw new ArgumentException($"IV must be non-null and exactly {blockSize} bytes long.", nameof(iv));

            if (input.Length % blockSize != 0)
                throw new ArgumentException($"Input length ({input.Length}) must be a multiple of block size ({blockSize}).", nameof(input));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output buffer length ({output.Length}) cannot be smaller than input length ({input.Length}).", nameof(output));
        }
    }
}

