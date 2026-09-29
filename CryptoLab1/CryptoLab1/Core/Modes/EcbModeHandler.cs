
namespace CryptoLab1.Core.Modes
{
    internal class EcbModeHandler : ICipherModeHandler
    {
        public bool RequiresIv => false;

        public bool RequiresPadding => true;

        public void Encrypt(ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Validate(cipher, input, output);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;

                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);
                    
                cipher.Encrypt(inputBlock, outputBlock);
            }
        }

        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Validate(cipher, input, output);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;

                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                cipher.Decrypt(inputBlock, outputBlock);
            }
        }

        private static void Validate(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            ArgumentNullException.ThrowIfNull(cipher);

            var blockSize = cipher.BlockSizeBytes;
            if (input.Length % blockSize != 0)
                throw new ArgumentException($"Input length ({input.Length}) must be a multiple of block size ({blockSize}).", nameof(input));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output buffer length ({output.Length}) cannot be smaller than input length ({input.Length}).", nameof(output));
        }
    }
}

