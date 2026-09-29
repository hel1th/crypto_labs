
namespace CryptoLab1.Core.Modes
{
    internal class CfbModeHandler : ICipherModeHandler
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

            int offset;
            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

            Span<byte> feedback = stackalloc byte[blockSize];
            iv!.CopyTo(feedback);

            Span<byte> keystream = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                EncryptBlock(cipher, inputBlock, outputBlock,
                    feedback, keystream);
            }

            if (remainder == 0) return;

            offset = blockCount * blockSize;
            ProcessTail(cipher, input.Slice(offset, remainder),
                output.Slice(offset, remainder), feedback, keystream);

        }

        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Validate(cipher, input, output, iv);

            int offset;
            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

            Span<byte> feedback = stackalloc byte[blockSize];
            iv!.CopyTo(feedback);

            Span<byte> keystream = stackalloc byte[blockSize];
            Span<byte> currentCipherBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                DecryptBlock(cipher, inputBlock, outputBlock,
                    feedback, keystream, currentCipherBlock);
            }

            if (remainder == 0) return;

            offset = blockCount * blockSize;
            ProcessTail(cipher, input.Slice(offset, remainder),
                output.Slice(offset, remainder), feedback, keystream);

        }


        private static void EncryptBlock(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> inputBlock,
            Span<byte> outputBlock,
            Span<byte> feedback,
            Span<byte> keystream)
        {
            cipher.Encrypt(feedback, keystream);
            ByteUtils.Xor(inputBlock, keystream, outputBlock);
            outputBlock.CopyTo(feedback);
        }

        private static void DecryptBlock(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> inputBlock,
            Span<byte> outputBlock,
            Span<byte> feedback,
            Span<byte> keystream,
            Span<byte> tempCipherBlock)
        {
            inputBlock.CopyTo(tempCipherBlock);

            cipher.Encrypt(feedback, keystream);
            ByteUtils.Xor(inputBlock, keystream, outputBlock);

            tempCipherBlock.CopyTo(feedback);
        }

        private static void ProcessTail(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> inputTail,
            Span<byte> outputTail,
            ReadOnlySpan<byte> feedback,
            Span<byte> keystream)
        {
            cipher.Encrypt(feedback, keystream);
            ByteUtils.Xor(inputTail, keystream[..inputTail.Length], outputTail);
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