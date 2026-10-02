namespace CryptoLab1.Core.Modes
{
    internal class OfbModeHandler : ICipherModeHandler
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

            Span<byte> state = stackalloc byte[cipher.BlockSizeBytes];
            iv!.CopyTo(state);

            EncryptChunk(cipher, input, output, state, extraParams);
        }

        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            Encrypt(cipher, input, output, iv, extraParams);
        }

        public void EncryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            ValidateChunk(cipher, input, output, state);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

            Span<byte> keystream = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                ProcessBlock(cipher, inputBlock, outputBlock, state, keystream);
            }

            if (remainder > 0)
            {
                var offset = blockCount * blockSize;
                ProcessTail(cipher, input.Slice(offset, remainder),
                    output.Slice(offset, remainder), state, keystream);
            }
        }

        public void DecryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            EncryptChunk(cipher, input, output, state, extraParams);
        }

        private static void ProcessBlock(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> inputBlock,
            Span<byte> outputBlock,
            Span<byte> feedback,
            Span<byte> keystream)
        {
            cipher.Encrypt(feedback, keystream);
            ByteUtils.Xor(inputBlock, keystream, outputBlock);
            keystream.CopyTo(feedback);
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

        private static void ValidateChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> state)
        {
            ArgumentNullException.ThrowIfNull(cipher);

            if (state.Length != cipher.BlockSizeBytes)
                throw new ArgumentException($"State must be {cipher.BlockSizeBytes} bytes long.", nameof(state));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output length ({output.Length}) must be at least as long as input length ({input.Length}).", nameof(output));
        }
    }
}