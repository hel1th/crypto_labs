
namespace CryptoLab1.Core.Modes
{
    internal class CtrModeHandler : ICipherModeHandler
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

                IncrementCounter(counter);
            }

            if (remainder > 0)
            {
                var offset = blockCount * blockSize;

                cipher.Encrypt(counter, keystream);

                ByteUtils.Xor(
                    keystream[..remainder],
                    input.Slice(offset, remainder),
                    output.Slice(offset, remainder));

            }
        }

        private static void IncrementCounter(Span<byte> counter)
        {
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
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