namespace CryptoLab1.Core.Modes
{
    internal class EcbModeHandler : ICipherModeHandler
    {
        public bool RequiresIv => false;

        public bool RequiresPadding => true;

        public void Encrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            EncryptChunk(cipher, input, output, [], extraParams);
        }

        public void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams)
        {
            DecryptChunk(cipher, input, output, [], extraParams);
        }

        private const int ParallelThreshold = 4;

        public void EncryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            Validate(cipher, input, output);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            if (blockCount >= ParallelThreshold)
            {
                unsafe
                {
                    fixed (byte* pIn = input, pOut = output)
                    {
                        var inAddr = (nint)pIn;
                        var outAddr = (nint)pOut;

                        Parallel.For(0, blockCount, i =>
                        {
                            var offset = i * blockSize;
                            var inBlock = new ReadOnlySpan<byte>((byte*)(inAddr + offset), blockSize);
                            var outBlock = new Span<byte>((byte*)(outAddr + offset), blockSize);
                            cipher.Encrypt(inBlock, outBlock);
                        });
                    }
                }
            }
            else
            {
                for (var i = 0; i < blockCount; i++)
                {
                    var offset = i * blockSize;
                    var inputBlock = input.Slice(offset, blockSize);
                    var outputBlock = output.Slice(offset, blockSize);

                    cipher.Encrypt(inputBlock, outputBlock);
                }
            }
        }

        public void DecryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            Validate(cipher, input, output);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            if (blockCount >= ParallelThreshold)
            {
                unsafe
                {
                    fixed (byte* pIn = input, pOut = output)
                    {
                        var inAddr = (nint)pIn;
                        var outAddr = (nint)pOut;

                        Parallel.For(0, blockCount, i =>
                        {
                            var offset = i * blockSize;
                            var inBlock = new ReadOnlySpan<byte>((byte*)(inAddr + offset), blockSize);
                            var outBlock = new Span<byte>((byte*)(outAddr + offset), blockSize);
                            cipher.Decrypt(inBlock, outBlock);
                        });
                    }
                }
            }
            else
            {
                for (var i = 0; i < blockCount; i++)
                {
                    var offset = i * blockSize;
                    var inputBlock = input.Slice(offset, blockSize);
                    var outputBlock = output.Slice(offset, blockSize);

                    cipher.Decrypt(inputBlock, outputBlock);
                }
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
