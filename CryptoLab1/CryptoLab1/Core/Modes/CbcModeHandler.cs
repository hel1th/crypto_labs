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
            Validate(cipher, input, output, iv);

            Span<byte> state = stackalloc byte[cipher.BlockSizeBytes];
            iv!.CopyTo(state);

            DecryptChunk(cipher, input, output, state, extraParams);
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

            Span<byte> xorBlock = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                var offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                ByteUtils.Xor(inputBlock, state, xorBlock);
                cipher.Encrypt(xorBlock, outputBlock);

                outputBlock.CopyTo(state);
            }
        }

        private const int ParallelThreshold = 4;

        public void DecryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            ValidateChunk(cipher, input, output, state);

            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;

            if (blockCount >= ParallelThreshold)
            {
                byte[] stateCopy = state.ToArray();
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

                            if (i == 0)
                            {
                                ByteUtils.Xor(outBlock, stateCopy, outBlock);
                            }
                            else
                            {
                                var prevBlock = new ReadOnlySpan<byte>((byte*)(inAddr + (i - 1) * blockSize), blockSize);
                                ByteUtils.Xor(outBlock, prevBlock, outBlock);
                            }
                        });
                    }
                }

                input.Slice((blockCount - 1) * blockSize, blockSize).CopyTo(state);
            }
            else
            {
                Span<byte> currentCipherBlock = stackalloc byte[blockSize];

                for (var i = 0; i < blockCount; i++)
                {
                    var offset = i * blockSize;
                    var inputBlock = input.Slice(offset, blockSize);
                    var outputBlock = output.Slice(offset, blockSize);

                    inputBlock.CopyTo(currentCipherBlock);

                    cipher.Decrypt(inputBlock, outputBlock);
                    ByteUtils.Xor(outputBlock, state, outputBlock);

                    currentCipherBlock.CopyTo(state);
                }
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

        private static void ValidateChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            ReadOnlySpan<byte> state)
        {
            ArgumentNullException.ThrowIfNull(cipher);

            var blockSize = cipher.BlockSizeBytes;
            if (state.Length != blockSize)
                throw new ArgumentException($"State must be exactly {blockSize} bytes long.", nameof(state));

            if (input.Length % blockSize != 0)
                throw new ArgumentException($"Input length ({input.Length}) must be a multiple of block size ({blockSize}).", nameof(input));

            if (output.Length < input.Length)
                throw new ArgumentException($"Output buffer length ({output.Length}) cannot be smaller than input length ({input.Length}).", nameof(output));
        }
    }
}
