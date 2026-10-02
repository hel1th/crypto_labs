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

            int offset;
            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

            Span<byte> keystream = stackalloc byte[blockSize];

            for (var i = 0; i < blockCount; i++)
            {
                offset = i * blockSize;
                var inputBlock = input.Slice(offset, blockSize);
                var outputBlock = output.Slice(offset, blockSize);

                EncryptBlock(cipher, inputBlock, outputBlock, state, keystream);
            }

            if (remainder == 0) return;

            offset = blockCount * blockSize;
            ProcessTail(cipher, input.Slice(offset, remainder),
                output.Slice(offset, remainder), state, keystream);
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

            int offset;
            var blockSize = cipher.BlockSizeBytes;
            var blockCount = input.Length / blockSize;
            var remainder = input.Length % blockSize;

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
                            var blkOffset = i * blockSize;
                            var inBlock = new ReadOnlySpan<byte>((byte*)(inAddr + blkOffset), blockSize);
                            var outBlock = new Span<byte>((byte*)(outAddr + blkOffset), blockSize);

                            Span<byte> keystream = stackalloc byte[blockSize];
                            if (i == 0)
                            {
                                cipher.Encrypt(stateCopy, keystream);
                            }
                            else
                            {
                                var prevCipherBlock = new ReadOnlySpan<byte>((byte*)(inAddr + (i - 1) * blockSize), blockSize);
                                cipher.Encrypt(prevCipherBlock, keystream);
                            }

                            ByteUtils.Xor(inBlock, keystream, outBlock);
                        });
                    }
                }

                input.Slice((blockCount - 1) * blockSize, blockSize).CopyTo(state);

                if (remainder > 0)
                {
                    offset = blockCount * blockSize;
                    Span<byte> keystream = stackalloc byte[blockSize];
                    ProcessTail(cipher, input.Slice(offset, remainder),
                        output.Slice(offset, remainder), state, keystream);
                }
            }
            else
            {
                Span<byte> keystream = stackalloc byte[blockSize];
                Span<byte> currentCipherBlock = stackalloc byte[blockSize];

                for (var i = 0; i < blockCount; i++)
                {
                    offset = i * blockSize;
                    var inputBlock = input.Slice(offset, blockSize);
                    var outputBlock = output.Slice(offset, blockSize);

                    DecryptBlock(cipher, inputBlock, outputBlock, state, keystream, currentCipherBlock);
                }

                if (remainder == 0) return;

                offset = blockCount * blockSize;
                ProcessTail(cipher, input.Slice(offset, remainder),
                    output.Slice(offset, remainder), state, keystream);
            }
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