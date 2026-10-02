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

        private const int ParallelThreshold = 4;

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

            if (blockCount >= ParallelThreshold)
            {
                byte[] baseCounter = state.ToArray();
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

                            Span<byte> counter = stackalloc byte[blockSize];
                            Span<byte> keystream = stackalloc byte[blockSize];

                            AddOffset(baseCounter, (ulong)i, counter);
                            cipher.Encrypt(counter, keystream);
                            ByteUtils.Xor(inBlock, keystream, outBlock);
                        });
                    }
                }

                AddOffset(state, (ulong)blockCount, state);

                if (remainder > 0)
                {
                    var offset = blockCount * blockSize;
                    Span<byte> keystream = stackalloc byte[blockSize];

                    cipher.Encrypt(state, keystream);

                    ByteUtils.Xor(
                        keystream[..remainder],
                        input.Slice(offset, remainder),
                        output.Slice(offset, remainder));
                }
            }
            else
            {
                Span<byte> keystream = stackalloc byte[blockSize];

                for (var i = 0; i < blockCount; i++)
                {
                    var offset = i * blockSize;

                    var inputBlock = input.Slice(offset, blockSize);
                    var outputBlock = output.Slice(offset, blockSize);

                    cipher.Encrypt(state, keystream);
                    ByteUtils.Xor(inputBlock, keystream, outputBlock);

                    IncrementCounter(state);
                }

                if (remainder > 0)
                {
                    var offset = blockCount * blockSize;

                    cipher.Encrypt(state, keystream);

                    ByteUtils.Xor(
                        keystream[..remainder],
                        input.Slice(offset, remainder),
                        output.Slice(offset, remainder));
                }
            }
        }

        private static void AddOffset(ReadOnlySpan<byte> baseCounter, ulong offset, Span<byte> destination)
        {
            baseCounter.CopyTo(destination);
            var carry = offset;
            for (var j = destination.Length - 1; j >= 0 && carry > 0; j--)
            {
                var sum = destination[j] + (carry & 0xFF);
                destination[j] = (byte)sum;
                carry = (carry >> 8) + (sum >> 8);
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

        private static void IncrementCounter(Span<byte> counter)
        {
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
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