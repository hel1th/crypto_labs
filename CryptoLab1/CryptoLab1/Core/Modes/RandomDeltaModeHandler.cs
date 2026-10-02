using System.Security.Cryptography;

namespace CryptoLab1.Core.Modes
{
    internal class RandomDeltaModeHandler : ICipherModeHandler
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
            ValidateDelta(extraParams, cipher.BlockSizeBytes);

            Span<byte> state = stackalloc byte[cipher.BlockSizeBytes];
            iv!.CopyTo(state);

            DecryptChunk(cipher, input, output, state, extraParams);
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

            Span<byte> deltaBuffer = stackalloc byte[blockSize];
            var delta = GetOrGenerateDelta(blockSize, extraParams, deltaBuffer);

            if (blockCount >= ParallelThreshold)
            {
                byte[] baseCounter = state.ToArray();
                byte[] deltaCopy = delta.ToArray();

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

                            AddScaledDelta(baseCounter, deltaCopy, (ulong)i, counter);
                            cipher.Encrypt(counter, keystream);
                            ByteUtils.Xor(inBlock, keystream, outBlock);
                        });
                    }
                }

                AddScaledDelta(state, delta, (ulong)blockCount, state);

                if (remainder > 0)
                {
                    var offset = blockCount * blockSize;
                    Span<byte> keystream = stackalloc byte[blockSize];

                    cipher.Encrypt(state, keystream);
                    ByteUtils.Xor(
                        input.Slice(offset, remainder),
                        keystream[..remainder],
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

                    AddDelta(state, delta);
                }

                if (remainder > 0)
                {
                    var offset = blockCount * blockSize;

                    cipher.Encrypt(state, keystream);
                    ByteUtils.Xor(
                        input.Slice(offset, remainder),
                        keystream[..remainder],
                        output.Slice(offset, remainder));
                }
            }
        }

        private static void AddScaledDelta(
            ReadOnlySpan<byte> baseCounter,
            ReadOnlySpan<byte> delta,
            ulong multiplier,
            Span<byte> destination)
        {
            baseCounter.CopyTo(destination);
            if (multiplier == 0) return;

            ulong carry = 0;
            for (var j = destination.Length - 1; j >= 0; j--)
            {
                var prod = (ulong)delta[j] * multiplier + carry + destination[j];
                destination[j] = (byte)prod;
                carry = prod >> 8;
            }
        }

        public void DecryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams)
        {
            ValidateDelta(extraParams, cipher.BlockSizeBytes);
            EncryptChunk(cipher, input, output, state, extraParams);
        }

        private static ReadOnlySpan<byte> GetOrGenerateDelta(
            int blockSize,
            object[]? extraParams,
            Span<byte> fallbackBuffer)
        {
            if (
                extraParams is { Length: > 0 }
                && extraParams[0] is byte[] delta
                && delta.Length == blockSize
            )
                return delta;

            RandomNumberGenerator.Fill(fallbackBuffer);
            return fallbackBuffer;
        }

        private static void AddDelta(Span<byte> counter, ReadOnlySpan<byte> delta)
        {
            var carry = 0;
            for (var i = counter.Length - 1; i >= 0; i--)
            {
                var sum = counter[i] + delta[i] + carry;
                counter[i] = (byte)sum;
                carry = sum >> 8;
            }
        }

        private static void ValidateDelta(
            object[]? extraParams,
            int blockSize)
        {
            if (extraParams == null || extraParams.Length == 0 || extraParams[0] is not byte[] delta || delta.Length != blockSize)
            {
                throw new ArgumentException(
                    $"Delta of length {blockSize} bytes must be provided in extraParams[0].",
                    nameof(extraParams));
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
