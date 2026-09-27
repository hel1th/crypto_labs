using System;

namespace CryptoLab1.Core
{
    // L_i = R_{i-1}
    // R_i = L_{i-1} XOR F(R_{i-1}, K_i)
    public class FeistelNetwork(
        IKeyScheduler keyScheduler,
        IRoundFunction roundFunction,
        int rounds,
        int blockSizeBytes,
        int[]? initialPermutation = null,
        int[]? finalPermutation = null,
        BitNumbering permutationNumbering = BitNumbering.Msb1) : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler = keyScheduler;
        private readonly IRoundFunction _roundFunction = roundFunction;
        private readonly int _rounds = rounds;
        private readonly int[]? _initialPermutation = initialPermutation;
        private readonly int[]? _finalPermutation = finalPermutation;
        private readonly BitNumbering _permutationNumbering = permutationNumbering;
        private byte[][]? _roundKeys;
        private const int MaxBlockSizeBytes = 256;

        public int BlockSizeBytes { get; } = blockSizeBytes % 2 == 0
            ? blockSizeBytes
            : throw new ArgumentException("Block size must be an even number of bytes.");

        public void SetKey(byte[] key)
        {
            var roundKeys = _keyScheduler.GenerateRoundKeys(key);
            if (roundKeys.Length != _rounds)
                throw new ArgumentException($"Key scheduler returned {roundKeys.Length} round keys, but {_rounds} were expected.");

            _roundKeys = roundKeys;
        }

        public byte[] Encrypt(byte[] block)
        {
            ArgumentNullException.ThrowIfNull(block);
            var result = new byte[BlockSizeBytes];
            Encrypt(block, result);
            return result;
        }

        public byte[] Decrypt(byte[] block)
        {
            ArgumentNullException.ThrowIfNull(block);
            var result = new byte[BlockSizeBytes];
            Decrypt(block, result);
            return result;
        }

        public void Encrypt(ReadOnlySpan<byte> input, Span<byte> output) => Run(input, output, reverseKeyOrder: false);

        public void Decrypt(ReadOnlySpan<byte> input, Span<byte> output) => Run(input, output, reverseKeyOrder: true);

        private void Run(ReadOnlySpan<byte> input, Span<byte> output, bool reverseKeyOrder)
        {
            ValidateInput(input, output);

            Span<byte> current = stackalloc byte[BlockSizeBytes];

            if (_initialPermutation is not null)
                BitPermutation.Permute(input, _initialPermutation, _permutationNumbering, current);
            else
                input.CopyTo(current);

            var halfSize = BlockSizeBytes / 2;

            Span<byte> left = stackalloc byte[halfSize];
            Span<byte> right = stackalloc byte[halfSize];
            Span<byte> temp = stackalloc byte[halfSize];

            current[..halfSize].CopyTo(left);
            current[halfSize..].CopyTo(right);

            for (var round = 0; round < _rounds; round++)
            {
                var key = GetRoundKey(round, reverseKeyOrder);
                var f = _roundFunction.Transform([.. right], key);

                ByteUtils.Xor(left, f, temp);

                right.CopyTo(left);
                temp.CopyTo(right);
            }

            right.CopyTo(current[..halfSize]);
            left.CopyTo(current[halfSize..]);

            if (_finalPermutation is not null)
                BitPermutation.Permute(current, _finalPermutation, _permutationNumbering, output);
            else
                current.CopyTo(output);
        }

        private void ValidateInput(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (_roundKeys == null)
                throw new InvalidOperationException("Round keys are not set. Call SetKey before encryption/decryption.");

            if (blockSizeBytes is <= 0 or > MaxBlockSizeBytes || blockSizeBytes % 2 != 0)
                throw new ArgumentOutOfRangeException(nameof(blockSizeBytes));

            if (input.Length != BlockSizeBytes)
                throw new ArgumentException($"Block size is {input.Length} bytes, but {BlockSizeBytes} were expected.");

            if (output.Length < BlockSizeBytes)
                throw new ArgumentException($"Output buffer length ({output.Length}) is smaller than block size ({BlockSizeBytes}).");
        }

        private byte[] GetRoundKey(int roundN, bool reverseKeyOrder) =>
            _roundKeys![GetRoundKeyIndex(roundN, reverseKeyOrder)];

        private int GetRoundKeyIndex(int roundN, bool reverseKeyOrder) =>
            reverseKeyOrder ? _rounds - 1 - roundN : roundN;
    }
}
