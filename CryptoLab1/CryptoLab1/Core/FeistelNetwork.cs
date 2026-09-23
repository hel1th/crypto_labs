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

        public byte[] Encrypt(byte[] block) => Run(block, reverseKeyOrder: false);

        public byte[] Decrypt(byte[] block) => Run(block, reverseKeyOrder: true);

        private byte[] Run(byte[] block, bool reverseKeyOrder)
        {
            ValidateInput(block);

            var current = new byte[BlockSizeBytes];

            if (_initialPermutation is not null)
                BitPermutation.Permute(block, _initialPermutation, _permutationNumbering, current);
            else
                block.CopyTo(current);

            var halfSize = BlockSizeBytes / 2;

            Span<byte> left = new byte[halfSize];
            Span<byte> right = new byte[halfSize];
            Span<byte> temp = new byte[halfSize];

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

            right.CopyTo(current.AsSpan()[..halfSize]);
            left.CopyTo(current.AsSpan()[halfSize..]);

            var result = new byte[BlockSizeBytes];
            if (_finalPermutation is not null)
                BitPermutation.Permute(current, _finalPermutation, _permutationNumbering, result);
            else
                current.CopyTo(result);

            return result;
        }

        private void ValidateInput(byte[] block)
        {
            if (_roundKeys == null)
                throw new InvalidOperationException("Round keys are not set. Call SetKey before encryption/decryption.");

            ArgumentNullException.ThrowIfNull(block);

            if (blockSizeBytes is <= 0 or > MaxBlockSizeBytes || blockSizeBytes % 2 != 0)
                throw new ArgumentOutOfRangeException(nameof(blockSizeBytes));

            if (block.Length != BlockSizeBytes)
                throw new ArgumentException($"Block size is {block.Length} bytes, but {BlockSizeBytes} were expected.");
        }

        private byte[] GetRoundKey(int roundN, bool reverseKeyOrder) =>
            _roundKeys![GetRoundKeyIndex(roundN, reverseKeyOrder)];

        private int GetRoundKeyIndex(int roundN, bool reverseKeyOrder) =>
            reverseKeyOrder ? _rounds - 1 - roundN : roundN;
    }
}
