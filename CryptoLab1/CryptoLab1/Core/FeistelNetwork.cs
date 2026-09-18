using System;

namespace CryptoLab1.Core
{
    // L_i = R_{i-1}
    // R_i = L_{i-1} XOR F(R_{i-1}, K_i)
    public class FeistelNetwork(IKeyScheduler keyScheduler, IRoundFunction roundFunction, int rounds, int blockSizeBytes) : ISymmetricCipher
    {
        private readonly IKeyScheduler _keyScheduler = keyScheduler;
        private readonly IRoundFunction _roundFunction = roundFunction;
        private readonly int _rounds = rounds;
        private byte[][]? _roundKeys;

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

            var (left, right) = SplitBlock(block);

            for (var round = 0; round < _rounds; round++)
            {
                var key = GetRoundKey(round, reverseKeyOrder);
                var f = _roundFunction.Transform(right, key);

                (left, right) = (right, Xor(left, f));
            }

            return CombineHalves(right, left);
        }

        private (byte[] Left, byte[] Right) SplitBlock(byte[] block)
        {
            var half = BlockSizeBytes / 2;
            return (block[..half], block[half..]);
        }

        private byte[] CombineHalves(byte[] first, byte[] second)
        {
            var result = new byte[BlockSizeBytes];
            first.CopyTo(result, 0);
            second.CopyTo(result, first.Length);
            return result;
        }

        private void ValidateInput(byte[] block)
        {
            if (_roundKeys == null)
                throw new InvalidOperationException("Round keys are not set. Call SetKey before encryption/decryption.");

            ArgumentNullException.ThrowIfNull(block);

            if (block.Length != BlockSizeBytes)
                throw new ArgumentException($"Block size is {block.Length} bytes, but {BlockSizeBytes} were expected.");
        }

        private byte[] GetRoundKey(int roundN, bool reverseKeyOrder) =>
            _roundKeys![GetRoundKeyIndex(roundN, reverseKeyOrder)];

        private int GetRoundKeyIndex(int roundN, bool reverseKeyOrder) =>
            reverseKeyOrder ? _rounds - 1 - roundN : roundN;

        private static byte[] Xor(byte[] a, byte[] b)
        {
            if (a.Length != b.Length)
                throw new ArgumentException($"Array lengths must be equal for XOR: {a.Length} and {b.Length}.");

            var result = new byte[a.Length];

            for (var i = 0; i < a.Length; i++)
                result[i] = (byte)(a[i] ^ b[i]);

            return result;
        }
    }
}
