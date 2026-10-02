using System;
using CryptoLab1.Core;
using CryptoLab1.Des;

namespace CryptoLab1.Deal
{
    public class DealKeyScheduler : IKeyScheduler
    {
        public static readonly byte[] DefaultConstantKey = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

        private readonly ISymmetricCipher _desCipher;

        public DealKeyScheduler(ISymmetricCipher? desCipher = null, byte[]? constantKey = null)
        {
            _desCipher = desCipher ?? DesCipherFactory.Create();
            _desCipher.SetKey(constantKey ?? DefaultConstantKey);
        }

        public byte[][] GenerateRoundKeys(byte[] key)
        {
            ArgumentNullException.ThrowIfNull(key);

            var (rounds, keyBlocksCount) = key.Length switch
            {
                16 => (6, 2),
                24 => (6, 3),
                32 => (8, 4),
                _ => throw new ArgumentException($"Invalid DEAL key length: {key.Length} bytes. Allowed: 16, 24, 32 bytes.")
            };

            var k = new byte[keyBlocksCount][];
            for (var i = 0; i < keyBlocksCount; i++)
            {
                k[i] = new byte[8];
                Array.Copy(key, i * 8, k[i], 0, 8);
            }

            var roundKeys = new byte[rounds][];
            var block = new byte[8];

            for (var i = 0; i < rounds; i++)
            {
                var ki = k[i % keyBlocksCount];

                if (i == 0)
                {
                    Array.Copy(ki, block, 8);
                }
                else
                {
                    for (var b = 0; b < 8; b++)
                        block[b] = (byte)(ki[b] ^ roundKeys[i - 1][b]);

                    if (key.Length == 16 && i >= 2)
                    {
                        var constant = 1 << (i - 2);
                        ApplyConstant(block, constant);
                    }
                    else if (key.Length == 24 && i >= 3)
                    {
                        var constant = 1 << (i - 3);
                        ApplyConstant(block, constant);
                    }
                    else if (key.Length == 32 && i >= 4)
                    {
                        var constant = 1 << (i - 4);
                        ApplyConstant(block, constant);
                    }
                }

                roundKeys[i] = _desCipher.Encrypt(block);
            }

            return roundKeys;
        }

        private static void ApplyConstant(byte[] block, int constant)
        {
            block[7] ^= (byte)constant;
        }
    }
}
