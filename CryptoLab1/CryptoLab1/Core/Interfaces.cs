
namespace CryptoLab1.Core
{
    public interface IKeyScheduler
    {
        byte[][] GenerateRoundKeys(byte[] key);
    }

    public interface IRoundFunction
    {
        byte[] Transform(byte[] inputBlock, byte[] roundKey);

        void Transform(ReadOnlySpan<byte> inputBlock, ReadOnlySpan<byte> roundKey, Span<byte> destination)
        {
            var res = Transform([.. inputBlock], [.. roundKey]);
            res.CopyTo(destination);
        }
    }

    public interface ISymmetricCipher
    {
        int BlockSizeBytes { get; }
        void SetKey(byte[] key);
        byte[] Encrypt(byte[] block);
        byte[] Decrypt(byte[] block);
        void Encrypt(ReadOnlySpan<byte> input, Span<byte> output);
        void Decrypt(ReadOnlySpan<byte> input, Span<byte> output);
    }

    public enum CipherMode
    {
        ECB, CBC, PCBC, CFB, OFB, CTR, RandomDelta
    }

    public enum PaddingMode
    {
        Zeros, AnsiX923, Pkcs7, Iso10126
    }


    public enum BitDirection
    {
        // От старшего бита к младшему MSB first Big-Endian
        MsbFirst,

        // От младшего бита к старшему LSB first  Little-Endian
        LsbFirst
    }


    public enum BitIndexingBase
    {
        Zero = 0, One = 1
    }

    public enum BitNumbering
    {
        Msb0, Msb1,
        Lsb0, Lsb1
    }

    public static class BitNumberingExtensions
    {
        public static BitDirection GetDirection(this BitNumbering numbering) =>
            numbering switch
            {
                BitNumbering.Msb0 or BitNumbering.Msb1 => BitDirection.MsbFirst,
                BitNumbering.Lsb0 or BitNumbering.Lsb1 => BitDirection.LsbFirst,
                _ => throw new ArgumentOutOfRangeException(nameof(numbering), numbering, "Unknown bit numbering convention.")
            };

        public static int GetStartIndex(this BitNumbering numbering) =>
            numbering switch
            {
                BitNumbering.Msb0 or BitNumbering.Lsb0 => 0,
                BitNumbering.Msb1 or BitNumbering.Lsb1 => 1,
                _ => throw new ArgumentOutOfRangeException(nameof(numbering), numbering, "Unknown bit numbering convention.")
            };
    }
}
