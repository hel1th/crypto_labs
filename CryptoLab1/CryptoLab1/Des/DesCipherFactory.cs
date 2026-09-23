using CryptoLab1.Core;

namespace CryptoLab1.Des
{
    public static class DesCipherFactory
    {
        public static ISymmetricCipher Create() =>
            new FeistelNetwork(
                keyScheduler: new DesKeyScheduler(),
                roundFunction: new DesRoundFunction(),
                rounds: 16,
                blockSizeBytes: 8,
                initialPermutation: DesConstants.IP,
                finalPermutation: DesConstants.FP,
                permutationNumbering: BitNumbering.Msb1);
    }
}
