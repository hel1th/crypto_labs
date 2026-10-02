using CryptoLab1.Core;
using CryptoLab1.Des;

namespace CryptoLab1.Deal
{
    public static class DealCipherFactory
    {
        public static ISymmetricCipher Create(byte[]? constantKey = null) =>
            new FeistelNetwork(
                keyScheduler: new DealKeyScheduler(constantKey: constantKey),
                roundFunction: new DesRoundFunctionAdapter(DesCipherFactory.Create()),
                rounds: 0,
                blockSizeBytes: 16);

        public static ISymmetricCipher Create128(byte[]? constantKey = null) =>
            new FeistelNetwork(
                keyScheduler: new DealKeyScheduler(constantKey: constantKey),
                roundFunction: new DesRoundFunctionAdapter(DesCipherFactory.Create()),
                rounds: 6,
                blockSizeBytes: 16);

        public static ISymmetricCipher Create192(byte[]? constantKey = null) =>
            new FeistelNetwork(
                keyScheduler: new DealKeyScheduler(constantKey: constantKey),
                roundFunction: new DesRoundFunctionAdapter(DesCipherFactory.Create()),
                rounds: 6,
                blockSizeBytes: 16);

        public static ISymmetricCipher Create256(byte[]? constantKey = null) =>
            new FeistelNetwork(
                keyScheduler: new DealKeyScheduler(constantKey: constantKey),
                roundFunction: new DesRoundFunctionAdapter(DesCipherFactory.Create()),
                rounds: 8,
                blockSizeBytes: 16);
    }
}
