
namespace CryptoLab1.Core.Modes
{
    internal static class CipherModeFactory
    {
        public static ICipherModeHandler Create(CipherMode mode) =>
            mode switch
            {
                CipherMode.ECB => new EcbModeHandler(),
                CipherMode.CBC => new CbcModeHandler(),
                CipherMode.PCBC => new PcbcModeHandler(),
                CipherMode.CFB => new CfbModeHandler(),
                CipherMode.OFB => new OfbModeHandler(),
                CipherMode.CTR => new CtrModeHandler(),
                CipherMode.RandomDelta => new RandomDeltaModeHandler(),
                _ => throw new ArgumentOutOfRangeException(nameof(mode), mode, $"Unsupported cipher mode: {mode}")
            };
    }
}
