namespace CryptoLab1.Core.Modes
{
    internal interface ICipherModeHandler
    {
        bool RequiresIv { get; }

        bool RequiresPadding { get; }

        void Encrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams);

        void Decrypt(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            byte[]? iv,
            object[]? extraParams);

        void EncryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams);

        void DecryptChunk(
            ISymmetricCipher cipher,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            Span<byte> state,
            object[]? extraParams);
    }
}
