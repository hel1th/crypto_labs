using System.Security.Cryptography;
using CryptoLab1.Core.Modes;
using CryptoLab1.Des;

namespace CryptoLab1.Core
{
    public class CryptoContext
    {
        private readonly ICipherModeHandler _handler;

        public ISymmetricCipher Cipher { get; }
        public CipherMode Mode { get; }
        public PaddingMode PaddingMode { get; }
        public byte[]? Iv { get; }
        public object[] ExtraParams { get; }

        public CryptoContext(
            ISymmetricCipher cipher,
            byte[] key,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            byte[]? iv = null,
            params object[]? extraParams)
        {
            ArgumentNullException.ThrowIfNull(cipher);
            ArgumentNullException.ThrowIfNull(key);

            Cipher = cipher;
            Mode = cipherMode;
            PaddingMode = paddingMode;
            _handler = CipherModeFactory.Create(cipherMode);

            cipher.SetKey(key);

            var blockSize = cipher.BlockSizeBytes;


            Iv = InitializeIv(iv);


            ExtraParams = extraParams ?? [];

            if (cipherMode != CipherMode.RandomDelta) return;

            if (extraParams is { Length: > 0 } && extraParams[0] is byte[] delta && delta.Length == blockSize)
                ExtraParams = [delta.Clone()];
            else
            {
                var genDelta = RandomNumberGenerator.GetBytes(blockSize);
                ExtraParams = [genDelta];
            }

        }


        private byte[]? InitializeIv(byte[]? iv)
        {
            var blockSize = Cipher.BlockSizeBytes;

            if (!_handler.RequiresIv)
            {
                return null;
            }

            if (iv == null)
            {
                return RandomNumberGenerator.GetBytes(blockSize);
            }


            if (iv.Length != blockSize)
            {

                throw new ArgumentException($"IV must be exactly {blockSize} bytes long, but was {iv.Length} bytes.", nameof(iv));
            }


            return (byte[])iv.Clone();
        }


        public CryptoContext(
            byte[] key,
            CipherMode cipherMode,
            PaddingMode paddingMode,
            byte[]? iv = null,
            params object[] extraParams)
            : this(DesCipherFactory.Create(), key, cipherMode, paddingMode, iv, extraParams)
        {
        }

        public void Encrypt(byte[] input, out byte[] output)
        {
            ArgumentNullException.ThrowIfNull(input);

            var padded = Padding.Apply(input, Cipher.BlockSizeBytes, PaddingMode);

            output = new byte[padded.Length];

            _handler.Encrypt(Cipher, padded, output, Iv, ExtraParams);
        }

        public void Decrypt(byte[] input, out byte[] output)
        {
            ArgumentNullException.ThrowIfNull(input);

            if (input.Length == 0 || input.Length % Cipher.BlockSizeBytes != 0)
                throw new ArgumentException($"Ciphertext length ({input.Length}) must be a non-zero multiple of block size ({Cipher.BlockSizeBytes}).", nameof(input));


            var decrypted = new byte[input.Length];

            _handler.Decrypt(Cipher, input, decrypted, Iv, ExtraParams);

            output = Padding.Remove(decrypted, Cipher.BlockSizeBytes, PaddingMode);
        }

        public byte[] Encrypt(byte[] input)
        {
            Encrypt(input, out var output);
            return output;
        }

        public byte[] Decrypt(byte[] input)
        {
            Decrypt(input, out var output);
            return output;
        }

        public async Task EncryptFileAsync(string inputFilePath, string outputFilePath, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(inputFilePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(outputFilePath);


            var data = await File.ReadAllBytesAsync(inputFilePath, cancellationToken).ConfigureAwait(false);

            Encrypt(data, out var encrypted);

            await File.WriteAllBytesAsync(outputFilePath, encrypted, cancellationToken).ConfigureAwait(false);
        }

        public async Task DecryptFileAsync(string inputFilePath, string outputFilePath, CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(inputFilePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(outputFilePath);

            var data = await File.ReadAllBytesAsync(inputFilePath, cancellationToken).ConfigureAwait(false);

            Decrypt(data, out var decrypted);

            await File.WriteAllBytesAsync(outputFilePath, decrypted, cancellationToken).ConfigureAwait(false);
        }
    }
}
