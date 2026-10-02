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
                return null;

            if (iv == null)
                return RandomNumberGenerator.GetBytes(blockSize);


            if (iv.Length != blockSize)
                throw new ArgumentException($"IV must be exactly {blockSize} bytes long, but was {iv.Length} bytes.", nameof(iv));
            


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

        public Task<byte[]> EncryptAsync(byte[] input, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input);
            return Task.Run(() => Encrypt(input), cancellationToken);
        }

        public Task<byte[]> DecryptAsync(byte[] input, CancellationToken cancellationToken = default)
        {
            ArgumentNullException.ThrowIfNull(input);
            return Task.Run(() => Decrypt(input), cancellationToken);
        }

        private const int FileBufferSize = 1024 * 1024; // 1 MB chunk buffer

        public Task EncryptFileAsync(string inputFilePath, string outputFilePath, CancellationToken cancellationToken) =>
            EncryptFileAsync(inputFilePath, outputFilePath, null, cancellationToken);

        public Task DecryptFileAsync(string inputFilePath, string outputFilePath, CancellationToken cancellationToken) =>
            DecryptFileAsync(inputFilePath, outputFilePath, null, cancellationToken);

        public async Task EncryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            Action<long, long>? onProgress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(inputFilePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(outputFilePath);

            var blockSize = Cipher.BlockSizeBytes;
            var bufferSize = Math.Max(blockSize, FileBufferSize / blockSize * blockSize);

            var inBuffer = new byte[bufferSize];
            var outBuffer = new byte[bufferSize];
            var state = Iv != null ? (byte[])Iv.Clone() : new byte[blockSize];

            await using var inputStream = new FileStream(
                inputFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                useAsync: true);

            await using var outputStream = new FileStream(
                outputFilePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                useAsync: true);

            var fileLength = inputStream.Length;

            while (inputStream.Position < fileLength)
            {
                var remaining = fileLength - inputStream.Position;
                var toRead = (int)Math.Min(bufferSize, remaining);

                await inputStream.ReadExactlyAsync(inBuffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);

                var isLast = inputStream.Position == fileLength;

                if (!isLast)
                {
                    _handler.EncryptChunk(Cipher, inBuffer.AsSpan(0, toRead), outBuffer.AsSpan(0, toRead), state, ExtraParams);
                    await outputStream.WriteAsync(outBuffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                    onProgress?.Invoke(inputStream.Position, fileLength);
                }
                else
                {
                    var paddedTail = Padding.Apply(inBuffer.AsSpan(0, toRead), blockSize, PaddingMode);
                    var outputTail = new byte[paddedTail.Length];
                    _handler.EncryptChunk(Cipher, paddedTail, outputTail, state, ExtraParams);
                    await outputStream.WriteAsync(outputTail, cancellationToken).ConfigureAwait(false);
                    onProgress?.Invoke(fileLength, fileLength);
                    return;
                }
            }

            if (fileLength == 0)
            {
                var paddedTail = Padding.Apply([], blockSize, PaddingMode);
                var outputTail = new byte[paddedTail.Length];
                _handler.EncryptChunk(Cipher, paddedTail, outputTail, state, ExtraParams);
                await outputStream.WriteAsync(outputTail, cancellationToken).ConfigureAwait(false);
                onProgress?.Invoke(0, 0);
            }
        }

        public async Task DecryptFileAsync(
            string inputFilePath,
            string outputFilePath,
            Action<long, long>? onProgress = null,
            CancellationToken cancellationToken = default)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(inputFilePath);
            ArgumentException.ThrowIfNullOrWhiteSpace(outputFilePath);

            var blockSize = Cipher.BlockSizeBytes;

            await using var inputStream = new FileStream(
                inputFilePath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                bufferSize: 64 * 1024,
                useAsync: true);

            var fileLength = inputStream.Length;
            if (fileLength == 0 || fileLength % blockSize != 0)
                throw new ArgumentException($"Ciphertext file length ({fileLength}) must be a non-zero multiple of block size ({blockSize}).", nameof(inputFilePath));

            var bufferSize = Math.Max(blockSize, FileBufferSize / blockSize * blockSize);
            var inBuffer = new byte[bufferSize];
            var outBuffer = new byte[bufferSize];
            var state = Iv != null ? (byte[])Iv.Clone() : new byte[blockSize];

            await using var outputStream = new FileStream(
                outputFilePath,
                FileMode.Create,
                FileAccess.Write,
                FileShare.None,
                bufferSize: 64 * 1024,
                useAsync: true);

            while (inputStream.Position < fileLength)
            {
                var remaining = fileLength - inputStream.Position;
                var toRead = (int)Math.Min(bufferSize, remaining);

                await inputStream.ReadExactlyAsync(inBuffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);

                var isLast = inputStream.Position == fileLength;

                _handler.DecryptChunk(Cipher, inBuffer.AsSpan(0, toRead), outBuffer.AsSpan(0, toRead), state, ExtraParams);
                if (!isLast)
                {
                    await outputStream.WriteAsync(outBuffer.AsMemory(0, toRead), cancellationToken).ConfigureAwait(false);
                    onProgress?.Invoke(inputStream.Position, fileLength);
                }
                else
                {
                    var unpaddedTail = Padding.Remove(outBuffer.AsSpan(0, toRead), blockSize, PaddingMode);
                    if (unpaddedTail.Length > 0)
                    {
                        await outputStream.WriteAsync(unpaddedTail, cancellationToken).ConfigureAwait(false);
                    }
                    onProgress?.Invoke(fileLength, fileLength);
                }
            }
        }
    }
}
