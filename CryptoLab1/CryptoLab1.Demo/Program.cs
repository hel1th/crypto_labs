using System.Security.Cryptography;
using CryptoLab1.Core;
using CryptoLab1.Deal;
using CipherMode = CryptoLab1.Core.CipherMode;
using PaddingMode = CryptoLab1.Core.PaddingMode;

Console.WriteLine("\n\t\tДЕМОНСТРАЦИЯ DES\n\n");

byte[] desKey = [0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1];
byte[] desIv = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

var desContext = new CryptoContext(desKey, CipherMode.ECB, PaddingMode.Pkcs7, desIv);

DemonstrateByteArrays(desContext, [1, 4, 7, 8, 9, 15, 16]);

var samplesDir = FindSamplesDirectory();
await DemonstrateFilesAsync(desContext, samplesDir, "DES");

Console.WriteLine("\n\t\tДЕМОНСТРАЦИЯ DEAL\n\n");

var dealCipher = DealCipherFactory.Create();
byte[] dealKey = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
byte[] dealIv = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x0F, 0xED, 0xCB, 0xA9, 0x87, 0x65, 0x43, 0x21];

var dealContext = new CryptoContext(dealCipher, dealKey, CipherMode.CBC, PaddingMode.Pkcs7, dealIv);

DemonstrateByteArrays(dealContext, [1, 4, 7, 8, 9, 15, 16, 17, 31, 32]);
await DemonstrateFilesAsync(dealContext, samplesDir, "DEAL");

Console.WriteLine("\n=== Все файлы успешно обработаны ===");


static void DemonstrateByteArrays(CryptoContext context, int[] lengths)
{
    Console.WriteLine("\n\t\tПсевдослучайные массивы байтов");

    foreach (var len in lengths)
    {
        var randomBytes = RandomNumberGenerator.GetBytes(len);
        var encryptedBytes = context.Encrypt(randomBytes);
        var decryptedBytes = context.Decrypt(encryptedBytes);

        Console.WriteLine($"\nИсходные байты ({randomBytes.Length} байт): {Convert.ToHexString(randomBytes)}");
        Console.WriteLine($"SHA-256 оригинала:     {Convert.ToHexString(SHA256.HashData(randomBytes))}");
        Console.WriteLine($"Зашифрованные байты:   {Convert.ToHexString(encryptedBytes)}");
        Console.WriteLine($"Расшифрованные байты:  {Convert.ToHexString(decryptedBytes)}");
        Console.WriteLine($"SHA-256 расшифровки:   {Convert.ToHexString(SHA256.HashData(decryptedBytes))}");
        Console.WriteLine($"Совпадение байтов:     {(randomBytes.SequenceEqual(decryptedBytes) ? "ДА" : "НЕТ")}");
    }
}

static async Task DemonstrateFilesAsync(CryptoContext context, string samplesDir, string cipherName)
{
    Console.WriteLine($"\n\t\tШифрование и дешифрование файлов ({cipherName})");

    var masterpicesDir = Path.Combine(samplesDir, "masterpices");
    var encryptedDir = Path.Combine(samplesDir, "encrypted", cipherName.ToLowerInvariant());
    var decryptedDir = Path.Combine(samplesDir, "decrypted", cipherName.ToLowerInvariant());

    Directory.CreateDirectory(encryptedDir);
    Directory.CreateDirectory(decryptedDir);

    var files = Directory.GetFiles(masterpicesDir)
        .OrderBy(f => new FileInfo(f).Length)
        .ToArray();
    if (files.Length == 0)
    {
        Console.WriteLine($"В папке {masterpicesDir} не найдено файлов.");
        return;
    }

    foreach (var filePath in files)
    {
        if (!File.Exists(filePath)) continue;
        await ProcessFileAsync(context, samplesDir, filePath, encryptedDir, decryptedDir);
    }
}

static async Task ProcessFileAsync(
    CryptoContext context,
    string samplesDir,
    string filePath,
    string encryptedDir,
    string decryptedDir)
{
    var fileName = Path.GetFileName(filePath);
    var encPath = Path.Combine(encryptedDir, fileName + ".enc");
    var decPath = Path.Combine(decryptedDir, fileName);
    var fileSize = new FileInfo(filePath).Length;

    Console.WriteLine($"\n[ФАЙЛ]: {fileName} ({fileSize:N0} байт)");

    var originalHash = await ComputeFileSha256Async(filePath);
    Console.WriteLine($"  Исходный SHA-256:        {originalHash}");

    await context.EncryptFileAsync(filePath, encPath, CreateProgress("Шифрование", fileSize));
    if (fileSize > 1024 * 1024) Console.WriteLine();
    Console.WriteLine($"  Зашифрован в:            {Path.GetRelativePath(samplesDir, encPath)} ({new FileInfo(encPath).Length:N0} байт)");

    await context.DecryptFileAsync(encPath, decPath, CreateProgress("Дешифрование", fileSize));
    if (fileSize > 1024 * 1024) Console.WriteLine();
    var decryptedHash = await ComputeFileSha256Async(decPath);
    Console.WriteLine($"  Расшифрован в:           {Path.GetRelativePath(samplesDir, decPath)}");
    Console.WriteLine($"  Расшифрованный SHA-256:  {decryptedHash}");
    Console.WriteLine($"  Совпадение SHA-256:      {(originalHash == decryptedHash ? "ДА (УСПЕХ)" : "НЕТ (ОШИБКА)")}");
}

static Action<long, long>? CreateProgress(string operation, long fileSize)
{
    if (fileSize <= 1024 * 1024)
        return null;

    return (done, total) =>
    {
        var pct = total > 0 ? (int)(done * 100 / total) : 100;
        Console.Write($"\r  {operation}: {pct}% ({done / (1024 * 1024)} / {total / (1024 * 1024)} МБ)...   ");
    };
}

static async Task<string> ComputeFileSha256Async(string path)
{
    await using var stream = File.OpenRead(path);
    var hash = await SHA256.HashDataAsync(stream);
    return Convert.ToHexString(hash);
}

static string FindSamplesDirectory()
{
    foreach (var baseDir in new[] { Directory.GetCurrentDirectory(), AppContext.BaseDirectory })
    {
        var dir = new DirectoryInfo(baseDir);
        while (dir != null)
        {
            var path = Path.Combine(dir.FullName, "CryptoLab1.Demo", "samples");
            if (Directory.Exists(path)) return path;

            path = Path.Combine(dir.FullName, "samples");
            if (Directory.Exists(path)) return path;

            dir = dir.Parent;
        }
    }

    throw new DirectoryNotFoundException("Не удалось найти папку samples.");
}
