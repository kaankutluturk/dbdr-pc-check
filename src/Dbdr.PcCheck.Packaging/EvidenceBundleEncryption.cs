using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Dbdr.PcCheck.Packaging;

internal static class EvidenceBundleEncryption
{
    public const int MinimumPassphraseCharacters = 12;
    public const int MaximumPassphraseCharacters = 256;
    public const int Pbkdf2Iterations = 600_000;
    public const int ChunkSizeBytes = 1024 * 1024;
    public const long MaximumEncryptedBundleBytes = EvidenceBundleReader.MaximumBundleFileBytes + (16L * 1024 * 1024);

    private const ushort FormatVersion = 1;
    private const ushort KdfPbkdf2Sha256 = 1;
    private const int HeaderSize = 52;
    private const int SaltSize = 16;
    private const int NoncePrefixSize = 8;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private static readonly byte[] Magic = "DBDRBND1"u8.ToArray();

    public static void ValidatePassphrase(string passphrase)
    {
        ArgumentNullException.ThrowIfNull(passphrase);
        if (passphrase.Length is < MinimumPassphraseCharacters or > MaximumPassphraseCharacters
            || string.IsNullOrWhiteSpace(passphrase))
        {
            throw new ArgumentException(
                $"The bundle passphrase must contain between {MinimumPassphraseCharacters} and {MaximumPassphraseCharacters} characters.",
                nameof(passphrase));
        }
    }

    public static bool HasMagic(ReadOnlySpan<byte> prefix) =>
        prefix.Length >= Magic.Length && prefix[..Magic.Length].SequenceEqual(Magic);

    public static async Task EncryptAsync(
        string plainZipPath,
        string encryptedPath,
        string passphrase,
        CancellationToken cancellationToken)
    {
        ValidatePassphrase(passphrase);
        var inputFile = new FileInfo(plainZipPath);
        if (!inputFile.Exists || inputFile.Length is <= 0 or > EvidenceBundleReader.MaximumBundleFileBytes)
        {
            throw new InvalidDataException("The plaintext evidence archive is missing, empty or exceeds its size limit.");
        }

        var salt = RandomNumberGenerator.GetBytes(SaltSize);
        var noncePrefix = RandomNumberGenerator.GetBytes(NoncePrefixSize);
        var header = CreateHeader(inputFile.Length, salt, noncePrefix);
        var key = new byte[KeySize];
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(
                passphrase.AsSpan(),
                salt,
                key,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256);

            await using var input = new FileStream(
                plainZipPath,
                FileMode.Open,
                FileAccess.Read,
                FileShare.Read,
                ChunkSizeBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await using var output = new FileStream(
                encryptedPath,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                ChunkSizeBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan);
            await output.WriteAsync(header, cancellationToken).ConfigureAwait(false);

            using var aes = new AesGcm(key, TagSize);
            var plain = new byte[ChunkSizeBytes];
            var cipher = new byte[ChunkSizeBytes];
            var tag = new byte[TagSize];
            var lengthBytes = new byte[sizeof(int)];
            uint chunkIndex = 0;
            int bytesRead;
            while ((bytesRead = await ReadChunkAsync(input, plain, cancellationToken).ConfigureAwait(false)) > 0)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var nonce = CreateNonce(noncePrefix, chunkIndex);
                var associatedData = CreateAssociatedData(header, chunkIndex, bytesRead);
                aes.Encrypt(
                    nonce,
                    plain.AsSpan(0, bytesRead),
                    cipher.AsSpan(0, bytesRead),
                    tag,
                    associatedData);
                BinaryPrimitives.WriteInt32LittleEndian(lengthBytes, bytesRead);
                await output.WriteAsync(lengthBytes, cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(cipher.AsMemory(0, bytesRead), cancellationToken).ConfigureAwait(false);
                await output.WriteAsync(tag, cancellationToken).ConfigureAwait(false);
                chunkIndex++;
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            TryDelete(encryptedPath);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    public static async Task<FileStream> DecryptToTemporaryStreamAsync(
        Stream encryptedStream,
        string passphrase,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(encryptedStream);
        ValidatePassphrase(passphrase);
        var header = new byte[HeaderSize];
        await ReadExactlyAsync(encryptedStream, header, cancellationToken).ConfigureAwait(false);
        var parsed = ParseHeader(header);
        var key = new byte[KeySize];
        var temporaryDirectory = Path.Combine(Path.GetTempPath(), "DBDRPcCheck", "reader");
        Directory.CreateDirectory(temporaryDirectory);
        var temporaryPath = Path.Combine(temporaryDirectory, $"{Guid.NewGuid():N}.zip");
        FileStream? output = null;
        try
        {
            Rfc2898DeriveBytes.Pbkdf2(
                passphrase.AsSpan(),
                parsed.Salt,
                key,
                parsed.Iterations,
                HashAlgorithmName.SHA256);
            output = new FileStream(
                temporaryPath,
                FileMode.CreateNew,
                FileAccess.ReadWrite,
                FileShare.None,
                ChunkSizeBytes,
                FileOptions.Asynchronous | FileOptions.SequentialScan | FileOptions.DeleteOnClose);
            using var aes = new AesGcm(key, TagSize);
            var lengthBytes = new byte[sizeof(int)];
            var cipher = new byte[parsed.ChunkSize];
            var plain = new byte[parsed.ChunkSize];
            var tag = new byte[TagSize];
            long remaining = parsed.PlaintextLength;
            uint chunkIndex = 0;
            while (remaining > 0)
            {
                await ReadExactlyAsync(encryptedStream, lengthBytes, cancellationToken).ConfigureAwait(false);
                var length = BinaryPrimitives.ReadInt32LittleEndian(lengthBytes);
                var expectedLength = (int)Math.Min(parsed.ChunkSize, remaining);
                if (length != expectedLength)
                {
                    throw new InvalidDataException("The encrypted evidence bundle contains an invalid chunk length.");
                }

                await ReadExactlyAsync(encryptedStream, cipher.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                await ReadExactlyAsync(encryptedStream, tag, cancellationToken).ConfigureAwait(false);
                var nonce = CreateNonce(parsed.NoncePrefix, chunkIndex);
                var associatedData = CreateAssociatedData(header, chunkIndex, length);
                try
                {
                    aes.Decrypt(
                        nonce,
                        cipher.AsSpan(0, length),
                        tag,
                        plain.AsSpan(0, length),
                        associatedData);
                }
                catch (AuthenticationTagMismatchException exception)
                {
                    throw new InvalidDataException("The bundle passphrase is incorrect or the encrypted bundle was modified.", exception);
                }

                await output.WriteAsync(plain.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
                remaining -= length;
                chunkIndex++;
            }

            if (encryptedStream.ReadByte() != -1)
            {
                throw new InvalidDataException("The encrypted evidence bundle contains trailing data.");
            }

            await output.FlushAsync(cancellationToken).ConfigureAwait(false);
            output.Position = 0;
            return output;
        }
        catch
        {
            if (output is not null)
            {
                await output.DisposeAsync().ConfigureAwait(false);
            }
            else
            {
                TryDelete(temporaryPath);
            }

            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    private static byte[] CreateHeader(long plaintextLength, byte[] salt, byte[] noncePrefix)
    {
        var header = new byte[HeaderSize];
        Magic.CopyTo(header, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(8, 2), FormatVersion);
        BinaryPrimitives.WriteUInt16LittleEndian(header.AsSpan(10, 2), KdfPbkdf2Sha256);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12, 4), Pbkdf2Iterations);
        BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(16, 4), ChunkSizeBytes);
        BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(20, 8), plaintextLength);
        salt.CopyTo(header, 28);
        noncePrefix.CopyTo(header, 44);
        return header;
    }

    private static ParsedHeader ParseHeader(byte[] header)
    {
        if (!HasMagic(header)
            || BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(8, 2)) != FormatVersion
            || BinaryPrimitives.ReadUInt16LittleEndian(header.AsSpan(10, 2)) != KdfPbkdf2Sha256)
        {
            throw new InvalidDataException("The encrypted evidence bundle format is unsupported.");
        }

        var iterations = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(12, 4));
        var chunkSize = BinaryPrimitives.ReadInt32LittleEndian(header.AsSpan(16, 4));
        var plaintextLength = BinaryPrimitives.ReadInt64LittleEndian(header.AsSpan(20, 8));
        if (iterations is < 100_000 or > 2_000_000
            || chunkSize is < 64 * 1024 or > 4 * 1024 * 1024
            || plaintextLength is <= 0 or > EvidenceBundleReader.MaximumBundleFileBytes)
        {
            throw new InvalidDataException("The encrypted evidence bundle header contains unsafe parameters.");
        }

        return new ParsedHeader(
            iterations,
            chunkSize,
            plaintextLength,
            header.AsSpan(28, SaltSize).ToArray(),
            header.AsSpan(44, NoncePrefixSize).ToArray());
    }

    private static byte[] CreateNonce(byte[] prefix, uint chunkIndex)
    {
        var nonce = new byte[NonceSize];
        prefix.CopyTo(nonce, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(nonce.AsSpan(NoncePrefixSize, sizeof(uint)), chunkIndex);
        return nonce;
    }

    private static byte[] CreateAssociatedData(byte[] header, uint chunkIndex, int length)
    {
        var associatedData = new byte[header.Length + sizeof(uint) + sizeof(int)];
        header.CopyTo(associatedData, 0);
        BinaryPrimitives.WriteUInt32LittleEndian(associatedData.AsSpan(header.Length, sizeof(uint)), chunkIndex);
        BinaryPrimitives.WriteInt32LittleEndian(associatedData.AsSpan(header.Length + sizeof(uint), sizeof(int)), length);
        return associatedData;
    }

    private static async Task<int> ReadChunkAsync(
        Stream stream,
        byte[] buffer,
        CancellationToken cancellationToken)
    {
        var totalRead = 0;
        while (totalRead < buffer.Length)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(totalRead), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            totalRead += read;
        }

        return totalRead;
    }

    private static async Task ReadExactlyAsync(
        Stream stream,
        Memory<byte> buffer,
        CancellationToken cancellationToken)
    {
        try
        {
            await stream.ReadExactlyAsync(buffer, cancellationToken).ConfigureAwait(false);
        }
        catch (EndOfStreamException exception)
        {
            throw new InvalidDataException("The encrypted evidence bundle is truncated.", exception);
        }
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            // The original exception is more useful than a best-effort cleanup failure.
        }
    }

    private sealed record ParsedHeader(
        int Iterations,
        int ChunkSize,
        long PlaintextLength,
        byte[] Salt,
        byte[] NoncePrefix);
}
