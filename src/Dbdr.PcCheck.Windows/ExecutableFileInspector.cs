using System.Diagnostics;
using System.Globalization;
using System.Security;
using System.Security.Cryptography;
using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Windows;

public sealed record ExecutableFileEvidence(
    string? SizeBytes,
    string? CreatedUtc,
    string? ModifiedUtc,
    string? Sha256,
    string AuthenticodeStatus,
    string? CompanyName,
    string? ProductName,
    string? OriginalFileName,
    string? IdentityStableDuringInspection,
    string? Error,
    string? EntropyBitsPerByte = null,
    string? EntropyClassification = null,
    YaraScanEvidence? Yara = null)
{
    public void AddTo(IDictionary<string, string?> fields)
    {
        fields["fileSizeBytes"] = SizeBytes;
        fields["fileCreatedUtc"] = CreatedUtc;
        fields["fileModifiedUtc"] = ModifiedUtc;
        fields["sha256"] = Sha256;
        fields["authenticodeStatus"] = AuthenticodeStatus;
        fields["companyName"] = CompanyName;
        fields["productName"] = ProductName;
        fields["originalFileName"] = OriginalFileName;
        fields["identityStableDuringInspection"] = IdentityStableDuringInspection;
        fields["fileInspectionError"] = Error;
        fields["entropyBitsPerByte"] = EntropyBitsPerByte;
        fields["entropyClassification"] = EntropyClassification;
        (Yara ?? YaraScanEvidence.Disabled).AddTo(fields);
    }
}

public interface IExecutableFileInspector
{
    Task<ExecutableFileEvidence> InspectAsync(string path, CancellationToken cancellationToken);
}

public sealed class ExecutableFileInspector(IYaraFileScanner? yaraScanner = null) : IExecutableFileInspector
{
    private readonly Dictionary<string, Task<ExecutableFileEvidence>> _cache = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _cacheGate = new();

    public Task<ExecutableFileEvidence> InspectAsync(string path, CancellationToken cancellationToken)
    {
        lock (_cacheGate)
        {
            if (_cache.TryGetValue(path, out var cached))
            {
                return cached;
            }

            var inspection = InspectCoreAsync(path, cancellationToken);
            _cache[path] = inspection;
            return inspection;
        }
    }

    private static async Task<ExecutableFileEvidence> InspectCoreAsync(
        string path,
        CancellationToken cancellationToken)
    {
        try
        {
            var before = new FileInfo(path);
            before.Refresh();
            if (!before.Exists)
            {
                return Unavailable("File no longer exists.");
            }

            var beforeLength = before.Length;
            var beforeCreatedUtc = before.CreationTimeUtc;
            var beforeModifiedUtc = before.LastWriteTimeUtc;

            string hash;
            var entropy = new BinaryEntropy();
            await using (var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete,
                81920,
                FileOptions.Asynchronous | FileOptions.SequentialScan))
            {
                using var incrementalHash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
                var buffer = new byte[81920];
                int bytesRead;
                while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
                {
                    incrementalHash.AppendData(buffer, 0, bytesRead);
                    entropy.Append(buffer.AsSpan(0, bytesRead));
                }

                hash = Convert.ToHexString(incrementalHash.GetHashAndReset());
            }

            cancellationToken.ThrowIfCancellationRequested();
            var version = FileVersionInfo.GetVersionInfo(path);
            var authenticodeStatus = AuthenticodeVerifier.GetStatus(path);
            var yaraEvidence = yaraScanner is null
                ? YaraScanEvidence.Disabled
                : await yaraScanner.ScanAsync(path, cancellationToken).ConfigureAwait(false);

            var after = new FileInfo(path);
            after.Refresh();
            var identityStable = after.Exists
                && beforeLength == after.Length
                && beforeCreatedUtc == after.CreationTimeUtc
                && beforeModifiedUtc == after.LastWriteTimeUtc;

            return new ExecutableFileEvidence(
                beforeLength.ToString(CultureInfo.InvariantCulture),
                beforeCreatedUtc.ToString("O", CultureInfo.InvariantCulture),
                beforeModifiedUtc.ToString("O", CultureInfo.InvariantCulture),
                hash,
                authenticodeStatus,
                version.CompanyName,
                version.ProductName,
                version.OriginalFilename,
                identityStable ? "true" : "false",
                identityStable ? null : "File identity changed while it was inspected.",
                entropy.CalculateBitsPerByte().ToString("F4", CultureInfo.InvariantCulture),
                BinaryEntropy.Classify(entropy.CalculateBitsPerByte()),
                yaraEvidence);
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or CryptographicException
            or SecurityException
            or ArgumentException
            or NotSupportedException
            or System.ComponentModel.Win32Exception)
        {
            return Unavailable(exception.GetType().Name);
        }
    }

    private static ExecutableFileEvidence Unavailable(string error) =>
        new(null, null, null, null, "unavailable", null, null, null, null, error);
}
