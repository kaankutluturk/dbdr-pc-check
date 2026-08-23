using System.IO.Compression;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Packaging;

public sealed record EvidenceBundleVerification(
    string EvidenceSchemaVersion,
    string AnalysisProfileVersion,
    int VerifiedEntryCount,
    long DecompressedBytes,
    bool Encrypted);

public sealed record EvidenceBundleReadResult(
    CollectionRunResult Result,
    EvidenceBundleVerification Verification);

public sealed class EvidenceBundlePassphraseRequiredException : IOException
{
    public EvidenceBundlePassphraseRequiredException()
        : base("The evidence bundle is encrypted and requires its case passphrase.")
    {
    }
}

public sealed class EvidenceBundleReader
{
    public const long MaximumBundleFileBytes = 512L * 1024 * 1024;
    public const long MaximumEntryBytes = 256L * 1024 * 1024;
    public const long MaximumDecompressedBytes = 768L * 1024 * 1024;
    public const int MaximumArchiveEntries = 32;
    public const int MaximumModules = 256;
    public const int MaximumRecords = 250_000;
    public const int MaximumFindings = 50_000;

    private static readonly string[] RequiredEntryNames =
    [
        "case.json",
        "collection-log.json",
        "evidence.json",
        "findings.json",
        "manifest.sha256",
        "privacy.txt",
        "report.html",
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        MaxDepth = 64,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public async Task<EvidenceBundleReadResult> ReadAsync(
        string bundlePath,
        CancellationToken cancellationToken)
        => await ReadAsync(bundlePath, passphrase: null, cancellationToken).ConfigureAwait(false);

    public async Task<EvidenceBundleReadResult> ReadAsync(
        string bundlePath,
        string? passphrase,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(bundlePath);
        var file = new FileInfo(bundlePath);
        if (!file.Exists)
        {
            throw new FileNotFoundException("The evidence bundle does not exist.", bundlePath);
        }

        if (file.Length is <= 0 or > EvidenceBundleEncryption.MaximumEncryptedBundleBytes)
        {
            throw new InvalidDataException($"The evidence bundle must be between 1 byte and {EvidenceBundleEncryption.MaximumEncryptedBundleBytes} bytes.");
        }

        await using var stream = new FileStream(
            bundlePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            81920,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        var prefix = new byte[8];
        var prefixLength = await stream.ReadAsync(prefix, cancellationToken).ConfigureAwait(false);
        stream.Position = 0;
        if (EvidenceBundleEncryption.HasMagic(prefix.AsSpan(0, prefixLength)))
        {
            if (passphrase is null)
            {
                throw new EvidenceBundlePassphraseRequiredException();
            }

            await using var decrypted = await EvidenceBundleEncryption
                .DecryptToTemporaryStreamAsync(stream, passphrase, cancellationToken)
                .ConfigureAwait(false);
            return await ReadZipAsync(decrypted, encrypted: true, cancellationToken).ConfigureAwait(false);
        }

        if (file.Length > MaximumBundleFileBytes)
        {
            throw new InvalidDataException($"The unencrypted evidence bundle exceeds {MaximumBundleFileBytes} bytes.");
        }

        return await ReadZipAsync(stream, encrypted: false, cancellationToken).ConfigureAwait(false);
    }

    internal static async Task<EvidenceBundleReadResult> ReadZipAsync(
        Stream stream,
        bool encrypted,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        using var archive = new ZipArchive(stream, ZipArchiveMode.Read, leaveOpen: true);
        if (archive.Entries.Count is 0 or > MaximumArchiveEntries)
        {
            throw new InvalidDataException($"The evidence bundle must contain between 1 and {MaximumArchiveEntries} entries.");
        }

        var entries = new Dictionary<string, ZipArchiveEntry>(StringComparer.OrdinalIgnoreCase);
        long decompressedBytes = 0;
        foreach (var entry in archive.Entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.IsNullOrWhiteSpace(entry.Name)
                || !string.Equals(entry.FullName, entry.Name, StringComparison.Ordinal)
                || entry.FullName.Contains("..", StringComparison.Ordinal)
                || entry.FullName.Contains('/')
                || entry.FullName.Contains('\\'))
            {
                throw new InvalidDataException("The evidence bundle contains a nested or unsafe archive entry.");
            }

            if (entry.Length < 0 || entry.Length > MaximumEntryBytes)
            {
                throw new InvalidDataException($"Archive entry '{entry.Name}' exceeds the {MaximumEntryBytes}-byte limit.");
            }

            decompressedBytes = checked(decompressedBytes + entry.Length);
            if (decompressedBytes > MaximumDecompressedBytes)
            {
                throw new InvalidDataException($"The evidence bundle exceeds the {MaximumDecompressedBytes}-byte decompressed limit.");
            }

            if (!entries.TryAdd(entry.Name, entry))
            {
                throw new InvalidDataException($"The evidence bundle contains duplicate entry '{entry.Name}'.");
            }
        }

        if (entries.Count != RequiredEntryNames.Length
            || RequiredEntryNames.Any(required => !entries.ContainsKey(required)))
        {
            throw new InvalidDataException("The evidence bundle does not contain the exact v0.5 entry set.");
        }

        var manifest = await ReadManifestAsync(entries["manifest.sha256"], cancellationToken).ConfigureAwait(false);
        if (manifest.Count != entries.Count - 1)
        {
            throw new InvalidDataException("The evidence manifest does not cover every content entry exactly once.");
        }

        foreach (var (name, entry) in entries)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (string.Equals(name, "manifest.sha256", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!manifest.TryGetValue(name, out var expectedHash))
            {
                throw new InvalidDataException($"Archive entry '{name}' is missing from the evidence manifest.");
            }

            var actualHash = await HashEntryAsync(entry, cancellationToken).ConfigureAwait(false);
            if (!CryptographicOperations.FixedTimeEquals(actualHash, expectedHash))
            {
                throw new InvalidDataException($"Archive entry '{name}' failed SHA-256 verification.");
            }
        }

        var caseEnvelope = await DeserializeEntryAsync<CaseEnvelope>(entries["case.json"], cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("case.json is empty or invalid.");
        if (!string.Equals(caseEnvelope.EvidenceSchemaVersion, EvidenceBundleWriter.EvidenceSchemaVersion, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(caseEnvelope.AnalysisProfileVersion))
        {
            throw new InvalidDataException("The evidence bundle schema or analysis profile is unsupported.");
        }

        if (!CaseIdValidator.IsValid(caseEnvelope.CaseId)
            || !ReviewWindowParser.IsOrdered(caseEnvelope.ReviewWindowStartUtc, caseEnvelope.ReviewWindowEndUtc)
            || caseEnvelope.CollectionStartedUtc > caseEnvelope.CompletedUtc)
        {
            throw new InvalidDataException("The evidence bundle case metadata is invalid.");
        }

        var modules = await DeserializeEntryAsync<List<ModuleResult>>(entries["evidence.json"], cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("evidence.json is empty or invalid.");
        var findings = await DeserializeEntryAsync<List<EvidenceFinding>>(entries["findings.json"], cancellationToken).ConfigureAwait(false)
            ?? throw new InvalidDataException("findings.json is empty or invalid.");
        var recordCount = modules.Sum(module => module.Records?.Count ?? 0);
        if (modules.Count > MaximumModules || recordCount > MaximumRecords || findings.Count > MaximumFindings)
        {
            throw new InvalidDataException("The evidence bundle exceeds normalized record limits.");
        }

        if (modules.Any(module => module.Records is null || module.Warnings is null || module.Errors is null))
        {
            throw new InvalidDataException("The evidence bundle contains an incomplete module record.");
        }

        var context = new CollectionContext(
            caseEnvelope.CaseId,
            caseEnvelope.ReviewWindowStartUtc,
            caseEnvelope.ReviewWindowEndUtc,
            caseEnvelope.CollectionStartedUtc,
            caseEnvelope.CollectorVersion);
        var result = new CollectionRunResult(context, caseEnvelope.CompletedUtc, modules)
        {
            Findings = findings,
        };

        return new EvidenceBundleReadResult(
            result,
            new EvidenceBundleVerification(
                caseEnvelope.EvidenceSchemaVersion,
                caseEnvelope.AnalysisProfileVersion,
                manifest.Count,
                decompressedBytes,
                encrypted));
    }

    private static async Task<Dictionary<string, byte[]>> ReadManifestAsync(
        ZipArchiveEntry entry,
        CancellationToken cancellationToken)
    {
        if (entry.Length > 64 * 1024)
        {
            throw new InvalidDataException("The evidence manifest exceeds its size limit.");
        }

        using var reader = new StreamReader(
            entry.Open(),
            System.Text.Encoding.ASCII,
            detectEncodingFromByteOrderMarks: false,
            bufferSize: 1024,
            leaveOpen: false);
        var text = await reader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
        var manifest = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var line in text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line.Length < 67 || line[64] != ' ' || line[65] != ' ')
            {
                throw new InvalidDataException("The evidence manifest contains a malformed line.");
            }

            byte[] hash;
            try
            {
                hash = Convert.FromHexString(line[..64]);
            }
            catch (FormatException exception)
            {
                throw new InvalidDataException("The evidence manifest contains an invalid SHA-256 value.", exception);
            }

            var name = line[66..];
            if (string.IsNullOrWhiteSpace(name)
                || !string.Equals(name, Path.GetFileName(name), StringComparison.Ordinal)
                || !manifest.TryAdd(name, hash))
            {
                throw new InvalidDataException("The evidence manifest contains an unsafe or duplicate entry name.");
            }
        }

        return manifest;
    }

    private static async Task<byte[]> HashEntryAsync(ZipArchiveEntry entry, CancellationToken cancellationToken)
    {
        await using var stream = entry.Open();
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[81920];
        long totalRead = 0;
        int bytesRead;
        while ((bytesRead = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
        {
            totalRead = checked(totalRead + bytesRead);
            if (totalRead > MaximumEntryBytes)
            {
                throw new InvalidDataException($"Archive entry '{entry.Name}' expanded beyond its size limit.");
            }

            hash.AppendData(buffer, 0, bytesRead);
        }

        return hash.GetHashAndReset();
    }

    private static async Task<T?> DeserializeEntryAsync<T>(
        ZipArchiveEntry entry,
        CancellationToken cancellationToken)
    {
        try
        {
            await using var stream = entry.Open();
            return await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken).ConfigureAwait(false);
        }
        catch (JsonException exception)
        {
            throw new InvalidDataException($"Archive entry '{entry.Name}' contains invalid JSON.", exception);
        }
    }

    private sealed record CaseEnvelope(
        string EvidenceSchemaVersion,
        string AnalysisProfileVersion,
        string CaseId,
        DateTimeOffset ReviewWindowStartUtc,
        DateTimeOffset ReviewWindowEndUtc,
        DateTimeOffset CollectionStartedUtc,
        DateTimeOffset CompletedUtc,
        string CollectorVersion);
}
