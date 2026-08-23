using System.Security.Cryptography;
using libyaraNET;

namespace Dbdr.PcCheck.Windows;

public sealed record YaraScanEvidence(
    string Status,
    IReadOnlyList<string> Matches,
    IReadOnlyDictionary<string, string> RulesetHashes,
    string? Error,
    string? MaximumFileSizeBytes = null,
    bool MatchesTruncated = false)
{
    public static YaraScanEvidence Disabled { get; } =
        new("disabled", [], new Dictionary<string, string>(), null);

    public void AddTo(IDictionary<string, string?> fields)
    {
        fields["yaraStatus"] = Status;
        fields["yaraMatchCount"] = Matches.Count.ToString(System.Globalization.CultureInfo.InvariantCulture);
        fields["yaraMatches"] = string.Join(", ", Matches);
        fields["yaraRulesets"] = string.Join(", ", RulesetHashes.Keys.Order(StringComparer.Ordinal));
        fields["yaraRulesetSha256"] = string.Join(
            ", ",
            RulesetHashes.OrderBy(pair => pair.Key, StringComparer.Ordinal)
                .Select(pair => $"{pair.Key}={pair.Value}"));
        fields["yaraRulesetTrust"] = string.Join(
            ", ",
            RulesetHashes.Keys.Order(StringComparer.Ordinal)
                .Select(id => $"{id}={TrustLabel(id)}"));
        fields["yaraError"] = Error;
        fields["yaraMaximumFileSizeBytes"] = MaximumFileSizeBytes;
        fields["yaraMatchesTruncated"] = MatchesTruncated.ToString().ToLowerInvariant();
    }

    private static string TrustLabel(string id) => id switch
    {
        "baseline" => "embedded",
        "custom" => "operator-supplied-unverified",
        _ when id.StartsWith(YaraRulePackVerifier.RuleSetPrefix, StringComparison.Ordinal) => "ecdsa-p256-sha256-verified",
        _ => "unknown",
    };
}

public interface IYaraFileScanner
{
    Task<YaraScanEvidence> ScanAsync(string path, CancellationToken cancellationToken);
}

public sealed class YaraFileScanner : IYaraFileScanner, IDisposable
{
    public const long MaximumScannedFileSizeBytes = 512L * 1024 * 1024;
    public const long MaximumCustomRuleFileSizeBytes = 4L * 1024 * 1024;
    public const int MaximumReportedMatches = 256;
    private const string EmbeddedRuleName = "Dbdr.PcCheck.Windows.Assets.Rules.dbdr-baseline.yar";
    private readonly object _scanGate = new();
    private readonly string _temporaryDirectory;
    private readonly YaraContext _context;
    private readonly IReadOnlyList<CompiledRuleSet> _ruleSets;
    private bool _disposed;

    public YaraFileScanner(string? customRulePath = null)
    {
        _temporaryDirectory = Path.Combine(Path.GetTempPath(), $"DBDR-Yara-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_temporaryDirectory);
        YaraContext? context = null;
        var ruleSets = new List<CompiledRuleSet>();

        try
        {
            var baselinePath = Path.Combine(_temporaryDirectory, "dbdr-baseline.yar");
            ExtractBaselineRules(baselinePath);

            context = new YaraContext();
            ruleSets.Add(Compile("baseline", baselinePath));

            if (!string.IsNullOrWhiteSpace(customRulePath))
            {
                var resolvedCustomPath = ValidateCustomRulePath(customRulePath);
                if (IsRulePackPath(resolvedCustomPath))
                {
                    var pack = YaraRulePackVerifier.VerifyDefault(resolvedCustomPath);
                    var verifiedRulesPath = Path.Combine(_temporaryDirectory, "verified-pack-rules.yar");
                    File.WriteAllBytes(verifiedRulesPath, pack.Rules);
                    ruleSets.Add(Compile(pack.RuleSetId, verifiedRulesPath));
                }
                else
                {
                    ruleSets.Add(Compile("custom", resolvedCustomPath));
                }
            }

            _context = context;
            _ruleSets = ruleSets.ToArray();
        }
        catch
        {
            foreach (var ruleSet in ruleSets)
            {
                ruleSet.Rules.Dispose();
            }

            context?.Dispose();
            TryDeleteTemporaryDirectory();
            throw;
        }
    }

    public IReadOnlyDictionary<string, string> RulesetHashes => RuleHashes();

    public static IReadOnlyDictionary<string, string> CalculateRulesetHashes(string? customRulePath = null)
    {
        var hashes = new Dictionary<string, string>(StringComparer.Ordinal);
        using (var baseline = typeof(YaraFileScanner).Assembly.GetManifestResourceStream(EmbeddedRuleName)
            ?? throw new InvalidOperationException("The embedded DBDR YARA baseline could not be loaded."))
        {
            hashes["baseline"] = Convert.ToHexString(SHA256.HashData(baseline));
        }

        if (!string.IsNullOrWhiteSpace(customRulePath))
        {
            var resolvedCustomPath = ValidateCustomRulePath(customRulePath);
            if (IsRulePackPath(resolvedCustomPath))
            {
                var pack = YaraRulePackVerifier.VerifyDefault(resolvedCustomPath);
                hashes[pack.RuleSetId] = pack.RulesSha256;
            }
            else
            {
                hashes["custom"] = HashFile(resolvedCustomPath);
            }
        }

        return hashes;
    }

    public static string ValidateCustomRulePath(string customRulePath)
    {
        var resolvedCustomPath = Path.GetFullPath(customRulePath);
        var customRuleInfo = new FileInfo(resolvedCustomPath);
        if (!customRuleInfo.Exists)
        {
            throw new FileNotFoundException("The custom YARA rule file was not found.", resolvedCustomPath);
        }

        if (customRuleInfo.Length > MaximumCustomRuleFileSizeBytes)
        {
            throw new InvalidDataException("The custom YARA rule file exceeds the 4 MiB safety limit.");
        }

        if (IsRulePackPath(resolvedCustomPath))
        {
            _ = YaraRulePackVerifier.VerifyDefault(resolvedCustomPath);
            return resolvedCustomPath;
        }

        if (!IsRawRulePath(resolvedCustomPath))
        {
            throw new InvalidDataException("YARA rule material must use .dbdrrules, .yar or .yara.");
        }

        using var stream = new FileStream(resolvedCustomPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var output = new MemoryStream(capacity: checked((int)customRuleInfo.Length));
        stream.CopyTo(output);
        YaraRulePackVerifier.ValidateSelfContainedRules(output.ToArray());
        return resolvedCustomPath;
    }

    public Task<YaraScanEvidence> ScanAsync(string path, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return Task.Run(() => ScanCore(path, cancellationToken), cancellationToken);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        foreach (var ruleSet in _ruleSets)
        {
            ruleSet.Rules.Dispose();
        }

        _context.Dispose();
        TryDeleteTemporaryDirectory();
        _disposed = true;
        GC.SuppressFinalize(this);
    }

    private YaraScanEvidence ScanCore(string path, CancellationToken cancellationToken)
    {
        try
        {
            var fileInfo = new FileInfo(path);
            fileInfo.Refresh();
            if (!fileInfo.Exists)
            {
                return Unavailable("FileNotFoundException");
            }

            if (fileInfo.Length > MaximumScannedFileSizeBytes)
            {
                return new YaraScanEvidence(
                    "skipped-size-limit",
                    [],
                    RuleHashes(),
                    null,
                    MaximumScannedFileSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
            }

            var matches = new HashSet<string>(StringComparer.Ordinal);
            var matchesTruncated = false;
            lock (_scanGate)
            {
                foreach (var ruleSet in _ruleSets)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    var scanner = new Scanner();
                    foreach (var result in scanner.ScanFile(path, ruleSet.Rules))
                    {
                        var identifier = result.MatchingRule?.Identifier;
                        if (!string.IsNullOrWhiteSpace(identifier))
                        {
                            if (matches.Count < MaximumReportedMatches)
                            {
                                matches.Add($"{ruleSet.Id}:{identifier}");
                            }
                            else
                            {
                                matchesTruncated = true;
                            }
                        }
                    }
                }
            }

            return new YaraScanEvidence(
                matches.Count == 0 ? "no-match" : "matched",
                matches.Order(StringComparer.Ordinal).ToArray(),
                RuleHashes(),
                null,
                MaximumScannedFileSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture),
                matchesTruncated);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidOperationException
            or System.Security.SecurityException
            or BadImageFormatException
            or DllNotFoundException
            or TypeInitializationException)
        {
            return Unavailable(exception.GetType().Name);
        }
    }

    private YaraScanEvidence Unavailable(string error) => new(
        "unavailable",
        [],
        RuleHashes(),
        error,
        MaximumScannedFileSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private IReadOnlyDictionary<string, string> RuleHashes() =>
        _ruleSets.ToDictionary(ruleSet => ruleSet.Id, ruleSet => ruleSet.Sha256, StringComparer.Ordinal);

    private static CompiledRuleSet Compile(string id, string path)
    {
        using var compiler = new libyaraNET.Compiler();
        compiler.AddRuleFile(path);
        return new CompiledRuleSet(id, HashFile(path), compiler.GetRules());
    }

    private static string HashFile(string path)
    {
        using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void ExtractBaselineRules(string destinationPath)
    {
        using var source = typeof(YaraFileScanner).Assembly.GetManifestResourceStream(EmbeddedRuleName)
            ?? throw new InvalidOperationException("The embedded DBDR YARA baseline could not be loaded.");
        using var destination = new FileStream(
            destinationPath,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None);
        source.CopyTo(destination);
    }

    private static bool IsRulePackPath(string path) =>
        string.Equals(Path.GetExtension(path), ".dbdrrules", StringComparison.OrdinalIgnoreCase);

    private static bool IsRawRulePath(string path) =>
        string.Equals(Path.GetExtension(path), ".yar", StringComparison.OrdinalIgnoreCase)
        || string.Equals(Path.GetExtension(path), ".yara", StringComparison.OrdinalIgnoreCase);

    private void TryDeleteTemporaryDirectory()
    {
        try
        {
            if (Directory.Exists(_temporaryDirectory))
            {
                Directory.Delete(_temporaryDirectory, recursive: true);
            }
        }
        catch (IOException)
        {
        }
        catch (UnauthorizedAccessException)
        {
        }
    }

    private sealed record CompiledRuleSet(string Id, string Sha256, Rules Rules);
}
