using System.Security.Cryptography;
using libyaraNET;

namespace Dbdr.PcCheck.Windows;

public sealed record YaraScanEvidence(
    string Status,
    IReadOnlyList<string> Matches,
    IReadOnlyDictionary<string, string> RulesetHashes,
    string? Error)
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
        fields["yaraError"] = Error;
    }
}

public interface IYaraFileScanner
{
    Task<YaraScanEvidence> ScanAsync(string path, CancellationToken cancellationToken);
}

public sealed class YaraFileScanner : IYaraFileScanner, IDisposable
{
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
                var resolvedCustomPath = Path.GetFullPath(customRulePath);
                if (!File.Exists(resolvedCustomPath))
                {
                    throw new FileNotFoundException("The custom YARA rule file was not found.", resolvedCustomPath);
                }

                ruleSets.Add(Compile("custom", resolvedCustomPath));
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
            var matches = new HashSet<string>(StringComparer.Ordinal);
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
                            matches.Add($"{ruleSet.Id}:{identifier}");
                        }
                    }
                }
            }

            return new YaraScanEvidence(
                matches.Count == 0 ? "no-match" : "matched",
                matches.Order(StringComparer.Ordinal).ToArray(),
                _ruleSets.ToDictionary(ruleSet => ruleSet.Id, ruleSet => ruleSet.Sha256, StringComparer.Ordinal),
                null);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidOperationException
            or BadImageFormatException
            or DllNotFoundException
            or TypeInitializationException)
        {
            return new YaraScanEvidence(
                "unavailable",
                [],
                _ruleSets.ToDictionary(ruleSet => ruleSet.Id, ruleSet => ruleSet.Sha256, StringComparer.Ordinal),
                exception.GetType().Name);
        }
    }

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
