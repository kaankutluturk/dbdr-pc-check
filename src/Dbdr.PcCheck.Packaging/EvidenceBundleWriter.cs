using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Packaging;

public sealed class EvidenceBundleWriter
{
    public const string EvidenceSchemaVersion = "0.3.0";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.Never,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    public async Task<string> WriteAsync(
        CollectionRunResult result,
        string outputDirectory,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(outputDirectory);
        Directory.CreateDirectory(outputDirectory);

        var workingDirectory = Path.Combine(Path.GetTempPath(), "DBDRPcCheck", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(workingDirectory);

        try
        {
            await WriteJsonAsync(Path.Combine(workingDirectory, "case.json"), new
            {
                evidenceSchemaVersion = EvidenceSchemaVersion,
                analysisProfileVersion = EvidenceAnalyzer.AnalysisProfileVersion,
                result.Context.CaseId,
                result.Context.ReviewWindowStartUtc,
                result.Context.ReviewWindowEndUtc,
                result.Context.CollectionStartedUtc,
                result.CompletedUtc,
                result.Context.CollectorVersion,
            }, cancellationToken).ConfigureAwait(false);

            await WriteJsonAsync(
                Path.Combine(workingDirectory, "evidence.json"),
                result.Modules,
                cancellationToken).ConfigureAwait(false);

            await WriteJsonAsync(
                Path.Combine(workingDirectory, "collection-log.json"),
                result.Modules.Select(module => new
                {
                    module.Module,
                    module.Completed,
                    durationMilliseconds = Math.Round(module.Duration.TotalMilliseconds, 2),
                    recordCount = module.Records.Count,
                    module.Warnings,
                    module.Errors,
                }),
                cancellationToken).ConfigureAwait(false);

            await WriteJsonAsync(
                Path.Combine(workingDirectory, "findings.json"),
                result.Findings,
                cancellationToken).ConfigureAwait(false);

            await File.WriteAllTextAsync(
                Path.Combine(workingDirectory, "report.html"),
                HtmlReportRenderer.Render(result),
                Encoding.UTF8,
                cancellationToken).ConfigureAwait(false);

            await File.WriteAllTextAsync(
                Path.Combine(workingDirectory, "privacy.txt"),
                "DBDR Evidence Suite development bundle: local-only, not encrypted, and not a moderation verdict. Depending on operator selection it can include redacted process/module paths, file metadata, byte entropy, YARA rule identifiers and ruleset hashes, time-bounded Windows execution artifacts, persistence configuration and privacy-minimized device facts. It excludes browser/chat data, credentials, PowerShell history, unique device serials, matched byte content and process memory. Treat as confidential system metadata. See PRIVACY.md in the source repository.",
                Encoding.UTF8,
                cancellationToken).ConfigureAwait(false);

            await WriteManifestAsync(workingDirectory, cancellationToken).ConfigureAwait(false);

            var timestamp = result.Context.CollectionStartedUtc.ToString("yyyyMMdd-HHmmss", System.Globalization.CultureInfo.InvariantCulture);
            var suffix = Guid.NewGuid().ToString("N")[..6];
            var fileName = $"dbdr-check-{result.Context.CaseId}-{timestamp}-{suffix}.zip";
            var outputPath = Path.Combine(outputDirectory, fileName);
            ZipFile.CreateFromDirectory(workingDirectory, outputPath, CompressionLevel.Optimal, includeBaseDirectory: false);
            return outputPath;
        }
        finally
        {
            if (Directory.Exists(workingDirectory))
            {
                try
                {
                    Directory.Delete(workingDirectory, recursive: true);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
                {
                    // A completed bundle must not be reported as failed because antivirus briefly retained a temporary file.
                }
            }
        }
    }

    private static async Task WriteJsonAsync<T>(string path, T value, CancellationToken cancellationToken)
    {
        await using var stream = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, useAsync: true);
        await JsonSerializer.SerializeAsync(stream, value, JsonOptions, cancellationToken).ConfigureAwait(false);
    }

    private static async Task WriteManifestAsync(string workingDirectory, CancellationToken cancellationToken)
    {
        var lines = new List<string>();
        foreach (var path in Directory.EnumerateFiles(workingDirectory).OrderBy(Path.GetFileName, StringComparer.Ordinal))
        {
            cancellationToken.ThrowIfCancellationRequested();
            await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, useAsync: true);
            var hash = Convert.ToHexString(await SHA256.HashDataAsync(stream, cancellationToken).ConfigureAwait(false));
            lines.Add($"{hash}  {Path.GetFileName(path)}");
        }

        await File.WriteAllLinesAsync(
            Path.Combine(workingDirectory, "manifest.sha256"),
            lines,
            Encoding.ASCII,
            cancellationToken).ConfigureAwait(false);
    }
}
