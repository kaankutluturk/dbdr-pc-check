using System.Globalization;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Core;

public static class EvidenceAnalyzer
{
    public const string AnalysisProfileVersion = "0.5.0";

    public static IReadOnlyList<EvidenceFinding> Analyze(CollectionRunResult result)
    {
        var candidates = new List<FindingCandidate>();

        foreach (var module in result.Modules)
        {
            if (!module.Completed)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} collection incomplete",
                    "The collector could not complete this module. Absence of its records is not a clean finding.",
                    module.Module,
                    null));
            }

            foreach (var error in module.Errors)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} error",
                    error,
                    module.Module,
                    null));
            }

            foreach (var warning in module.Warnings)
            {
                candidates.Add(new FindingCandidate(
                    FindingDisposition.CoverageGap,
                    $"{module.Module} coverage warning",
                    warning,
                    module.Module,
                    null));
            }
        }

        foreach (var record in result.Records)
        {
            AnalyzeCoverage(record, candidates);
            AnalyzeFileInspection(record, candidates);
            AnalyzeBinaryTriage(record, result.Context, candidates);
            AnalyzePersistence(record, result.Context, candidates);
            AnalyzeCodeIntegrity(record, candidates);
            AnalyzeSecurityPosture(record, candidates);
            AnalyzeUsnExecutableChange(record, candidates);
        }

        AnalyzeCorrelations(result, candidates);

        return candidates
            .DistinctBy(candidate => new
            {
                candidate.Disposition,
                candidate.Title,
                candidate.Detail,
                candidate.Module,
                candidate.RecordKind,
            })
            .Select((candidate, index) => new EvidenceFinding(
                $"F-{(index + 1).ToString("D3", CultureInfo.InvariantCulture)}",
                candidate.Disposition,
                candidate.Title,
                candidate.Detail,
                candidate.Module,
                candidate.RecordKind))
            .ToArray();
    }

    private static void AnalyzeBinaryTriage(
        EvidenceRecord record,
        CollectionContext context,
        ICollection<FindingCandidate> findings)
    {
        if (record.Kind is not ("process.module" or "file.metadata" or "persistence.binary"))
        {
            return;
        }

        var path = Get(record, "modulePath") ?? Get(record, "executablePath") ?? "A referenced file";
        if (int.TryParse(Get(record, "yaraMatchCount"), NumberStyles.None, CultureInfo.InvariantCulture, out var matchCount)
            && matchCount > 0)
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "YARA rule match on a referenced file",
                $"{path} matched {Get(record, "yaraMatches") ?? matchCount.ToString(CultureInfo.InvariantCulture)}. A rule match is a review lead, not proof; validate the rule rationale and corroborate the file identity.",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "yaraStatus"), "unavailable", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                "YARA scan unavailable",
                $"{path}: {Get(record, "yaraError") ?? "The ruleset could not scan this file."}",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "yaraMatchesTruncated"), "true", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                "YARA match reporting cap reached",
                $"{path} reached the per-file rule-identifier reporting cap. The recorded identifiers remain review leads, but the match list is incomplete.",
                record.Module,
                record.Kind));
        }

        var isHighEntropy = string.Equals(
            Get(record, "entropyClassification"),
            "high",
            StringComparison.OrdinalIgnoreCase);
        var signature = Get(record, "authenticodeStatus");
        if (string.Equals(signature, "unsigned", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.Informational,
                "Unsigned referenced executable",
                $"{path} has no Authenticode signature. Unsigned software is common; use this observation to filter and correlate, not as a verdict.",
                record.Module,
                record.Kind));
        }

        if (isHighEntropy && !string.Equals(signature, "valid", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "High-entropy file without a valid signature",
                $"{path} measured {Get(record, "entropyBitsPerByte") ?? "unknown"} bits/byte and its signature status was {signature ?? "unknown"}. Packed or compressed legitimate software is a common alternative explanation.",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "peStatus"), "malformed", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                "PE structure inspection incomplete",
                $"{path}: {Get(record, "peInspectionError") ?? "The bounded PE parser could not safely interpret the file."}",
                record.Module,
                record.Kind));
        }

        var userWritable = IsUserWritablePath(path);
        var isValidSignature = string.Equals(signature, "valid", StringComparison.OrdinalIgnoreCase);
        if (TryGetPositiveInteger(record, "peWritableExecutableSectionCount", out var writableExecutableCount)
            && (userWritable || !isValidSignature))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Writable and executable PE section",
                $"{path} contains {writableExecutableCount.ToString(CultureInfo.InvariantCulture)} writable+executable section(s) and is {(userWritable ? "referenced from a user-writable path" : $"signature={signature ?? "unknown"}")}. Packers and protectors are common alternatives; corroborate imports, signer, hash and execution evidence.",
                record.Module,
                record.Kind));
        }

        var riskClusters = Get(record, "peImportRiskClusters");
        if (!string.IsNullOrWhiteSpace(riskClusters) && (userWritable || !isValidSignature))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Loader-capable PE import cluster",
                $"{path} exposes the bounded import cluster(s) {riskClusters} and is {(userWritable ? "referenced from a user-writable path" : $"signature={signature ?? "unknown"}")}. These APIs are also used by legitimate administration, overlay and security software.",
                record.Module,
                record.Kind));
        }

        var suspiciousSections = Get(record, "peSuspiciousSectionNames");
        if (!string.IsNullOrWhiteSpace(suspiciousSections) && isHighEntropy && !isValidSignature)
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Packed-section indicators on an unsigned PE",
                $"{path} contains section name(s) {suspiciousSections}, high whole-file entropy and signature={signature ?? "unknown"}. This is a multi-signal review lead, not proof of malicious behavior.",
                record.Module,
                record.Kind));
        }

        if (!isValidSignature
            && long.TryParse(
                Get(record, "peOverlaySizeBytes"),
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var overlaySize)
            && overlaySize >= 1024 * 1024
            && string.Equals(
                Get(record, "peOverlayEntropyClassification"),
                "high",
                StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Large high-entropy PE overlay without a valid signature",
                $"{path} has a {overlaySize.ToString(CultureInfo.InvariantCulture)}-byte overlay sampled at {Get(record, "peOverlayEntropyBitsPerByte") ?? "unknown"} bits/byte and signature={signature ?? "unknown"}. Installers, self-extractors and game launchers are common alternatives.",
                record.Module,
                record.Kind));
        }

        if (!isValidSignature
            && string.Equals(Get(record, "peCertificateTablePresent"), "true", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "PE certificate table present but signature not valid",
                $"{path} contains a PE certificate table but WinVerifyTrust returned {signature ?? "unknown"}. Expired, untrusted or malformed signatures are possible; inspect the signature chain before interpreting the result.",
                record.Module,
                record.Kind));
        }

        if (!isValidSignature
            && userWritable
            && IsWithinReviewWindow(Get(record, "fileCreatedUtc"), context))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Recently created unsigned executable in a user-writable path",
                $"{path} has signature={signature ?? "unknown"} and its file creation timestamp falls inside the authorized review window. File timestamps are mutable and legitimate installs/updates are common; corroborate with execution and persistence sources.",
                record.Module,
                record.Kind));
        }
    }

    private static void AnalyzeCoverage(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "coverage.source")
        {
            return;
        }

        var status = Get(record, "status");
        var detail = Get(record, "detail");
        if (detail?.Contains("capped=true", StringComparison.OrdinalIgnoreCase) == true
            || detail?.Contains("enumerationCapped=true", StringComparison.OrdinalIgnoreCase) == true)
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                $"{Get(record, "sourceName") ?? record.Source} collection cap reached",
                detail,
                record.Module,
                record.Kind));
        }

        if (HasNonZeroMetric(detail, "parseFailures"))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                $"{Get(record, "sourceName") ?? record.Source} partial parse failure",
                detail,
                record.Module,
                record.Kind));
        }

        if (status is not ("unavailable" or "disabled" or "notSupported"))
        {
            return;
        }

        var source = Get(record, "sourceName") ?? record.Source;
        var availability = status switch
        {
            "disabled" => "disabled by operator",
            "notSupported" => "not supported on this system",
            _ => "unavailable",
        };
        findings.Add(new FindingCandidate(
            FindingDisposition.CoverageGap,
            $"{source} {availability}",
            Get(record, "detail") ?? "The source did not provide evidence for this collection.",
            record.Module,
            record.Kind));
    }

    private static void AnalyzeFileInspection(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind is not ("process.module" or "file.metadata" or "persistence.binary"))
        {
            return;
        }

        var path = Get(record, "modulePath") ?? Get(record, "executablePath");
        var error = Get(record, "fileInspectionError");
        if (!string.IsNullOrWhiteSpace(error))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.CoverageGap,
                "File inspection incomplete",
                $"{path ?? "A referenced file"}: {error}",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "identityStableDuringInspection"), "false", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "File changed during inspection",
                $"{path ?? "A referenced file"} changed while it was being hashed and inspected. Corroborate before interpreting the result.",
                record.Module,
                record.Kind));
        }

        if (record.Kind == "process.module" && IsUserWritablePath(path))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Game module loaded from a user-writable location",
                $"{path} was present in the live game module list. Location alone is not proof; review its signer, hash and case context.",
                record.Module,
                record.Kind));
        }
    }

    private static void AnalyzePersistence(
        EvidenceRecord record,
        CollectionContext context,
        ICollection<FindingCandidate> findings)
    {
        if (record.Kind == "persistence.scheduled_task")
        {
            var command = Get(record, "command");
            if (IsUserWritablePath(command))
            {
                findings.Add(new FindingCandidate(
                    FindingDisposition.NeedsReview,
                    "Scheduled task launches from a user-writable location",
                    $"{Get(record, "taskPath") ?? "A scheduled task"} references {command}. Review the task in context; this is not a verdict.",
                    record.Module,
                    record.Kind));
            }
        }

        if (record.Kind == "persistence.ifeo_debugger")
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Image File Execution Options debugger persistence",
                $"{Get(record, "imageName") ?? "An image"} has debugger value {Get(record, "debugger") ?? "<unavailable>"}. Development, accessibility and diagnostic configuration are alternative explanations.",
                record.Module,
                record.Kind));
        }

        if (record.Kind == "persistence.registry_location"
            && IsUserWritablePath(Get(record, "value")))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Autorun registry location references a user-writable path",
                $"{Get(record, "locationType") ?? "An autorun location"}/{Get(record, "entryName") ?? "entry"} references {Get(record, "value")}. Review signer and binary identity where resolvable.",
                record.Module,
                record.Kind));
        }

        if (record.Kind == "persistence.startup_file"
            && record.SourceTimestampUtc is { } startupTimestamp
            && startupTimestamp >= context.ReviewWindowStartUtc
            && startupTimestamp <= context.ReviewWindowEndUtc)
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Startup-folder entry modified in the review window",
                $"{Get(record, "path") ?? Get(record, "fileName") ?? "A Startup entry"} has a last-write timestamp inside the authorized review window. Installation and user configuration are common alternatives.",
                record.Module,
                record.Kind));
        }

        var consumerClass = Get(record, "consumerClass");
        if (record.Kind == "persistence.wmi_consumer"
            && consumerClass is not null
            && (consumerClass.Contains("CommandLineEventConsumer", StringComparison.OrdinalIgnoreCase)
                || consumerClass.Contains("ActiveScriptEventConsumer", StringComparison.OrdinalIgnoreCase)))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Executable WMI permanent event consumer present",
                $"{Get(record, "name") ?? "A WMI consumer"} is a {consumerClass}. The collector intentionally excludes its command/script content; inspect it under case authority and corroborate before drawing a conclusion.",
                record.Module,
                record.Kind));
        }
    }

    private static void AnalyzeCodeIntegrity(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "event.code_integrity")
        {
            return;
        }

        if (string.Equals(
                Get(record, "classification"),
                "correlated-signature-information",
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        findings.Add(new FindingCandidate(
            FindingDisposition.NeedsReview,
            "Code Integrity event in the review window",
            $"Windows Code Integrity recorded event {Get(record, "eventId") ?? "unknown"} ({Get(record, "classification") ?? "selected validation event"}) for {Get(record, "filePath") ?? "an unspecified file"}. Interpret it with its signing fields and surrounding evidence.",
            record.Module,
                record.Kind));
    }

    private static void AnalyzeUsnExecutableChange(
        EvidenceRecord record,
        ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "execution.usn_executable_change"
            || !string.Equals(Get(record, "sequence"), "created-and-deleted", StringComparison.OrdinalIgnoreCase)
            || Get(record, "reasons")?.Contains("file-delete", StringComparison.OrdinalIgnoreCase) != true)
        {
            return;
        }

        findings.Add(new FindingCandidate(
            FindingDisposition.NeedsReview,
            "Executable was created and deleted inside retained USN history",
            $"{Get(record, "fileName") ?? "An execution-capable file"} has create and delete records tied to the same internal NTFS file reference during the review window. Installers, updates and temporary extraction are common alternatives; correlate with Prefetch, BAM, Amcache, signer and hash evidence.",
            record.Module,
            record.Kind));
    }

    private static void AnalyzeSecurityPosture(EvidenceRecord record, ICollection<FindingCandidate> findings)
    {
        if (record.Kind != "system.snapshot")
        {
            return;
        }

        var configured = Get(record, "securityServicesConfigured");
        var running = Get(record, "securityServicesRunning");
        if (configured?.Contains("memory-integrity", StringComparison.OrdinalIgnoreCase) == true
            && running?.Contains("memory-integrity", StringComparison.OrdinalIgnoreCase) != true)
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.Informational,
                "Memory integrity configured but not running",
                "Windows reports memory integrity in the configured security-service set but not the running set. Compatibility, boot configuration and policy failure are alternative explanations; correlate with Code Integrity and driver evidence.",
                record.Module,
                record.Kind));
        }

        if (string.Equals(
                Get(record, "vulnerableDriverBlocklistRegistryEnabled"),
                "false",
                StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.Informational,
                "Vulnerable driver blocklist configured off",
                "The documented Windows registry setting reports the vulnerable-driver blocklist off. This weakens one protection layer but is not evidence that a vulnerable driver was present or used.",
                record.Module,
                record.Kind));
        }

        if (string.Equals(Get(record, "secureBootEnabled"), "false", StringComparison.OrdinalIgnoreCase))
        {
            findings.Add(new FindingCandidate(
                FindingDisposition.Informational,
                "Secure Boot reported off",
                "Windows reports Secure Boot off. Unsupported firmware, dual-boot requirements and deliberate configuration are common alternatives; treat this as posture context only.",
                record.Module,
                record.Kind));
        }
    }

    private static void AnalyzeCorrelations(CollectionRunResult result, ICollection<FindingCandidate> findings)
    {
        var binaryRecords = result.Records
            .Where(record => record.Kind is "process.module" or "file.metadata" or "persistence.binary")
            .ToArray();

        foreach (var hashGroup in binaryRecords
                     .Where(record => !string.IsNullOrWhiteSpace(Get(record, "sha256")))
                     .GroupBy(record => Get(record, "sha256")!, StringComparer.OrdinalIgnoreCase))
        {
            var records = hashGroup.ToArray();
            var hasGameModule = records.Any(record => record.Kind == "process.module");
            var hasPersistence = records.Any(record => record.Kind == "persistence.binary");
            if (!hasGameModule || !hasPersistence || !records.Any(HasElevatedBinarySignal))
            {
                continue;
            }

            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Flagged binary identity spans game module and persistence evidence",
                $"SHA-256 {hashGroup.Key} appears in both live DBD module and service/driver persistence evidence, with at least one signature, YARA or PE-import review signal. Legitimate anti-cheat and hardware software can have the same relationship; verify signer, paths and rule rationale.",
                "correlation",
                null));
        }

        foreach (var fingerprintGroup in binaryRecords
                     .Where(record => !string.IsNullOrWhiteSpace(Get(record, "peImportFingerprintSha256")))
                     .GroupBy(record => Get(record, "peImportFingerprintSha256")!, StringComparer.OrdinalIgnoreCase))
        {
            var records = fingerprintGroup.ToArray();
            var distinctHashes = records
                .Select(record => Get(record, "sha256"))
                .Where(value => !string.IsNullOrWhiteSpace(value))
                .Select(value => value!)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();
            if (distinctHashes < 2
                || !records.Any(record => record.Kind == "process.module")
                || !records.Any(record => record.Kind == "persistence.binary")
                || !records.Any(record => !string.IsNullOrWhiteSpace(Get(record, "peImportRiskClusters")))
                || !records.Any(record => !string.Equals(
                    Get(record, "authenticodeStatus"),
                    "valid",
                    StringComparison.OrdinalIgnoreCase)))
            {
                continue;
            }

            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Related PE import profile spans game module and persistence",
                $"Import fingerprint {fingerprintGroup.Key} is shared by {distinctHashes.ToString(CultureInfo.InvariantCulture)} distinct SHA-256 identities across live DBD module and persistence evidence, with a loader-capable import cluster and at least one non-valid signature. Related legitimate builds can share imports; compare signer, hashes, paths and timestamps.",
                "correlation",
                null));
        }

        var processesById = result.Records
            .Where(record => record.Kind == "process.snapshot")
            .Select(record => new { Record = record, ProcessId = ParseUInt32(Get(record, "processId")) })
            .Where(item => item.ProcessId.HasValue)
            .GroupBy(item => item.ProcessId!.Value)
            .ToDictionary(group => group.Key, group => group.First().Record);
        var fileEvidenceByProcessId = new Dictionary<uint, EvidenceRecord>();
        foreach (var record in binaryRecords.Where(record => record.Kind == "file.metadata"))
        {
            foreach (var processId in ParseProcessIds(Get(record, "processIds")))
            {
                fileEvidenceByProcessId.TryAdd(processId, record);
            }
        }

        var gameProcessIds = result.Records
            .Where(record => record.Kind == "process.module")
            .Select(record => ParseUInt32(Get(record, "processId")))
            .Where(value => value.HasValue)
            .Select(value => value!.Value)
            .Distinct()
            .ToArray();
        foreach (var gameProcessId in gameProcessIds)
        {
            if (!processesById.TryGetValue(gameProcessId, out var gameProcess)
                || !ParseUInt32(Get(gameProcess, "parentProcessId")).HasValue)
            {
                continue;
            }

            var parentProcessId = ParseUInt32(Get(gameProcess, "parentProcessId"))!.Value;
            if (!processesById.TryGetValue(parentProcessId, out var parentProcess)
                || !fileEvidenceByProcessId.TryGetValue(parentProcessId, out var parentFile)
                || !HasElevatedBinarySignal(parentFile))
            {
                continue;
            }

            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "DBD parent process has corroborated binary review signals",
                $"{Get(parentProcess, "name") ?? "The parent process"} (PID {parentProcessId.ToString(CultureInfo.InvariantCulture)}) launched a live DBD process and its referenced binary has a signature, YARA or PE-import review signal. Game launchers, debuggers and overlays are common alternatives.",
                "correlation",
                "process.snapshot"));
        }

        var executedFileNames = result.Records
            .Where(record => record.Kind is "execution.prefetch" or "execution.bam")
            .Select(record => record.Kind == "execution.prefetch"
                ? Get(record, "executableName")
                : GetFileName(Get(record, "executablePath")))
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(value => value!)
            .ToHashSet(StringComparer.OrdinalIgnoreCase);
        foreach (var usnRecord in result.Records.Where(record =>
                     record.Kind == "execution.usn_executable_change"
                     && string.Equals(Get(record, "sequence"), "created-and-deleted", StringComparison.OrdinalIgnoreCase)
                     && Get(record, "reasons")?.Contains("file-delete", StringComparison.OrdinalIgnoreCase) == true))
        {
            var fileName = Get(usnRecord, "fileName");
            if (string.IsNullOrWhiteSpace(fileName) || !executedFileNames.Contains(fileName))
            {
                continue;
            }

            findings.Add(new FindingCandidate(
                FindingDisposition.NeedsReview,
                "Created-and-deleted executable corroborated by an execution artifact",
                $"{fileName} has a same-file-reference create/delete sequence in retained USN history and an exact filename match in BAM or parsed Prefetch evidence. Filename collisions and temporary installers remain possible; compare timestamps and any surviving hash/signer evidence.",
                "correlation",
                "execution.usn_executable_change"));
        }
    }

    private static bool HasElevatedBinarySignal(EvidenceRecord record)
    {
        var signature = Get(record, "authenticodeStatus");
        return (!string.IsNullOrWhiteSpace(signature)
                && !string.Equals(signature, "valid", StringComparison.OrdinalIgnoreCase))
            || TryGetPositiveInteger(record, "yaraMatchCount", out _)
            || !string.IsNullOrWhiteSpace(Get(record, "peImportRiskClusters"));
    }

    private static bool IsWithinReviewWindow(string? value, CollectionContext context) =>
        DateTimeOffset.TryParse(
            value,
            CultureInfo.InvariantCulture,
            DateTimeStyles.RoundtripKind,
            out var timestamp)
        && timestamp >= context.ReviewWindowStartUtc
        && timestamp <= context.ReviewWindowEndUtc;

    private static uint? ParseUInt32(string? value) =>
        uint.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : null;

    private static string? GetFileName(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        var separator = Math.Max(path.LastIndexOf('\\'), path.LastIndexOf('/'));
        return separator >= 0 && separator + 1 < path.Length ? path[(separator + 1)..] : path;
    }

    private static IEnumerable<uint> ParseProcessIds(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            yield break;
        }

        foreach (var part in value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (uint.TryParse(part, NumberStyles.None, CultureInfo.InvariantCulture, out var processId))
            {
                yield return processId;
            }
        }
    }

    private static bool HasNonZeroMetric(string? detail, string key)
    {
        if (string.IsNullOrWhiteSpace(detail))
        {
            return false;
        }

        foreach (var segment in detail.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var pair = segment.Split('=', 2, StringSplitOptions.TrimEntries);
            if (pair.Length == 2
                && string.Equals(pair[0], key, StringComparison.OrdinalIgnoreCase)
                && int.TryParse(pair[1], NumberStyles.None, CultureInfo.InvariantCulture, out var value))
            {
                return value > 0;
            }
        }

        return false;
    }

    private static bool IsUserWritablePath(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        return value.StartsWith("%USERPROFILE%", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\AppData\\", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\Downloads\\", StringComparison.OrdinalIgnoreCase)
            || value.Contains("\\Temp\\", StringComparison.OrdinalIgnoreCase)
            || value.StartsWith("%TEMP%", StringComparison.OrdinalIgnoreCase);
    }

    private static string? Get(EvidenceRecord record, string key) =>
        record.Fields.TryGetValue(key, out var value) ? value : null;

    private static bool TryGetPositiveInteger(EvidenceRecord record, string key, out int value) =>
        int.TryParse(Get(record, key), NumberStyles.None, CultureInfo.InvariantCulture, out value) && value > 0;

    private sealed record FindingCandidate(
        FindingDisposition Disposition,
        string Title,
        string Detail,
        string Module,
        string? RecordKind);
}
