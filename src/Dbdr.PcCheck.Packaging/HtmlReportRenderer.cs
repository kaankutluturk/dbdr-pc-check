using System.Globalization;
using System.Net;
using System.Text;
using Dbdr.PcCheck.Core.Models;

namespace Dbdr.PcCheck.Packaging;

public static class HtmlReportRenderer
{
    public static string Render(CollectionRunResult result)
    {
        var builder = new StringBuilder();
        builder.Append("""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width,initial-scale=1">
              <title>DBDR Evidence Suite Report</title>
              <style>
                :root{color-scheme:light;--ink:#17202b;--muted:#627083;--line:#dce3eb;--panel:#fff;--page:#f3f6f9;--red:#b93248;--redbg:#fff0f2;--amber:#8a5b00;--amberbg:#fff7df;--blue:#285d92;--bluebg:#edf5ff;--green:#21663c;--greenbg:#edf9f1}
                *{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;max-width:1380px;margin:0 auto;padding:32px 24px 60px;color:var(--ink);background:var(--page)}
                h1{font-size:30px;margin:0}h2{font-size:21px;margin:32px 0 12px}h3{font-size:16px;margin:20px 0 8px}.muted{color:var(--muted)}
                .top{display:flex;justify-content:space-between;gap:20px;align-items:flex-start}.brand{color:var(--red);font-size:12px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;margin-bottom:8px}
                .notice{padding:14px 16px;background:var(--amberbg);border:1px solid #efd99b;border-left:4px solid #d69a18;border-radius:7px;margin:22px 0}
                .cards{display:grid;grid-template-columns:repeat(4,minmax(140px,1fr));gap:12px;margin:20px 0}.card,.panel,details{background:var(--panel);border:1px solid var(--line);border-radius:9px}.card{padding:16px}.card .value{font-size:25px;font-weight:650;margin-top:5px}.card .label{font-size:12px;color:var(--muted)}
                .panel{padding:16px;margin:12px 0}.scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;background:var(--panel);margin:8px 0}th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}th{background:#edf2f7;white-space:nowrap;font-size:12px;color:#455365}td{font-size:13px}
                .badge{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;font-weight:650;white-space:nowrap}.review{color:var(--red);background:var(--redbg)}.gap{color:var(--amber);background:var(--amberbg)}.info{color:var(--blue);background:var(--bluebg)}.ok{color:var(--green);background:var(--greenbg)}
                code,.mono{font-family:Cascadia Mono,Consolas,monospace;word-break:break-all;font-size:.9em}details{margin:12px 0;padding:13px 15px}summary{cursor:pointer;font-weight:650}.count{font-weight:400;color:var(--muted)}
                ul.compact{margin:7px 0 0;padding-left:20px}ul.compact li{margin:4px 0}.empty{color:var(--muted);font-style:italic}.finding{padding:13px 14px;border:1px solid var(--line);border-radius:8px;background:var(--panel);margin:8px 0}.finding-title{font-weight:650;margin-left:7px}.finding-detail{margin:7px 0 0;color:#425064}.source{font-size:11px;color:var(--muted);margin-top:7px}
                @media(max-width:800px){.cards{grid-template-columns:repeat(2,1fr)}.top{display:block}.top .muted{margin-top:10px}}
              </style>
            </head>
            <body>
            """);

        var reviewCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.NeedsReview);
        var gapCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.CoverageGap);
        var completedModules = result.Modules.Count(module => module.Completed);

        builder.Append("<div class=\"top\"><div><div class=\"brand\">DBDR Evidence Suite</div><h1>Authorized PC Check Report</h1><div class=\"muted\">Collector ")
            .Append(Encode(result.Context.CollectorVersion))
            .Append("</div></div><div class=\"muted mono\">")
            .Append(Encode(result.Context.CaseId)).Append("</div></div>");
        builder.Append("<div class=\"notice\"><strong>Observations, not a verdict.</strong> Review items identify facts that need corroboration. Missing, inaccessible, disabled or unsupported sources are coverage gaps and never establish that a machine is clean or that cheating occurred.</div>");

        builder.Append("<div class=\"cards\">");
        SummaryCard(builder, "Evidence records", result.Records.Count);
        SummaryCard(builder, "Modules completed", $"{completedModules}/{result.Modules.Count}");
        SummaryCard(builder, "Needs review", reviewCount);
        SummaryCard(builder, "Coverage gaps", gapCount);
        builder.Append("</div>");

        RenderCase(builder, result);
        RenderFindings(builder, result, FindingDisposition.NeedsReview, "Review queue", "No automated review items were generated. This is not a clean finding.");
        RenderFindings(builder, result, FindingDisposition.CoverageGap, "Coverage gaps", "No collection gaps were reported by the enabled modules.");
        RenderSourceCoverage(builder, result);
        RenderTimeline(builder, result);
        RenderLiveGame(builder, result);
        RenderExecutionHistory(builder, result);
        RenderPersistence(builder, result);
        RenderDevices(builder, result);
        RenderProcessAndFileEvidence(builder, result);
        RenderSystem(builder, result);
        RenderModuleLog(builder, result);

        builder.Append("<p class=\"muted\">Normalized evidence is in <code>evidence.json</code>, neutral findings are in <code>findings.json</code>, module diagnostics are in <code>collection-log.json</code>, and integrity hashes are in <code>manifest.sha256</code>.</p></body></html>");
        return builder.ToString();
    }

    private static void RenderCase(StringBuilder builder, CollectionRunResult result)
    {
        builder.Append("<h2>Case and time boundary</h2><div class=\"scroll\"><table><tbody>");
        Row(builder, "Case ID", result.Context.CaseId);
        Row(builder, "Review window (UTC)", $"{FormatTimestamp(result.Context.ReviewWindowStartUtc)} — {FormatTimestamp(result.Context.ReviewWindowEndUtc)}");
        Row(builder, "Collection started (UTC)", FormatTimestamp(result.Context.CollectionStartedUtc));
        Row(builder, "Collection completed (UTC)", FormatTimestamp(result.CompletedUtc));
        builder.Append("</tbody></table></div><p class=\"muted\">Only sources with reliable timestamps can be filtered into the review-window timeline. Current-state records may legitimately have no source timestamp.</p>");
    }

    private static void RenderFindings(
        StringBuilder builder,
        CollectionRunResult result,
        FindingDisposition disposition,
        string heading,
        string emptyMessage)
    {
        var findings = result.Findings.Where(finding => finding.Disposition == disposition).ToArray();
        builder.Append("<h2>").Append(Encode(heading)).Append(" <span class=\"count\">(")
            .Append(findings.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></h2>");
        if (findings.Length == 0)
        {
            builder.Append("<div class=\"panel empty\">").Append(Encode(emptyMessage)).Append("</div>");
            return;
        }

        foreach (var finding in findings)
        {
            builder.Append("<div class=\"finding\"><span class=\"badge ")
                .Append(disposition == FindingDisposition.NeedsReview ? "review\">needs review" : "gap\">coverage gap")
                .Append("</span><span class=\"finding-title\">").Append(Encode(finding.Title))
                .Append("</span><div class=\"finding-detail\">").Append(Encode(finding.Detail))
                .Append("</div><div class=\"source\">").Append(Encode($"{finding.Id} · {finding.Module} · {finding.RecordKind ?? "module"}"))
                .Append("</div></div>");
        }
    }

    private static void RenderSourceCoverage(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind == "coverage.source").ToArray();
        builder.Append("<h2>Source coverage</h2>");
        if (records.Length == 0)
        {
            builder.Append("<div class=\"panel empty\">No source-level coverage records were produced.</div>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Source</th><th>Status</th><th>Records</th><th>Detail</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => Get(record, "sourceName") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            var status = Get(record, "status");
            builder.Append("<tr><td>").Append(Encode(Get(record, "sourceName")))
                .Append("</td><td>").Append(StatusBadge(status))
                .Append("</td><td>").Append(Encode(Get(record, "recordCount")))
                .Append("</td><td>").Append(Encode(Get(record, "detail"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div>");
    }

    private static void RenderTimeline(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records
            .Where(record => record.SourceTimestampUtc.HasValue
                && record.SourceTimestampUtc.Value >= result.Context.ReviewWindowStartUtc
                && record.SourceTimestampUtc.Value <= result.Context.ReviewWindowEndUtc)
            .OrderBy(record => record.SourceTimestampUtc)
            .ThenBy(record => record.Kind, StringComparer.Ordinal)
            .ToArray();

        builder.Append("<h2>Review-window timeline <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(" records)</span></h2>");
        if (records.Length == 0)
        {
            builder.Append("<div class=\"panel empty\">No enabled source exposed a timestamp inside the selected review window. This is not a clean finding.</div>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Source time (UTC)</th><th>Kind</th><th>Observation</th><th>Source</th></tr></thead><tbody>");
        foreach (var record in records)
        {
            builder.Append("<tr><td class=\"mono\">").Append(Encode(FormatTimestamp(record.SourceTimestampUtc!.Value)))
                .Append("</td><td><code>").Append(Encode(record.Kind)).Append("</code></td><td>")
                .Append(Encode(Summarize(record))).Append("</td><td>").Append(Encode(record.Source)).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div>");
    }

    private static void RenderLiveGame(StringBuilder builder, CollectionRunResult result)
    {
        var status = result.Records.FirstOrDefault(record => record.Kind == "game.snapshot");
        var modules = result.Records.Where(record => record.Kind == "process.module").ToArray();
        builder.Append("<h2>Live DBD state</h2>");
        if (status is null)
        {
            builder.Append("<div class=\"panel empty\">The live game module produced no status record.</div>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><tbody>");
        Row(builder, "Matching processes", Get(status, "matchingProcesses"));
        Row(builder, "Matching process count", Get(status, "matchingProcessCount"));
        Row(builder, "Enumeration succeeded", Get(status, "moduleEnumerationSucceededCount"));
        Row(builder, "Enumeration failed", Get(status, "moduleEnumerationFailedCount"));
        Row(builder, "Loaded-module records", Get(status, "moduleRecordCount"));
        builder.Append("</tbody></table></div>");

        builder.Append("<details open><summary>Loaded file-backed modules <span class=\"count\">(")
            .Append(modules.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (modules.Length == 0)
        {
            builder.Append("<p class=\"empty\">No loaded-module records were collected. Review coverage above.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Process</th><th>Module</th><th>Path</th><th>Signature</th><th>Entropy</th><th>YARA</th><th>Stable</th><th>SHA-256</th><th>Error</th></tr></thead><tbody>");
        foreach (var record in modules.OrderBy(record => Get(record, "modulePath") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td>").Append(Encode($"{Get(record, "processName")} ({Get(record, "processId")})"))
                .Append("</td><td>").Append(Encode(Get(record, "moduleName")))
                    .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "modulePath")))
                    .Append("</td><td>").Append(Encode(Get(record, "authenticodeStatus")))
                    .Append("</td><td>").Append(Encode(Get(record, "entropyBitsPerByte")))
                    .Append("</td><td>").Append(Encode(Get(record, "yaraMatches") ?? Get(record, "yaraStatus")))
                    .Append("</td><td>").Append(Encode(Get(record, "identityStableDuringInspection")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "sha256")))
                .Append("</td><td>").Append(Encode(Get(record, "fileInspectionError"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderExecutionHistory(StringBuilder builder, CollectionRunResult result)
    {
        var kinds = new[]
        {
            "execution.bam", "execution.prefetch", "execution.amcache", "event.service_install",
            "event.code_integrity", "event.application_crash", "event.powershell_engine",
        };
        var records = result.Records.Where(record => kinds.Contains(record.Kind, StringComparer.Ordinal)).ToArray();
        builder.Append("<h2>Execution, crash and integrity metadata</h2><details open><summary>Selected records <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No execution-history records were collected. Review source coverage.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Time (UTC)</th><th>Kind</th><th>Path / subject</th><th>Timestamp basis</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => record.SourceTimestampUtc))
        {
            builder.Append("<tr><td class=\"mono\">").Append(Encode(FormatTimestamp(record.SourceTimestampUtc)))
                .Append("</td><td><code>").Append(Encode(record.Kind))
                .Append("</code></td><td class=\"mono\">").Append(Encode(ExecutionSubject(record)))
                .Append("</td><td>").Append(Encode(Get(record, "timestampBasis") ?? record.Source)).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderPersistence(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind.StartsWith("persistence.", StringComparison.Ordinal)).ToArray();
        builder.Append("<h2>Persistence configuration</h2><details><summary>Run keys, services, drivers and tasks <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No persistence records were collected.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Kind</th><th>Name</th><th>Command / image / value</th><th>State</th><th>Triggers</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => record.Kind, StringComparer.Ordinal)
                     .ThenBy(record => PersistenceName(record) ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td><code>").Append(Encode(record.Kind))
                .Append("</code></td><td>").Append(Encode(PersistenceName(record)))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "command") ?? Get(record, "imagePath") ?? Get(record, "value")))
                .Append("</td><td>").Append(Encode(Get(record, "state") ?? Get(record, "enabled")))
                .Append("</td><td>").Append(Encode(Get(record, "triggerTypes"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderDevices(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind == "device.snapshot").ToArray();
        builder.Append("<h2>Device inventory</h2><details><summary>Privacy-minimized Plug and Play records <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No device records were collected.</p></details>");
            return;
        }

        builder.Append("<p class=\"muted\">Unique device-instance identifiers and serial suffixes are intentionally excluded. A model identifier does not establish DMA use.</p><div class=\"scroll\"><table><thead><tr><th>Class</th><th>Name</th><th>Manufacturer</th><th>Model ID</th><th>Service</th><th>Status</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => Get(record, "pnpClass") ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(record => Get(record, "name") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td>").Append(Encode(Get(record, "pnpClass")))
                .Append("</td><td>").Append(Encode(Get(record, "name")))
                .Append("</td><td>").Append(Encode(Get(record, "manufacturer")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "modelIdentifier")))
                .Append("</td><td>").Append(Encode(Get(record, "service")))
                .Append("</td><td>").Append(Encode(Get(record, "status"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderProcessAndFileEvidence(StringBuilder builder, CollectionRunResult result)
    {
        var processes = result.Records.Where(record => record.Kind == "process.snapshot").ToArray();
        var files = result.Records.Where(record => record.Kind == "file.metadata").ToArray();
        builder.Append("<h2>Process and executable evidence</h2><details><summary>Live processes <span class=\"count\">(")
            .Append(processes.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (processes.Length > 0)
        {
            builder.Append("<div class=\"scroll\"><table><thead><tr><th>PID</th><th>Parent</th><th>Session</th><th>Created</th><th>Name</th><th>Path</th></tr></thead><tbody>");
            foreach (var record in processes.OrderBy(record => ParseUInt64(Get(record, "processId"))))
            {
                builder.Append("<tr><td>").Append(Encode(Get(record, "processId")))
                    .Append("</td><td>").Append(Encode(Get(record, "parentProcessId")))
                    .Append("</td><td>").Append(Encode(Get(record, "sessionId")))
                    .Append("</td><td class=\"mono\">").Append(Encode(FormatTimestamp(record.SourceTimestampUtc)))
                    .Append("</td><td>").Append(Encode(Get(record, "name")))
                    .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "executablePath"))).Append("</td></tr>");
            }

            builder.Append("</tbody></table></div>");
        }
        else
        {
            builder.Append("<p class=\"empty\">No process records were collected.</p>");
        }

        builder.Append("</details><details><summary>Executable enrichment <span class=\"count\">(")
            .Append(files.Length.ToString(CultureInfo.InvariantCulture)).Append(")</span></summary>");
        if (files.Length > 0)
        {
            builder.Append("<div class=\"scroll\"><table><thead><tr><th>Path</th><th>Referenced by</th><th>Signature</th><th>Entropy</th><th>YARA</th><th>Stable</th><th>SHA-256</th><th>Error</th></tr></thead><tbody>");
            foreach (var record in files.OrderBy(record => Get(record, "executablePath") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            {
                builder.Append("<tr><td class=\"mono\">").Append(Encode(Get(record, "executablePath")))
                    .Append("</td><td>").Append(Encode(Get(record, "processNames")))
                    .Append("</td><td>").Append(Encode(Get(record, "authenticodeStatus")))
                    .Append("</td><td>").Append(Encode(Get(record, "entropyBitsPerByte")))
                    .Append("</td><td>").Append(Encode(Get(record, "yaraMatches") ?? Get(record, "yaraStatus")))
                    .Append("</td><td>").Append(Encode(Get(record, "identityStableDuringInspection")))
                    .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "sha256")))
                    .Append("</td><td>").Append(Encode(Get(record, "fileInspectionError"))).Append("</td></tr>");
            }

            builder.Append("</tbody></table></div>");
        }
        else
        {
            builder.Append("<p class=\"empty\">Executable enrichment was disabled or produced no records.</p>");
        }

        builder.Append("</details>");
    }

    private static void RenderSystem(StringBuilder builder, CollectionRunResult result)
    {
        var record = result.Records.FirstOrDefault(candidate => candidate.Kind == "system.snapshot");
        builder.Append("<details><summary>Non-identifying system snapshot</summary>");
        if (record is null)
        {
            builder.Append("<p class=\"empty\">No system snapshot was collected.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><tbody>");
        foreach (var field in record.Fields.OrderBy(field => field.Key, StringComparer.Ordinal))
        {
            Row(builder, field.Key, field.Value);
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderModuleLog(StringBuilder builder, CollectionRunResult result)
    {
        builder.Append("<h2>Module diagnostics</h2><div class=\"scroll\"><table><thead><tr><th>Module</th><th>Status</th><th>Records</th><th>Warnings</th><th>Errors</th><th>Duration</th></tr></thead><tbody>");
        foreach (var module in result.Modules)
        {
            builder.Append("<tr><td>").Append(Encode(module.Module)).Append("</td><td>")
                .Append(module.Completed ? "<span class=\"badge ok\">completed</span>" : "<span class=\"badge gap\">incomplete</span>")
                .Append("</td><td>").Append(module.Records.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Warnings.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Errors.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Duration.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture)).Append(" s</td></tr>");

            if (module.Warnings.Count > 0 || module.Errors.Count > 0)
            {
                builder.Append("<tr><td colspan=\"6\"><ul class=\"compact\">");
                foreach (var issue in module.Warnings.Concat(module.Errors))
                {
                    builder.Append("<li>").Append(Encode(issue)).Append("</li>");
                }

                builder.Append("</ul></td></tr>");
            }
        }

        builder.Append("</tbody></table></div>");
    }

    private static string Summarize(EvidenceRecord record) => record.Kind switch
    {
        "process.snapshot" => $"Process {Get(record, "name")} (PID {Get(record, "processId")})",
        "execution.bam" => $"BAM entry for {Get(record, "executablePath")}",
        "execution.prefetch" => $"Prefetch metadata for {Get(record, "prefetchFile")}",
        "execution.amcache" => $"Amcache inventory entry for {Get(record, "executablePath") ?? Get(record, "fileName")}",
        "event.service_install" => $"Service installation: {Get(record, "serviceName")}",
        "event.code_integrity" => $"Code Integrity event {Get(record, "eventId")}",
        "event.application_crash" => $"Application crash: {Get(record, "applicationName")}",
        "event.powershell_engine" => $"PowerShell {Get(record, "lifecycle")} event",
        "persistence.scheduled_task" => $"Scheduled task {Get(record, "taskPath")}",
        _ => string.Join(", ", record.Fields.Take(3).Select(field => $"{field.Key}={field.Value}")),
    };

    private static string? ExecutionSubject(EvidenceRecord record) => record.Kind switch
    {
        "execution.bam" => Get(record, "executablePath"),
        "execution.prefetch" => Get(record, "prefetchFile"),
        "execution.amcache" => Get(record, "executablePath") ?? Get(record, "fileName"),
        "event.service_install" => $"{Get(record, "serviceName")} · {Get(record, "imagePath")}",
        "event.code_integrity" => $"Event {Get(record, "eventId")}",
        "event.application_crash" => $"{Get(record, "applicationName")} · {Get(record, "applicationPath")}",
        "event.powershell_engine" => $"{Get(record, "lifecycle")} · Event {Get(record, "eventId")}",
        _ => null,
    };

    private static string? PersistenceName(EvidenceRecord record) =>
        Get(record, "taskPath") ?? Get(record, "name") ?? Get(record, "entryName");

    private static string StatusBadge(string? status) => status switch
    {
        "available" => "<span class=\"badge ok\">available</span>",
        "empty" => "<span class=\"badge info\">empty</span>",
        "disabled" => "<span class=\"badge gap\">disabled</span>",
        "notSupported" => "<span class=\"badge gap\">not supported</span>",
        _ => "<span class=\"badge gap\">unavailable</span>",
    };

    private static string? Get(EvidenceRecord record, string key) =>
        record.Fields.TryGetValue(key, out var value) ? value : null;

    private static ulong ParseUInt64(string? value) =>
        ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : ulong.MaxValue;

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'Z'", CultureInfo.InvariantCulture);

    private static string FormatTimestamp(DateTimeOffset? value) =>
        value.HasValue ? FormatTimestamp(value.Value) : "—";

    private static void SummaryCard(StringBuilder builder, string label, object value) =>
        builder.Append("<div class=\"card\"><div class=\"label\">").Append(Encode(label))
            .Append("</div><div class=\"value\">").Append(Encode(Convert.ToString(value, CultureInfo.InvariantCulture)))
            .Append("</div></div>");

    private static void Row(StringBuilder builder, string label, string? value) =>
        builder.Append("<tr><th>").Append(Encode(label)).Append("</th><td>").Append(Encode(value)).Append("</td></tr>");

    private static string Encode(string? value) =>
        WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(value) ? "—" : value);
}
