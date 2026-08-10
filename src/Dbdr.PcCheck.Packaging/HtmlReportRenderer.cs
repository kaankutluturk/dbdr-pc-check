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
              <title>DBDR PC Check Report</title>
              <style>
                :root{color-scheme:light;--ink:#18202a;--muted:#5c6875;--line:#dfe5ec;--panel:#fff;--page:#f5f7fa;--warn:#905d00;--bad:#9f2f36;--ok:#1d6b3b;--accent:#b83f50}
                *{box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;max-width:1280px;margin:36px auto;padding:0 20px;color:var(--ink);background:var(--page)}
                h1{margin-bottom:4px}h2{margin:30px 0 10px}h3{margin:22px 0 8px}.muted{color:var(--muted)}
                .notice{padding:14px 16px;background:#fff4d6;border-left:4px solid #d79b00;margin:22px 0}.errorbox{padding:12px 14px;background:#fff0f1;border-left:4px solid var(--bad);margin:10px 0}
                .panel{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin:12px 0}.scroll{overflow-x:auto}
                table{width:100%;border-collapse:collapse;background:var(--panel);margin:10px 0}th,td{text-align:left;vertical-align:top;padding:9px 10px;border-bottom:1px solid var(--line)}
                th{background:#edf2f7;white-space:nowrap}.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
                code,.mono{font-family:Cascadia Mono,Consolas,monospace;word-break:break-all;font-size:.92em}details{background:var(--panel);border:1px solid var(--line);border-radius:8px;margin:12px 0;padding:12px 14px}
                summary{cursor:pointer;font-weight:600}.count{font-weight:400;color:var(--muted)}ul.compact{margin:8px 0;padding-left:22px}ul.compact li{margin:4px 0}.empty{color:var(--muted);font-style:italic}
              </style>
            </head>
            <body>
            """);

        builder.Append("<h1>DBDR PC Check Report</h1><div class=\"muted\">Development collector v")
            .Append(Encode(result.Context.CollectorVersion))
            .Append("</div>");
        builder.Append("<div class=\"notice\"><strong>Observations, not a verdict.</strong> This report does not prove that a machine is clean. Missing, disabled, unsupported or inaccessible sources must be treated as coverage gaps—not as evidence for or against a player.</div>");

        RenderCase(builder, result);
        RenderModuleCoverage(builder, result);
        RenderIssues(builder, result);
        RenderReviewWindowTimeline(builder, result);
        RenderGameState(builder, result);
        RenderFileMetadata(builder, result);
        RenderProcesses(builder, result);
        RenderPersistence(builder, result);
        RenderSystem(builder, result);

        builder.Append("<p class=\"muted\">Normalized records are in <code>evidence.json</code>; module failures are in <code>collection-log.json</code>; bundle integrity hashes are in <code>manifest.sha256</code>.</p></body></html>");
        return builder.ToString();
    }

    private static void RenderCase(StringBuilder builder, CollectionRunResult result)
    {
        builder.Append("<h2>Case</h2><div class=\"scroll\"><table><tbody>");
        Row(builder, "Case ID", result.Context.CaseId);
        Row(builder, "Review window (UTC)", $"{FormatTimestamp(result.Context.ReviewWindowStartUtc)} — {FormatTimestamp(result.Context.ReviewWindowEndUtc)}");
        Row(builder, "Collection started (UTC)", FormatTimestamp(result.Context.CollectionStartedUtc));
        Row(builder, "Collection completed (UTC)", FormatTimestamp(result.CompletedUtc));
        builder.Append("</tbody></table></div><p class=\"muted\">The review window was supplied as case metadata. A record appears in the timeline only when its source exposes a timestamp inside that window.</p>");
    }

    private static void RenderModuleCoverage(StringBuilder builder, CollectionRunResult result)
    {
        builder.Append("<h2>Collection coverage</h2><div class=\"scroll\"><table><thead><tr><th>Module</th><th>Status</th><th>Records</th><th>Warnings</th><th>Errors</th><th>Duration</th></tr></thead><tbody>");
        foreach (var module in result.Modules)
        {
            builder.Append("<tr><td>").Append(Encode(module.Module)).Append("</td><td class=\"")
                .Append(module.Completed ? "ok\">completed" : "bad\">incomplete")
                .Append("</td><td>").Append(module.Records.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Warnings.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Errors.Count.ToString(CultureInfo.InvariantCulture))
                .Append("</td><td>").Append(module.Duration.TotalSeconds.ToString("F2", CultureInfo.InvariantCulture)).Append(" s</td></tr>");
        }

        builder.Append("</tbody></table></div>");
    }

    private static void RenderIssues(StringBuilder builder, CollectionRunResult result)
    {
        var modulesWithIssues = result.Modules
            .Where(module => module.Warnings.Count > 0 || module.Errors.Count > 0)
            .ToArray();
        builder.Append("<h2>Coverage gaps and collection issues</h2>");
        if (modulesWithIssues.Length == 0)
        {
            builder.Append("<div class=\"panel empty\">No module warnings or errors were recorded.</div>");
            return;
        }

        foreach (var module in modulesWithIssues)
        {
            builder.Append("<div class=\"errorbox\"><strong>").Append(Encode(module.Module)).Append("</strong>");
            AppendIssueList(builder, "Warnings", module.Warnings, "warn");
            AppendIssueList(builder, "Errors", module.Errors, "bad");
            builder.Append("</div>");
        }
    }

    private static void RenderReviewWindowTimeline(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records
            .Where(record => record.SourceTimestampUtc.HasValue
                && record.SourceTimestampUtc.Value >= result.Context.ReviewWindowStartUtc
                && record.SourceTimestampUtc.Value <= result.Context.ReviewWindowEndUtc)
            .OrderBy(record => record.SourceTimestampUtc)
            .ThenBy(record => record.Kind, StringComparer.Ordinal)
            .ToArray();

        builder.Append("<h2>Review-window timeline</h2>");
        if (records.Length == 0)
        {
            builder.Append("<div class=\"panel empty\">No current collector record exposed a source timestamp inside the selected review window. This is not a clean finding.</div>");
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

    private static void RenderGameState(StringBuilder builder, CollectionRunResult result)
    {
        var status = result.Records.FirstOrDefault(record => record.Kind == "game.snapshot");
        var modules = result.Records.Where(record => record.Kind == "process.module").ToArray();
        builder.Append("<h2>Live DBD state</h2>");
        if (status is null)
        {
            builder.Append("<div class=\"panel empty\">The game-module module produced no status record.</div>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><tbody>");
        Row(builder, "Matching processes", Get(status, "matchingProcesses"));
        Row(builder, "Matching process count", Get(status, "matchingProcessCount"));
        Row(builder, "Module enumeration succeeded", Get(status, "moduleEnumerationSucceededCount"));
        Row(builder, "Module enumeration failed", Get(status, "moduleEnumerationFailedCount"));
        Row(builder, "Module records", Get(status, "moduleRecordCount"));
        builder.Append("</tbody></table></div>");

        builder.Append("<details open><summary>Loaded modules <span class=\"count\">(")
            .Append(modules.Length.ToString(CultureInfo.InvariantCulture)).Append(" records)</span></summary>");
        if (modules.Length == 0)
        {
            builder.Append("<p class=\"empty\">No module records were collected. Review the status and coverage issues above.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Process</th><th>Module</th><th>Path</th><th>Signature</th><th>Stable</th><th>SHA-256</th><th>Error</th></tr></thead><tbody>");
        foreach (var record in modules.OrderBy(record => Get(record, "processName") ?? string.Empty, StringComparer.OrdinalIgnoreCase)
                     .ThenBy(record => Get(record, "modulePath") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td>").Append(Encode($"{Get(record, "processName")} ({Get(record, "processId")})"))
                .Append("</td><td>").Append(Encode(Get(record, "moduleName")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "modulePath")))
                .Append("</td><td>").Append(Encode(Get(record, "authenticodeStatus")))
                .Append("</td><td>").Append(Encode(Get(record, "identityStableDuringInspection")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "sha256")))
                .Append("</td><td>").Append(Encode(Get(record, "fileInspectionError"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderFileMetadata(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind == "file.metadata").ToArray();
        builder.Append("<details><summary>Running-process executable metadata <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(" records)</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No executable metadata records were collected.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Path</th><th>Referenced by</th><th>Signature</th><th>Stable</th><th>SHA-256</th><th>Error</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => Get(record, "executablePath") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td class=\"mono\">").Append(Encode(Get(record, "executablePath")))
                .Append("</td><td>").Append(Encode(Get(record, "processNames")))
                .Append("</td><td>").Append(Encode(Get(record, "authenticodeStatus")))
                .Append("</td><td>").Append(Encode(Get(record, "identityStableDuringInspection")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "sha256")))
                .Append("</td><td>").Append(Encode(Get(record, "fileInspectionError"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderProcesses(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind == "process.snapshot").ToArray();
        builder.Append("<details><summary>Captured processes <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(" records)</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No process records were collected.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>PID</th><th>Parent PID</th><th>Session</th><th>Created (UTC)</th><th>Name</th><th>Path</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => ParseUInt64(Get(record, "processId"))))
        {
            builder.Append("<tr><td>").Append(Encode(Get(record, "processId")))
                .Append("</td><td>").Append(Encode(Get(record, "parentProcessId")))
                .Append("</td><td>").Append(Encode(Get(record, "sessionId")))
                .Append("</td><td class=\"mono\">").Append(Encode(FormatTimestamp(record.SourceTimestampUtc)))
                .Append("</td><td>").Append(Encode(Get(record, "name")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "executablePath"))).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
    }

    private static void RenderPersistence(StringBuilder builder, CollectionRunResult result)
    {
        var records = result.Records.Where(record => record.Kind.StartsWith("persistence.", StringComparison.Ordinal)).ToArray();
        builder.Append("<details><summary>Persistence configuration <span class=\"count\">(")
            .Append(records.Length.ToString(CultureInfo.InvariantCulture)).Append(" records)</span></summary>");
        if (records.Length == 0)
        {
            builder.Append("<p class=\"empty\">No persistence records were collected.</p></details>");
            return;
        }

        builder.Append("<div class=\"scroll\"><table><thead><tr><th>Kind</th><th>Name</th><th>Display / value</th><th>State</th><th>Start mode</th><th>Image path</th><th>Source</th></tr></thead><tbody>");
        foreach (var record in records.OrderBy(record => record.Kind, StringComparer.Ordinal)
                     .ThenBy(record => Get(record, "name") ?? Get(record, "entryName") ?? string.Empty, StringComparer.OrdinalIgnoreCase))
        {
            builder.Append("<tr><td><code>").Append(Encode(record.Kind))
                .Append("</code></td><td>").Append(Encode(Get(record, "name") ?? Get(record, "entryName")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "displayName") ?? Get(record, "value")))
                .Append("</td><td>").Append(Encode(Get(record, "state")))
                .Append("</td><td>").Append(Encode(Get(record, "startMode")))
                .Append("</td><td class=\"mono\">").Append(Encode(Get(record, "imagePath")))
                .Append("</td><td class=\"mono\">").Append(Encode(record.Source)).Append("</td></tr>");
        }

        builder.Append("</tbody></table></div></details>");
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

    private static void AppendIssueList(
        StringBuilder builder,
        string label,
        IReadOnlyList<string> issues,
        string cssClass)
    {
        if (issues.Count == 0)
        {
            return;
        }

        builder.Append("<div class=\"").Append(cssClass).Append("\"><span>").Append(Encode(label))
            .Append(":</span><ul class=\"compact\">");
        foreach (var issue in issues)
        {
            builder.Append("<li>").Append(Encode(issue)).Append("</li>");
        }

        builder.Append("</ul></div>");
    }

    private static string Summarize(EvidenceRecord record) => record.Kind switch
    {
        "process.snapshot" => $"Process {Get(record, "name")} (PID {Get(record, "processId")})",
        _ => string.Join(", ", record.Fields.Take(3).Select(field => $"{field.Key}={field.Value}")),
    };

    private static string? Get(EvidenceRecord record, string key) =>
        record.Fields.TryGetValue(key, out var value) ? value : null;

    private static ulong ParseUInt64(string? value) =>
        ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var parsed) ? parsed : ulong.MaxValue;

    private static string FormatTimestamp(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss.fff 'Z'", CultureInfo.InvariantCulture);

    private static string FormatTimestamp(DateTimeOffset? value) => value.HasValue ? FormatTimestamp(value.Value) : "—";

    private static void Row(StringBuilder builder, string label, string? value) =>
        builder.Append("<tr><th>").Append(Encode(label)).Append("</th><td>").Append(Encode(value)).Append("</td></tr>");

    private static string Encode(string? value) => WebUtility.HtmlEncode(string.IsNullOrWhiteSpace(value) ? "—" : value);
}
