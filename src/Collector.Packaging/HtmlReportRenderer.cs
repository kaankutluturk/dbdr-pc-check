using System.Net;
using System.Text;
using Dbdr.PcCheck.Collector.Core.Models;

namespace Dbdr.PcCheck.Collector.Packaging;

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
                body{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#18202a;background:#f6f8fb}
                h1{margin-bottom:4px}.notice{padding:14px 16px;background:#fff4d6;border-left:4px solid #d79b00;margin:22px 0}
                table{width:100%;border-collapse:collapse;background:white;margin:18px 0}th,td{text-align:left;padding:10px;border-bottom:1px solid #e2e7ee}
                th{background:#edf2f7}.ok{color:#1d6b3b}.warn{color:#905d00}.muted{color:#5c6875}code{word-break:break-all}
              </style>
            </head>
            <body>
            """);

        builder.Append("<h1>DBDR PC Check Report</h1>");
        builder.Append("<div class=\"muted\">Development collector v");
        builder.Append(Encode(result.Context.CollectorVersion));
        builder.Append("</div>");
        builder.Append("<div class=\"notice\"><strong>Not a verdict.</strong> This report contains observations and collection failures. No flagged evidence does not mean the machine is clean.</div>");
        builder.Append("<h2>Case</h2><table><tbody>");
        Row(builder, "Case ID", result.Context.CaseId);
        Row(builder, "Review window", $"{result.Context.ReviewWindowStartUtc:O} — {result.Context.ReviewWindowEndUtc:O}");
        Row(builder, "Collection started", result.Context.CollectionStartedUtc.ToString("O"));
        Row(builder, "Collection completed", result.CompletedUtc.ToString("O"));
        builder.Append("</tbody></table>");

        builder.Append("<h2>Modules</h2><table><thead><tr><th>Module</th><th>Status</th><th>Records</th><th>Warnings</th><th>Errors</th><th>Duration</th></tr></thead><tbody>");
        foreach (var module in result.Modules)
        {
            builder.Append("<tr><td>").Append(Encode(module.Module)).Append("</td><td class=\"");
            builder.Append(module.Completed ? "ok\">completed" : "warn\">incomplete");
            builder.Append("</td><td>").Append(module.Records.Count).Append("</td><td>").Append(module.Warnings.Count);
            builder.Append("</td><td>").Append(module.Errors.Count).Append("</td><td>").Append(module.Duration.TotalSeconds.ToString("F2", System.Globalization.CultureInfo.InvariantCulture)).Append(" s</td></tr>");
        }
        builder.Append("</tbody></table>");

        builder.Append("<h2>Record counts</h2><table><thead><tr><th>Kind</th><th>Count</th></tr></thead><tbody>");
        foreach (var group in result.Records.GroupBy(record => record.Kind).OrderBy(group => group.Key, StringComparer.Ordinal))
        {
            builder.Append("<tr><td><code>").Append(Encode(group.Key)).Append("</code></td><td>").Append(group.Count()).Append("</td></tr>");
        }
        builder.Append("</tbody></table><p class=\"muted\">Inspect evidence.json for normalized record details and collection-log.json for failures.</p></body></html>");
        return builder.ToString();
    }

    private static void Row(StringBuilder builder, string label, string value) =>
        builder.Append("<tr><th>").Append(Encode(label)).Append("</th><td>").Append(Encode(value)).Append("</td></tr>");

    private static string Encode(string value) => WebUtility.HtmlEncode(value);
}
