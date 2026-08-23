using Dbdr.PcCheck.Validation;

if (args.Length > 2)
{
    Console.Error.WriteLine("Usage: Dbdr.PcCheck.Validation [fixture-directory] [output-directory]");
    return 64;
}

var fixtureDirectory = Path.GetFullPath(args.Length >= 1 ? args[0] : "validation/fixtures");
var outputDirectory = Path.GetFullPath(args.Length == 2 ? args[1] : "artifacts/detection-validation");
try
{
    var report = await DetectionValidationRunner.RunAsync(fixtureDirectory, CancellationToken.None);
    await DetectionValidationRunner.WriteReportAsync(report, outputDirectory, CancellationToken.None);
    Console.WriteLine(
        $"Detection validation {(report.Passed ? "passed" : "failed")}: "
        + $"{report.PassedFixtureCount}/{report.FixtureCount} fixtures, "
        + $"precision={report.Precision:F4}, recall={report.Recall:F4}, F1={report.F1Score:F4}.");
    Console.WriteLine($"Reports: {outputDirectory}");
    return report.Passed ? 0 : 2;
}
catch (Exception exception) when (exception is IOException
    or UnauthorizedAccessException
    or InvalidOperationException)
{
    Console.Error.WriteLine($"Detection validation could not run ({exception.GetType().Name}): {exception.Message}");
    return 1;
}
