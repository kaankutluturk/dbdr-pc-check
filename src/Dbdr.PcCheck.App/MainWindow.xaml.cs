using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Packaging;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.App;

public partial class MainWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private CancellationTokenSource? _cancellationTokenSource;
    private string? _lastBundlePath;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        var now = DateTimeOffset.UtcNow;
        ReviewWindowStartTextBox.Text = FormatUtc(now.AddHours(-2));
        ReviewWindowEndTextBox.Text = FormatUtc(now);
    }

    public ObservableCollection<string> Activity { get; } = [];

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);

        var darkMode = 1;
        var handle = new WindowInteropHelper(this).Handle;
        _ = DwmSetWindowAttribute(handle, DwmwaUseImmersiveDarkMode, ref darkMode, sizeof(int));
    }

    private async void StartButton_OnClick(object sender, RoutedEventArgs e)
    {
        var caseId = CaseIdTextBox.Text.Trim();
        if (!CaseIdValidator.IsValid(caseId))
        {
            MessageBox.Show(
                this,
                "Enter a case ID containing only letters, numbers, hyphens or underscores (maximum 64 characters).",
                "Invalid case ID",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (ConsentCheckBox.IsChecked != true)
        {
            MessageBox.Show(
                this,
                "Read the collection boundary and explicitly authorize the collection before continuing.",
                "Authorization required",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (!ReviewWindowParser.TryParseUtc(ReviewWindowStartTextBox.Text, out var reviewWindowStartUtc)
            || !ReviewWindowParser.TryParseUtc(ReviewWindowEndTextBox.Text, out var reviewWindowEndUtc))
        {
            MessageBox.Show(
                this,
                "Enter both review timestamps in ISO 8601 format with Z or an explicit UTC offset.",
                "Invalid review window",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (!ReviewWindowParser.IsOrdered(reviewWindowStartUtc, reviewWindowEndUtc))
        {
            MessageBox.Show(
                this,
                "The review-window start must be earlier than its end.",
                "Invalid review window",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        SetRunningState(true);
        Activity.Clear();
        ActivityNavButton.IsChecked = true;
        _cancellationTokenSource = new CancellationTokenSource();

        try
        {
            var collectionStartedUtc = DateTimeOffset.UtcNow;
            var version = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion ?? "0.2.0-development";
            var context = new CollectionContext(
                caseId,
                reviewWindowStartUtc,
                reviewWindowEndUtc,
                collectionStartedUtc,
                version);
            var redactor = new PathRedactor();
            var processSnapshotProvider = new LiveProcessSnapshotProvider();
            var gameModuleEnumerator = new GameModuleEnumerator();
            var fileInspector = new ExecutableFileInspector();
            var disabledSources = new List<string>();
            var collectors = new List<IEvidenceCollector>
            {
                new ProcessSnapshotCollector(processSnapshotProvider, redactor),
                new GameModuleSnapshotCollector(processSnapshotProvider, gameModuleEnumerator, fileInspector, redactor),
                new SystemSnapshotCollector(),
            };

            if (FileEnrichmentCheckBox.IsChecked == true)
            {
                collectors.Add(new ProcessFileMetadataCollector(processSnapshotProvider, fileInspector, redactor));
            }
            else
            {
                disabledSources.Add("Process executable enrichment");
            }

            if (ExecutionHistoryCheckBox.IsChecked == true)
            {
                collectors.Add(new ExecutionHistoryCollector(
                [
                    new BamExecutionHistorySource(redactor),
                    new PrefetchExecutionHistorySource(redactor),
                    new ServiceInstallEventSource(redactor),
                    new CodeIntegrityEventSource(),
                ]));
            }
            else
            {
                disabledSources.AddRange(
                [
                    "Background Activity Monitor (BAM)",
                    "Windows Prefetch",
                    "Service Control Manager installation events",
                    "Windows Code Integrity warnings and errors",
                ]);
            }

            if (PersistenceCheckBox.IsChecked == true)
            {
                collectors.Add(new PersistenceSnapshotCollector(redactor));
            }
            else
            {
                disabledSources.Add("Persistence inventory");
            }

            if (ScheduledTasksCheckBox.IsChecked == true)
            {
                collectors.Add(new ScheduledTaskCollector(redactor));
            }
            else
            {
                disabledSources.Add("Windows scheduled task definitions");
            }

            if (DeviceInventoryCheckBox.IsChecked == true)
            {
                collectors.Add(new DeviceSnapshotCollector(new DeviceSnapshotProvider()));
            }
            else
            {
                disabledSources.Add("Plug and Play device inventory");
            }

            if (disabledSources.Count > 0)
            {
                collectors.Add(new DisabledSourceCollector(disabledSources));
            }

            var progress = new Progress<CollectionProgress>(UpdateProgress);
            var collectedResult = await new CollectionOrchestrator(collectors)
                .RunAsync(context, progress, _cancellationTokenSource.Token);
            var result = collectedResult with
            {
                Findings = EvidenceAnalyzer.Analyze(collectedResult),
            };

            StatusTextBlock.Text = "Packaging local evidence bundle";
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var outputDirectory = Path.Combine(desktop, "DBDR-PC-Checks");
            var bundlePath = await new EvidenceBundleWriter()
                .WriteAsync(result, outputDirectory, _cancellationTokenSource.Token);

            _lastBundlePath = bundlePath;
            Activity.Add($"Bundle created: {bundlePath}");
            var reviewCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.NeedsReview);
            var gapCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.CoverageGap);
            StatusTextBlock.Text = "Collection complete — observations, not a verdict";
            CollectionSummaryTextBlock.Text = $"{result.Records.Count} records · {reviewCount} review item(s) · {gapCount} coverage gap(s)";
            LastBundlePathTextBlock.Text = bundlePath;
            OpenLastBundleButton.IsEnabled = true;

            var answer = MessageBox.Show(
                this,
                $"The local evidence bundle was created successfully.\n\n{bundlePath}\n\nOpen its folder now?",
                "Collection complete",
                MessageBoxButton.YesNo,
                MessageBoxImage.Information);

            if (answer == MessageBoxResult.Yes)
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{bundlePath}\"")
                {
                    UseShellExecute = true,
                });
            }
        }
        catch (OperationCanceledException)
        {
            StatusTextBlock.Text = "Collection cancelled";
            CollectionSummaryTextBlock.Text = "No bundle was created for the cancelled run.";
            Activity.Add("Collection was cancelled. No bundle was created.");
        }
        catch (Exception exception)
        {
            StatusTextBlock.Text = "Collection failed";
            CollectionSummaryTextBlock.Text = "Review the final activity entry for the failure type.";
            Activity.Add($"{exception.GetType().Name}: {exception.Message}");
            MessageBox.Show(this, exception.Message, "Collection failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            _cancellationTokenSource?.Dispose();
            _cancellationTokenSource = null;
            SetRunningState(false);
        }
    }

    private void CancelButton_OnClick(object sender, RoutedEventArgs e) => _cancellationTokenSource?.Cancel();

    private void OpenLastBundleButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_lastBundlePath) || !File.Exists(_lastBundlePath))
        {
            return;
        }

        Process.Start(new ProcessStartInfo("explorer.exe", $"/select,\"{_lastBundlePath}\"")
        {
            UseShellExecute = true,
        });
    }

    private void UpdateProgress(CollectionProgress progress)
    {
        var count = progress.Current.HasValue && progress.Total.HasValue
            ? $" ({progress.Current}/{progress.Total})"
            : string.Empty;
        var line = $"[{progress.Module}] {progress.Message}{count}";
        StatusTextBlock.Text = line;
        Activity.Add(line);
        if (Activity.Count > 250)
        {
            Activity.RemoveAt(0);
        }

        ActivityListBox.ScrollIntoView(Activity.LastOrDefault());
    }

    private void SetRunningState(bool isRunning)
    {
        StartButton.IsEnabled = !isRunning;
        CancelButton.IsEnabled = isRunning;
        ActivityCancelButton.IsEnabled = isRunning;
        CollectionProgressBar.IsIndeterminate = isRunning;
        CaseIdTextBox.IsEnabled = !isRunning;
        ReviewWindowStartTextBox.IsEnabled = !isRunning;
        ReviewWindowEndTextBox.IsEnabled = !isRunning;
        ConsentCheckBox.IsEnabled = !isRunning;
        ExecutionHistoryCheckBox.IsEnabled = !isRunning;
        FileEnrichmentCheckBox.IsEnabled = !isRunning;
        PersistenceCheckBox.IsEnabled = !isRunning;
        ScheduledTasksCheckBox.IsEnabled = !isRunning;
        DeviceInventoryCheckBox.IsEnabled = !isRunning;
    }

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr windowHandle,
        int attribute,
        ref int attributeValue,
        int attributeSize);
}
