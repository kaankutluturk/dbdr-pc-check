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
using Microsoft.Win32;

namespace Dbdr.PcCheck.App;

public partial class MainWindow : Window
{
    private const int DwmwaUseImmersiveDarkMode = 20;
    private CancellationTokenSource? _cancellationTokenSource;
    private string? _lastBundlePath;
    private CollectionRunResult? _lastResult;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;

        var now = DateTimeOffset.UtcNow;
        ReviewWindowStartTextBox.Text = FormatUtc(now.AddHours(-2));
        ReviewWindowEndTextBox.Text = FormatUtc(now);
        RefreshModuleCatalog();
        RefreshEvidenceSearch();
    }

    public ObservableCollection<string> Activity { get; } = [];

    public ObservableCollection<ModuleCardViewModel> VisibleModules { get; } = [];

    public ObservableCollection<string> EvidenceSearchResults { get; } = [];

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

        var customYaraRules = YaraRulesPathTextBox.Text.Trim();
        if (YaraScanCheckBox.IsChecked == true
            && customYaraRules.Length > 0
            && !File.Exists(customYaraRules))
        {
            MessageBox.Show(
                this,
                "The selected custom YARA rule file does not exist.",
                "Invalid YARA rules",
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
                .InformationalVersion ?? "0.3.0-development";
            var context = new CollectionContext(
                caseId,
                reviewWindowStartUtc,
                reviewWindowEndUtc,
                collectionStartedUtc,
                version);
            var redactor = new PathRedactor();
            var processSnapshotProvider = new LiveProcessSnapshotProvider();
            var gameModuleEnumerator = new GameModuleEnumerator();
            using var yaraScanner = YaraScanCheckBox.IsChecked == true
                ? new YaraFileScanner(customYaraRules.Length == 0 ? null : customYaraRules)
                : null;
            var fileInspector = new ExecutableFileInspector(yaraScanner);
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
            _lastResult = result;
            RefreshEvidenceSearch();

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

    private void YaraRulesBrowseButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select optional custom YARA rules",
            Filter = "YARA rules (*.yar;*.yara)|*.yar;*.yara|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) == true)
        {
            YaraRulesPathTextBox.Text = dialog.FileName;
        }
    }

    private void ModuleSearchTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        RefreshModuleCatalog();

    private void EvidenceSearchTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        RefreshEvidenceSearch();

    private void RefreshModuleCatalog()
    {
        var query = ModuleSearchTextBox?.Text;
        VisibleModules.Clear();
        foreach (var module in EvidenceModuleCatalog.Search(query))
        {
            VisibleModules.Add(ModuleCardViewModel.From(module));
        }
    }

    private void RefreshEvidenceSearch()
    {
        EvidenceSearchResults.Clear();
        if (_lastResult is null)
        {
            EvidenceSearchResults.Add("Run an authorized collection to search its normalized evidence.");
            return;
        }

        var records = EvidenceSearchEngine.Search(
            _lastResult.Records,
            EvidenceSearchTextBox?.Text,
            EvidenceModuleScopeTextBox?.Text);
        foreach (var record in records.Take(500))
        {
            EvidenceSearchResults.Add(FormatEvidenceRecord(record));
        }

        if (records.Count == 0)
        {
            EvidenceSearchResults.Add("No normalized evidence records match this query and module scope.");
        }
        else if (records.Count > 500)
        {
            EvidenceSearchResults.Add($"Showing 500 of {records.Count.ToString(CultureInfo.InvariantCulture)} matches. Refine the search to narrow the result set.");
        }
    }

    private static string FormatEvidenceRecord(EvidenceRecord record)
    {
        var timestamp = record.SourceTimestampUtc ?? record.CollectedAtUtc;
        var fields = string.Join(
            "  ·  ",
            record.Fields
                .Where(field => !string.IsNullOrWhiteSpace(field.Value))
                .Take(4)
                .Select(field => $"{field.Key}={field.Value}"));
        return $"{FormatUtc(timestamp)}  [{record.Module}/{record.Kind}]  {fields}";
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
        YaraScanCheckBox.IsEnabled = !isRunning;
        YaraRulesPathTextBox.IsEnabled = !isRunning;
        YaraRulesBrowseButton.IsEnabled = !isRunning;
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
