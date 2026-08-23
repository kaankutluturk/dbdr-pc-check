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
        CaseIdTextBox.Text = CreateCaseId(now);
        SetReviewWindow(now.AddHours(-6), now);
        RefreshModuleCatalog();
        RefreshEvidenceDashboard();
    }

    public ObservableCollection<string> Activity { get; } = [];

    public ObservableCollection<ModuleCardViewModel> VisibleModules { get; } = [];

    public ObservableCollection<string> EvidenceSearchResults { get; } = [];

    public ObservableCollection<FindingListItem> FindingItems { get; } = [];

    public string DisplayVersion { get; } = $"DEVELOPMENT  •  {Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.5.0"}";

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

        if (!ReviewWindowParser.TryParseUtcParts(
                ReviewWindowStartDateTextBox.Text,
                ReviewWindowStartTimeTextBox.Text,
                out var reviewWindowStartUtc)
            || !ReviewWindowParser.TryParseUtcParts(
                ReviewWindowEndDateTextBox.Text,
                ReviewWindowEndTimeTextBox.Text,
                out var reviewWindowEndUtc))
        {
            MessageBox.Show(
                this,
                "Enter both UTC dates as YYYY-MM-DD and times as HH:mm using the 24-hour clock.",
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

        var bundlePassphrase = BundlePassphrasePasswordBox.Password;
        if (bundlePassphrase.Length is < EvidenceBundleWriter.MinimumPassphraseCharacters
            or > EvidenceBundleWriter.MaximumPassphraseCharacters
            || string.IsNullOrWhiteSpace(bundlePassphrase))
        {
            MessageBox.Show(
                this,
                $"Enter a case passphrase containing {EvidenceBundleWriter.MinimumPassphraseCharacters}–{EvidenceBundleWriter.MaximumPassphraseCharacters} characters.",
                "Bundle passphrase required",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        if (!string.Equals(bundlePassphrase, BundlePassphraseConfirmPasswordBox.Password, StringComparison.Ordinal))
        {
            MessageBox.Show(
                this,
                "The case passphrase and confirmation do not match.",
                "Passphrases do not match",
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
            var version = GetCollectorVersion();
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
                ? new IsolatedYaraFileScanner(customYaraRules.Length == 0 ? null : customYaraRules)
                : null;
            var fileInspector = new ExecutableFileInspector(yaraScanner);
            var disabledSources = new List<string>();
            var executionSources = new List<IExecutionHistorySource>();
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
                executionSources.AddRange(
                [
                    new BamExecutionHistorySource(redactor),
                    new PrefetchExecutionHistorySource(redactor),
                    new ServiceInstallEventSource(redactor),
                    new CodeIntegrityEventSource(redactor),
                ]);
            }
            else
            {
                disabledSources.AddRange(
                [
                    "Background Activity Monitor (BAM)",
                    "Windows Prefetch",
                    "Service Control Manager installation events",
                    "Windows Code Integrity validation and block events",
                ]);
            }

            if (ExtendedForensicsCheckBox.IsChecked == true)
            {
                executionSources.AddRange(
                [
                    new AmcacheExecutionHistorySource(redactor),
                    new ApplicationCrashEventSource(redactor),
                    new PowerShellEngineEventSource(),
                    new UsnJournalExecutionHistorySource(),
                    new SrumApplicationUsageSource(redactor),
                ]);
            }
            else
            {
                disabledSources.AddRange(
                [
                    "Amcache application inventory",
                    "Application Error crash metadata",
                    "PowerShell engine and provider lifecycle",
                    "NTFS USN Journal executable changes",
                    "SRUM application usage",
                ]);
            }

            if (executionSources.Count > 0)
            {
                collectors.Add(new ExecutionHistoryCollector(executionSources));
            }

            if (PersistenceCheckBox.IsChecked == true)
            {
                collectors.Add(new PersistenceSnapshotCollector(redactor, fileInspector));
            }
            else
            {
                disabledSources.Add("Persistence inventory");
            }

            if (ScheduledTasksCheckBox.IsChecked == true)
            {
                collectors.Add(new ScheduledTaskCollector(redactor, fileInspector: fileInspector));
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
            RefreshEvidenceDashboard();

            StatusTextBlock.Text = "Packaging local evidence bundle";
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var outputDirectory = Path.Combine(desktop, "DBDR-PC-Checks");
            var bundlePath = await new EvidenceBundleWriter()
                .WriteEncryptedAsync(result, outputDirectory, bundlePassphrase, _cancellationTokenSource.Token);
            var verifiedBundle = await new EvidenceBundleReader()
                .ReadAsync(bundlePath, bundlePassphrase, _cancellationTokenSource.Token);

            _lastBundlePath = bundlePath;
            Activity.Add($"Encrypted bundle created and verified: {bundlePath}");
            var reviewCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.NeedsReview);
            var gapCount = result.Findings.Count(finding => finding.Disposition == FindingDisposition.CoverageGap);
            StatusTextBlock.Text = "Collection complete — observations, not a verdict";
            CollectionSummaryTextBlock.Text = $"{result.Records.Count} records · {reviewCount} review item(s) · {gapCount} coverage gap(s)";
            LastBundlePathTextBlock.Text = bundlePath;
            BundleVerificationTextBlock.Text = $"Current case {result.Context.CaseId} · encrypted · {verifiedBundle.Verification.VerifiedEntryCount} manifest entries verified.";
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
            BundlePassphrasePasswordBox.Clear();
            BundlePassphraseConfirmPasswordBox.Clear();
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

    private async void OpenEvidenceBundleButton_OnClick(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Open and verify DBDR evidence bundle",
            Filter = "DBDR evidence bundles (*.dbdr;*.zip)|*.dbdr;*.zip|All files (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };
        if (dialog.ShowDialog(this) != true)
        {
            return;
        }

        OpenEvidenceBundleButton.IsEnabled = false;
        BundleVerificationTextBlock.Text = "Verifying bundle structure and manifest…";
        try
        {
            var reader = new EvidenceBundleReader();
            EvidenceBundleReadResult reopened;
            try
            {
                reopened = await reader.ReadAsync(dialog.FileName, CancellationToken.None);
            }
            catch (EvidenceBundlePassphraseRequiredException)
            {
                var passphraseDialog = new BundlePassphraseDialog { Owner = this };
                if (passphraseDialog.ShowDialog() != true)
                {
                    BundleVerificationTextBlock.Text = "Encrypted bundle opening was cancelled.";
                    return;
                }

                reopened = await reader.ReadAsync(dialog.FileName, passphraseDialog.Passphrase, CancellationToken.None);
            }

            _lastResult = reopened.Result;
            _lastBundlePath = dialog.FileName;
            RefreshEvidenceDashboard();
            ExplorerNavButton.IsChecked = true;
            OpenLastBundleButton.IsEnabled = true;
            LastBundlePathTextBlock.Text = dialog.FileName;
            var reviewCount = reopened.Result.Findings.Count(finding => finding.Disposition == FindingDisposition.NeedsReview);
            var gapCount = reopened.Result.Findings.Count(finding => finding.Disposition == FindingDisposition.CoverageGap);
            CollectionSummaryTextBlock.Text = $"{reopened.Result.Records.Count} records · {reviewCount} review item(s) · {gapCount} coverage gap(s)";
            var protection = reopened.Verification.Encrypted ? "encrypted" : "legacy plaintext";
            BundleVerificationTextBlock.Text = $"Case {reopened.Result.Context.CaseId} · {protection} · {reopened.Verification.VerifiedEntryCount} manifest entries verified.";
            Activity.Add($"Verified and reopened {protection} evidence bundle for case {reopened.Result.Context.CaseId}.");
        }
        catch (Exception exception) when (exception is InvalidDataException
            or IOException
            or UnauthorizedAccessException
            or System.Security.Cryptography.CryptographicException)
        {
            BundleVerificationTextBlock.Text = "Bundle verification failed. No evidence was loaded.";
            MessageBox.Show(
                this,
                $"The evidence bundle could not be verified ({exception.GetType().Name}): {exception.Message}",
                "Bundle verification failed",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
        }
        finally
        {
            OpenEvidenceBundleButton.IsEnabled = true;
        }
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

    private void CaseIdRefreshButton_OnClick(object sender, RoutedEventArgs e) =>
        CaseIdTextBox.Text = CreateCaseId(DateTimeOffset.UtcNow);

    private void ReviewWindowPresetButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: string hoursText }
            || !double.TryParse(hoursText, NumberStyles.Number, CultureInfo.InvariantCulture, out var hours))
        {
            return;
        }

        var endUtc = DateTimeOffset.UtcNow;
        SetReviewWindow(endUtc.AddHours(-hours), endUtc);
    }

    private void ReviewBoundaryButton_OnClick(object sender, RoutedEventArgs e) =>
        PrivacyNavButton.IsChecked = true;

    private void ModuleSearchTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        RefreshModuleCatalog();

    private void ModuleCatalogFilter_OnChanged(object sender, RoutedEventArgs e) =>
        RefreshModuleCatalog();

    private void EvidenceSearchTextBox_OnTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) =>
        RefreshEvidenceSearch();

    private void FindingListBox_OnSelectionChanged(
        object sender,
        System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (FindingListBox.SelectedItem is not FindingListItem finding)
        {
            SetEmptyFindingDetail();
            return;
        }

        FindingDetailDispositionTextBlock.Text = $"{finding.Id}  ·  {finding.DispositionLabel}";
        FindingDetailTitleTextBlock.Text = finding.Title;
        FindingDetailContextTextBlock.Text = finding.ContextLabel;
        FindingDetailTextBlock.Text = finding.Detail;
        ScopeFindingButton.IsEnabled = true;
    }

    private void ScopeFindingButton_OnClick(object sender, RoutedEventArgs e)
    {
        if (FindingListBox.SelectedItem is not FindingListItem finding)
        {
            return;
        }

        EvidenceModuleScopeTextBox.Text = finding.RecordKind ?? finding.Module;
        EvidenceSearchTextBox.Focus();
    }

    private void ClearEvidenceFiltersButton_OnClick(object sender, RoutedEventArgs e)
    {
        EvidenceSearchTextBox.Clear();
        EvidenceModuleScopeTextBox.Clear();
    }

    private void RefreshModuleCatalog()
    {
        var query = ModuleSearchTextBox?.Text;
        var definitions = EvidenceModuleCatalog.Search(query);
        if (ShowUnavailableModulesCheckBox?.IsChecked != true)
        {
            definitions = definitions
                .Where(module => module.Availability is ModuleAvailability.Available or ModuleAvailability.Preview)
                .ToArray();
        }

        VisibleModules.Clear();
        foreach (var module in definitions)
        {
            VisibleModules.Add(ModuleCardViewModel.From(module));
        }

        if (ModuleCatalogSummaryTextBlock is not null)
        {
            ModuleCatalogSummaryTextBlock.Text = $"{VisibleModules.Count.ToString(CultureInfo.InvariantCulture)} shown";
        }
    }

    private void RefreshEvidenceSearch()
    {
        EvidenceSearchResults.Clear();
        if (_lastResult is null)
        {
            EvidenceSearchResults.Add("Run an authorized collection to search its normalized evidence.");
            if (EvidenceResultSummaryTextBlock is not null)
            {
                EvidenceResultSummaryTextBlock.Text = "NO CASE LOADED";
            }

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

        if (EvidenceResultSummaryTextBlock is not null)
        {
            EvidenceResultSummaryTextBlock.Text = records.Count > 500
                ? $"500 OF {records.Count.ToString(CultureInfo.InvariantCulture)} SHOWN"
                : $"{records.Count.ToString(CultureInfo.InvariantCulture)} MATCHES";
        }
    }

    private void RefreshEvidenceDashboard()
    {
        FindingItems.Clear();
        if (_lastResult is null)
        {
            RecordsMetricTextBlock.Text = "—";
            ReviewMetricTextBlock.Text = "—";
            CoverageGapMetricTextBlock.Text = "—";
            ModuleCoverageMetricTextBlock.Text = "—";
            SourceCoverageMetricTextBlock.Text = "—";
            ModuleCoverageDetailTextBlock.Text = "No case loaded";
            SourceCoverageDetailTextBlock.Text = "No case loaded";
            SetEmptyFindingDetail();
            RefreshEvidenceSearch();
            return;
        }

        var summary = EvidenceCoverageSummary.Create(_lastResult);
        RecordsMetricTextBlock.Text = summary.RecordCount.ToString("N0", CultureInfo.InvariantCulture);
        ReviewMetricTextBlock.Text = summary.ReviewFindingCount.ToString("N0", CultureInfo.InvariantCulture);
        CoverageGapMetricTextBlock.Text = summary.CoverageGapCount.ToString("N0", CultureInfo.InvariantCulture);
        ModuleCoverageMetricTextBlock.Text = $"{summary.CompletedModuleCount.ToString(CultureInfo.InvariantCulture)}/{summary.ModuleCount.ToString(CultureInfo.InvariantCulture)}";
        SourceCoverageMetricTextBlock.Text = $"{summary.AvailableSourceCount.ToString(CultureInfo.InvariantCulture)}/{summary.SourceCount.ToString(CultureInfo.InvariantCulture)}";
        ModuleCoverageDetailTextBlock.Text = summary.CompletedModuleCount == summary.ModuleCount
            ? "All modules completed"
            : $"{(summary.ModuleCount - summary.CompletedModuleCount).ToString(CultureInfo.InvariantCulture)} incomplete";
        SourceCoverageDetailTextBlock.Text = $"{summary.LimitedSourceCount.ToString(CultureInfo.InvariantCulture)} limited · {summary.UnavailableSourceCount.ToString(CultureInfo.InvariantCulture)} unavailable";

        foreach (var finding in _lastResult.Findings
                     .OrderBy(finding => FindingOrder(finding.Disposition))
                     .ThenBy(finding => finding.Id, StringComparer.Ordinal))
        {
            FindingItems.Add(new FindingListItem(
                finding.Id,
                finding.Disposition,
                finding.Title,
                finding.Detail,
                finding.Module,
                finding.RecordKind));
        }

        if (FindingItems.Count > 0)
        {
            FindingListBox.SelectedIndex = 0;
        }
        else
        {
            SetEmptyFindingDetail();
        }

        RefreshEvidenceSearch();
    }

    private void SetEmptyFindingDetail()
    {
        FindingDetailDispositionTextBlock.Text = "NO FINDING SELECTED";
        FindingDetailTitleTextBlock.Text = FindingItems.Count == 0
            ? "No automated findings"
            : "Select a finding";
        FindingDetailContextTextBlock.Text = string.Empty;
        FindingDetailTextBlock.Text = FindingItems.Count == 0
            ? "This is not a clean verdict. Review source coverage and the normalized evidence before reaching any conclusion."
            : "Choose a finding to review its full neutral rationale and scope matching records.";
        ScopeFindingButton.IsEnabled = false;
    }

    private static int FindingOrder(FindingDisposition disposition) => disposition switch
    {
        FindingDisposition.NeedsReview => 0,
        FindingDisposition.CoverageGap => 1,
        _ => 2,
    };

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
        CaseIdRefreshButton.IsEnabled = !isRunning;
        ReviewWindowStartDateTextBox.IsEnabled = !isRunning;
        ReviewWindowStartTimeTextBox.IsEnabled = !isRunning;
        ReviewWindowEndDateTextBox.IsEnabled = !isRunning;
        ReviewWindowEndTimeTextBox.IsEnabled = !isRunning;
        LastHourButton.IsEnabled = !isRunning;
        LastSixHoursButton.IsEnabled = !isRunning;
        LastDayButton.IsEnabled = !isRunning;
        ConsentCheckBox.IsEnabled = !isRunning;
        ExecutionHistoryCheckBox.IsEnabled = !isRunning;
        FileEnrichmentCheckBox.IsEnabled = !isRunning;
        PersistenceCheckBox.IsEnabled = !isRunning;
        ScheduledTasksCheckBox.IsEnabled = !isRunning;
        DeviceInventoryCheckBox.IsEnabled = !isRunning;
        ExtendedForensicsCheckBox.IsEnabled = !isRunning;
        YaraScanCheckBox.IsEnabled = !isRunning;
        YaraRulesPathTextBox.IsEnabled = !isRunning;
        YaraRulesBrowseButton.IsEnabled = !isRunning;
        AdvancedTriageExpander.IsEnabled = !isRunning;
        BundlePassphrasePasswordBox.IsEnabled = !isRunning;
        BundlePassphraseConfirmPasswordBox.IsEnabled = !isRunning;
        OpenEvidenceBundleButton.IsEnabled = !isRunning;
    }

    private void SetReviewWindow(DateTimeOffset startUtc, DateTimeOffset endUtc)
    {
        ReviewWindowStartDateTextBox.Text = FormatUtcDate(startUtc);
        ReviewWindowStartTimeTextBox.Text = FormatUtcTime(startUtc);
        ReviewWindowEndDateTextBox.Text = FormatUtcDate(endUtc);
        ReviewWindowEndTimeTextBox.Text = FormatUtcTime(endUtc);
    }

    private static string CreateCaseId(DateTimeOffset value) =>
        $"DBDR-{value.ToUniversalTime():yyyyMMdd-HHmm}-{Guid.NewGuid():N}"[..24].ToUpperInvariant();

    private static string FormatUtcDate(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);

    private static string FormatUtcTime(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("HH:mm", CultureInfo.InvariantCulture);

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);

    private static string GetCollectorVersion() =>
        Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion ?? "0.5.0-development";

    [DllImport("dwmapi.dll", PreserveSig = true)]
    private static extern int DwmSetWindowAttribute(
        IntPtr windowHandle,
        int attribute,
        ref int attributeValue,
        int attributeSize);
}
