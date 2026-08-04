using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Reflection;
using System.Windows;
using Dbdr.PcCheck.Collector.Core;
using Dbdr.PcCheck.Collector.Core.Models;
using Dbdr.PcCheck.Collector.Packaging;
using Dbdr.PcCheck.Collector.Windows;

namespace Dbdr.PcCheck.Collector.App;

public partial class MainWindow : Window
{
    private CancellationTokenSource? _cancellationTokenSource;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = this;
    }

    public ObservableCollection<string> Activity { get; } = [];

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

        SetRunningState(true);
        Activity.Clear();
        _cancellationTokenSource = new CancellationTokenSource();

        try
        {
            var now = DateTimeOffset.UtcNow;
            var version = Assembly.GetExecutingAssembly()
                .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
                .InformationalVersion ?? "0.1.0-development";
            var context = new CollectionContext(caseId, now.AddHours(-2), now, now, version);
            var redactor = new PathRedactor();
            var collectors = new IEvidenceCollector[]
            {
                new SystemSnapshotCollector(),
                new ProcessSnapshotCollector(redactor),
                new PersistenceSnapshotCollector(redactor),
            };

            var progress = new Progress<CollectionProgress>(UpdateProgress);
            var result = await new CollectionOrchestrator(collectors)
                .RunAsync(context, progress, _cancellationTokenSource.Token);

            StatusTextBlock.Text = "Packaging local evidence bundle";
            var desktop = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
            var outputDirectory = Path.Combine(desktop, "DBDR-PC-Checks");
            var bundlePath = await new EvidenceBundleWriter()
                .WriteAsync(result, outputDirectory, _cancellationTokenSource.Token);

            Activity.Add($"Bundle created: {bundlePath}");
            StatusTextBlock.Text = "Collection complete — not a moderation verdict";

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
            Activity.Add("Collection was cancelled. No bundle was created.");
        }
        catch (Exception exception)
        {
            StatusTextBlock.Text = "Collection failed";
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
        CaseIdTextBox.IsEnabled = !isRunning;
        ConsentCheckBox.IsEnabled = !isRunning;
    }
}
