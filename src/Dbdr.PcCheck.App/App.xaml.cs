using System.IO;
using System.Windows;
using System.Windows.Threading;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.App;

public partial class App : Application
{
    private readonly PathRedactor _redactor = new();
    private bool _selfTestMode;
    private bool _workerMode;

    protected override void OnStartup(StartupEventArgs e)
    {
        _selfTestMode = e.Args.Any(argument => string.Equals(argument, "--self-test", StringComparison.OrdinalIgnoreCase));
        _workerMode = e.Args.Any(argument => string.Equals(argument, "--yara-worker", StringComparison.OrdinalIgnoreCase));
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        try
        {
            base.OnStartup(e);

            if (_workerMode)
            {
                var exitCode = YaraWorkerHost.RunAsync(CancellationToken.None).GetAwaiter().GetResult();
                Shutdown(exitCode);
                return;
            }

            if (_selfTestMode)
            {
                var window = new MainWindow();
                window.Close();
                using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(75));
                PackagedApplicationSelfTest.RunAsync(timeout.Token).GetAwaiter().GetResult();
                Shutdown(0);
                return;
            }

            MainWindow = new MainWindow();
            MainWindow.Show();
        }
        catch (Exception exception)
        {
            HandleFatalException(exception);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        HandleFatalException(e.Exception);
        e.Handled = true;
        Shutdown(1);
    }

    private void OnUnhandledException(object? sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception exception)
        {
            WriteDiagnostic(exception);
        }
    }

    private void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        WriteDiagnostic(e.Exception);
        e.SetObserved();
    }

    private void ReportStartupFailure(Exception exception)
    {
        var diagnosticPath = WriteDiagnostic(exception);
        var suffix = diagnosticPath is null
            ? string.Empty
            : $"\n\nA redacted diagnostic was written to:\n{diagnosticPath}";

        MessageBox.Show(
            $"DBDR PC Check could not start ({exception.GetType().Name}).{suffix}",
            "Startup failed",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
    }

    private void HandleFatalException(Exception exception)
    {
        if (_selfTestMode || _workerMode)
        {
            WriteDiagnostic(exception);
            return;
        }

        ReportStartupFailure(exception);
    }

    private string? WriteDiagnostic(Exception exception)
    {
        try
        {
            var directory = Path.Combine(Path.GetTempPath(), "DBDR-PC-Check", "diagnostics");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "startup-error.log");
            var diagnostic = string.Join(
                Environment.NewLine,
                DateTimeOffset.UtcNow.ToString("O", System.Globalization.CultureInfo.InvariantCulture),
                _redactor.Redact(exception.ToString()));
            File.AppendAllText(path, diagnostic + Environment.NewLine + Environment.NewLine);
            return _redactor.Redact(path);
        }
        catch (Exception writeException) when (writeException is IOException
            or UnauthorizedAccessException
            or System.Security.SecurityException)
        {
            return null;
        }
    }
}
