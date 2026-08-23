using System.IO;
using System.Windows;
using System.Windows.Threading;
using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.App;

public partial class App : Application
{
    private readonly PathRedactor _redactor = new();

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;

        try
        {
            base.OnStartup(e);

            if (e.Args.Any(argument => string.Equals(argument, "--self-test", StringComparison.OrdinalIgnoreCase)))
            {
                var window = new MainWindow();
                window.Close();
                Shutdown(0);
                return;
            }

            MainWindow = new MainWindow();
            MainWindow.Show();
        }
        catch (Exception exception)
        {
            ReportStartupFailure(exception);
            Shutdown(1);
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        ReportStartupFailure(e.Exception);
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
