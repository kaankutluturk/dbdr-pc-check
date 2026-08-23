using System.Diagnostics;
using System.Text.Json;

namespace Dbdr.PcCheck.Windows;

/// <summary>
/// Runs native YARA scanning in the same signed executable as a killable helper process. This keeps
/// a malformed file or expensive custom rule from making collection cancellation unbounded.
/// </summary>
public sealed class IsolatedYaraFileScanner : IYaraFileScanner, IDisposable
{
    public static readonly TimeSpan DefaultScanTimeout = TimeSpan.FromSeconds(20);
    private static readonly TimeSpan WorkerStartupTimeout = TimeSpan.FromSeconds(30);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string? _customRulePath;
    private readonly TimeSpan _scanTimeout;
    private Process? _worker;
    private StreamWriter? _input;
    private StreamReader? _output;
    private IReadOnlyDictionary<string, string> _rulesetHashes = new Dictionary<string, string>();
    private string? _terminalInitializationError;
    private bool _disposed;

    public IsolatedYaraFileScanner(string? customRulePath = null, TimeSpan? scanTimeout = null)
    {
        _customRulePath = string.IsNullOrWhiteSpace(customRulePath)
            ? null
            : YaraFileScanner.ValidateCustomRulePath(customRulePath);
        _rulesetHashes = YaraFileScanner.CalculateRulesetHashes(_customRulePath);
        _scanTimeout = scanTimeout ?? DefaultScanTimeout;
        if (_scanTimeout <= TimeSpan.Zero || _scanTimeout > TimeSpan.FromMinutes(2))
        {
            throw new ArgumentOutOfRangeException(nameof(scanTimeout));
        }
    }

    public async Task<YaraScanEvidence> ScanAsync(string path, CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        var file = new FileInfo(path);
        file.Refresh();
        if (!file.Exists)
        {
            return Unavailable("FileNotFoundException");
        }

        if (file.Length > YaraFileScanner.MaximumScannedFileSizeBytes)
        {
            return new YaraScanEvidence(
                "skipped-size-limit",
                [],
                _rulesetHashes,
                null,
                YaraFileScanner.MaximumScannedFileSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));
        }

        if (_terminalInitializationError is not null)
        {
            return Unavailable(_terminalInitializationError);
        }

        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await EnsureWorkerAsync(cancellationToken).ConfigureAwait(false);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            timeout.CancelAfter(_scanTimeout);

            await WriteMessageAsync(new YaraWorkerMessage("scan", path), timeout.Token).ConfigureAwait(false);
            var reply = await ReadReplyAsync(timeout.Token).ConfigureAwait(false);
            if (!string.Equals(reply.Operation, "scan-result", StringComparison.Ordinal))
            {
                throw new InvalidDataException("The YARA worker returned an unexpected response.");
            }

            return reply.ToEvidence();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            TerminateWorker();
            throw;
        }
        catch (OperationCanceledException)
        {
            TerminateWorker();
            return Unavailable("Timeout");
        }
        catch (Exception exception) when (exception is IOException
            or InvalidDataException
            or JsonException
            or InvalidOperationException
            or System.Security.Cryptography.CryptographicException
            or System.ComponentModel.Win32Exception
            or ObjectDisposedException)
        {
            TerminateWorker();
            return Unavailable(exception.GetType().Name);
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        TerminateWorker();
        _gate.Dispose();
        GC.SuppressFinalize(this);
    }

    private async Task EnsureWorkerAsync(CancellationToken cancellationToken)
    {
        if (_worker is { HasExited: false } && _input is not null && _output is not null)
        {
            return;
        }

        TerminateWorker();
        var processPath = Environment.ProcessPath
            ?? throw new InvalidOperationException("The current executable path is unavailable.");
        var startInfo = new ProcessStartInfo(processPath)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
        };

        if (string.Equals(Path.GetFileNameWithoutExtension(processPath), "dotnet", StringComparison.OrdinalIgnoreCase))
        {
            var entryAssemblyPath = Environment.GetCommandLineArgs().FirstOrDefault();
            if (string.IsNullOrWhiteSpace(entryAssemblyPath))
            {
                throw new InvalidOperationException("The managed entry assembly path is unavailable.");
            }

            startInfo.ArgumentList.Add(entryAssemblyPath);
        }

        startInfo.ArgumentList.Add("--yara-worker");
        var worker = Process.Start(startInfo)
            ?? throw new InvalidOperationException("The isolated YARA worker could not be started.");
        _worker = worker;
        _input = worker.StandardInput;
        _output = worker.StandardOutput;

        using var startup = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        startup.CancelAfter(WorkerStartupTimeout);
        await WriteMessageAsync(new YaraWorkerMessage("initialize", _customRulePath), startup.Token).ConfigureAwait(false);
        var reply = await ReadReplyAsync(startup.Token).ConfigureAwait(false);
        if (!string.Equals(reply.Operation, "ready", StringComparison.Ordinal)
            || !string.Equals(reply.Status, "ready", StringComparison.Ordinal))
        {
            _terminalInitializationError = reply.Error ?? "WorkerInitializationFailed";
            throw new InvalidDataException($"YARA worker initialization failed ({_terminalInitializationError}).");
        }

        _rulesetHashes = reply.RulesetHashes ?? new Dictionary<string, string>();
    }

    private async Task WriteMessageAsync(YaraWorkerMessage message, CancellationToken cancellationToken)
    {
        var input = _input ?? throw new InvalidOperationException("The YARA worker input is unavailable.");
        var json = JsonSerializer.Serialize(message);
        await input.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
        await input.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    private async Task<YaraWorkerReply> ReadReplyAsync(CancellationToken cancellationToken)
    {
        var output = _output ?? throw new InvalidOperationException("The YARA worker output is unavailable.");
        var line = await output.ReadLineAsync(cancellationToken).ConfigureAwait(false);
        if (line is null)
        {
            throw new InvalidDataException("The YARA worker exited without a response.");
        }

        return JsonSerializer.Deserialize<YaraWorkerReply>(line)
            ?? throw new InvalidDataException("The YARA worker response was empty.");
    }

    private YaraScanEvidence Unavailable(string error) => new(
        "unavailable",
        [],
        _rulesetHashes,
        error,
        YaraFileScanner.MaximumScannedFileSizeBytes.ToString(System.Globalization.CultureInfo.InvariantCulture));

    private void TerminateWorker()
    {
        var worker = _worker;
        _worker = null;
        _input = null;
        _output = null;
        if (worker is null)
        {
            return;
        }

        try
        {
            if (!worker.HasExited)
            {
                worker.Kill(entireProcessTree: true);
                worker.WaitForExit(5000);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException
            or System.ComponentModel.Win32Exception
            or NotSupportedException)
        {
        }
        finally
        {
            worker.Dispose();
        }
    }
}

public static class YaraWorkerHost
{
    public static async Task<int> RunAsync(CancellationToken cancellationToken)
    {
        try
        {
            var initializationLine = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
            var initialization = initializationLine is null
                ? null
                : JsonSerializer.Deserialize<YaraWorkerMessage>(initializationLine);
            if (initialization is null || !string.Equals(initialization.Operation, "initialize", StringComparison.Ordinal))
            {
                await WriteReplyAsync(YaraWorkerReply.Failure("initialize-result", "InvalidInitialization"), cancellationToken)
                    .ConfigureAwait(false);
                return 2;
            }

            using var scanner = new YaraFileScanner(initialization.Path);
            await WriteReplyAsync(
                new YaraWorkerReply("ready", "ready", [], scanner.RulesetHashes, null, null, false),
                cancellationToken).ConfigureAwait(false);

            while (true)
            {
                var line = await Console.In.ReadLineAsync(cancellationToken).ConfigureAwait(false);
                if (line is null)
                {
                    return 0;
                }

                var request = JsonSerializer.Deserialize<YaraWorkerMessage>(line);
                if (request is null
                    || !string.Equals(request.Operation, "scan", StringComparison.Ordinal)
                    || string.IsNullOrWhiteSpace(request.Path))
                {
                    await WriteReplyAsync(YaraWorkerReply.Failure("scan-result", "InvalidRequest"), cancellationToken)
                        .ConfigureAwait(false);
                    continue;
                }

                var evidence = await scanner.ScanAsync(request.Path, cancellationToken).ConfigureAwait(false);
                await WriteReplyAsync(YaraWorkerReply.FromEvidence(evidence), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return 3;
        }
        catch (Exception exception) when (exception is IOException
            or InvalidDataException
            or JsonException
            or UnauthorizedAccessException
            or ArgumentException
            or InvalidOperationException
            or System.Security.Cryptography.CryptographicException
            or BadImageFormatException
            or DllNotFoundException
            or TypeInitializationException)
        {
            await WriteReplyAsync(
                YaraWorkerReply.Failure("initialize-result", exception.GetType().Name),
                CancellationToken.None).ConfigureAwait(false);
            return 2;
        }
    }

    private static async Task WriteReplyAsync(YaraWorkerReply reply, CancellationToken cancellationToken)
    {
        var json = JsonSerializer.Serialize(reply);
        await Console.Out.WriteLineAsync(json.AsMemory(), cancellationToken).ConfigureAwait(false);
        await Console.Out.FlushAsync(cancellationToken).ConfigureAwait(false);
    }
}

public sealed record YaraWorkerMessage(string Operation, string? Path);

public sealed record YaraWorkerReply(
    string Operation,
    string Status,
    IReadOnlyList<string> Matches,
    IReadOnlyDictionary<string, string>? RulesetHashes,
    string? Error,
    string? MaximumFileSizeBytes,
    bool MatchesTruncated)
{
    public static YaraWorkerReply FromEvidence(YaraScanEvidence evidence) => new(
        "scan-result",
        evidence.Status,
        evidence.Matches,
        evidence.RulesetHashes,
        evidence.Error,
        evidence.MaximumFileSizeBytes,
        evidence.MatchesTruncated);

    public static YaraWorkerReply Failure(string operation, string error) =>
        new(operation, "unavailable", [], new Dictionary<string, string>(), error, null, false);

    public YaraScanEvidence ToEvidence() => new(
        Status,
        Matches,
        RulesetHashes ?? new Dictionary<string, string>(),
        Error,
        MaximumFileSizeBytes,
        MatchesTruncated);
}
