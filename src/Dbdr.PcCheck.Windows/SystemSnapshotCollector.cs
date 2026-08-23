using System.Diagnostics;
using System.Globalization;
using System.Management;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Principal;
using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Microsoft.Win32;

namespace Dbdr.PcCheck.Windows;

public sealed class SystemSnapshotCollector : IEvidenceCollector
{
    public string Name => "system";

    public Task<ModuleResult> CollectAsync(
        CollectionContext context,
        IProgress<CollectionProgress>? progress,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var stopwatch = Stopwatch.StartNew();
        var warnings = new List<string>();
        progress?.Report(new CollectionProgress(Name, "Reading non-identifying system metadata"));

        string? isElevated = null;
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            isElevated = new WindowsPrincipal(identity)
                .IsInRole(WindowsBuiltInRole.Administrator)
                .ToString();
        }
        catch (Exception exception) when (exception is SecurityException or UnauthorizedAccessException)
        {
            warnings.Add($"Elevation state unavailable: {exception.GetType().Name}");
        }

        var fields = new Dictionary<string, string?>
        {
            ["operatingSystem"] = RuntimeInformation.OSDescription,
            ["osArchitecture"] = RuntimeInformation.OSArchitecture.ToString(),
            ["processArchitecture"] = RuntimeInformation.ProcessArchitecture.ToString(),
            ["framework"] = RuntimeInformation.FrameworkDescription,
            ["processorCount"] = Environment.ProcessorCount.ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["timeZoneId"] = TimeZoneInfo.Local.Id,
            ["systemUptimeSeconds"] = (Environment.TickCount64 / 1000).ToString(System.Globalization.CultureInfo.InvariantCulture),
            ["is64BitOperatingSystem"] = Environment.Is64BitOperatingSystem.ToString(),
            ["collectorIsElevated"] = isElevated,
        };
        CollectSecurityPosture(fields, warnings, cancellationToken);

        var collectedAtUtc = DateTimeOffset.UtcNow;
        var record = new EvidenceRecord(
            Name,
            "system.snapshot",
            "RuntimeInformation, Win32_DeviceGuard and Windows security configuration",
            collectedAtUtc,
            null,
            fields);

        var coverage = new EvidenceRecord(
            Name,
            "coverage.source",
            "RuntimeInformation, Windows identity and security posture",
            DateTimeOffset.UtcNow,
            null,
            new Dictionary<string, string?>
            {
                ["sourceName"] = "Non-identifying system snapshot",
                ["status"] = "available",
                ["recordCount"] = "1",
                ["detail"] = isElevated is null ? "Elevation state was unavailable." : null,
            });

        stopwatch.Stop();
        return Task.FromResult(new ModuleResult(Name, true, stopwatch.Elapsed, [record, coverage], warnings, []));
    }

    private static void CollectSecurityPosture(
        IDictionary<string, string?> fields,
        ICollection<string> warnings,
        CancellationToken cancellationToken)
    {
        ReadRegistryDword(
            fields,
            warnings,
            @"SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "UEFISecureBootEnabled",
            "secureBootEnabled");
        ReadRegistryDword(
            fields,
            warnings,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "EnableVirtualizationBasedSecurity",
            "vbsRegistryEnabled");
        ReadRegistryDword(
            fields,
            warnings,
            @"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
            "Enabled",
            "memoryIntegrityRegistryEnabled");
        ReadRegistryDword(
            fields,
            warnings,
            @"SYSTEM\CurrentControlSet\Control\CI\Config",
            "VulnerableDriverBlocklistEnable",
            "vulnerableDriverBlocklistRegistryEnabled");

        cancellationToken.ThrowIfCancellationRequested();
        try
        {
            var scope = new ManagementScope(@"\\.\root\Microsoft\Windows\DeviceGuard");
            scope.Connect();
            using var searcher = new ManagementObjectSearcher(
                scope,
                new ObjectQuery("SELECT VirtualizationBasedSecurityStatus, CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus, SecurityServicesConfigured, SecurityServicesRunning, AvailableSecurityProperties FROM Win32_DeviceGuard"));
            using var collection = searcher.Get();
            using var item = collection.Cast<ManagementObject>().FirstOrDefault();
            if (item is null)
            {
                warnings.Add("Win32_DeviceGuard returned no security posture instance.");
                return;
            }

            fields["virtualizationBasedSecurityStatus"] = FormatVbsStatus(item["VirtualizationBasedSecurityStatus"]);
            fields["kernelCodeIntegrityPolicyStatus"] = FormatPolicyStatus(item["CodeIntegrityPolicyEnforcementStatus"]);
            fields["userModeCodeIntegrityPolicyStatus"] = FormatPolicyStatus(item["UsermodeCodeIntegrityPolicyEnforcementStatus"]);
            fields["securityServicesConfigured"] = FormatSecurityServices(item["SecurityServicesConfigured"]);
            fields["securityServicesRunning"] = FormatSecurityServices(item["SecurityServicesRunning"]);
            fields["availableSecurityProperties"] = FormatNumericArray(item["AvailableSecurityProperties"]);
        }
        catch (Exception exception) when (exception is ManagementException
            or UnauthorizedAccessException
            or SecurityException
            or COMException)
        {
            warnings.Add($"Win32_DeviceGuard unavailable: {exception.GetType().Name}");
        }
    }

    private static void ReadRegistryDword(
        IDictionary<string, string?> fields,
        ICollection<string> warnings,
        string keyPath,
        string valueName,
        string fieldName)
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(keyPath, writable: false);
            fields[fieldName] = key?.GetValue(valueName) switch
            {
                int value => (value != 0).ToString().ToLowerInvariant(),
                long value => (value != 0).ToString().ToLowerInvariant(),
                _ => "not-configured",
            };
        }
        catch (Exception exception) when (exception is IOException
            or UnauthorizedAccessException
            or SecurityException)
        {
            warnings.Add($"{fieldName} unavailable: {exception.GetType().Name}");
        }
    }

    private static string? FormatVbsStatus(object? value) => ToUInt32(value) switch
    {
        0 => "disabled",
        1 => "enabled-not-running",
        2 => "enabled-running",
        _ => null,
    };

    private static string? FormatPolicyStatus(object? value) => ToUInt32(value) switch
    {
        0 => "off",
        1 => "audit",
        2 => "enforced",
        _ => null,
    };

    private static string FormatSecurityServices(object? value)
    {
        var names = ToUInt32Array(value).Select(item => item switch
        {
            1 => "credential-guard",
            2 => "memory-integrity",
            3 => "secure-launch",
            4 => "smm-firmware-measurement",
            5 => "kernel-hardware-stack-protection",
            6 => "kernel-hardware-stack-protection-audit",
            7 => "hypervisor-enforced-paging-translation",
            _ => $"unknown-{item.ToString(CultureInfo.InvariantCulture)}",
        });
        return string.Join(", ", names);
    }

    private static string FormatNumericArray(object? value) => string.Join(",", ToUInt32Array(value));

    private static uint? ToUInt32(object? value)
    {
        try
        {
            return value is null ? null : Convert.ToUInt32(value, CultureInfo.InvariantCulture);
        }
        catch (Exception exception) when (exception is FormatException or InvalidCastException or OverflowException)
        {
            return null;
        }
    }

    private static IReadOnlyList<uint> ToUInt32Array(object? value)
    {
        if (value is not Array array)
        {
            return [];
        }

        var result = new List<uint>(array.Length);
        foreach (var item in array)
        {
            var converted = ToUInt32(item);
            if (converted.HasValue)
            {
                result.Add(converted.Value);
            }
        }

        return result;
    }
}
