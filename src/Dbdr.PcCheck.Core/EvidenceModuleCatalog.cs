namespace Dbdr.PcCheck.Core;

public enum ModuleAvailability
{
    Available,
    Preview,
    Planned,
    PrivacyRestricted,
}

public sealed record EvidenceModuleDefinition(
    string Id,
    string DisplayName,
    string Category,
    ModuleAvailability Availability,
    string Description,
    string Boundary,
    bool RequiresAdministrator,
    IReadOnlyList<string> SearchTerms);

public static class EvidenceModuleCatalog
{
    public static IReadOnlyList<EvidenceModuleDefinition> All { get; } =
    [
        New("winprefetch", "WinPrefetch View", "Execution", ModuleAvailability.Preview,
            "Prefetch observations inside the case window.",
            "Current adapter exposes file metadata; parsed run timestamps are the next source upgrade.",
            true, "prefetch", "execution.prefetch"),
        New("autoruns", "Autoruns", "Persistence", ModuleAvailability.Available,
            "Run keys, services, drivers and scheduled task launch points.",
            "Read-only current-state inventory; startup location alone is never proof.",
            true, "persistence", "scheduled task", "run key", "driver"),
        New("string-explorer", "String Explorer", "Binary triage", ModuleAvailability.Preview,
            "Searchable binary triage for files already referenced by collected evidence.",
            "No arbitrary disk crawl and no process-memory strings.",
            false, "file.metadata", "process.module", "strings", "entropy", "yara"),
        New("usbdeview", "USBDeview", "Devices", ModuleAvailability.Preview,
            "Privacy-minimized Plug and Play device context.",
            "Unique device serials and instance identifiers remain excluded.",
            true, "device.snapshot", "usb", "pnp"),
        New("saved-files", "Saved Files Viewer", "File activity", ModuleAvailability.PrivacyRestricted,
            "Recent-file and save-location artifacts.",
            "Blocked by the current privacy contract because personal filenames and paths are not collected.",
            false, "recent files", "saved files"),
        New("powershell", "PowerShell Parser", "Execution", ModuleAvailability.Preview,
            "Time-bounded PowerShell engine and provider lifecycle metadata.",
            "Event payloads, commands, scripts, script blocks, users and terminal history are excluded.",
            true, "powershell", "event log", "event.powershell_engine"),
        New("paths", "Paths Parser", "File activity", ModuleAvailability.Planned,
            "Correlates execution and file-system paths across normalized evidence.",
            "Only redacted paths from approved sources are indexed.",
            false, "path", "lnk", "jumplist"),
        New("mft", "MFT Explorer", "File system", ModuleAvailability.Planned,
            "Time-bounded NTFS Master File Table parsing and search.",
            "Requires an administrator-approved, read-only raw-volume adapter and strict path redaction.",
            true, "$mft", "ntfs", "file system"),
        New("kernel-live-dump", "Kernel Live Dump", "Memory", ModuleAvailability.PrivacyRestricted,
            "Kernel memory capture and analysis.",
            "Excluded: live dumps can contain user-mode pages and conflict with the no-memory collection boundary.",
            true, "kernel", "memory", "dump"),
        New("journal-trace", "Journal Trace", "File system", ModuleAvailability.Planned,
            "Time-bounded NTFS USN journal activity.",
            "No journal deletion checks are interpreted without corroborating source coverage.",
            true, "$j", "usn", "journal"),
        New("crashed-files", "Crashed File Viewer", "Reliability", ModuleAvailability.Preview,
            "Time-bounded Application Error crash metadata and redacted executable identity.",
            "Event messages, report IDs, crash dumps and memory-derived content are excluded.",
            true, "wer", "crash", "reliability", "event.application_crash"),
        New("browser-history", "Browsing History View", "Browser", ModuleAvailability.PrivacyRestricted,
            "Browser navigation history.",
            "Excluded by the current privacy contract.",
            false, "browser", "history"),
        New("browser-downloads", "Browser Downloads View", "Browser", ModuleAvailability.PrivacyRestricted,
            "Browser download records.",
            "Excluded by the current privacy contract.",
            false, "browser", "downloads"),
        New("bam", "BAM Parser", "Execution", ModuleAvailability.Available,
            "Time-bounded Background Activity Moderator execution records.",
            "SID identities are excluded and missing BAM coverage is reported explicitly.",
            true, "execution.bam", "bam"),
        New("amcache", "Amcache Parser", "Execution", ModuleAvailability.Preview,
            "Capped live Amcache inventory for executable application files.",
            "Current inventory is not execution proof; paths are redacted and unrelated file types are excluded.",
            true, "amcache", "inventoryapplication", "execution.amcache"),
        New("srum", "SRUM Explorer", "Execution", ModuleAvailability.Planned,
            "Time-bounded application resource-usage observations.",
            "Network destinations, user identities and unrelated application history remain excluded.",
            true, "srum", "srudb"),
        New("binary-triage", "YARA + Entropy", "Binary triage", ModuleAvailability.Available,
            "Hashes, Authenticode, Shannon entropy and bounded YARA rule matching.",
            "Only files already referenced by approved process/module evidence are opened; rule hits are review leads.",
            false, "yara", "entropy", "sha256", "authenticode"),
    ];

    public static IReadOnlyList<EvidenceModuleDefinition> Search(string? query)
    {
        if (string.IsNullOrWhiteSpace(query))
        {
            return All;
        }

        var terms = query.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return All.Where(module => terms.All(term => Matches(module, term))).ToArray();
    }

    private static bool Matches(EvidenceModuleDefinition module, string term) =>
        module.Id.Contains(term, StringComparison.OrdinalIgnoreCase)
        || module.DisplayName.Contains(term, StringComparison.OrdinalIgnoreCase)
        || module.Category.Contains(term, StringComparison.OrdinalIgnoreCase)
        || module.Description.Contains(term, StringComparison.OrdinalIgnoreCase)
        || module.Boundary.Contains(term, StringComparison.OrdinalIgnoreCase)
        || module.SearchTerms.Any(value => value.Contains(term, StringComparison.OrdinalIgnoreCase));

    private static EvidenceModuleDefinition New(
        string id,
        string displayName,
        string category,
        ModuleAvailability availability,
        string description,
        string boundary,
        bool requiresAdministrator,
        params string[] searchTerms) =>
        new(id, displayName, category, availability, description, boundary, requiresAdministrator, searchTerms);
}
