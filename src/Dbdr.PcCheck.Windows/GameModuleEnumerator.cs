using System.Diagnostics;

namespace Dbdr.PcCheck.Windows;

public sealed record LoadedModuleInfo(string Name, string Path);

public interface IGameModuleEnumerator
{
    IReadOnlyList<LoadedModuleInfo> Enumerate(uint processId);
}

public sealed class GameModuleEnumerator : IGameModuleEnumerator
{
    public IReadOnlyList<LoadedModuleInfo> Enumerate(uint processId)
    {
        using var process = Process.GetProcessById(checked((int)processId));
        return process.Modules
            .Cast<ProcessModule>()
            .Select(module => new LoadedModuleInfo(module.ModuleName, module.FileName))
            .Where(module => !string.IsNullOrWhiteSpace(module.Path))
            .DistinctBy(module => module.Path, StringComparer.OrdinalIgnoreCase)
            .OrderBy(module => module.Path, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }
}
