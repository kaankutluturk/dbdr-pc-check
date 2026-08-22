using System.Text;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class YaraFileScannerTests
{
    [Fact]
    public async Task EmbeddedBaselineReportsRuleIdentifierWithoutMatchedBytes()
    {
        var path = Path.Combine(Path.GetTempPath(), $"dbdr-yara-test-{Guid.NewGuid():N}.bin");
        try
        {
            var sample = Encoding.ASCII.GetBytes(
                "MZ\0\0OpenProcess\0WriteProcessMemory\0VirtualAllocEx\0CreateRemoteThread\0");
            await File.WriteAllBytesAsync(path, sample);
            using var scanner = new YaraFileScanner();

            var evidence = await scanner.ScanAsync(path, CancellationToken.None);

            Assert.Equal("matched", evidence.Status);
            Assert.Contains(
                evidence.Matches,
                match => match == "baseline:DBDR_Remote_Process_API_Cluster");
            Assert.Single(evidence.RulesetHashes);
            Assert.Null(evidence.Error);
        }
        finally
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
    }
}
