using Dbdr.PcCheck.Core;
using Dbdr.PcCheck.Core.Models;
using Dbdr.PcCheck.Windows;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class ScheduledTaskCollectorTests
{
    [Fact]
    public async Task ExcludesArgumentsAndRedactsCommandPath()
    {
        var taskDirectory = Path.Combine(Path.GetTempPath(), "DbdrScheduledTaskTests", Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(taskDirectory);
        var taskPath = Path.Combine(taskDirectory, "ExampleTask");
        await File.WriteAllTextAsync(taskPath, """
            <?xml version="1.0" encoding="UTF-8"?>
            <Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
              <RegistrationInfo><Date>2026-08-11T17:30:00Z</Date></RegistrationInfo>
              <Triggers><LogonTrigger /></Triggers>
              <Principals><Principal id="Author"><UserId>PrivateUser</UserId></Principal></Principals>
              <Settings><Enabled>true</Enabled><Hidden>false</Hidden></Settings>
              <Actions Context="Author">
                <Exec>
                  <Command>C:\Users\Alice\AppData\Local\runner.exe</Command>
                  <Arguments>--token should-not-be-collected</Arguments>
                </Exec>
              </Actions>
            </Task>
            """);

        try
        {
            var now = new DateTimeOffset(2026, 8, 11, 18, 0, 0, TimeSpan.Zero);
            var collector = new ScheduledTaskCollector(new PathRedactor(@"C:\Users\Alice"), taskDirectory);
            var context = new CollectionContext("case-1", now.AddHours(-2), now, now, "test");

            var result = await collector.CollectAsync(context, null, CancellationToken.None);

            var task = Assert.Single(result.Records.Where(record => record.Kind == "persistence.scheduled_task"));
            Assert.Equal(@"%USERPROFILE%\AppData\Local\runner.exe", task.Fields["command"]);
            Assert.Equal("LogonTrigger", task.Fields["triggerTypes"]);
            Assert.False(task.Fields.ContainsKey("arguments"));
            Assert.DoesNotContain("PrivateUser", string.Join("|", task.Fields.Values), StringComparison.Ordinal);
            Assert.Empty(result.Warnings);
        }
        finally
        {
            Directory.Delete(taskDirectory, recursive: true);
        }
    }
}
