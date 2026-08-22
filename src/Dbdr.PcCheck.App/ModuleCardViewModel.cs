using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.App;

public sealed record ModuleCardViewModel(
    string Id,
    string DisplayName,
    string Category,
    string Status,
    string StatusColor,
    string Description,
    string Boundary,
    string Access)
{
    public static ModuleCardViewModel From(EvidenceModuleDefinition definition) =>
        new(
            definition.Id,
            definition.DisplayName,
            definition.Category.ToUpperInvariant(),
            StatusText(definition.Availability),
            StatusColorValue(definition.Availability),
            definition.Description,
            definition.Boundary,
            definition.RequiresAdministrator ? "ADMIN SOURCE" : "STANDARD USER");

    private static string StatusText(ModuleAvailability availability) => availability switch
    {
        ModuleAvailability.Available => "AVAILABLE",
        ModuleAvailability.Preview => "PREVIEW",
        ModuleAvailability.Planned => "PLANNED",
        ModuleAvailability.PrivacyRestricted => "PRIVACY GATED",
        _ => availability.ToString().ToUpperInvariant(),
    };

    private static string StatusColorValue(ModuleAvailability availability) => availability switch
    {
        ModuleAvailability.Available => "#61C78A",
        ModuleAvailability.Preview => "#E5B75D",
        ModuleAvailability.Planned => "#B3ADB0",
        ModuleAvailability.PrivacyRestricted => "#C1354A",
        _ => "#B3ADB0",
    };
}
