using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class EvidenceModuleCatalogTests
{
    [Fact]
    public void ContainsEveryRequestedModuleAndExplicitPrivacyGates()
    {
        Assert.Equal(17, EvidenceModuleCatalog.All.Count);
        Assert.Contains(EvidenceModuleCatalog.All, module => module.Id == "bam" && module.Availability == ModuleAvailability.Available);
        Assert.Contains(EvidenceModuleCatalog.All, module => module.Id == "amcache");
        Assert.Contains(EvidenceModuleCatalog.All, module => module.Id == "srum");
        Assert.Contains(EvidenceModuleCatalog.All, module => module.Id == "browser-history" && module.Availability == ModuleAvailability.PrivacyRestricted);
        Assert.Contains(EvidenceModuleCatalog.All, module => module.Id == "kernel-live-dump" && module.Availability == ModuleAvailability.PrivacyRestricted);
    }

    [Fact]
    public void SearchesNamesDescriptionsAndEvidenceKinds()
    {
        var results = EvidenceModuleCatalog.Search("entropy");

        Assert.Contains(results, module => module.Id == "binary-triage");
        Assert.Contains(results, module => module.Id == "string-explorer");
    }
}
