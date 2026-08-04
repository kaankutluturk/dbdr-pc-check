using Dbdr.PcCheck.Core;

namespace Dbdr.PcCheck.Core.Tests;

public sealed class CaseIdValidatorTests
{
    [Theory]
    [InlineData("DBDR-2026-001")]
    [InlineData("case_42")]
    [InlineData("A")]
    public void AcceptsSafeIdentifiers(string value) => Assert.True(CaseIdValidator.IsValid(value));

    [Theory]
    [InlineData("")]
    [InlineData("contains spaces")]
    [InlineData("../escape")]
    [InlineData("semi;colon")]
    [InlineData("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789___")]
    public void RejectsUnsafeIdentifiers(string value) => Assert.False(CaseIdValidator.IsValid(value));
}
