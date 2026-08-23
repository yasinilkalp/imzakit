using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Packaging;

public sealed class PublicApiCompatibilityTests
{
    [Fact]
    public void LegacyPadesValidatorAndReportConstructorRemainPublic()
    {
        Assert.Contains(
            typeof(PadesValidator).GetMethods(),
            method => method.Name == nameof(PadesValidator.Validate) &&
                      method.GetParameters() is [{ ParameterType: var parameterType }] &&
                      parameterType == typeof(ReadOnlySpan<byte>));

        Assert.Contains(
            typeof(PadesValidationReport).GetConstructors(),
            constructor => constructor.GetParameters().Length == 6);
    }
}
