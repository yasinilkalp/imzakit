using ImzaKit.Revocation.Models;
using ImzaKit.Verify.Validation;

namespace ImzaKit.Verify.Tests.Validation;

public sealed class ValidationDecisionEngineTests
{
    [Fact]
    public void DefinitiveFailureWinsOverUnavailableRevocationEvidence()
    {
        ValidationStatus result = new ValidationDecisionEngine().Decide(Input(
            chain: ValidationStatus.Failed,
            revocation: RevocationStatus.Unavailable));

        Assert.Equal(ValidationStatus.Failed, result);
    }

    [Theory]
    [InlineData(RevocationStatus.Unavailable)]
    [InlineData(RevocationStatus.Stale)]
    [InlineData(RevocationStatus.Invalid)]
    public void NonDefinitiveRevocationEvidenceProducesIndeterminate(RevocationStatus revocation)
    {
        Assert.Equal(
            ValidationStatus.Indeterminate,
            new ValidationDecisionEngine().Decide(Input(revocation: revocation)));
    }

    [Theory]
    [InlineData(RevocationStatus.Revoked)]
    [InlineData(RevocationStatus.Suspended)]
    public void RevokedOrSuspendedCertificateProducesFailure(RevocationStatus revocation)
    {
        Assert.Equal(
            ValidationStatus.Failed,
            new ValidationDecisionEngine().Decide(Input(revocation: revocation)));
    }

    [Fact]
    public void AllMandatoryChecksPassingProducesPassed()
    {
        Assert.Equal(
            ValidationStatus.Passed,
            new ValidationDecisionEngine().Decide(Input()));
    }

    private static ValidationDecisionInput Input(
        ValidationStatus chain = ValidationStatus.Passed,
        RevocationStatus revocation = RevocationStatus.Good) => new(
            ValidationStatus.Passed,
            ValidationStatus.Passed,
            chain,
            ValidationStatus.Passed,
            ValidationStatus.Passed,
            revocation);
}
