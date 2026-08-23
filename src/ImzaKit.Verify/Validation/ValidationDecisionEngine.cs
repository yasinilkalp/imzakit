using ImzaKit.Revocation.Models;

namespace ImzaKit.Verify.Validation;

public class ValidationDecisionEngine
{
    public virtual ValidationStatus Decide(ValidationDecisionInput input)
    {
        ArgumentNullException.ThrowIfNull(input);
        if (input.ByteRangeStatus == ValidationStatus.Failed
            || input.CryptographicStatus == ValidationStatus.Failed
            || input.ChainStatus == ValidationStatus.Failed
            || input.TrustStatus == ValidationStatus.Failed
            || input.PolicyStatus == ValidationStatus.Failed
            || input.RevocationStatus is RevocationStatus.Revoked or RevocationStatus.Suspended)
        {
            return ValidationStatus.Failed;
        }

        if (input.ByteRangeStatus != ValidationStatus.Passed
            || input.CryptographicStatus != ValidationStatus.Passed
            || input.ChainStatus != ValidationStatus.Passed
            || input.TrustStatus != ValidationStatus.Passed
            || input.PolicyStatus != ValidationStatus.Passed
            || input.RevocationStatus != RevocationStatus.Good)
        {
            return ValidationStatus.Indeterminate;
        }

        return ValidationStatus.Passed;
    }
}
