namespace ImzaKit.Trust.Models;

public sealed record CertificatePolicyEntry
{
    public CertificatePolicyEntry(
        ValidationProfile profile,
        string policyOid,
        DateTimeOffset effectiveFromUtc,
        DateTimeOffset? effectiveUntilUtc,
        TimeSpan revocationFreshnessTolerance)
    {
        if (!IsValidOid(policyOid))
        {
            throw new ArgumentException("Certificate policy OID is invalid.", nameof(policyOid));
        }

        if (effectiveFromUtc.Offset != TimeSpan.Zero
            || effectiveUntilUtc is { Offset: var offset } && offset != TimeSpan.Zero)
        {
            throw new ArgumentException("Certificate policy effective times must be UTC.");
        }

        if (effectiveUntilUtc <= effectiveFromUtc)
        {
            throw new ArgumentException("Certificate policy end must be later than its start.", nameof(effectiveUntilUtc));
        }

        if (revocationFreshnessTolerance < TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(revocationFreshnessTolerance),
                "Revocation freshness tolerance cannot be negative.");
        }

        Profile = profile;
        PolicyOid = policyOid.Trim();
        EffectiveFromUtc = effectiveFromUtc;
        EffectiveUntilUtc = effectiveUntilUtc;
        RevocationFreshnessTolerance = revocationFreshnessTolerance;
    }

    public ValidationProfile Profile { get; }

    public string PolicyOid { get; }

    public DateTimeOffset EffectiveFromUtc { get; }

    public DateTimeOffset? EffectiveUntilUtc { get; }

    public TimeSpan RevocationFreshnessTolerance { get; }

    private static bool IsValidOid(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return false;
        }

        string[] arcs = value.Split('.');
        if (arcs.Length < 2 || arcs.Any(arc => arc.Length == 0 || arc.Any(character => !char.IsAsciiDigit(character))))
        {
            return false;
        }

        if (!int.TryParse(arcs[0], out int first) || first is < 0 or > 2)
        {
            return false;
        }

        return first == 2 || int.TryParse(arcs[1], out int second) && second is >= 0 and <= 39;
    }
}
