namespace ImzaKit.Release.Licensing;

public enum LicenseDecision
{
    Allowed,
    Denied,
    ReviewRequired
}

public static class LicenseAllowList
{
    private static readonly HashSet<string> Allowed = new(StringComparer.OrdinalIgnoreCase)
    {
        "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause", "ISC"
    };

    private static readonly HashSet<string> Review = new(StringComparer.OrdinalIgnoreCase)
    {
        "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "MPL-2.0"
    };

    public static LicenseDecision Evaluate(string spdx)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(spdx);
        if (Allowed.Contains(spdx))
        {
            return LicenseDecision.Allowed;
        }

        if (Review.Contains(spdx))
        {
            return LicenseDecision.ReviewRequired;
        }

        return LicenseDecision.Denied;
    }
}
