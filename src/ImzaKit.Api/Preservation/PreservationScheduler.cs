namespace ImzaKit.Api.Preservation;

public static class PreservationProblemCodes
{
    public const string NotDue = "IMZAKIT.PRESERVATION.NOT_DUE";
    public const string NotArchiveLevel = "IMZAKIT.PRESERVATION.NOT_ARCHIVE_LEVEL";
    public const string UnsupportedFormat = "IMZAKIT.PRESERVATION.UNSUPPORTED_FORMAT";
    public const string Unavailable = "IMZAKIT.PRESERVATION.UNAVAILABLE";
}

public sealed record PreservationObject(
    string ObjectKey,
    string Format,
    DateTimeOffset ArchiveTimestampNotAfterUtc);

public sealed record PreservationRenewalResult(
    bool Succeeded,
    string? ProblemCode = null,
    DateTimeOffset? NextNotAfterUtc = null);

public sealed record PreservationItemResult(
    string ObjectKey,
    bool Renewed,
    string? ProblemCode = null);

public sealed record PreservationRunResult(
    int DueCount,
    int RenewedCount,
    int FailedCount,
    IReadOnlyList<PreservationItemResult> Items);

public static class PreservationScheduler
{
    public static bool IsDue(PreservationObject item, DateTimeOffset nowUtc, TimeSpan leadTime)
    {
        ArgumentNullException.ThrowIfNull(item);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(leadTime, TimeSpan.Zero);
        return nowUtc >= item.ArchiveTimestampNotAfterUtc - leadTime;
    }

    public static IReadOnlyList<PreservationObject> SelectDue(
        IReadOnlyList<PreservationObject> catalog,
        DateTimeOffset nowUtc,
        TimeSpan leadTime)
    {
        ArgumentNullException.ThrowIfNull(catalog);
        List<PreservationObject> due = [];
        foreach (PreservationObject item in catalog)
        {
            if (IsDue(item, nowUtc, leadTime))
            {
                due.Add(item);
            }
        }

        return due;
    }

    public static PreservationRunResult Run(
        IReadOnlyList<PreservationObject> catalog,
        DateTimeOffset nowUtc,
        TimeSpan leadTime,
        Func<PreservationObject, PreservationRenewalResult> renew)
    {
        ArgumentNullException.ThrowIfNull(renew);
        IReadOnlyList<PreservationObject> due = SelectDue(catalog, nowUtc, leadTime);
        List<PreservationItemResult> items = [];
        int renewed = 0;
        int failed = 0;
        foreach (PreservationObject item in due)
        {
            if (!string.Equals(item.Format, "PAdES", StringComparison.Ordinal))
            {
                failed++;
                items.Add(new(item.ObjectKey, false, PreservationProblemCodes.UnsupportedFormat));
                continue;
            }

            PreservationRenewalResult result = renew(item);
            if (result.Succeeded)
            {
                renewed++;
                items.Add(new(item.ObjectKey, true));
            }
            else
            {
                failed++;
                items.Add(new(item.ObjectKey, false, result.ProblemCode ?? PreservationProblemCodes.Unavailable));
            }
        }

        return new(due.Count, renewed, failed, items);
    }
}
