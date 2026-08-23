namespace ImzaKit.PAdES.Preflight;

public sealed record PdfPreflightLimits(long MaximumPdfBytes, int MaximumObjects, int MaximumRevisions)
{
    public static PdfPreflightLimits Default { get; } = new(32L * 1024 * 1024, 100_000, 32);
}
