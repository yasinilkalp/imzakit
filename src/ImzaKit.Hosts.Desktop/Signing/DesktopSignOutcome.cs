using ImzaKit.Verify.Validation;

namespace ImzaKit.Hosts.Desktop.Signing;

public enum DesktopSignStatus
{
    Succeeded,
    Cancelled,
    Failed
}

public sealed record DesktopSignOutcome(
    DesktopSignStatus Status,
    string? Code,
    string? Message,
    byte[]? SignedPdf,
    PadesValidationReport? Validation)
{
    public static DesktopSignOutcome Succeeded(byte[] signedPdf, PadesValidationReport validation) =>
        new(DesktopSignStatus.Succeeded, null, null, signedPdf, validation);

    public static DesktopSignOutcome Cancelled() =>
        new(DesktopSignStatus.Cancelled, "CANCELLED", "PIN girişi iptal edildi.", null, null);

    public static DesktopSignOutcome Failed(string code, string message) =>
        new(DesktopSignStatus.Failed, code, message, null, null);
}
