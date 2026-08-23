namespace ImzaKit.PAdES.Preflight;

public enum PdfPreflightErrorCode
{
    PdfTooLarge,
    UnsupportedVersion,
    Encrypted,
    XrefStream,
    ObjectStream,
    HybridReference,
    ExistingAcroForm,
    TooManyObjects,
    TooManyRevisions,
    CertificationForbidsChanges,
    TargetFieldLocked,
}

public sealed class PdfPreflightException : NotSupportedException
{
    public PdfPreflightException(PdfPreflightErrorCode code, string message)
        : base(message)
    {
        Code = code;
    }

    public PdfPreflightErrorCode Code { get; }
}
