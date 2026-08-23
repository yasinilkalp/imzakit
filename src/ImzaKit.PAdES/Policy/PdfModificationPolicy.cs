namespace ImzaKit.PAdES.Policy;

public enum PdfCertificationChangeLevel
{
    None,
    NoChanges,
    FormFillAndSign,
    FormFillSignAndAnnotate,
}

public enum PdfFieldLockAction
{
    None,
    All,
    Include,
    Exclude,
}

public sealed class PdfModificationPolicy
{
    private readonly string[] fieldNames;

    public PdfModificationPolicy(
        PdfCertificationChangeLevel certificationPermission,
        PdfFieldLockAction fieldLockAction,
        IEnumerable<string> fieldNames)
    {
        ArgumentNullException.ThrowIfNull(fieldNames);
        CertificationPermission = certificationPermission;
        FieldLockAction = fieldLockAction;
        this.fieldNames = fieldNames.ToArray();
    }

    public PdfCertificationChangeLevel CertificationPermission { get; }

    public PdfFieldLockAction FieldLockAction { get; }

    public IReadOnlyList<string> FieldNames => fieldNames;
}
