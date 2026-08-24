namespace ImzaKit.Api.Audit;

public static class AuditEventKinds
{
    public const string OperationCreated = "operation.created";
    public const string ConsentGranted = "consent.granted";
    public const string CertificateSelected = "certificate.selected";
    public const string Prepared = "prepare.completed";
    public const string SignatureCreated = "signature.created";
    public const string Timestamped = "timestamp.applied";
    public const string Validated = "validation.completed";
    public const string Downloaded = "document.downloaded";
    public const string Cancelled = "operation.cancelled";
    public const string RetentionSwept = "retention.swept";
    public const string RetentionPolicyChanged = "retention.policy.changed";
}

public sealed record AuditEvent(
    string Kind,
    DateTimeOffset At,
    string TenantHash,
    Guid? OperationId,
    IReadOnlyDictionary<string, string> Attributes,
    string PreviousHash,
    string EventHash);
