namespace ImzaKit.Api.Workflow;

public sealed record WorkflowStep(
    int Index,
    string Role,
    WorkflowStepStatus Status,
    string ApprovedDigestSha256,
    string? CertificateFingerprintSha256 = null,
    int? CoveredRevision = null,
    int? CompletionOrder = null);

public sealed record SignatureEnvelope(
    Guid Id,
    SignatureFlowKind Flow,
    ParallelMergeStrategy MergeStrategy,
    SignaturePolicy Policy,
    string ApprovedDocumentSha256,
    string CurrentDocumentSha256,
    EnvelopeStatus Status,
    IReadOnlyList<WorkflowStep> Steps);

public sealed record WorkflowMutationResult(
    bool Succeeded,
    SignatureEnvelope Envelope,
    string? ProblemCode = null);

public sealed record WorkflowSignatureReport(
    int Order,
    string Role,
    string? CertificateFingerprintSha256,
    string ApprovedDigestSha256,
    int? CoveredRevision,
    string SubsequentChangeSemantics);
