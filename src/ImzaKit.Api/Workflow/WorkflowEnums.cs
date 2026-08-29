namespace ImzaKit.Api.Workflow;

public enum SignatureFlowKind
{
    Serial,
    Parallel
}

public enum ParallelMergeStrategy
{
    SequentialRevisions,
    CosignCms
}

public enum SignatureRejectionBehavior
{
    CancelEnvelope,
    FailStep
}

public enum DuplicateSignerPolicy
{
    Reject,
    Allow
}

public enum WorkflowStepStatus
{
    Pending,
    Prepared,
    Completed,
    Rejected,
    Cancelled
}

public enum EnvelopeStatus
{
    Open,
    Completed,
    Rejected,
    Failed
}

public static class WorkflowProblemCodes
{
    public const string StepNotReady = "IMZAKIT.WORKFLOW.STEP_NOT_READY";
    public const string DuplicateSigner = "IMZAKIT.WORKFLOW.DUPLICATE_SIGNER";
    public const string DeadlineExpired = "IMZAKIT.WORKFLOW.DEADLINE_EXPIRED";
    public const string EnvelopeClosed = "IMZAKIT.WORKFLOW.ENVELOPE_CLOSED";
}

public static class SubsequentChangeSemantics
{
    public const string LaterRevisionsDoNotInvalidatePriorCrypto = "LaterRevisionsDoNotInvalidatePriorCrypto";
    public const string IndependentArtifacts = "IndependentArtifacts";
}
