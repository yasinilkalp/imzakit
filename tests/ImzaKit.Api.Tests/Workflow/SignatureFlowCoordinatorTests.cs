using ImzaKit.Api.Workflow;

namespace ImzaKit.Api.Tests.Workflow;

public sealed class SignatureFlowCoordinatorTests
{
    [Fact]
    public void SerialPrepareRejectsUntilPreviousStepIsCompleted()
    {
        SignatureEnvelope envelope = CreateSerial();

        WorkflowMutationResult first = SignatureFlowCoordinator.PrepareStep(envelope, 0, Now);
        WorkflowMutationResult tooEarly = SignatureFlowCoordinator.PrepareStep(first.Envelope, 1, Now);

        Assert.True(first.Succeeded);
        Assert.Equal(WorkflowStepStatus.Prepared, first.Envelope.Steps[0].Status);
        Assert.False(tooEarly.Succeeded);
        Assert.Equal(WorkflowProblemCodes.StepNotReady, tooEarly.ProblemCode);
        Assert.Equal(WorkflowStepStatus.Pending, tooEarly.Envelope.Steps[1].Status);
    }

    [Fact]
    public void SerialCompletePreservesRevisionChainForNextPrepare()
    {
        SignatureEnvelope envelope = CreateSerial();
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 0, Now));
        envelope = Must(SignatureFlowCoordinator.CompleteStep(
            envelope, 0, "AA", "DIGEST-AFTER-FIRST", coveredRevision: 1, Now));

        WorkflowMutationResult second = SignatureFlowCoordinator.PrepareStep(envelope, 1, Now);

        Assert.True(second.Succeeded);
        Assert.Equal("DIGEST-AFTER-FIRST", second.Envelope.Steps[1].ApprovedDigestSha256);
        Assert.Equal("APPROVED", second.Envelope.ApprovedDocumentSha256);
        Assert.Equal(1, envelope.Steps[0].CoveredRevision);
    }

    [Fact]
    public void ParallelPrepareBindsEveryStepToTheSameApprovedDigest()
    {
        SignatureEnvelope envelope = CreateParallel();

        WorkflowMutationResult first = SignatureFlowCoordinator.PrepareStep(envelope, 0, Now);
        WorkflowMutationResult second = SignatureFlowCoordinator.PrepareStep(first.Envelope, 1, Now);

        Assert.True(first.Succeeded);
        Assert.True(second.Succeeded);
        Assert.Equal("APPROVED", first.Envelope.Steps[0].ApprovedDigestSha256);
        Assert.Equal("APPROVED", second.Envelope.Steps[1].ApprovedDigestSha256);
        Assert.Equal(ParallelMergeStrategy.SequentialRevisions, second.Envelope.MergeStrategy);
    }

    [Fact]
    public void ParallelPadesReportListsSigningOrderAndSubsequentChangeSemantics()
    {
        SignatureEnvelope envelope = CreateParallel();
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 0, Now));
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 1, Now));
        envelope = Must(SignatureFlowCoordinator.CompleteStep(envelope, 1, "BB", "APPROVED", coveredRevision: 2, Now));
        envelope = Must(SignatureFlowCoordinator.CompleteStep(envelope, 0, "AA", "APPROVED", coveredRevision: 1, Now));

        IReadOnlyList<WorkflowSignatureReport> report = SignatureFlowCoordinator.Report(envelope);

        Assert.Equal(2, report.Count);
        Assert.Equal(1, report[0].Order);
        Assert.Equal("reviewer", report[0].Role);
        Assert.Equal(2, report[0].CoveredRevision);
        Assert.Equal(2, report[1].Order);
        Assert.Equal("approver", report[1].Role);
        Assert.Equal(1, report[1].CoveredRevision);
        Assert.All(
            report,
            item => Assert.Equal(
                SubsequentChangeSemantics.LaterRevisionsDoNotInvalidatePriorCrypto,
                item.SubsequentChangeSemantics));
    }

    [Fact]
    public void PolicyRejectsPrepareAfterDeadline()
    {
        SignatureEnvelope envelope = CreateSerial(deadline: Now.AddMinutes(-1));

        WorkflowMutationResult result = SignatureFlowCoordinator.PrepareStep(envelope, 0, Now);

        Assert.False(result.Succeeded);
        Assert.Equal(WorkflowProblemCodes.DeadlineExpired, result.ProblemCode);
    }

    [Fact]
    public void DuplicateSignerFingerprintIsRejectedByPolicy()
    {
        SignatureEnvelope envelope = CreateSerial(duplicate: DuplicateSignerPolicy.Reject);
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 0, Now));
        envelope = Must(SignatureFlowCoordinator.CompleteStep(envelope, 0, "SAME", "D1", 1, Now));
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 1, Now));

        WorkflowMutationResult duplicate = SignatureFlowCoordinator.CompleteStep(
            envelope, 1, "SAME", "D2", 2, Now);

        Assert.False(duplicate.Succeeded);
        Assert.Equal(WorkflowProblemCodes.DuplicateSigner, duplicate.ProblemCode);
        Assert.Equal(WorkflowStepStatus.Prepared, duplicate.Envelope.Steps[1].Status);
    }

    [Fact]
    public void RejectionCancelsRemainingSteps()
    {
        SignatureEnvelope envelope = CreateSerial(rejection: SignatureRejectionBehavior.CancelEnvelope);
        envelope = Must(SignatureFlowCoordinator.PrepareStep(envelope, 0, Now));

        WorkflowMutationResult rejected = SignatureFlowCoordinator.RejectStep(envelope, 0, Now);

        Assert.True(rejected.Succeeded);
        Assert.Equal(EnvelopeStatus.Rejected, rejected.Envelope.Status);
        Assert.Equal(WorkflowStepStatus.Rejected, rejected.Envelope.Steps[0].Status);
        Assert.Equal(WorkflowStepStatus.Cancelled, rejected.Envelope.Steps[1].Status);
    }

    private static readonly DateTimeOffset Now = new(2026, 8, 29, 18, 0, 0, TimeSpan.Zero);

    private static SignatureEnvelope CreateSerial(
        DateTimeOffset? deadline = null,
        DuplicateSignerPolicy duplicate = DuplicateSignerPolicy.Reject,
        SignatureRejectionBehavior rejection = SignatureRejectionBehavior.CancelEnvelope) =>
        SignatureFlowCoordinator.Create(
            SignatureFlowKind.Serial,
            ParallelMergeStrategy.SequentialRevisions,
            new SignaturePolicy(2, ["approver", "reviewer"], true, deadline, rejection, duplicate),
            "APPROVED");

    private static SignatureEnvelope CreateParallel() =>
        SignatureFlowCoordinator.Create(
            SignatureFlowKind.Parallel,
            ParallelMergeStrategy.SequentialRevisions,
            new SignaturePolicy(
                2,
                ["approver", "reviewer"],
                enforceOrder: false,
                deadlineUtc: null,
                SignatureRejectionBehavior.FailStep,
                DuplicateSignerPolicy.Reject),
            "APPROVED");

    private static SignatureEnvelope Must(WorkflowMutationResult result)
    {
        Assert.True(result.Succeeded, result.ProblemCode);
        return result.Envelope;
    }
}
