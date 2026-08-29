namespace ImzaKit.Api.Workflow;

public static class SignatureFlowCoordinator
{
    public static SignatureEnvelope Create(
        SignatureFlowKind flow,
        ParallelMergeStrategy mergeStrategy,
        SignaturePolicy policy,
        string approvedDocumentSha256)
    {
        ArgumentNullException.ThrowIfNull(policy);
        ArgumentException.ThrowIfNullOrWhiteSpace(approvedDocumentSha256);
        if (flow == SignatureFlowKind.Serial && mergeStrategy != ParallelMergeStrategy.SequentialRevisions)
        {
            throw new ArgumentException(
                "Serial flow requires sequential revisions so the revision chain can be preserved.",
                nameof(mergeStrategy));
        }

        List<WorkflowStep> steps = [];
        for (int index = 0; index < policy.RequiredRoles.Count; index++)
        {
            steps.Add(new(
                index,
                policy.RequiredRoles[index],
                WorkflowStepStatus.Pending,
                approvedDocumentSha256));
        }

        return new(
            Guid.NewGuid(),
            flow,
            mergeStrategy,
            policy,
            approvedDocumentSha256,
            approvedDocumentSha256,
            EnvelopeStatus.Open,
            steps);
    }

    public static WorkflowMutationResult PrepareStep(
        SignatureEnvelope envelope,
        int stepIndex,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (!TryOpenStep(envelope, stepIndex, nowUtc, out WorkflowMutationResult? closed, out WorkflowStep step))
        {
            return closed!;
        }

        if (step.Status is not WorkflowStepStatus.Pending and not WorkflowStepStatus.Prepared)
        {
            return Fail(envelope, WorkflowProblemCodes.StepNotReady);
        }

        if (envelope.Flow == SignatureFlowKind.Serial
            && stepIndex > 0
            && envelope.Steps[stepIndex - 1].Status != WorkflowStepStatus.Completed)
        {
            return Fail(envelope, WorkflowProblemCodes.StepNotReady);
        }

        string digest = envelope.Flow == SignatureFlowKind.Parallel
            ? envelope.ApprovedDocumentSha256
            : envelope.CurrentDocumentSha256;
        return Succeed(ReplaceStep(envelope, step with
        {
            Status = WorkflowStepStatus.Prepared,
            ApprovedDigestSha256 = digest
        }));
    }

    public static WorkflowMutationResult CompleteStep(
        SignatureEnvelope envelope,
        int stepIndex,
        string certificateFingerprintSha256,
        string signedDocumentSha256,
        int coveredRevision,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateFingerprintSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(signedDocumentSha256);
        if (!TryOpenStep(envelope, stepIndex, nowUtc, out WorkflowMutationResult? closed, out WorkflowStep step))
        {
            return closed!;
        }

        if (step.Status != WorkflowStepStatus.Prepared)
        {
            return Fail(envelope, WorkflowProblemCodes.StepNotReady);
        }

        if (envelope.Policy.DuplicateSigner == DuplicateSignerPolicy.Reject
            && envelope.Steps.Any(existing =>
                existing.Status == WorkflowStepStatus.Completed
                && string.Equals(
                    existing.CertificateFingerprintSha256,
                    certificateFingerprintSha256,
                    StringComparison.OrdinalIgnoreCase)))
        {
            return Fail(envelope, WorkflowProblemCodes.DuplicateSigner);
        }

        int completionOrder = envelope.Steps.Count(item => item.CompletionOrder is not null) + 1;
        WorkflowStep completed = step with
        {
            Status = WorkflowStepStatus.Completed,
            CertificateFingerprintSha256 = certificateFingerprintSha256,
            CoveredRevision = coveredRevision,
            CompletionOrder = completionOrder
        };
        SignatureEnvelope updated = ReplaceStep(envelope, completed);
        string currentDigest = envelope.Flow == SignatureFlowKind.Serial
            ? signedDocumentSha256
            : envelope.CurrentDocumentSha256;
        EnvelopeStatus status = updated.Steps.All(item => item.Status == WorkflowStepStatus.Completed)
            ? EnvelopeStatus.Completed
            : EnvelopeStatus.Open;
        return Succeed(updated with
        {
            CurrentDocumentSha256 = currentDigest,
            Status = status
        });
    }

    public static WorkflowMutationResult RejectStep(
        SignatureEnvelope envelope,
        int stepIndex,
        DateTimeOffset nowUtc)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (!TryOpenStep(envelope, stepIndex, nowUtc, out WorkflowMutationResult? closed, out WorkflowStep step))
        {
            return closed!;
        }

        if (step.Status is WorkflowStepStatus.Completed or WorkflowStepStatus.Cancelled or WorkflowStepStatus.Rejected)
        {
            return Fail(envelope, WorkflowProblemCodes.StepNotReady);
        }

        if (envelope.Policy.Rejection == SignatureRejectionBehavior.CancelEnvelope)
        {
            List<WorkflowStep> steps = [];
            foreach (WorkflowStep item in envelope.Steps)
            {
                if (item.Index == stepIndex)
                {
                    steps.Add(item with { Status = WorkflowStepStatus.Rejected });
                }
                else if (item.Status is WorkflowStepStatus.Pending or WorkflowStepStatus.Prepared)
                {
                    steps.Add(item with { Status = WorkflowStepStatus.Cancelled });
                }
                else
                {
                    steps.Add(item);
                }
            }

            return Succeed(envelope with { Status = EnvelopeStatus.Rejected, Steps = steps });
        }

        SignatureEnvelope failed = ReplaceStep(envelope, step with { Status = WorkflowStepStatus.Rejected });
        return Succeed(failed with { Status = EnvelopeStatus.Failed });
    }

    public static IReadOnlyList<WorkflowSignatureReport> Report(SignatureEnvelope envelope)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        string semantics = envelope.MergeStrategy == ParallelMergeStrategy.SequentialRevisions
            ? SubsequentChangeSemantics.LaterRevisionsDoNotInvalidatePriorCrypto
            : SubsequentChangeSemantics.IndependentArtifacts;
        return [.. envelope.Steps
            .Where(step => step.CompletionOrder is not null)
            .OrderBy(step => step.CompletionOrder)
            .Select(step => new WorkflowSignatureReport(
                step.CompletionOrder!.Value,
                step.Role,
                step.CertificateFingerprintSha256,
                step.ApprovedDigestSha256,
                step.CoveredRevision,
                semantics))];
    }

    private static bool TryOpenStep(
        SignatureEnvelope envelope,
        int stepIndex,
        DateTimeOffset nowUtc,
        out WorkflowMutationResult? failure,
        out WorkflowStep step)
    {
        step = null!;
        if (envelope.Status != EnvelopeStatus.Open)
        {
            failure = Fail(envelope, WorkflowProblemCodes.EnvelopeClosed);
            return false;
        }

        if (envelope.Policy.DeadlineUtc is { } deadline && nowUtc > deadline)
        {
            failure = Fail(envelope, WorkflowProblemCodes.DeadlineExpired);
            return false;
        }

        if (stepIndex < 0 || stepIndex >= envelope.Steps.Count)
        {
            failure = Fail(envelope, WorkflowProblemCodes.StepNotReady);
            return false;
        }

        step = envelope.Steps[stepIndex];
        failure = null;
        return true;
    }

    private static SignatureEnvelope ReplaceStep(SignatureEnvelope envelope, WorkflowStep replacement)
    {
        List<WorkflowStep> steps = [.. envelope.Steps];
        steps[replacement.Index] = replacement;
        return envelope with { Steps = steps };
    }

    private static WorkflowMutationResult Succeed(SignatureEnvelope envelope) => new(true, envelope);

    private static WorkflowMutationResult Fail(SignatureEnvelope envelope, string problemCode) =>
        new(false, envelope, problemCode);
}
