namespace ImzaKit.Revocation.Evaluation;

public interface IOfflineRevocationEvaluator
{
    OfflineRevocationResult Evaluate(OfflineRevocationRequest request);
}
