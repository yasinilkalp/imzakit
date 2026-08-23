namespace ImzaKit.Trust.Evaluation;

public interface ITrustPolicyEvaluator
{
    TrustPolicyEvaluationResult Evaluate(TrustPolicyEvaluationRequest request);
}
