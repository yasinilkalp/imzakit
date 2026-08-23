namespace ImzaKit.Trust.Evaluation;

public sealed record TrustPolicyEvaluationResult(
    TrustPolicyStatus AnchorStatus,
    TrustPolicyStatus PolicyStatus,
    string? MatchedAnchorSha256,
    string? MatchedPolicyOid,
    string TrustStoreVersion,
    string PolicyCatalogVersion,
    IReadOnlyList<TrustPolicyFailure> Failures);
