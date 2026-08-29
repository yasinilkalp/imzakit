namespace ImzaKit.Api.Workflow;

public sealed class SignaturePolicy
{
    public SignaturePolicy(
        int requiredSignerCount,
        IReadOnlyList<string> requiredRoles,
        bool enforceOrder,
        DateTimeOffset? deadlineUtc,
        SignatureRejectionBehavior rejection,
        DuplicateSignerPolicy duplicateSigner)
    {
        ArgumentNullException.ThrowIfNull(requiredRoles);
        ArgumentOutOfRangeException.ThrowIfLessThan(requiredSignerCount, 1);

        if (requiredRoles.Count != requiredSignerCount)
        {
            throw new ArgumentException(
                "Required role count must match the required signer count.",
                nameof(requiredRoles));
        }

        List<string> roles = [];
        foreach (string role in requiredRoles)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(role);
            roles.Add(role);
        }

        RequiredSignerCount = requiredSignerCount;
        RequiredRoles = roles;
        EnforceOrder = enforceOrder;
        DeadlineUtc = deadlineUtc;
        Rejection = rejection;
        DuplicateSigner = duplicateSigner;
    }

    public int RequiredSignerCount { get; }

    public IReadOnlyList<string> RequiredRoles { get; }

    public bool EnforceOrder { get; }

    public DateTimeOffset? DeadlineUtc { get; }

    public SignatureRejectionBehavior Rejection { get; }

    public DuplicateSignerPolicy DuplicateSigner { get; }
}
