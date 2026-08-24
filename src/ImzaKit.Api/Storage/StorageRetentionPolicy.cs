namespace ImzaKit.Api.Storage;

public sealed record StorageRetentionPolicy(TimeSpan IncompleteOperation, TimeSpan CompletedArtifact)
{
    public static StorageRetentionPolicy Default { get; } = Create(TimeSpan.FromHours(24), TimeSpan.FromDays(7));

    public static StorageRetentionPolicy Create(TimeSpan incompleteOperation, TimeSpan completedArtifact)
    {
        Validate(incompleteOperation, nameof(incompleteOperation));
        Validate(completedArtifact, nameof(completedArtifact));
        return new StorageRetentionPolicy(incompleteOperation, completedArtifact);
    }

    public StorageRetentionPolicy With(TimeSpan? incompleteOperation = null, TimeSpan? completedArtifact = null) =>
        Create(incompleteOperation ?? IncompleteOperation, completedArtifact ?? CompletedArtifact);

    private static void Validate(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero || value == Timeout.InfiniteTimeSpan || value > TimeSpan.FromDays(3650))
        {
            throw new ArgumentOutOfRangeException(name, "Retention must be finite; unlimited storage is not a default.");
        }
    }
}
