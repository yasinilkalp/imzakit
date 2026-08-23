namespace ImzaKit.Revocation.Models;

public sealed class RevocationEvidenceSet
{
    private readonly IReadOnlyList<RevocationEvidence> _evidence;

    public RevocationEvidenceSet(IEnumerable<RevocationEvidence> evidence)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        _evidence = Array.AsReadOnly(evidence.ToArray());
    }

    public IReadOnlyList<RevocationEvidence> Evidence => _evidence;

    public static RevocationEvidenceSet Empty { get; } = new([]);
}
