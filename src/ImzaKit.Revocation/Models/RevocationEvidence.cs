namespace ImzaKit.Revocation.Models;

public sealed class RevocationEvidence
{
    private readonly byte[] _encoded;

    public RevocationEvidence(
        RevocationEvidenceType type,
        RevocationEvidenceSource source,
        ReadOnlySpan<byte> encoded)
    {
        if (encoded.IsEmpty)
        {
            throw new ArgumentException("Revocation evidence cannot be empty.", nameof(encoded));
        }

        Type = type;
        Source = source;
        _encoded = encoded.ToArray();
    }

    public RevocationEvidenceType Type { get; }

    public RevocationEvidenceSource Source { get; }

    public byte[] ExportEncoded() => _encoded.ToArray();
}
