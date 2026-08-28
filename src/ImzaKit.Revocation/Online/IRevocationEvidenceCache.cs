using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Online;

public interface IRevocationEvidenceCache
{
    bool TryGet(string key, DateTimeOffset nowUtc, out RevocationEvidence evidence);

    void Store(
        string key,
        RevocationEvidenceType type,
        ReadOnlySpan<byte> encoded,
        DateTimeOffset nextUpdateUtc,
        DateTimeOffset nowUtc);
}
