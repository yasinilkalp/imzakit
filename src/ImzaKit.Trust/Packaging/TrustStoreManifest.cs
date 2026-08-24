using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Packaging;

public sealed record TrustStorePackageEntry(
    string ProviderName,
    TrustAnchorRole Role,
    string CertificateDerBase64,
    string Sha256,
    DateTimeOffset NotBeforeUtc,
    DateTimeOffset NotAfterUtc,
    IReadOnlyList<string> PolicyOids,
    IReadOnlyList<ValidationProfile> Profiles,
    string Provenance,
    string ChangeRationale,
    bool Removed = false);

public sealed record TrustStoreManifest(
    int Sequence,
    string Version,
    ValidationProfile Profile,
    string AlgorithmPolicyVersion,
    string Provider,
    DateTimeOffset IssuedAtUtc,
    string ProvenanceCommit,
    string SourceUri,
    IReadOnlyList<TrustStorePackageEntry> Entries);
