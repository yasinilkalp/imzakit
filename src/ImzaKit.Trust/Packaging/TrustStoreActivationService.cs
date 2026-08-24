using System.Security.Cryptography;
using ImzaKit.Certificate.Models;
using ImzaKit.Trust.Models;

namespace ImzaKit.Trust.Packaging;

public enum TrustStoreActivationStatus
{
    Activated,
    Rejected,
    RolledBack,
    Removed
}

public sealed record TrustStoreActivationResult(
    TrustStoreActivationStatus Status,
    string? Reason = null,
    TrustStoreSnapshot? Snapshot = null,
    CertificatePolicyCatalog? Catalog = null,
    string? ChangeRationale = null);

public sealed class TrustStoreActivationService
{
    private readonly ECDsa _releasePublicKey;
    private readonly List<Activation> _history = [];
    private readonly Lock _gate = new();

    public TrustStoreActivationService(ECDsa releasePublicKey)
    {
        ArgumentNullException.ThrowIfNull(releasePublicKey);
        _releasePublicKey = releasePublicKey;
    }

    public TrustStoreSnapshot? Current { get; private set; }

    public CertificatePolicyCatalog? CurrentCatalog { get; private set; }

    public TrustStoreActivationResult Activate(ReadOnlySpan<byte> package)
    {
        if (!TrustStorePackageCodec.TryVerify(package, _releasePublicKey, out TrustStoreManifest? manifest) ||
            manifest is null)
        {
            return new(TrustStoreActivationStatus.Rejected, "IMZAKIT.TRUST.INVALID_SIGNATURE", Current, CurrentCatalog);
        }

        lock (_gate)
        {
            int currentSequence = _history.Count == 0 ? 0 : _history[^1].Manifest.Sequence;
            if (manifest.Sequence <= currentSequence)
            {
                return new(TrustStoreActivationStatus.Rejected, "IMZAKIT.TRUST.STALE_VERSION", Current, CurrentCatalog);
            }

            if (!TryMaterialize(manifest, out TrustStoreSnapshot snapshot, out CertificatePolicyCatalog catalog, out string? reason))
            {
                return new(TrustStoreActivationStatus.Rejected, reason, Current, CurrentCatalog);
            }

            _history.Add(new Activation(manifest, snapshot, catalog));
            Current = snapshot;
            CurrentCatalog = catalog;
            return new(TrustStoreActivationStatus.Activated, Snapshot: snapshot, Catalog: catalog);
        }
    }

    public TrustStoreActivationResult Rollback()
    {
        lock (_gate)
        {
            if (_history.Count < 2)
            {
                return new(TrustStoreActivationStatus.Rejected, "IMZAKIT.TRUST.ROLLBACK_UNAVAILABLE", Current, CurrentCatalog);
            }

            _history.RemoveAt(_history.Count - 1);
            Activation previous = _history[^1];
            Current = previous.Snapshot;
            CurrentCatalog = previous.Catalog;
            return new(TrustStoreActivationStatus.RolledBack, Snapshot: Current, Catalog: CurrentCatalog);
        }
    }

    public TrustStoreActivationResult EmergencyRemove(string certificateSha256, string rationale)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(certificateSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(rationale);
        lock (_gate)
        {
            if (Current is null || _history.Count == 0)
            {
                return new(TrustStoreActivationStatus.Rejected, "IMZAKIT.TRUST.NO_ACTIVE_PACKAGE");
            }

            TrustAnchor[] remaining = [.. Current.Anchors.Where(anchor =>
                !string.Equals(anchor.Certificate.Sha256Thumbprint, certificateSha256, StringComparison.OrdinalIgnoreCase))];
            string version = $"{_history[^1].Manifest.Version}-removed-{certificateSha256[..Math.Min(8, certificateSha256.Length)]}";
            TrustStoreSnapshot snapshot = new(version, remaining);
            Current = snapshot;
            return new(TrustStoreActivationStatus.Removed, Snapshot: snapshot, Catalog: CurrentCatalog, ChangeRationale: rationale);
        }
    }

    private static bool TryMaterialize(
        TrustStoreManifest manifest,
        out TrustStoreSnapshot snapshot,
        out CertificatePolicyCatalog catalog,
        out string? reason)
    {
        snapshot = null!;
        catalog = null!;
        reason = "IMZAKIT.TRUST.INVALID_PACKAGE";
        try
        {
            List<TrustAnchor> anchors = [];
            List<CertificatePolicyEntry> policies = [];
            foreach (TrustStorePackageEntry entry in manifest.Entries)
            {
                if (entry.Removed)
                {
                    continue;
                }

                byte[] der = Convert.FromBase64String(entry.CertificateDerBase64);
                string thumbprint = Convert.ToHexString(SHA256.HashData(der));
                if (!string.Equals(thumbprint, entry.Sha256, StringComparison.OrdinalIgnoreCase))
                {
                    return false;
                }

                CertificateDescriptor certificate = CertificateDescriptor.FromDer(der, CertificateSource.Local);
                anchors.Add(new TrustAnchor(certificate, entry.Profiles, entry.Provenance, entry.Role));
                foreach (string oid in entry.PolicyOids)
                {
                    policies.Add(new CertificatePolicyEntry(
                        manifest.Profile,
                        oid,
                        entry.NotBeforeUtc,
                        entry.NotAfterUtc,
                        TimeSpan.FromHours(12)));
                }
            }

            snapshot = new TrustStoreSnapshot(manifest.Version, anchors);
            catalog = new CertificatePolicyCatalog(manifest.Version + "-policy", policies);
            reason = null;
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or FormatException)
        {
            return false;
        }
    }

    private sealed record Activation(
        TrustStoreManifest Manifest,
        TrustStoreSnapshot Snapshot,
        CertificatePolicyCatalog Catalog);
}
