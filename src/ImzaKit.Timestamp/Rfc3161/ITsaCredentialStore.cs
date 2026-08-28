namespace ImzaKit.Timestamp.Rfc3161;

public interface ITsaCredentialStore
{
    ValueTask<TsaCredential?> GetAsync(string authorityName, CancellationToken cancellationToken);
}
