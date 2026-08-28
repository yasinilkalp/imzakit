using ImzaKit.Core.Net;

namespace ImzaKit.Trust.Packaging;

public sealed class TrustStoreUpdateChannel(
    TrustStoreActivationService activation,
    IExternalResourceFetcher fetcher)
{
    public const int MaxPackageBytes = 1_048_576;

    public async Task<TrustStoreActivationResult> PullAsync(Uri packageUri, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(activation);
        ArgumentNullException.ThrowIfNull(fetcher);
        ArgumentNullException.ThrowIfNull(packageUri);

        ExternalResourceFetchResult fetched = await fetcher.FetchAsync(
            new ExternalResourceFetchRequest(
                packageUri,
                "GET",
                [],
                ContentType: null,
                AllowedResponseContentTypes: ["application/json"],
                MaxResponseBytes: MaxPackageBytes,
                Timeout: TimeSpan.FromSeconds(15),
                MaxRedirects: 0),
            cancellationToken).ConfigureAwait(false);
        return activation.Activate(fetched.Body);
    }
}
