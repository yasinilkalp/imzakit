using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;

namespace ImzaKit.Core.Net;

public sealed class SsrfExternalResourceFetcher : IExternalResourceFetcher, IDisposable
{
    private readonly HttpClient _client;

    public SsrfExternalResourceFetcher(HttpMessageHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        _client = new HttpClient(handler, disposeHandler: false)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    public SsrfExternalResourceFetcher()
        : this(CreateDefaultHandler())
    {
    }

    public async Task<ExternalResourceFetchResult> FetchAsync(
        ExternalResourceFetchRequest request,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(request.Uri);
        ArgumentException.ThrowIfNullOrWhiteSpace(request.Method);
        ArgumentNullException.ThrowIfNull(request.Body);
        ArgumentNullException.ThrowIfNull(request.AllowedResponseContentTypes);
        if (request.MaxResponseBytes <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(request));
        }

        SsrfDestinationGuard.EnsureAllowed(request.Uri);
        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(request.Timeout);
        using HttpRequestMessage message = new(new HttpMethod(request.Method), request.Uri);
        if (request.Body.Length > 0 || string.Equals(request.Method, "POST", StringComparison.OrdinalIgnoreCase))
        {
            ByteArrayContent content = new(request.Body);
            if (!string.IsNullOrWhiteSpace(request.ContentType))
            {
                content.Headers.ContentType = new MediaTypeHeaderValue(request.ContentType);
            }

            message.Content = content;
        }

        using HttpResponseMessage response = await _client
            .SendAsync(message, HttpCompletionOption.ResponseHeadersRead, timeout.Token)
            .ConfigureAwait(false);
        if ((int)response.StatusCode is >= 300 and < 400)
        {
            throw new InvalidOperationException("IMZAKIT.NET.REDIRECT_NOT_FOLLOWED");
        }

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                (int)response.StatusCode is 503 or 504
                    ? "IMZAKIT.NET.TRANSIENT_HTTP"
                    : "IMZAKIT.NET.HTTP_ERROR");
        }

        string? mediaType = response.Content.Headers.ContentType?.MediaType;
        if (string.IsNullOrWhiteSpace(mediaType) ||
            !request.AllowedResponseContentTypes.Any(allowed =>
                string.Equals(allowed, mediaType, StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("IMZAKIT.NET.UNEXPECTED_CONTENT_TYPE");
        }

        byte[] body = await response.Content.ReadAsByteArrayAsync(timeout.Token).ConfigureAwait(false);
        if (body.Length > request.MaxResponseBytes)
        {
            throw new InvalidOperationException("IMZAKIT.NET.PAYLOAD_TOO_LARGE");
        }

        return new ExternalResourceFetchResult(body, mediaType);
    }

    private static SocketsHttpHandler CreateDefaultHandler()
    {
        SocketsHttpHandler handler = new()
        {
            AllowAutoRedirect = false,
            ConnectTimeout = TimeSpan.FromSeconds(10)
        };
        handler.ConnectCallback = static async (context, cancellationToken) =>
        {
            IPAddress[] addresses = await Dns
                .GetHostAddressesAsync(context.DnsEndPoint.Host, cancellationToken)
                .ConfigureAwait(false);
            if (addresses.Length == 0)
            {
                throw new InvalidOperationException("IMZAKIT.NET.SSRF_BLOCKED");
            }

            foreach (IPAddress address in addresses)
            {
                SsrfDestinationGuard.EnsureAllowed(address);
            }

            Socket socket = new(SocketType.Stream, ProtocolType.Tcp);
            try
            {
                await socket
                    .ConnectAsync(addresses[0], context.DnsEndPoint.Port, cancellationToken)
                    .ConfigureAwait(false);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        };
        return handler;
    }

    public void Dispose() => _client.Dispose();
}
