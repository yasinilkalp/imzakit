using System.Net;
using System.Net.Http;
using ImzaKit.Core.Net;

namespace ImzaKit.Core.Tests.Net;

public sealed class SsrfExternalResourceFetcherTests
{
    [Fact]
    public async Task FetchRejectsLoopbackWithoutSending()
    {
        RecordingHandler handler = new(new HttpResponseMessage(HttpStatusCode.OK));
        SsrfExternalResourceFetcher fetcher = new(handler);

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            fetcher.FetchAsync(Get(new Uri("http://127.0.0.1/tsa")), CancellationToken.None));

        Assert.Equal("IMZAKIT.NET.SSRF_BLOCKED", error.Message);
        Assert.Equal(0, handler.Calls);
    }

    [Fact]
    public async Task FetchPostsBodyToPublicHttpsHost()
    {
        RecordingHandler handler = new(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent([0x30, 0x03] )
            {
                Headers = { ContentType = new("application/timestamp-reply") }
            }
        });
        SsrfExternalResourceFetcher fetcher = new(handler);
        ExternalResourceFetchRequest request = new(
            new Uri("https://tsa.example/rfc3161"),
            "POST",
            [0x30, 0x01],
            "application/timestamp-query",
            ["application/timestamp-reply"],
            MaxResponseBytes: 64,
            Timeout: TimeSpan.FromSeconds(5),
            MaxRedirects: 0);

        ExternalResourceFetchResult result = await fetcher.FetchAsync(request, CancellationToken.None);

        Assert.Equal(1, handler.Calls);
        Assert.Equal("POST", handler.LastMethod);
        Assert.Equal(new byte[] { 0x30, 0x01 }, handler.LastBody);
        Assert.Equal(new byte[] { 0x30, 0x03 }, result.Body);
        Assert.Equal("application/timestamp-reply", result.ContentType);
    }

    [Fact]
    public async Task FetchRejectsUnexpectedContentType()
    {
        RecordingHandler handler = new(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("html") { Headers = { ContentType = new("text/html") } }
        });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SsrfExternalResourceFetcher(handler).FetchAsync(
                Get(new Uri("https://tsa.example/rfc3161"), allowed: ["application/timestamp-reply"]),
                CancellationToken.None));

        Assert.Equal("IMZAKIT.NET.UNEXPECTED_CONTENT_TYPE", error.Message);
    }

    [Fact]
    public async Task FetchRejectsOversizedResponse()
    {
        RecordingHandler handler = new(new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new ByteArrayContent(new byte[8])
            {
                Headers = { ContentType = new("application/timestamp-reply") }
            }
        });

        InvalidOperationException error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            new SsrfExternalResourceFetcher(handler).FetchAsync(
                Get(new Uri("https://tsa.example/rfc3161"), maxBytes: 4),
                CancellationToken.None));

        Assert.Equal("IMZAKIT.NET.PAYLOAD_TOO_LARGE", error.Message);
    }

    private static ExternalResourceFetchRequest Get(
        Uri uri,
        IReadOnlyList<string>? allowed = null,
        int maxBytes = 1024) =>
        new(
            uri,
            "GET",
            [],
            ContentType: null,
            AllowedResponseContentTypes: allowed ?? ["application/timestamp-reply"],
            maxBytes,
            TimeSpan.FromSeconds(5),
            MaxRedirects: 0);

    private sealed class RecordingHandler(HttpResponseMessage response) : HttpMessageHandler
    {
        public int Calls { get; private set; }

        public string? LastMethod { get; private set; }

        public byte[]? LastBody { get; private set; }

        protected override async Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Calls++;
            LastMethod = request.Method.Method;
            LastBody = request.Content is null
                ? null
                : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            return response;
        }
    }
}
