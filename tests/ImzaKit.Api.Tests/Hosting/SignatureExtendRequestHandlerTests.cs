using System.Security.Cryptography;
using System.Text.Json;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class SignatureExtendRequestHandlerTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("pdf"u8.ToArray()));

    [Fact]
    public void UnauthenticatedExtendIsRejected()
    {
        HandlerFixture fixture = new(authenticated: false);

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody(), correlationId: "corr-ext"));

        Assert.Equal(401, response.StatusCode);
        Assert.Equal("corr-ext", response.CorrelationId);
        Assert.Contains("IMZAKIT.CORE.UNAUTHENTICATED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingIdempotencyKeyIsUnprocessable()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody(), idempotencyKey: null));

        Assert.Equal(422, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.UNPROCESSABLE", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void BaselineBTargetIsRejected()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody(targetLevel: "B-B")));

        Assert.Equal(422, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.UNPROCESSABLE", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingDocumentIsNotFound()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody()));

        Assert.Equal(404, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.NOT_FOUND", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void SuccessfulExtendReturnsResultDocumentAndReplays()
    {
        SignatureExtensionResult payload = new(
            Guid.Parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            "B-B",
            "B-T",
            "tenant-a/extended.pdf",
            Digest,
            4096);
        HandlerFixture fixture = new(extensions: new ScriptedExtensionWorkflow(
            new SignatureExtensionOutcome(SignatureExtensionStatus.Succeeded, payload)));

        ApiHttpRequest request = HandlerFixture.Post(
            "/v1/signatures/extend",
            CreateExtendBody(),
            idempotencyKey: "idempotency-key-extend-01");
        ApiHttpResponse first = fixture.Handler.Handle(request);
        ApiHttpResponse replay = fixture.Handler.Handle(request);

        Assert.Equal(200, first.StatusCode);
        using JsonDocument json = JsonDocument.Parse(first.Body);
        Assert.Equal("B-B", json.RootElement.GetProperty("fromLevel").GetString());
        Assert.Equal("B-T", json.RootElement.GetProperty("toLevel").GetString());
        Assert.Equal("tenant-a/extended.pdf", json.RootElement.GetProperty("result").GetProperty("objectKey").GetString());
        Assert.Equal(200, replay.StatusCode);
        Assert.Equal(first.Body, replay.Body);
        Assert.Equal(1, fixture.Extensions.Calls);
    }

    [Fact]
    public void SameIdempotencyKeyWithDifferentBodyConflicts()
    {
        HandlerFixture fixture = new(extensions: new ScriptedExtensionWorkflow(
            new SignatureExtensionOutcome(
                SignatureExtensionStatus.Succeeded,
                new SignatureExtensionResult(Guid.NewGuid(), "B-B", "B-T", "k", Digest, 1))));

        fixture.Handler.Handle(HandlerFixture.Post(
            "/v1/signatures/extend",
            CreateExtendBody(targetLevel: "B-T"),
            idempotencyKey: "idempotency-key-extend-02"));
        ApiHttpResponse conflict = fixture.Handler.Handle(HandlerFixture.Post(
            "/v1/signatures/extend",
            CreateExtendBody(targetLevel: "B-LT"),
            idempotencyKey: "idempotency-key-extend-02"));

        Assert.Equal(409, conflict.StatusCode);
        Assert.Contains("IMZAKIT.CORE.IDEMPOTENCY_CONFLICT", conflict.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void UnsupportedTransitionIsUnprocessable()
    {
        HandlerFixture fixture = new(extensions: new ScriptedExtensionWorkflow(
            new SignatureExtensionOutcome(SignatureExtensionStatus.UnsupportedTransition)));

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody()));

        Assert.Equal(422, response.StatusCode);
    }

    [Fact]
    public void TimeStampFailureIsRetryableServiceUnavailable()
    {
        HandlerFixture fixture = new(extensions: new ScriptedExtensionWorkflow(
            new SignatureExtensionOutcome(SignatureExtensionStatus.DependencyUnavailable)));

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signatures/extend", CreateExtendBody()));

        Assert.Equal(503, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.DEPENDENCY_UNAVAILABLE", response.Body, StringComparison.Ordinal);
        Assert.Contains("\"retryable\":true", response.Body, StringComparison.Ordinal);
    }

    private static string CreateExtendBody(string targetLevel = "B-T") =>
        $$"""
        {"document":{"objectKey":"tenant-a/uploads/signed.pdf","sha256":"{{Digest}}","size":2048},"targetLevel":"{{targetLevel}}","validationProfile":"TurkiyeNes","timeStampAuthorities":[{"name":"primary","url":"https://tsa.example/rfc3161"}]}
        """;

    private sealed class HandlerFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
        public SignatureApiRequestHandler Handler { get; }
        public ScriptedExtensionWorkflow Extensions { get; }

        public HandlerFixture(bool authenticated = true, ISignatureExtensionWorkflow? extensions = null)
        {
            Extensions = extensions as ScriptedExtensionWorkflow
                ?? new ScriptedExtensionWorkflow(new(SignatureExtensionStatus.DocumentNotFound));
            AgentTicketIssuer issuer = new(_privateKey.GetEncoded());
            Handler = new SignatureApiRequestHandler(
                new SignatureOperationService(new InMemoryIdempotencyStore()),
                new StaticApiCallerResolver(new ApiCallerIdentity(authenticated, "tenant-1", "app-1")),
                issuer,
                extensions: extensions ?? Extensions);
        }

        public static ApiHttpRequest Post(
            string path,
            string body,
            string? idempotencyKey = "idempotency-key-01",
            string? correlationId = null)
        {
            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            if (idempotencyKey is not null)
            {
                headers["Idempotency-Key"] = idempotencyKey;
            }

            if (correlationId is not null)
            {
                headers["X-Correlation-Id"] = correlationId;
            }

            return new ApiHttpRequest { Method = "POST", Path = path, Body = body, Headers = headers };
        }
    }

    private sealed class ScriptedExtensionWorkflow(SignatureExtensionOutcome next) : ISignatureExtensionWorkflow
    {
        public int Calls { get; private set; }

        public SignatureExtensionOutcome Extend(SignatureExtensionRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            Calls++;
            return next;
        }
    }
}
