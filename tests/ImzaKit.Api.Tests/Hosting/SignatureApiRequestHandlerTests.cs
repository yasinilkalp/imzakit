using System.Security.Cryptography;
using System.Text.Json;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class SignatureApiRequestHandlerTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("pdf"u8.ToArray()));

    [Fact]
    public void OpenApiContractContainsMvpOperationIds()
    {
        string yaml = OpenApiContract.ReadYaml();

        Assert.Contains("operationId: createSignatureOperation", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: createAgentTicket", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: createValidation", yaml, StringComparison.Ordinal);
        Assert.DoesNotContain("/signatures/extend", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public void UnauthenticatedCallerReceivesProblemDetailsWithCorrelation()
    {
        HandlerFixture fixture = new(authenticated: false);
        ApiHttpRequest request = HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(), correlationId: "corr-1");

        ApiHttpResponse response = fixture.Handler.Handle(request);

        Assert.Equal(401, response.StatusCode);
        Assert.Equal("application/problem+json", response.ContentType);
        Assert.Equal("corr-1", response.CorrelationId);
        Assert.Contains("IMZAKIT.CORE.UNAUTHENTICATED", response.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("tenantId", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingIdempotencyKeyIsUnprocessable()
    {
        HandlerFixture fixture = new();
        ApiHttpRequest request = HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(), idempotencyKey: null);

        ApiHttpResponse response = fixture.Handler.Handle(request);

        Assert.Equal(422, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.UNPROCESSABLE", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CreateUsesCallerIdentityAndDocumentReferenceNotEmbeddedPdf()
    {
        HandlerFixture fixture = new();
        string body = HandlerFixture.CreateBody(tenantInBody: "evil-tenant") + "\n";
        Assert.DoesNotContain("%PDF", body, StringComparison.Ordinal);

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signature-operations", body, idempotencyKey: "idempotency-key-01"));

        Assert.Equal(201, response.StatusCode);
        using JsonDocument json = JsonDocument.Parse(response.Body);
        Assert.Equal("Created", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(Digest, json.RootElement.GetProperty("documentDigest").GetString());
        Assert.NotEqual(Guid.Empty, json.RootElement.GetProperty("operationId").GetGuid());
    }

    [Fact]
    public void SameIdempotencyKeyAndBodyReplaysCreate()
    {
        HandlerFixture fixture = new();
        ApiHttpRequest request = HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(), idempotencyKey: "idempotency-key-01");
        ApiHttpResponse first = fixture.Handler.Handle(request);

        ApiHttpResponse replay = fixture.Handler.Handle(request);

        Assert.Equal(201, replay.StatusCode);
        Assert.Equal(first.Body, replay.Body);
    }

    [Fact]
    public void SameIdempotencyKeyDifferentBodyConflicts()
    {
        HandlerFixture fixture = new();
        fixture.Handler.Handle(HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(), idempotencyKey: "idempotency-key-01"));

        ApiHttpResponse conflict = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(size: 2048), idempotencyKey: "idempotency-key-01"));

        Assert.Equal(409, conflict.StatusCode);
        Assert.Contains("IMZAKIT.CORE.IDEMPOTENCY_CONFLICT", conflict.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void OversizedDocumentReferenceIsPayloadTooLarge()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signature-operations", HandlerFixture.CreateBody(size: 104_857_601), idempotencyKey: "idempotency-key-01"));

        Assert.Equal(413, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.PAYLOAD_TOO_LARGE", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void AgentTicketBindsCallerTenantAndIsAcceptedByValidator()
    {
        HandlerFixture fixture = new();
        Guid operationId = fixture.CreateOperation();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post($"/v1/signature-operations/{operationId:D}/agent-ticket", "", idempotencyKey: "idempotency-key-ticket", origin: "https://app.example"));

        Assert.Equal(200, response.StatusCode);
        using JsonDocument json = JsonDocument.Parse(response.Body);
        string ticket = json.RootElement.GetProperty("ticket").GetString()!;
        Assert.True(ticket.Length >= 32);
        AgentTicket decoded = AgentTicketCodec.Decode(ticket);
        Assert.Equal("tenant-1", decoded.TenantId);
        Assert.Equal("app-1", decoded.ApplicationId);
        Assert.Equal("https://app.example", decoded.Origin);
        Assert.Equal(AgentTicketValidationStatus.Passed, fixture.Validator.ValidateAndConsume(
            decoded, "https://app.example", Digest, "sign").Status);

        ApiHttpResponse get = fixture.Handler.Handle(HandlerFixture.Get($"/v1/signature-operations/{operationId:D}"));
        using JsonDocument operation = JsonDocument.Parse(get.Body);
        Assert.Equal("WaitingForClient", operation.RootElement.GetProperty("status").GetString());
    }

    [Fact]
    public void PrepareFromCreatedIsInvalidState()
    {
        HandlerFixture fixture = new();
        Guid operationId = fixture.CreateOperation();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post($"/v1/signature-operations/{operationId:D}/prepare", "", idempotencyKey: "idempotency-key-prepare"));

        Assert.Equal(409, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.INVALID_STATE_TRANSITION", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CertificatePrepareCompleteAndCancelFollowOpenApiStates()
    {
        HandlerFixture fixture = new();
        Guid operationId = fixture.CreateOperation();
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-operations/{operationId:D}/agent-ticket", "", idempotencyKey: "idempotency-key-ticket", origin: "https://app.example"));
        byte[] certificate = "certificate-der"u8.ToArray();
        string fingerprint = Convert.ToHexString(SHA256.HashData(certificate));

        ApiHttpResponse bound = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-operations/{operationId:D}/certificate",
            $$"""{"certificateDerBase64":"{{Convert.ToBase64String(certificate)}}","fingerprintSha256":"{{fingerprint}}"}""",
            idempotencyKey: "idempotency-key-cert"));
        Assert.Equal(200, bound.StatusCode);
        Assert.Contains("CertificateSelected", bound.Body, StringComparison.Ordinal);

        ApiHttpResponse prepared = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-operations/{operationId:D}/prepare", "", idempotencyKey: "idempotency-key-prepare"));
        Assert.Equal(200, prepared.StatusCode);
        using JsonDocument prepareJson = JsonDocument.Parse(prepared.Body);
        Assert.Equal("RSA-SHA256", prepareJson.RootElement.GetProperty("algorithm").GetString());
        string token = prepareJson.RootElement.GetProperty("completionToken").GetString()!;
        int version = prepareJson.RootElement.GetProperty("prepareVersion").GetInt32();

        ApiHttpResponse completed = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-operations/{operationId:D}/complete",
            $$"""{"prepareVersion":{{version}},"signatureValueBase64":"AAAA","completionToken":"{{token}}","certificateFingerprintSha256":"{{fingerprint}}"}""",
            idempotencyKey: "idempotency-key-complete"));
        Assert.Equal(200, completed.StatusCode);
        Assert.Contains("Signed", completed.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CancelFromCreatedSucceeds()
    {
        HandlerFixture fixture = new();
        Guid operationId = fixture.CreateOperation();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post($"/v1/signature-operations/{operationId:D}/cancel", "", idempotencyKey: "idempotency-key-cancel"));

        Assert.Equal(200, response.StatusCode);
        Assert.Contains("Cancelled", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void ValidationAcceptedWithoutOnlineRevocation()
    {
        HandlerFixture fixture = new();
        ApiHttpResponse created = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/validations", HandlerFixture.CreateValidationBody(), idempotencyKey: "idempotency-key-val"));

        Assert.Equal(202, created.StatusCode);
        using JsonDocument json = JsonDocument.Parse(created.Body);
        Assert.Equal("INDETERMINATE", json.RootElement.GetProperty("outcome").GetString());
        Assert.False(json.RootElement.GetProperty("onlineRevocationChecked").GetBoolean());
        Guid validationId = json.RootElement.GetProperty("validationId").GetGuid();

        ApiHttpResponse fetched = fixture.Handler.Handle(HandlerFixture.Get($"/v1/validations/{validationId:D}"));
        Assert.Equal(200, fetched.StatusCode);
        Assert.Contains(validationId.ToString("D"), fetched.Body, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void AgentCallbackWithoutMtlsIsUnauthorized()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/agent-callbacks/signature-results", "{}", idempotencyKey: "idempotency-key-cb"));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.AGENT.MTLS_REQUIRED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void OpenApiYamlIsServedWithoutAuthentication()
    {
        HandlerFixture fixture = new(authenticated: false);

        ApiHttpResponse response = fixture.Handler.Handle(HandlerFixture.Get("/v1/openapi.yaml"));

        Assert.Equal(200, response.StatusCode);
        Assert.Equal("application/yaml", response.ContentType);
        Assert.Contains("openapi: 3.1.0", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingOperationIsNotFound()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Get($"/v1/signature-operations/{Guid.NewGuid():D}"));

        Assert.Equal(404, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.NOT_FOUND", response.Body, StringComparison.Ordinal);
    }

    private sealed class HandlerFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());
        public SignatureApiRequestHandler Handler { get; }
        public AgentTicketValidator Validator { get; }

        public HandlerFixture(bool authenticated = true)
        {
            AgentTicketIssuer issuer = new(_privateKey.GetEncoded());
            Validator = new(issuer.PublicKey, new InMemoryNonceStore());
            Handler = new SignatureApiRequestHandler(
                new SignatureOperationService(new InMemoryIdempotencyStore()),
                new StaticApiCallerResolver(new ApiCallerIdentity(authenticated, "tenant-1", "app-1")),
                issuer);
        }

        public Guid CreateOperation()
        {
            ApiHttpResponse response = Handler.Handle(
                Post("/v1/signature-operations", CreateBody(), idempotencyKey: "idempotency-key-create"));
            using JsonDocument json = JsonDocument.Parse(response.Body);
            return json.RootElement.GetProperty("operationId").GetGuid();
        }

        public static string CreateBody(string? tenantInBody = null, long size = 1024) =>
            $$"""
            {"document":{"objectKey":"tenant-a/uploads/contract.pdf","sha256":"{{Digest}}","size":{{size}},"contentType":"application/pdf"},"format":"PAdES","targetLevel":"B-B","validationProfile":"TurkiyeNes"{{(tenantInBody is null ? "" : $",\"tenantId\":\"{tenantInBody}\"")}}}
            """;

        public static string CreateValidationBody() =>
            $$"""{"document":{"objectKey":"tenant-a/uploads/signed.pdf","sha256":"{{Digest}}","size":2048},"validationProfile":"TurkiyeNes"}""";

        public static ApiHttpRequest Post(
            string path,
            string body,
            string? idempotencyKey = "idempotency-key-01",
            string? correlationId = null,
            string? origin = null)
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

            if (origin is not null)
            {
                headers["Origin"] = origin;
            }

            return new ApiHttpRequest { Method = "POST", Path = path, Body = body, Headers = headers };
        }

        public static ApiHttpRequest Get(string path) => new()
        {
            Method = "GET",
            Path = path,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };
    }
}
