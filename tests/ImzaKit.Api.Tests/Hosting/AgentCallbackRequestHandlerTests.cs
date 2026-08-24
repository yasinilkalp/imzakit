using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using ImzaKit.Agent.Mtls;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Mtls;
using ImzaKit.Api.Operations;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class AgentCallbackRequestHandlerTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("pdf"u8.ToArray()));

    [Fact]
    public void CallbackWithoutClientCertificateIsMtlsRequiredEvenWhenUnauthenticated()
    {
        CallbackFixture fixture = new(oauthAuthenticated: false);

        ApiHttpResponse response = fixture.Handler.Handle(
            CallbackFixture.Post("/v1/agent-callbacks/signature-results", "{}", idempotencyKey: "idempotency-key-cb"));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.AGENT.MTLS_REQUIRED", response.Body, StringComparison.Ordinal);
        Assert.DoesNotContain("IMZAKIT.CORE.UNAUTHENTICATED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownClientCertificateIsRejected()
    {
        CallbackFixture fixture = new();
        using ECDsa foreign = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        CertificateRequest request = new("CN=stranger", foreign, HashAlgorithmName.SHA256);
        using X509Certificate2 stranger = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

        ApiHttpResponse response = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            "{}",
            idempotencyKey: "idempotency-key-cb",
            clientCertificateDer: stranger.Export(X509ContentType.Cert)));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.AGENT.DEVICE_UNKNOWN", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void PreparedOperationCompletesOverMtlsWithoutOauthAndWithoutPrivateKeyInBody()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        fixture.Caller.Authenticated = false;
        string body = CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint);
        Assert.DoesNotContain("BEGIN", body, StringComparison.Ordinal);
        Assert.DoesNotContain("PRIVATE", body, StringComparison.Ordinal);
        Assert.DoesNotContain("pin", body, StringComparison.OrdinalIgnoreCase);

        ApiHttpResponse response = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            body,
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer));

        Assert.Equal(200, response.StatusCode);
        using JsonDocument json = JsonDocument.Parse(response.Body);
        Assert.Equal("Signed", json.RootElement.GetProperty("status").GetString());
        Assert.Equal(prepared.OperationId, json.RootElement.GetProperty("operationId").GetGuid());
    }

    [Fact]
    public void DuplicateCallbackReplaysWithoutNewArtifact()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        ApiHttpRequest request = CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer);

        ApiHttpResponse first = fixture.Handler.Handle(request);
        ApiHttpResponse replay = fixture.Handler.Handle(request);

        Assert.Equal(200, first.StatusCode);
        Assert.Equal(200, replay.StatusCode);
        Assert.Equal(first.Body, replay.Body);
    }

    [Fact]
    public void DuplicateCallbackWithDifferentBodyConflicts()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer));

        ApiHttpResponse conflict = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint, signature: "BBBB"),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer));

        Assert.Equal(409, conflict.StatusCode);
        Assert.Contains("IMZAKIT.CORE.IDEMPOTENCY_CONFLICT", conflict.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void RevokedDeviceCannotCallback()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        fixture.Devices.Revoke(prepared.DeviceId);

        ApiHttpResponse response = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.AGENT.DEVICE_REVOKED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void TicketBoundToAnotherTenantIsRejected()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        using AgentDeviceIdentity otherDevice = AgentDeviceIdentity.Create();
        EnrollmentToken token = fixture.Devices.IssueAdminToken("tenant-other", "app-other");
        DeviceEnrollmentResult enrolled = fixture.Devices.Enroll(token.Value, otherDevice.ExportSubjectPublicKeyInfo());

        ApiHttpResponse response = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: enrolled.CertificateDer));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.AGENT.TICKET_REJECTED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void AgentNonceConsumptionDoesNotBlockApiCallback()
    {
        CallbackFixture fixture = new();
        PreparedCallback prepared = fixture.PrepareOperation();
        AgentTicket decoded = AgentTicketCodec.Decode(prepared.Ticket);
        Assert.Equal(AgentTicketValidationStatus.Passed, fixture.AgentValidator.ValidateAndConsume(
            decoded, decoded.Origin, decoded.DocumentSha256, "sign").Status);

        ApiHttpResponse response = fixture.Handler.Handle(CallbackFixture.Post(
            "/v1/agent-callbacks/signature-results",
            CallbackFixture.CallbackBody(prepared.OperationId, prepared.Ticket, prepared.Fingerprint),
            idempotencyKey: "idempotency-key-callback",
            clientCertificateDer: prepared.ClientCertificateDer));

        Assert.Equal(200, response.StatusCode);
        Assert.Contains("Signed", response.Body, StringComparison.Ordinal);
    }

    private sealed class CallbackFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());

        public SignatureApiRequestHandler Handler { get; }
        public DeviceEnrollmentAuthority Devices { get; } = new();
        public AgentTicketValidator AgentValidator { get; }
        public MutableApiCallerResolver Caller { get; }

        public CallbackFixture(bool oauthAuthenticated = true)
        {
            AgentTicketIssuer issuer = new(_privateKey.GetEncoded());
            AgentValidator = new(issuer.PublicKey, new InMemoryNonceStore());
            Caller = new MutableApiCallerResolver(oauthAuthenticated);
            Handler = new SignatureApiRequestHandler(
                new SignatureOperationService(new InMemoryIdempotencyStore()),
                Caller,
                issuer,
                devices: Devices);
        }

        public PreparedCallback PrepareOperation()
        {
            using AgentDeviceIdentity device = AgentDeviceIdentity.Create();
            EnrollmentToken token = Devices.IssueAdminToken("tenant-1", "app-1");
            DeviceEnrollmentResult enrolled = Devices.Enroll(token.Value, device.ExportSubjectPublicKeyInfo());

            ApiHttpResponse created = Handler.Handle(
                Post("/v1/signature-operations", CreateBody(), idempotencyKey: "idempotency-key-create"));
            using JsonDocument createdJson = JsonDocument.Parse(created.Body);
            Guid operationId = createdJson.RootElement.GetProperty("operationId").GetGuid();

            ApiHttpResponse ticketResponse = Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/agent-ticket",
                "",
                idempotencyKey: "idempotency-key-ticket",
                origin: "https://app.example"));
            using JsonDocument ticketJson = JsonDocument.Parse(ticketResponse.Body);
            string ticket = ticketJson.RootElement.GetProperty("ticket").GetString()!;

            byte[] certificate = "certificate-der"u8.ToArray();
            string fingerprint = Convert.ToHexString(SHA256.HashData(certificate));
            Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/certificate",
                $$"""{"certificateDerBase64":"{{Convert.ToBase64String(certificate)}}","fingerprintSha256":"{{fingerprint}}"}""",
                idempotencyKey: "idempotency-key-cert"));
            Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/prepare",
                "",
                idempotencyKey: "idempotency-key-prepare"));

            return new PreparedCallback(operationId, ticket, fingerprint, enrolled.CertificateDer!, enrolled.Device!.DeviceId);
        }

        public static string CallbackBody(
            Guid operationId,
            string ticket,
            string fingerprint,
            string signature = "AAAA") =>
            $$"""{"operationId":"{{operationId:D}}","ticket":"{{ticket}}","signatureValueBase64":"{{signature}}","certificateFingerprintSha256":"{{fingerprint}}"}""";

        public static string CreateBody() =>
            $$"""
            {"document":{"objectKey":"tenant-a/uploads/contract.pdf","sha256":"{{Digest}}","size":1024,"contentType":"application/pdf"},"format":"PAdES","targetLevel":"B-B","validationProfile":"TurkiyeNes"}
            """;

        public static ApiHttpRequest Post(
            string path,
            string body,
            string? idempotencyKey = "idempotency-key-01",
            string? origin = null,
            byte[]? clientCertificateDer = null)
        {
            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase);
            if (idempotencyKey is not null)
            {
                headers["Idempotency-Key"] = idempotencyKey;
            }

            if (origin is not null)
            {
                headers["Origin"] = origin;
            }

            return new ApiHttpRequest
            {
                Method = "POST",
                Path = path,
                Body = body,
                Headers = headers,
                ClientCertificateDer = clientCertificateDer,
                HasMutualTlsClientCertificate = clientCertificateDer is { Length: > 0 }
            };
        }
    }

    private sealed record PreparedCallback(
        Guid OperationId,
        string Ticket,
        string Fingerprint,
        byte[] ClientCertificateDer,
        Guid DeviceId);

    private sealed class MutableApiCallerResolver(bool authenticated) : IApiCallerResolver
    {
        public bool Authenticated { get; set; } = authenticated;

        public ApiCallerIdentity Resolve(ApiHttpRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            return new ApiCallerIdentity(Authenticated, "tenant-1", "app-1");
        }
    }
}
