using System.Security.Cryptography;
using System.Text.Json;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class SignatureApiOwnershipTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("pdf"u8.ToArray()));

    [Fact]
    public void OperationOfAnotherTenantIsInvisibleAndImmutable()
    {
        OwnershipFixture fixture = new();
        Guid operationId = fixture.CreateOperation("tenant-a");

        fixture.Caller.TenantId = "tenant-b";
        ApiHttpResponse get = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-operations/{operationId:D}"));
        ApiHttpResponse cancel = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-operations/{operationId:D}/cancel", "", "idempotency-key-cancel-b"));
        ApiHttpResponse ticket = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-operations/{operationId:D}/agent-ticket", "", "idempotency-key-ticket-b", origin: "https://evil.example"));

        Assert.Equal(404, get.StatusCode);
        Assert.Equal(404, cancel.StatusCode);
        Assert.Equal(404, ticket.StatusCode);
        fixture.Caller.TenantId = "tenant-a";
        ApiHttpResponse owner = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-operations/{operationId:D}"));
        Assert.Equal(200, owner.StatusCode);
        Assert.Contains("\"status\":\"Created\"", owner.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void SameIdempotencyKeyInAnotherTenantDoesNotReplayForeignOperation()
    {
        OwnershipFixture fixture = new();
        Guid first = fixture.CreateOperation("tenant-a");

        Guid second = fixture.CreateOperation("tenant-b");

        Assert.NotEqual(first, second);
    }

    [Fact]
    public void ValidationOfAnotherTenantIsNotFound()
    {
        OwnershipFixture fixture = new();
        ApiHttpResponse created = fixture.Handler.Handle(OwnershipFixture.Post(
            "/v1/validations",
            $$"""{"document":{"objectKey":"tenant-a/uploads/signed.pdf","sha256":"{{Digest}}","size":2048},"validationProfile":"TurkiyeNes"}""",
            "idempotency-key-validation"));
        using JsonDocument json = JsonDocument.Parse(created.Body);
        Guid validationId = json.RootElement.GetProperty("validationId").GetGuid();

        fixture.Caller.TenantId = "tenant-b";
        ApiHttpResponse foreign = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/validations/{validationId:D}"));

        Assert.Equal(404, foreign.StatusCode);
    }

    [Fact]
    public void EnvelopeOfAnotherTenantIsInvisibleAndImmutable()
    {
        OwnershipFixture fixture = new();
        ApiHttpResponse created = fixture.Handler.Handle(OwnershipFixture.Post(
            "/v1/signature-envelopes",
            $$$"""{"document":{"sha256":"{{{Digest}}}"},"flow":"Serial","mergeStrategy":"SequentialRevisions","policy":{"requiredRoles":["approver","reviewer"],"rejection":"CancelEnvelope","duplicateSigner":"Reject"}}""",
            "idempotency-key-envelope"));
        Assert.Equal(201, created.StatusCode);
        using JsonDocument json = JsonDocument.Parse(created.Body);
        Guid envelopeId = json.RootElement.GetProperty("envelopeId").GetGuid();

        fixture.Caller.TenantId = "tenant-b";
        ApiHttpResponse get = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-envelopes/{envelopeId:D}"));
        ApiHttpResponse report = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-envelopes/{envelopeId:D}/report"));
        ApiHttpResponse reject = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/reject", "", "idempotency-key-reject-b"));

        Assert.Equal(404, get.StatusCode);
        Assert.Equal(404, report.StatusCode);
        Assert.Equal(404, reject.StatusCode);
        fixture.Caller.TenantId = "tenant-a";
        ApiHttpResponse owner = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-envelopes/{envelopeId:D}"));
        Assert.DoesNotContain("Rejected", owner.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CompletionTokenOfAnotherOperationIsRejected()
    {
        OwnershipFixture fixture = new();
        PreparedOperation donor = fixture.PrepareOperation("donor");
        PreparedOperation target = fixture.PrepareOperation("target");

        ApiHttpResponse response = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-operations/{target.OperationId:D}/complete",
            OwnershipFixture.CompleteBody(donor.Version, donor.Token, donor.Fingerprint),
            "idempotency-key-complete-cross"));

        Assert.Equal(422, response.StatusCode);
        ApiHttpResponse state = fixture.Handler.Handle(OwnershipFixture.Get($"/v1/signature-operations/{target.OperationId:D}"));
        Assert.Contains("\"status\":\"Prepared\"", state.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void CompletionTokenIsSingleUseButReplaysUnderSameIdempotencyKey()
    {
        OwnershipFixture fixture = new();
        PreparedOperation prepared = fixture.PrepareOperation("single");
        ApiHttpRequest complete = OwnershipFixture.Post(
            $"/v1/signature-operations/{prepared.OperationId:D}/complete",
            OwnershipFixture.CompleteBody(prepared.Version, prepared.Token, prepared.Fingerprint),
            "idempotency-key-complete-01");

        ApiHttpResponse first = fixture.Handler.Handle(complete);
        ApiHttpResponse replay = fixture.Handler.Handle(complete);
        ApiHttpResponse reuse = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-operations/{prepared.OperationId:D}/complete",
            OwnershipFixture.CompleteBody(prepared.Version, prepared.Token, prepared.Fingerprint),
            "idempotency-key-complete-02"));

        Assert.Equal(200, first.StatusCode);
        Assert.Contains("Signed", first.Body, StringComparison.Ordinal);
        Assert.Equal(200, replay.StatusCode);
        Assert.Equal(first.Body, replay.Body);
        Assert.Equal(422, reuse.StatusCode);
    }

    [Fact]
    public void ExpiredCompletionTokenIsRejected()
    {
        OwnershipFixture fixture = new();
        PreparedOperation prepared = fixture.PrepareOperation("expired");
        fixture.Clock.Advance(TimeSpan.FromMinutes(6));

        ApiHttpResponse response = fixture.Handler.Handle(OwnershipFixture.Post(
            $"/v1/signature-operations/{prepared.OperationId:D}/complete",
            OwnershipFixture.CompleteBody(prepared.Version, prepared.Token, prepared.Fingerprint),
            "idempotency-key-complete-late"));

        Assert.Equal(422, response.StatusCode);
    }

    private sealed record PreparedOperation(Guid OperationId, string Token, int Version, string Fingerprint);

    private sealed class OwnershipFixture
    {
        private readonly Ed25519PrivateKeyParameters _privateKey = new(new SecureRandom());

        public SignatureApiRequestHandler Handler { get; }
        public SwitchableApiCallerResolver Caller { get; } = new();
        public ManualTimeProvider Clock { get; } = new(DateTimeOffset.UtcNow);

        public OwnershipFixture()
        {
            Handler = new SignatureApiRequestHandler(
                new SignatureOperationService(new InMemoryIdempotencyStore()),
                Caller,
                new AgentTicketIssuer(_privateKey.GetEncoded()),
                timeProvider: Clock);
        }

        public Guid CreateOperation(string tenantId, string idempotencyKey = "idempotency-key-create")
        {
            Caller.TenantId = tenantId;
            ApiHttpResponse response = Handler.Handle(Post(
                "/v1/signature-operations",
                $$"""{"document":{"objectKey":"tenant-a/uploads/contract.pdf","sha256":"{{Digest}}","size":1024,"contentType":"application/pdf"},"format":"PAdES","targetLevel":"B-B","validationProfile":"TurkiyeNes"}""",
                idempotencyKey));
            Assert.Equal(201, response.StatusCode);
            using JsonDocument json = JsonDocument.Parse(response.Body);
            return json.RootElement.GetProperty("operationId").GetGuid();
        }

        public PreparedOperation PrepareOperation(string name)
        {
            Guid operationId = CreateOperation("tenant-a", $"idempotency-key-create-{name}");
            Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/agent-ticket", "", $"idempotency-key-ticket-{name}", origin: "https://app.example"));
            byte[] certificate = "certificate-der"u8.ToArray();
            string fingerprint = Convert.ToHexString(SHA256.HashData(certificate));
            Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/certificate",
                $$"""{"certificateDerBase64":"{{Convert.ToBase64String(certificate)}}","fingerprintSha256":"{{fingerprint}}"}""",
                $"idempotency-key-cert-{name}"));
            ApiHttpResponse prepared = Handler.Handle(Post(
                $"/v1/signature-operations/{operationId:D}/prepare", "", $"idempotency-key-prepare-{name}"));
            Assert.Equal(200, prepared.StatusCode);
            using JsonDocument json = JsonDocument.Parse(prepared.Body);
            return new PreparedOperation(
                operationId,
                json.RootElement.GetProperty("completionToken").GetString()!,
                json.RootElement.GetProperty("prepareVersion").GetInt32(),
                fingerprint);
        }

        public static string CompleteBody(int version, string token, string fingerprint) =>
            $$"""{"prepareVersion":{{version}},"signatureValueBase64":"AAAA","completionToken":"{{token}}","certificateFingerprintSha256":"{{fingerprint}}"}""";

        public static ApiHttpRequest Post(string path, string body, string idempotencyKey, string? origin = null)
        {
            Dictionary<string, string> headers = new(StringComparer.OrdinalIgnoreCase)
            {
                ["Idempotency-Key"] = idempotencyKey
            };
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

    private sealed class SwitchableApiCallerResolver : IApiCallerResolver
    {
        public string TenantId { get; set; } = "tenant-a";

        public ApiCallerIdentity Resolve(ApiHttpRequest request)
        {
            ArgumentNullException.ThrowIfNull(request);
            return new ApiCallerIdentity(true, TenantId, "app-1");
        }
    }

    private sealed class ManualTimeProvider(DateTimeOffset now) : TimeProvider
    {
        private DateTimeOffset _now = now;

        public void Advance(TimeSpan delta) => _now += delta;

        public override DateTimeOffset GetUtcNow() => _now;
    }
}
