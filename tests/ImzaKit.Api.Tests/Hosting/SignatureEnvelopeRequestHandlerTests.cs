using System.Security.Cryptography;
using System.Text.Json;
using ImzaKit.Agent.Security;
using ImzaKit.Api.Hosting;
using ImzaKit.Api.Idempotency;
using ImzaKit.Api.Operations;
using ImzaKit.Api.Workflow;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ImzaKit.Api.Tests.Hosting;

public sealed class SignatureEnvelopeRequestHandlerTests
{
    private static readonly string Digest = Convert.ToHexString(SHA256.HashData("pdf"u8.ToArray()));
    private static readonly string AfterFirst = Convert.ToHexString(SHA256.HashData("after-first"u8.ToArray()));
    private static readonly string FingerprintA = new string('A', 64);
    private static readonly string FingerprintB = new string('B', 64);

    [Fact]
    public void OpenApiContractContainsEnvelopeOperationIds()
    {
        string yaml = OpenApiContract.ReadYaml();

        Assert.Contains("operationId: createSignatureEnvelope", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: getSignatureEnvelope", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: getSignatureEnvelopeReport", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: prepareSignatureEnvelopeStep", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: completeSignatureEnvelopeStep", yaml, StringComparison.Ordinal);
        Assert.Contains("operationId: rejectSignatureEnvelopeStep", yaml, StringComparison.Ordinal);
        Assert.Contains("/signature-envelopes", yaml, StringComparison.Ordinal);
    }

    [Fact]
    public void UnauthenticatedCreateIsRejected()
    {
        HandlerFixture fixture = new(authenticated: false);

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signature-envelopes", CreateEnvelopeBody(), correlationId: "corr-env"));

        Assert.Equal(401, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.UNAUTHENTICATED", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingIdempotencyKeyIsUnprocessable()
    {
        HandlerFixture fixture = new();

        ApiHttpResponse response = fixture.Handler.Handle(
            HandlerFixture.Post("/v1/signature-envelopes", CreateEnvelopeBody(), idempotencyKey: null));

        Assert.Equal(422, response.StatusCode);
        Assert.Contains("IMZAKIT.CORE.UNPROCESSABLE", response.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void SerialSecondPrepareBeforeCompleteIsNotReady()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateSerialEnvelope();

        ApiHttpResponse first = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-prep-0"));
        ApiHttpResponse tooEarly = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-prep-1"));

        Assert.Equal(200, first.StatusCode);
        Assert.Equal(409, tooEarly.StatusCode);
        Assert.Contains(WorkflowProblemCodes.StepNotReady, tooEarly.Body, StringComparison.Ordinal);
        using JsonDocument json = JsonDocument.Parse(first.Body);
        Assert.Equal("Prepared", json.RootElement.GetProperty("steps")[0].GetProperty("status").GetString());
        Assert.Equal(Digest, json.RootElement.GetProperty("steps")[0].GetProperty("approvedDigestSha256").GetString());
    }

    [Fact]
    public void SerialCompleteThenNextPrepareBindsRevisionDigest()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateSerialEnvelope();
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-prep-a"));
        ApiHttpResponse completed = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/complete",
            CompleteBody(FingerprintA, AfterFirst, 1),
            idempotencyKey: "idempotency-key-env-complete-0"));
        ApiHttpResponse second = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-prep-b"));

        Assert.Equal(200, completed.StatusCode);
        Assert.Equal(200, second.StatusCode);
        using JsonDocument json = JsonDocument.Parse(second.Body);
        Assert.Equal(AfterFirst, json.RootElement.GetProperty("currentDocumentSha256").GetString());
        Assert.Equal(AfterFirst, json.RootElement.GetProperty("steps")[1].GetProperty("approvedDigestSha256").GetString());
        Assert.Equal(Digest, json.RootElement.GetProperty("approvedDocumentSha256").GetString());
    }

    [Fact]
    public void ParallelPrepareBindsTheSameApprovedDigest()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateEnvelope(flow: "Parallel");

        ApiHttpResponse first = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-par-0"));
        ApiHttpResponse second = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-par-1"));

        Assert.Equal(200, first.StatusCode);
        Assert.Equal(200, second.StatusCode);
        using JsonDocument firstJson = JsonDocument.Parse(first.Body);
        using JsonDocument secondJson = JsonDocument.Parse(second.Body);
        Assert.Equal(Digest, firstJson.RootElement.GetProperty("steps")[0].GetProperty("approvedDigestSha256").GetString());
        Assert.Equal(Digest, secondJson.RootElement.GetProperty("steps")[1].GetProperty("approvedDigestSha256").GetString());
    }

    [Fact]
    public void DuplicateSignerFingerprintIsRejected()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateSerialEnvelope();
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-dup-p0"));
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/complete",
            CompleteBody(FingerprintA, AfterFirst, 1),
            idempotencyKey: "idempotency-key-env-dup-c0"));
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-dup-p1"));
        ApiHttpResponse duplicate = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/complete",
            CompleteBody(FingerprintA, Convert.ToHexString(SHA256.HashData("d2"u8.ToArray())), 2),
            idempotencyKey: "idempotency-key-env-dup-c1"));

        Assert.Equal(422, duplicate.StatusCode);
        Assert.Contains(WorkflowProblemCodes.DuplicateSigner, duplicate.Body, StringComparison.Ordinal);
    }

    [Fact]
    public void ReportListsSigningOrderAndSubsequentChangeSemantics()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateEnvelope(flow: "Parallel");
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-rep-p0"));
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-rep-p1"));
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/1/complete",
            CompleteBody(FingerprintB, Digest, 2),
            idempotencyKey: "idempotency-key-env-rep-c1"));
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/complete",
            CompleteBody(FingerprintA, Digest, 1),
            idempotencyKey: "idempotency-key-env-rep-c0"));

        ApiHttpResponse report = fixture.Handler.Handle(
            HandlerFixture.Get($"/v1/signature-envelopes/{envelopeId:D}/report"));

        Assert.Equal(200, report.StatusCode);
        using JsonDocument json = JsonDocument.Parse(report.Body);
        JsonElement signatures = json.RootElement.GetProperty("signatures");
        Assert.Equal(2, signatures.GetArrayLength());
        Assert.Equal(1, signatures[0].GetProperty("order").GetInt32());
        Assert.Equal("reviewer", signatures[0].GetProperty("role").GetString());
        Assert.Equal(2, signatures[0].GetProperty("coveredRevision").GetInt32());
        Assert.Equal(
            SubsequentChangeSemantics.LaterRevisionsDoNotInvalidatePriorCrypto,
            signatures[0].GetProperty("subsequentChangeSemantics").GetString());
        Assert.Equal("approver", signatures[1].GetProperty("role").GetString());
    }

    [Fact]
    public void CreateReplaysWithTheSameIdempotencyKey()
    {
        HandlerFixture fixture = new();
        ApiHttpRequest request = HandlerFixture.Post(
            "/v1/signature-envelopes",
            CreateEnvelopeBody(),
            idempotencyKey: "idempotency-key-env-create");
        ApiHttpResponse first = fixture.Handler.Handle(request);
        ApiHttpResponse replay = fixture.Handler.Handle(request);

        Assert.Equal(201, first.StatusCode);
        Assert.Equal(201, replay.StatusCode);
        Assert.Equal(first.Body, replay.Body);
    }

    [Fact]
    public void RejectionCancelsRemainingSteps()
    {
        HandlerFixture fixture = new();
        Guid envelopeId = fixture.CreateSerialEnvelope();
        fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/prepare",
            "{}",
            idempotencyKey: "idempotency-key-env-rej-p"));
        ApiHttpResponse rejected = fixture.Handler.Handle(HandlerFixture.Post(
            $"/v1/signature-envelopes/{envelopeId:D}/steps/0/reject",
            "{}",
            idempotencyKey: "idempotency-key-env-rej"));

        Assert.Equal(200, rejected.StatusCode);
        using JsonDocument json = JsonDocument.Parse(rejected.Body);
        Assert.Equal("Rejected", json.RootElement.GetProperty("status").GetString());
        Assert.Equal("Rejected", json.RootElement.GetProperty("steps")[0].GetProperty("status").GetString());
        Assert.Equal("Cancelled", json.RootElement.GetProperty("steps")[1].GetProperty("status").GetString());
    }

    private static string CreateEnvelopeBody(string flow = "Serial") =>
        $$"""
        {"document":{"objectKey":"tenant-a/uploads/contract.pdf","sha256":"{{Digest}}","size":1024,"contentType":"application/pdf"},"flow":"{{flow}}","mergeStrategy":"SequentialRevisions","policy":{"requiredRoles":["approver","reviewer"],"rejection":"CancelEnvelope","duplicateSigner":"Reject"}
        }
        """;

    private static string CompleteBody(string fingerprint, string signedDigest, int revision) =>
        $$"""{"certificateFingerprintSha256":"{{fingerprint}}","signedDocumentSha256":"{{signedDigest}}","coveredRevision":{{revision}}}""";

    private sealed class HandlerFixture
    {
        public SignatureApiRequestHandler Handler { get; }

        public HandlerFixture(bool authenticated = true)
        {
            Ed25519PrivateKeyParameters privateKey = new(new SecureRandom());
            Handler = new SignatureApiRequestHandler(
                new SignatureOperationService(new InMemoryIdempotencyStore()),
                new StaticApiCallerResolver(new ApiCallerIdentity(authenticated, "tenant-1", "app-1")),
                new AgentTicketIssuer(privateKey.GetEncoded()));
        }

        public Guid CreateSerialEnvelope() => CreateEnvelope("Serial");

        public Guid CreateEnvelope(string flow)
        {
            ApiHttpResponse response = Handler.Handle(
                Post("/v1/signature-envelopes", CreateEnvelopeBody(flow), idempotencyKey: "idempotency-key-env-create"));
            using JsonDocument json = JsonDocument.Parse(response.Body);
            return json.RootElement.GetProperty("envelopeId").GetGuid();
        }

        public static ApiHttpRequest Post(
            string path,
            string body,
            string? idempotencyKey = "idempotency-key-01",
            string? correlationId = null) =>
            new()
            {
                Method = "POST",
                Path = path,
                Body = body,
                Headers = Headers(idempotencyKey, correlationId)
            };

        public static ApiHttpRequest Get(string path) => new()
        {
            Method = "GET",
            Path = path,
            Headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        };

        private static Dictionary<string, string> Headers(string? idempotencyKey, string? correlationId)
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

            return headers;
        }
    }
}
