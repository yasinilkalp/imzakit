using System.Text.Json;
using ImzaKit.Api.Problems;

namespace ImzaKit.Api.Hosting;

public static class ProblemDetailsFactory
{
    private static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static ApiHttpResponse Create(
        ApiProblemKind kind,
        string correlationId,
        Guid? operationId = null,
        bool retryable = false)
    {
        ApiProblemDescriptor descriptor = ApiProblemCatalog.Get(kind);
        string slug = descriptor.Code.ToLowerInvariant().Replace('.', '-');
        var payload = new
        {
            type = "https://docs.imzakit.dev/errors/" + slug,
            title = descriptor.Code,
            status = descriptor.HttpStatus,
            code = descriptor.Code,
            correlationId,
            operationId,
            retryable
        };
        return new ApiHttpResponse
        {
            StatusCode = descriptor.HttpStatus,
            Body = JsonSerializer.Serialize(payload, Json),
            ContentType = "application/problem+json",
            CorrelationId = correlationId
        };
    }
}
