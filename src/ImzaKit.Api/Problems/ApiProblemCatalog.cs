namespace ImzaKit.Api.Problems;

public static class ApiProblemCatalog
{
    public static ApiProblemDescriptor Get(ApiProblemKind kind) => kind switch
    {
        ApiProblemKind.Conflict => new(409, "IMZAKIT.CORE.CONFLICT"),
        ApiProblemKind.PayloadTooLarge => new(413, "IMZAKIT.CORE.PAYLOAD_TOO_LARGE"),
        ApiProblemKind.Unprocessable => new(422, "IMZAKIT.CORE.UNPROCESSABLE"),
        ApiProblemKind.RateLimited => new(429, "IMZAKIT.CORE.RATE_LIMITED"),
        ApiProblemKind.DependencyUnavailable => new(503, "IMZAKIT.CORE.DEPENDENCY_UNAVAILABLE"),
        _ => throw new ArgumentOutOfRangeException(nameof(kind))
    };
}
