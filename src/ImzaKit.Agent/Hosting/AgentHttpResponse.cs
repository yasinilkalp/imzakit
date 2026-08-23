namespace ImzaKit.Agent.Hosting;

public sealed class AgentHttpResponse
{
    public required int StatusCode { get; init; }
    public required string Body { get; init; }
    public string? AccessControlAllowOrigin { get; init; }
}
