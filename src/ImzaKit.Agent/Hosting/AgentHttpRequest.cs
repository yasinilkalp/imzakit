using System.Net;

namespace ImzaKit.Agent.Hosting;

public sealed class AgentHttpRequest
{
    public required string Method { get; init; }
    public required string Path { get; init; }
    public required IPAddress RemoteAddress { get; init; }
    public string? Origin { get; init; }
    public string Body { get; init; } = "";
}
