using System.Net;
using ImzaKit.Agent.Configuration;

namespace ImzaKit.Agent.Hosting;

public sealed class AgentLoopbackHost
{
    public AgentLoopbackHost(AgentLoopbackOptions options, AgentSignRequestHandler handler)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(handler);
        Prefixes = options.Endpoints.Select(ToPrefix).ToArray();
        Handler = handler;
    }

    public IReadOnlyList<string> Prefixes { get; }

    public AgentSignRequestHandler Handler { get; }

    private static string ToPrefix(AgentLoopbackEndpoint endpoint)
    {
        if (endpoint.Address.Equals(IPAddress.Loopback))
        {
            return $"http://127.0.0.1:{endpoint.Port}/";
        }

        return $"http://[::1]:{endpoint.Port}/";
    }
}
