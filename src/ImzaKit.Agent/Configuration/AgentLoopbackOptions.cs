namespace ImzaKit.Agent.Configuration;

public sealed class AgentLoopbackOptions
{
    public AgentLoopbackOptions(IEnumerable<AgentLoopbackEndpoint> endpoints)
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        Endpoints = endpoints.ToArray();
        if (Endpoints.Count == 0) throw new ArgumentException("At least one loopback endpoint is required.", nameof(endpoints));
    }

    public IReadOnlyList<AgentLoopbackEndpoint> Endpoints { get; }
}
