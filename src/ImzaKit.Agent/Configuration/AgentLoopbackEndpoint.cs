using System.Net;

namespace ImzaKit.Agent.Configuration;

public sealed record AgentLoopbackEndpoint
{
    public AgentLoopbackEndpoint(IPAddress address, int port)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (!address.Equals(IPAddress.Loopback) && !address.Equals(IPAddress.IPv6Loopback))
            throw new ArgumentException("Only literal loopback addresses are allowed.", nameof(address));
        if (port is < 1 or > 65535) throw new ArgumentOutOfRangeException(nameof(port));
        Address = address;
        Port = port;
    }

    public IPAddress Address { get; }
    public int Port { get; }
}
