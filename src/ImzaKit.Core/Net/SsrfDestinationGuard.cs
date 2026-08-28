using System.Net;
using System.Net.Sockets;

namespace ImzaKit.Core.Net;

public static class SsrfDestinationGuard
{
    private static readonly HashSet<string> BlockedHosts = new(StringComparer.OrdinalIgnoreCase)
    {
        "localhost",
        "metadata.google.internal",
        "metadata.google.com",
        "instance-data"
    };

    public static void EnsureAllowed(Uri uri)
    {
        ArgumentNullException.ThrowIfNull(uri);
        if (!uri.IsAbsoluteUri ||
            (uri.Scheme != Uri.UriSchemeHttp && uri.Scheme != Uri.UriSchemeHttps))
        {
            throw Blocked();
        }

        string host = string.IsNullOrWhiteSpace(uri.IdnHost) ? uri.Host : uri.IdnHost;
        if (uri.IsLoopback || BlockedHosts.Contains(host) || BlockedHosts.Contains(uri.Host))
        {
            throw Blocked();
        }

        if (IPAddress.TryParse(host, out IPAddress? literal))
        {
            EnsureAllowed(literal);
        }
    }

    public static void EnsureAllowed(IPAddress address)
    {
        ArgumentNullException.ThrowIfNull(address);
        IPAddress normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        if (IsBlocked(normalized))
        {
            throw Blocked();
        }
    }

    private static bool IsBlocked(IPAddress address)
    {
        if (IPAddress.IsLoopback(address) ||
            address.Equals(IPAddress.Any) ||
            address.Equals(IPAddress.IPv6Any) ||
            address.Equals(IPAddress.Broadcast) ||
            address.Equals(IPAddress.None))
        {
            return true;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] is 0 or 10 or >= 224
                || (bytes[0] == 100 && bytes[1] is >= 64 and <= 127)
                || (bytes[0] == 127)
                || (bytes[0] == 169 && bytes[1] == 254)
                || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
                || (bytes[0] == 192 && bytes[1] == 168);
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            byte[] bytes = address.GetAddressBytes();
            return address.IsIPv6LinkLocal
                || address.IsIPv6Multicast
                || address.IsIPv6SiteLocal
                || (bytes[0] & 0xFE) == 0xFC;
        }

        return true;
    }

    private static InvalidOperationException Blocked() => new("IMZAKIT.NET.SSRF_BLOCKED");
}
