using System.Security.Cryptography;
using System.Text;

namespace ImzaKit.Api.Hosting;

public static class CanonicalRequestHasher
{
    public static string Hash(string method, string path, string body)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(method);
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        string canonical = string.Concat(method.ToUpperInvariant(), "\n", path, "\n", body ?? "");
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(canonical)));
    }
}
