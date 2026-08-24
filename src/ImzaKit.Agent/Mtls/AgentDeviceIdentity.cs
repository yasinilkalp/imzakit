using System.Security.Cryptography;

namespace ImzaKit.Agent.Mtls;

public sealed class AgentDeviceIdentity : IDisposable
{
    private ECDsa? _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

    public static AgentDeviceIdentity Create() => new();

    public byte[] ExportSubjectPublicKeyInfo()
    {
        ObjectDisposedException.ThrowIf(_key is null, this);
        return _key.ExportSubjectPublicKeyInfo();
    }

    public void Dispose()
    {
        _key?.Dispose();
        _key = null;
    }
}
