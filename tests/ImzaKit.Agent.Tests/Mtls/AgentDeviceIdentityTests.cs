using System.Security.Cryptography;
using ImzaKit.Agent.Mtls;

namespace ImzaKit.Agent.Tests.Mtls;

public sealed class AgentDeviceIdentityTests
{
    [Fact]
    public void EnrollmentMaterialContainsOnlyThePublicKey()
    {
        using AgentDeviceIdentity device = AgentDeviceIdentity.Create();
        byte[] spki = device.ExportSubjectPublicKeyInfo();

        using ECDsa imported = ECDsa.Create();
        imported.ImportSubjectPublicKeyInfo(spki, out int read);

        Assert.Equal(spki.Length, read);
        Assert.ThrowsAny<CryptographicException>(() => imported.ExportECPrivateKey());
        Assert.Null(typeof(AgentDeviceIdentity).GetMethod("ExportPrivateKey"));
        Assert.Null(typeof(AgentDeviceIdentity).GetMethod("ExportECPrivateKey"));
        Assert.Null(typeof(AgentDeviceIdentity).GetMethod("ExportPkcs8PrivateKey"));
    }

    [Fact]
    public void DisposedIdentityCannotExportPublicMaterial()
    {
        AgentDeviceIdentity device = AgentDeviceIdentity.Create();
        device.Dispose();

        Assert.Throws<ObjectDisposedException>(() => device.ExportSubjectPublicKeyInfo());
    }
}
