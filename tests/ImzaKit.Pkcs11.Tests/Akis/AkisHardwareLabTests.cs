#if AKIS_HARDWARE_LAB
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Akis;

public sealed class AkisHardwareLabTests
{
    [Fact]
    public void DiscoverTokensFromAllowlistedVendorModule()
    {
        Assert.True(OperatingSystem.IsWindows(), "AKİS hardware lab requires Windows.");

        string? configuredPath = Environment.GetEnvironmentVariable("IMZAKIT_AKIS_MODULE");
        Assert.False(string.IsNullOrWhiteSpace(configuredPath), "Set IMZAKIT_AKIS_MODULE to an allowlisted akisp11.dll path.");
        Assert.True(File.Exists(configuredPath), "IMZAKIT_AKIS_MODULE does not point to an existing file.");

        string fullPath = Path.GetFullPath(configuredPath!);
        string allowlistRoot = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("PKCS#11 module path has no directory.");

        IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(fullPath, [allowlistRoot]);
        using NativePkcs11Provider provider = new(native, NativePkcs11ProviderOptions.ForAkis());
        provider.Initialize();
        IReadOnlyList<Pkcs11Token> tokens = provider.DiscoverTokens();

        Assert.False(
            tokens.Count == 0,
            "akisp11.dll loaded but no token could be read. " +
            "This machine's present slot is a SafeNet Token JC (eToken 5110); AKİS PKCS#11 cannot read it. " +
            "Insert a KamuSM AKİS card, or run the eToken lab with eTPKCS11.dll.");
        Pkcs11Token token = tokens[0];
        Assert.False(string.IsNullOrWhiteSpace(token.Label));
        Assert.False(string.IsNullOrWhiteSpace(token.Manufacturer));
        Assert.False(string.IsNullOrWhiteSpace(token.Model));
        Assert.StartsWith("****", token.MaskedSerialNumber, StringComparison.Ordinal);
    }
}
#endif
