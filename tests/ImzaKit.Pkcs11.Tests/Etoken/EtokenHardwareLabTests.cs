#if ETOKEN_HARDWARE_LAB
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Etoken;

public sealed class EtokenHardwareLabTests
{
    [Fact]
    public void DiscoverTokensFromAllowlistedVendorModule()
    {
        Assert.True(OperatingSystem.IsWindows(), "eToken hardware lab requires Windows.");

        using NativePkcs11Provider provider = LoadProvider();
        provider.Initialize();
        IReadOnlyList<Pkcs11Token> tokens = provider.DiscoverTokens();

        Assert.False(
            tokens.Count == 0,
            "eTPKCS11.dll loaded but no token could be read. Insert a SafeNet/Thales eToken and re-run.");
        Pkcs11Token token = tokens[0];
        Assert.False(string.IsNullOrWhiteSpace(token.Label));
        Assert.False(string.IsNullOrWhiteSpace(token.Manufacturer));
        Assert.False(string.IsNullOrWhiteSpace(token.Model));
        Assert.StartsWith("****", token.MaskedSerialNumber, StringComparison.Ordinal);
    }

    [Fact]
    public void FindCertificatesWithoutPinReadsX509CkaIdValueAndLabel()
    {
        using NativePkcs11Provider provider = LoadProvider();
        provider.Initialize();
        Pkcs11Token token = Assert.Single(provider.DiscoverTokens());
        ulong session = provider.OpenSession(token.SlotId);
        try
        {
            IReadOnlyList<Pkcs11Certificate> certificates = provider.FindCertificates(session);
            Assert.False(
                certificates.Count == 0,
                "No public X.509 certificate was readable without PIN. Login/CredUI is required for the remaining lab items.");

            Pkcs11Certificate certificate = certificates[0];
            Assert.NotEmpty(certificate.CkaId);
            Assert.False(string.IsNullOrWhiteSpace(certificate.Label));
            Assert.NotEmpty(certificate.DerEncoded);
            Assert.Equal(0x30, certificate.DerEncoded[0]);
        }
        finally
        {
            provider.CloseSession(session);
        }
    }

    private static NativePkcs11Provider LoadProvider()
    {
        Assert.True(OperatingSystem.IsWindows(), "eToken hardware lab requires Windows.");
        string? configuredPath = Environment.GetEnvironmentVariable("IMZAKIT_ETOKEN_MODULE");
        Assert.False(string.IsNullOrWhiteSpace(configuredPath), "Set IMZAKIT_ETOKEN_MODULE to an allowlisted eTPKCS11.dll path.");
        Assert.True(File.Exists(configuredPath), "IMZAKIT_ETOKEN_MODULE does not point to an existing file.");
        string fullPath = Path.GetFullPath(configuredPath!);
        string allowlistRoot = Path.GetDirectoryName(fullPath)
            ?? throw new InvalidOperationException("PKCS#11 module path has no directory.");
        IPkcs11NativeApi native = Pkcs11NativeLibraryLoader.Load(
            fullPath,
            [allowlistRoot],
            EtokenProviderProfile.SupportedLibraryFileNames);
        return new NativePkcs11Provider(native, NativePkcs11ProviderOptions.ForEtoken());
    }
}
#endif
