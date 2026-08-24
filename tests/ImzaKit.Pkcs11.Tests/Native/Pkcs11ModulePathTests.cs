using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Native;

public sealed class Pkcs11ModulePathTests
{
    [Fact]
    public void RelativePathIsRejected()
    {
        ArgumentException exception = Assert.Throws<ArgumentException>(() =>
            Pkcs11ModulePath.ResolveAllowed("akisp11.dll", [Path.GetTempPath()], AkisProviderProfile.SupportedLibraryFileNames));

        Assert.Contains("absolute", exception.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void PathOutsideAllowlistIsRejected()
    {
        string allowed = CreateTempDirectory();
        string outsider = CreateTempDirectory();
        string path = Path.Combine(outsider, "akisp11.dll");
        File.WriteAllBytes(path, [1]);

        try
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(() =>
                Pkcs11ModulePath.ResolveAllowed(path, [allowed], AkisProviderProfile.SupportedLibraryFileNames));
            Assert.Contains("allowlist", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(allowed, true);
            Directory.Delete(outsider, true);
        }
    }

    [Fact]
    public void DisallowedFileNameIsRejectedEvenInsideAllowlist()
    {
        string allowed = CreateTempDirectory();
        string path = Path.Combine(allowed, "evil.dll");
        File.WriteAllBytes(path, [1]);

        try
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(() =>
                Pkcs11ModulePath.ResolveAllowed(path, [allowed], AkisProviderProfile.SupportedLibraryFileNames));
            Assert.Contains("file name", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(allowed, true);
        }
    }

    [Fact]
    public void AllowlistedAkisModulePathIsNormalized()
    {
        string allowed = CreateTempDirectory();
        string path = Path.Combine(allowed, "vendor", "akisp11.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [1]);
        string sneaky = Path.Combine(allowed, "vendor", "..", "vendor", "akisp11.dll");

        try
        {
            string resolved = Pkcs11ModulePath.ResolveAllowed(
                sneaky, [allowed], AkisProviderProfile.SupportedLibraryFileNames);
            Assert.Equal(Path.GetFullPath(path), resolved);
        }
        finally
        {
            Directory.Delete(allowed, true);
        }
    }

    [Fact]
    public void NeighborDirectoryWithSimilarPrefixIsRejected()
    {
        string parent = CreateTempDirectory();
        string allowed = Path.Combine(parent, "AKIS");
        string neighbor = Path.Combine(parent, "AKIS-evil");
        Directory.CreateDirectory(allowed);
        Directory.CreateDirectory(neighbor);
        string path = Path.Combine(neighbor, "akisp11.dll");
        File.WriteAllBytes(path, [1]);

        try
        {
            Assert.Throws<ArgumentException>(() =>
                Pkcs11ModulePath.ResolveAllowed(path, [allowed], AkisProviderProfile.SupportedLibraryFileNames));
        }
        finally
        {
            Directory.Delete(parent, true);
        }
    }

    [Fact]
    public void AllowlistedEtokenModulePathIsNormalized()
    {
        string allowed = CreateTempDirectory();
        string path = Path.Combine(allowed, "SAC", "eTPKCS11.dll");
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [1]);

        try
        {
            string resolved = Pkcs11ModulePath.ResolveAllowed(
                path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames);
            Assert.Equal(Path.GetFullPath(path), resolved);
        }
        finally
        {
            Directory.Delete(allowed, true);
        }
    }

    [Fact]
    public void LegacyEtokenDllNameIsRejected()
    {
        string allowed = CreateTempDirectory();
        string path = Path.Combine(allowed, "eToken.dll");
        File.WriteAllBytes(path, [1]);

        try
        {
            ArgumentException exception = Assert.Throws<ArgumentException>(() =>
                Pkcs11ModulePath.ResolveAllowed(path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames));
            Assert.Contains("file name", exception.Message, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            Directory.Delete(allowed, true);
        }
    }

    [Fact]
    public void AkisFileNameIsRejectedOnEtokenAllowlist()
    {
        string allowed = CreateTempDirectory();
        string path = Path.Combine(allowed, "akisp11.dll");
        File.WriteAllBytes(path, [1]);

        try
        {
            Assert.Throws<ArgumentException>(() =>
                Pkcs11ModulePath.ResolveAllowed(path, [allowed], EtokenProviderProfile.SupportedLibraryFileNames));
        }
        finally
        {
            Directory.Delete(allowed, true);
        }
    }

    [Fact]
    public void LoaderExposesExplicitFileNameListOverload()
    {
        System.Reflection.MethodInfo? method = typeof(Pkcs11NativeLibraryLoader)
            .GetMethods()
            .SingleOrDefault(candidate =>
                candidate.Name == nameof(Pkcs11NativeLibraryLoader.Load) &&
                candidate.GetParameters().Length == 3);

        Assert.NotNull(method);
    }

    private static string CreateTempDirectory()
    {
        string path = Path.Combine(Path.GetTempPath(), "imzakit-pkcs11-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }
}
