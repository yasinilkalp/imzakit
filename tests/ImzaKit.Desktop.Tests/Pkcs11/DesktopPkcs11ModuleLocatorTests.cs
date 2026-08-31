using ImzaKit.Hosts.Desktop.Pkcs11;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;

namespace ImzaKit.Desktop.Tests.Pkcs11;

public sealed class DesktopPkcs11ModuleLocatorTests
{
    [Fact]
    public void MissingRootsYieldEmptyListWithoutThrowing()
    {
        IReadOnlyList<string> paths = DesktopPkcs11ModuleLocator.FindExistingModules(
            [Path.Combine(Path.GetTempPath(), "imzakit-no-akis-" + Guid.NewGuid().ToString("N"))],
            [Path.Combine(Path.GetTempPath(), "imzakit-no-etoken-" + Guid.NewGuid().ToString("N"))]);
        Assert.Empty(paths);
    }

    [Fact]
    public void FindsAkisModuleUnderAllowlistRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), "imzakis-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string module = Path.Combine(root, AkisProviderProfile.SupportedLibraryFileNames[0]);
        File.WriteAllBytes(module, [0]);

        IReadOnlyList<string> paths = DesktopPkcs11ModuleLocator.FindExistingModules([root], []);

        Assert.Single(paths);
        Assert.Equal(Path.GetFullPath(module), paths[0]);
        Assert.DoesNotContain(paths, path => path.Contains("eTPKCS11", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FindsEtokenModuleUnderAllowlistRoot()
    {
        string root = Path.Combine(Path.GetTempPath(), "imzaetoken-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        string module = Path.Combine(root, EtokenProviderProfile.SupportedLibraryFileNames[0]);
        File.WriteAllBytes(module, [0]);

        IReadOnlyList<string> paths = DesktopPkcs11ModuleLocator.FindExistingModules([], [root]);

        Assert.Single(paths);
        Assert.Equal(Path.GetFullPath(module), paths[0], StringComparer.OrdinalIgnoreCase);
    }
}
