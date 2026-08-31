using ImzaKit.Agent.Native;
using ImzaKit.Hosts.Desktop.Session;
using ImzaKit.Hosts.Desktop.Signing;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Etoken;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Hosts.Desktop.Pkcs11;

public static class DesktopHostFactory
{
    public static SignSessionViewModel CreateSession(INativePinPrompt pinPrompt)
    {
        ArgumentNullException.ThrowIfNull(pinPrompt);
        return new SignSessionViewModel(LoadInstalledProviders(), new DesktopPadesSigner(pinPrompt));
    }

    public static IReadOnlyList<NamedPkcs11Provider> LoadInstalledProviders()
    {
        List<NamedPkcs11Provider> providers = [];
        IReadOnlyList<string> paths = DesktopPkcs11ModuleLocator.FindExistingModules(
            DesktopPkcs11ModuleLocator.DefaultAkisRoots,
            DesktopPkcs11ModuleLocator.DefaultEtokenRoots);
        foreach (string path in paths)
        {
            bool etoken = path.EndsWith("eTPKCS11.dll", StringComparison.OrdinalIgnoreCase);
            try
            {
                IPkcs11NativeApi api = Pkcs11NativeLibraryLoader.Load(
                    path,
                    etoken ? DesktopPkcs11ModuleLocator.DefaultEtokenRoots : DesktopPkcs11ModuleLocator.DefaultAkisRoots,
                    etoken ? EtokenProviderProfile.SupportedLibraryFileNames : AkisProviderProfile.SupportedLibraryFileNames);
                NativePkcs11Provider provider = new(
                    api,
                    etoken ? NativePkcs11ProviderOptions.ForEtoken() : NativePkcs11ProviderOptions.ForAkis());
                string name = etoken ? EtokenProviderProfile.Name : AkisProviderProfile.Name;
                providers.Add(new NamedPkcs11Provider(name, provider));
            }
            catch (Pkcs11ProviderException)
            {
            }
            catch (ArgumentException)
            {
            }
            catch (DllNotFoundException)
            {
            }
            catch (BadImageFormatException)
            {
            }
        }

        return providers;
    }
}
