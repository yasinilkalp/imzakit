using System.Runtime.InteropServices;
using ImzaKit.Pkcs11.Akis;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Native;

public static class Pkcs11NativeLibraryLoader
{
    public static IPkcs11NativeApi Load(string path, IReadOnlyList<string> allowedDirectoryRoots)
    {
        string resolved = Pkcs11ModulePath.ResolveAllowed(
            path,
            allowedDirectoryRoots,
            AkisProviderProfile.SupportedLibraryFileNames);

        nint handle = 0;
        try
        {
            handle = NativeLibrary.Load(resolved);
            return Pkcs11NativeLibraryApi.FromHandle(handle);
        }
        catch (Exception exception) when (exception is not Pkcs11ProviderException and not ArgumentException)
        {
            if (handle != 0)
            {
                NativeLibrary.Free(handle);
            }

            throw new Pkcs11ProviderException(
                Pkcs11ErrorCode.DriverError,
                "PKCS#11 module could not be loaded.",
                exception);
        }
    }
}
