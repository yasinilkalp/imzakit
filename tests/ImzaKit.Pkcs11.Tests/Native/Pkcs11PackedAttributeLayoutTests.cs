using System.Runtime.InteropServices;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Native;

public sealed class Pkcs11PackedAttributeLayoutTests
{
    [Fact]
    public void WindowsAttributeMatchesCryptokiPack1()
    {
        int expected = 4 + IntPtr.Size + 4;
        Assert.Equal(expected, Pkcs11NativeConstants.PackedAttributeSize(windowsUlong: true));
        Assert.Equal(4, Pkcs11NativeConstants.PackedAttributePointerOffset(windowsUlong: true));
        Assert.Equal(4 + IntPtr.Size, Pkcs11NativeConstants.PackedAttributeLengthOffset(windowsUlong: true));
    }

    [Fact]
    public void UnixAttributeMatchesCryptokiPack1()
    {
        int expected = 8 + IntPtr.Size + 8;
        Assert.Equal(expected, Pkcs11NativeConstants.PackedAttributeSize(windowsUlong: false));
        Assert.Equal(8, Pkcs11NativeConstants.PackedAttributePointerOffset(windowsUlong: false));
        Assert.Equal(8 + IntPtr.Size, Pkcs11NativeConstants.PackedAttributeLengthOffset(windowsUlong: false));
    }

    [Fact]
    public void WindowsPack1StructIsNotNaturallyAligned24()
    {
        Assert.NotEqual(24, Pkcs11NativeConstants.PackedAttributeSize(windowsUlong: true));
        Assert.Equal(4 + IntPtr.Size + 4, Marshal.SizeOf<CkAttributeWindowsPack1>());
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    private struct CkAttributeWindowsPack1
    {
        public uint type;
        public IntPtr pValue;
        public uint ulValueLen;
    }
}
