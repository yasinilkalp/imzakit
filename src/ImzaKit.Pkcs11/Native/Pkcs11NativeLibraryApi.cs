using System.Runtime.InteropServices;
using System.Text;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Native;

internal sealed class Pkcs11NativeLibraryApi : IPkcs11NativeApi
{
    private static readonly string[] RequiredExports =
    [
        "C_Initialize", "C_Finalize", "C_GetSlotList", "C_GetTokenInfo", "C_OpenSession", "C_CloseSession",
        "C_Login", "C_Logout", "C_FindObjectsInit", "C_FindObjects", "C_FindObjectsFinal", "C_GetAttributeValue",
        "C_SignInit", "C_Sign"
    ];

    private readonly nint _handle;
    private readonly bool _windowsUlong;
    private readonly Dictionary<string, nint> _exports;
    private bool _disposed;

    private Pkcs11NativeLibraryApi(nint handle, bool windowsUlong, Dictionary<string, nint> exports)
    {
        _handle = handle;
        _windowsUlong = windowsUlong;
        _exports = exports;
    }

    public static Pkcs11NativeLibraryApi FromHandle(nint handle)
    {
        Dictionary<string, nint> exports = new(StringComparer.Ordinal);
        foreach (string name in RequiredExports)
        {
            if (!NativeLibrary.TryGetExport(handle, name, out nint address))
            {
                NativeLibrary.Free(handle);
                throw new Pkcs11ProviderException(
                    Pkcs11ErrorCode.DriverError,
                    "PKCS#11 module is missing a required export.");
            }

            exports[name] = address;
        }

        return new Pkcs11NativeLibraryApi(handle, OperatingSystem.IsWindows(), exports);
    }

    public void Initialize() =>
        Pkcs11RvMapper.ThrowIfFailed(PtrFn("C_Initialize")(IntPtr.Zero), "initialize");

    public void FinalizeCryptoki() =>
        Pkcs11RvMapper.ThrowIfFailed(PtrFn("C_Finalize")(IntPtr.Zero), "finalize");

    public IReadOnlyList<ulong> GetSlotsWithPresentTokens()
    {
        nint countPtr = Marshal.AllocHGlobal(UlongSize);
        nint listPtr = IntPtr.Zero;
        try
        {
            WriteUlong(countPtr, 0);
            Pkcs11RvMapper.ThrowIfFailed(GetSlotList(1, IntPtr.Zero, countPtr), "get slot list");
            ulong count = ReadUlong(countPtr);
            if (count == 0)
            {
                return [];
            }

            listPtr = Marshal.AllocHGlobal((int)count * UlongSize);
            Pkcs11RvMapper.ThrowIfFailed(GetSlotList(1, listPtr, countPtr), "get slot list");
            count = ReadUlong(countPtr);
            ulong[] slots = new ulong[count];
            for (int index = 0; index < (int)count; index++)
            {
                slots[index] = ReadUlong(listPtr + (index * UlongSize));
            }

            return slots;
        }
        finally
        {
            if (listPtr != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(listPtr);
            }

            Marshal.FreeHGlobal(countPtr);
        }
    }

    public Pkcs11NativeTokenInfo GetTokenInfo(ulong slotId)
    {
        nint info = Marshal.AllocHGlobal(256);
        try
        {
            Pkcs11RvMapper.ThrowIfFailed(SlotPtrFn("C_GetTokenInfo")(ToNative(slotId), info), "get token info");
            byte[] buffer = new byte[96];
            Marshal.Copy(info, buffer, 0, buffer.Length);
            return new Pkcs11NativeTokenInfo(
                ReadPaddedUtf8(buffer.AsSpan(0, 32)),
                ReadPaddedUtf8(buffer.AsSpan(32, 32)),
                ReadPaddedUtf8(buffer.AsSpan(64, 16)),
                ReadPaddedUtf8(buffer.AsSpan(80, 16)));
        }
        finally
        {
            Marshal.FreeHGlobal(info);
        }
    }

    public ulong OpenSession(ulong slotId)
    {
        nint sessionPtr = Marshal.AllocHGlobal(UlongSize);
        try
        {
            WriteUlong(sessionPtr, 0);
            uint flags = Pkcs11NativeConstants.CkfSerialSession | Pkcs11NativeConstants.CkfRwSession;
            Pkcs11RvMapper.ThrowIfFailed(
                OpenSessionFn("C_OpenSession")(ToNative(slotId), flags, IntPtr.Zero, IntPtr.Zero, sessionPtr),
                "open session");
            return ReadUlong(sessionPtr);
        }
        finally
        {
            Marshal.FreeHGlobal(sessionPtr);
        }
    }

    public void CloseSession(ulong session) =>
        Pkcs11RvMapper.ThrowIfFailed(UlongFn("C_CloseSession")(ToNative(session)), "close session");

    public void LoginUser(ulong session, byte[] utf8Pin)
    {
        ArgumentNullException.ThrowIfNull(utf8Pin);
        GCHandle pin = GCHandle.Alloc(utf8Pin, GCHandleType.Pinned);
        try
        {
            Pkcs11RvMapper.ThrowIfFailed(
                LoginFn("C_Login")(
                    ToNative(session),
                    Pkcs11NativeConstants.CkuUser,
                    pin.AddrOfPinnedObject(),
                    ToNative((ulong)utf8Pin.Length)),
                "login");
        }
        finally
        {
            pin.Free();
        }
    }

    public void Logout(ulong session) =>
        Pkcs11RvMapper.ThrowIfFailed(UlongFn("C_Logout")(ToNative(session)), "logout");

    public IReadOnlyList<ulong> FindObjects(ulong session, ulong objectClass, params (ulong Type, byte[] Value)[] additional)
    {
        additional ??= [];
        using AttributeBlock template = AttributeBlock.Create(_windowsUlong, objectClass, additional);
        Pkcs11RvMapper.ThrowIfFailed(
            FindInitFn("C_FindObjectsInit")(ToNative(session), template.Pointer, ToNative((ulong)template.Count)),
            "find objects init");
        nint handlesPtr = Marshal.AllocHGlobal(32 * UlongSize);
        nint countPtr = Marshal.AllocHGlobal(UlongSize);
        try
        {
            WriteUlong(countPtr, 0);
            Pkcs11RvMapper.ThrowIfFailed(
                FindFn("C_FindObjects")(ToNative(session), handlesPtr, ToNative(32), countPtr),
                "find objects");
            ulong found = ReadUlong(countPtr);
            ulong[] handles = new ulong[found];
            for (int index = 0; index < (int)found; index++)
            {
                handles[index] = ReadUlong(handlesPtr + (index * UlongSize));
            }

            return handles;
        }
        finally
        {
            Marshal.FreeHGlobal(countPtr);
            Marshal.FreeHGlobal(handlesPtr);
            Pkcs11RvMapper.ThrowIfFailed(UlongFn("C_FindObjectsFinal")(ToNative(session)), "find objects final");
        }
    }

    public byte[]? TryGetAttribute(ulong session, ulong objectHandle, ulong attributeType)
    {
        using AttributeBlock lengthQuery = AttributeBlock.ForRead(_windowsUlong, attributeType, IntPtr.Zero, 0);
        uint rv = GetAttributeFn("C_GetAttributeValue")(
            ToNative(session),
            ToNative(objectHandle),
            lengthQuery.Pointer,
            ToNative(1));
        if (rv != Pkcs11Rv.Ok)
        {
            return null;
        }

        ulong length = lengthQuery.ReadLength();
        if (length is 0 or ulong.MaxValue)
        {
            return [];
        }

        byte[] value = new byte[length];
        GCHandle pinned = GCHandle.Alloc(value, GCHandleType.Pinned);
        try
        {
            using AttributeBlock valueQuery = AttributeBlock.ForRead(
                _windowsUlong,
                attributeType,
                pinned.AddrOfPinnedObject(),
                length);
            rv = GetAttributeFn("C_GetAttributeValue")(
                ToNative(session),
                ToNative(objectHandle),
                valueQuery.Pointer,
                ToNative(1));
            return rv == Pkcs11Rv.Ok ? value : null;
        }
        finally
        {
            pinned.Free();
        }
    }

    public void SignInit(ulong session, ulong mechanismType, ulong keyHandle)
    {
        using MechanismBlock mechanism = MechanismBlock.Create(_windowsUlong, mechanismType);
        Pkcs11RvMapper.ThrowIfFailed(
            SignInitFn("C_SignInit")(ToNative(session), mechanism.Pointer, ToNative(keyHandle)),
            "sign init");
    }

    public byte[] Sign(ulong session, ReadOnlySpan<byte> data)
    {
        byte[] payload = data.ToArray();
        GCHandle dataHandle = GCHandle.Alloc(payload, GCHandleType.Pinned);
        nint lengthPtr = Marshal.AllocHGlobal(UlongSize);
        try
        {
            WriteUlong(lengthPtr, 0);
            Pkcs11RvMapper.ThrowIfFailed(
                SignFn("C_Sign")(
                    ToNative(session),
                    dataHandle.AddrOfPinnedObject(),
                    ToNative((ulong)payload.Length),
                    IntPtr.Zero,
                    lengthPtr),
                "sign");
            ulong signatureLength = ReadUlong(lengthPtr);
            byte[] signature = new byte[signatureLength];
            GCHandle signatureHandle = GCHandle.Alloc(signature, GCHandleType.Pinned);
            try
            {
                Pkcs11RvMapper.ThrowIfFailed(
                    SignFn("C_Sign")(
                        ToNative(session),
                        dataHandle.AddrOfPinnedObject(),
                        ToNative((ulong)payload.Length),
                        signatureHandle.AddrOfPinnedObject(),
                        lengthPtr),
                    "sign");
                ulong actual = ReadUlong(lengthPtr);
                if (actual != (ulong)signature.Length)
                {
                    Array.Resize(ref signature, (int)actual);
                }

                return signature;
            }
            finally
            {
                signatureHandle.Free();
            }
        }
        finally
        {
            Marshal.FreeHGlobal(lengthPtr);
            dataHandle.Free();
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        NativeLibrary.Free(_handle);
        _disposed = true;
    }

    private int UlongSize => _windowsUlong ? 4 : 8;

    private nuint ToNative(ulong value) => _windowsUlong ? (uint)value : (nuint)value;

    private void WriteUlong(nint pointer, ulong value)
    {
        if (_windowsUlong)
        {
            Marshal.WriteInt32(pointer, (int)value);
        }
        else
        {
            Marshal.WriteInt64(pointer, (long)value);
        }
    }

    private ulong ReadUlong(nint pointer) =>
        _windowsUlong ? (uint)Marshal.ReadInt32(pointer) : (ulong)Marshal.ReadInt64(pointer);

    private PtrDelegate PtrFn(string name) => Marshal.GetDelegateForFunctionPointer<PtrDelegate>(_exports[name]);
    private UlongDelegate UlongFn(string name) => Marshal.GetDelegateForFunctionPointer<UlongDelegate>(_exports[name]);
    private SlotPtrDelegate SlotPtrFn(string name) => Marshal.GetDelegateForFunctionPointer<SlotPtrDelegate>(_exports[name]);
    private OpenSessionDelegate OpenSessionFn(string name) => Marshal.GetDelegateForFunctionPointer<OpenSessionDelegate>(_exports[name]);
    private LoginDelegate LoginFn(string name) => Marshal.GetDelegateForFunctionPointer<LoginDelegate>(_exports[name]);
    private FindInitDelegate FindInitFn(string name) => Marshal.GetDelegateForFunctionPointer<FindInitDelegate>(_exports[name]);
    private FindDelegate FindFn(string name) => Marshal.GetDelegateForFunctionPointer<FindDelegate>(_exports[name]);
    private GetAttributeDelegate GetAttributeFn(string name) => Marshal.GetDelegateForFunctionPointer<GetAttributeDelegate>(_exports[name]);
    private SignInitDelegate SignInitFn(string name) => Marshal.GetDelegateForFunctionPointer<SignInitDelegate>(_exports[name]);
    private SignDelegate SignFn(string name) => Marshal.GetDelegateForFunctionPointer<SignDelegate>(_exports[name]);

    private uint GetSlotList(byte tokenPresent, IntPtr slotList, nint countPtr)
    {
        GetSlotListDelegate fn = Marshal.GetDelegateForFunctionPointer<GetSlotListDelegate>(_exports["C_GetSlotList"]);
        return fn(tokenPresent, slotList, countPtr);
    }

    private static string ReadPaddedUtf8(ReadOnlySpan<byte> buffer)
    {
        int end = buffer.Length;
        while (end > 0 && (buffer[end - 1] == 0 || buffer[end - 1] == (byte)' '))
        {
            end--;
        }

        return Encoding.UTF8.GetString(buffer[..end]);
    }

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint PtrDelegate(IntPtr argument);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint UlongDelegate(nuint value);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint SlotPtrDelegate(nuint slotId, IntPtr info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GetSlotListDelegate(byte tokenPresent, IntPtr slotList, nint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint OpenSessionDelegate(nuint slotId, uint flags, IntPtr application, IntPtr notify, nint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint LoginDelegate(nuint session, uint userType, IntPtr pin, nuint pinLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FindInitDelegate(nuint session, IntPtr template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FindDelegate(nuint session, IntPtr objects, nuint maxCount, nint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GetAttributeDelegate(nuint session, nuint objectHandle, IntPtr template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint SignInitDelegate(nuint session, IntPtr mechanism, nuint keyHandle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint SignDelegate(nuint session, IntPtr data, nuint dataLength, IntPtr signature, nint signatureLength);

    private sealed class AttributeBlock : IDisposable
    {
        private readonly List<GCHandle> _valuePins = [];
        private GCHandle _templatePin;
        private readonly byte[] _template;
        private readonly bool _windowsUlong;

        private AttributeBlock(byte[] template, bool windowsUlong)
        {
            _template = template;
            _windowsUlong = windowsUlong;
            _templatePin = GCHandle.Alloc(template, GCHandleType.Pinned);
        }

        public IntPtr Pointer => _templatePin.AddrOfPinnedObject();
        public int Count { get; private init; }

        public static AttributeBlock Create(bool windowsUlong, ulong objectClass, (ulong Type, byte[] Value)[] additional)
        {
            int count = 1 + additional.Length;
            AttributeBlock block = new(new byte[count * 24], windowsUlong) { Count = count };
            block.Write(0, Pkcs11NativeConstants.CkaClass, EncodeUlong(windowsUlong, objectClass));
            for (int index = 0; index < additional.Length; index++)
            {
                block.Write(index + 1, additional[index].Type, additional[index].Value);
            }

            return block;
        }

        public static AttributeBlock ForRead(bool windowsUlong, ulong type, IntPtr value, ulong length)
        {
            AttributeBlock block = new(new byte[24], windowsUlong) { Count = 1 };
            block.WriteHeader(0, type, value, length);
            return block;
        }

        public ulong ReadLength() =>
            _windowsUlong ? BitConverter.ToUInt32(_template, 16) : BitConverter.ToUInt64(_template, 16);

        private void Write(int index, ulong type, byte[] value)
        {
            GCHandle pin = GCHandle.Alloc(value, GCHandleType.Pinned);
            _valuePins.Add(pin);
            WriteHeader(index, type, pin.AddrOfPinnedObject(), (ulong)value.Length);
        }

        private void WriteHeader(int index, ulong type, IntPtr value, ulong length)
        {
            int offset = index * 24;
            if (_windowsUlong)
            {
                BitConverter.TryWriteBytes(_template.AsSpan(offset), (uint)type);
                WritePointer(_template.AsSpan(offset + 8), value);
                BitConverter.TryWriteBytes(_template.AsSpan(offset + 16), (uint)length);
            }
            else
            {
                BitConverter.TryWriteBytes(_template.AsSpan(offset), type);
                WritePointer(_template.AsSpan(offset + 8), value);
                BitConverter.TryWriteBytes(_template.AsSpan(offset + 16), length);
            }
        }

        public void Dispose()
        {
            if (_templatePin.IsAllocated)
            {
                _templatePin.Free();
            }

            foreach (GCHandle pin in _valuePins)
            {
                if (pin.IsAllocated)
                {
                    pin.Free();
                }
            }
        }

        private static byte[] EncodeUlong(bool windowsUlong, ulong value) =>
            windowsUlong ? BitConverter.GetBytes((uint)value) : BitConverter.GetBytes(value);

        private static void WritePointer(Span<byte> destination, IntPtr value)
        {
            if (IntPtr.Size == 8)
            {
                BitConverter.TryWriteBytes(destination, value.ToInt64());
            }
            else
            {
                BitConverter.TryWriteBytes(destination, value.ToInt32());
            }
        }
    }

    private sealed class MechanismBlock : IDisposable
    {
        private GCHandle _pin;

        private MechanismBlock(byte[] buffer) => _pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);

        public IntPtr Pointer => _pin.AddrOfPinnedObject();

        public static MechanismBlock Create(bool windowsUlong, ulong mechanismType)
        {
            byte[] buffer = new byte[24];
            if (windowsUlong)
            {
                BitConverter.TryWriteBytes(buffer.AsSpan(0), (uint)mechanismType);
            }
            else
            {
                BitConverter.TryWriteBytes(buffer.AsSpan(0), mechanismType);
            }

            return new MechanismBlock(buffer);
        }

        public void Dispose()
        {
            if (_pin.IsAllocated)
            {
                _pin.Free();
            }
        }
    }
}
