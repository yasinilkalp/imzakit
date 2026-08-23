using System.Runtime.InteropServices;
using System.Text;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Native;

internal sealed class Pkcs11NativeLibraryApi : IPkcs11NativeApi
{
    private readonly nint _handle;
    private readonly bool _windowsUlong;
    private readonly InitializeFn _initialize;
    private readonly FinalizeFn _finalize;
    private readonly GetSlotListFn _getSlotList;
    private readonly GetTokenInfoFn _getTokenInfo;
    private readonly OpenSessionFn _openSession;
    private readonly CloseSessionFn _closeSession;
    private readonly LoginFn _login;
    private readonly LogoutFn _logout;
    private readonly FindObjectsInitFn _findObjectsInit;
    private readonly FindObjectsFn _findObjects;
    private readonly FindObjectsFinalFn _findObjectsFinal;
    private readonly GetAttributeValueFn _getAttributeValue;
    private readonly SignInitFn _signInit;
    private readonly SignFn _sign;
    private bool _disposed;

    private Pkcs11NativeLibraryApi(
        nint handle,
        bool windowsUlong,
        InitializeFn initialize,
        FinalizeFn finalize,
        GetSlotListFn getSlotList,
        GetTokenInfoFn getTokenInfo,
        OpenSessionFn openSession,
        CloseSessionFn closeSession,
        LoginFn login,
        LogoutFn logout,
        FindObjectsInitFn findObjectsInit,
        FindObjectsFn findObjects,
        FindObjectsFinalFn findObjectsFinal,
        GetAttributeValueFn getAttributeValue,
        SignInitFn signInit,
        SignFn sign)
    {
        _handle = handle;
        _windowsUlong = windowsUlong;
        _initialize = initialize;
        _finalize = finalize;
        _getSlotList = getSlotList;
        _getTokenInfo = getTokenInfo;
        _openSession = openSession;
        _closeSession = closeSession;
        _login = login;
        _logout = logout;
        _findObjectsInit = findObjectsInit;
        _findObjects = findObjects;
        _findObjectsFinal = findObjectsFinal;
        _getAttributeValue = getAttributeValue;
        _signInit = signInit;
        _sign = sign;
    }

    public static Pkcs11NativeLibraryApi FromHandle(nint handle)
    {
        try
        {
            bool windowsUlong = OperatingSystem.IsWindows();
            return new Pkcs11NativeLibraryApi(
                handle,
                windowsUlong,
                Get<InitializeFn>(handle, "C_Initialize"),
                Get<FinalizeFn>(handle, "C_Finalize"),
                Get<GetSlotListFn>(handle, "C_GetSlotList"),
                Get<GetTokenInfoFn>(handle, "C_GetTokenInfo"),
                Get<OpenSessionFn>(handle, "C_OpenSession"),
                Get<CloseSessionFn>(handle, "C_CloseSession"),
                Get<LoginFn>(handle, "C_Login"),
                Get<LogoutFn>(handle, "C_Logout"),
                Get<FindObjectsInitFn>(handle, "C_FindObjectsInit"),
                Get<FindObjectsFn>(handle, "C_FindObjects"),
                Get<FindObjectsFinalFn>(handle, "C_FindObjectsFinal"),
                Get<GetAttributeValueFn>(handle, "C_GetAttributeValue"),
                Get<SignInitFn>(handle, "C_SignInit"),
                Get<SignFn>(handle, "C_Sign"));
        }
        catch (Exception exception) when (exception is not Pkcs11ProviderException)
        {
            NativeLibrary.Free(handle);
            throw new Pkcs11ProviderException(
                Pkcs11ErrorCode.DriverError,
                "PKCS#11 module is missing a required export.",
                exception);
        }
    }

    public void Initialize() => Pkcs11RvMapper.ThrowIfFailed(_initialize(IntPtr.Zero), "initialize");

    public void FinalizeCryptoki() => Pkcs11RvMapper.ThrowIfFailed(_finalize(IntPtr.Zero), "finalize");

    public IReadOnlyList<ulong> GetSlotsWithPresentTokens()
    {
        nuint count = 0;
        Pkcs11RvMapper.ThrowIfFailed(_getSlotList(1, IntPtr.Zero, ref count), "get slot list");
        if (count == 0)
        {
            return [];
        }

        int ulongSize = UlongSize;
        byte[] buffer = new byte[(int)count * ulongSize];
        GCHandle pinned = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        try
        {
            nuint actual = count;
            Pkcs11RvMapper.ThrowIfFailed(_getSlotList(1, pinned.AddrOfPinnedObject(), ref actual), "get slot list");
            List<ulong> slots = [];
            for (int index = 0; index < (int)actual; index++)
            {
                slots.Add(ReadUlong(buffer.AsSpan(index * ulongSize, ulongSize)));
            }

            return slots;
        }
        finally
        {
            pinned.Free();
        }
    }

    public Pkcs11NativeTokenInfo GetTokenInfo(ulong slotId)
    {
        byte[] info = new byte[256];
        GCHandle pinned = GCHandle.Alloc(info, GCHandleType.Pinned);
        try
        {
            Pkcs11RvMapper.ThrowIfFailed(
                _getTokenInfo(ToNativeUlong(slotId), pinned.AddrOfPinnedObject()),
                "get token info");
        }
        finally
        {
            pinned.Free();
        }

        return new Pkcs11NativeTokenInfo(
            ReadPaddedUtf8(info.AsSpan(0, 32)),
            ReadPaddedUtf8(info.AsSpan(32, 32)),
            ReadPaddedUtf8(info.AsSpan(64, 16)),
            ReadPaddedUtf8(info.AsSpan(80, 16)));
    }

    public ulong OpenSession(ulong slotId)
    {
        nuint session = 0;
        uint flags = Pkcs11NativeConstants.CkfSerialSession | Pkcs11NativeConstants.CkfRwSession;
        Pkcs11RvMapper.ThrowIfFailed(
            _openSession(ToNativeUlong(slotId), flags, IntPtr.Zero, IntPtr.Zero, ref session),
            "open session");
        return session;
    }

    public void CloseSession(ulong session) =>
        Pkcs11RvMapper.ThrowIfFailed(_closeSession(ToNativeUlong(session)), "close session");

    public void LoginUser(ulong session, byte[] utf8Pin)
    {
        ArgumentNullException.ThrowIfNull(utf8Pin);
        GCHandle pinned = GCHandle.Alloc(utf8Pin, GCHandleType.Pinned);
        try
        {
            Pkcs11RvMapper.ThrowIfFailed(
                _login(
                    ToNativeUlong(session),
                    Pkcs11NativeConstants.CkuUser,
                    pinned.AddrOfPinnedObject(),
                    ToNativeUlong((ulong)utf8Pin.Length)),
                "login");
        }
        finally
        {
            pinned.Free();
        }
    }

    public void Logout(ulong session) =>
        Pkcs11RvMapper.ThrowIfFailed(_logout(ToNativeUlong(session)), "logout");

    public IReadOnlyList<ulong> FindObjects(ulong session, ulong objectClass, params (ulong Type, byte[] Value)[] additional)
    {
        additional ??= [];
        using AttributeBuffer template = AttributeBuffer.Create(_windowsUlong, objectClass, additional);
        Pkcs11RvMapper.ThrowIfFailed(
            _findObjectsInit(ToNativeUlong(session), template.Pointer, ToNativeUlong((ulong)template.Count)),
            "find objects init");
        try
        {
            byte[] handles = new byte[32 * UlongSize];
            GCHandle pinned = GCHandle.Alloc(handles, GCHandleType.Pinned);
            try
            {
                nuint found = 0;
                Pkcs11RvMapper.ThrowIfFailed(
                    _findObjects(ToNativeUlong(session), pinned.AddrOfPinnedObject(), ToNativeUlong(32), ref found),
                    "find objects");
                List<ulong> result = [];
                for (int index = 0; index < (int)found; index++)
                {
                    result.Add(ReadUlong(handles.AsSpan(index * UlongSize, UlongSize)));
                }

                return result;
            }
            finally
            {
                pinned.Free();
            }
        }
        finally
        {
            Pkcs11RvMapper.ThrowIfFailed(_findObjectsFinal(ToNativeUlong(session)), "find objects final");
        }
    }

    public byte[]? TryGetAttribute(ulong session, ulong objectHandle, ulong attributeType)
    {
        using AttributeBuffer lengthQuery = AttributeBuffer.ForRead(_windowsUlong, attributeType, IntPtr.Zero, 0);
        uint rv = _getAttributeValue(ToNativeUlong(session), ToNativeUlong(objectHandle), lengthQuery.Pointer, ToNativeUlong(1));
        if (rv != Pkcs11Rv.Ok)
        {
            return null;
        }

        nuint length = lengthQuery.ReadValueLength();
        if (length == 0 || length == nuint.MaxValue)
        {
            return [];
        }

        byte[] value = new byte[(int)length];
        GCHandle pinned = GCHandle.Alloc(value, GCHandleType.Pinned);
        try
        {
            using AttributeBuffer valueQuery = AttributeBuffer.ForRead(
                _windowsUlong,
                attributeType,
                pinned.AddrOfPinnedObject(),
                length);
            rv = _getAttributeValue(ToNativeUlong(session), ToNativeUlong(objectHandle), valueQuery.Pointer, ToNativeUlong(1));
            return rv == Pkcs11Rv.Ok ? value : null;
        }
        finally
        {
            pinned.Free();
        }
    }

    public void SignInit(ulong session, ulong mechanismType, ulong keyHandle)
    {
        using MechanismBuffer mechanism = MechanismBuffer.Create(_windowsUlong, mechanismType);
        Pkcs11RvMapper.ThrowIfFailed(
            _signInit(ToNativeUlong(session), mechanism.Pointer, ToNativeUlong(keyHandle)),
            "sign init");
    }

    public byte[] Sign(ulong session, ReadOnlySpan<byte> data)
    {
        byte[] payload = data.ToArray();
        GCHandle dataHandle = GCHandle.Alloc(payload, GCHandleType.Pinned);
        try
        {
            nuint signatureLength = 0;
            Pkcs11RvMapper.ThrowIfFailed(
                _sign(
                    ToNativeUlong(session),
                    dataHandle.AddrOfPinnedObject(),
                    ToNativeUlong((ulong)payload.Length),
                    IntPtr.Zero,
                    ref signatureLength),
                "sign");
            byte[] signature = new byte[(int)signatureLength];
            GCHandle signatureHandle = GCHandle.Alloc(signature, GCHandleType.Pinned);
            try
            {
                Pkcs11RvMapper.ThrowIfFailed(
                    _sign(
                        ToNativeUlong(session),
                        dataHandle.AddrOfPinnedObject(),
                        ToNativeUlong((ulong)payload.Length),
                        signatureHandle.AddrOfPinnedObject(),
                        ref signatureLength),
                    "sign");
                if ((int)signatureLength != signature.Length)
                {
                    Array.Resize(ref signature, (int)signatureLength);
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

    private nuint ToNativeUlong(ulong value) => _windowsUlong ? (uint)value : (nuint)value;

    private ulong ReadUlong(ReadOnlySpan<byte> source) =>
        _windowsUlong ? BitConverter.ToUInt32(source) : BitConverter.ToUInt64(source);

    private static T Get<T>(nint handle, string name) where T : Delegate
    {
        if (!NativeLibrary.TryGetExport(handle, name, out nint address))
        {
            throw new Pkcs11ProviderException(Pkcs11ErrorCode.DriverError, "PKCS#11 module is missing a required export.");
        }

        return Marshal.GetDelegateForFunctionPointer<T>(address);
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
    private delegate uint InitializeFn(IntPtr args);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FinalizeFn(IntPtr reserved);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GetSlotListFn(byte tokenPresent, IntPtr slotList, ref nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GetTokenInfoFn(nuint slotId, IntPtr info);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint OpenSessionFn(nuint slotId, uint flags, IntPtr application, IntPtr notify, ref nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint CloseSessionFn(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint LoginFn(nuint session, uint userType, IntPtr pin, nuint pinLength);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint LogoutFn(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FindObjectsInitFn(nuint session, IntPtr template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FindObjectsFn(nuint session, IntPtr objects, nuint maxCount, ref nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint FindObjectsFinalFn(nuint session);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint GetAttributeValueFn(nuint session, nuint objectHandle, IntPtr template, nuint count);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint SignInitFn(nuint session, IntPtr mechanism, nuint keyHandle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    private delegate uint SignFn(nuint session, IntPtr data, nuint dataLength, IntPtr signature, ref nuint signatureLength);

    private sealed class AttributeBuffer : IDisposable
    {
        private readonly List<GCHandle> _pins = [];
        private GCHandle _templatePin;
        private readonly byte[] _template;
        private readonly bool _windowsUlong;

        private AttributeBuffer(byte[] template, bool windowsUlong)
        {
            _template = template;
            _windowsUlong = windowsUlong;
            _templatePin = GCHandle.Alloc(template, GCHandleType.Pinned);
        }

        public IntPtr Pointer => _templatePin.AddrOfPinnedObject();
        public int Count { get; private init; }

        public static AttributeBuffer Create(bool windowsUlong, ulong objectClass, (ulong Type, byte[] Value)[] additional)
        {
            int count = 1 + additional.Length;
            int stride = AttributeStride(windowsUlong);
            AttributeBuffer buffer = new(new byte[count * stride], windowsUlong) { Count = count };
            buffer.WriteAttribute(0, Pkcs11NativeConstants.CkaClass, EncodeUlong(windowsUlong, objectClass));
            for (int index = 0; index < additional.Length; index++)
            {
                buffer.WriteAttribute(index + 1, additional[index].Type, additional[index].Value);
            }

            return buffer;
        }

        public static AttributeBuffer ForRead(bool windowsUlong, ulong type, IntPtr value, nuint length)
        {
            int stride = AttributeStride(windowsUlong);
            AttributeBuffer buffer = new(new byte[stride], windowsUlong) { Count = 1 };
            buffer.WriteHeader(0, type, value, length);
            return buffer;
        }

        public nuint ReadValueLength()
        {
            int stride = AttributeStride(_windowsUlong);
            int offset = _windowsUlong ? 16 : 16;
            return _windowsUlong
                ? BitConverter.ToUInt32(_template, offset)
                : (nuint)BitConverter.ToUInt64(_template, offset);
        }

        private void WriteAttribute(int index, ulong type, byte[] value)
        {
            GCHandle pin = GCHandle.Alloc(value, GCHandleType.Pinned);
            _pins.Add(pin);
            WriteHeader(index, type, pin.AddrOfPinnedObject(), (nuint)value.Length);
        }

        private void WriteHeader(int index, ulong type, IntPtr value, nuint length)
        {
            int stride = AttributeStride(_windowsUlong);
            int offset = index * stride;
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
                BitConverter.TryWriteBytes(_template.AsSpan(offset + 16), (ulong)length);
            }
        }

        public void Dispose()
        {
            if (_templatePin.IsAllocated)
            {
                _templatePin.Free();
            }

            foreach (GCHandle pin in _pins)
            {
                if (pin.IsAllocated)
                {
                    pin.Free();
                }
            }
        }

        private static int AttributeStride(bool windowsUlong) => 24;

        private static byte[] EncodeUlong(bool windowsUlong, ulong value)
        {
            return windowsUlong ? BitConverter.GetBytes((uint)value) : BitConverter.GetBytes(value);
        }

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

    private sealed class MechanismBuffer : IDisposable
    {
        private readonly byte[] _buffer;
        private GCHandle _pin;

        private MechanismBuffer(byte[] buffer)
        {
            _buffer = buffer;
            _pin = GCHandle.Alloc(buffer, GCHandleType.Pinned);
        }

        public IntPtr Pointer => _pin.AddrOfPinnedObject();

        public static MechanismBuffer Create(bool windowsUlong, ulong mechanismType)
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

            return new MechanismBuffer(buffer);
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
