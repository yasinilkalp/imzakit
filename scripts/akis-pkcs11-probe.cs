using System.Runtime.InteropServices;
using System.Text;

string path = Environment.GetEnvironmentVariable("IMZAKIT_AKIS_MODULE")
    ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "akisp11.dll");
Console.WriteLine($"Module: {path}");
if (!File.Exists(path))
{
    Console.WriteLine("Module not found.");
    return 2;
}

nint handle = NativeLibrary.Load(path);
try
{
    nint init = NativeLibrary.GetExport(handle, "C_Initialize");
    nint getSlotList = NativeLibrary.GetExport(handle, "C_GetSlotList");
    nint getTokenInfo = NativeLibrary.GetExport(handle, "C_GetTokenInfo");
    nint getSlotInfo = NativeLibrary.GetExport(handle, "C_GetSlotInfo");
    nint finalize = NativeLibrary.GetExport(handle, "C_Finalize");

    CInitialize initialize = Marshal.GetDelegateForFunctionPointer<CInitialize>(init);
    CGetSlotListByte getSlotsByte = Marshal.GetDelegateForFunctionPointer<CGetSlotListByte>(getSlotList);
    CGetSlotListUInt getSlotsUInt = Marshal.GetDelegateForFunctionPointer<CGetSlotListUInt>(getSlotList);
    CGetTokenInfo getToken = Marshal.GetDelegateForFunctionPointer<CGetTokenInfo>(getTokenInfo);
    CGetSlotInfo getSlot = Marshal.GetDelegateForFunctionPointer<CGetSlotInfo>(getSlotInfo);
    CFinalize cFinalize = Marshal.GetDelegateForFunctionPointer<CFinalize>(finalize);

    uint rvInit = initialize(IntPtr.Zero);
    Console.WriteLine($"C_Initialize(NULL) = 0x{rvInit:X8}");

    ProbeSlots("byte tokenPresent=1", (list, count) => getSlotsByte(1, list, count), getToken, getSlot);

    uint rvFin = cFinalize(IntPtr.Zero);
    Console.WriteLine($"C_Finalize = 0x{rvFin:X8}");
    return 0;
}
finally
{
    NativeLibrary.Free(handle);
}

void ProbeSlots(string label, Func<IntPtr, nint, uint> getSlots, CGetTokenInfo getToken, CGetSlotInfo getSlot)
{
    nint countPtr = Marshal.AllocHGlobal(4);
    nint listPtr = IntPtr.Zero;
    try
    {
        Marshal.WriteInt32(countPtr, 0);
        uint rv = getSlots(IntPtr.Zero, countPtr);
        int count = Marshal.ReadInt32(countPtr);
        Console.WriteLine($"{label}: first C_GetSlotList rv=0x{rv:X8} count={count}");
        if (rv != 0 || count <= 0)
        {
            return;
        }

        listPtr = Marshal.AllocHGlobal(count * 4);
        rv = getSlots(listPtr, countPtr);
        count = Marshal.ReadInt32(countPtr);
        Console.WriteLine($"{label}: second C_GetSlotList rv=0x{rv:X8} count={count}");
        for (int i = 0; i < count; i++)
        {
            uint slotId = (uint)Marshal.ReadInt32(listPtr + (i * 4));
            nint info = Marshal.AllocHGlobal(256);
            try
            {
                for (int b = 0; b < 256; b++)
                {
                    Marshal.WriteByte(info, b, 0);
                }

                uint tokenRv = getToken(slotId, info);
                nint slotInfo = Marshal.AllocHGlobal(256);
                uint slotRv;
                uint flags;
                string description;
                try
                {
                    for (int b = 0; b < 256; b++)
                    {
                        Marshal.WriteByte(slotInfo, b, 0);
                    }

                    slotRv = getSlot(slotId, slotInfo);
                    description = ReadPad(slotInfo, 0, 64);
                    flags = (uint)Marshal.ReadInt32(slotInfo, 96);
                }
                finally
                {
                    Marshal.FreeHGlobal(slotInfo);
                }

                string labelText = ReadPad(info, 0, 32);
                string manufacturer = ReadPad(info, 32, 32);
                string model = ReadPad(info, 64, 16);
                Console.WriteLine(
                    $"  slot={slotId} C_GetSlotInfo=0x{slotRv:X8} flags=0x{flags:X8} desc='{description}' " +
                    $"C_GetTokenInfo=0x{tokenRv:X8} label='{labelText}' manufacturer='{manufacturer}' model='{model}'");
            }
            finally
            {
                Marshal.FreeHGlobal(info);
            }
        }
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

static string ReadPad(nint info, int offset, int length)
{
    byte[] buffer = new byte[length];
    Marshal.Copy(info + offset, buffer, 0, length);
    int end = buffer.Length;
    while (end > 0 && (buffer[end - 1] == 0 || buffer[end - 1] == (byte)' '))
    {
        end--;
    }

    return Encoding.ASCII.GetString(buffer, 0, end);
}

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CInitialize(IntPtr args);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CFinalize(IntPtr reserved);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CGetSlotListByte(byte tokenPresent, IntPtr slotList, nint count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CGetSlotListUInt(uint tokenPresent, IntPtr slotList, nint count);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CGetTokenInfo(uint slotId, IntPtr info);

[UnmanagedFunctionPointer(CallingConvention.Cdecl)]
delegate uint CGetSlotInfo(uint slotId, IntPtr info);
