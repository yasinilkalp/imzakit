namespace ImzaKit.ASiC;

internal static class ZipCrc32
{
    private static readonly uint[] Table = CreateTable();

    public static uint Compute(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte value in data)
        {
            crc = Table[(crc ^ value) & 0xFF] ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFF;
    }

    private static uint[] CreateTable()
    {
        uint[] table = new uint[256];
        for (uint index = 0; index < table.Length; index++)
        {
            uint crc = index;
            for (int bit = 0; bit < 8; bit++)
            {
                crc = (crc & 1) != 0 ? (0xEDB88320 ^ (crc >> 1)) : crc >> 1;
            }

            table[index] = crc;
        }

        return table;
    }
}
