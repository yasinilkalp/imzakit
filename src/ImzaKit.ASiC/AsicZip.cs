using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace ImzaKit.ASiC;

internal static class AsicZip
{
    private const uint LocalSignature = 0x04034B50;
    private const uint CentralSignature = 0x02014B50;
    private const uint EocdSignature = 0x06054B50;
    private const ushort Store = 0;
    private const ushort Deflate = 8;
    private const ushort Version = 20;
    private const ushort DosDate = 0x0021;
    private const int LocalHeaderSize = 30;
    private const int CentralHeaderSize = 46;
    private const int EocdSize = 22;

    public sealed record Entry(string Name, ushort Method, byte[] Content);

    public static byte[] Write(IReadOnlyList<Entry> entries)
    {
        ArgumentNullException.ThrowIfNull(entries);
        using MemoryStream stream = new();
        List<(Entry Entry, uint Crc, uint Offset, byte[] Payload)> written = [];
        foreach (Entry entry in entries)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.Name);
            byte[] payload = entry.Method == Store ? entry.Content : DeflateBytes(entry.Content);
            uint crc = ZipCrc32.Compute(entry.Content);
            uint offset = (uint)stream.Position;
            WriteUInt32(stream, LocalSignature);
            WriteUInt16(stream, Version);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, entry.Method);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, DosDate);
            WriteUInt32(stream, crc);
            WriteUInt32(stream, (uint)payload.Length);
            WriteUInt32(stream, (uint)entry.Content.Length);
            WriteUInt16(stream, (ushort)nameBytes.Length);
            WriteUInt16(stream, 0);
            stream.Write(nameBytes);
            stream.Write(payload);
            written.Add((entry, crc, offset, payload));
        }

        uint centralOffset = (uint)stream.Position;
        foreach ((Entry entry, uint crc, uint offset, byte[] payload) in written)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(entry.Name);
            WriteUInt32(stream, CentralSignature);
            WriteUInt16(stream, Version);
            WriteUInt16(stream, Version);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, entry.Method);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, DosDate);
            WriteUInt32(stream, crc);
            WriteUInt32(stream, (uint)payload.Length);
            WriteUInt32(stream, (uint)entry.Content.Length);
            WriteUInt16(stream, (ushort)nameBytes.Length);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0);
            WriteUInt32(stream, 0);
            WriteUInt32(stream, offset);
            stream.Write(nameBytes);
        }

        uint centralSize = (uint)stream.Position - centralOffset;
        WriteUInt32(stream, EocdSignature);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, (ushort)written.Count);
        WriteUInt16(stream, (ushort)written.Count);
        WriteUInt32(stream, centralSize);
        WriteUInt32(stream, centralOffset);
        WriteUInt16(stream, 0);
        return stream.ToArray();
    }

    public static IReadOnlyList<Entry> Read(ReadOnlySpan<byte> zip)
    {
        if (zip.Length < EocdSize)
        {
            throw new InvalidDataException("ASiC container is not a ZIP archive.");
        }

        int eocd = FindEocd(zip);
        ushort disk = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(eocd + 4));
        ushort entries = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(eocd + 8));
        ushort total = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(eocd + 10));
        uint centralSize = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(eocd + 12));
        uint centralOffset = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(eocd + 16));
        if (disk != 0 || entries != total || entries == 0xFFFF || centralSize == 0xFFFFFFFF || centralOffset == 0xFFFFFFFF)
        {
            throw new InvalidDataException("ASiC ZIP64 or split archives are not allowed.");
        }

        if (entries == 0 || entries > AsicLimits.MaxEntries)
        {
            throw new InvalidDataException("ASiC ZIP entry count exceeds the allowed limit.");
        }

        long centralEnd = (long)centralOffset + centralSize;
        if (centralEnd > eocd || centralOffset >= zip.Length)
        {
            throw new InvalidDataException("ASiC ZIP central directory is truncated.");
        }

        List<Entry> result = [];
        HashSet<string> names = new(StringComparer.OrdinalIgnoreCase);
        int cursor = (int)centralOffset;
        int totalUncompressed = 0;
        for (int index = 0; index < entries; index++)
        {
            if (cursor + CentralHeaderSize > zip.Length
                || BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(cursor)) != CentralSignature)
            {
                throw new InvalidDataException("ASiC ZIP central directory is invalid.");
            }

            ushort flags = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(cursor + 8));
            ushort method = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(cursor + 10));
            uint compressed = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(cursor + 20));
            uint uncompressed = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(cursor + 24));
            ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(cursor + 28));
            ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(cursor + 30));
            ushort commentLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(cursor + 32));
            uint localOffset = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(cursor + 42));
            if ((flags & 0x0001) != 0 || (flags & 0x0008) != 0)
            {
                throw new InvalidDataException("ASiC ZIP encryption and data descriptors are not allowed.");
            }

            int nameStart = cursor + CentralHeaderSize;
            if (nameStart + nameLen > zip.Length)
            {
                throw new InvalidDataException("ASiC ZIP central directory is truncated.");
            }

            string name = AsicPaths.ValidateZipEntryName(Encoding.UTF8.GetString(zip.Slice(nameStart, nameLen)));
            if (!names.Add(name))
            {
                throw new InvalidDataException("ASiC ZIP duplicate entry is not allowed.");
            }

            byte[] content = ReadLocalFile(zip, localOffset, name, method, compressed, uncompressed, extraLen);
            totalUncompressed = checked(totalUncompressed + content.Length);
            if (totalUncompressed > AsicLimits.MaxTotalUncompressedBytes)
            {
                throw new InvalidDataException("ASiC ZIP uncompressed size exceeds the allowed limit.");
            }

            result.Add(new Entry(name, method, content));
            cursor = nameStart + nameLen + extraLen + commentLen;
        }

        if (result.Count == 0 || result[0].Name != AsicPaths.MimeTypeEntry)
        {
            throw new InvalidDataException("ASiC mimetype must be the first ZIP entry.");
        }

        if (result[0].Method != Store)
        {
            throw new InvalidDataException("ASiC mimetype must be stored uncompressed.");
        }

        return result;
    }

    public static Entry Stored(string name, byte[] content) => new(name, Store, content);

    private static byte[] ReadLocalFile(
        ReadOnlySpan<byte> zip,
        uint localOffset,
        string expectedName,
        ushort method,
        uint compressed,
        uint uncompressed,
        ushort centralExtra)
    {
        if (localOffset > zip.Length - LocalHeaderSize
            || BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice((int)localOffset)) != LocalSignature)
        {
            throw new InvalidDataException("ASiC ZIP local header is invalid.");
        }

        int header = (int)localOffset;
        ushort localFlags = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(header + 6));
        ushort localMethod = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(header + 8));
        uint localCompressed = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(header + 18));
        uint localUncompressed = BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(header + 22));
        ushort nameLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(header + 26));
        ushort extraLen = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(header + 28));
        if ((localFlags & 0x0001) != 0 || (localFlags & 0x0008) != 0 || localMethod != method)
        {
            throw new InvalidDataException("ASiC ZIP local header is invalid.");
        }

        if (expectedName == AsicPaths.MimeTypeEntry && extraLen != 0)
        {
            throw new InvalidDataException("ASiC mimetype must not have a ZIP extra field.");
        }

        int nameStart = header + LocalHeaderSize;
        if (nameStart + nameLen + extraLen + compressed > zip.Length)
        {
            throw new InvalidDataException("ASiC ZIP local file is truncated.");
        }

        string localName = AsicPaths.ValidateZipEntryName(Encoding.UTF8.GetString(zip.Slice(nameStart, nameLen)));
        if (!string.Equals(localName, expectedName, StringComparison.Ordinal)
            || localCompressed != compressed
            || localUncompressed != uncompressed)
        {
            throw new InvalidDataException("ASiC ZIP local header does not match the central directory.");
        }

        _ = centralExtra;
        byte[] payload = zip.Slice(nameStart + nameLen + extraLen, (int)compressed).ToArray();
        return Inflate(method, payload, uncompressed);
    }

    private static byte[] Inflate(ushort method, byte[] payload, uint uncompressed)
    {
        if (uncompressed > AsicLimits.MaxEntryUncompressedBytes)
        {
            throw new InvalidDataException("ASiC ZIP uncompressed size exceeds the allowed limit.");
        }

        if (method == Store)
        {
            if (payload.Length != uncompressed)
            {
                throw new InvalidDataException("ASiC stored ZIP entry size mismatch.");
            }

            return payload;
        }

        if (method != Deflate)
        {
            throw new InvalidDataException("ASiC ZIP compression method is not allowed.");
        }

        if (payload.Length > 0 && uncompressed / Math.Max(payload.Length, 1) > AsicLimits.MaxCompressionRatio)
        {
            throw new InvalidDataException("ASiC ZIP compression ratio exceeds the allowed limit.");
        }

        using MemoryStream input = new(payload, writable: false);
        using DeflateStream deflate = new(input, CompressionMode.Decompress);
        using MemoryStream output = new();
        byte[] buffer = new byte[4096];
        int total = 0;
        while (true)
        {
            int read = deflate.Read(buffer, 0, buffer.Length);
            if (read == 0)
            {
                break;
            }

            total += read;
            if (total > uncompressed || total > AsicLimits.MaxEntryUncompressedBytes)
            {
                throw new InvalidDataException("ASiC ZIP uncompressed size exceeds the allowed limit.");
            }

            output.Write(buffer, 0, read);
        }

        if (total != uncompressed)
        {
            throw new InvalidDataException("ASiC ZIP deflate size mismatch.");
        }

        return output.ToArray();
    }

    private static byte[] DeflateBytes(byte[] content)
    {
        using MemoryStream output = new();
        using (DeflateStream deflate = new(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(content);
        }

        return output.ToArray();
    }

    private static int FindEocd(ReadOnlySpan<byte> zip)
    {
        int min = Math.Max(0, zip.Length - EocdSize - 65535);
        for (int offset = zip.Length - EocdSize; offset >= min; offset--)
        {
            if (BinaryPrimitives.ReadUInt32LittleEndian(zip.Slice(offset)) != EocdSignature)
            {
                continue;
            }

            ushort comment = BinaryPrimitives.ReadUInt16LittleEndian(zip.Slice(offset + 20));
            if (offset + EocdSize + comment == zip.Length)
            {
                return offset;
            }
        }

        throw new InvalidDataException("ASiC ZIP end of central directory is missing.");
    }

    private static void WriteUInt16(Stream stream, ushort value)
    {
        Span<byte> buffer = stackalloc byte[2];
        BinaryPrimitives.WriteUInt16LittleEndian(buffer, value);
        stream.Write(buffer);
    }

    private static void WriteUInt32(Stream stream, uint value)
    {
        Span<byte> buffer = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buffer, value);
        stream.Write(buffer);
    }
}
