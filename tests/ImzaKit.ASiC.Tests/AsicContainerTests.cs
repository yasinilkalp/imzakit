using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using ImzaKit.ASiC;

namespace ImzaKit.ASiC.Tests;

public sealed class AsicContainerTests
{
    [Fact]
    public void SimpleRoundTripPreservesSingleDataObjectAndSignature()
    {
        byte[] packed = AsicPacker.PackSimple(
            new AsicDataObject("document.txt", "hello-asic"u8),
            new AsicSignatureFile("signature.p7s", "p7s"u8));

        AsicContainer opened = AsicReader.Open(packed);

        Assert.Equal(AsicProfile.Simple, opened.Profile);
        Assert.Equal("document.txt", Assert.Single(opened.DataObjects).Name);
        Assert.Equal("hello-asic"u8.ToArray(), opened.DataObjects[0].Content);
        Assert.Equal("signature.p7s", Assert.Single(opened.Signatures).FileName);
        AssertFirstEntryIsStoredMimetype(packed, AsicMediaTypes.Simple);
        Assert.Contains("META-INF/signature.p7s"u8.ToArray(), packed);
    }

    [Fact]
    public void ExtendedRoundTripPreservesMultipleDataObjectsAndSignatures()
    {
        byte[] packed = AsicPacker.PackExtended(
            [
                new AsicDataObject("folder/b.txt", "two"u8),
                new AsicDataObject("a.txt", "one"u8)
            ],
            [
                new AsicSignatureFile("signatures.xml", "<sig/>"u8),
                new AsicSignatureFile("signature.p7s", "p7s"u8)
            ]);

        AsicContainer opened = AsicReader.Open(packed);

        Assert.Equal(AsicProfile.Extended, opened.Profile);
        Assert.Equal(["a.txt", "folder/b.txt"], opened.DataObjects.Select(item => item.Name));
        Assert.Equal(2, opened.Signatures.Count);
        AssertFirstEntryIsStoredMimetype(packed, AsicMediaTypes.Extended);
        Assert.Contains("META-INF/ASiCManifest.xml"u8.ToArray(), packed);
    }

    [Fact]
    public void PackingIsDeterministic()
    {
        AsicDataObject data = new("document.txt", "same"u8);
        AsicSignatureFile signature = new("signature.p7s", "p7s"u8);

        byte[] first = AsicPacker.PackSimple(data, signature);
        byte[] second = AsicPacker.PackSimple(data, signature);

        Assert.Equal(first, second);
    }

    [Fact]
    public void SimplePackRejectsNestedDataPath()
    {
        InvalidOperationException error = Assert.Throws<InvalidOperationException>(() =>
            AsicPacker.PackSimple(
                new AsicDataObject("folder/document.txt", "x"u8),
                new AsicSignatureFile("signature.p7s", "p7s"u8)));

        Assert.Contains("ASiC-S", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TraversalDataNameIsRejected()
    {
        Assert.ThrowsAny<Exception>(() => new AsicDataObject("../secret.txt", "x"u8));
    }

    [Fact]
    public void OpenRejectsPathTraversal()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("../secret.txt", "stolen"u8.ToArray()),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("path", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsDuplicateEntries()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("document.txt", "one"u8.ToArray()),
            Stored("document.txt", "two"u8.ToArray()),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("duplicate", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsCaseConflictingEntries()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("document.txt", "one"u8.ToArray()),
            Stored("Document.TXT", "two"u8.ToArray()),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("duplicate", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsZipBombCompressionRatio()
    {
        byte[] zeros = new byte[200_000];
        byte[] zip = AdversarialZip.Write(
        [
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Deflated("document.txt", zeros),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("ratio", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsMimetypeWhenNotFirst()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Stored("document.txt", "hello"u8.ToArray()),
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("mimetype", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsDeflatedMimetype()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Deflated("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("document.txt", "hello"u8.ToArray()),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("uncompressed", error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OpenRejectsSimpleContainerWithTwoDataObjects()
    {
        byte[] zip = AdversarialZip.Write(
        [
            Stored("mimetype", Encoding.ASCII.GetBytes(AsicMediaTypes.Simple)),
            Stored("a.txt", "one"u8.ToArray()),
            Stored("b.txt", "two"u8.ToArray()),
            Stored("META-INF/signature.p7s", "p7s"u8.ToArray())
        ]);

        InvalidDataException error = Assert.Throws<InvalidDataException>(() => AsicReader.Open(zip));
        Assert.Contains("ASiC-S", error.Message, StringComparison.Ordinal);
    }

    private static void AssertFirstEntryIsStoredMimetype(byte[] zip, string mediaType)
    {
        ushort method = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(8));
        ushort nameLength = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(26));
        ushort extraLength = BinaryPrimitives.ReadUInt16LittleEndian(zip.AsSpan(28));
        string name = Encoding.UTF8.GetString(zip, 30, nameLength);
        string value = Encoding.ASCII.GetString(zip, 30 + nameLength + extraLength, mediaType.Length);

        Assert.Equal(0, method);
        Assert.Equal(0, extraLength);
        Assert.Equal("mimetype", name);
        Assert.Equal(mediaType, value);
    }

    private static AdversarialZip.Item Stored(string name, byte[] content) =>
        new(name, 0, content, content);

    private static AdversarialZip.Item Deflated(string name, byte[] content)
    {
        using MemoryStream output = new();
        using (DeflateStream deflate = new(output, CompressionLevel.SmallestSize, leaveOpen: true))
        {
            deflate.Write(content);
        }

        return new(name, 8, content, output.ToArray());
    }
}

internal static class AdversarialZip
{
    public sealed record Item(string Name, ushort Method, byte[] Uncompressed, byte[] Compressed);

    public static byte[] Write(IReadOnlyList<Item> entries)
    {
        using MemoryStream stream = new();
        List<(Item Item, uint Crc, uint Offset)> written = [];
        foreach (Item item in entries)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(item.Name);
            uint crc = Crc(item.Uncompressed);
            uint offset = (uint)stream.Position;
            WriteUInt32(stream, 0x04034B50);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, item.Method);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0x0021);
            WriteUInt32(stream, crc);
            WriteUInt32(stream, (uint)item.Compressed.Length);
            WriteUInt32(stream, (uint)item.Uncompressed.Length);
            WriteUInt16(stream, (ushort)nameBytes.Length);
            WriteUInt16(stream, 0);
            stream.Write(nameBytes);
            stream.Write(item.Compressed);
            written.Add((item, crc, offset));
        }

        uint centralOffset = (uint)stream.Position;
        foreach ((Item item, uint crc, uint offset) in written)
        {
            byte[] nameBytes = Encoding.UTF8.GetBytes(item.Name);
            WriteUInt32(stream, 0x02014B50);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 20);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, item.Method);
            WriteUInt16(stream, 0);
            WriteUInt16(stream, 0x0021);
            WriteUInt32(stream, crc);
            WriteUInt32(stream, (uint)item.Compressed.Length);
            WriteUInt32(stream, (uint)item.Uncompressed.Length);
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
        WriteUInt32(stream, 0x06054B50);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, 0);
        WriteUInt16(stream, (ushort)written.Count);
        WriteUInt16(stream, (ushort)written.Count);
        WriteUInt32(stream, centralSize);
        WriteUInt32(stream, centralOffset);
        WriteUInt16(stream, 0);
        return stream.ToArray();
    }

    private static uint Crc(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (byte value in data)
        {
            uint lookup = (crc ^ value) & 0xFF;
            for (int bit = 0; bit < 8; bit++)
            {
                lookup = (lookup & 1) != 0 ? 0xEDB88320 ^ (lookup >> 1) : lookup >> 1;
            }

            crc = lookup ^ (crc >> 8);
        }

        return crc ^ 0xFFFFFFFF;
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
