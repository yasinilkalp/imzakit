namespace ImzaKit.ASiC;

public enum AsicProfile
{
    Simple,
    Extended
}

public static class AsicMediaTypes
{
    public const string Simple = "application/vnd.etsi.asic-s+zip";
    public const string Extended = "application/vnd.etsi.asic-e+zip";
}

public static class AsicLimits
{
    public const int MaxEntries = 256;
    public const int MaxEntryUncompressedBytes = 8 * 1024 * 1024;
    public const int MaxTotalUncompressedBytes = 16 * 1024 * 1024;
    public const int MaxCompressionRatio = 100;
}

public sealed class AsicDataObject
{
    public AsicDataObject(string name, ReadOnlySpan<byte> content)
    {
        Name = AsicPaths.ValidateDataName(name, allowDirectory: true);
        Content = content.ToArray();
    }

    public string Name { get; }

    public byte[] Content { get; }
}

public sealed class AsicSignatureFile
{
    public AsicSignatureFile(string fileName, ReadOnlySpan<byte> content)
    {
        FileName = AsicPaths.ValidateSignatureFileName(fileName);
        Content = content.ToArray();
    }

    public string FileName { get; }

    public byte[] Content { get; }
}

public sealed class AsicContainer
{
    public AsicContainer(
        AsicProfile profile,
        IReadOnlyList<AsicDataObject> dataObjects,
        IReadOnlyList<AsicSignatureFile> signatures)
    {
        ArgumentNullException.ThrowIfNull(dataObjects);
        ArgumentNullException.ThrowIfNull(signatures);
        Profile = profile;
        DataObjects = dataObjects;
        Signatures = signatures;
    }

    public AsicProfile Profile { get; }

    public IReadOnlyList<AsicDataObject> DataObjects { get; }

    public IReadOnlyList<AsicSignatureFile> Signatures { get; }
}
