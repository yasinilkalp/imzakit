using System.Text;

namespace ImzaKit.ASiC;

public static class AsicReader
{
    public static AsicContainer Open(ReadOnlySpan<byte> container)
    {
        IReadOnlyList<AsicZip.Entry> entries = AsicZip.Read(container);
        AsicProfile profile = ReadProfile(entries[0].Content);
        List<AsicDataObject> data = [];
        List<AsicSignatureFile> signatures = [];
        byte[]? manifest = null;
        for (int index = 1; index < entries.Count; index++)
        {
            AsicZip.Entry entry = entries[index];
            if (AsicPaths.IsMetaInf(entry.Name))
            {
                string fileName = entry.Name[(AsicPaths.MetaInf.Length + 1)..];
                if (string.Equals(fileName, AsicPaths.ManifestFile, StringComparison.OrdinalIgnoreCase))
                {
                    manifest = entry.Content;
                    continue;
                }

                try
                {
                    signatures.Add(new AsicSignatureFile(fileName, entry.Content));
                }
                catch (InvalidOperationException)
                {
                    throw new InvalidDataException("ASiC META-INF entry is not allowed.");
                }
                continue;
            }

            data.Add(new AsicDataObject(entry.Name, entry.Content));
        }

        if (profile == AsicProfile.Simple && data.Count != 1)
        {
            throw new InvalidDataException("ASiC-S must contain exactly one data object.");
        }

        if (profile == AsicProfile.Extended && data.Count == 0)
        {
            throw new InvalidDataException("ASiC-E must contain at least one data object.");
        }

        if (signatures.Count == 0)
        {
            throw new InvalidDataException("ASiC container must contain a signature in META-INF.");
        }

        if (profile == AsicProfile.Simple && data[0].Name.Contains('/', StringComparison.Ordinal))
        {
            throw new InvalidDataException("ASiC-S data objects must be a single root file.");
        }

        if (manifest is not null)
        {
            if (profile != AsicProfile.Extended)
            {
                throw new InvalidDataException("ASiC-S must not contain an ASiCManifest.");
            }

            AsicManifest.Verify(manifest, data);
        }

        return new AsicContainer(profile, data, signatures);
    }

    private static AsicProfile ReadProfile(byte[] mimetype)
    {
        string value = Encoding.ASCII.GetString(mimetype);
        return value switch
        {
            AsicMediaTypes.Simple => AsicProfile.Simple,
            AsicMediaTypes.Extended => AsicProfile.Extended,
            _ => throw new InvalidDataException("ASiC mimetype is not a supported ASiC media type.")
        };
    }
}
