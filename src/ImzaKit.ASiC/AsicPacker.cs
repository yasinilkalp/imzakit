using System.Text;

namespace ImzaKit.ASiC;

public static class AsicPacker
{
    public static byte[] PackSimple(AsicDataObject data, AsicSignatureFile signature)
    {
        ArgumentNullException.ThrowIfNull(data);
        ArgumentNullException.ThrowIfNull(signature);
        AsicPaths.ValidateDataName(data.Name, allowDirectory: false);
        return Pack(AsicProfile.Simple, [data], [signature]);
    }

    public static byte[] PackExtended(
        IReadOnlyList<AsicDataObject> dataObjects,
        IReadOnlyList<AsicSignatureFile> signatures)
    {
        ArgumentNullException.ThrowIfNull(dataObjects);
        ArgumentNullException.ThrowIfNull(signatures);
        if (dataObjects.Count == 0)
        {
            throw new ArgumentException("ASiC-E requires at least one data object.", nameof(dataObjects));
        }

        if (signatures.Count == 0)
        {
            throw new ArgumentException("ASiC-E requires at least one signature.", nameof(signatures));
        }

        foreach (AsicDataObject data in dataObjects)
        {
            ArgumentNullException.ThrowIfNull(data);
            AsicPaths.ValidateDataName(data.Name, allowDirectory: true);
        }

        return Pack(AsicProfile.Extended, dataObjects, signatures);
    }

    private static byte[] Pack(
        AsicProfile profile,
        IReadOnlyList<AsicDataObject> dataObjects,
        IReadOnlyList<AsicSignatureFile> signatures)
    {
        HashSet<string> dataNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (AsicDataObject data in dataObjects)
        {
            if (!dataNames.Add(data.Name))
            {
                throw new InvalidOperationException("ASiC data object names must be unique.");
            }
        }

        HashSet<string> signatureNames = new(StringComparer.OrdinalIgnoreCase);
        foreach (AsicSignatureFile signature in signatures)
        {
            ArgumentNullException.ThrowIfNull(signature);
            if (!signatureNames.Add(signature.FileName))
            {
                throw new InvalidOperationException("ASiC signature file names must be unique.");
            }
        }

        List<AsicZip.Entry> entries =
        [
            AsicZip.Stored(
                AsicPaths.MimeTypeEntry,
                Encoding.ASCII.GetBytes(
                    profile == AsicProfile.Simple ? AsicMediaTypes.Simple : AsicMediaTypes.Extended))
        ];

        AsicDataObject[] orderedData = [.. dataObjects.OrderBy(item => item.Name, StringComparer.Ordinal)];
        AsicSignatureFile[] orderedSignatures =
            [.. signatures.OrderBy(item => item.FileName, StringComparer.Ordinal)];

        foreach (AsicDataObject data in orderedData)
        {
            entries.Add(AsicZip.Stored(data.Name, data.Content));
        }

        if (profile == AsicProfile.Extended)
        {
            entries.Add(
                AsicZip.Stored(
                    AsicPaths.MetaInfFile(AsicPaths.ManifestFile),
                    AsicManifest.Create(orderedData, orderedSignatures)));
        }

        foreach (AsicSignatureFile signature in orderedSignatures)
        {
            entries.Add(AsicZip.Stored(AsicPaths.MetaInfFile(signature.FileName), signature.Content));
        }

        return AsicZip.Write(entries);
    }
}
