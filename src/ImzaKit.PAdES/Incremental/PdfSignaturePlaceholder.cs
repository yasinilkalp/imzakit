namespace ImzaKit.PAdES.Incremental;

public sealed class PdfSignaturePlaceholder
{
    private readonly byte[] documentBytes;
    private readonly long[] byteRange;

    public PdfSignaturePlaceholder(byte[] documentBytes, int contentsOffset, int contentsLength, long[] byteRange)
    {
        ArgumentNullException.ThrowIfNull(documentBytes);
        ArgumentNullException.ThrowIfNull(byteRange);
        this.documentBytes = documentBytes.ToArray();
        ContentsOffset = contentsOffset;
        ContentsLength = contentsLength;
        this.byteRange = byteRange.ToArray();
    }

    public byte[] DocumentBytes => documentBytes.ToArray();

    public int ContentsOffset { get; }

    public int ContentsLength { get; }

    public long[] ByteRange => byteRange.ToArray();

    public byte[] GetSignableBytes()
    {
        byte[] signableBytes = new byte[documentBytes.Length - ContentsLength];
        documentBytes.AsSpan(0, ContentsOffset).CopyTo(signableBytes);
        documentBytes.AsSpan(ContentsOffset + ContentsLength).CopyTo(
            signableBytes.AsSpan(ContentsOffset));
        return signableBytes;
    }

    public byte[] EmbedSignature(byte[] cmsSignature)
    {
        ArgumentNullException.ThrowIfNull(cmsSignature);

        int capacity = (ContentsLength - 2) / 2;
        if (cmsSignature.Length > capacity)
        {
            throw new ArgumentException(
                $"CMS signature length {cmsSignature.Length} exceeds reserved capacity {capacity}.",
                nameof(cmsSignature));
        }

        byte[] signedDocument = documentBytes.ToArray();
        string hexadecimalSignature = Convert.ToHexString(cmsSignature);
        System.Text.Encoding.ASCII.GetBytes(
            hexadecimalSignature,
            signedDocument.AsSpan(ContentsOffset + 1, hexadecimalSignature.Length));

        return signedDocument;
    }
}
