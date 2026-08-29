namespace ImzaKit.XAdES;

public sealed class XadesLongTermEvidence
{
    public XadesLongTermEvidence(
        IEnumerable<byte[]> certificates,
        IEnumerable<byte[]>? ocspResponses = null,
        IEnumerable<byte[]>? certificateRevocationLists = null)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        Certificates = Copy(certificates);
        if (Certificates.Count == 0)
        {
            throw new ArgumentException("XAdES B-LT requires at least one certificate.", nameof(certificates));
        }

        OcspResponses = Copy(ocspResponses);
        CertificateRevocationLists = Copy(certificateRevocationLists);
    }

    public IReadOnlyList<byte[]> Certificates { get; }

    public IReadOnlyList<byte[]> OcspResponses { get; }

    public IReadOnlyList<byte[]> CertificateRevocationLists { get; }

    private static List<byte[]> Copy(IEnumerable<byte[]>? values)
    {
        if (values is null)
        {
            return [];
        }

        List<byte[]> copy = [];
        foreach (byte[] value in values)
        {
            ArgumentNullException.ThrowIfNull(value);
            if (value.Length == 0)
            {
                throw new ArgumentException("Long-term evidence entries cannot be empty.");
            }

            copy.Add(value.ToArray());
        }

        return copy;
    }
}
