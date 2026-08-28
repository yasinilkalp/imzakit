namespace ImzaKit.PAdES.Dss;

public sealed class PadesValidationMaterial
{
    public PadesValidationMaterial(
        IEnumerable<byte[]> certificates,
        IEnumerable<byte[]>? ocspResponses = null,
        IEnumerable<byte[]>? certificateRevocationLists = null)
    {
        ArgumentNullException.ThrowIfNull(certificates);
        Certificates = Copy(certificates);
        if (Certificates.Count == 0)
        {
            throw new ArgumentException("B-LT DSS requires at least one certificate.", nameof(certificates));
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
                throw new ArgumentException("Validation material entries cannot be empty.");
            }

            copy.Add(value.ToArray());
        }

        return copy;
    }
}
