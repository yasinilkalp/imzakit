namespace ImzaKit.Cms.Completion;

public sealed class CmsUnsignedValue
{
    public CmsUnsignedValue(string oid, byte[] value)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(oid);
        ArgumentNullException.ThrowIfNull(value);
        if (value.Length == 0)
        {
            throw new ArgumentException("Unsigned attribute value cannot be empty.", nameof(value));
        }

        Oid = oid;
        Value = value.ToArray();
    }

    public string Oid { get; }

    public byte[] Value { get; }
}
