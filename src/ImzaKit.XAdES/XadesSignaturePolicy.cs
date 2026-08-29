namespace ImzaKit.XAdES;

public sealed class XadesSignaturePolicy
{
    public static XadesSignaturePolicy AllowAll { get; } = new(
        XadesPackaging.Enveloped,
        XadesPackaging.Enveloping,
        XadesPackaging.Detached);

    public XadesSignaturePolicy(params XadesPackaging[] allowedPackagings)
    {
        ArgumentNullException.ThrowIfNull(allowedPackagings);
        if (allowedPackagings.Length == 0)
        {
            throw new ArgumentException("At least one XMLDSig packaging must be allowed.", nameof(allowedPackagings));
        }

        AllowedPackagings = allowedPackagings.Distinct().ToArray();
    }

    public IReadOnlyList<XadesPackaging> AllowedPackagings { get; }

    public bool Allows(XadesPackaging packaging) => AllowedPackagings.Contains(packaging);

    public void EnsureAllowed(XadesPackaging packaging)
    {
        if (!Allows(packaging))
        {
            throw new InvalidOperationException($"XAdES packaging {packaging} is not allowed by policy.");
        }
    }
}
