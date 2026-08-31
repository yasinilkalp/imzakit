using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Hosts.Desktop.Pkcs11;

public sealed record NamedPkcs11Provider(string Name, IPkcs11Provider Provider);

public sealed record DesktopCertificateItem(
    string ProviderName,
    ulong SlotId,
    Pkcs11Certificate Certificate,
    string Subject);
