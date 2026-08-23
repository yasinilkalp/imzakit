using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Signing;

public sealed record Pkcs11SigningResult(
    Pkcs11SigningStatus Status,
    byte[]? Signature = null,
    Pkcs11Certificate? Certificate = null);
