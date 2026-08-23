namespace ImzaKit.Pkcs11.Models;

public sealed class Pkcs11ProviderException(Pkcs11ErrorCode code, string? message = null, Exception? innerException = null)
    : Exception(message ?? code.ToString(), innerException)
{
    public Pkcs11ErrorCode Code { get; } = code;
}
