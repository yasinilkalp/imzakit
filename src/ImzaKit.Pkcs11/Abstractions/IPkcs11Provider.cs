using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Abstractions;

public interface IPkcs11Provider
{
    void Initialize();
    IReadOnlyList<Pkcs11Token> DiscoverTokens();
    ulong OpenSession(ulong slotId);
    void Login(ulong session, ReadOnlySpan<char> pin);
    IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session);
    ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId);
    byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> digestInfo);
    void Logout(ulong session);
    void CloseSession(ulong session);
    void FinalizeProvider();
}
