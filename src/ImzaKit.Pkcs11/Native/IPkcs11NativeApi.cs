namespace ImzaKit.Pkcs11.Native;

public interface IPkcs11NativeApi : IDisposable
{
    void Initialize();
    void FinalizeCryptoki();
    IReadOnlyList<ulong> GetSlotsWithPresentTokens();
    Pkcs11NativeTokenInfo GetTokenInfo(ulong slotId);
    ulong OpenSession(ulong slotId);
    void CloseSession(ulong session);
    void LoginUser(ulong session, byte[] utf8Pin);
    void Logout(ulong session);
    IReadOnlyList<ulong> FindObjects(ulong session, ulong objectClass, params (ulong Type, byte[] Value)[] additional);
    byte[]? TryGetAttribute(ulong session, ulong objectHandle, ulong attributeType);
    void SignInit(ulong session, ulong mechanismType, ulong keyHandle);
    byte[] Sign(ulong session, ReadOnlySpan<byte> data);
}
