using System.Security.Cryptography;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Signing;

public sealed class Pkcs11SigningService(IPkcs11Provider provider)
{
    public Pkcs11SigningResult Sign(
        ulong slotId,
        ReadOnlySpan<byte> certificateCkaId,
        ReadOnlySpan<char> pin,
        ReadOnlySpan<byte> digestInfo)
    {
        ulong session = 0;
        bool initialized = false;
        bool sessionOpened = false;
        bool loggedIn = false;
        try
        {
            provider.Initialize();
            initialized = true;
            if (!provider.DiscoverTokens().Any(token => token.SlotId == slotId))
            {
                return new(Pkcs11SigningStatus.TokenNotFound);
            }

            session = provider.OpenSession(slotId);
            sessionOpened = true;
            provider.Login(session, pin);
            loggedIn = true;

            byte[] requestedCkaId = certificateCkaId.ToArray();
            Pkcs11Certificate? certificate = provider.FindCertificates(session)
                .FirstOrDefault(item => CryptographicOperations.FixedTimeEquals(item.CkaId, requestedCkaId));
            if (certificate is null) return new(Pkcs11SigningStatus.CertificateNotFound);

            ulong? keyHandle = provider.FindPrivateKey(session, certificate.CkaId);
            if (keyHandle is null) return new(Pkcs11SigningStatus.PrivateKeyNotFound);

            byte[] signature = provider.SignRsaPkcs1Sha256(session, keyHandle.Value, digestInfo);
            return new(Pkcs11SigningStatus.Succeeded, signature, certificate);
        }
        catch (Pkcs11ProviderException exception)
        {
            return new(Map(exception.Code));
        }
        finally
        {
            if (loggedIn) SafeCleanup(() => provider.Logout(session));
            if (sessionOpened) SafeCleanup(() => provider.CloseSession(session));
            if (initialized) SafeCleanup(provider.FinalizeProvider);
        }
    }

    private static Pkcs11SigningStatus Map(Pkcs11ErrorCode code) => code switch
    {
        Pkcs11ErrorCode.PinIncorrect => Pkcs11SigningStatus.PinIncorrect,
        Pkcs11ErrorCode.PinLocked => Pkcs11SigningStatus.PinLocked,
        Pkcs11ErrorCode.TokenRemoved => Pkcs11SigningStatus.TokenRemoved,
        Pkcs11ErrorCode.MechanismUnsupported => Pkcs11SigningStatus.MechanismUnsupported,
        _ => Pkcs11SigningStatus.DriverError
    };

    private static void SafeCleanup(Action cleanup)
    {
        try { cleanup(); }
        catch (Pkcs11ProviderException) { }
    }
}
