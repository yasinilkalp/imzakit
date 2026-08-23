namespace ImzaKit.Pkcs11.Signing;

public enum Pkcs11SigningStatus
{
    Succeeded,
    TokenNotFound,
    CertificateNotFound,
    PrivateKeyNotFound,
    PinIncorrect,
    PinLocked,
    TokenRemoved,
    MechanismUnsupported,
    DriverError
}
