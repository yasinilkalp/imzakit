using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Native;

public static class Pkcs11RvMapper
{
    public static Pkcs11ErrorCode Map(uint rv) => rv switch
    {
        Pkcs11Rv.PinIncorrect or Pkcs11Rv.PinInvalid or Pkcs11Rv.PinLenRange => Pkcs11ErrorCode.PinIncorrect,
        Pkcs11Rv.PinLocked => Pkcs11ErrorCode.PinLocked,
        Pkcs11Rv.TokenNotPresent or Pkcs11Rv.DeviceRemoved or Pkcs11Rv.TokenNotRecognized or Pkcs11Rv.SessionClosed =>
            Pkcs11ErrorCode.TokenRemoved,
        Pkcs11Rv.MechanismInvalid or Pkcs11Rv.MechanismParamInvalid or Pkcs11Rv.FunctionNotSupported =>
            Pkcs11ErrorCode.MechanismUnsupported,
        _ => Pkcs11ErrorCode.DriverError
    };

    public static void ThrowIfFailed(uint rv, string operation)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(operation);
        if (rv is Pkcs11Rv.Ok or Pkcs11Rv.CryptokiAlreadyInitialized)
        {
            return;
        }

        throw new Pkcs11ProviderException(Map(rv), $"PKCS#11 {operation} failed (0x{rv:X8}).");
    }
}
