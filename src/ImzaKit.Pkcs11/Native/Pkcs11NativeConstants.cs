namespace ImzaKit.Pkcs11.Native;

public static class Pkcs11NativeConstants
{
    public const ulong CkoCertificate = 0x00000001;
    public const ulong CkoPrivateKey = 0x00000003;
    public const ulong CkcX509 = 0x00000000;
    public const ulong CkaClass = 0x00000000;
    public const ulong CkaLabel = 0x00000003;
    public const ulong CkaValue = 0x00000011;
    public const ulong CkaCertificateType = 0x00000080;
    public const ulong CkaId = 0x00000102;
    public const ulong CkaModulus = 0x00000120;
    public const ulong CkaSign = 0x00000108;
    public const ulong CkmSha256RsaPkcs = 0x00000040;
    public const uint CkfRwSession = 0x00000002;
    public const uint CkfSerialSession = 0x00000004;
    public const uint CkuUser = 1;
}

public static class Pkcs11Rv
{
    public const uint Ok = 0x00000000;
    public const uint DeviceError = 0x00000030;
    public const uint DeviceRemoved = 0x00000032;
    public const uint FunctionNotSupported = 0x00000054;
    public const uint MechanismInvalid = 0x00000070;
    public const uint MechanismParamInvalid = 0x00000071;
    public const uint PinIncorrect = 0x000000A0;
    public const uint PinInvalid = 0x000000A1;
    public const uint PinLenRange = 0x000000A2;
    public const uint PinLocked = 0x000000A4;
    public const uint TokenNotPresent = 0x000000E0;
    public const uint TokenNotRecognized = 0x000000E1;
    public const uint SessionClosed = 0x000000B0;
    public const uint GeneralError = 0x00000005;
    public const uint CryptokiNotInitialized = 0x00000190;
    public const uint CryptokiAlreadyInitialized = 0x00000191;
}
