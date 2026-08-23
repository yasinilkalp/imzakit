namespace ImzaKit.Pkcs11.Native;

public sealed record Pkcs11NativeTokenInfo(
    string Label,
    string Manufacturer,
    string Model,
    string SerialNumber);
