namespace ImzaKit.Pkcs11.Models;

public sealed record Pkcs11Token(ulong SlotId, string Label, string Manufacturer, string Model, string MaskedSerialNumber);
