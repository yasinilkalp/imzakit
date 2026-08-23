namespace ImzaKit.Pkcs11.Models;

public sealed record Pkcs11Certificate(byte[] CkaId, string Label, byte[] DerEncoded);
