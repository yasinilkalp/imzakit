namespace ImzaKit.Timestamp.Rfc3161;

public sealed record TimeStampAuthority(string Name, Uri Url);

public sealed record Rfc3161TimeStampResult(byte[] TokenDer, byte[] Nonce);
