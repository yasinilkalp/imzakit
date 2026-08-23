using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Signing;

namespace ImzaKit.Pkcs11.Tests.Signing;

public sealed class Pkcs11SigningServiceTests
{
    [Fact]
    public void SuccessfulSignMatchesCertificateAndKeyByCkaIdAndCleansUp()
    {
        FakeProvider provider = new();
        Pkcs11SigningResult result = new Pkcs11SigningService(provider).Sign(
            provider.Token.SlotId, provider.Certificate.CkaId, "1234".AsSpan(), [1, 2, 3]);

        Assert.Equal(Pkcs11SigningStatus.Succeeded, result.Status);
        Assert.Equal([9, 8, 7], result.Signature);
        Assert.Equal(provider.Certificate, result.Certificate);
        Assert.Equal(["Initialize", "Discover", "Open", "Login", "Certificates", "Key:0102", "Sign", "Logout", "Close", "Finalize"], provider.Calls);
        Assert.DoesNotContain("1234", string.Join('|', provider.Calls));
    }

    [Theory]
    [InlineData(Pkcs11ErrorCode.PinIncorrect, Pkcs11SigningStatus.PinIncorrect)]
    [InlineData(Pkcs11ErrorCode.PinLocked, Pkcs11SigningStatus.PinLocked)]
    [InlineData(Pkcs11ErrorCode.TokenRemoved, Pkcs11SigningStatus.TokenRemoved)]
    [InlineData(Pkcs11ErrorCode.MechanismUnsupported, Pkcs11SigningStatus.MechanismUnsupported)]
    public void ProviderFailuresHaveDedicatedResults(Pkcs11ErrorCode error, Pkcs11SigningStatus expected)
    {
        FakeProvider provider = new() { Failure = error };

        Pkcs11SigningResult result = new Pkcs11SigningService(provider).Sign(
            provider.Token.SlotId, provider.Certificate.CkaId, "secret".AsSpan(), [1]);

        Assert.Equal(expected, result.Status);
        Assert.Null(result.Signature);
        Assert.Contains("Finalize", provider.Calls);
        Assert.DoesNotContain("secret", string.Join('|', provider.Calls));
    }

    [Fact]
    public void MissingPrivateKeyWithSameCkaIdIsReported()
    {
        FakeProvider provider = new() { KeyMatches = false };

        Pkcs11SigningResult result = new Pkcs11SigningService(provider).Sign(
            provider.Token.SlotId, provider.Certificate.CkaId, "1234".AsSpan(), [1]);

        Assert.Equal(Pkcs11SigningStatus.PrivateKeyNotFound, result.Status);
        Assert.Null(result.Signature);
        Assert.DoesNotContain("Sign", provider.Calls);
    }

    private sealed class FakeProvider : IPkcs11Provider
    {
        public Pkcs11Token Token { get; } = new(7, "AKIS", "KamuSM", "Model", "****1234");
        public Pkcs11Certificate Certificate { get; } = new([1, 2], "NES", [3, 4]);
        public List<string> Calls { get; } = [];
        public Pkcs11ErrorCode? Failure { get; init; }
        public bool KeyMatches { get; init; } = true;

        public void Initialize() => Calls.Add("Initialize");
        public IReadOnlyList<Pkcs11Token> DiscoverTokens() { Calls.Add("Discover"); return [Token]; }
        public ulong OpenSession(ulong slotId) { Calls.Add("Open"); return 11; }
        public void Login(ulong session, ReadOnlySpan<char> pin)
        {
            Calls.Add("Login");
            Fail(Failure is Pkcs11ErrorCode.PinIncorrect or Pkcs11ErrorCode.PinLocked ? Failure.Value : Pkcs11ErrorCode.PinIncorrect);
        }
        public IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session) { Calls.Add("Certificates"); return [Certificate]; }
        public ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId) { Calls.Add($"Key:{Convert.ToHexString(ckaId)}"); return KeyMatches ? 21UL : null; }
        public byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> digestInfo) { Calls.Add("Sign"); Fail(Failure is Pkcs11ErrorCode.TokenRemoved or Pkcs11ErrorCode.MechanismUnsupported ? Failure.Value : null); return [9, 8, 7]; }
        public void Logout(ulong session) => Calls.Add("Logout");
        public void CloseSession(ulong session) => Calls.Add("Close");
        public void FinalizeProvider() => Calls.Add("Finalize");
        private void Fail(Pkcs11ErrorCode? code) { if (Failure == code && code is not null) throw new Pkcs11ProviderException(code.Value); }
    }
}
