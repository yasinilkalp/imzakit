using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Native;

public sealed class Pkcs11RvMapperTests
{
    [Theory]
    [InlineData(Pkcs11Rv.PinIncorrect, Pkcs11ErrorCode.PinIncorrect)]
    [InlineData(Pkcs11Rv.PinInvalid, Pkcs11ErrorCode.PinIncorrect)]
    [InlineData(Pkcs11Rv.PinLenRange, Pkcs11ErrorCode.PinIncorrect)]
    [InlineData(Pkcs11Rv.PinLocked, Pkcs11ErrorCode.PinLocked)]
    [InlineData(Pkcs11Rv.TokenNotPresent, Pkcs11ErrorCode.TokenRemoved)]
    [InlineData(Pkcs11Rv.DeviceRemoved, Pkcs11ErrorCode.TokenRemoved)]
    [InlineData(Pkcs11Rv.TokenNotRecognized, Pkcs11ErrorCode.TokenRemoved)]
    [InlineData(Pkcs11Rv.MechanismInvalid, Pkcs11ErrorCode.MechanismUnsupported)]
    [InlineData(Pkcs11Rv.MechanismParamInvalid, Pkcs11ErrorCode.MechanismUnsupported)]
    [InlineData(Pkcs11Rv.GeneralError, Pkcs11ErrorCode.DriverError)]
    [InlineData(Pkcs11Rv.DeviceError, Pkcs11ErrorCode.DriverError)]
    public void MapsKnownReturnValues(uint rv, Pkcs11ErrorCode expected)
    {
        Assert.Equal(expected, Pkcs11RvMapper.Map(rv));
    }

    [Fact]
    public void ThrowIfFailedOmitsCallerSuppliedPinFromMessage()
    {
        Pkcs11ProviderException exception = Assert.Throws<Pkcs11ProviderException>(
            () => Pkcs11RvMapper.ThrowIfFailed(Pkcs11Rv.PinIncorrect, "login"));

        Assert.Equal(Pkcs11ErrorCode.PinIncorrect, exception.Code);
        Assert.DoesNotContain("pin", exception.Message, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("login", exception.Message, StringComparison.OrdinalIgnoreCase);
    }
}
