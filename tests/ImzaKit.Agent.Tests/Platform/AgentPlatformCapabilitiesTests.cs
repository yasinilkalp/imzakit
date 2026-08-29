using ImzaKit.Agent.Native;
using ImzaKit.Agent.Platform;

namespace ImzaKit.Agent.Tests.Platform;

public sealed class AgentPlatformCapabilitiesTests
{
    [Fact]
    public void LoopbackProtocolIsSupportedOnEveryOs()
    {
        AgentPlatformAssessment assessment = AgentPlatformCapabilities.Evaluate();

        Assert.True(assessment.LoopbackProtocolSupported);
        Assert.Equal(OperatingSystem.IsWindows(), assessment.NativePinSupported);
        Assert.Equal(OperatingSystem.IsWindows(), assessment.NativeConsentSupported);
        Assert.Equal(OperatingSystem.IsWindows(), assessment.HostReady);
    }

    [Fact]
    public void UnsupportedPinPromptFailsClosedWithoutASession()
    {
        UnsupportedNativePinPrompt prompt = new();

        using NativePinSession? session = prompt.Acquire();

        Assert.Null(session);
    }

    [Fact]
    public void UnsupportedConsentPromptDeniesWithoutAskingForPin()
    {
        UnsupportedNativeConsentPrompt prompt = new();

        NativeConsentDecision decision = prompt.Prompt(new NativeConsentRequest(
            "sozlesme.pdf",
            "AABBCCDDEEFF",
            "https://app.example",
            "Test NES",
            "SHA256withRSA"));

        Assert.Equal(NativeConsentDecision.Denied, decision);
    }

    [Fact]
    public void NonWindowsCredUiDoesNotReturnAPin()
    {
        if (OperatingSystem.IsWindows())
        {
            return;
        }

        CredUiSecurePinDialog dialog = new();

        bool read = dialog.TryReadPin(new PinDialogRequest("caption", "message"), out char[] pin);

        Assert.False(read);
        Assert.Empty(pin);
    }
}
