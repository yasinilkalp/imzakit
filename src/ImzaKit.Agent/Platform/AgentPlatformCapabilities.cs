namespace ImzaKit.Agent.Platform;

public sealed record AgentPlatformAssessment(
    bool LoopbackProtocolSupported,
    bool NativePinSupported,
    bool NativeConsentSupported,
    bool HostReady);

public static class AgentPlatformCapabilities
{
    public static AgentPlatformAssessment Evaluate()
    {
        bool windows = OperatingSystem.IsWindows();
        return new(
            LoopbackProtocolSupported: true,
            NativePinSupported: windows,
            NativeConsentSupported: windows,
            HostReady: windows);
    }
}
