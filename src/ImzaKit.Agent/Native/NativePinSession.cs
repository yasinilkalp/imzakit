namespace ImzaKit.Agent.Native;

public sealed class NativePinSession : IDisposable
{
    private char[]? _pin;

    public NativePinSession(ReadOnlySpan<char> pin) => _pin = pin.ToArray();

    public void Use(Action<ReadOnlySpan<char>> consume)
    {
        ArgumentNullException.ThrowIfNull(consume);
        ObjectDisposedException.ThrowIf(_pin is null, this);

        consume(_pin);
    }

    public void Dispose()
    {
        if (_pin is null)
        {
            return;
        }

        Array.Clear(_pin);
        _pin = null;
    }
}
