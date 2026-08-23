using System.Text;
using ImzaKit.Pkcs11.Models;
using ImzaKit.Pkcs11.Native;

namespace ImzaKit.Pkcs11.Tests.Native;

internal sealed class FakePkcs11NativeApi : IPkcs11NativeApi
{
    private readonly object _gate = new();
    private readonly List<FakeObject> _objects = [];
    private int _currentCalls;
    private bool _disposed;
    private ulong _nextSession = 11;

    public int InitializeCalls { get; private set; }
    public int FinalizeCalls { get; private set; }
    public int MaxConcurrentCalls { get; private set; }
    public int OpenSessionCount { get; private set; }
    public TimeSpan CallDelay { get; set; }
    public Pkcs11ErrorCode? LoginFailure { get; set; }
    public Pkcs11ErrorCode? SignFailure { get; set; }
    public byte[]? LastLoginPinBuffer { get; private set; }
    public ulong LastSignMechanism { get; private set; }
    public bool PrivateKeyValueWasRead { get; private set; }
    public List<string> Calls { get; } = [];
    public byte[] SignableCertificateDer { get; } = [0x30, 0x03, 0x01, 0x02, 0x03];
    public Pkcs11NativeTokenInfo Token { get; } = new("AKIS", "KamuSM", "Model", "1234567890");

    public static FakePkcs11NativeApi CreateAkisFixture()
    {
        FakePkcs11NativeApi api = new();
        api._objects.Add(Certificate(20, [1, 2], "NES", api.SignableCertificateDer, Pkcs11NativeConstants.CkcX509));
        api._objects.Add(Certificate(30, [3, 4], "Auth", [0x30, 0x01], Pkcs11NativeConstants.CkcX509));
        api._objects.Add(Certificate(40, [9, 9], "WTLS", [0x01], 1));
        api._objects.Add(PrivateKey(21, [1, 2], sign: true));
        api._objects.Add(PrivateKey(31, [3, 4], sign: false));
        return api;
    }

    public static FakePkcs11NativeApi CreateModulusFallbackFixture(byte[] certificateDer, byte[] modulus)
    {
        FakePkcs11NativeApi api = new();
        api._objects.Add(Certificate(20, [0xAA], "NES", certificateDer, Pkcs11NativeConstants.CkcX509));
        FakeObject key = PrivateKey(42, [0xBB], sign: true);
        key.Attributes[Pkcs11NativeConstants.CkaModulus] = modulus;
        api._objects.Add(key);
        return api;
    }

    public void Initialize() => Track("Initialize", () => InitializeCalls++);

    public void FinalizeCryptoki() => Track("Finalize", () =>
    {
        OpenSessionCount = 0;
        FinalizeCalls++;
    });

    public IReadOnlyList<ulong> GetSlotsWithPresentTokens() =>
        Track("GetSlots", () => (IReadOnlyList<ulong>)[7UL]);

    public Pkcs11NativeTokenInfo GetTokenInfo(ulong slotId) =>
        Track("GetTokenInfo", () => Token);

    public ulong OpenSession(ulong slotId) => Track("OpenSession", () =>
    {
        OpenSessionCount++;
        return _nextSession++;
    });

    public void CloseSession(ulong session) => Track("CloseSession", () =>
    {
        if (OpenSessionCount > 0)
        {
            OpenSessionCount--;
        }
    });

    public void LoginUser(ulong session, byte[] utf8Pin) => Track("Login", () =>
    {
        ArgumentNullException.ThrowIfNull(utf8Pin);
        LastLoginPinBuffer = utf8Pin;
        if (LoginFailure is not null)
        {
            throw new Pkcs11ProviderException(LoginFailure.Value);
        }
    });

    public void Logout(ulong session) => Track("Logout", () => { });

    public IReadOnlyList<ulong> FindObjects(
        ulong session,
        ulong objectClass,
        params (ulong Type, byte[] Value)[] additional) =>
        Track("FindObjects", () =>
        {
            List<ulong> matches = [];
            foreach (FakeObject item in _objects)
            {
                if (item.Class != objectClass)
                {
                    continue;
                }

                bool matched = true;
                foreach ((ulong Type, byte[] Value) filter in additional)
                {
                    if (!item.Attributes.TryGetValue(filter.Type, out byte[]? stored) ||
                        !stored.AsSpan().SequenceEqual(filter.Value))
                    {
                        matched = false;
                        break;
                    }
                }

                if (matched)
                {
                    matches.Add(item.Handle);
                }
            }

            return (IReadOnlyList<ulong>)matches;
        });

    public byte[]? TryGetAttribute(ulong session, ulong objectHandle, ulong attributeType) =>
        Track("GetAttribute", () =>
        {
            FakeObject? item = _objects.FirstOrDefault(candidate => candidate.Handle == objectHandle);
            if (item is null)
            {
                return null;
            }

            if (item.Class == Pkcs11NativeConstants.CkoPrivateKey &&
                attributeType == Pkcs11NativeConstants.CkaValue)
            {
                PrivateKeyValueWasRead = true;
                return null;
            }

            return item.Attributes.TryGetValue(attributeType, out byte[]? value) ? value : null;
        });

    public void SignInit(ulong session, ulong mechanismType, ulong keyHandle) => Track("SignInit", () =>
    {
        LastSignMechanism = mechanismType;
        if (SignFailure is not null)
        {
            throw new Pkcs11ProviderException(SignFailure.Value);
        }
    });

    public byte[] Sign(ulong session, ReadOnlySpan<byte> data) =>
        Track("Sign", () => (byte[])[0x55, 0x66]);

    public void Dispose() => _disposed = true;

    private T Track<T>(string name, Func<T> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        int current = Interlocked.Increment(ref _currentCalls);
        try
        {
            lock (_gate)
            {
                MaxConcurrentCalls = Math.Max(MaxConcurrentCalls, current);
                Calls.Add(name);
            }

            if (CallDelay > TimeSpan.Zero)
            {
                Thread.Sleep(CallDelay);
            }

            return action();
        }
        finally
        {
            Interlocked.Decrement(ref _currentCalls);
        }
    }

    private void Track(string name, Action action) => Track(name, () =>
    {
        action();
        return 0;
    });

    private static FakeObject Certificate(ulong handle, byte[] ckaId, string label, byte[] value, ulong certificateType) =>
        new(handle, Pkcs11NativeConstants.CkoCertificate)
        {
            Attributes =
            {
                [Pkcs11NativeConstants.CkaCertificateType] = BitConverter.GetBytes(certificateType),
                [Pkcs11NativeConstants.CkaId] = ckaId,
                [Pkcs11NativeConstants.CkaLabel] = Encoding.UTF8.GetBytes(label),
                [Pkcs11NativeConstants.CkaValue] = value
            }
        };

    private static FakeObject PrivateKey(ulong handle, byte[] ckaId, bool sign) =>
        new(handle, Pkcs11NativeConstants.CkoPrivateKey)
        {
            Attributes =
            {
                [Pkcs11NativeConstants.CkaId] = ckaId,
                [Pkcs11NativeConstants.CkaSign] = [(byte)(sign ? 1 : 0)]
            }
        };

    private sealed class FakeObject(ulong handle, ulong objectClass)
    {
        public ulong Handle { get; } = handle;
        public ulong Class { get; } = objectClass;
        public Dictionary<ulong, byte[]> Attributes { get; } = [];
    }
}
