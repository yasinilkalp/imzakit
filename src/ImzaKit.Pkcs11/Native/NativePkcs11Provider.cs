using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Pkcs11.Native;

public sealed class NativePkcs11Provider : IPkcs11Provider, IDisposable
{
    private readonly IPkcs11NativeApi _api;
    private readonly NativePkcs11ProviderOptions _options;
    private readonly object _gate = new();
    private readonly HashSet<ulong> _sessions = [];
    private readonly Dictionary<(ulong Session, string CkaIdHex), ulong> _privateKeysByCertificateId = [];
    private bool _initialized;
    private bool _disposed;

    public NativePkcs11Provider(IPkcs11NativeApi api, NativePkcs11ProviderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(api);
        _api = api;
        _options = options ?? NativePkcs11ProviderOptions.ForAkis();
    }

    public void Initialize() => Execute(() =>
    {
        if (_initialized)
        {
            return;
        }

        _api.Initialize();
        _initialized = true;
    });

    public IReadOnlyList<Pkcs11Token> DiscoverTokens() => Execute(() =>
    {
        EnsureInitialized();
        List<Pkcs11Token> tokens = [];
        foreach (ulong slotId in _api.GetSlotsWithPresentTokens())
        {
            Pkcs11NativeTokenInfo info = _api.GetTokenInfo(slotId);
            tokens.Add(new Pkcs11Token(
                slotId,
                info.Label,
                info.Manufacturer,
                info.Model,
                MaskSerial(info.SerialNumber)));
        }

        return tokens;
    });

    public ulong OpenSession(ulong slotId) => Execute(() =>
    {
        EnsureInitialized();
        ulong session = _api.OpenSession(slotId);
        _sessions.Add(session);
        return session;
    });

    public void Login(ulong session, ReadOnlySpan<char> pin) => Execute(() =>
    {
        EnsureInitialized();
        byte[] utf8Pin = Encoding.UTF8.GetBytes(pin);
        try
        {
            _api.LoginUser(session, utf8Pin);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(utf8Pin);
        }
    });

    public IReadOnlyList<Pkcs11Certificate> FindCertificates(ulong session) => Execute(() =>
    {
        EnsureInitialized();
        List<Pkcs11Certificate> certificates = [];
        foreach (ulong handle in _api.FindObjects(session, Pkcs11NativeConstants.CkoCertificate))
        {
            if (ReadUlongAttribute(session, handle, Pkcs11NativeConstants.CkaCertificateType) !=
                Pkcs11NativeConstants.CkcX509)
            {
                continue;
            }

            byte[]? ckaId = _api.TryGetAttribute(session, handle, Pkcs11NativeConstants.CkaId);
            byte[]? der = _api.TryGetAttribute(session, handle, Pkcs11NativeConstants.CkaValue);
            if (ckaId is null || der is null || ckaId.Length == 0 || der.Length == 0)
            {
                continue;
            }

            ulong? keyHandle = FindSignablePrivateKey(session, ckaId, der);
            if (_options.ExcludeCertificatesWithoutSignableKey && keyHandle is null)
            {
                continue;
            }

            if (keyHandle is not null)
            {
                _privateKeysByCertificateId[(session, Convert.ToHexString(ckaId))] = keyHandle.Value;
            }

            string label = Encoding.UTF8.GetString(
                _api.TryGetAttribute(session, handle, Pkcs11NativeConstants.CkaLabel) ?? []);
            certificates.Add(new Pkcs11Certificate(ckaId, label.Trim('\0', ' '), der));
        }

        return certificates;
    });

    public ulong? FindPrivateKey(ulong session, ReadOnlySpan<byte> ckaId) => Execute(() =>
    {
        EnsureInitialized();
        byte[] id = ckaId.ToArray();
        if (_options.MatchPrivateKeyByCkaIdFirst)
        {
            ulong? byId = FindSignablePrivateKeyByCkaId(session, id);
            if (byId is not null)
            {
                return byId;
            }
        }

        return _privateKeysByCertificateId.TryGetValue((session, Convert.ToHexString(id)), out ulong cached)
            ? cached
            : null;
    });

    public byte[] SignRsaPkcs1Sha256(ulong session, ulong keyHandle, ReadOnlySpan<byte> digestInfo) => Execute(() =>
    {
        EnsureInitialized();
        _api.SignInit(session, Pkcs11NativeConstants.CkmSha256RsaPkcs, keyHandle);
        return _api.Sign(session, digestInfo);
    });

    public void Logout(ulong session) => Execute(() =>
    {
        EnsureInitialized();
        _api.Logout(session);
    });

    public void CloseSession(ulong session) => Execute(() =>
    {
        EnsureInitialized();
        CloseSessionCore(session);
    });

    public void FinalizeProvider() => Execute(() =>
    {
        if (!_initialized)
        {
            return;
        }

        foreach (ulong session in _sessions.ToArray())
        {
            try
            {
                CloseSessionCore(session);
            }
            catch (Pkcs11ProviderException)
            {
            }
        }

        _api.FinalizeCryptoki();
        _initialized = false;
        _privateKeysByCertificateId.Clear();
    });

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        try
        {
            if (_initialized)
            {
                FinalizeProvider();
            }
        }
        catch (Pkcs11ProviderException)
        {
        }

        _api.Dispose();
        _disposed = true;
    }

    private ulong? FindSignablePrivateKey(ulong session, byte[] certificateCkaId, byte[] certificateDer)
    {
        if (_options.MatchPrivateKeyByCkaIdFirst)
        {
            ulong? byId = FindSignablePrivateKeyByCkaId(session, certificateCkaId);
            if (byId is not null)
            {
                return byId;
            }
        }

        return _options.AllowPublicKeyFallback
            ? FindSignablePrivateKeyByModulus(session, certificateDer)
            : null;
    }

    private ulong? FindSignablePrivateKeyByCkaId(ulong session, byte[] ckaId)
    {
        foreach (ulong handle in _api.FindObjects(
            session,
            Pkcs11NativeConstants.CkoPrivateKey,
            (Pkcs11NativeConstants.CkaId, ckaId)))
        {
            if (IsSignable(session, handle))
            {
                return handle;
            }
        }

        return null;
    }

    private ulong? FindSignablePrivateKeyByModulus(ulong session, byte[] certificateDer)
    {
        byte[]? modulus = TryReadCertificateModulus(certificateDer);
        if (modulus is null)
        {
            return null;
        }

        foreach (ulong handle in _api.FindObjects(session, Pkcs11NativeConstants.CkoPrivateKey))
        {
            if (!IsSignable(session, handle))
            {
                continue;
            }

            byte[]? keyModulus = _api.TryGetAttribute(session, handle, Pkcs11NativeConstants.CkaModulus);
            if (keyModulus is not null && ModulusEquals(modulus, keyModulus))
            {
                return handle;
            }
        }

        return null;
    }

    private bool IsSignable(ulong session, ulong privateKeyHandle)
    {
        byte[]? sign = _api.TryGetAttribute(session, privateKeyHandle, Pkcs11NativeConstants.CkaSign);
        return sign is { Length: > 0 } && sign[0] != 0;
    }

    private ulong ReadUlongAttribute(ulong session, ulong objectHandle, ulong attributeType)
    {
        byte[]? value = _api.TryGetAttribute(session, objectHandle, attributeType);
        if (value is null || value.Length == 0)
        {
            return 0;
        }

        if (value.Length >= 8)
        {
            return BitConverter.ToUInt64(value, 0);
        }

        if (value.Length >= 4)
        {
            return BitConverter.ToUInt32(value, 0);
        }

        return value[0];
    }

    private void CloseSessionCore(ulong session)
    {
        _api.CloseSession(session);
        _sessions.Remove(session);
        foreach ((ulong Session, string CkaIdHex) key in _privateKeysByCertificateId.Keys
            .Where(item => item.Session == session)
            .ToArray())
        {
            _privateKeysByCertificateId.Remove(key);
        }
    }

    private void EnsureInitialized()
    {
        if (!_initialized)
        {
            throw new Pkcs11ProviderException(Pkcs11ErrorCode.DriverError, "PKCS#11 provider is not initialized.");
        }
    }

    private void Execute(Action action) => Execute(() =>
    {
        action();
        return 0;
    });

    private T Execute<T>(Func<T> action)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (!_options.RequiresSingleThreadedProviderAccess)
        {
            return action();
        }

        lock (_gate)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            return action();
        }
    }

    private static byte[]? TryReadCertificateModulus(byte[] der)
    {
        try
        {
            using X509Certificate2 certificate = new(der);
            using RSA? rsa = certificate.GetRSAPublicKey();
            return rsa?.ExportParameters(includePrivateParameters: false).Modulus;
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static bool ModulusEquals(byte[] left, byte[] right)
    {
        ReadOnlySpan<byte> normalizedLeft = StripLeadingZeros(left);
        ReadOnlySpan<byte> normalizedRight = StripLeadingZeros(right);
        return normalizedLeft.Length == normalizedRight.Length &&
               CryptographicOperations.FixedTimeEquals(normalizedLeft, normalizedRight);
    }

    private static ReadOnlySpan<byte> StripLeadingZeros(byte[] value)
    {
        int index = 0;
        while (index < value.Length - 1 && value[index] == 0)
        {
            index++;
        }

        return value.AsSpan(index);
    }

    private static string MaskSerial(string serial)
    {
        if (string.IsNullOrWhiteSpace(serial))
        {
            return "****";
        }

        string trimmed = serial.Trim();
        string visible = trimmed.Length <= 4 ? trimmed : trimmed[^4..];
        return "****" + visible;
    }
}
