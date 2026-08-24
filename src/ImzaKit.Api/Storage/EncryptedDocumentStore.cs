using System.Globalization;
using System.Security.Cryptography;

namespace ImzaKit.Api.Storage;

public sealed class EncryptedDocumentStore : IDocumentStore
{
    private readonly IBlobStore _blobs;
    private readonly byte[] _key;
    private readonly TimeProvider _timeProvider;
    private readonly StorageRetentionPolicy _retention;
    private readonly Lock _gate = new();
    private readonly Dictionary<string, StoredDocument> _index = new(StringComparer.Ordinal);

    public EncryptedDocumentStore(
        IBlobStore blobs,
        ReadOnlySpan<byte> encryptionKey,
        TimeProvider? timeProvider = null,
        StorageRetentionPolicy? retention = null)
    {
        ArgumentNullException.ThrowIfNull(blobs);
        if (encryptionKey.Length != 32)
        {
            throw new ArgumentOutOfRangeException(nameof(encryptionKey), "Document store key must be 32 bytes.");
        }

        _blobs = blobs;
        _key = encryptionKey.ToArray();
        _timeProvider = timeProvider ?? TimeProvider.System;
        _retention = retention ?? StorageRetentionPolicy.Default;
    }

    public DocumentObject Put(string tenantId, ReadOnlySpan<byte> content, string contentType, TimeSpan? ttl = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(contentType);
        TimeSpan lifetime = ttl ?? _retention.CompletedArtifact;
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);

        DateTimeOffset now = _timeProvider.GetUtcNow();
        string tenantHash = MetadataKey.Hash(tenantId);
        string objectKey = $"{tenantHash}/{Guid.NewGuid():N}";
        byte[] plain = content.ToArray();
        string sha256 = Convert.ToHexString(SHA256.HashData(plain));
        _blobs.Put(objectKey, Encrypt(plain));
        StoredDocument stored = new(tenantHash, objectKey, sha256, contentType, plain.Length, now.Add(lifetime));
        lock (_gate)
        {
            _index[objectKey] = stored;
        }

        return new DocumentObject(objectKey, sha256, contentType, plain.Length, stored.ExpiresAt);
    }

    public bool TryGet(string tenantId, string objectKey, out byte[] content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(objectKey);
        content = [];
        if (!TryRead(objectKey, MetadataKey.Hash(tenantId), out byte[] bytes))
        {
            return false;
        }

        content = bytes;
        return true;
    }

    public DocumentAccessUrl CreateDownloadUrl(string tenantId, string objectKey, TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        ArgumentException.ThrowIfNullOrWhiteSpace(objectKey);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(lifetime, TimeSpan.Zero);

        if (!TryGet(tenantId, objectKey, out _))
        {
            throw new InvalidOperationException("Document is not accessible for this tenant.");
        }

        DateTimeOffset expiresAt = _timeProvider.GetUtcNow().Add(lifetime);
        string tenantHash = MetadataKey.Hash(tenantId);
        string payload = $"{tenantHash}|{objectKey}|{expiresAt.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture)}";
        string url = "imzakit://download/" + payload + "|" + Convert.ToHexString(Hmac(payload));
        return new DocumentAccessUrl(url, expiresAt);
    }

    public bool TryRedeem(string url, out byte[] content)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(url);
        content = [];
        const string prefix = "imzakit://download/";
        if (!url.StartsWith(prefix, StringComparison.Ordinal))
        {
            return false;
        }

        string token = url[prefix.Length..];
        int split = token.LastIndexOf('|');
        if (split <= 0)
        {
            return false;
        }

        string payload = token[..split];
        string signature = token[(split + 1)..];
        if (!CryptographicOperations.FixedTimeEquals(Hmac(payload), Convert.FromHexString(signature)))
        {
            return false;
        }

        string[] parts = payload.Split('|');
        if (parts.Length != 3 ||
            !long.TryParse(parts[2], CultureInfo.InvariantCulture, out long expiresUnix) ||
            DateTimeOffset.FromUnixTimeSeconds(expiresUnix) <= _timeProvider.GetUtcNow())
        {
            return false;
        }

        return TryRead(parts[1], parts[0], out content);
    }

    public int SweepExpired()
    {
        lock (_gate)
        {
            DateTimeOffset now = _timeProvider.GetUtcNow();
            List<string> expired = [.. _index.Where(pair => pair.Value.ExpiresAt <= now).Select(pair => pair.Key)];
            foreach (string key in expired)
            {
                _index.Remove(key);
                _blobs.Remove(key);
            }

            return expired.Count;
        }
    }

    private bool TryRead(string objectKey, string tenantHash, out byte[] content)
    {
        content = [];
        StoredDocument stored;
        lock (_gate)
        {
            if (!_index.TryGetValue(objectKey, out stored!) ||
                stored.ExpiresAt <= _timeProvider.GetUtcNow() ||
                !string.Equals(stored.TenantHash, tenantHash, StringComparison.Ordinal))
            {
                return false;
            }
        }

        if (!_blobs.TryGet(objectKey, out byte[] cipher) || !TryDecrypt(cipher, out byte[] plain))
        {
            return false;
        }

        content = plain;
        return true;
    }

    private byte[] Encrypt(ReadOnlySpan<byte> plain)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(AesGcm.NonceByteSizes.MaxSize);
        byte[] cipher = new byte[plain.Length];
        byte[] tag = new byte[AesGcm.TagByteSizes.MaxSize];
        using AesGcm aes = new(_key, tag.Length);
        aes.Encrypt(nonce, plain, cipher, tag);
        byte[] packed = new byte[nonce.Length + tag.Length + cipher.Length];
        nonce.CopyTo(packed);
        tag.CopyTo(packed.AsSpan(nonce.Length));
        cipher.CopyTo(packed.AsSpan(nonce.Length + tag.Length));
        return packed;
    }

    private bool TryDecrypt(byte[] packed, out byte[] plain)
    {
        plain = [];
        int nonceLength = AesGcm.NonceByteSizes.MaxSize;
        int tagLength = AesGcm.TagByteSizes.MaxSize;
        if (packed.Length < nonceLength + tagLength)
        {
            return false;
        }

        ReadOnlySpan<byte> nonce = packed.AsSpan(0, nonceLength);
        ReadOnlySpan<byte> tag = packed.AsSpan(nonceLength, tagLength);
        ReadOnlySpan<byte> cipher = packed.AsSpan(nonceLength + tagLength);
        byte[] output = new byte[cipher.Length];
        try
        {
            using AesGcm aes = new(_key, tagLength);
            aes.Decrypt(nonce, cipher, tag, output);
            plain = output;
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private byte[] Hmac(string payload) => HMACSHA256.HashData(_key, System.Text.Encoding.UTF8.GetBytes(payload));

    private sealed record StoredDocument(
        string TenantHash,
        string ObjectKey,
        string Sha256,
        string ContentType,
        long Size,
        DateTimeOffset ExpiresAt);
}
