using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ImzaKit.Pkcs11.Abstractions;
using ImzaKit.Pkcs11.Models;

namespace ImzaKit.Hosts.Desktop.Pkcs11;

public static class TokenCertificateCatalog
{
    public static IReadOnlyList<DesktopCertificateItem> List(IEnumerable<NamedPkcs11Provider> providers)
    {
        ArgumentNullException.ThrowIfNull(providers);
        List<DesktopCertificateItem> items = [];
        foreach (NamedPkcs11Provider named in providers)
        {
            if (named.Provider is null || string.IsNullOrWhiteSpace(named.Name))
            {
                continue;
            }

            try
            {
                named.Provider.Initialize();
                IReadOnlyList<Pkcs11Token> tokens;
                try
                {
                    tokens = named.Provider.DiscoverTokens();
                }
                catch (Pkcs11ProviderException)
                {
                    continue;
                }

                foreach (Pkcs11Token token in tokens)
                {
                    ulong session = 0;
                    bool opened = false;
                    try
                    {
                        session = named.Provider.OpenSession(token.SlotId);
                        opened = true;
                        foreach (Pkcs11Certificate certificate in named.Provider.FindCertificates(session))
                        {
                            items.Add(new(
                                named.Name,
                                token.SlotId,
                                certificate,
                                ReadSubject(certificate.DerEncoded)));
                        }
                    }
                    catch (Pkcs11ProviderException)
                    {
                    }
                    finally
                    {
                        if (opened)
                        {
                            try
                            {
                                named.Provider.CloseSession(session);
                            }
                            catch (Pkcs11ProviderException)
                            {
                            }
                        }
                    }
                }
            }
            catch (Pkcs11ProviderException)
            {
            }
        }

        return items;
    }

    private static string ReadSubject(byte[] der)
    {
        try
        {
            using X509Certificate2 certificate = X509CertificateLoader.LoadCertificate(der);
            return string.IsNullOrWhiteSpace(certificate.Subject) ? certificate.Thumbprint : certificate.Subject;
        }
        catch (CryptographicException)
        {
            return "Sertifika";
        }
    }
}
