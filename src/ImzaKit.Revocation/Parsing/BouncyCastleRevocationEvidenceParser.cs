using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Org.BouncyCastle.X509;
using BcX509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace ImzaKit.Revocation.Parsing;

public sealed class BouncyCastleRevocationEvidenceParser : IRevocationEvidenceParser
{
    private static readonly HashSet<string> SupportedCriticalCrlExtensions =
    [
        X509Extensions.IssuingDistributionPoint.Id,
        X509Extensions.DeltaCrlIndicator.Id
    ];

    public ParsedRevocationEvidence Parse(
        RevocationEvidence evidence,
        CertificateDescriptor certificate,
        CertificateDescriptor issuer)
    {
        ArgumentNullException.ThrowIfNull(evidence);
        ArgumentNullException.ThrowIfNull(certificate);
        ArgumentNullException.ThrowIfNull(issuer);

        try
        {
            return evidence.Type switch
            {
                RevocationEvidenceType.Ocsp => ParseOcsp(evidence, certificate, issuer),
                RevocationEvidenceType.Crl => ParseCrl(evidence, certificate, issuer),
                _ => Invalid()
            };
        }
        catch (Exception exception) when (exception is
            IOException or
            ArgumentException or
            InvalidOperationException or
            OcspException or
            CrlException or
            CertificateException or
            SecurityUtilityException)
        {
            return Invalid();
        }
    }

    private static ParsedRevocationEvidence ParseOcsp(
        RevocationEvidence evidence,
        CertificateDescriptor certificate,
        CertificateDescriptor issuer)
    {
        BcX509Certificate issuerCertificate = ReadCertificate(issuer);
        BcX509Certificate targetCertificate = ReadCertificate(certificate);
        OcspResp response = new(evidence.ExportEncoded());
        if (response.Status != OCSPRespGenerator.Successful
            || response.GetResponseObject() is not BasicOcspResp basicResponse)
        {
            return Invalid();
        }

        bool signatureValid = basicResponse.Verify(issuerCertificate.GetPublicKey());
        SingleResp? singleResponse = basicResponse.Responses.FirstOrDefault(candidate =>
            candidate.GetCertID().SerialNumber.Equals(targetCertificate.SerialNumber)
            && candidate.GetCertID().MatchesIssuer(issuerCertificate));
        if (singleResponse is null)
        {
            return new(RevocationStatus.Invalid, false, signatureValid, signatureValid, null, null, null);
        }

        object? certificateStatus = singleResponse.GetCertStatus();
        RevocationStatus status = certificateStatus switch
        {
            null => RevocationStatus.Good,
            RevokedStatus revoked when revoked.HasRevocationReason
                && revoked.RevocationReason == CrlReason.CertificateHold => RevocationStatus.Suspended,
            RevokedStatus => RevocationStatus.Revoked,
            _ => RevocationStatus.Invalid
        };
        string? reason = certificateStatus is RevokedStatus revokedStatus && revokedStatus.HasRevocationReason
            ? ReasonName(revokedStatus.RevocationReason)
            : null;

        return new(
            signatureValid ? status : RevocationStatus.Invalid,
            true,
            signatureValid,
            signatureValid,
            AsUtc(singleResponse.ThisUpdate),
            singleResponse.NextUpdate is DateTime nextUpdate ? AsUtc(nextUpdate) : null,
            reason);
    }

    private static ParsedRevocationEvidence ParseCrl(
        RevocationEvidence evidence,
        CertificateDescriptor certificate,
        CertificateDescriptor issuer)
    {
        BcX509Certificate issuerCertificate = ReadCertificate(issuer);
        BcX509Certificate targetCertificate = ReadCertificate(certificate);
        X509Crl crl = new X509CrlParser().ReadCrl(evidence.ExportEncoded());
        bool targetMatches = crl.IssuerDN.Equivalent(issuerCertificate.SubjectDN);
        bool signatureValid = targetMatches && crl.IsSignatureValid(issuerCertificate.GetPublicKey());
        if (!targetMatches)
        {
            return new(RevocationStatus.Invalid, false, false, false, AsUtc(crl.ThisUpdate),
                crl.NextUpdate is DateTime mismatchedNextUpdate ? AsUtc(mismatchedNextUpdate) : null, null);
        }

        X509CrlEntry? entry = crl.GetRevokedCertificate(targetCertificate.SerialNumber);
        IssuingDistributionPoint? scope = ReadIssuingDistributionPoint(crl);

        // RFC 5280: a CRL with critical extensions we cannot process must not be used, and indirect
        // CRLs need per-entry issuer tracking that is not implemented.
        if (HasUnsupportedCriticalExtension(crl.GetCriticalExtensionOids(), SupportedCriticalCrlExtensions)
            || (entry is not null && HasUnsupportedCriticalExtension(entry.GetCriticalExtensionOids(), [])
            || scope?.IsIndirectCrl == true))
        {
            return new(RevocationStatus.Invalid, true, signatureValid, false, AsUtc(crl.ThisUpdate),
                crl.NextUpdate is DateTime unusableNextUpdate ? AsUtc(unusableNextUpdate) : null, null);
        }

        int? reasonCode = entry is null ? null : ReadCrlReason(entry);

        // A missing entry only proves the certificate is not revoked when the CRL is a complete list
        // for it; a delta CRL or a partitioned/reason-limited CRL leaves the question to other evidence.
        bool complete = crl.GetExtensionValue(X509Extensions.DeltaCrlIndicator) is null
            && Covers(scope, targetCertificate);
        if ((entry is null && !complete) || reasonCode == CrlReason.RemoveFromCrl)
        {
            return new(RevocationStatus.Unavailable, false, signatureValid, false, AsUtc(crl.ThisUpdate),
                crl.NextUpdate is DateTime partialNextUpdate ? AsUtc(partialNextUpdate) : null, null);
        }

        RevocationStatus status = entry switch
        {
            null => RevocationStatus.Good,
            _ when reasonCode == CrlReason.CertificateHold => RevocationStatus.Suspended,
            _ => RevocationStatus.Revoked
        };
        bool akiMatches = CrlAuthorityKeyMatchesIssuer(crl, issuer);
        bool authorized = signatureValid && akiMatches;
        return new(
            authorized ? status : RevocationStatus.Invalid,
            true,
            signatureValid,
            authorized,
            AsUtc(crl.ThisUpdate),
            crl.NextUpdate is DateTime nextUpdate ? AsUtc(nextUpdate) : null,
            reasonCode is int value ? ReasonName(value) : null);
    }

    private static IssuingDistributionPoint? ReadIssuingDistributionPoint(X509Crl crl)
    {
        Asn1OctetString? extension = crl.GetExtensionValue(X509Extensions.IssuingDistributionPoint);
        return extension is null
            ? null
            : IssuingDistributionPoint.GetInstance(Asn1Object.FromByteArray(extension.GetOctets()));
    }

    private static bool Covers(IssuingDistributionPoint? scope, BcX509Certificate certificate)
    {
        if (scope is null)
        {
            return true;
        }

        bool isCa = certificate.GetBasicConstraints() >= 0;
        if (scope.OnlySomeReasons is not null
            || scope.OnlyContainsAttributeCerts
            || (scope.OnlyContainsUserCerts && isCa)
            || (scope.OnlyContainsCACerts && !isCa))
        {
            return false;
        }

        if (scope.DistributionPoint is null)
        {
            return true;
        }

        Asn1OctetString? points = certificate.GetExtensionValue(X509Extensions.CrlDistributionPoints);
        return points is not null
            && CrlDistPoint.GetInstance(Asn1Object.FromByteArray(points.GetOctets()))
                .GetDistributionPoints()
                .Any(point => scope.DistributionPoint.Equals(point.DistributionPointName));
    }

    private static bool HasUnsupportedCriticalExtension(IEnumerable<string>? critical, HashSet<string> supported) =>
        critical?.Any(oid => !supported.Contains(oid)) == true;

    private static bool CrlAuthorityKeyMatchesIssuer(X509Crl crl, CertificateDescriptor issuer)
    {
        Asn1OctetString? extension = crl.GetExtensionValue(X509Extensions.AuthorityKeyIdentifier);
        if (extension is null || issuer.SubjectKeyIdentifier is not string issuerSki)
        {
            return true;
        }

        AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.GetInstance(
            Asn1Object.FromByteArray(extension.GetOctets()));
        Asn1OctetString? keyIdentifier = aki.KeyIdentifier;
        return keyIdentifier is null
            || string.Equals(
                Convert.ToHexString(keyIdentifier.GetOctets()),
                issuerSki,
                StringComparison.OrdinalIgnoreCase);
    }

    private static ParsedRevocationEvidence Invalid() =>
        new(RevocationStatus.Invalid, false, false, false, null, null, null);

    private static BcX509Certificate ReadCertificate(CertificateDescriptor descriptor) =>
        new X509CertificateParser().ReadCertificate(descriptor.ExportDer());

    private static int? ReadCrlReason(X509CrlEntry entry)
    {
        Asn1OctetString? extension = entry.GetExtensionValue(X509Extensions.ReasonCode);
        return extension is null
            ? null
            : DerEnumerated.GetInstance(Asn1Object.FromByteArray(extension.GetOctets())).IntValueExact;
    }

    private static DateTimeOffset AsUtc(DateTime value) =>
        new(DateTime.SpecifyKind(value, DateTimeKind.Utc));

    private static string ReasonName(int reason) => reason switch
    {
        CrlReason.KeyCompromise => "KeyCompromise",
        CrlReason.CACompromise => "CACompromise",
        CrlReason.AffiliationChanged => "AffiliationChanged",
        CrlReason.Superseded => "Superseded",
        CrlReason.CessationOfOperation => "CessationOfOperation",
        CrlReason.CertificateHold => "CertificateHold",
        CrlReason.RemoveFromCrl => "RemoveFromCrl",
        CrlReason.PrivilegeWithdrawn => "PrivilegeWithdrawn",
        CrlReason.AACompromise => "AACompromise",
        _ => "Unspecified"
    };
}
