using ImzaKit.Certificate.Models;
using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Parsing;

public interface IRevocationEvidenceParser
{
    ParsedRevocationEvidence Parse(
        RevocationEvidence evidence,
        CertificateDescriptor certificate,
        CertificateDescriptor issuer);
}
