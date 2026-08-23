using ImzaKit.Revocation.Models;

namespace ImzaKit.Revocation.Tests.Models;

public sealed class RevocationEvidenceModelTests
{
    [Fact]
    public void EvidenceCopiesInputAndExportedBytes()
    {
        byte[] callerOwned = [0x30, 0x00];
        RevocationEvidence evidence = new(
            RevocationEvidenceType.Crl,
            RevocationEvidenceSource.Local,
            callerOwned);
        callerOwned[0] = 0xff;
        byte[] exported = evidence.ExportEncoded();
        exported[1] = 0xff;

        Assert.Equal(new byte[] { 0x30, 0x00 }, evidence.ExportEncoded());
        Assert.Equal(RevocationEvidenceType.Crl, evidence.Type);
        Assert.Equal(RevocationEvidenceSource.Local, evidence.Source);
    }

    [Fact]
    public void EvidenceRejectsEmptyEncoding()
    {
        Assert.Throws<ArgumentException>(() => new RevocationEvidence(
            RevocationEvidenceType.Ocsp,
            RevocationEvidenceSource.Embedded,
            ReadOnlySpan<byte>.Empty));
    }

    [Fact]
    public void EvidenceSetCopiesCallerCollection()
    {
        List<RevocationEvidence> source = [new(
            RevocationEvidenceType.Crl,
            RevocationEvidenceSource.Local,
            new byte[] { 0x30, 0x00 })];
        RevocationEvidenceSet set = new(source);
        source.Clear();

        Assert.Single(set.Evidence);
    }
}
