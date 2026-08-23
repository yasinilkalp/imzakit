using System.Globalization;
using System.Text;
using ImzaKit.PAdES.Policy;

namespace ImzaKit.PAdES.Preflight;

public static class PdfSigningPreflight
{
    public static void Validate(ReadOnlySpan<byte> pdf, PdfPreflightLimits limits)
    {
        ArgumentNullException.ThrowIfNull(limits);
        ArgumentOutOfRangeException.ThrowIfLessThan(limits.MaximumPdfBytes, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(limits.MaximumObjects, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(limits.MaximumRevisions, 1);

        Reject(pdf.Length > limits.MaximumPdfBytes, PdfPreflightErrorCode.PdfTooLarge,
            "PDF exceeds the configured byte limit.");

        string source = Encoding.ASCII.GetString(pdf);
        bool supportedVersion = source.StartsWith("%PDF-1.4", StringComparison.Ordinal) ||
            source.StartsWith("%PDF-1.5", StringComparison.Ordinal) ||
            source.StartsWith("%PDF-1.6", StringComparison.Ordinal) ||
            source.StartsWith("%PDF-1.7", StringComparison.Ordinal);
        Reject(!supportedVersion, PdfPreflightErrorCode.UnsupportedVersion,
            "Only PDF versions 1.4 through 1.7 are supported.");
        Reject(source.Contains("/Encrypt", StringComparison.Ordinal), PdfPreflightErrorCode.Encrypted,
            "Encrypted PDF documents are not supported.");
        Reject(source.Contains("/Type /XRef", StringComparison.Ordinal), PdfPreflightErrorCode.XrefStream,
            "XRef streams are not supported.");
        Reject(source.Contains("/Type /ObjStm", StringComparison.Ordinal), PdfPreflightErrorCode.ObjectStream,
            "Object streams are not supported.");
        Reject(source.Contains("/XRefStm", StringComparison.Ordinal), PdfPreflightErrorCode.HybridReference,
            "Hybrid-reference PDF documents are not supported.");

        PdfModificationPolicy policy = PdfModificationPolicyInspector.Inspect(pdf);
        Reject(policy.CertificationPermission == PdfCertificationChangeLevel.NoChanges,
            PdfPreflightErrorCode.CertificationForbidsChanges,
            "The DocMDP certification policy forbids document changes.");
        Reject(IsFieldLocked(policy, "Signature1"), PdfPreflightErrorCode.TargetFieldLocked,
            "The FieldMDP policy locks the target signature field.");
        Reject(source.Contains("/AcroForm", StringComparison.Ordinal), PdfPreflightErrorCode.ExistingAcroForm,
            "PDF documents with an existing AcroForm are not supported.");

        int declaredObjects = ReadLargestIntegerAfterToken(source, "/Size");
        Reject(declaredObjects > limits.MaximumObjects, PdfPreflightErrorCode.TooManyObjects,
            "PDF object count exceeds the configured limit.");
        int revisionCount = CountToken(source, "startxref");
        Reject(revisionCount > limits.MaximumRevisions, PdfPreflightErrorCode.TooManyRevisions,
            "PDF revision count exceeds the configured limit.");
    }

    private static int ReadLargestIntegerAfterToken(string source, string token)
    {
        int largest = 0;
        int searchIndex = 0;
        while ((searchIndex = source.IndexOf(token, searchIndex, StringComparison.Ordinal)) >= 0)
        {
            ReadOnlySpan<char> remainder = source.AsSpan(searchIndex + token.Length).TrimStart();
            int digitCount = 0;
            while (digitCount < remainder.Length && char.IsAsciiDigit(remainder[digitCount]))
            {
                digitCount++;
            }

            if (digitCount > 0 && int.TryParse(
                    remainder[..digitCount], NumberStyles.None, CultureInfo.InvariantCulture, out int value))
            {
                largest = Math.Max(largest, value);
            }

            searchIndex += token.Length;
        }

        return largest;
    }

    private static int CountToken(string source, string token)
    {
        int count = 0;
        int searchIndex = 0;
        while ((searchIndex = source.IndexOf(token, searchIndex, StringComparison.Ordinal)) >= 0)
        {
            count++;
            searchIndex += token.Length;
        }

        return count;
    }

    private static bool IsFieldLocked(PdfModificationPolicy policy, string targetFieldName)
    {
        bool listed = policy.FieldNames.Contains(targetFieldName, StringComparer.Ordinal);
        return policy.FieldLockAction switch
        {
            PdfFieldLockAction.All => true,
            PdfFieldLockAction.Include => listed,
            PdfFieldLockAction.Exclude => !listed,
            _ => false,
        };
    }

    private static void Reject(bool condition, PdfPreflightErrorCode code, string message)
    {
        if (condition)
        {
            throw new PdfPreflightException(code, message);
        }
    }
}
