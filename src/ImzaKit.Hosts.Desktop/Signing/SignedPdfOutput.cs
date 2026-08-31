namespace ImzaKit.Hosts.Desktop.Signing;

public static class SignedPdfOutput
{
    public static string Write(string originalPdfPath, byte[] signedPdf)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(originalPdfPath);
        ArgumentNullException.ThrowIfNull(signedPdf);

        string? directory = Path.GetDirectoryName(originalPdfPath);
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new IOException("Original PDF path has no directory.");
        }

        string stem = Path.GetFileNameWithoutExtension(originalPdfPath);
        if (string.IsNullOrWhiteSpace(stem))
        {
            throw new ArgumentException("Original PDF file name is missing.", nameof(originalPdfPath));
        }

        string candidate = Path.Combine(directory, stem + "-imzali.pdf");
        int suffix = 2;
        while (File.Exists(candidate))
        {
            candidate = Path.Combine(directory, $"{stem}-imzali-{suffix}.pdf");
            suffix++;
        }

        using FileStream stream = new(candidate, FileMode.CreateNew, FileAccess.Write, FileShare.None);
        stream.Write(signedPdf);
        return candidate;
    }
}
