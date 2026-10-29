using System.Text.RegularExpressions;

namespace ImzaKit.PAdES.Policy;

// Ordered by severity; DocMDP permission levels allow everything up to a given kind.
internal enum PdfChangeKind
{
    Neutral,
    Preservation,
    Signature,
    FormFill,
    Annotation,
    Content,
}

internal sealed record PdfChange(PdfChangeKind Kind, int ObjectNumber, bool ModifiesExistingObject, string Description);

// Compares the revisions appended after a signature with the revision it covers, object by object.
// New objects only matter when an existing object starts referencing them, so modifications of
// existing objects (plus deletions and a replaced /Root) are what change the signed document.
internal sealed partial class PdfRevisionChanges
{
    private static readonly HashSet<string> InfoKeys = new(StringComparer.Ordinal)
    {
        "/Title", "/Author", "/Subject", "/Keywords", "/Creator", "/Producer", "/CreationDate", "/ModDate", "/Trapped"
    };

    private readonly PdfRevisionObjects _covered;
    private readonly PdfRevisionObjects _tail;
    private readonly int? _acroFormNumber;
    private readonly List<PdfChange> _changes = [];
    private readonly HashSet<string> _changedFieldNames = new(StringComparer.Ordinal);

    private PdfRevisionChanges(PdfRevisionObjects covered, PdfRevisionObjects tail)
    {
        _covered = covered;
        _tail = tail;
        Complete = tail.Complete;
        if (covered.RootObject is int root && covered.Objects.TryGetValue(root, out PdfObjectDefinition? catalog))
        {
            _acroFormNumber = PdfSyntax.SingleReference(catalog.Dictionary.GetValueOrDefault("/AcroForm"));
        }
    }

    public IReadOnlyList<PdfChange> Changes => _changes;

    // Fully qualified names of form fields added or changed after the signature, named as signed.
    public IReadOnlyCollection<string> ChangedFieldNames => _changedFieldNames;

    public bool Complete { get; private set; }

    public static PdfRevisionChanges Compare(ReadOnlySpan<byte> pdf, int coveredLength)
    {
        PdfRevisionChanges result = new(
            PdfRevisionObjects.Read(pdf, 0, coveredLength),
            PdfRevisionObjects.Read(pdf, coveredLength, pdf.Length));
        result.Analyze();
        return result;
    }

    private void Analyze()
    {
        int coveredSize = _covered.DeclaredSize
            ?? (_covered.Objects.Count == 0 ? 0 : _covered.Objects.Keys.Max() + 1);
        foreach (PdfObjectDefinition updated in _tail.Objects.Values.OrderBy(item => item.Number))
        {
            if (_covered.Objects.TryGetValue(updated.Number, out PdfObjectDefinition? original))
            {
                PdfChangeKind kind = ClassifyModification(original, updated);
                if (kind != PdfChangeKind.Neutral)
                {
                    _changes.Add(new(kind, updated.Number, true, $"object {updated.Number} {Describe(original)} changed"));
                    if (IsField(original) || IsField(updated))
                    {
                        AddChangedField(original);
                    }
                }
            }
            else if (updated.Number < coveredSize && !_covered.Complete)
            {
                Complete = false;
            }
            else
            {
                PdfChangeKind kind = ClassifyNew(updated);
                _changes.Add(new(kind, updated.Number, false, $"object {updated.Number} {Describe(updated)} added"));
                if (IsField(updated) && kind != PdfChangeKind.Preservation)
                {
                    AddChangedField(updated);
                }
            }
        }

        foreach (int freed in _tail.FreedObjects.Where(number => _covered.Objects.ContainsKey(number)).Order())
        {
            _changes.Add(new(PdfChangeKind.Content, freed, true, $"object {freed} deleted"));
        }

        if (_tail.RootObject is int root && _covered.RootObject is int coveredRoot && root != coveredRoot)
        {
            _changes.Add(new(PdfChangeKind.Content, root, true, "document catalog replaced"));
        }
    }

    private PdfChangeKind ClassifyNew(PdfObjectDefinition item)
    {
        string? type = item.Name("/Type");
        if (type is "/DSS" or "/DocTimeStamp")
        {
            return PdfChangeKind.Preservation;
        }

        if (type == "/Sig")
        {
            return PdfChangeKind.Signature;
        }

        if (item.Has("/FT"))
        {
            return ClassifyField(item);
        }

        if (type is "/Page" or "/Pages" or "/Catalog")
        {
            return PdfChangeKind.Content;
        }

        return IsAnnotation(item) ? ClassifyAnnotation(item) : PdfChangeKind.Neutral;
    }

    private PdfChangeKind ClassifyModification(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        if (original.Body == updated.Body)
        {
            return PdfChangeKind.Neutral;
        }

        if (original.IsStream || updated.IsStream)
        {
            return original.Name("/Type") == "/Metadata" && updated.Name("/Type") == "/Metadata"
                ? PdfChangeKind.Neutral
                : PdfChangeKind.Content;
        }

        if (original.Dictionary.Count == 0 || updated.Dictionary.Count == 0)
        {
            return ClassifyArrayModification(original, updated);
        }

        if (!ChangedKeys(original, updated).Any())
        {
            return PdfChangeKind.Neutral;
        }

        string? type = original.Name("/Type") ?? updated.Name("/Type");
        return type switch
        {
            "/Catalog" => ClassifyCatalog(original, updated),
            "/Page" => ClassifyPage(original, updated),
            "/DSS" => PdfChangeKind.Preservation,
            "/Pages" or "/Sig" or "/DocTimeStamp" => PdfChangeKind.Content,
            _ when IsAcroForm(original) => ClassifyAcroForm(original, updated),
            _ when original.Has("/FT") || updated.Has("/FT") => ClassifyFieldModification(original, updated),
            _ when IsAnnotation(original) => ClassifyAnnotation(updated),
            _ when IsInfo(original) && IsInfo(updated) => PdfChangeKind.Neutral,
            _ when IsVri(original) && IsVri(updated) => PdfChangeKind.Preservation,
            _ => PdfChangeKind.Content,
        };
    }

    private static PdfChangeKind ClassifyCatalog(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        PdfChangeKind kind = PdfChangeKind.Neutral;
        foreach (string key in ChangedKeys(original, updated))
        {
            kind = Max(kind, key switch
            {
                "/DSS" or "/Extensions" => PdfChangeKind.Preservation,
                "/AcroForm" => PdfChangeKind.Signature,
                "/Metadata" => PdfChangeKind.Neutral,
                _ => PdfChangeKind.Content,
            });
        }

        return kind;
    }

    private PdfChangeKind ClassifyPage(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        PdfChangeKind kind = PdfChangeKind.Neutral;
        foreach (string key in ChangedKeys(original, updated))
        {
            kind = Max(kind, key == "/Annots"
                ? ClassifyReferenceList(
                    original.Dictionary.GetValueOrDefault("/Annots"),
                    updated.Dictionary.GetValueOrDefault("/Annots"),
                    ClassifyAnnotationReference,
                    PdfChangeKind.Annotation)
                : PdfChangeKind.Content);
        }

        return kind;
    }

    private PdfChangeKind ClassifyAcroForm(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        PdfChangeKind kind = PdfChangeKind.Neutral;
        foreach (string key in ChangedKeys(original, updated))
        {
            kind = Max(kind, key switch
            {
                "/Fields" => ClassifyReferenceList(
                    original.Dictionary.GetValueOrDefault("/Fields"),
                    updated.Dictionary.GetValueOrDefault("/Fields"),
                    ClassifyFieldReference,
                    PdfChangeKind.Content),
                "/XFA" => PdfChangeKind.Content,
                _ => PdfChangeKind.FormFill,
            });
        }

        return kind;
    }

    private PdfChangeKind ClassifyFieldModification(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        if (original.Name("/FT") != "/Sig" && updated.Name("/FT") != "/Sig")
        {
            return PdfChangeKind.FormFill;
        }

        // Filling an empty signature field is signing; replacing an existing value is not.
        return original.Has("/V") ? PdfChangeKind.Content : ClassifyField(updated);
    }

    // Arrays held in their own objects, such as an indirect /Annots or /Fields array.
    private PdfChangeKind ClassifyArrayModification(PdfObjectDefinition original, PdfObjectDefinition updated)
    {
        if (!original.Body.StartsWith('[') || !updated.Body.StartsWith('['))
        {
            return PdfChangeKind.Content;
        }

        string reference = $"{original.Number} 0 R";
        if (_covered.Objects.Values.Any(page => page.Name("/Type") == "/Page"
                && page.Dictionary.GetValueOrDefault("/Annots") == reference))
        {
            return ClassifyReferenceList(original.Body, updated.Body, ClassifyAnnotationReference, PdfChangeKind.Annotation);
        }

        return _acroFormNumber is int acroForm
            && _covered.Objects.TryGetValue(acroForm, out PdfObjectDefinition? form)
            && form.Dictionary.GetValueOrDefault("/Fields") == reference
                ? ClassifyReferenceList(original.Body, updated.Body, ClassifyFieldReference, PdfChangeKind.Content)
                : PdfChangeKind.Content;
    }

    private PdfChangeKind ClassifyReferenceList(
        string? original,
        string? updated,
        Func<int, PdfChangeKind> classifyAdded,
        PdfChangeKind removedKind)
    {
        HashSet<int> before = [.. ResolveArray(original)];
        HashSet<int> after = [.. ResolveArray(updated)];
        PdfChangeKind kind = before.Except(after).Any() ? removedKind : PdfChangeKind.Neutral;
        foreach (int added in after.Except(before))
        {
            kind = Max(kind, classifyAdded(added));
        }

        return kind;
    }

    // An array value may itself be an indirect reference to an array object.
    private IReadOnlyList<int> ResolveArray(string? value)
    {
        if (value is null)
        {
            return [];
        }

        if (!value.StartsWith('[') && PdfSyntax.SingleReference(value) is int reference)
        {
            return Find(reference) is { Dictionary.Count: 0 } array && array.Body.StartsWith('[')
                ? PdfSyntax.References(array.Body)
                : [];
        }

        return PdfSyntax.References(value);
    }

    private PdfChangeKind ClassifyAnnotationReference(int number)
    {
        PdfObjectDefinition? annotation = Find(number);
        if (annotation is null)
        {
            Complete = false;
            return PdfChangeKind.Neutral;
        }

        return ClassifyAnnotation(annotation);
    }

    private PdfChangeKind ClassifyFieldReference(int number)
    {
        PdfObjectDefinition? field = Find(number);
        if (field is null)
        {
            Complete = false;
            return PdfChangeKind.Neutral;
        }

        return field.Has("/FT") ? ClassifyField(field) : PdfChangeKind.FormFill;
    }

    private PdfChangeKind ClassifyAnnotation(PdfObjectDefinition annotation)
    {
        if (annotation.Name("/Subtype") != "/Widget")
        {
            return PdfChangeKind.Annotation;
        }

        if (annotation.Has("/FT"))
        {
            return ClassifyField(annotation);
        }

        return PdfSyntax.SingleReference(annotation.Dictionary.GetValueOrDefault("/Parent")) is int parent
            && Find(parent) is { } field
            && field.Has("/FT")
                ? ClassifyField(field)
                : PdfChangeKind.FormFill;
    }

    private PdfChangeKind ClassifyField(PdfObjectDefinition field)
    {
        if (field.Name("/FT") != "/Sig")
        {
            return PdfChangeKind.FormFill;
        }

        if (PdfSyntax.SingleReference(field.Dictionary.GetValueOrDefault("/V")) is not int value)
        {
            return PdfChangeKind.FormFill;
        }

        return Find(value)?.Name("/Type") == "/DocTimeStamp" ? PdfChangeKind.Preservation : PdfChangeKind.Signature;
    }

    private PdfObjectDefinition? Find(int number) =>
        _tail.Objects.GetValueOrDefault(number) ?? _covered.Objects.GetValueOrDefault(number);

    // Widgets without /T take their name (and value) from the parent field.
    private void AddChangedField(PdfObjectDefinition field)
    {
        List<string> parts = [];
        PdfObjectDefinition? current = field;
        for (int depth = 0; current is not null && depth < 32; depth++)
        {
            if (current.Dictionary.TryGetValue("/T", out string? title) && PdfSyntax.TextStrings(title) is [string name, ..])
            {
                parts.Insert(0, name);
            }

            current = PdfSyntax.SingleReference(current.Dictionary.GetValueOrDefault("/Parent")) is int parent
                ? _covered.Objects.GetValueOrDefault(parent) ?? _tail.Objects.GetValueOrDefault(parent)
                : null;
        }

        if (parts.Count > 0)
        {
            _changedFieldNames.Add(string.Join('.', parts));
        }
    }

    private static bool IsField(PdfObjectDefinition item) =>
        item.Has("/T") || item.Has("/FT") || (item.Name("/Subtype") == "/Widget" && item.Has("/Parent"));

    private bool IsAcroForm(PdfObjectDefinition item) =>
        item.Number == _acroFormNumber || (item.Has("/Fields") && !item.Has("/Type"));

    private static bool IsAnnotation(PdfObjectDefinition item) =>
        item.Name("/Type") == "/Annot" || (item.Has("/Subtype") && item.Has("/Rect"));

    private static bool IsInfo(PdfObjectDefinition item) =>
        item.Dictionary.Keys.All(InfoKeys.Contains);

    private static bool IsVri(PdfObjectDefinition item) =>
        item.Dictionary.Count > 0 && item.Dictionary.Keys.All(key => VriKey().IsMatch(key));

    private static IEnumerable<string> ChangedKeys(PdfObjectDefinition original, PdfObjectDefinition updated) =>
        original.Dictionary.Keys.Union(updated.Dictionary.Keys)
            .Where(key => original.Dictionary.GetValueOrDefault(key) != updated.Dictionary.GetValueOrDefault(key));

    private static string Describe(PdfObjectDefinition item) =>
        item.Name("/Type") is string type ? $"({type[1..]})" : item.Has("/FT") ? "(field)" : "";

    private static PdfChangeKind Max(PdfChangeKind left, PdfChangeKind right) => left > right ? left : right;

    [GeneratedRegex("^/[0-9A-Fa-f]{40}$")]
    private static partial Regex VriKey();
}
