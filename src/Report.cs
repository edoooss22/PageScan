namespace PageScan;

internal enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

internal sealed class Finding
{
    public required string Category { get; init; }
    public required string Title { get; init; }
    public required Severity Severity { get; init; }
    public string? Explanation { get; init; }

    public List<(string Key, string Value)> Data { get; } = new();
    public List<(string Title, string Text)> Blocks { get; } = new();

    public Finding Add(string key, string value)
    {
        Data.Add((key, value));
        return this;
    }

    public Finding Block(string title, string text)
    {
        Blocks.Add((title, text));
        return this;
    }
}

internal sealed class ScanReport
{
    public List<Finding> Findings { get; } = new();
    public List<(string Title, string Text)> Sections { get; } = new();
    public List<string> Errors { get; } = new();
    public List<(string Key, string Value)> Meta { get; } = new();

    public void AddMeta(string key, string value) => Meta.Add((key, value));

    public Finding Report(string category, string title, Severity severity, string explanation)
    {
        var f = new Finding
        {
            Category = category,
            Title = title,
            Severity = severity,
            Explanation = explanation,
        };
        Findings.Add(f);
        return f;
    }

    public void Section(string title, string text) => Sections.Add((title, text));

    public int Count(Severity s) => Findings.Count(f => f.Severity == s);
}
