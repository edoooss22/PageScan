using System.Diagnostics;
using System.Text;
using static PageScan.Native;

namespace PageScan;

internal enum PageKind { Header, Code, Data }

internal enum Verdict
{
    Explained,
    Restored,
    Patch,
    Rewritten,
    Replaced,
    SelfPatch,
    Unverified,
}

internal sealed class PatchSite
{
    public uint Rva;
    public byte[] Disk = Array.Empty<byte>();
    public byte[] Mem = Array.Empty<byte>();
    public bool AtFunctionStart;
    public string Symbol = "";
    public string Target = "";
    public bool TargetOutside;
}

internal sealed class PageFact
{
    public ulong Address;
    public uint Rva;
    public string Section = "";
    public PageKind Kind;
    public bool WasAbsent;
    public bool Combined;
    public uint Protection;

    public Verdict Verdict = Verdict.Unverified;
    public string Reason = "";
    public int DiffBytes;
    public int DiffRuns;
    public int ExplainedBytes;
    public string Symbol = "";
    public string Exports = "";
    public int Functions;
    public bool TargetOutside;
    public List<PatchSite> Sites { get; } = new();
    public List<string> Slots { get; } = new();

    public bool Unexplained => Verdict is not (Verdict.Explained or Verdict.SelfPatch);
}

internal sealed class ModuleFacts
{
    public required MappedImage Image;
    public string Note = "";
    public bool Comparable;
    public bool RelocatedInProcess;
    public bool HeaderBroken;
    public long Delta;

    public int Pages;
    public int Shared;
    public int AbsentClean;
    public int AbsentUnknown;
    public int CodePages;
    public int Suspects;
    public int Confirmed;
    public int Refuted;
    public int RelocPages;
    public int RelocPrivate;

    public List<PageFact> Facts { get; } = new();

    public IEnumerable<PageFact> Of(PageKind kind, Verdict verdict) =>
        Facts.Where(f => f.Kind == kind && f.Verdict == verdict);
}

internal sealed class PageAudit
{
    private const int PageSize = Target.PageSize;
    private const int SelfPatchRun = 6;
    private const int ReplacedBytes = PageSize / 2;
    private const int MaxSites = 48;
    private const string MutableData = ".mrdata";
    private const string MutableDataReason = "изменяемые защищённые данные модуля (.mrdata)";

    private static readonly HashSet<string> KeyModules = new(StringComparer.OrdinalIgnoreCase)
    {
        "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "win32u.dll",
        "gdi32.dll", "gdi32full.dll", "ws2_32.dll", "advapi32.dll", "wininet.dll",
        "jvm.dll", "java.dll", "jimage.dll", "net.dll", "nio.dll", "verify.dll",
        "management.dll", "instrument.dll", "zip.dll", "jli.dll", "awt.dll",
        "lwjgl.dll", "lwjgl_opengl.dll", "lwjgl_stb.dll", "lwjgl_glfw.dll",
        "glfw.dll", "openal.dll", "opengl32.dll",
    };

    private readonly Target _t;
    private readonly ScanReport _rep;
    private readonly bool _verifyAll;
    private List<MappedImage> _images = new();
    private bool _originBit;
    private readonly List<ModuleFacts> _modules = new();
    private readonly SortedDictionary<string, int[]> _shapes = new();

    private readonly byte[] _expected = new byte[PageSize];
    private readonly byte[] _actual = new byte[PageSize];
    private readonly string?[] _why = new string?[PageSize];

    private PageAudit(Target t, ScanReport rep, bool verifyAll)
    {
        _t = t;
        _rep = rep;
        _verifyAll = verifyAll;
    }

    public static void Run(Target t, ScanReport rep, bool verifyAll,
        Action<int, int, string> progress)
    {
        var audit = new PageAudit(t, rep, verifyAll);
        audit._images = t.Images();
        audit._originBit = audit.Calibrate();

        int n = 0;
        foreach (var im in audit._images)
        {
            progress(++n, audit._images.Count, im.Name);
            try
            {
                audit._modules.Add(audit.Examine(im));
            }
            catch (Exception ex)
            {
                rep.Errors.Add($"{im.Name} (0x{im.Base:X}): {ex}");
            }
        }

        audit.WriteFindings();
        audit.WriteSections();
        audit.WriteMeta();
    }

    private bool Calibrate()
    {
        foreach (var im in _images)
        {
            var info = _t.QueryPages(im.Base, (int)Math.Min(im.Size / PageSize, 2048));
            if (info is not null && info.Any(p => p.Valid && p.SharedOriginal)) return true;
        }
        return false;
    }

    private bool Untouched(PageInfo p) => _originBit ? p.SharedOriginal : p.Shared;

    private ModuleFacts Examine(MappedImage im)
    {
        var mf = new ModuleFacts { Image = im };

        var head = new byte[PageSize];
        PeHeader? mem = _t.Read(im.Base, head) ? PeHeader.Parse(head) : null;
        mf.HeaderBroken = mem is null;

        var first = _t.QueryPages(im.Base, 1);
        bool headerPrivate = first is { Length: 1 } && first[0].Valid && !Untouched(first[0]);

        PeFile? disk = null;
        if (im.Path.Length == 0)
        {
            mf.Note = "у проекции нет имени файла";
        }
        else
        {
            disk = PeFile.Load(im.Path, out string error);
            mf.Note = error;
        }

        if (disk is not null)
        {
            bool same = mem is not null && !headerPrivate
                ? disk.Header.TimeDateStamp == mem.TimeDateStamp &&
                  disk.Header.SizeOfImage == mem.SizeOfImage
                : ((ulong)disk.Header.SizeOfImage + PageSize - 1) / PageSize * PageSize == im.Size;
            if (!same)
            {
                mf.Note = "файл на диске уже не тот, из которого загружен образ";
                disk = null;
            }
        }

        mf.Comparable = disk is not null;
        var layout = disk?.Header ?? mem;
        if (disk is not null) mf.Delta = (long)im.Base - (long)disk.Header.ImageBase;

        var plan = new List<(uint Rva, string Section, PageKind Kind)>();
        var seen = new HashSet<uint>();

        void AddRange(uint rva, uint size, string name, PageKind kind)
        {
            if (size == 0) return;
            ulong last = ((ulong)rva + size - 1) & ~0xFFFUL;
            for (ulong p = rva & ~0xFFFu; p <= last && p < im.Size; p += PageSize)
                if (seen.Add((uint)p)) plan.Add(((uint)p, name, kind));
        }

        if (layout is null)
        {
            mf.Note = (mf.Note.Length > 0 ? mf.Note + "; " : "") +
                      "заголовок образа в памяти не разбирается";
            AddRange(0, (uint)Math.Min(im.Size, 0x40000000), "?", PageKind.Code);
        }
        else
        {
            AddRange(0, Math.Max(layout.SizeOfHeaders, 1), "заголовок", PageKind.Header);
            var writableCode = new List<string>();
            foreach (var s in layout.Sections)
            {
                if (s.IsDiscardable) continue;
                if (s.IsWritable)
                {
                    if (s.IsCode) writableCode.Add(s.Name);
                    continue;
                }
                AddRange(s.Rva, s.VirtualSize != 0 ? s.VirtualSize : s.RawSize, s.Name,
                    s.IsCode ? PageKind.Code : PageKind.Data);
            }
            if (writableCode.Count > 0)
                mf.Note = (mf.Note.Length > 0 ? mf.Note + "; " : "") +
                          "секции кода с правом записи не проверялись: " +
                          string.Join(", ", writableCode);
        }

        if (plan.Count == 0) return mf;

        var addresses = plan.Select(p => im.Base + p.Rva).ToArray();
        var info = _t.QueryPages(addresses);
        if (info is null)
        {
            mf.Note = (mf.Note.Length > 0 ? mf.Note + "; " : "") +
                      "система не отдаёт состояние страниц";
            return mf;
        }

        mf.Pages = plan.Count;
        mf.CodePages = plan.Count(p => p.Kind == PageKind.Code);
        var privateIndex = new List<int>();
        var suspects = new List<int>();
        var cleanAbsent = new List<int>();

        for (int i = 0; i < plan.Count; i++)
        {
            var p = info[i];
            if (p.Valid)
            {
                if (layout is null && (p.Protection & 0xF0) == 0) { mf.Pages--; continue; }
                if (Untouched(p)) mf.Shared++;
                else privateIndex.Add(i);
                CountReloc(mf, disk, plan[i].Rva, !Untouched(p));
            }
            else if (Untouched(p))
            {
                mf.AbsentClean++;
                if (_verifyAll) cleanAbsent.Add(i);
            }
            else
            {
                suspects.Add(i);
            }
        }

        var wasAbsent = new HashSet<int>();
        if (suspects.Count > 0)
        {
            mf.Suspects = suspects.Count;
            var again = Reprobe(suspects.Select(i => addresses[i]).ToArray());
            for (int k = 0; k < suspects.Count; k++)
            {
                int i = suspects[k];
                var before = info[i];
                var after = again?[k];
                int outcome;
                if (after is { Valid: true } back && Untouched(back))
                {
                    mf.Refuted++;
                    mf.AbsentClean++;
                    outcome = 1;
                    CountReloc(mf, disk, plan[i].Rva, false);
                }
                else if (after is { Valid: true })
                {
                    if (layout is null && (after.Value.Protection & 0xF0) == 0)
                    {
                        mf.Pages--;
                        continue;
                    }
                    mf.Confirmed++;
                    outcome = 0;
                    info[i] = after.Value;
                    privateIndex.Add(i);
                    wasAbsent.Add(i);
                    CountReloc(mf, disk, plan[i].Rva, true);
                }
                else
                {
                    mf.AbsentUnknown++;
                    outcome = 2;
                }
                Shape(before, outcome);
            }
        }

        if (cleanAbsent.Count > 0)
        {
            var again = Reprobe(cleanAbsent.Select(i => addresses[i]).ToArray());
            for (int k = 0; k < cleanAbsent.Count; k++)
            {
                var after = again?[k];
                int outcome = after is { Valid: true } back && Untouched(back) ? 1
                    : after is { Valid: true } ? 0 : 2;
                Shape(info[cleanAbsent[k]], outcome);
                if (outcome != 0) continue;
                mf.AbsentClean--;
                mf.Confirmed++;
                info[cleanAbsent[k]] = after!.Value;
                privateIndex.Add(cleanAbsent[k]);
                wasAbsent.Add(cleanAbsent[k]);
            }
        }

        mf.RelocatedInProcess =
            (mem is not null && !headerPrivate && mem.ImageBase != im.Base) ||
            (mf.RelocPages >= 8 && mf.RelocPrivate * 10 >= mf.RelocPages * 9);

        privateIndex.Sort();
        foreach (int i in privateIndex)
        {
            var f = new PageFact
            {
                Address = addresses[i],
                Rva = plan[i].Rva,
                Section = plan[i].Section,
                Kind = plan[i].Kind,
                WasAbsent = wasAbsent.Contains(i),
                Combined = info[i].Valid && info[i].Shared,
                Protection = info[i].Protection,
            };
            if (disk is null) f.Reason = mf.Note;
            else Compare(mf, f, disk);
            mf.Facts.Add(f);
        }

        MarkRuns(mf);
        return mf;
    }

    private static void CountReloc(ModuleFacts mf, PeFile? disk, uint rva, bool isPrivate)
    {
        if (disk is null || !disk.HasRelocs(rva)) return;
        mf.RelocPages++;
        if (isPrivate) mf.RelocPrivate++;
    }

    private PageInfo[]? Reprobe(ulong[] addresses)
    {
        Span<byte> one = stackalloc byte[1];
        foreach (ulong a in addresses) _t.Read(a, one);
        return _t.QueryPages(addresses);
    }

    private void Shape(PageInfo before, int outcome)
    {
        string key = $"общая={(before.Shared ? 1 : 0)} прообраз={(before.SharedOriginal ? 1 : 0)} " +
                     $"место={(before.Attributes >> 22) & 3} сбой={(before.Bad ? 1 : 0)}";
        if (!_shapes.TryGetValue(key, out var counts)) _shapes[key] = counts = new int[3];
        counts[outcome]++;
    }

    private void Compare(ModuleFacts mf, PageFact f, PeFile disk)
    {
        disk.ExpectedPage(f.Rva, mf.Delta, _expected);
        if (!_t.Read(f.Address, _actual))
        {
            f.Reason = "страница не читается";
            return;
        }

        Array.Clear(_why);
        bool touchesLoader = false;
        foreach (var (rva, size, why) in disk.LoaderWritten)
            touchesLoader |= Mark(f.Rva, rva, size, why);
        f.Exports = disk.ExportsOnPage(f.Rva);
        if (f.Kind == PageKind.Header)
        {
            if (!disk.Header.Is64 && disk.Header.DirRva[14] != 0)
            {
                f.Verdict = Verdict.Explained;
                f.Reason = "образ .NET: загрузчик переписывает заголовок под 64 разряда";
                return;
            }
            int at = (int)disk.Header.ImageBaseOffset - (int)f.Rva;
            if (at >= 0 && at + 8 <= PageSize)
            {
                if (mf.RelocatedInProcess) Mark(f.Rva, disk.Header.ImageBaseOffset, 8, "");
                else BitConverter.TryWriteBytes(_expected.AsSpan(at), mf.Image.Base);
            }
        }

        int diff = 0, explained = 0;
        string reason = "";
        var runs = new List<(int Start, int End)>();
        for (int b = 0; b < PageSize; b++)
        {
            if (_actual[b] == _expected[b]) continue;
            if (_why[b] is { } w)
            {
                if (w.Length > 0)
                {
                    explained++;
                    reason = w;
                }
                continue;
            }
            diff++;
            if (runs.Count > 0 && b - runs[^1].End <= 3) runs[^1] = (runs[^1].Start, b + 1);
            else runs.Add((b, b + 1));
        }

        f.DiffBytes = diff;
        f.DiffRuns = runs.Count;
        f.ExplainedBytes = explained;
        f.Functions = disk.FunctionsOnPage(f.Rva);
        f.Symbol = disk.Nearest(f.Rva);

        if (diff == 0)
        {
            if (explained > 0)
            {
                f.Verdict = Verdict.Explained;
                f.Reason = reason;
            }
            else if (mf.RelocatedInProcess && disk.HasRelocs(f.Rva))
            {
                f.Verdict = Verdict.Explained;
                f.Reason = "перенос базы внутри процесса";
            }
            else if (touchesLoader)
            {
                f.Verdict = Verdict.Explained;
                f.Reason = _why.First(x => !string.IsNullOrEmpty(x)) + " (значения прежние)";
            }
            else if (f.Kind == PageKind.Data && f.Section == MutableData)
            {
                f.Verdict = Verdict.Explained;
                f.Reason = MutableDataReason;
            }
            else
            {
                f.Verdict = Verdict.Restored;
            }
            return;
        }

        bool small = runs.Count <= MaxSites && runs.All(r => r.End - r.Start <= 24);
        foreach (var (start, end) in runs.Take(small ? MaxSites : 1))
        {
            int fn = f.Kind == PageKind.Code
                ? disk.FunctionStartIn(f.Rva + (uint)Math.Max(start - 4, 0), f.Rva + (uint)end)
                : -1;
            int at = fn >= 0 && fn - (int)f.Rva <= start ? fn - (int)f.Rva : start;
            int len = Math.Min(Math.Clamp(end - at, 16, 32), PageSize - at);
            var site = new PatchSite
            {
                Rva = f.Rva + (uint)at,
                Mem = _actual.AsSpan(at, len).ToArray(),
                Disk = _expected.AsSpan(at, len).ToArray(),
                AtFunctionStart = fn >= 0,
            };
            site.Symbol = disk.Nearest(site.Rva);
            if (f.Kind == PageKind.Code)
                (site.Target, site.TargetOutside) = Trace(site.Mem, mf.Image.Base + site.Rva);
            f.Sites.Add(site);
        }

        f.TargetOutside = f.Sites.Any(s => s.TargetOutside);
        f.Symbol = f.Sites[0].Symbol;
        bool hook = f.Sites.Any(s => s.AtFunctionStart && s.Target.Length > 0);
        f.Verdict = (diff <= 64 && runs.Count <= 2) || (small && hook) ? Verdict.Patch
            : diff >= ReplacedBytes ? Verdict.Replaced
            : Verdict.Rewritten;

        if (f.Kind == PageKind.Code) return;

        foreach (var (s, _) in runs.Take(12))
        {
            int slot = s & ~7;
            ulong was = BitConverter.ToUInt64(_expected, slot);
            ulong now = BitConverter.ToUInt64(_actual, slot);
            string line = $"+0x{slot:X3}: было 0x{was:X16}, стало 0x{now:X16}";
            if (now > 0x10000 && now < 0x7FFF_FFFF_0000UL)
            {
                var (text, outside) = _t.Describe(now, _images);
                line += $" → {text}";
                f.TargetOutside |= outside;
            }
            f.Slots.Add(line);
        }

        if (f.Kind == PageKind.Data && f.Section == MutableData && !f.TargetOutside)
        {
            f.Verdict = Verdict.Explained;
            f.Reason = MutableDataReason;
        }
    }

    private bool Mark(uint pageRva, uint rva, uint size, string why)
    {
        long from = Math.Max((long)rva, pageRva) - pageRva;
        long to = Math.Min((long)rva + size, (long)pageRva + PageSize) - pageRva;
        if (to <= from) return false;
        for (long b = from; b < to; b++) _why[b] = why;
        return true;
    }

    private (string Text, bool Outside) Trace(byte[] bytes, ulong site)
    {
        var hops = new List<string>();
        bool outside = false;
        ulong target = DecodeJump(bytes, site, true);
        for (int hop = 0; target != 0 && hop < 4; hop++)
        {
            var (text, executable) = _t.Describe(target, _images);
            hops.Add($"0x{target:X} — {text}");
            outside |= executable;
            if (!executable && bytes[0] != 0xEB) break;

            bytes = new byte[16];
            if (!_t.Read(target, bytes)) break;
            target = DecodeJump(bytes, target, false);
        }
        return (string.Join("  →  ", hops), outside);
    }

    private ulong DecodeJump(byte[] b, ulong site, bool allowCall)
    {
        ulong target = 0;
        if (b.Length >= 5 && (b[0] == 0xE9 || (b[0] == 0xE8 && allowCall)))
            target = site + 5 + (ulong)(long)BitConverter.ToInt32(b, 1);
        else if (b.Length >= 2 && b[0] == 0xEB)
            target = site + 2 + (ulong)(long)(sbyte)b[1];
        else if (b.Length >= 6 && b[0] == 0xFF && b[1] == 0x25)
            target = _t.ReadU64(site + 6 + (ulong)(long)BitConverter.ToInt32(b, 2));
        else if (b.Length >= 10 && b[0] is 0x48 or 0x49 && b[1] is >= 0xB8 and <= 0xBF)
            target = BitConverter.ToUInt64(b, 2);
        else if (b.Length >= 14 && b[0] == 0x68 && b[5] == 0xC7 && b[6] == 0x44 && b[7] == 0x24 &&
                 b[8] == 0x04)
            target = BitConverter.ToUInt32(b, 1) | ((ulong)BitConverter.ToUInt32(b, 9) << 32);
        else if (b.Length >= 6 && b[0] == 0x68 && b[5] == 0xC3)
            target = BitConverter.ToUInt32(b, 1);
        return target;
    }

    private static void MarkRuns(ModuleFacts mf)
    {
        var pages = mf.Facts.Where(f => f.Kind == PageKind.Code).OrderBy(f => f.Rva).ToList();
        int i = 0;
        while (i < pages.Count)
        {
            if (pages[i].Verdict is not (Verdict.Rewritten or Verdict.Replaced)) { i++; continue; }
            int j = i;
            while (j + 1 < pages.Count && pages[j + 1].Rva == pages[j].Rva + PageSize &&
                   pages[j + 1].Verdict is Verdict.Rewritten or Verdict.Replaced)
                j++;

            if (j - i + 1 >= SelfPatchRun)
            {
                double average = pages.Skip(i).Take(j - i + 1).Average(p => p.DiffBytes);
                var verdict = average >= ReplacedBytes ? Verdict.Replaced : Verdict.SelfPatch;
                for (int k = i; k <= j; k++) pages[k].Verdict = verdict;
            }
            i = j + 1;
        }
    }

    private void WriteFindings()
    {
        foreach (var mf in _modules.OrderBy(m => m.Image.Name, StringComparer.OrdinalIgnoreCase))
        {
            ReportRestored(mf);
            ReportPatches(mf);
            ReportReplaced(mf);
            ReportRewritten(mf);
            ReportUnverified(mf);
            ReportSelfPatch(mf);
            ReportHeader(mf);
            ReportData(mf);
        }
    }

    private Finding Start(ModuleFacts mf, string category, string title, Severity severity,
        string explanation)
    {
        var im = mf.Image;
        var f = _rep.Report(category, $"{im.Name}: {title}", severity, explanation);
        f.Add("модуль", im.Name);
        f.Add("путь", im.Path.Length > 0 ? im.Path : "нет");
        f.Add("база образа", $"0x{im.Base:X}");
        f.Add("размер образа", $"0x{im.Size:X}");
        if (mf.Comparable)
            f.Add("смещение от базы в файле", mf.Delta == 0 ? "нет" : $"0x{mf.Delta:X}");
        if (mf.RelocatedInProcess)
            f.Add("перенос базы", "выполнен внутри процесса — страницы с адресами приватны законно");
        if (mf.Note.Length > 0) f.Add("примечание", mf.Note);

        try
        {
            if (im.Path.Length > 0 && File.Exists(im.Path))
            {
                var vi = FileVersionInfo.GetVersionInfo(im.Path);
                if (!string.IsNullOrEmpty(vi.CompanyName)) f.Add("издатель по ресурсам файла", vi.CompanyName);
                if (!string.IsNullOrEmpty(vi.FileVersion)) f.Add("версия файла", vi.FileVersion);
            }
        }
        catch { }

        f.Add("страниц проверено", $"{mf.Pages}, из них кода {mf.CodePages}");
        f.Add("общих / приватных", $"{mf.Shared} / {mf.Facts.Count}");
        return f;
    }

    private static string PageLine(ModuleFacts mf, PageFact p) =>
        $"0x{p.Address:X16}  RVA 0x{p.Rva:X8}  {Trim(p.Section, 9),-9} " +
        $"{Target.Protection(p.Protection),-5} " +
        $"{(p.WasAbsent ? "была вытеснена" : p.Combined ? "объединена" : "в памяти"),-14} " +
        (p.Functions > 0 ? $"функций на странице: {p.Functions,-4} " : "") +
        (p.Verdict == Verdict.Restored && p.Exports.Length > 0 ? $"[экспорты: {p.Exports}]"
            : p.Symbol.Length > 0 ? $"[{p.Symbol}]" : "");

    private void ReportRestored(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.Restored).ToList();
        if (hits.Count == 0) return;

        int absent = hits.Count(h => h.WasAbsent);
        var f = Start(mf, "КОД",
            $"в код писали и вернули байты как было — страниц: {hits.Count}",
            KeyModules.Contains(mf.Image.Name) ? Severity.Critical : Severity.High,
            "Страница кода загруженного модуля физически общая: одна и та же страница " +
            "обслуживает все процессы, где загружен модуль. Приватная копия отделяется " +
            "ровно в одном случае — при ЗАПИСИ в страницу, и обратно к общей странице она " +
            "не привязывается никогда: восстановление прежних байт возвращает содержимое, " +
            "но не отменяет отделения копии. Поэтому сочетание «страница приватная, а " +
            "байты те же, что в файле» означает буквально следующее: в страницу ПИСАЛИ, " +
            "а потом запись откатили. Так выглядит снятый перехват: в начало функции " +
            "кладут переход, работают, а перед проверкой возвращают исходные байты. " +
            "Побайтовая сверка с файлом в этот момент не находит ничего — а запись " +
            "таблицы страниц помнит. Смена прав доступа без записи такого следа не " +
            "оставляет. Законные записи загрузчика (таблицы импорта, указатели проверки " +
            "вызовов, перенос базы) сверены побайтно и вычтены. Страница считается " +
            "приватной по происхождению: если система позже слила её с одинаковыми " +
            "копиями в других процессах, она помечена словом «объединена», и это та " +
            "же запись." +
            (absent > 0
                ? $" Вытеснены из памяти к моменту проверки: {absent}. Такие страницы " +
                  "возвращены чтением и вернулись приватными — след пережил вытеснение."
                : ""));

        f.Block("Страницы, в которые писали и вернули как было",
            string.Join("\n", hits.Take(400).Select(p => PageLine(mf, p))) +
            (hits.Count > 400 ? $"\n... ещё {hits.Count - 400}" : ""));
    }

    private void ReportPatches(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.Patch).OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        var sites = hits.SelectMany(p => p.Sites.Select(s => (Page: p, Site: s)))
            .OrderByDescending(x => x.Site.AtFunctionStart).ThenBy(x => x.Site.Rva).ToList();
        int atStart = sites.Count(x => x.Site.AtFunctionStart);
        int outside = sites.Count(x => x.Site.TargetOutside);
        var f = Start(mf, "КОД",
            $"точечная правка кода — мест: {sites.Count}" +
            (atStart > 0 ? $", в начале функции: {atStart}" : "") +
            (outside > 0 ? $", с переходом в исполняемую память вне образов: {outside}" : ""),
            atStart > 0 || outside > 0 ? Severity.Critical : Severity.High,
            "Страница приватная — значит, в неё писали, — и её содержимое до сих пор " +
            "отличается от файла, причём короткими участками. Так выглядит перехват, " +
            "стоящий прямо сейчас: в начало функции кладётся переход на чужой код, " +
            "остальная страница не трогается. Начала функций взяты из таблицы раскрутки " +
            "стека и таблицы экспорта самого файла, а не угаданы. Там, где правка " +
            "разбирается как переход, он прослежен до конца, через промежуточные " +
            "заглушки: видно, какому образу принадлежит код, получающий управление. " +
            "Переход в исполняемую память, не принадлежащую ни одному образу, — это " +
            "код, которого нет ни в одном файле. Адреса, которые правит перенос базы, " +
            "пересчитаны и в отличия не попадают.");
        f.Add("страниц с правками", hits.Count.ToString());

        var sb = new StringBuilder();
        foreach (var (p, s) in sites.Take(200))
        {
            sb.AppendLine($"{mf.Image.Name}+0x{s.Rva:X}  (0x{mf.Image.Base + s.Rva:X})" +
                          (s.Symbol.Length > 0 ? $"  [{s.Symbol}]" : "") +
                          (s.AtFunctionStart ? "  — НАЧАЛО ФУНКЦИИ" : ""));
            sb.AppendLine("    в файле : " + Hex(s.Disk));
            sb.AppendLine("    в памяти: " + Hex(s.Mem) + Meaning(s.Mem));
            if (s.Target.Length > 0) sb.AppendLine("    ведёт в : " + s.Target);
            sb.AppendLine($"    секция {p.Section}, права {Target.Protection(p.Protection)}; " +
                          $"всего на странице отличается {p.DiffBytes} байт, мест {p.DiffRuns}" +
                          (p.WasAbsent ? "; страница была вытеснена" : ""));
        }
        if (sites.Count > 200) sb.AppendLine($"... ещё {sites.Count - 200}");
        f.Block("Правки", sb.ToString().TrimEnd());
    }

    private void ReportReplaced(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.Replaced).OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        var f = Start(mf, "КОД",
            $"код замещён другим содержимым — страниц: {hits.Count} " +
            $"(RVA 0x{hits[0].Rva:X}–0x{hits[^1].Rva + PageSize:X})",
            Severity.High,
            "Страницы приватные, и больше половины байт на каждой не совпадает с файлом: " +
            "от исходного кода модуля на них ничего не осталось. Точечный перехват так " +
            "не выглядит, и правка модулем самого себя тоже — она меняет отдельные " +
            "адреса, а не весь код. Так выглядит замещение: поверх кода загруженной " +
            "библиотеки записан другой код, который исполняется под её именем, а " +
            "проверки по списку модулей видят обычный файл с диска.");
        f.Add("в среднем отличается байт на странице",
            ((int)hits.Average(p => p.DiffBytes)).ToString());
        f.Block("Замещённые страницы", string.Join("\n", hits.Take(400).Select(p =>
            PageLine(mf, p) + $"  отличий {p.DiffBytes}")) +
            (hits.Count > 400 ? $"\n... ещё {hits.Count - 400}" : ""));
        AddSamples(f, mf, hits);
    }

    private void ReportRewritten(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.Rewritten).OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        bool outside = hits.Any(h => h.TargetOutside);
        var f = Start(mf, "КОД",
            $"код изменён во многих местах — страниц: {hits.Count}",
            outside ? Severity.High : Severity.Medium,
            "Страницы приватные, и содержимое отличается от файла не точечно: участков " +
            "много либо они длинные, и ни один не разбирается как переход в начале " +
            "функции, но основная часть кода на месте. Для перехвата это много, для " +
            "замещения кода — мало. Так выглядят крупная заглушка, вписанная в код, " +
            "или правка модулем самого себя. Смотрите первые отличия и то, чьему " +
            "издателю принадлежит файл.");
        f.Block("Изменённые страницы", string.Join("\n", hits.Take(400).Select(p =>
            PageLine(mf, p) + $"  отличий {p.DiffBytes}, участков {p.DiffRuns}")) +
            (hits.Count > 400 ? $"\n... ещё {hits.Count - 400}" : ""));
        AddSamples(f, mf, hits);
    }

    private static void AddSamples(Finding f, ModuleFacts mf, List<PageFact> hits)
    {
        var sb = new StringBuilder();
        foreach (var s in hits.Take(8).SelectMany(p => p.Sites.Take(1)))
        {
            sb.AppendLine($"{mf.Image.Name}+0x{s.Rva:X}" +
                          (s.Symbol.Length > 0 ? $"  [{s.Symbol}]" : ""));
            sb.AppendLine("    в файле : " + Hex(s.Disk));
            sb.AppendLine("    в памяти: " + Hex(s.Mem) + Meaning(s.Mem));
            if (s.Target.Length > 0) sb.AppendLine("    ведёт в : " + s.Target);
        }
        f.Block("Первое отличие на странице", sb.ToString().TrimEnd());
    }

    private void ReportUnverified(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.Unverified).OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        var f = Start(mf, "КОД",
            $"страницы кода приватны, а сверить их не с чем — страниц: {hits.Count}",
            Severity.High,
            "Страницы приватные — значит, в них писали. Сказать, остались ли изменения " +
            "или их вернули, нельзя: нет файла, с которым образ можно сравнить, либо " +
            "файл на диске уже другой, либо страница не читается. Образ, у которого " +
            "после загрузки пропал или сменился файл, сам по себе требует объяснения.");
        f.Add("почему не сверено", string.Join("; ",
            hits.Select(h => h.Reason).Where(r => r.Length > 0).Distinct()));
        f.Block("Приватные страницы", string.Join("\n", hits.Take(400).Select(p =>
            PageLine(mf, p))) + (hits.Count > 400 ? $"\n... ещё {hits.Count - 400}" : ""));
    }

    private void ReportSelfPatch(ModuleFacts mf)
    {
        var hits = mf.Of(PageKind.Code, Verdict.SelfPatch).OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        var f = Start(mf, "СПРАВКА",
            $"модуль правит свой код сплошной полосой — страниц: {hits.Count} " +
            $"(RVA 0x{hits[0].Rva:X}–0x{hits[^1].Rva + PageSize:X})",
            Severity.Info,
            "Страницы приватные и отличаются от файла, но идут подряд, и на каждой " +
            "изменена меньшая часть байт: код модуля на месте, поправлены адреса внутри " +
            "него. Это почерк модуля, который правит сам себя при запуске, — так " +
            "поступают драйверы видеокарт, размещая в коде свои таблицы переходов. " +
            "Перехват так не выглядит: он точечный. Строка приведена, чтобы полоса была " +
            "видна и её можно было отличить от находок выше.");
        f.Add("в среднем отличается байт на странице",
            ((int)hits.Average(p => p.DiffBytes)).ToString());
    }

    private void ReportHeader(ModuleFacts mf)
    {
        var hits = mf.Facts.Where(p => p.Kind == PageKind.Header && p.Unexplained).ToList();
        if (hits.Count == 0) return;

        bool restored = hits.All(h => h.Verdict == Verdict.Restored);
        var f = Start(mf, "ЗАГОЛОВОК",
            mf.HeaderBroken
                ? "заголовок образа в памяти стёрт или испорчен"
                : restored
                    ? "в заголовок образа писали и вернули байты как было"
                    : "заголовок образа в памяти изменён",
            mf.HeaderBroken ? Severity.High : Severity.Medium,
            "Заголовок образа — такая же общая страница, как код: штатной работе в него " +
            "писать незачем. Приватная страница заголовка означает запись. Заголовок " +
            "стирают, чтобы образ нельзя было найти в памяти по подписи и снять с него " +
            "копию, и правят, чтобы изменить описание секций. Поле базы, которое система " +
            "переписывает при размещении образа, в отличия не входит.");
        var sb = new StringBuilder();
        foreach (var p in hits)
        {
            sb.AppendLine(PageLine(mf, p) + $"  {VerdictName(p)}");
            foreach (string s in p.Slots) sb.AppendLine("    " + s);
        }
        f.Block("Страницы заголовка", sb.ToString().TrimEnd());
    }

    private void ReportData(ModuleFacts mf)
    {
        var hits = mf.Facts.Where(p => p.Kind == PageKind.Data && p.Unexplained)
            .OrderBy(p => p.Rva).ToList();
        if (hits.Count == 0) return;

        bool outside = hits.Any(h => h.TargetOutside);
        var f = Start(mf, "ДАННЫЕ",
            $"в данные только для чтения писали — страниц: {hits.Count}" +
            (outside ? ", записанный адрес ведёт в исполняемую память вне образов" : ""),
            outside ? Severity.High : Severity.Low,
            "Секция объявлена в файле доступной только для чтения, а её страница " +
            "приватна: чтобы в неё записать, права сначала сняли. В таких секциях лежат " +
            "таблицы виртуальных функций и таблицы адресов — подмена одного адреса в них " +
            "перенаправляет вызов без единой правки кода. Законные записи загрузчика " +
            "(импорт, отложенный импорт, указатели проверки вызовов) сверены побайтно и " +
            "вычтены. Для каждого изменённого места показано прежнее и нынешнее значение " +
            "и то, куда нынешнее ведёт. Сама по себе находка слабая: часть библиотек " +
            "штатно правит свои защищённые данные; сильной её делает адрес, ведущий в " +
            "исполняемую память вне образов.");
        var sb = new StringBuilder();
        foreach (var p in hits.Take(200))
        {
            sb.AppendLine(PageLine(mf, p) + $"  {VerdictName(p)}");
            foreach (string s in p.Slots) sb.AppendLine("    " + s);
        }
        if (hits.Count > 200) sb.AppendLine($"... ещё {hits.Count - 200}");
        f.Block("Страницы данных", sb.ToString().TrimEnd());
    }

    private void WriteSections()
    {
        var sb = new StringBuilder();
        sb.AppendLine("ЧТО ПРОВЕРЯЕТСЯ");
        sb.AppendLine();
        sb.AppendLine("Код и данные только для чтения у загруженного образа физически общие:");
        sb.AppendLine("одна и та же страница обслуживает все процессы, где загружен файл.");
        sb.AppendLine("Приватная копия отделяется ровно в одном случае — при записи в страницу,");
        sb.AppendLine("и обратно к общей уже не привязывается. Восстановление прежних байт");
        sb.AppendLine("возвращает содержимое, но не отменяет отделения копии.");
        sb.AppendLine();
        sb.AppendLine("Для каждого образа процесса берутся заголовок и все секции без права");
        sb.AppendLine("записи. Состояние каждой страницы запрашивается у ядра:");
        sb.AppendLine();
        sb.AppendLine("    ОБЩАЯ         — в страницу ни разу не писали;");
        sb.AppendLine("    ПРИВАТНАЯ     — отделена копия: запись была;");
        sb.AppendLine("    ОБЪЕДИНЕНА    — копия отделена, но система позже слила её с");
        sb.AppendLine("                    одинаковыми копиями в других процессах. Такая");
        sb.AppendLine("                    страница снова числится общей, и отличает её только");
        sb.AppendLine("                    разряд происхождения: её прообраз общим не был.");
        sb.AppendLine("                    Запись в неё была точно так же;");
        sb.AppendLine("    ВЫТЕСНЕНА     — страницы нет в памяти. Если ядро помнит её общий");
        sb.AppendLine("                    прообраз, в неё не писали. Иначе страница читается,");
        sb.AppendLine("                    чтобы вернуть её в память, и смотрится, какой она");
        sb.AppendLine("                    вернулась: общей или приватной.");
        sb.AppendLine();
        sb.AppendLine("Решает разряд происхождения страницы, а не разряд «общая»: за минуты");
        sb.AppendLine("работы система сливает одинаковые копии страниц разных процессов, и");
        sb.AppendLine("страница, в которую писали, начинает числиться общей.");
        sb.AppendLine();
        sb.AppendLine("Каждая приватная страница побайтно сверяется с файлом на диске. Адреса,");
        sb.AppendLine("которые правит перенос базы, пересчитываются, а места, куда штатно пишет");
        sb.AppendLine("загрузчик, вычитаются по байтам, а не страницами целиком:");
        sb.AppendLine();
        sb.AppendLine("    таблица адресов импорта, отложенный импорт, указатели проверки");
        sb.AppendLine("    вызовов (CFG), поле базы в заголовке, перенос базы внутри процесса,");
        sb.AppendLine("    секция .mrdata, которую модуль сам открывает на запись.");
        sb.AppendLine();
        sb.AppendLine("По итогу сверки страница получает одно из значений:");
        sb.AppendLine();
        sb.AppendLine("    СОВПАДАЕТ С ФАЙЛОМ — писали и вернули как было (снятый перехват);");
        sb.AppendLine("    ТОЧЕЧНАЯ ПРАВКА    — короткие участки: до 64 байт в одном-двух местах");
        sb.AppendLine("                         либо несколько переходов в началах функций;");
        sb.AppendLine("    ИЗМЕНЕНА           — отличий больше, но код в основном на месте;");
        sb.AppendLine("    ЗАМЕЩЕНА           — отличается больше половины страницы;");
        sb.AppendLine("    ПОЛОСА             — подряд идущие изменённые страницы с малой долей");
        sb.AppendLine("                         отличий: модуль правит сам себя;");
        sb.AppendLine("    ОБЪЯСНЕНА          — отличия только там, куда пишет загрузчик;");
        sb.AppendLine("    НЕ СВЕРЕНА         — файла нет, он другой либо страница не читается.");
        sb.AppendLine();
        sb.AppendLine("Сканер читает из процесса только заголовки образов, сами приватные");
        sb.AppendLine("страницы и по одному байту из вытесненных страниц без общего прообраза.");
        _rep.Section("МЕТОД", sb.ToString());

        sb.Clear();
        sb.AppendLine($"{"МОДУЛЬ",-30} {"СТР.",-7} {"ОБЩИХ",-7} {"ПРИВАТ.",-8} {"ВЫТЕСН.",-8} " +
                      $"{"КОД:ПРИВ.",-10} {"БЕЗ ПРИЧИНЫ",-12} {"БАЗА",-16} ПРИМЕЧАНИЕ");
        sb.AppendLine(new string('-', 140));
        foreach (var mf in _modules.OrderByDescending(m => m.Facts.Count(f => f.Unexplained && f.Kind == PageKind.Code))
                     .ThenByDescending(m => m.Facts.Count(f => f.Unexplained))
                     .ThenByDescending(m => m.Facts.Count)
                     .ThenBy(m => m.Image.Name, StringComparer.OrdinalIgnoreCase))
        {
            var notes = new List<string>();
            if (mf.RelocatedInProcess) notes.Add("база перенесена внутри процесса");
            if (mf.AbsentUnknown > 0) notes.Add($"не удалось вернуть в память: {mf.AbsentUnknown}");
            if (mf.Note.Length > 0) notes.Add(mf.Note);
            sb.AppendLine(
                $"{Trim(mf.Image.Name, 30),-30} {mf.Pages,-7} {mf.Shared,-7} {mf.Facts.Count,-8} " +
                $"{mf.AbsentClean + mf.AbsentUnknown,-8} " +
                $"{mf.Facts.Count(f => f.Kind == PageKind.Code),-10} " +
                $"{mf.Facts.Count(f => f.Unexplained),-12} {mf.Image.Base,-16:X} " +
                string.Join("; ", notes));
        }
        sb.AppendLine();
        sb.AppendLine("    СТР.        — страниц заголовка и секций без права записи;");
        sb.AppendLine("    ВЫТЕСН.     — страниц нет в памяти, и в них не писали;");
        sb.AppendLine("    КОД:ПРИВ.   — приватные страницы в секциях кода;");
        sb.AppendLine("    БЕЗ ПРИЧИНЫ — приватные страницы, которые не объяснились записью");
        sb.AppendLine("                  загрузчика и правкой модулем самого себя.");
        _rep.Section("СВОДКА ПО ОБРАЗАМ", sb.ToString());

        sb.Clear();
        foreach (var mf in _modules.Where(m => m.Facts.Count > 0)
                     .OrderByDescending(m => m.Facts.Count(f => f.Unexplained))
                     .ThenBy(m => m.Image.Name, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"=== {mf.Image.Name}  (0x{mf.Image.Base:X})");
            sb.AppendLine($"    {(mf.Image.Path.Length > 0 ? mf.Image.Path : "файла нет")}");
            if (mf.Note.Length > 0) sb.AppendLine($"    примечание: {mf.Note}");
            if (mf.RelocatedInProcess)
                sb.AppendLine($"    база перенесена внутри процесса: страниц с адресами " +
                              $"{mf.RelocPages}, из них приватных {mf.RelocPrivate}");

            foreach (var p in mf.Facts.Where(f => f.Unexplained).OrderBy(f => f.Rva).Take(300))
            {
                sb.AppendLine("    " + PageLine(mf, p) + "  " + VerdictName(p));
                foreach (var s in p.Sites.Take(p.Kind == PageKind.Code ? 8 : 1))
                {
                    sb.AppendLine($"        +0x{s.Rva - p.Rva:X3} в файле : {Hex(s.Disk)}");
                    sb.AppendLine($"        +0x{s.Rva - p.Rva:X3} в памяти: {Hex(s.Mem)}" +
                                  (p.Kind == PageKind.Code ? Meaning(s.Mem) : "") +
                                  (s.AtFunctionStart ? $"   [{s.Symbol}, начало функции]" : ""));
                    if (s.Target.Length > 0) sb.AppendLine("        ведёт в : " + s.Target);
                }
                foreach (string s in p.Slots) sb.AppendLine("        " + s);
            }
            int more = mf.Facts.Count(f => f.Unexplained) - 300;
            if (more > 0) sb.AppendLine($"    ... ещё {more}");

            var explained = mf.Facts.Where(f => !f.Unexplained)
                .GroupBy(f => f.Verdict == Verdict.SelfPatch ? "полоса правок модулем самого себя" : f.Reason)
                .OrderByDescending(g => g.Count()).ToList();
            if (explained.Count > 0)
            {
                sb.AppendLine("    объяснено:");
                foreach (var g in explained)
                    sb.AppendLine($"        {g.Count(),6}  {g.Key}  " +
                                  $"(секции: {string.Join(", ", g.Select(x => x.Section).Distinct().Take(6))})");
            }
            sb.AppendLine();
        }
        if (sb.Length == 0) sb.AppendLine("Приватных страниц в проверенных секциях нет.");
        _rep.Section("ПРИВАТНЫЕ СТРАНИЦЫ ПО МОДУЛЯМ", sb.ToString());

        sb.Clear();
        int suspects = _modules.Sum(m => m.Suspects);
        sb.AppendLine("Страница, которой нет в памяти, сама по себе ничего не значит: система");
        sb.AppendLine("вытесняет и общие страницы. У нетронутой страницы ядро помнит общий");
        sb.AppendLine("прообраз, и такие страницы не читаются вовсе. Остальные читаются по");
        sb.AppendLine("одному байту: чтение возвращает страницу в память, и после этого её");
        sb.AppendLine("состояние однозначно.");
        sb.AppendLine();
        sb.AppendLine($"    вытеснено без общего прообраза : {suspects}");
        sb.AppendLine($"    вернулись ПРИВАТНЫМИ           : {_modules.Sum(m => m.Confirmed)}  (в них писали)");
        sb.AppendLine($"    вернулись общими               : {_modules.Sum(m => m.Refuted)}  (в них не писали)");
        sb.AppendLine($"    вернуть не удалось             : {_modules.Sum(m => m.AbsentUnknown)}");
        sb.AppendLine($"    вытеснено с общим прообразом   : {_modules.Sum(m => m.AbsentClean - m.Refuted)}  " +
                      (_verifyAll ? "(перепроверены чтением по ключу --verify-all)" : "(не читались)"));
        if (_shapes.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine($"{"РАЗРЯДЫ ЗАПИСИ ВЫТЕСНЕННОЙ СТРАНИЦЫ",-48} {"ПРИВАТНЫХ",-10} {"ОБЩИХ",-8} НЕ ВЕРНУЛИСЬ");
            sb.AppendLine(new string('-', 84));
            foreach (var (key, c) in _shapes)
                sb.AppendLine($"{key,-48} {c[0],-10} {c[1],-8} {c[2]}");
        }
        _rep.Section("ВЫТЕСНЕННЫЕ СТРАНИЦЫ: ПЕРЕПРОВЕРКА ЧТЕНИЕМ", sb.ToString());
    }

    private void WriteMeta()
    {
        _rep.AddMeta("Образов в процессе", _modules.Count.ToString());
        _rep.AddMeta("Образов сверено с файлом", _modules.Count(m => m.Comparable).ToString());
        _rep.AddMeta("Страниц проверено", _modules.Sum(m => m.Pages).ToString());
        _rep.AddMeta("Из них общих", _modules.Sum(m => m.Shared).ToString());
        _rep.AddMeta("Приватных", _modules.Sum(m => m.Facts.Count).ToString());
        _rep.AddMeta("Из приватных слито с чужими копиями",
            _originBit ? _modules.Sum(m => m.Facts.Count(f => f.Combined)).ToString()
                : "система не сообщает происхождение страниц — слитые копии не видны");
        _rep.AddMeta("Приватных в коде", _modules.Sum(m => m.Facts.Count(f => f.Kind == PageKind.Code)).ToString());
        _rep.AddMeta("Приватных без объяснения", _modules.Sum(m => m.Facts.Count(f => f.Unexplained)).ToString());
        _rep.AddMeta("Вытесненных, перепроверено чтением", _modules.Sum(m => m.Suspects).ToString());
    }

    private static string VerdictName(PageFact p) => p.Verdict switch
    {
        Verdict.Restored => "СОВПАДАЕТ С ФАЙЛОМ",
        Verdict.Patch => $"ТОЧЕЧНАЯ ПРАВКА: {p.DiffBytes} байт, мест {p.DiffRuns}" +
                         (p.Sites.Any(s => s.AtFunctionStart) ? ", НАЧАЛО ФУНКЦИИ" : ""),
        Verdict.Rewritten => $"ИЗМЕНЕНА: {p.DiffBytes} байт, участков {p.DiffRuns}",
        Verdict.Replaced => $"ЗАМЕЩЕНА: {p.DiffBytes} байт",
        Verdict.SelfPatch => "ПОЛОСА",
        Verdict.Explained => "ОБЪЯСНЕНА: " + p.Reason,
        _ => "НЕ СВЕРЕНА" + (p.Reason.Length > 0 ? ": " + p.Reason : ""),
    };

    private static string Hex(byte[]? b) =>
        b is null ? "-" : string.Join(' ', b.Select(x => x.ToString("X2")));

    private static string Meaning(byte[]? b)
    {
        if (b is null || b.Length == 0) return "";
        string m =
            b.Length >= 5 && b[0] == 0xE9 ? "относительный переход (jmp rel32)" :
            b.Length >= 5 && b[0] == 0xE8 ? "относительный вызов (call rel32)" :
            b.Length >= 6 && b[0] == 0xFF && b[1] == 0x25 ? "переход по указателю (jmp [rip+disp])" :
            b.Length >= 10 && b[0] is 0x48 or 0x49 && b[1] is >= 0xB8 and <= 0xBF
                ? "загрузка адреса в регистр, далее переход" :
            b.Length >= 2 && b[0] == 0xEB ? "короткий переход (jmp rel8)" :
            b[0] == 0xCC ? "точка останова (int3)" :
            b.Length >= 2 && b[0] == 0x0F && b[1] == 0x0B ? "недопустимая команда (ud2)" :
            b[0] == 0xC3 ? "немедленный возврат — функция отключена" :
            b.Length >= 3 && b[0] is 0x31 or 0x33 && b[1] == 0xC0 ? "обнуление результата (xor eax,eax)" :
            b.Length >= 6 && b[0] == 0x68 ? "адрес на стек, далее возврат (push/ret)" :
            b[0] == 0x90 ? "пустые команды (nop)" : "";
        return m.Length > 0 ? "   ← " + m : "";
    }

    private static string Trim(string s, int n) => s.Length <= n ? s : s.Substring(0, n - 1) + "…";
}
