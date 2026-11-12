using System.Diagnostics;
using System.Text;
using Microsoft.Win32;

namespace PageScan;

internal static class Program
{
    public const string Tool = "PageScan";
    public const string Version = "1.0";

    private static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }

        bool ownConsole = OwnsConsole();
        int code;
        try
        {
            code = Run(Options.Parse(args), ownConsole);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Ошибка: {ex.Message}");
            code = 3;
        }

        if (ownConsole)
        {
            Console.WriteLine();
            Console.Write("Нажмите любую клавишу, чтобы закрыть окно…");
            try { Console.ReadKey(true); } catch { }
        }
        return code;
    }

    private static int Run(Options opt, bool ownConsole)
    {
        if (opt.Help)
        {
            PrintHelp();
            return 0;
        }

        bool debug = Native.EnableDebugPrivilege();
        if (!debug)
            Console.Error.WriteLine("ВНИМАНИЕ: права отладки не получены. Запустите сканер от " +
                                    "имени администратора, иначе процесс может не открыться.");

        if (opt.List)
        {
            PrintCandidates(Target.FindJava());
            return 0;
        }

        int pid = opt.Pid;
        if (pid <= 0)
        {
            var all = Target.FindJava();
            var mc = all.Where(c => c.LooksLikeMinecraft).ToList();
            if (mc.Count != 1)
            {
                Console.Error.WriteLine(mc.Count == 0
                    ? "Процесс Minecraft (java/javaw) не найден. Укажите его: --pid <N>"
                    : "Найдено несколько процессов Minecraft. Укажите нужный: --pid <N>");
                PrintCandidates(mc.Count == 0 ? all : mc);
                return 2;
            }
            pid = mc[0].Pid;
        }

        var sw = Stopwatch.StartNew();
        var rep = new ScanReport();
        using (var target = Target.Open(pid))
        {
            Console.WriteLine($"{Tool} {Version} — приватные страницы внутри образов процесса");
            Console.WriteLine($"Цель: PID {pid}  {target.ImagePath}");

            rep.AddMeta("Образ", target.ImagePath);
            rep.AddMeta("PID", pid.ToString());
            rep.AddMeta("Командная строка", target.CommandLine());
            rep.AddMeta("Процесс запущен", target.StartUtc == default
                ? "-"
                : target.StartUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
            rep.AddMeta("Доступ к процессу", target.Access);
            rep.AddMeta("Права отладки", debug ? "получены" : "НЕ получены");

            bool live = !Console.IsErrorRedirected;
            PageAudit.Run(target, rep, opt.VerifyAll, (n, total, name) =>
            {
                if (live) Console.Error.Write($"\r  [{n}/{total}] {Fit(name, 44),-44}");
            });
            if (live) Console.Error.Write("\r" + new string(' ', 64) + "\r");
        }
        sw.Stop();

        string dir = opt.OutputDir ?? Path.Combine(AppContext.BaseDirectory, "reports");
        Directory.CreateDirectory(dir);
        string html = Path.Combine(dir, $"pagescan-{pid}-{DateTime.Now:yyyyMMdd-HHmmss}.html");
        File.WriteAllText(html, HtmlReport.Render(rep, pid, sw.Elapsed), new UTF8Encoding(false));

        PrintSummary(rep, sw.Elapsed);
        Console.WriteLine();
        Console.WriteLine($"Отчёт: {html}");

        if (opt.Open || ownConsole) OpenInBrowser(html);

        if (rep.Count(Severity.Critical) > 0) return 10;
        if (rep.Count(Severity.High) > 0) return 9;
        if (rep.Count(Severity.Medium) > 0) return 8;
        return 0;
    }

    private static void PrintSummary(ScanReport rep, TimeSpan elapsed)
    {
        Console.WriteLine();
        foreach (var (sev, label, color) in new[]
                 {
                     (Severity.Critical, "КРИТИЧНО", ConsoleColor.Red),
                     (Severity.High, "ВЫСОКАЯ ", ConsoleColor.Yellow),
                     (Severity.Medium, "СРЕДНЯЯ ", ConsoleColor.Cyan),
                 })
        {
            foreach (var f in rep.Findings.Where(x => x.Severity == sev))
            {
                Colored(color, $"  {label} ");
                Console.WriteLine($"[{f.Category}] {f.Title}");
            }
        }

        Console.WriteLine();
        foreach (var (k, v) in rep.Meta.Skip(6)) Console.WriteLine($"  {k,-36}: {v}");
        Console.WriteLine();
        Console.WriteLine($"  Критических: {rep.Count(Severity.Critical)}   " +
                          $"Высоких: {rep.Count(Severity.High)}   " +
                          $"Средних: {rep.Count(Severity.Medium)}   " +
                          $"Низких: {rep.Count(Severity.Low)}   " +
                          $"Инфо: {rep.Count(Severity.Info)}   " +
                          $"Время: {elapsed.TotalSeconds:F1} с");

        if (rep.Count(Severity.Critical) > 0)
            Colored(ConsoleColor.Red, "  ВЫВОД: в код образов писали — найдены следы перехватов.\n");
        else if (rep.Count(Severity.High) > 0)
            Colored(ConsoleColor.Yellow, "  ВЫВОД: есть аномалии, требующие ручной проверки.\n");
        else
            Colored(ConsoleColor.Green, "  ВЫВОД: следов записи в код образов не найдено.\n");

        if (rep.Errors.Count > 0)
            Console.WriteLine($"  Ошибок при проверке: {rep.Errors.Count} — см. вкладку отчёта.");
    }

    private static void Colored(ConsoleColor color, string text)
    {
        var old = Console.ForegroundColor;
        Console.ForegroundColor = color;
        Console.Write(text);
        Console.ForegroundColor = old;
    }

    private static void PrintCandidates(List<Candidate> list)
    {
        if (list.Count == 0)
        {
            Console.WriteLine("Процессов java/javaw нет.");
            return;
        }
        Console.WriteLine("Процессы Java:");
        foreach (var c in list)
        {
            Console.WriteLine($"  PID {c.Pid,-7} {c.Name,-9} Minecraft: {(c.LooksLikeMinecraft ? "да " : "нет")}  " +
                              $"{(c.Title.Length > 0 ? c.Title : "без окна")}");
            if (c.ExePath.Length > 0) Console.WriteLine($"      {c.ExePath}");
        }
    }

    private static string Fit(string s, int n) => s.Length <= n ? s : s.Substring(0, n);

    private static unsafe bool OwnsConsole()
    {
        try
        {
            uint* list = stackalloc uint[2];
            return Native.GetConsoleProcessList(list, 2) == 1;
        }
        catch
        {
            return false;
        }
    }

    private static void OpenInBrowser(string path)
    {
        try
        {
            string? exe = BrowserExe();
            if (exe is not null)
                Process.Start(new ProcessStartInfo(exe, $"\"{new Uri(path).AbsoluteUri}\"")
                {
                    UseShellExecute = false,
                });
            else
                Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Открыть отчёт не удалось: {ex.Message}");
        }
    }

    private static string? BrowserExe()
    {
        using var choice = Registry.CurrentUser.OpenSubKey(
            @"Software\Microsoft\Windows\Shell\Associations\UrlAssociations\http\UserChoice");
        if (choice?.GetValue("ProgId") is not string progId) return null;
        using var command = Registry.ClassesRoot.OpenSubKey(progId + @"\shell\open\command");
        if (command?.GetValue(null) is not string line) return null;

        line = line.Trim();
        int close = line.StartsWith('"') ? line.IndexOf('"', 1) : -1;
        string exe = close > 0 ? line.Substring(1, close - 1) : line.Split(' ')[0];
        return File.Exists(exe) ? exe : null;
    }

    private static void PrintHelp()
    {
        Console.WriteLine($"""
        {Tool} {Version} — проверка образов процесса на приватные страницы.

        Код загруженного модуля общий для всех процессов, пока в него не запишут.
        Запись отделяет приватную копию страницы, и вернуть её обратно нельзя,
        поэтому приватная страница кода — след записи, даже если байты уже
        возвращены на место. Сканер находит такие страницы, сверяет их с файлом
        на диске и пишет отчёт в .html.

        Использование:
          PageScan.exe                    процесс Minecraft ищется сам
          PageScan.exe --pid <N>          проверить процесс с этим PID

          --pid, -p <N>     PID процесса
          --list, -l        показать процессы java/javaw и выйти
          --out, -o <dir>   каталог для отчёта (по умолчанию reports рядом с exe)
          --open            открыть отчёт в браузере после проверки
          --verify-all      перечитать и те вытесненные страницы, которые ядро
                            считает нетронутыми (проверка правила самого сканера)

        Коды возврата: 10 — есть КРИТИЧНО, 9 — ВЫСОКАЯ, 8 — СРЕДНЯЯ, 0 — чисто,
        2 — процесс не найден, 3 — ошибка.

        Запускать от имени администратора.
        """);
    }
}

internal sealed class Options
{
    public int Pid;
    public bool List;
    public bool Help;
    public bool Open;
    public bool VerifyAll;
    public string? OutputDir;

    public static Options Parse(string[] args)
    {
        var o = new Options();
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "-h" or "--help" or "/?": o.Help = true; break;
                case "-l" or "--list": o.List = true; break;
                case "--open": o.Open = true; break;
                case "--verify-all": o.VerifyAll = true; break;
                case "-p" or "--pid":
                    if (i + 1 < args.Length && int.TryParse(args[++i], out int pid)) o.Pid = pid;
                    break;
                case "-o" or "--out":
                    if (i + 1 < args.Length) o.OutputDir = args[++i];
                    break;
                default:
                    if (int.TryParse(args[i], out int bare) && o.Pid == 0) o.Pid = bare;
                    break;
            }
        }
        return o;
    }
}
