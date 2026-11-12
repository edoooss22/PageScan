using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using static PageScan.Native;

namespace PageScan;

internal sealed class MappedImage
{
    public ulong Base;
    public ulong Size;
    public string Path = "";
    public string Name = "";

    public bool Contains(ulong address) => address >= Base && address < Base + Size;
}

internal sealed record Candidate(int Pid, string Name, string Title, string ExePath,
    string CommandLine, DateTime StartUtc, bool LooksLikeMinecraft);

internal sealed unsafe class Target : IDisposable
{
    public const int PageSize = 0x1000;

    public int Pid { get; }
    public IntPtr Handle { get; private set; }
    public string ImagePath { get; private set; } = "";
    public DateTime StartUtc { get; private set; }
    public string Access { get; private set; } = "";

    private Target(int pid, IntPtr handle)
    {
        Pid = pid;
        Handle = handle;
    }

    public static Target Open(int pid)
    {
        var levels = new (uint Access, string Name)[]
        {
            (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, "QUERY_INFORMATION|VM_READ"),
            (PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, "QUERY_LIMITED_INFORMATION|VM_READ"),
        };

        foreach (var (access, name) in levels)
        {
            IntPtr h = OpenProcess(access, false, pid);
            if (h == IntPtr.Zero) continue;
            var t = new Target(pid, h) { Access = name };
            t.Init();
            return t;
        }
        throw new InvalidOperationException(
            $"Процесс {pid} не открывается (ошибка Win32 {Marshal.GetLastWin32Error()}). " +
            "Запустите сканер от имени администратора.");
    }

    private void Init()
    {
        uint cap = 4096;
        char* buf = stackalloc char[(int)cap];
        if (QueryFullProcessImageNameW(Handle, 0, buf, ref cap))
            ImagePath = new string(buf, 0, (int)cap);
        if (GetProcessTimes(Handle, out long created, out _, out _, out _))
            StartUtc = DateTime.FromFileTimeUtc(created);
    }

    public bool Read(ulong address, Span<byte> dest)
    {
        fixed (byte* p = dest)
            return ReadProcessMemory(Handle, address, p, (nuint)dest.Length, out var read) &&
                   read == (nuint)dest.Length;
    }

    public ulong ReadU64(ulong address)
    {
        ulong v = 0;
        return Read(address, new Span<byte>(&v, 8)) ? v : 0;
    }

    public string CommandLine()
    {
        for (int cap = 0x1000; cap <= 0x40000; cap *= 4)
        {
            var buf = new byte[cap];
            fixed (byte* p = buf)
            {
                uint ret = 0;
                int st = NtQueryInformationProcess(Handle, ProcessCommandLineInformation, p,
                    (uint)cap, &ret);
                if (st == unchecked((int)0xC0000004)) continue;
                if (st != 0) return "";
                ushort len = BitConverter.ToUInt16(buf, 0);
                if (len == 0 || len > cap - 16) return "";
                return Encoding.Unicode.GetString(buf, 16, len);
            }
        }
        return "";
    }

    public List<MappedImage> Images()
    {
        var byBase = new Dictionary<ulong, MappedImage>();
        ulong address = 0;
        int failures = 0;

        while (address < 0x7FFF_FFFF_0000UL)
        {
            if (VirtualQueryEx(Handle, address, out var mbi,
                    (nuint)sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            {
                if (++failures > 256) break;
                address += 0x10000;
                continue;
            }
            failures = 0;

            ulong next = mbi.BaseAddress + mbi.RegionSize;
            if (mbi.Type == MEM_IMAGE && mbi.AllocationBase != 0)
            {
                if (!byBase.TryGetValue(mbi.AllocationBase, out var im))
                {
                    im = new MappedImage { Base = mbi.AllocationBase };
                    byBase[im.Base] = im;
                }
                if (next - im.Base > im.Size) im.Size = next - im.Base;
            }

            if (next <= address) break;
            address = next;
        }

        foreach (var im in byBase.Values)
        {
            string? nt = MappedFile(im.Base);
            im.Path = nt is null ? "" : DevicePaths.ToDos(nt);
            im.Name = im.Path.Length > 0 ? System.IO.Path.GetFileName(im.Path) : $"image_{im.Base:X}";
        }
        return byBase.Values.OrderBy(x => x.Base).ToList();
    }

    private string? MappedFile(ulong address)
    {
        var buf = new byte[2048];
        fixed (byte* p = buf)
        {
            nuint ret;
            if (NtQueryVirtualMemory(Handle, address, MemoryMappedFilenameInformation, p,
                    (nuint)buf.Length, &ret) != 0)
                return null;
            ushort len = *(ushort*)p;
            if (len == 0 || len > buf.Length - 16) return null;
            return new string((char*)(p + 16), 0, len / 2);
        }
    }

    public PageInfo[]? QueryPages(ulong start, int count)
    {
        var addresses = new ulong[count];
        for (int i = 0; i < count; i++) addresses[i] = start + (ulong)i * PageSize;
        return QueryPages(addresses);
    }

    public PageInfo[]? QueryPages(IReadOnlyList<ulong> addresses)
    {
        const int Batch = 8192;
        var buf = new PageInfo[addresses.Count];
        for (int i = 0; i < buf.Length; i++) buf[i].VirtualAddress = addresses[i];

        fixed (PageInfo* p = buf)
        {
            for (int done = 0; done < buf.Length; done += Batch)
            {
                int n = Math.Min(Batch, buf.Length - done);
                if (NtQueryVirtualMemory(Handle, 0, MemoryWorkingSetExInformation, p + done,
                        (nuint)(n * sizeof(PageInfo)), null) != 0)
                    return null;
            }
        }
        return buf;
    }

    public (string Text, bool ExecutableOutsideImages) Describe(ulong address,
        List<MappedImage> images)
    {
        foreach (var im in images)
            if (im.Contains(address))
                return ($"{im.Name}+0x{address - im.Base:X}", false);

        if (VirtualQueryEx(Handle, address, out var mbi,
                (nuint)sizeof(MEMORY_BASIC_INFORMATION)) == 0)
            return ("адрес вне адресного пространства", false);
        if (mbi.State == MEM_FREE) return ("свободный адрес — памяти там нет", false);

        string type = mbi.Type switch
        {
            MEM_PRIVATE => "приватная память вне образов",
            MEM_MAPPED => "проекция данных вне образов",
            _ => "память вне образов",
        };
        bool exec = mbi.State == MEM_COMMIT && (mbi.Protect & 0xF0) != 0;
        return ($"{type}, права {Protection(mbi.Protect)}, " +
                $"выделение с 0x{mbi.AllocationBase:X}", exec);
    }

    public static string Protection(uint p)
    {
        if (p == 0) return "-";
        string s = (p & 0xFF) switch
        {
            0x01 => "---",
            0x02 => "R--",
            0x04 => "RW-",
            0x08 => "RWC",
            0x10 => "--X",
            0x20 => "R-X",
            0x40 => "RWX",
            0x80 => "RWXC",
            _ => $"0x{p & 0xFF:X2}",
        };
        if ((p & 0x100) != 0) s += "+G";
        return s;
    }

    public void Dispose()
    {
        if (Handle == IntPtr.Zero) return;
        CloseHandle(Handle);
        Handle = IntPtr.Zero;
    }

    public static List<Candidate> FindJava()
    {
        var list = new List<Candidate>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                string name = p.ProcessName;
                if (!name.Equals("java", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("javaw", StringComparison.OrdinalIgnoreCase) &&
                    !name.Equals("minecraft", StringComparison.OrdinalIgnoreCase))
                    continue;

                string exe = "", cmd = "", title = "";
                DateTime start = default;
                try { title = p.MainWindowTitle; } catch { }
                try
                {
                    using var t = Open(p.Id);
                    exe = t.ImagePath;
                    cmd = t.CommandLine();
                    start = t.StartUtc;
                }
                catch { }

                bool mc = title.Contains("Minecraft", StringComparison.OrdinalIgnoreCase);
                foreach (string mark in new[] { "minecraft", "fabricmc", "cpw.mods", "forge", "lwjgl" })
                    if (cmd.Contains(mark, StringComparison.OrdinalIgnoreCase)) mc = true;

                list.Add(new Candidate(p.Id, name, title, exe, cmd, start, mc));
            }
            catch { }
            finally { p.Dispose(); }
        }
        return list;
    }
}

internal static class DevicePaths
{
    private static readonly List<(string Device, string Drive)> Map = Build();

    private static List<(string, string)> Build()
    {
        var list = new List<(string, string)>();
        var sb = new StringBuilder(1024);
        for (char c = 'A'; c <= 'Z'; c++)
        {
            sb.Clear();
            if (QueryDosDeviceW($"{c}:", sb, sb.Capacity) != 0)
                list.Add((sb.ToString() + "\\", $"{c}:\\"));
        }
        return list;
    }

    public static string ToDos(string ntPath)
    {
        foreach (var (device, drive) in Map)
            if (ntPath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
                return drive + ntPath.Substring(device.Length);
        const string Mup = @"\Device\Mup\";
        if (ntPath.StartsWith(Mup, StringComparison.OrdinalIgnoreCase))
            return @"\\" + ntPath.Substring(Mup.Length);
        return ntPath;
    }
}
