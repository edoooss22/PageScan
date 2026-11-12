using System.Runtime.InteropServices;
using System.Text;

namespace PageScanTarget;

internal static unsafe class Program
{
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint MEM_COMMIT_RESERVE = 0x3000;
    private const uint DONT_RESOLVE_DLL_REFERENCES = 0x1;

    [StructLayout(LayoutKind.Sequential)]
    private struct PageInfo
    {
        public ulong Address;
        public ulong Attributes;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr LoadLibraryExW(string name, IntPtr file, uint flags);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    private static extern IntPtr GetProcAddress(IntPtr module, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualProtect(byte* address, nuint size, uint protect, out uint old);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern byte* VirtualAlloc(byte* address, nuint size, uint type, uint protect);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool FlushInstructionCache(IntPtr process, byte* address, nuint size);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool EmptyWorkingSet(IntPtr process);

    [DllImport("psapi.dll", SetLastError = true)]
    private static extern bool QueryWorkingSetEx(IntPtr process, PageInfo* info, uint size);

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        int seconds = args.Length > 0 && int.TryParse(args[0], out int s) ? s : 600;

        byte* stub = VirtualAlloc(null, 0x1000, MEM_COMMIT_RESERVE, PAGE_EXECUTE_READWRITE);
        stub[0] = 0xC3;

        byte* beep = Export("kernel32.dll", "Beep");
        Line("restored", "kernel32.dll", beep, Attr(beep));
        WriteAndRestore(beep);
        Line("restored-after", "kernel32.dll", beep, Attr(beep));

        byte* sleepEx = Export("kernel32.dll", "SleepEx");
        byte* control = (byte*)(((ulong)sleepEx + 0x3000) & ~0xFFFUL);
        byte probe = *control;
        VirtualProtect(control, 1, PAGE_EXECUTE_READWRITE, out uint keep);
        VirtualProtect(control, 1, keep, out _);
        Line("control-protect-only", "kernel32.dll", control, Attr(control));

        byte* evicted = Export("version.dll", "GetFileVersionInfoSizeW");
        WriteAndRestore(evicted);
        Line("evicted-before-trim", "version.dll", evicted, Attr(evicted));

        byte* hooked = Export("dbghelp.dll", "SymCleanup");
        Patch(hooked, Jump(hooked, stub));
        Line("hook-at-start", "dbghelp.dll", hooked, Attr(hooked));

        byte* middle = Export("dbghelp.dll", "SymSetOptions") + 0x1000 + 0x123;
        Patch(middle, new byte[] { 0xEB, 0xFE });
        Line("patch-in-middle", "dbghelp.dll", middle, Attr(middle));

        byte* big = Image("msxml6.dll");
        byte* text = Section(big, ".text", out uint textSize);
        byte* rdata = Section(big, ".rdata", out _);

        byte* replaced = text + 0x20000;
        var noise = new byte[8 * 0x1000];
        new Random(7).NextBytes(noise);
        Patch(replaced, noise);
        Line("replaced-run", "msxml6.dll", replaced, Attr(replaced));

        byte* rewritten = text + 0x40000;
        for (int i = 0; i < 6; i++)
        {
            var chunk = new byte[40];
            new Random(i + 11).NextBytes(chunk);
            Patch(rewritten + i * 0x200, chunk);
        }
        Line("rewritten", "msxml6.dll", rewritten, Attr(rewritten));

        byte* slot = rdata + 0x8000 + 0x40;
        Patch(slot, BitConverter.GetBytes((ulong)stub));
        Line("data-pointer", "msxml6.dll", slot, Attr(slot));

        byte* erased = Image("msftedit.dll");
        Patch(erased, new byte[0x200]);
        Line("header-erased", "msftedit.dll", erased, Attr(erased));

        byte* touched = Image("riched20.dll");
        WriteAndRestore(touched + 0x40);
        Line("header-restored", "riched20.dll", touched, Attr(touched));

        byte* idle = text + 0x80000;
        probe ^= *idle;
        Line("control-read-only", "msxml6.dll", idle, Attr(idle));

        byte* never = text + textSize - 0x3000;
        Line("control-never-touched", "msxml6.dll", never, Attr(never));

        EmptyWorkingSet(GetCurrentProcess());
        Thread.Sleep(300);
        Line("evicted-after-trim", "version.dll", evicted, Attr(evicted));
        Line("control-read-only-after-trim", "msxml6.dll", idle, Attr(idle));
        Line("replaced-after-trim", "msxml6.dll", replaced, Attr(replaced));

        Console.WriteLine($"READY {Environment.ProcessId} {probe}");
        Console.Out.Flush();
        Thread.Sleep(seconds * 1000);
        System.Diagnostics.Process.GetCurrentProcess().Kill();
        return 0;
    }

    private static void Line(string what, string module, byte* address, ulong attributes) =>
        Console.WriteLine(
            $"{what,-30} {module,-13} 0x{(ulong)address:X}  attr=0x{attributes:X8}  " +
            $"valid={attributes & 1} shared={(attributes >> 15) & 1} " +
            $"count={(attributes >> 1) & 7} location={(attributes >> 22) & 3} " +
            $"original={(attributes >> 30) & 1}");

    private static ulong Attr(byte* address)
    {
        var info = new PageInfo { Address = (ulong)address & ~0xFFFUL };
        return QueryWorkingSetEx(GetCurrentProcess(), &info, (uint)sizeof(PageInfo))
            ? info.Attributes
            : ulong.MaxValue;
    }

    private static byte* Image(string name)
    {
        IntPtr h = LoadLibraryExW(name, IntPtr.Zero, DONT_RESOLVE_DLL_REFERENCES);
        if (h == IntPtr.Zero) throw new InvalidOperationException("не загружен " + name);
        return (byte*)h;
    }

    private static byte* Export(string module, string name)
    {
        IntPtr h = LoadLibraryExW(module, IntPtr.Zero, 0);
        IntPtr p = h == IntPtr.Zero ? IntPtr.Zero : GetProcAddress(h, name);
        if (p == IntPtr.Zero) throw new InvalidOperationException($"нет {module}!{name}");
        return (byte*)p;
    }

    private static byte* Section(byte* image, string name, out uint size)
    {
        byte* nt = image + *(uint*)(image + 0x3C);
        int count = *(ushort*)(nt + 6);
        byte* table = nt + 0x18 + *(ushort*)(nt + 0x14);
        for (int i = 0; i < count; i++)
        {
            byte* s = table + i * 40;
            string n = Encoding.ASCII.GetString(new ReadOnlySpan<byte>(s, 8)).TrimEnd('\0');
            if (n != name) continue;
            size = *(uint*)(s + 8);
            return image + *(uint*)(s + 12);
        }
        throw new InvalidOperationException("нет секции " + name);
    }

    private static byte[] Jump(byte* from, byte* to)
    {
        var code = new byte[12];
        code[0] = 0x48;
        code[1] = 0xB8;
        BitConverter.GetBytes((ulong)to).CopyTo(code, 2);
        code[10] = 0xFF;
        code[11] = 0xE0;
        return code;
    }

    private static void Patch(byte* address, byte[] bytes)
    {
        if (!VirtualProtect(address, (nuint)bytes.Length, PAGE_EXECUTE_READWRITE, out uint old))
            throw new InvalidOperationException("права не меняются");
        for (int i = 0; i < bytes.Length; i++) address[i] = bytes[i];
        VirtualProtect(address, (nuint)bytes.Length, old, out _);
        FlushInstructionCache(GetCurrentProcess(), address, (nuint)bytes.Length);
    }

    private static void WriteAndRestore(byte* address)
    {
        VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, out uint old);
        byte original = *address;
        *address = 0xCC;
        *address = original;
        VirtualProtect(address, 1, old, out _);
        FlushInstructionCache(GetCurrentProcess(), address, 1);
    }
}
