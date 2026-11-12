using System.Runtime.InteropServices;
using System.Text;

namespace PageScan;

internal static unsafe class Native
{
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_FREE = 0x10000;
    public const uint MEM_IMAGE = 0x1000000;
    public const uint MEM_MAPPED = 0x40000;
    public const uint MEM_PRIVATE = 0x20000;

    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    public const int MemoryMappedFilenameInformation = 2;
    public const int MemoryWorkingSetExInformation = 4;
    public const int ProcessCommandLineInformation = 60;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public ulong BaseAddress;
        public ulong AllocationBase;
        public uint AllocationProtect;
        private readonly uint _pad1;
        public ulong RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
        private readonly uint _pad2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PageInfo
    {
        public ulong VirtualAddress;
        public ulong Attributes;

        public bool Valid => (Attributes & 1) != 0;
        public int ShareCount => (int)((Attributes >> 1) & 0x7);
        public uint Protection => (uint)((Attributes >> 4) & 0x7FF);
        public bool Shared => ((Attributes >> 15) & 1) != 0;
        public bool SharedOriginal => ((Attributes >> 30) & 1) != 0;
        public bool Bad => ((Attributes >> 31) & 1) != 0;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID { public uint Low; public int High; }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool CloseHandle(IntPtr h);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool ReadProcessMemory(IntPtr process, ulong address, byte* buffer,
        nuint size, out nuint read);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern nuint VirtualQueryEx(IntPtr process, ulong address,
        out MEMORY_BASIC_INFORMATION mbi, nuint length);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool QueryFullProcessImageNameW(IntPtr process, uint flags, char* name,
        ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetProcessTimes(IntPtr process, out long creation, out long exit,
        out long kernel, out long user);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern int QueryDosDeviceW(string device, StringBuilder buffer, int size);

    [DllImport("kernel32.dll")]
    public static extern uint GetConsoleProcessList(uint* list, uint count);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryVirtualMemory(IntPtr process, ulong address, int infoClass,
        void* buffer, nuint length, nuint* returned);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(IntPtr process, int infoClass,
        void* buffer, uint length, uint* returned);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool OpenProcessToken(IntPtr process, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool LookupPrivilegeValueW(string? system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
        ref TOKEN_PRIVILEGES state, uint length, IntPtr previous, IntPtr returned);

    public static bool EnableDebugPrivilege()
    {
        if (!OpenProcessToken(GetCurrentProcess(), 0x0020 | 0x0008, out var token)) return false;
        try
        {
            if (!LookupPrivilegeValueW(null, "SeDebugPrivilege", out var luid)) return false;
            var tp = new TOKEN_PRIVILEGES { PrivilegeCount = 1, Luid = luid, Attributes = 2 };
            if (!AdjustTokenPrivileges(token, false, ref tp, (uint)sizeof(TOKEN_PRIVILEGES),
                    IntPtr.Zero, IntPtr.Zero))
                return false;
            return Marshal.GetLastWin32Error() == 0;
        }
        finally { CloseHandle(token); }
    }
}
