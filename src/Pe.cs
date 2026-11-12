using System.Buffers.Binary;
using System.Text;

namespace PageScan;

internal sealed class Section
{
    public string Name = "";
    public uint Rva;
    public uint VirtualSize;
    public uint RawPointer;
    public uint RawSize;
    public uint Flags;

    public bool IsCode => (Flags & 0x20000020) != 0;
    public bool IsWritable => (Flags & 0x80000000) != 0;
    public bool IsDiscardable => (Flags & 0x02000000) != 0;
}

internal sealed class PeHeader
{
    public ushort Machine;
    public bool Is64;
    public ulong ImageBase;
    public uint ImageBaseOffset;
    public uint SizeOfImage;
    public uint SizeOfHeaders;
    public uint TimeDateStamp;
    public uint CheckSum;
    public uint[] DirRva = new uint[16];
    public uint[] DirSize = new uint[16];
    public List<Section> Sections { get; } = new();

    public int PointerSize => Is64 ? 8 : 4;

    public static PeHeader? Parse(ReadOnlySpan<byte> d)
    {
        if (d.Length < 0x40 || d[0] != 'M' || d[1] != 'Z') return null;
        uint nt = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(0x3C));
        if (nt == 0 || nt > 0x10000 || nt + 0x18 + 0x70 > d.Length) return null;
        if (d[(int)nt] != 'P' || d[(int)nt + 1] != 'E' || d[(int)nt + 2] != 0 || d[(int)nt + 3] != 0)
            return null;

        var h = new PeHeader
        {
            Machine = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice((int)nt + 4)),
            TimeDateStamp = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice((int)nt + 8)),
        };
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice((int)nt + 6));
        int optSize = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice((int)nt + 0x14));
        int opt = (int)nt + 0x18;
        if (opt + optSize > d.Length) return null;

        ushort magic = BinaryPrimitives.ReadUInt16LittleEndian(d.Slice(opt));
        if (magic != 0x20B && magic != 0x10B) return null;
        h.Is64 = magic == 0x20B;
        h.ImageBaseOffset = (uint)(opt + (h.Is64 ? 0x18 : 0x1C));
        h.ImageBase = h.Is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(d.Slice(opt + 0x18))
            : BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(opt + 0x1C));
        h.SizeOfImage = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(opt + 0x38));
        h.SizeOfHeaders = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(opt + 0x3C));
        h.CheckSum = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(opt + 0x40));

        int dirs = opt + (h.Is64 ? 0x70 : 0x60);
        for (int i = 0; i < 16; i++)
        {
            int o = dirs + i * 8;
            if (o + 8 > opt + optSize || o + 8 > d.Length) break;
            h.DirRva[i] = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(o));
            h.DirSize[i] = BinaryPrimitives.ReadUInt32LittleEndian(d.Slice(o + 4));
        }

        int table = opt + optSize;
        for (int i = 0; i < Math.Min(sections, 96); i++)
        {
            int o = table + i * 40;
            if (o + 40 > d.Length) break;
            var s = d.Slice(o, 40);
            h.Sections.Add(new Section
            {
                Name = Encoding.ASCII.GetString(s.Slice(0, 8)).TrimEnd('\0'),
                VirtualSize = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(8)),
                Rva = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(12)),
                RawSize = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(16)),
                RawPointer = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(20)),
                Flags = BinaryPrimitives.ReadUInt32LittleEndian(s.Slice(36)),
            });
        }
        return h;
    }
}

internal sealed class PeFile
{
    private const int PageSize = 0x1000;

    private static readonly int[] GuardPointerOffsets =
        { 0x70, 0x78, 0xD8, 0xE8, 0x118, 0x120, 0x128, 0x130, 0x138 };

    public PeHeader Header { get; }
    private readonly byte[] _raw;
    private uint[] _relocRva = Array.Empty<uint>();
    private byte[] _relocSize = Array.Empty<byte>();
    private uint[] _functions = Array.Empty<uint>();
    private (uint Rva, string Name)[] _exports = Array.Empty<(uint, string)>();
    private readonly List<(uint Rva, uint Raw, uint Size)> _extents = new();

    public List<(uint Rva, uint Size, string Why)> LoaderWritten { get; } = new();
    public int RelocCount => _relocRva.Length;

    private PeFile(PeHeader header, byte[] raw)
    {
        Header = header;
        _raw = raw;
        BuildExtents();
    }

    public static PeFile? Load(string path, out string error)
    {
        error = "";
        byte[] raw;
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) { error = "файла на диске нет"; return null; }
            if (fi.Length > 768L * 1024 * 1024) { error = "файл слишком велик"; return null; }
            raw = File.ReadAllBytes(path);
        }
        catch (Exception ex)
        {
            error = "файл не читается: " + ex.Message;
            return null;
        }

        var header = PeHeader.Parse(raw);
        if (header is null) { error = "файл на диске не является образом PE"; return null; }

        var pe = new PeFile(header, raw);
        try
        {
            pe.ParseRelocs();
            pe.ParseFunctions();
            pe.ParseExports();
            pe.ParseLoaderWritten();
        }
        catch (Exception ex)
        {
            error = "таблицы файла повреждены: " + ex.Message;
        }
        return pe;
    }

    private void BuildExtents()
    {
        var sections = Header.Sections.OrderBy(s => s.Rva).ToList();
        uint firstRva = sections.Count > 0 ? sections[0].Rva : uint.MaxValue;
        _extents.Add((0, 0, Math.Min(Header.SizeOfHeaders, firstRva)));
        for (int i = 0; i < sections.Count; i++)
        {
            var s = sections[i];
            uint limit = i + 1 < sections.Count ? sections[i + 1].Rva - s.Rva : uint.MaxValue;
            _extents.Add((s.Rva, s.RawPointer, Math.Min(s.RawSize, limit)));
        }
    }

    private long Offset(uint rva)
    {
        for (int i = _extents.Count - 1; i >= 0; i--)
        {
            var (start, raw, size) = _extents[i];
            if (rva < start) continue;
            return rva - start < size ? (long)raw + (rva - start) : -1;
        }
        return -1;
    }

    public void ReadImage(uint rva, Span<byte> dest)
    {
        dest.Clear();
        foreach (var (start, raw, size) in _extents)
        {
            long from = Math.Max((long)start, rva);
            long to = Math.Min((long)start + size, (long)rva + dest.Length);
            if (to <= from) continue;
            long off = raw + (from - start);
            if (off >= _raw.Length) continue;
            int n = (int)Math.Min(to - from, _raw.Length - off);
            _raw.AsSpan((int)off, n).CopyTo(dest.Slice((int)(from - rva)));
        }
    }

    private bool TryRead(uint rva, Span<byte> dest)
    {
        long off = Offset(rva);
        if (off < 0 || off + dest.Length > _raw.Length) return false;
        if (dest.Length > 1 && Offset(rva + (uint)dest.Length - 1) != off + dest.Length - 1)
            return false;
        _raw.AsSpan((int)off, dest.Length).CopyTo(dest);
        return true;
    }

    private uint U32(uint rva)
    {
        Span<byte> b = stackalloc byte[4];
        return TryRead(rva, b) ? BinaryPrimitives.ReadUInt32LittleEndian(b) : 0;
    }

    private ulong Pointer(uint rva)
    {
        Span<byte> b = stackalloc byte[8];
        b.Clear();
        return TryRead(rva, b.Slice(0, Header.PointerSize))
            ? BinaryPrimitives.ReadUInt64LittleEndian(b)
            : 0;
    }

    private string CString(uint rva, int max = 256)
    {
        long off = Offset(rva);
        if (rva == 0 || off < 0) return "";
        int end = (int)off;
        while (end < _raw.Length && end - off < max && _raw[end] != 0) end++;
        return Encoding.ASCII.GetString(_raw, (int)off, end - (int)off);
    }

    private void ParseRelocs()
    {
        uint rva = Header.DirRva[5], size = Header.DirSize[5];
        if (rva == 0 || size < 8 || size > 64 * 1024 * 1024) return;
        var blob = new byte[size];
        ReadImage(rva, blob);

        var rvas = new List<uint>();
        var sizes = new List<byte>();
        int off = 0;
        while (off + 8 <= blob.Length)
        {
            uint page = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(off));
            uint block = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(off + 4));
            if (block < 8 || off + block > blob.Length) break;
            for (int i = off + 8; i + 2 <= off + block; i += 2)
            {
                ushort e = BinaryPrimitives.ReadUInt16LittleEndian(blob.AsSpan(i));
                int type = e >> 12;
                if (type == 10) { rvas.Add(page + (uint)(e & 0xFFF)); sizes.Add(8); }
                else if (type == 3) { rvas.Add(page + (uint)(e & 0xFFF)); sizes.Add(4); }
            }
            off += (int)block;
        }

        _relocRva = rvas.ToArray();
        _relocSize = sizes.ToArray();
        Array.Sort(_relocRva, _relocSize);
    }

    private void ParseFunctions()
    {
        if (Header.Machine != 0x8664) return;
        uint rva = Header.DirRva[3], size = Header.DirSize[3];
        if (rva == 0 || size < 12 || size > 64 * 1024 * 1024) return;
        var blob = new byte[size];
        ReadImage(rva, blob);

        var starts = new List<uint>((int)(size / 12));
        for (int i = 0; i + 12 <= blob.Length; i += 12)
        {
            uint begin = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i));
            uint end = BinaryPrimitives.ReadUInt32LittleEndian(blob.AsSpan(i + 4));
            if (begin != 0 && end > begin) starts.Add(begin);
        }
        starts.Sort();
        _functions = starts.ToArray();
    }

    private void ParseExports()
    {
        uint dir = Header.DirRva[0], dirSize = Header.DirSize[0];
        if (dir == 0 || dirSize < 40) return;
        uint functions = U32(dir + 20), names = U32(dir + 24);
        uint functionsRva = U32(dir + 28), namesRva = U32(dir + 32), ordinalsRva = U32(dir + 36);
        uint ordinalBase = U32(dir + 16);
        if (functions == 0 || functions > 200000 || functionsRva == 0) return;

        var name = new string?[functions];
        if (names > 0 && names <= 200000 && namesRva != 0 && ordinalsRva != 0)
        {
            Span<byte> ord = stackalloc byte[2];
            for (uint i = 0; i < names; i++)
            {
                if (!TryRead(ordinalsRva + i * 2, ord)) break;
                ushort index = BinaryPrimitives.ReadUInt16LittleEndian(ord);
                if (index < functions) name[index] = CString(U32(namesRva + i * 4));
            }
        }

        var list = new List<(uint, string)>();
        for (uint i = 0; i < functions; i++)
        {
            uint rva = U32(functionsRva + i * 4);
            if (rva == 0 || (rva >= dir && rva < dir + dirSize)) continue;
            list.Add((rva, string.IsNullOrEmpty(name[i]) ? $"#{ordinalBase + i}" : name[i]!));
        }
        list.Sort((a, b) => a.Item1.CompareTo(b.Item1));
        _exports = list.ToArray();
    }

    private void ParseLoaderWritten()
    {
        uint ptr = (uint)Header.PointerSize;

        if (Header.DirRva[12] != 0 && Header.DirSize[12] != 0)
            LoaderWritten.Add((Header.DirRva[12], Header.DirSize[12], "таблица адресов импорта"));

        uint imports = Header.DirRva[1];
        for (uint i = 0; imports != 0 && i < 4096; i++)
        {
            uint d = imports + i * 20;
            uint lookup = U32(d), nameRva = U32(d + 12), thunks = U32(d + 16);
            if (lookup == 0 && nameRva == 0 && thunks == 0) break;
            if (thunks == 0) continue;
            uint count = CountThunks(lookup != 0 ? lookup : thunks);
            LoaderWritten.Add((thunks, (count + 1) * ptr, "таблица адресов импорта"));
        }

        uint delay = Header.DirRva[13];
        for (uint i = 0; delay != 0 && i < 4096; i++)
        {
            uint d = delay + i * 32;
            uint attrs = U32(d), nameRva = U32(d + 4), module = U32(d + 8), iat = U32(d + 12);
            if (nameRva == 0 && iat == 0) break;
            if ((attrs & 1) == 0)
            {
                if (Header.Is64) break;
                module = Rebase(module);
                iat = Rebase(iat);
            }
            if (module != 0) LoaderWritten.Add((module, ptr, "отложенный импорт"));
            if (iat != 0)
                LoaderWritten.Add((iat, (CountThunks(iat) + 1) * ptr, "отложенный импорт"));
        }

        uint config = Header.DirRva[10];
        if (config != 0 && Header.Is64)
        {
            uint size = U32(config);
            foreach (int off in GuardPointerOffsets)
            {
                if (off + 8 > size) break;
                ulong va = Pointer(config + (uint)off);
                if (va <= Header.ImageBase || va - Header.ImageBase >= Header.SizeOfImage) continue;
                LoaderWritten.Add(((uint)(va - Header.ImageBase), 8, "указатель проверки вызовов (CFG)"));
            }
        }
    }

    private uint Rebase(uint va) =>
        va > Header.ImageBase && va - Header.ImageBase < Header.SizeOfImage
            ? (uint)(va - Header.ImageBase)
            : 0;

    private uint CountThunks(uint rva)
    {
        uint ptr = (uint)Header.PointerSize;
        uint n = 0;
        while (n < 65536 && Pointer(rva + n * ptr) != 0) n++;
        return n;
    }

    public void ExpectedPage(uint pageRva, long delta, Span<byte> dest)
    {
        ReadImage(pageRva, dest);
        if (delta == 0 || _relocRva.Length == 0) return;

        int i = Array.BinarySearch(_relocRva, pageRva >= 7 ? pageRva - 7 : 0);
        if (i < 0) i = ~i;
        while (i > 0 && _relocRva[i - 1] + 8 > pageRva) i--;

        Span<byte> value = stackalloc byte[8];
        for (; i < _relocRva.Length && _relocRva[i] < pageRva + PageSize; i++)
        {
            uint r = _relocRva[i];
            int size = _relocSize[i];
            if (r + size <= pageRva) continue;

            ReadImage(r, value.Slice(0, size));
            if (size == 8)
                BinaryPrimitives.WriteUInt64LittleEndian(value,
                    (ulong)((long)BinaryPrimitives.ReadUInt64LittleEndian(value) + delta));
            else
                BinaryPrimitives.WriteUInt32LittleEndian(value,
                    (uint)(BinaryPrimitives.ReadUInt32LittleEndian(value) + delta));

            for (int k = 0; k < size; k++)
            {
                long at = (long)r + k - pageRva;
                if (at >= 0 && at < dest.Length) dest[(int)at] = value[k];
            }
        }
    }

    public bool HasRelocs(uint pageRva)
    {
        int i = Array.BinarySearch(_relocRva, pageRva);
        if (i >= 0) return true;
        i = ~i;
        return i < _relocRva.Length && _relocRva[i] < pageRva + PageSize;
    }

    public int FunctionStartIn(uint fromRva, uint toRva)
    {
        int i = Array.BinarySearch(_functions, fromRva);
        if (i < 0) i = ~i;
        if (i < _functions.Length && _functions[i] < toRva) return (int)_functions[i];

        int e = LowerBound(fromRva);
        if (e < _exports.Length && _exports[e].Rva < toRva) return (int)_exports[e].Rva;
        return -1;
    }

    public int FunctionsOnPage(uint pageRva)
    {
        int lo = Array.BinarySearch(_functions, pageRva);
        if (lo < 0) lo = ~lo;
        int hi = Array.BinarySearch(_functions, pageRva + PageSize);
        if (hi < 0) hi = ~hi;
        return Math.Max(0, hi - lo);
    }

    private int LowerBound(uint rva)
    {
        int lo = 0, hi = _exports.Length;
        while (lo < hi)
        {
            int mid = (lo + hi) / 2;
            if (_exports[mid].Rva < rva) lo = mid + 1; else hi = mid;
        }
        return lo;
    }

    public string ExportsOnPage(uint pageRva)
    {
        var names = new List<string>();
        int total = 0;
        for (int i = LowerBound(pageRva);
             i < _exports.Length && _exports[i].Rva < pageRva + PageSize; i++)
            if (++total <= 6) names.Add(_exports[i].Name);
        return string.Join(", ", names) + (total > 6 ? $" и ещё {total - 6}" : "");
    }

    public string Nearest(uint rva)
    {
        int i = LowerBound(rva + 1) - 1;
        if (i < 0) return "";
        uint delta = rva - _exports[i].Rva;
        if (delta > 0x20000) return "";
        return delta == 0 ? _exports[i].Name : $"{_exports[i].Name}+0x{delta:X}";
    }
}
