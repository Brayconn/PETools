using System.Runtime.InteropServices;

namespace PETools
{
    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IMAGE_RELOCATION
    {
        [FieldOffset(0)] public uint VirtualAddress;
        [FieldOffset(4)] public uint SymbolTableIndex;
        [FieldOffset(8)] public IMAGE_REL_AMD64 AMD64_Type;
        //TODO implement all these comments as more enums...
        //ARM
        //ARM64
        //SH3
        //PPC
        [FieldOffset(8)] public IMAGE_REL_I386 I386_Type;
        //IA64
        //MIPS
        //M32R
    }

#pragma warning disable CA1712 // Do not prefix enum values with type name
    public enum IMAGE_REL_AMD64 : ushort
    { 
        IMAGE_REL_AMD64_ABSOLUTE       = 0x0000,
        IMAGE_REL_AMD64_ADDR64         = 0x0001,
        IMAGE_REL_AMD64_ADDR32         = 0x0002,
        IMAGE_REL_AMD64_ADDR32NB       = 0x0003,
        IMAGE_REL_AMD64_REL32          = 0x0004,
        IMAGE_REL_AMD64_REL32_1        = 0x0005,
        IMAGE_REL_AMD64_REL32_2        = 0x0006,
        IMAGE_REL_AMD64_REL32_3        = 0x0007,
        IMAGE_REL_AMD64_REL32_4        = 0x0008,
        IMAGE_REL_AMD64_REL32_5        = 0x0009,
        IMAGE_REL_AMD64_SECTION        = 0x000A,
        IMAGE_REL_AMD64_SECREL         = 0x000B,
        IMAGE_REL_AMD64_SECREL7        = 0x000C,
        IMAGE_REL_AMD64_TOKEN          = 0x000D,
        IMAGE_REL_AMD64_SREL32         = 0x000E,
        IMAGE_REL_AMD64_PAIR           = 0x000F,
        IMAGE_REL_AMD64_SSPAN32        = 0x0010,
    }

    public enum IMAGE_REL_I386 : ushort
    {
        IMAGE_REL_I386_ABSOLUTE = 0x0000,
        IMAGE_REL_I386_DIR16 = 0x0001,
        IMAGE_REL_I386_REL16 = 0x0002,
        IMAGE_REL_I386_DIR32 = 0x0006,
        IMAGE_REL_I386_DIR32NB = 0x0007,
        IMAGE_REL_I386_SEG12 = 0x0009,
        IMAGE_REL_I386_SECTION = 0x000A,
        IMAGE_REL_I386_SECREL = 0x000B,
        IMAGE_REL_I386_TOKEN = 0x000C,
        IMAGE_REL_I386_SECREL7 = 0x000D,
        IMAGE_REL_I386_REL32 = 0x0014,
    }
#pragma warning restore CA1712
}
