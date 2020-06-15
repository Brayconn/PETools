using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PETools
{
    [DebuggerDisplay("Name = {new string(Name)}")]
    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IMAGE_SYMBOL
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        [FieldOffset(0)] public byte[] Name;
        [FieldOffset(0)] public uint Zeros;
        [FieldOffset(4)] public uint Offset;
        [FieldOffset(8)] public uint Value;
        [FieldOffset(12)] public IMAGE_SECTION_NUMBER SectionNumber;
        [FieldOffset(14)] public IMAGE_SYMBOL_TYPE Type;
        [FieldOffset(16)] public IMAGE_SYMBOL_CLASS StorageClass;
        [FieldOffset(17)] public byte NumberOfAuxSymbols;
    }

    public enum IMAGE_SECTION_NUMBER : short
    {
        IMAGE_SYM_UNDEFINED = 0,
        IMAGE_SYM_ABSOLUTE = -1,
        IMAGE_SYM_DEBUG = -2,
    }

    public enum IMAGE_SYMBOL_TYPE : ushort
    {
        IMAGE_SYM_TYPE_NULL = 0x0000,
        IMAGE_SYM_TYPE_VOID = 0x0001,
        IMAGE_SYM_TYPE_CHAR = 0x0002,
        IMAGE_SYM_TYPE_SHORT = 0x0003,
        IMAGE_SYM_TYPE_INT = 0x0004,
        IMAGE_SYM_TYPE_LONG = 0x0005,
        IMAGE_SYM_TYPE_FLOAT = 0x0006,
        IMAGE_SYM_TYPE_DOUBLE = 0x0007,
        IMAGE_SYM_TYPE_STRUCT = 0x0008,
        IMAGE_SYM_TYPE_UNION = 0x0009,
        IMAGE_SYM_TYPE_ENUM = 0x000A,
        IMAGE_SYM_TYPE_MOE = 0x000B,
        IMAGE_SYM_TYPE_BYTE = 0x000C,
        IMAGE_SYM_TYPE_WORD = 0x000D,
        IMAGE_SYM_TYPE_UINT = 0x000E,
        IMAGE_SYM_TYPE_DWORD = 0x000F,
        // Special Microsoft flag
        IMAGE_SYM_TYPE_MSFT_FN = 0x0020,
        IMAGE_SYM_TYPE_PCODE = 0x8000,
    }

#pragma warning disable CA1712 // Do not prefix enum values with type name
    public enum IMAGE_SYMBOL_CLASS : byte
    {
        IMAGE_SYM_CLASS_END_OF_FUNCTION = 0xFF, //A special symbol that represents the end of function, for debugging purposes.
        IMAGE_SYM_CLASS_NULL = 0, //No assigned storage class.
        IMAGE_SYM_CLASS_AUTOMATIC = 1, //The automatic (stack) variable. The Value field specifies the stack frame offset.
        IMAGE_SYM_CLASS_EXTERNAL = 2, //A value that Microsoft tools use for external symbols. The Value field indicates the size if the section number is IMAGE_SYM_UNDEFINED (0). If the section number is not zero, then the Value field specifies the offset within the section.
        IMAGE_SYM_CLASS_STATIC = 3, //The offset of the symbol within the section. If the Value field is zero, then the symbol represents a section name.
        IMAGE_SYM_CLASS_REGISTER = 4, //A register variable. The Value field specifies the register number.
        IMAGE_SYM_CLASS_EXTERNAL_DEF = 5, //A symbol that is defined externally.
        IMAGE_SYM_CLASS_LABEL = 6, //A code label that is defined within the module. The Value field specifies the offset of the symbol within the section.
        IMAGE_SYM_CLASS_UNDEFINED_LABEL = 7, //A reference to a code label that is not defined.
        IMAGE_SYM_CLASS_MEMBER_OF_STRUCT = 8, //The structure member. The Value field specifies the n th member.
        IMAGE_SYM_CLASS_ARGUMENT = 9, //A formal argument (parameter) of a function. The Value field specifies the n th argument.
        IMAGE_SYM_CLASS_STRUCT_TAG = 10, //The structure tag-name entry.
        IMAGE_SYM_CLASS_MEMBER_OF_UNION = 11, //A union member. The Value field specifies the n th member.
        IMAGE_SYM_CLASS_UNION_TAG = 12, //The Union tag-name entry.
        IMAGE_SYM_CLASS_TYPE_DEFINITION = 13, //A Typedef entry.
        IMAGE_SYM_CLASS_UNDEFINED_STATIC = 14, //A static data declaration.
        IMAGE_SYM_CLASS_ENUM_TAG = 15, //An enumerated type tagname entry.
        IMAGE_SYM_CLASS_MEMBER_OF_ENUM = 16, //A member of an enumeration. The Value field specifies the n th member.
        IMAGE_SYM_CLASS_REGISTER_PARAM = 17, //A register parameter.
        IMAGE_SYM_CLASS_BIT_FIELD = 18, //A bit-field reference. The Value field specifies the n th bit in the bit field.
        IMAGE_SYM_CLASS_BLOCK = 100, //A .bb (beginning of block) or .eb (end of block) record. The Value field is the relocatable address of the code location.
        IMAGE_SYM_CLASS_FUNCTION = 101, //A value that Microsoft tools use for symbol records that define the extent of a function: begin function (.bf ), end function ( .ef ), and lines in function ( .lf ). For .lf records, the Value field gives the number of source lines in the function. For .ef records, the Value field gives the size of the function code.
        IMAGE_SYM_CLASS_END_OF_STRUCT = 102, //An end-of-structure entry.
        IMAGE_SYM_CLASS_FILE = 103, //A value that Microsoft tools, as well as traditional COFF format, use for the source-file symbol record. The symbol is followed by auxiliary records that name the file.
        IMAGE_SYM_CLASS_SECTION = 104, //A definition of a section (Microsoft tools use STATIC storage class instead).
        IMAGE_SYM_CLASS_WEAK_EXTERNAL = 105, //A weak external. For more information, see Auxiliary Format 3: Weak Externals.
        IMAGE_SYM_CLASS_CLR_TOKEN = 107, //A CLR token symbol. The name is an ASCII string that consists of the hexadecimal value of the token. For more information, see CLR Token Definition (Object Only). 
    }
#pragma warning restore CA1712 // Do not prefix enum values with type name
}
