using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace PETools.Structs
{
    [DebuggerDisplay("Name Entries = {NumberOfNameEntries} ID Entries = {NumberOfIDEntries}")]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_RESOURCE_DIRECTORY
    {
        public uint Characteristics;
        public uint TimeDateStamp;
        public ushort MajorVersion;
        public ushort MinorVersion;
        public ushort NumberOfNameEntries;
        public ushort NumberOfIDEntries;
    }

    [DebuggerDisplay("Type = {IsString ? \"String\" : \"ID\"} String Offset = {StringOffset} Data/Subdirectory Offset = {DataOffset}")]
    [StructLayout(LayoutKind.Explicit, Pack = 1)]
    public struct IMAGE_RESOURCE_DIRECTORY_ENTRY
    {
        const uint HighBit = 0x80000000;

        [FieldOffset(0)] public uint NameOffset;
        [FieldOffset(0)] public uint IntegerID;
        public bool IsID => (IntegerID & HighBit) == 0;
        public bool IsString => (NameOffset & HighBit) != 0;
        public uint StringOffset => NameOffset & ~HighBit;


        [FieldOffset(4)] public uint DataEntryOffset;
        [FieldOffset(4)] public uint SubdirectoryOffset;
        public bool IsLeaf => (DataEntryOffset & HighBit) == 0;
        public bool IsTable => (SubdirectoryOffset & HighBit) != 0;
        public uint DataOffset => IsTable ? SubdirectoryOffset & ~HighBit : DataEntryOffset;
    }

    [DebuggerDisplay("Text = {UnicodeString}")]
    //TODO despite all my attempts, there doesn't appear to be any way to have this struct be marshaled correctly
    //as a result, I've had to do it all manually...
    //[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 2)] //Pack = 2 because this one is WORD aligned
    [StructLayout(LayoutKind.Auto)] //using this to force errors if I ever try to use this with the normal functions
    public struct IMAGE_RESOURCE_DIR_STRING_U
    {
        public ushort Length;
        //[MarshalAs(UnmanagedType.ByValTStr, SizeParamIndex = 0)]
        public string UnicodeString;

#if USE_SIZE
        internal long Size => sizeof(ushort) + (Length * 2); //Encoding.Unicode.GetBytes(UnicodeString).Length;
#endif
        public static IMAGE_RESOURCE_DIR_STRING_U FromStream(BinaryReader br)
        {
            
            var len = br.ReadUInt16();
            var str = Encoding.Unicode.GetString(br.ReadBytes(len * 2));
            return new IMAGE_RESOURCE_DIR_STRING_U()
            {
                Length = len,
                UnicodeString = str
            };
        }

        public byte[] ToArray()
        {
            return BitConverter.GetBytes(Length).Concat(Encoding.Unicode.GetBytes(UnicodeString)).ToArray();
        }
    }

    [DebuggerDisplay("RVA = {DataRVA} Size = {Size}")]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    struct IMAGE_RESOURCE_DATA_ENTRY
    {
        public uint DataRVA;
        public uint Size;
        public uint Codepage;
        public uint Reserved;
    }
}
