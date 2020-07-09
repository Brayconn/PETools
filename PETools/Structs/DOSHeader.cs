using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PETools
{
    [DebuggerDisplay("Magic = {new string(e_magic)}, PE Header Address = {e_lfanew}")]
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_DOS_HEADER
    {
        /// <summary>
        /// Magic number {'M','Z'}
        /// </summary>
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
        public char[] e_magic;
        /// <summary>
        /// Bytes on last page of file
        /// </summary>
        public ushort e_cblp;
        /// <summary>
        /// Pages in file
        /// </summary>
        public ushort e_cp;
        /// <summary>
        /// Relocations
        /// </summary>
        public ushort e_crlc;
        /// <summary>
        /// Size of header in paragraphs
        /// </summary>
        public ushort e_cparhdr;
        /// <summary>
        /// Minimum extra paragraphs needed
        /// </summary>
        public ushort e_minalloc;
        /// <summary>
        /// Maximum extra paragraphs needed
        /// </summary>
        public ushort e_maxalloc;
        /// <summary>
        /// Initial (relative) SS value
        /// </summary>
        public ushort e_ss;
        /// <summary>
        /// Initial SP value
        /// </summary>
        public ushort e_sp;
        /// <summary>
        /// Checksum
        /// </summary>
        public ushort e_csum;
        /// <summary>
        /// Initial IP value
        /// </summary>
        public ushort e_ip;
        /// <summary>
        /// Initial (relative) CS value
        /// </summary>
        public ushort e_cs;
        /// <summary>
        /// File address of relocation table
        /// </summary>
        public ushort e_lfarlc;
        /// <summary>
        /// Overlay number
        /// </summary>
        public ushort e_ovno;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public ushort[] reserved1;
        /// <summary>
        /// OEM identifier (for e_oeminfo)
        /// </summary>
        public ushort e_oemid;
        /// <summary>
        /// OEM information; e_oemid specific
        /// </summary>
        public ushort e_oeminfo;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
        public ushort[] reserved2;
        /// <summary>
        /// File address of new exe header
        /// </summary>
        public uint e_lfanew;
    }
}
