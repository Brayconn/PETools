using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PETools
{
    [DebuggerDisplay("Signature = {new string(Signature)}, IsValid = {IsValid}")]
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi, Pack = 1)]
    public struct IMAGE_NT_HEADERS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public char[] Signature;

        public const string ValidSignature = "PE\0\0";
        public bool IsValid => new string(Signature) == ValidSignature;
    }
}
