using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;

namespace PETools
{
    [DebuggerDisplay("Signature = {new string(Signature)}, IsValid = {IsValid}")]
    public struct IMAGE_NT_HEADERS
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public char[] Signature;
        public bool IsValid => Signature.SequenceEqual("PE\0\0".ToCharArray());
    }
}
