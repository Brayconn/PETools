using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

namespace PETools
{

    public static class PEUtility
    {
        public static uint AlignUp(uint x, uint mask)
        {
            return (x + (mask - 1)) & ~(mask - 1);
        }

        public static byte[] RawSerialize(object obj)
        {
            byte[] rawdata = new byte[Marshal.SizeOf(obj)];

            GCHandle handle = GCHandle.Alloc(rawdata, GCHandleType.Pinned);
            Marshal.StructureToPtr(obj, handle.AddrOfPinnedObject(), false);
            handle.Free();

            return rawdata;
        }

        // Reads in a block from a file and converts it to the struct
        // type specified by the template parameter
        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public static string StringFromBinaryReader(BinaryReader reader)
        {
            List<byte> chars = new List<byte>();
            byte c;
            while ((c = reader.ReadByte()) != '\0')
                chars.Add(c);

            ASCIIEncoding encoding = new ASCIIEncoding();
            string str = encoding.GetString(chars.ToArray());
            return str;
        }

    }

    public class SectionVirtualComparer : IComparer<PESection>
    {
        public int Compare(PESection x, PESection y)
        {
            if (x.VirtualAddress < y.VirtualAddress)
                return -1;
            else if (x.VirtualAddress == y.VirtualAddress)
                return 0;
            else
                return 1;
        }
    }

    public class SectionPhysicalComparer : IComparer<PESection>
    {
        public int Compare(PESection x, PESection y)
        {
            if (x.PhysicalAddress < y.PhysicalAddress)
                return -1;
            else if (x.PhysicalAddress == y.PhysicalAddress)
                return 0;
            else
                return 1;
        }
    }

}
