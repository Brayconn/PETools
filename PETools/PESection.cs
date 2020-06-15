using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Linq;

namespace PETools
{
    public class PESection
    {
        public COFFTool SourceCoff { get; }

        public IMAGE_SECTION_HEADER Header;
        public byte[] Data { get; set; }

        List<IMAGE_RELOCATION> relocations;

        public PESection(IMAGE_SECTION_HEADER header)
        {
            Header = header;
        }

        public PESection(COFFTool coff, IMAGE_SECTION_HEADER header)
        {
            this.SourceCoff = coff;
            this.Header = header;
            this.relocations = null;
        }

        public string Name
        {
            get
            {
                ASCIIEncoding encoding = new ASCIIEncoding();
                byte[] bytes = new byte[8];
                int len = 0;
                foreach (char c in Header.Name)
                {
                    if (c == '\0')
                        break;
                    bytes[len] = (byte)c;
                    len++;
                }
                return encoding.GetString(bytes, 0, len);
            }
            set
            {
                char[] chars = value.ToCharArray();
                Array.Clear(Header.Name, 0, 8);
                Array.Copy(chars, Header.Name, chars.Length);

            }
        }

        public bool HasRelocations => Header.NumberOfRelocations != 0;

        public bool HasUninitializedData => (Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_UNINITIALIZED_DATA) != 0;

        public bool HasInitializedData => (Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0;

        public bool HasCode => (Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_CODE) != 0;

        public uint VirtualAddress
        {
            get => Header.VirtualAddress;
            set => Header.VirtualAddress = value;
        }

        public uint VirtualSize
        {
            get => Header.VirtualSize;
            set => Header.VirtualSize = value;
        }

        public uint PhysicalAddress
        {
            get => Header.PointerToRawData;
            set => Header.PointerToRawData = value;
        }

        public uint RawSize
        {
            get => Header.SizeOfRawData;
            set => Header.SizeOfRawData = value;
        }

        public bool ContributesToFileSize =>
                ((Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_INITIALIZED_DATA) != 0) ||
                (
                 ((Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_CODE) != 0) &&
                 ((Header.Characteristics & IMAGE_SECTION_FLAGS.IMAGE_SCN_CNT_UNINITIALIZED_DATA) == 0)
                );

        public void Parse(ref byte[] file)
        {
            // Differentiate between COFF object and PE image.
            uint sectionSize = Header.SizeOfRawData;
            /*TODO if virtualsize is > sizeofrawdata, need to 0 pad something???
            if (Header.PhysicalAddressOrVirtualSizeUnion > 0)
             sectionSize = Math.Min(
                 Header.SizeOfRawData,
                 Header.PhysicalAddressOrVirtualSizeUnion);
            */

            Data = new byte[sectionSize];
            // Make a copy of the section data
            Array.Copy(file, Header.PointerToRawData,
                Data, 0,
                sectionSize);

            ParseRelocations(ref file);
        }

        void ParseRelocations(ref byte[] file)
        {
            relocations = new List<IMAGE_RELOCATION>();

            if (!HasRelocations)
                return;

            MemoryStream stream = new MemoryStream(file);
            stream.Seek(Header.PointerToRelocations, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(stream);

            for (int i = 0; i < Header.NumberOfRelocations; i++)
            {
                IMAGE_RELOCATION reloc;
                reloc = PEUtility.FromBinaryReader<IMAGE_RELOCATION>(reader);
                relocations.Add(reloc);
            }
        }

        public static int Compare(PESection x, PESection y)
        {
            if (!x.Name.Contains("$") && !y.Name.Contains("$"))
            {
                // COFF file ordinal is used as tie-breaker
                return COFFTool.Compare(x.SourceCoff, y.SourceCoff);
            }

            // Always give preference to sections with no $
            else if (!x.Name.Contains("$") && y.Name.Contains("$"))
                return -1;
            else if (x.Name.Contains("$") && !y.Name.Contains("$"))
                return 1;

            // If both have a $ grouping, order by $ suffix.
            else // (x.Name.Contains("$") && y.Name.Contains("$"))
            {
                string xdollar = x.Name.Substring(x.Name.IndexOf('$') + 1);
                string ydollar = y.Name.Substring(x.Name.IndexOf('$') + 1);

                int cmp = string.Compare(xdollar, ydollar);
                // COFF file ordinal is used as tie-breaker
                if (cmp == 0)
                    return COFFTool.Compare(x.SourceCoff, y.SourceCoff);
                else
                    return cmp;
            }
        }

        public override string ToString()
        {
            var ret = string.Empty;
            ret += string.Format("Name: {0,-15}\tVirt Addr: {1:X}\tVirt Size: {2:X}\tPhys Addr: {3:X}\tRaw Size: {4:X}",
                Name, VirtualAddress, VirtualSize, PhysicalAddress, RawSize);

            if ((relocations == null) || (relocations.Count == 0))
                return ret;

            ret += "\n\tRelocation fixups:\n";
            foreach (IMAGE_RELOCATION reloc in relocations)
            {
                ret += string.Format("\tIndex: {0:X}\tVirt Addr: {1:X} Type: {2}\n",
                    reloc.SymbolTableIndex, reloc.VirtualAddress, reloc.I386_Type);
            }

            return ret;
        }
    }
}
