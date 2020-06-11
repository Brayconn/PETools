using System;
using System.Collections.Generic;
using System.Text;
using System.IO;
using System.Runtime.InteropServices;

namespace PETools
{
    public class COFFTool
    {
        public COFFTool(int ordinal)
        {
            this.Ordinal = ordinal;
        }

        public int Ordinal { get; }
        public string SourceFile { get; private set; }

        byte[] rawData;
        IMAGE_FILE_HEADER fileHeader;

        public SymbolTable SymbolTable { get; private set; }
        public List<PESection> Sections { get; private set; }

        public void Read(string filePath)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                SourceFile = Path.GetFileName(filePath);
                Parse(stream);
                stream.Close();
            }
        }

        public void Read(byte[] data)
        {
            using (MemoryStream stream = new MemoryStream(data))
            {
                Parse(stream);
                stream.Close();
            }
        }

        private void Parse(Stream stream)
        {
            rawData = new byte[stream.Length];
            stream.Read(rawData, 0, (int)stream.Length);
            stream.Seek(0, SeekOrigin.Begin);
            BinaryReader reader = new BinaryReader(stream);

            fileHeader = PEUtility.FromBinaryReader<IMAGE_FILE_HEADER>(reader);

            // Read the sections
            Sections = new List<PESection>();
            for (int i = 0; i < fileHeader.NumberOfSections; i++)
            {
                IMAGE_SECTION_HEADER header;
                header = PEUtility.FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                PESection section = new PESection(this, header);
                section.Parse(ref rawData);
                Sections.Add(section);
            }

            // Read the symbol table from fileHeader.PointerToSymbolTable
            SymbolTable = new SymbolTable(fileHeader.NumberOfSymbols);
            stream.Seek(fileHeader.PointerToSymbolTable, SeekOrigin.Begin);
            for (int i = 0; i < fileHeader.NumberOfSymbols; i++)
            {
                IMAGE_SYMBOL symbol;
                symbol = PEUtility.FromBinaryReader<IMAGE_SYMBOL>(reader);
                SymbolTable.AddSymbol(symbol, i);
            }

            uint pointerToStringTable = fileHeader.PointerToSymbolTable +
                (uint)(fileHeader.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL)));
            stream.Seek(pointerToStringTable, SeekOrigin.Begin);
            uint stringTableSize = PEUtility.FromBinaryReader<uint>(reader);

            for (ushort i = (ushort)Marshal.SizeOf(typeof(uint)); i < stringTableSize; )
            {
                String stringEntry = PEUtility.StringFromBinaryReader(reader);
                SymbolTable.AddString(stringEntry, i);
                i += (ushort)(stringEntry.Length + 1); // include NULL terminator
            }

            Console.WriteLine("Object File: {0}", SourceFile);
            Console.WriteLine(SymbolTable.ToString());
            Console.WriteLine("Sections:");
            foreach (PESection s in Sections)
            {
                Console.WriteLine(s.ToString());
            }
            Console.WriteLine();
        }

        public static int Compare(COFFTool x, COFFTool y)
        {
            return x.Ordinal.CompareTo(y.Ordinal);
        }
    }
}
