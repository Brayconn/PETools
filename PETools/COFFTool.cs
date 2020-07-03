using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace PETools
{
    public class COFFTool
    {
        public COFFTool(int ordinal)
        {
            this.Ordinal = ordinal;
        }

        public int Ordinal { get; }

        IMAGE_FILE_HEADER fileHeader;

        public SymbolTable SymbolTable { get; private set; }
        public List<PESection> Sections { get; private set; }

        public void Read(string filePath)
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                Parse(stream);
            }
        }

        public void Read(byte[] data)
        {
            using (MemoryStream stream = new MemoryStream(data))
            {
                Parse(stream);
            }
        }

        private void Parse(Stream stream)
        {
            using (var reader = new BinaryReader(stream, Encoding.ASCII, true))
            {
                fileHeader = reader.ReadStruct<IMAGE_FILE_HEADER>();

                // Read the sections
                Sections = new List<PESection>();
                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADER header;
                    header = reader.ReadStruct<IMAGE_SECTION_HEADER>();
                    PESection section = new PESection(this, header);
                    section.Parse(stream);
                    Sections.Add(section);
                }

                // Read the symbol table from fileHeader.PointerToSymbolTable
                SymbolTable = new SymbolTable(fileHeader.NumberOfSymbols);
                stream.Seek(fileHeader.PointerToSymbolTable, SeekOrigin.Begin);
                for (int i = 0; i < fileHeader.NumberOfSymbols; i++)
                {
                    IMAGE_SYMBOL symbol;
                    symbol = reader.ReadStruct<IMAGE_SYMBOL>();
                    SymbolTable.AddSymbol(symbol, i);
                }

                uint pointerToStringTable = fileHeader.PointerToSymbolTable +
                    (uint)(fileHeader.NumberOfSymbols * Marshal.SizeOf(typeof(IMAGE_SYMBOL)));
                stream.Seek(pointerToStringTable, SeekOrigin.Begin);
                uint stringTableSize = reader.ReadStruct<uint>();

                for (ushort i = (ushort)Marshal.SizeOf(typeof(uint)); i < stringTableSize;)
                {
                    string stringEntry = reader.ReadCString();
                    SymbolTable.AddString(stringEntry, i);
                    i += (ushort)(stringEntry.Length + 1); // include NULL terminator
                }
            }
        }

        public static int Compare(COFFTool x, COFFTool y)
        {
            return x.Ordinal.CompareTo(y.Ordinal);
        }
    }
}
