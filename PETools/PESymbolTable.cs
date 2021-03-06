﻿using System;
using System.Text;
using System.Collections.Generic;

namespace PETools
{
    class PEImageSymbol
    {
        public string Name { get; set; }
        public ushort Offset { get; }

        public int index;
        public uint value;
        public IMAGE_SECTION_NUMBER sectionNumber;
        public IMAGE_SYMBOL_TYPE type;
        public IMAGE_SYMBOL_CLASS storageClass;
        public byte numberOfAuxSymbols;

        public PEImageSymbol(IMAGE_SYMBOL symbol, int index)
        {
            this.index = index;
            this.value = symbol.Value;
            this.sectionNumber = symbol.SectionNumber;
            this.type = symbol.Type;
            this.storageClass = symbol.StorageClass;
            this.numberOfAuxSymbols = symbol.NumberOfAuxSymbols;

            // TODO: NULL and UNDEFINED symbols are ignored

            // if name[0..3] are all zero, name[4..7] contain offset into symbol table
            if (symbol.Zeros == 0)
            {
                this.Offset = Offset;
                this.Name = null;
            }
            else
            {
                //was using ASCII encoding
                this.Name = new string(symbol.Name);
            }
        }

        public override string ToString()
        {
            return string.Format("\t[{0:X}] Name: {1,-25}\tType: {2,-20}\tSection: {3,-15}\n",
                index, Name, type, sectionNumber);
        }
    }

    public class SymbolTable
    {
        PEImageSymbol[] symbols;

        public SymbolTable(uint numberOfSymbols)
        {
            symbols = new PEImageSymbol[numberOfSymbols];
        }

        public void AddSymbol(IMAGE_SYMBOL symbol, int index)
        {
            symbols[index] = new PEImageSymbol(symbol, index);
        }

        public bool AddString(string name, ushort offset)
        {
            bool found = false;
            foreach (PEImageSymbol s in symbols)
            {
                if ((s.Name == null) && (s.Offset == offset))
                {
                    s.Name = name;
                    found = true;
                }
            }
            return found;
        }

        public override string ToString()
        {
            string ret = "Symbol Table:\n";
            foreach (PEImageSymbol s in symbols)
                ret += s.ToString();
            return ret;
        }
    }
}
