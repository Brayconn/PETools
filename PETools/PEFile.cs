using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;
using System.Text;
using System.Runtime.CompilerServices;
using PETools.Structs;

namespace PETools
{
    public class PEFile
    {
        //DOS header stuffs
        public IMAGE_DOS_HEADER dosHeader;
        public byte[] dosStub;

        //Actual PE stuff
        //normally, there would be a split between IMAGE_NT_HEADERS32 and IMAGE_NT_HEADERS64,
        //but that would make it impossible to dynamically load the right header when needed
        //so instead...
        public IMAGE_NT_HEADERS ntSignature;
        public IMAGE_FILE_HEADER fileHeader;
        public IMAGE_OPTIONAL_HEADER_STANDARD optionalStandard;
        //...I put the split way down here
        public IMAGE_OPTIONAL_HEADER_32 optionalHeader32;
        public IMAGE_OPTIONAL_HEADER_32PLUS optionalHeader32plus;
        //this stuff isn't affected
        public IMAGE_DATA_DIRECTORIES dataDirectories;
        public List<PESection> sections;

        public long TotalSize
        {
            get
            {
                long size = 0;
                /*
                size = Marshal.SizeOf(dosHeader) +
                            dosStub.Length +
                            Marshal.SizeOf(ntSignature) +
                            Marshal.SizeOf(fileHeader) +
                            Marshal.SizeOf(optionalStandard) +
                            //optional header +
                            Marshal.SizeOf(dataDirectories);
                */

                switch (optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        size = optionalHeader32.SizeOfHeaders;
                        break;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        throw new NotSupportedException();
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        size = optionalHeader32plus.SizeOfHeaders;
                        break;
                }

                size += Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)) * sections.Count;
                for (int i = 0; i < sections.Count; i++)
                {
                    if (sections[i].ContributesToFileSize)
                    {
                        size += sections[i].RawSize;
                    }
                }
                
                return size;
            }
        }            

        public bool Is32BitHeader => (fileHeader.Characteristics & IMAGE_FILE.IMAGE_FILE_32BIT_MACHINE) != 0;

        public static bool TryGetBaseAddress(string path, out ulong baseAddress)
        {
            baseAddress = 0;
            try
            {
                var file = FromFile(path);
                switch (file.optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        baseAddress = file.optionalHeader32.ImageBase;
                        break;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        baseAddress = 0;
                        return false;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        baseAddress = file.optionalHeader32plus.ImageBase;
                        break;
                }
                return true;
            }
            catch (FileLoadException)
            {
                return false;
            }
        }

        #region construction

        public PEFile()
        {
            dosStub = Array.Empty<byte>();
            sections = new List<PESection>();
        }

        public static PEFile FromFile(string path)
        {
            return FromStream(new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite));
        }

        public static PEFile FromBytes(byte[] data)
        {
            return FromStream(new MemoryStream(data));
        }

        /// <summary>
        /// Parse a PE.
        /// </summary>
        /// <param name="stream">A stream of the PE contents.</param>
        private static PEFile FromStream(Stream stream)
        {
            var pe = new PEFile();
            using (var br = new BinaryReader(stream))
            {
                pe.dosHeader = br.ReadStruct<IMAGE_DOS_HEADER>();

                int stubSize = (int)pe.dosHeader.e_lfanew - Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
                pe.dosStub = br.ReadBytes(stubSize);
                
                // Add 4 bytes to the offset
                stream.Seek(pe.dosHeader.e_lfanew, SeekOrigin.Begin);
                pe.ntSignature = br.ReadStruct<IMAGE_NT_HEADERS>();
                if (!pe.ntSignature.IsValid)
                    throw new FileLoadException();
                pe.fileHeader = br.ReadStruct<IMAGE_FILE_HEADER>();
                pe.optionalStandard = br.ReadStruct<IMAGE_OPTIONAL_HEADER_STANDARD>();
                switch (pe.optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        pe.optionalHeader32 = br.ReadStruct<IMAGE_OPTIONAL_HEADER_32>();
                        break;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        throw new NotSupportedException();
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        pe.optionalHeader32plus = br.ReadStruct<IMAGE_OPTIONAL_HEADER_32PLUS>();
                        break;
                    default:
                        throw new FileLoadException();
                }
                pe.dataDirectories = br.ReadStruct<IMAGE_DATA_DIRECTORIES>();

                pe.sections = new List<PESection>(pe.fileHeader.NumberOfSections);
                for (int i = 0; i < pe.fileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADER header = br.ReadStruct<IMAGE_SECTION_HEADER>();
                    PESection section = new PESection(header);
                    section.Parse(stream);
                    pe.sections.Add(section);
                }
            }
            return pe;
        }

        #endregion

        #region section alignment

        public void UpdateSectionLayout()
        {
            UpdatePhysicalLayout();
            UpdateVirtualLayout();
            UpdateDataDirectories();
        }
        public uint FileAlignment
        {
            get
            {
                switch (optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        return optionalHeader32.FileAlignment;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        throw new NotSupportedException();
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        return optionalHeader32plus.FileAlignment;
                    default:
                        throw new ArgumentException();
                }
            }
            set
            {
                switch (optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        optionalHeader32.FileAlignment = value;
                        break;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        throw new NotSupportedException();
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        optionalHeader32plus.FileAlignment = value;
                        break;
                    default:
                        throw new ArgumentException();
                }
            }
        }
        /// <summary>
        /// Updates the physical location of all sections, and updates the amount of initialized data
        /// </summary>
        public void UpdatePhysicalLayout()
        {
            uint fileAlignment, filePosition;
            switch (optionalStandard.Magic)
            {
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                    fileAlignment = optionalHeader32.FileAlignment;
                    filePosition = optionalHeader32.SizeOfHeaders;
                    break;
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                    throw new NotSupportedException();
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                    fileAlignment = optionalHeader32plus.FileAlignment;
                    filePosition = optionalHeader32plus.SizeOfHeaders;
                    break;
                default:
                    throw new ArgumentException();
            }

            uint initializedDataSize = 0;

            /* Layout the sections in physical order */
            foreach (var s in sections)
            {
                if (s.ContributesToFileSize)
                {
                    //TODO use null coalecing operator somehow
                    if (s.Data != null)
                        s.RawSize = PEUtility.AlignUp((uint)s.Data.Length, fileAlignment);
                    else
                        s.RawSize = PEUtility.AlignUp(s.RawSize, fileAlignment);
                    s.PhysicalAddress = filePosition;

                    filePosition += s.RawSize;
                    initializedDataSize += s.RawSize;
                }
            }

            optionalStandard.SizeOfInitializedData = initializedDataSize;
        }

        const string EDATA = ".edata";
        const string IDATA = ".idata";
        const string RSRC = ".rsrc";
        const string PDATA = ".pdata";
        const string RELOC = ".reloc";
        const string DEBUG = ".debug";
        const string TLS = ".tls";
        const string CORMETA = ".cormeta";
        public void UpdateDataDirectories()
        {
            void UpdateDataDirectory(ref IMAGE_DATA_DIRECTORY dir, string name)
            {
                if(TryGetSection(name, out PESection sect))
                {
                    dir.VirtualAddress = sect.VirtualAddress;
                    dir.Size = sect.VirtualSize;
                }
                else
                {
                    dir.VirtualAddress = 0;
                    dir.Size = 0;
                }
            }
            //99% of the commented out code is because their data can be either in IDATA or RDATA
            //it's really annoying 'cause there's no easy way to tell when stuff has moved
            UpdateDataDirectory(ref dataDirectories.ExportTable, EDATA);
            //UpdateDataDirectory(ref dataDirectories.ImportTable, IDATA);
            UpdateDataDirectory(ref dataDirectories.ResourceTable, RSRC);
            UpdateDataDirectory(ref dataDirectories.ExportTable, PDATA);
            //certificate table
            UpdateDataDirectory(ref dataDirectories.BaseRelocationTable, RELOC);
            UpdateDataDirectory(ref dataDirectories.Debug, DEBUG);
            dataDirectories.Architecture.VirtualAddress = 0;
            dataDirectories.Architecture.Size = 0;
            //dataDirectories.GlobalPtr.VirtualAddress = ???
            dataDirectories.GlobalPtr.Size = 0;
            UpdateDataDirectory(ref dataDirectories.TLSTable, TLS);
            //load config table
            //bound import
            //UpdateDataDirectory(ref dataDirectories.IAT, IDATA);
            //delay import desc
            UpdateDataDirectory(ref dataDirectories.CLRRuntimeHeader, CORMETA);
            dataDirectories.Reserved.VirtualAddress = 0;
            dataDirectories.Reserved.Size = 0;
        }

        const string TEXT = ".text";
        const string RDATA = ".rdata";
        const string DATA = ".data";
        const uint StartingVirtualAddress = 0x1000;
        public void UpdateVirtualLayout(uint initialVirtualAddress = StartingVirtualAddress)
        {
            uint virtualAlignment;
            switch (optionalStandard.Magic)
            {
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                    virtualAlignment = optionalHeader32.SectionAlignment;
                    break;
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                    throw new NotSupportedException();
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                    virtualAlignment = optionalHeader32plus.SectionAlignment;
                    break;
                default:
                    throw new ArgumentException();
            }

            /*
             * Fix up virtual addresses of the sections.
             * We start at 0x1000 (seems to be the convention)
             * Text should come first, then followed by data, then reloc
             * As we encounter certain sections, we need to update
             * special fields (data directory entries etc.).
             */
            uint virtualPosition = initialVirtualAddress;
            bool dataSectionEncountered = false;
            foreach (var s in sections)
            {
                //update optional header
                switch(s.Name)
                {
                    case TEXT:
                        optionalStandard.BaseOfCode = virtualPosition;
                        break;
                    case RDATA:
                    case DATA:
                        //PE32 headers want to know where the data starts
                        if(optionalStandard.Magic == IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32 && !dataSectionEncountered)
                        {
                            dataSectionEncountered = true;
                            optionalHeader32.BaseOfData = virtualPosition;
                        }
                        break;
                }

                //update virtual address
                if (s.VirtualAddress != virtualPosition)
                {
                    switch (s.Name)
                    {
                        case RSRC:
                            ResourceTable res;
                            using (var ms = new MemoryStream(s.Data))
                            {
                                //need to give it the original RVA 'cause that's important
                                res = new ResourceTable(ms, s.VirtualAddress);
                            }
                            res.UpdateVirtualAddress(virtualPosition);
                            //this is only safe because all I've done is changed the virtual address and reserialized the data
                            //this means the data size can only go DOWN (because of alignment not being included)
                            //do not repeat this anywhere else where the data gets changed
                            s.Data = res.ToArray();
                            goto default;
                        default:
                            s.VirtualAddress = virtualPosition;
                            break;
                    }
                }
                                
                //update size
                if (s.HasUninitializedData)
                {
                    // Leave uninitialized data sizes untouched, their raw size is 0
                }
                else if (s.HasInitializedData && s.HasCode)
                {
                    //TODO really not sure why this is here...
                    // It is possible for the virtual size to be greater than the size of raw data
                    // Leave the virtual size untouched if this is the case
                    if (s.VirtualSize <= s.RawSize)
                        s.VirtualSize = (uint)s.Data.Length;
                }

                virtualPosition += PEUtility.AlignUp(s.VirtualSize, virtualAlignment);
            }

            /* Total virtual size is the final virtual address, which includes the initial virtual offset. */
            if (optionalStandard.Magic == IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32)
                optionalHeader32.SizeOfImage = virtualPosition;
            else
                optionalHeader32plus.SizeOfImage = virtualPosition;
        }

        #endregion

        #region Serialization

        private void SerializeHeader(Stream file)
        {
            using (var bw = new BinaryWriter(file, Encoding.Default, true))
            {
                bw.WriteStruct(dosHeader);
                bw.Write(dosStub);
                bw.WriteStruct(ntSignature);
                bw.WriteStruct(fileHeader);
                bw.WriteStruct(optionalStandard);

                switch (optionalStandard.Magic)
                {
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                        bw.WriteStruct(optionalHeader32);
                        break;
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                        throw new NotSupportedException();
                    case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                        bw.WriteStruct(optionalHeader32plus);
                        break;
                }                
            }
        }

        public static explicit operator byte[](PEFile pe)
        {
            return pe.ToArray();
        }
        public byte[] ToArray()
        {
            /* Allocate enough space to contain the whole new file */
            byte[] file = new byte[TotalSize];
            using (var bw = new BinaryWriter(new MemoryStream(file, true)))
            {
                SerializeHeader(bw.BaseStream);
                bw.WriteStruct(dataDirectories);
                
                foreach (var section in sections)
                {
                    //write the header
                    bw.WriteStruct(section.Header);
                    var temp = bw.BaseStream.Position;
                    //jump to where the data belongs
                    bw.BaseStream.Seek(section.PhysicalAddress, SeekOrigin.Begin);
                    bw.Write(section.Data ?? new byte[section.RawSize]);
                    //jump back
                    bw.BaseStream.Position = temp;
                }
            }
            return file;
        }

        /// <summary>
        /// Write contents of PE.
        /// </summary>
        /// <param name="filename">Path of file to write to.</param>
        public void WriteFile(string filename)
        {
            /* Flush the contents of rawData back to disk */
            using (var fs = new FileStream(filename, FileMode.OpenOrCreate, FileAccess.Write, FileShare.ReadWrite))
            {
                var data = ToArray();
                fs.Write(data, 0, data.Length);
            }
        }

        #endregion

        #region section addition/removal

        /// <summary>
        /// Write the contents of the provided byte array into the section specified.
        /// </summary>
        /// <param name="name">Name of section</param>
        /// <param name="data">Byte array of section data</param>
        /// <returns>Bytes written</returns>
        public void WriteSectionData(string name, byte[] data)
        {
            var sect = GetSection(name);
            sect.Data = data;
            sect.RawSize = sect.VirtualSize = (uint)data.Length;
        }

        public void AddSection(PESection section)
        {
            sections.Add(section);
            fileHeader.NumberOfSections++;
        }

        public void InsertSection(int index, PESection section)
        {
            sections.Insert(index, section);
            fileHeader.NumberOfSections++;
        }

        public void RemoveSection(string name)
        {
            sections.Remove(GetSection(name));
            fileHeader.NumberOfSections--;
        }

        /// <summary>
        /// Retrieve the contents of the specified section.
        /// </summary>
        /// <param name="name">Name of section whose contents should be retrieved</param>
        /// <returns>Byte array of section contents</returns>
        public byte[] GetSectionData(string name)
        {
            return GetSection(name)?.Data;
        }

        private PESection FindSection(string name)
        {
            return sections.Find(x => x.Name == name);
        }

        public bool TryGetSection(string name, out PESection section)
        {
            return (section = FindSection(name)) != null;
        }

        public PESection GetSection(string name)
        {
            return FindSection(name) ?? throw new KeyNotFoundException();
        }

        public bool ContainsSection(string name)
        {
            return sections.Any(x => x.Name == name);
        }

        #endregion
    }
}
