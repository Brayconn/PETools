using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Linq;

namespace PETools
{
    public partial class PETool
    {
        public IMAGE_DOS_HEADER dosHeader;
        public byte[] dosStub;
        public IMAGE_NT_HEADERS ntSignature;
        public IMAGE_FILE_HEADER fileHeader;
        public IMAGE_OPTIONAL_HEADER_STANDARD optionalStandard;
        public IMAGE_OPTIONAL_HEADER_32 optionalHeader32;
        public IMAGE_OPTIONAL_HEADER_32PLUS optionalHeader32plus;
        public IMAGE_DATA_DIRECTORIES dataDirectories;
        public List<PESection> sections;

        /// <summary>
        /// Raw data content of entire PE.
        /// </summary>
        public byte[] rawData;

        public bool Is32BitHeader => (fileHeader.Characteristics & PECharacteristics.IMAGE_FILE_32BIT_MACHINE) != 0;

        public PETool() { }
        public PETool(string path)
        {
            Read(path);
        }

        /// <summary>
        /// Read a PE file.
        /// </summary>
        /// <param name="filePath">Path to PE file.</param>
        public void Read(string filePath)
        {
            // Read in the DLL or EXE and get the timestamp
            using (var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                Parse(stream);
            }
        }

        /// <summary>
        /// Read a PE file.
        /// </summary>
        /// <param name="data">Contents of a PE as a byte array.</param>
        public void Read(byte[] data)
        {
            using (var stream = new MemoryStream(data))
            {
                Parse(stream);
            }
        }

        /// <summary>
        /// Parse a PE.
        /// </summary>
        /// <param name="stream">A stream of the PE contents.</param>
        private void Parse(Stream stream)
        {
            rawData = new byte[stream.Length];
            stream.Read(rawData, 0, (int)stream.Length);
            stream.Seek(0, SeekOrigin.Begin);

            using (var reader = new BinaryReader(stream))
            {
                dosHeader = PEUtility.FromBinaryReader<IMAGE_DOS_HEADER>(reader);

                int stubSize = (int)dosHeader.e_lfanew - Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));
                dosStub = reader.ReadBytes(stubSize);

                // Add 4 bytes to the offset
                stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);
                ntSignature = PEUtility.FromBinaryReader<IMAGE_NT_HEADERS>(reader);
                if (!ntSignature.IsValid)
                    throw new FileLoadException();
                fileHeader = PEUtility.FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                optionalStandard = PEUtility.FromBinaryReader<IMAGE_OPTIONAL_HEADER_STANDARD>(reader);
                switch (optionalStandard.Magic)
                {
                    case 0x10B:
                        optionalHeader32 = PEUtility.FromBinaryReader<IMAGE_OPTIONAL_HEADER_32>(reader);
                        break;
                    case 0x107:
                        throw new NotSupportedException("Can't load ROM images I guess");
                    case 0x20B:
                        optionalHeader32plus = PEUtility.FromBinaryReader<IMAGE_OPTIONAL_HEADER_32PLUS>(reader);
                        break;
                }
                dataDirectories = PEUtility.FromBinaryReader<IMAGE_DATA_DIRECTORIES>(reader);

                sections = new List<PESection>(fileHeader.NumberOfSections);
                for (int i = 0; i < fileHeader.NumberOfSections; i++)
                {
                    IMAGE_SECTION_HEADER header = PEUtility.FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
                    PESection section = new PESection(header);
                    section.Parse(ref rawData);
                    sections.Add(section);
                }
            }
        }

        /// <summary>
        /// Layout contents of PE file, updating headers and order sections.
        /// </summary>
        /// <returns>Returns bool describing if layout succeeded.</returns>
        public bool Layout()
        {
            uint virtualAlignment = optionalHeader32.SectionAlignment;
            uint fileAlignment = optionalHeader32.FileAlignment;
            uint totalSize = 0;
            uint initializedDataSize = 0;

            totalSize += optionalHeader32.SizeOfHeaders;
            /* Calculate total physical size required */
            foreach (PESection s in sections)
            {
                totalSize += PEUtility.AlignUp((uint)s.Data.Length, fileAlignment);
            }

            /* Layout the sections in physical order */
            uint filePosition = optionalHeader32.SizeOfHeaders;
            sections.Sort(new SectionPhysicalComparer());
            foreach (PESection s in sections)
            {
                if (s.ContributesToFileSize)
                {
                    s.RawSize = PEUtility.AlignUp((uint)s.Data.Length, fileAlignment);
                    s.PhysicalAddress = filePosition;

                    filePosition += s.RawSize;
                    initializedDataSize += s.RawSize;
                }
            }

            optionalStandard.SizeOfInitializedData = initializedDataSize;

            /*
             * Fix up virtual addresses of the sections.
             * We start at 0x1000 (seems to be the convention)
             * Text should come first, then followed by data, then reloc
             * As we encounter certain sections, we need to update
             * special fields (data directory entries etc.).
             */
            uint virtAddr = 0x1000;
            bool dataSectionEncountered = false;
            sections.Sort(new SectionVirtualComparer());
            foreach (PESection s in sections)
            {
                switch(s.Name)
                {
                    case ".text":
                        optionalStandard.BaseOfCode = virtAddr;
                        break;
                    case ".rdata":
                        dataDirectories.Debug.VirtualAddress = virtAddr;
                        goto case ".data";
                    case ".data":
                        if(!dataSectionEncountered)
                        {
                            dataSectionEncountered = true;
                            if(optionalStandard.Magic == IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32)
                                optionalHeader32.BaseOfData = virtAddr;
                        }
                        break;
                    case ".reloc":
                        dataDirectories.BaseRelocationTable.VirtualAddress = virtAddr;
                        break;
                }

                s.VirtualAddress = virtAddr;

                if (s.HasUninitializedData)
                {
                    // Leave uninitialized data sizes untouched, their raw size is 0
                    virtAddr += PEUtility.AlignUp(s.VirtualSize, virtualAlignment);
                }
                else if (s.HasInitializedData && s.HasCode)
                {
                    // It is possible for the virtual size to be greater than the size of raw data
                    // Leave the virtual size untouched if this is the case
                    if (s.VirtualSize <= s.RawSize)
                        s.VirtualSize = (uint)s.Data.Length;
                    virtAddr += PEUtility.AlignUp(s.VirtualSize, virtualAlignment);
                }
            }

            /* Total virtual size is the final virtual address, which includes the initial virtual offset. */
            optionalHeader32.SizeOfImage = virtAddr;

            /* Serialize and write the header contents */
            Serialize(totalSize);

            return true;
        }

        public void UpdateHeader()
        {
            SerializeHeader(ref rawData);
        }

        private uint SerializeHeader(ref byte[] file)
        {
            uint filePosition = 0;

            Array.Copy(PEUtility.RawSerialize(dosHeader), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_DOS_HEADER)));
            filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_DOS_HEADER));

            Array.Copy(dosStub, 0, file, filePosition, dosStub.Length);
            filePosition += (uint)dosStub.Length;

            Array.Copy(PEUtility.RawSerialize(ntSignature), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_NT_HEADERS)));
            filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_NT_HEADERS));

            Array.Copy(PEUtility.RawSerialize(fileHeader), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));
            filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));

            Array.Copy(PEUtility.RawSerialize(optionalStandard), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)));
            filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_FILE_HEADER));

            switch(optionalStandard.Magic)
            {
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32:
                    Array.Copy(PEUtility.RawSerialize(optionalHeader32), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER_32)));
                    filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER_32));
                    break;
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_ROM:
                    throw new NotSupportedException("No ROMS");
                case IMAGE_OPTIONAL_HEADER_STANDARD.MAGIC_PE32PLUS:
                    Array.Copy(PEUtility.RawSerialize(optionalHeader32plus), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER_32PLUS)));
                    filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER_32PLUS));
                    break;
            }

            return filePosition;
        }

        private void Serialize(uint totalSize)
        {
            /* Allocate enough space to contain the whole new file */
            byte[] file = new byte[totalSize];
            uint filePosition = SerializeHeader(ref file);

            Array.Copy(PEUtility.RawSerialize(dataDirectories), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORIES)));
            filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_DATA_DIRECTORIES));

            // XXX: Sections must be sorted in layout order!
            foreach (PESection section in sections)
            {
                Array.Copy(PEUtility.RawSerialize(section.Header), 0, file, filePosition, Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER)));
                filePosition += (uint)Marshal.SizeOf(typeof(IMAGE_SECTION_HEADER));
            }

            /* Copy the section data */
            filePosition = optionalHeader32.SizeOfHeaders;
            sections.Sort(new SectionPhysicalComparer());
            foreach (PESection s in sections)
            {
                Array.Copy(s.Data, 0, file, filePosition, s.Data.Length);
                filePosition += s.RawSize;
            }

            /* Overwrite the container data */
            rawData = file;
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
                fs.Write(rawData, 0, rawData.Length);
            }
        }

        public void AddCOFFSections(List<PESection> sections)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Write the contents of the provided byte array into the section specified.
        /// </summary>
        /// <param name="name">Name of section</param>
        /// <param name="data">Byte array of section data</param>
        /// <returns>Bytes written</returns>
        public uint WriteSectionData(string name, byte[] data)
        {
            PESection section = sections.Find(s => s.Name == name);
            if (section == null)
                return 0;

            section.Data = data;
            return (uint)data.Length;
        }

        public void AddSection(PESection section)
        {
            section.PhysicalAddress = sections[sections.Count - 1].PhysicalAddress * 2;
            sections.Add(section);
            fileHeader.NumberOfSections++;
        }

        public void InsertSection(int index, PESection section)
        {
            var pre = sections[index - 1];
            var post = sections[index];
            var virt = (post.PhysicalAddress - pre.PhysicalAddress) / 2;
            section.VirtualAddress = virt;
            sections.Insert(index, section);
            fileHeader.NumberOfSections++;
        }

        public void RemoveSection(string name)
        {
            if (TryGetSection(name, out PESection s))
            {
                sections.Remove(s);
                fileHeader.NumberOfSections--;
            }
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

        public bool TryGetSection(string name, out PESection section)
        {
            return (section = GetSection(name)) != null;
        }

        public PESection GetSection(string name)
        {
            return sections.Find(x => x.Name == name);
        }

        public bool ContainsSection(string name)
        {
            return sections.Any(x => x.Name == name);
        }
    }
}
