using PETools.Structs;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

#if USE_SIZE
using System.Runtime.InteropServices;
#if COVERAGE_TEST
using static PETools.CoverageTest;
#endif
#endif

namespace PETools
{
#if COVERAGE_TEST && USE_SIZE
    static class CoverageTest
    {
        public static HashSet<long> coveredBytes = new HashSet<long>();
        public static void Init(long start, long end)
        {
            for (var i = start; i < end; i++)
                coveredBytes.Add(i);
        }
        public static void RemoveRange(long start, long length)
        {
            coveredBytes.RemoveWhere(x => start <= x && x < start + length);
        }
        public static void RemoveBack(long position, Type readType)
        {
            RemoveBack(position, Marshal.SizeOf(readType));
        }
        public static void RemoveBack(long position, long length)
        {
            RemoveRange(position - length, length);
        }

        public static long BaseAddress = 0x9F000;
        public static string Report()
        {
            StringBuilder output = new StringBuilder();
            long? start = null;
            long? end = null;
            void init(long val)
            {
                start = end = val;
            }
            void add()
            {
                output.AppendLine($"{(BaseAddress + start).Value:X}-{(BaseAddress + end).Value:X}");
            }
            foreach(var address in coveredBytes)
            {
                if (start == null)
                {
                    init(address);
                }
                else if(address == end + 1)
                {
                    end = address;
                }
                else
                {
                    add();
                    init(address);
                }
            }
            add();
            return output.ToString();
        }
    }
#endif

    [DebuggerDisplay("Name Entries = {Header.NumberOfNameEntries} ID Entries = {Header.NumberOfIDEntries}")]
    class ResourceTable
    {
        public IMAGE_RESOURCE_DIRECTORY Header;
        public List<ResourceDirectoryEntry> NamedEntryPointers;
        public List<ResourceDirectoryEntry> IDEntryPointers;
        public List<object> NamedEntries;
        public List<object> IDEntries;

        public long SectionRVA { get; private set; }

#if USE_SIZE
        long Size
        {
            get
            {
                long size = Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY));
                void addPointerSizes(IEnumerable<ResourceDirectoryEntry> dirs)
                {
                    foreach (var dir in dirs)
                        size += dir.Size;
                }
                addPointerSizes(NamedEntryPointers);
                addPointerSizes(IDEntryPointers);

                void addEntrySizes(IEnumerable<object> entries)
                {
                    foreach(var entry in entries)
                    {
                        if (entry is ResourceTable t)
                            size += t.Size;
                        else if (entry is ResourceDataEntry d)
                            size += d.Size;
                        else
                            throw new ArgumentException(); //invalid type?!
                    }
                }
                addEntrySizes(NamedEntries);
                addEntrySizes(IDEntries);

                return size;
            }
        }
#endif
        public ResourceTable(Stream stream, long rsrcSectionRVA, long? rsrcSectionFileAddress = null)
        {
#if COVERAGE_TEST && USE_SIZE
            if (rsrcSectionFileAddress == null)
                Init(stream.Position, stream.Length);
#endif
            SectionRVA = rsrcSectionRVA;
            var SectionPA = rsrcSectionFileAddress ?? stream.Position;
            using (var br = new BinaryReader(stream, Encoding.Default, true))
            {
                Header = br.ReadStruct<IMAGE_RESOURCE_DIRECTORY>();
#if COVERAGE_TEST && USE_SIZE
                RemoveBack(br.BaseStream.Position, typeof(IMAGE_RESOURCE_DIRECTORY));
#endif
                void InitEntries(ref List<ResourceDirectoryEntry> entryPointers, ref List<object> entryValues, int count)
                {
                    entryPointers = new List<ResourceDirectoryEntry>(count);
                    entryValues = new List<object>(count);
                    for (int i = 0; i < count; i++)
                        entryPointers.Add(new ResourceDirectoryEntry(br.BaseStream, SectionPA));
                }
                InitEntries(ref NamedEntryPointers, ref NamedEntries, Header.NumberOfNameEntries);
                InitEntries(ref IDEntryPointers, ref IDEntries, Header.NumberOfIDEntries);

                void ReadEntries(ref List<ResourceDirectoryEntry> entryPointers, ref List<object> entryValues)
                {
                    foreach (var pointer in entryPointers)
                    {
                        br.BaseStream.Seek(SectionPA + pointer.header.DataOffset, SeekOrigin.Begin);
                        if (pointer.header.IsTable)
                            entryValues.Add(new ResourceTable(br.BaseStream, SectionRVA, SectionPA));
                        else
                            entryValues.Add(new ResourceDataEntry(br.BaseStream, SectionRVA, SectionPA));
                    }
                }
                ReadEntries(ref NamedEntryPointers, ref NamedEntries);
                ReadEntries(ref IDEntryPointers, ref IDEntries);

#if COVERAGE_TEST && USE_SIZE
                if (rsrcSectionFileAddress == null)
                {
                    System.Diagnostics.Debug.Write(Report());
                }
#endif
            }
        }

        public void UpdateVirtualAddress(long newRVA)
        {
            void updateRVA(IEnumerable<object> entries)
            {
                foreach(var entry in entries)
                {
                    if (entry is ResourceTable t)
                        t.UpdateVirtualAddress(newRVA);
                    else if (entry is ResourceDataEntry d)
                        d.DataRVA = (uint)(d.DataRVA - SectionRVA + newRVA);
                }
            }
            updateRVA(NamedEntries);
            updateRVA(IDEntries);
            SectionRVA = newRVA;
        }

        public byte[] ToArray()
        {
#if USE_SIZE
            byte[] data = new byte[Size];
            using(var ms = new MemoryStream(data, true))
            {
                Serialize(ms);
            }
            return data;
#else
            var ms = new MemoryStream();
            Serialize(ms);
            return ms.ToArray();
#endif
        }
        internal void Serialize(Stream stream)
        {
            var pos = stream.Position;
            using (var bw = new BinaryWriter(stream, Encoding.Default, true))
            {
                bw.WriteStruct(Header);
                void WritePointers(IEnumerable<ResourceDirectoryEntry> dirs)
                {
                    foreach (var dir in dirs)
                        dir.Serialize(bw.BaseStream);
                }
                WritePointers(NamedEntryPointers);
                WritePointers(IDEntryPointers);

                void WriteEntries(IList<ResourceDirectoryEntry> pointers, IList<object> entries)
                {
                    for (int i = 0; i < pointers.Count; i++)
                    {
                        bw.BaseStream.Seek(pointers[i].header.DataOffset, SeekOrigin.Begin);
                        if (entries[i] is ResourceTable t)
                            t.Serialize(bw.BaseStream);
                        else if (entries[i] is ResourceDataEntry d)
                            d.Serialize(bw.BaseStream, SectionRVA);
                        else
                            throw new ArgumentException();
                    }
                }
                WriteEntries(NamedEntryPointers, NamedEntries);
                WriteEntries(IDEntryPointers, IDEntries);
            }
            stream.Position = pos;
        }
    }

    [DebuggerDisplay("Type = {header.IsString ? \"String\" : \"ID\"} String Offset = {header.StringOffset} Data/Subdirectory Offset = {header.DataOffset} Text = {name.HasValue ? name.Value.UnicodeString : \"null\"}")]
    class ResourceDirectoryEntry
    {
        public IMAGE_RESOURCE_DIRECTORY_ENTRY header;
        public IMAGE_RESOURCE_DIR_STRING_U? name = null;
        public ResourceDirectoryEntry(Stream stream, long rsrcSectionFileAddress)
        {
            using(var br = new BinaryReader(stream, Encoding.Unicode, true))
            {
                header = br.ReadStruct<IMAGE_RESOURCE_DIRECTORY_ENTRY>();
#if COVERAGE_TEST && USE_SIZE
                RemoveBack(br.BaseStream.Position, header.GetType());
#endif
                if(header.IsString)
                {
                    var pos = br.BaseStream.Position;
                    br.BaseStream.Seek(rsrcSectionFileAddress + header.StringOffset, SeekOrigin.Begin);
                    //need to use this function because of the variable length
                    name = IMAGE_RESOURCE_DIR_STRING_U.FromStream(br);
#if COVERAGE_TEST && USE_SIZE
                    RemoveBack(br.BaseStream.Position, name.Value.Size);
#endif
                    br.BaseStream.Position = pos;
                }
            }
        }

#if USE_SIZE
        //size should also work just fine since it's with the specific object, not just the type
        internal long Size => Marshal.SizeOf(typeof(IMAGE_RESOURCE_DIRECTORY_ENTRY)) + ((name != null) ? name.Value.Size : 0);
#endif
        public void Serialize(Stream stream)
        {
            using(var bw = new BinaryWriter(stream, Encoding.Unicode, true))
            {
                bw.WriteStruct(header);
                if(name != null)
                {
                    var pos = bw.BaseStream.Position;
                    bw.BaseStream.Seek(header.StringOffset, SeekOrigin.Begin);
                    //unlike reading, writing should work just fine
                    //bw.WriteStruct(name);
                    bw.Write(name.Value.ToArray());
                    bw.BaseStream.Position = pos;
                }
            }
        }
    }

    [DebuggerDisplay("RVA = {DataRVA} Size = {Size}")]
    class ResourceDataEntry
    {
        public IMAGE_RESOURCE_DATA_ENTRY entry;
        public byte[] data;
        public ResourceDataEntry(Stream stream, long rsrcSectionRVA, long rsrcSectionPA)
        {
            using(var br = new BinaryReader(stream, Encoding.Default, true))
            {
                //read struct and record position
                entry = br.ReadStruct<IMAGE_RESOURCE_DATA_ENTRY>();
                var temp = Encoding.GetEncoding((int)entry.Codepage);
#if COVERAGE_TEST && USE_SIZE
                RemoveBack(br.BaseStream.Position, entry.GetType());
#endif
                var pos = br.BaseStream.Position;

                //go to the actual data and read it
                br.BaseStream.Seek(rsrcSectionPA + entry.DataRVA - rsrcSectionRVA, SeekOrigin.Begin);
                data = br.ReadBytes(entry.Size);
#if COVERAGE_TEST && USE_SIZE
                RemoveBack(br.BaseStream.Position, data.Length);
#endif
                //jump back
                br.BaseStream.Position = pos;
            }
        }
        public uint DataRVA
        {
            get => entry.DataRVA;
            set => entry.DataRVA = value;
        }
        public uint Size
        {
            get => entry.Size;
            set => entry.Size = value;
        }
#if USE_SIZE
        internal long Size => Marshal.SizeOf(typeof(IMAGE_RESOURCE_DATA_ENTRY)) + data.Length;
#endif
        internal void Serialize(Stream stream, long rsrcSectionRVA)
        {
            using (var bw = new BinaryWriter(stream, Encoding.Default, true))
            {
                //write header
                bw.WriteStruct(entry);
                var pos = bw.BaseStream.Position;

                //jump and write data
                bw.BaseStream.Seek(entry.DataRVA - rsrcSectionRVA, SeekOrigin.Begin);
                bw.Write(data);
                
                //jump back
                bw.BaseStream.Position = pos;
            }
        }
    }
}
